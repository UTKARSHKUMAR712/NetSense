#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include "../third_party/json/json.hpp"
#include "app_data.h"
#include "proxy_reader.h"
#include "traffic_db.h"
#include "../analysis/flow_pipeline.h"
#include "../backend/runtime_health.h"
#include "../utils/time_utils.h"
#include "../rules/rule_manager.h"

using json = nlohmann::json;

// ── Proxy-startup pending log (posted to g_state NEXT frame) ──
// StartProxyServer() cannot call ProxyLog() while the UI holds
// g_state.mtx.  Messages are queued here and flushed by the proxy reader.
static std::mutex              g_pendingLogMtx;
static std::vector<std::string> g_pendingLogs;

static void ProxyLog(const std::string& msg) {
    // Also emit to VS/MSYS2 debug output for immediate visibility
    OutputDebugStringA((msg + "\n").c_str());
    std::lock_guard<std::mutex> lk(g_pendingLogMtx);
    g_pendingLogs.push_back(msg);
}

// Called from ProxyLoop (background thread) — safe to lock g_state.mtx here
static void FlushPendingProxyLogs() {
    std::vector<std::string> tmp;
    {
        std::lock_guard<std::mutex> lk(g_pendingLogMtx);
        tmp.swap(g_pendingLogs);
    }
    for (auto& m : tmp) ProxyLog(m);
}

static std::atomic<bool> g_proxy_running{false};
static std::thread       g_proxy_thread;


static HANDLE g_hProxyProcess = NULL;

static std::string FmtBytes5(long long b) {
    char buf[32];
    if(b >= 1024*1024) snprintf(buf,sizeof(buf),"%.1fMB",b/(1024.0*1024.0));
    else if(b >= 1024) snprintf(buf,sizeof(buf),"%.1fKB",b/1024.0);
    else               snprintf(buf,sizeof(buf),"%lldB",(long long)b);
    return buf;
}

static void ProxyLoop() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string dir(exePath);
    auto slash = dir.rfind('\\');
    if(slash != std::string::npos) dir.resize(slash+1);
    std::string logPath = dir + "proxy\\netsense_proxy.log";

    std::ifstream f;
    
    // Tries to open the file and seeks to end (so we only see NEW proxy traffic)
    auto openAndSeekEnd = [&]() {
        f.open(logPath, std::ios::in | std::ios::binary);
        if(f.is_open()) {
            f.seekg(0, std::ios::end);
        }
    };

    openAndSeekEnd();

    while(g_proxy_running) {
        // Flush any log messages queued by StartProxyServer() (UI-safe)
        FlushPendingProxyLogs();

        if(!f.is_open()) {
            openAndSeekEnd();
        }

        if(f.is_open()) {
            f.clear(); // clear any previous EOF flags
            std::string line;
            while(std::getline(f, line)) {
                if(line.empty()) continue;
                
                try {
                    auto j = json::parse(line);
                    ProxyFlow flow;
                    flow.id = j.value("id", std::to_string(time(NULL)) + std::to_string(rand()));
                    flow.ts = j.value("ts", 0.0);
                    flow.type = j.value("type", "");
                    flow.method = j.value("method", "");
                    flow.url = j.value("url", "");
                    flow.host = j.value("host", "");

                    // Intercept Rule Engine Events for live hit tracking
                    if (flow.type == "RULE_EVENT") {
                        std::string rule_id = j.value("rule_id", "");
                        if (!rule_id.empty() && rule_id != "?") {
                            RuleManager::IncrementHit(rule_id);
                        }
                        // For Alerts, we could also route to an alert log, but it's already written to netsense_alerts.log in python
                        continue; 
                    }

                    flow.port = j.value("port", 0);
                    flow.http_version = j.value("http_version", "");
                    flow.req_size = j.value("req_size", 0);
                    flow.content_type = j.value("content_type", "");
                    flow.query_params = j.value("query_params", "");
                    flow.is_websocket = j.value("is_websocket", false);
                    flow.tls_valid = j.value("tls_valid", false);
                    flow.tls_sni = j.value("tls_sni", "");
                    flow.tls_version = j.value("tls_version", "");
                    flow.tls_cipher = j.value("tls_cipher", "");
                    flow.tls_alpn = j.value("tls_alpn", "");
                    flow.form_data = j.value("form_data", "");
                    flow.redirect_chain = j.value("redirect_chain", "");
                    flow.ws_opcode = j.value("ws_opcode", -1);
                    flow.ws_message = j.value("ws_message", "");
                    
                    if (j.contains("req_headers")) flow.raw_req_headers = j["req_headers"].dump();
                    if (j.contains("cookies")) flow.cookies = j["cookies"].dump();
                    
                    if (j.contains("insight_tags") && j["insight_tags"].is_array()) {
                        std::string joined_tags;
                        for (size_t i = 0; i < j["insight_tags"].size(); ++i) {
                            joined_tags += j["insight_tags"][i].get<std::string>();
                            if (i < j["insight_tags"].size() - 1) joined_tags += ",";
                        }
                        flow.insight_tags = joined_tags;
                    }
                    
                    if (j.contains("catcher_data")) {
                        auto& cd = j["catcher_data"];
                        flow.insight.vaultPayload.username = cd.value("username", "");
                        flow.insight.vaultPayload.password = cd.value("password", "");
                        flow.insight.vaultPayload.bearerToken = cd.value("bearerToken", "");
                        flow.insight.vaultPayload.authCookies = cd.value("authCookies", "");
                    }
                    
                    if (flow.type == "RSP") {
                        flow.status = j.value("status", 0);
                        flow.duration_ms = j.value("duration_ms", 0.0);
                        flow.rsp_size = j.value("rsp_size", 0);
                        flow.body_preview = j.value("body_preview", "");
                        if (j.contains("rsp_headers")) flow.raw_rsp_headers = j["rsp_headers"].dump();
                        
                        if (flow.duration_ms > 0) {
                            flow.bandwidth_bps = (long long)(((double)(flow.req_size + flow.rsp_size)) / (flow.duration_ms / 1000.0));
                        }
                    }
                    // Execute pipeline on the background thread before storing
                    FlowPipeline::ProcessFlow(flow);

                    // Add to g_state
                    {
                        std::lock_guard<std::mutex> lk(g_state.mtx);
                        g_state.proxyFlows.push_back(flow);
                        if (g_state.proxyFlows.size() > g_settings.maxLiveFlows) {
                            g_state.proxyFlows.pop_front();
                        }
                    }
                    
                    if (g_settings.enableSQLite && g_state.currentSessionId != -1) {
                        TrafficDB::QueueFlowInsert(g_state.currentSessionId, flow);
                    }
                    
                    // Legacy logLines push for existing UI functionality
                    std::string entry;
                    if(flow.type == "REQ") {
                        entry = "[MITM REQ]  " + flow.method + "  " + flow.url;
                    } else if(flow.type == "RSP") {
                        entry = "[MITM RSP]  " + std::to_string(flow.status) + "  " + flow.method + "  " + flow.url;
                    }
                    
                    if(!entry.empty()) {
                        ProxyLog(entry);
                    }
                    
                } catch(...) {
                    // Ignore malformed JSON
                }
            }
            f.clear(); // clear EOF again so next iteration can read
        }

        // ── Heartbeat (health monitor) ─────────────────────────
        RuntimeHealthMonitor::Heartbeat(SubsystemId::ProxyReader);

        // ── Proxy crash recovery ───────────────────────────────
        // Every 5s check if mitmdump.exe is still alive.
        static double s_lastCrashCheck = 0.0;
        double nowMs = TimeUtils::MonotonicMs();
        if ((nowMs - s_lastCrashCheck) > 5000.0) {
            s_lastCrashCheck = nowMs;
            if (g_hProxyProcess != NULL) {
                DWORD rc = WaitForSingleObject(g_hProxyProcess, 0);
                if (rc == WAIT_OBJECT_0) {
                    // Process has exited unexpectedly
                    CloseHandle(g_hProxyProcess);
                    g_hProxyProcess = NULL;
                    ProxyLog("[PROXY] mitmdump process died — attempting auto-restart...");
                    if (StartProxyServer()) {
                        ProxyLog("[PROXY] Auto-restart successful.");
                    } else {
                        ProxyLog("[PROXY ERROR] Auto-restart FAILED. Check Settings > Proxy.");
                    }
                }
            }
        }

        Sleep(500);
    }
    
    if(f.is_open()) f.close();
}

void StartProxyReader() {
    g_proxy_running = true;
    g_proxy_thread  = std::thread(ProxyLoop);
}
void StopProxyReader() {
    g_proxy_running = false;
    if(g_proxy_thread.joinable()) g_proxy_thread.join();
}

bool StartProxyServer() {
    if (g_hProxyProcess != NULL) return true;

    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string dir(exePath);
    auto slash = dir.rfind('\\');
    if (slash != std::string::npos) dir.resize(slash + 1);

    // Ensure runtime dirs exist
    CreateDirectoryA((dir + "proxy").c_str(), NULL);
    CreateDirectoryA((dir + "recordings").c_str(), NULL);

    // ── Resolve mitmdump.exe ──────────────────────────────────
    // Priority 1: user-supplied path from Settings
    std::string mitmPath = g_settings.mitmdumpPath;

    // Priority 2: auto-detect mitmdump.exe alongside NetSense.exe
    if (mitmPath.empty() ||
        GetFileAttributesA(mitmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        mitmPath = dir + "mitmdump.exe";
    }
    // Priority 3: mitmproxy.exe (alternate install name)
    if (GetFileAttributesA(mitmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        mitmPath = dir + "mitmproxy.exe";
    }
    // Not found — emit actionable error
    if (GetFileAttributesA(mitmPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ProxyLog("[PROXY ERROR] mitmdump.exe not found at: " + dir + "mitmdump.exe");
        ProxyLog("[PROXY ERROR] Set path manually in Settings > Proxy > mitmdump Path.");
        return false;
    }

    // ── Resolve addon script ──────────────────────────────────
    std::string scriptPath = dir + "proxy\\netsense_addon.py";
    if (GetFileAttributesA(scriptPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ProxyLog("[PROXY ERROR] netsense_addon.py not found at: " + scriptPath);
        return false;
    }

    ProxyLog("[PROXY] mitmdump : " + mitmPath);
    ProxyLog("[PROXY] addon    : " + scriptPath);

    std::string cmd = "\"" + mitmPath + "\" --listen-port "
                    + std::to_string(g_settings.proxyPort)
                    + " -s \"" + scriptPath + "\"";

    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "[PROXY ERROR] CreateProcess failed (err=%lu). Check mitmdump path.", err);
        ProxyLog(buf);
        return false;
    }

    g_hProxyProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    return true;
}

void StopProxyServer() {
    if (g_hProxyProcess != NULL) {
        TerminateProcess(g_hProxyProcess, 0);
        CloseHandle(g_hProxyProcess);
        g_hProxyProcess = NULL;
    }
    // Also run taskkill to ensure any zombie child processes of mitmdump are destroyed
    // Run asynchronously to avoid freezing the UI thread if taskkill blocks
    std::thread([](){
        system("taskkill /F /IM mitmdump.exe /T 2>nul");
    }).detach();
}
