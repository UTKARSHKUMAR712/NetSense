#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <deque>
#include <fstream>

struct ConnectionEntry {
    std::string localAddr;
    uint16_t    localPort   = 0;
    std::string remoteAddr;
    uint16_t    remotePort  = 0;
    DWORD       pid         = 0;
    std::string processName;
    std::string remoteDomain;
    std::string state;
};

// Grouped domain stat for a single process (Phase 3)
struct DomainStat {
    std::string domain;
    uint16_t    port  = 0;
    int         count = 0;  // connections to this domain:port
};

struct ProcessEntry {
    DWORD       pid       = 0;
    std::string name;
    int         connCount = 0;
    // Grouped domain view (built by monitor)
    std::vector<DomainStat> domainStats;
    // Phase 3 — bandwidth
    uint64_t    bpsIn     = 0;   // bytes/sec download
    uint64_t    bpsOut    = 0;   // bytes/sec upload
};

struct ProxyFlow {
    std::string id;              // flow UUID from Python
    double      ts;              // unix timestamp
    std::string type;            // "REQ", "RSP", "WS_MSG"
    std::string method;          // GET, POST, PUT...
    std::string url;             // full URL
    std::string host;            // hostname only
    int         port       = 0;
    int         status     = 0;  // HTTP status code
    std::string http_version;
    double      duration_ms= 0;  // request round-trip time
    long long   req_size   = 0;  // bytes
    long long   rsp_size   = 0;  // bytes
    std::string content_type;    // MIME type
    std::string query_params;    // raw query string
    std::string cookies;         // key=value pairs
    std::string body_preview;    // first 512 bytes (only if enabled)
    std::string raw_req_headers; // raw headers blob
    std::string raw_rsp_headers;
    std::string insight_tags;    // comma-separated: "streaming,api"
    bool        is_websocket = false;
    std::string process_hint;    // best-guess process name
    bool        tls_valid = false;
    std::string tls_sni;
    std::string redirect_chain;
    std::string form_data;
    std::string ws_message;
    int         ws_opcode = -1;
    long long   bandwidth_bps = 0;
};

struct AppSettings {
    // Proxy
    int    proxyPort           = 8080;
    bool   proxyAutoStart      = false;

    // Body Capture (OFF by default)
    bool   enableBodyPreview   = false;
    int    maxBodyBytes        = 512;
    bool   jsonOnlyPreview     = true;
    bool   ignoreBinaryRsp     = true;
    bool   ignoreMediaTraffic  = true;

    // Privacy
    bool   privateMode         = false;   // disables all body + cookie logging
    bool   maskAuthHeaders     = true;    // always mask Authorization
    bool   encryptSensitiveFields = false;
    bool   storeCookies           = false; // OFF by default
    bool   storeFormData          = false; // OFF by default

    // Performance
    int    maxLiveFlows        = 2000;    // ring buffer size
    int    maxLogLines         = 500;

    // Storage
    bool   enableSQLite        = true;
    std::string dbPath         = "netsense.db";

    // UI
    int    themeIndex          = 0;
    float  uiScale             = 1.0f;

    // Proxy path — empty = auto-detect mitmdump.exe alongside NetSense.exe
    std::string mitmdumpPath   = "";
};

// Persist settings across restarts
void LoadSettings();
void SaveSettings();

struct AppState {
    std::mutex                    mtx;
    std::map<DWORD, ProcessEntry> processes;
    std::vector<ConnectionEntry>  connections;
    std::deque<std::string>       logLines;       // ring buffer, max 500
    std::deque<ProxyFlow>         proxyFlows;     // ring buffer, max 2000
    std::deque<float>             bwHistoryIn;    // last 120 samples
    std::deque<float>             bwHistoryOut;   // last 120 samples
    std::atomic<bool>             running{true};
    std::atomic<bool>             disclaimerAccepted{false};
    // Phase 3 filter — show only ESTABLISHED connections
    std::atomic<bool>             filterEstablished{true};

    bool                          recording = false;
    int                           currentSessionId = -1; // Active SQLite session ID
    std::string                   recordTarget = ""; // empty means All
    std::ofstream                 recordStream;

    void addLog(const std::string& line) {
        std::lock_guard<std::mutex> lk(mtx);
        logLines.push_back(line);
        if (logLines.size() > 500) logLines.pop_front();
        
        if (recording && recordStream.is_open()) {
            if (recordTarget.empty() || line.find(recordTarget) != std::string::npos || line.find("MITM") != std::string::npos) {
                recordStream << line << "\n";
                recordStream.flush();
            }
        }
    }
};

// Single global instance — defined in main.cpp
extern AppState g_state;
extern AppSettings g_settings;
