#include "traffic_analyzer.h"
#include "../core/app_data.h"
#include <thread>
#include <atomic>
#include <map>
#include <vector>
#include <algorithm>
#include <windows.h>

static std::atomic<bool> g_analyzer_running{false};
static std::thread g_analyzer_thread;

struct UrlStats {
    std::vector<double> timestamps;
};

struct HostStats {
    std::vector<double> timestamps;
};

struct PostStats {
    std::vector<double> timestamps;
};

static void AnalyzerLoop() {
    std::map<std::string, UrlStats> urlHistory;
    std::map<std::string, HostStats> hostHistory;
    std::map<std::string, PostStats> postHistory;
    
    double last_check_ts = 0;
    
    while (g_analyzer_running) {
        std::vector<ProxyFlow> flows_to_analyze;
        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            for (auto it = g_state.proxyFlows.rbegin(); it != g_state.proxyFlows.rend(); ++it) {
                if (it->ts <= last_check_ts) break;
                flows_to_analyze.push_back(*it);
            }
            if (!g_state.proxyFlows.empty()) {
                last_check_ts = g_state.proxyFlows.back().ts;
            }
        }
        
        for (auto it = flows_to_analyze.rbegin(); it != flows_to_analyze.rend(); ++it) {
            const auto& f = *it;
            
            // 1. [POLL] Same URL repeated > 5x in 10s
            auto& urlStat = urlHistory[f.url];
            urlStat.timestamps.push_back(f.ts);
            int poll_count = 0;
            for (auto t : urlStat.timestamps) {
                if (f.ts - t <= 10.0) poll_count++;
            }
            if (poll_count > 5) {
                g_state.addLog("[POLL ALERT] High polling rate on " + f.url);
                urlStat.timestamps.clear();
            }
            
            // 2. [FLOOD] Same host > 20 requests in 5s
            auto& hostStat = hostHistory[f.host];
            hostStat.timestamps.push_back(f.ts);
            int flood_count = 0;
            for (auto t : hostStat.timestamps) {
                if (f.ts - t <= 5.0) flood_count++;
            }
            if (flood_count > 20) {
                g_state.addLog("[FLOOD ALERT] Too many requests to host: " + f.host);
                hostStat.timestamps.clear();
            }
            
            // 3. [RETRY] Repeated identical POST > 5x
            if (f.method == "POST") {
                auto& postStat = postHistory[f.url];
                postStat.timestamps.push_back(f.ts);
                int retry_count = 0;
                for (auto t : postStat.timestamps) {
                    if (f.ts - t <= 15.0) retry_count++;
                }
                if (retry_count > 5) {
                    g_state.addLog("[RETRY ALERT] Repeated POSTs to: " + f.url);
                    postStat.timestamps.clear();
                }
            }
            
            // 4. [SPIKE] bps > 5x 10s average AND > 5MB/s
            if (f.bandwidth_bps > 5LL * 1024 * 1024) {
                static std::vector<long long> recent_bps;
                long long avg = 0;
                if (!recent_bps.empty()) {
                    for (auto b : recent_bps) avg += b;
                    avg /= recent_bps.size();
                }
                recent_bps.push_back(f.bandwidth_bps);
                if (recent_bps.size() > 20) recent_bps.erase(recent_bps.begin());
                
                if (avg > 0 && f.bandwidth_bps > avg * 5) {
                    g_state.addLog("[SPIKE ALERT] Sudden bandwidth spike: " + std::to_string(f.bandwidth_bps / (1024*1024)) + " MB/s");
                    recent_bps.clear();
                }
            }
            
            // Cleanup old tracking data
            auto cleanup = [&](std::vector<double>& ts_list) {
                ts_list.erase(std::remove_if(ts_list.begin(), ts_list.end(),
                    [&](double t) { return f.ts - t > 30.0; }), ts_list.end());
            };
            cleanup(urlStat.timestamps);
            cleanup(hostStat.timestamps);
            if (f.method == "POST") cleanup(postHistory[f.url].timestamps);
        }
        
        Sleep(1000);
    }
}

void StartTrafficAnalyzer() {
    if (g_analyzer_running) return;
    g_analyzer_running = true;
    g_analyzer_thread = std::thread(AnalyzerLoop);
}

void StopTrafficAnalyzer() {
    g_analyzer_running = false;
    if (g_analyzer_thread.joinable()) {
        g_analyzer_thread.join();
    }
}
