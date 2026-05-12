#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include "app_data.h"
#include "network_monitor.h"
#include "../dns/dns_resolver.h"
#include "../process/process_mapper.h"

static std::atomic<bool> g_mon_running{false};
static std::thread       g_mon_thread;

// ── Helpers ─────────────────────────────────────────────────
static std::string StateStr(DWORD s) {
    switch(s) {
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        default:                       return "OTHER";
    }
}
static std::string FormatIP(DWORD addr) {
    IN_ADDR in; in.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, buf, sizeof(buf));
    return buf;
}

// ── Bandwidth tracking (per-connection) ─────────────────────
struct ConnKey {
    DWORD la, lp, ra, rp;
    bool operator<(const ConnKey& o) const {
        if(la!=o.la) return la<o.la;
        if(lp!=o.lp) return lp<o.lp;
        if(ra!=o.ra) return ra<o.ra;
        return rp<o.rp;
    }
};
struct ConnBW  { uint64_t prevIn=0, prevOut=0; bool enabled=false; };
static std::map<ConnKey, ConnBW> g_bw;

// Phase 4 — Request/Response flow tracking
struct ConnFlow {
    uint64_t prevIn  = 0;
    uint64_t prevOut = 0;
    bool     reqSent = false;   // true after outbound burst seen
};
static std::map<ConnKey, ConnFlow> g_flow;

static std::string FmtBytes(uint64_t b) {
    char buf[32];
    if(b >= 1024*1024) snprintf(buf,sizeof(buf),"%.1fMB",b/(1024.0*1024.0));
    else if(b >= 1024) snprintf(buf,sizeof(buf),"%.1fKB",b/1024.0);
    else               snprintf(buf,sizeof(buf),"%lluB",(unsigned long long)b);
    return buf;
}

static void EnableStats(const MIB_TCPROW_OWNER_PID& row) {
    MIB_TCPROW tr{row.dwState,row.dwLocalAddr,row.dwLocalPort,
                              row.dwRemoteAddr,row.dwRemotePort};
    TCP_ESTATS_DATA_RW_v0 rw{}; rw.EnableCollection = TRUE;
    SetPerTcpConnectionEStats(&tr, TcpConnectionEstatsData,
        (PUCHAR)&rw, 0, sizeof(rw), 0);
}
static bool ReadStats(const MIB_TCPROW_OWNER_PID& row,
                      uint64_t& bIn, uint64_t& bOut) {
    MIB_TCPROW tr{row.dwState,row.dwLocalAddr,row.dwLocalPort,
                              row.dwRemoteAddr,row.dwRemotePort};
    TCP_ESTATS_DATA_ROD_v0 rod{};
    ULONG rc = GetPerTcpConnectionEStats(&tr, TcpConnectionEstatsData,
        nullptr,0,0, nullptr,0,0, (PUCHAR)&rod,0,sizeof(rod));
    if(rc != NO_ERROR) return false;
    bIn=rod.DataBytesIn; bOut=rod.DataBytesOut;
    return true;
}

// ── Monitor loop ─────────────────────────────────────────────
static void MonitorLoop() {
    std::map<DWORD, std::set<std::string>> prevDomains;
    auto lastTick = std::chrono::steady_clock::now();

    while(g_mon_running) {
        // ── Fetch TCP table ──────────────────────────────────
        ULONG needed = 0;
        GetExtendedTcpTable(nullptr,&needed,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
        std::vector<BYTE> buf(needed + 512);
        if(GetExtendedTcpTable(buf.data(),&needed,FALSE,
                               AF_INET,TCP_TABLE_OWNER_PID_ALL,0) != NO_ERROR) {
            std::this_thread::sleep_for(std::chrono::seconds(2)); continue;
        }
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());

        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - lastTick).count();
        if(elapsed < 0.001) elapsed = 2.0;
        lastTick = now;

        std::vector<ConnectionEntry>  fresh;
        std::map<DWORD, ProcessEntry> freshProcs;
        std::map<DWORD, std::pair<uint64_t,uint64_t>> procBW;

        bool filterOn = g_state.filterEstablished.load();

        // ── Per-connection pass ──────────────────────────────
        for(DWORD i = 0; i < table->dwNumEntries; i++) {
            const auto& row = table->table[i];

            // Skip listeners always
            if(row.dwState == MIB_TCP_STATE_LISTEN) continue;

            // Filter: only ESTABLISHED when toggle is ON
            bool isEstab = (row.dwState == MIB_TCP_STATE_ESTAB);
            if(filterOn && !isEstab) continue;

            // Bandwidth tracking
            ConnKey key{row.dwLocalAddr,row.dwLocalPort,
                        row.dwRemoteAddr,row.dwRemotePort};
            auto& bwe = g_bw[key];
            if(!bwe.enabled) { EnableStats(row); bwe.enabled=true; }

            uint64_t totIn=0, totOut=0;
            if(ReadStats(row,totIn,totOut)) {
                uint64_t dIn  = totIn  >= bwe.prevIn  ? totIn  - bwe.prevIn  : 0;
                uint64_t dOut = totOut >= bwe.prevOut ? totOut - bwe.prevOut : 0;
                bwe.prevIn=totIn; bwe.prevOut=totOut;
                procBW[row.dwOwningPid].first  += dIn;
                procBW[row.dwOwningPid].second += dOut;

                // Phase 4: detect request/response bursts
                auto& fl = g_flow[key];
                std::string procName = GetProcessName(row.dwOwningPid);
                std::string remIP    = FormatIP(row.dwRemoteAddr);
                uint16_t    remPort  = ntohs((uint16_t)row.dwRemotePort);
                std::string domKey   = remIP + ":" + std::to_string(remPort);

                if(dOut >= 512 && !fl.reqSent) {
                    fl.reqSent = true;
                    g_state.addLog("[REQ] " + procName + " -> " + domKey
                        + "  sent:" + FmtBytes(dOut));
                }
                if(dIn >= 512 && fl.reqSent) {
                    fl.reqSent = false;
                    g_state.addLog("[RSP] " + procName + " <- " + domKey
                        + "  recv:" + FmtBytes(dIn));
                }
                fl.prevIn=totIn; fl.prevOut=totOut;
            }

            // Build connection entry
            ConnectionEntry ce;
            ce.pid         = row.dwOwningPid;
            ce.localAddr   = FormatIP(row.dwLocalAddr);
            ce.localPort   = ntohs((uint16_t)row.dwLocalPort);
            ce.remoteAddr  = FormatIP(row.dwRemoteAddr);
            ce.remotePort  = ntohs((uint16_t)row.dwRemotePort);
            ce.state       = StateStr(row.dwState);
            ce.processName = GetProcessName(ce.pid);
            ce.remoteDomain= ResolveIP(ce.remoteAddr);
            fresh.push_back(ce);

            // Update process entry
            auto& pe = freshProcs[ce.pid];
            pe.pid=ce.pid; pe.name=ce.processName; pe.connCount++;

            // Group into DomainStat (domain:port with count)
            std::string dom =
                (!ce.remoteDomain.empty() && ce.remoteDomain != "0.0.0.0")
                ? ce.remoteDomain : ce.remoteAddr;

            // "Only not show IP" rule:
            // Check if domain is purely an IPv4 address
            bool isIP = true;
            for(char c : dom) {
                if(!isdigit(c) && c != '.') { isIP = false; break; }
            }

            if(dom != "0.0.0.0" && !dom.empty() && !isIP) {
                bool found=false;
                for(auto& ds : pe.domainStats)
                    if(ds.domain==dom && ds.port==ce.remotePort){ds.count++;found=true;break;}
                if(!found) pe.domainStats.push_back({dom, ce.remotePort, 1});
            }
        }

        // ── Bandwidth bps ────────────────────────────────────
        for(auto& [pid, bwp] : procBW) {
            auto& pe = freshProcs[pid];
            pe.bpsIn  = (uint64_t)(bwp.first  / elapsed);
            pe.bpsOut = (uint64_t)(bwp.second / elapsed);
        }

        // Sort domainStats by count desc for each process
        for(auto& [pid, pe] : freshProcs)
            std::sort(pe.domainStats.begin(), pe.domainStats.end(),
                [](const DomainStat& a, const DomainStat& b){ return a.count > b.count; });

        // Phase 7: Smart Insights Engine
        static std::map<std::string, std::chrono::steady_clock::time_point> lastAlert;
        auto insightNow = std::chrono::steady_clock::now();

        for(auto& [pid, pe] : freshProcs) {
            // New app connected insight
            if(prevDomains.find(pid) == prevDomains.end() && !pe.domainStats.empty()) {
                g_state.addLog("[INSIGHT] [NEW] New app connected to network: " + pe.name);
            }

            // High bandwidth check (throttle alerts to once per 60s per app)
            if (pe.bpsIn > 500 * 1024) { // > 500 KB/s
                bool isStreaming = false;
                for(auto& ds : pe.domainStats) {
                    if(ds.domain.find("youtube") != std::string::npos ||
                       ds.domain.find("googlevideo") != std::string::npos ||
                       ds.domain.find("netflix") != std::string::npos ||
                       ds.domain.find("twitch") != std::string::npos) {
                        isStreaming = true;
                        break;
                    }
                }
                
                std::string alertKey = pe.name + (isStreaming ? "_stream" : "_bw");
                if (insightNow - lastAlert[alertKey] > std::chrono::seconds(60)) {
                    if (isStreaming) {
                        g_state.addLog("[INSIGHT] [STREAM] Video streaming detected on " + pe.name + " (" + FmtBytes(pe.bpsIn) + "/s)");
                    } else {
                        g_state.addLog("[INSIGHT] [HIGH-BW] High bandwidth usage by " + pe.name + " (" + FmtBytes(pe.bpsIn) + "/s)");
                    }
                    lastAlert[alertKey] = insightNow;
                }
            }

            // App-specific pattern checks
            for(auto& ds : pe.domainStats) {
                if(ds.domain.find("whatsapp.net") != std::string::npos || 
                   ds.domain.find("web.whatsapp.com") != std::string::npos) {
                    if(insightNow - lastAlert[pe.name+"_wa"] > std::chrono::seconds(300)) { // 5 min cooldown
                        g_state.addLog("[INSIGHT] [CHAT] WhatsApp messaging activity detected on " + pe.name);
                        lastAlert[pe.name+"_wa"] = insightNow;
                    }
                }
            }
        }

        // Log newly discovered domains
        for(auto& [pid, pe] : freshProcs)
            for(auto& ds : pe.domainStats)
                if(prevDomains[pid].find(ds.domain)==prevDomains[pid].end()) {
                    prevDomains[pid].insert(ds.domain);
                    g_state.addLog("[+] " + pe.name + " -> " + ds.domain);
                }

        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            g_state.connections = std::move(fresh);
            g_state.processes   = std::move(freshProcs);
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void StartNetworkMonitor() { g_mon_running=true; g_mon_thread=std::thread(MonitorLoop); }
void StopNetworkMonitor()  { g_mon_running=false; if(g_mon_thread.joinable()) g_mon_thread.join(); }
