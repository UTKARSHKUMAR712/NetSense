#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <map>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include "dns_resolver.h"

static std::map<std::string, std::string> g_dns_cache;
static std::queue<std::string>            g_dns_queue;
static std::mutex                         g_cache_mtx;
static std::mutex                         g_queue_mtx;
static std::atomic<bool>                  g_dns_running{false};
static std::thread                        g_dns_thread;

std::string ResolveIP(const std::string& ip) {
    if (ip.empty() || ip == "0.0.0.0") return ip;
    {
        std::lock_guard<std::mutex> lk(g_cache_mtx);
        auto it = g_dns_cache.find(ip);
        if (it != g_dns_cache.end()) return it->second;
    }
    // Queue for background resolution
    {
        std::lock_guard<std::mutex> lk(g_queue_mtx);
        // Avoid duplicate queuing
        g_dns_queue.push(ip);
        // Pre-cache with raw IP so we don't queue again
    }
    {
        std::lock_guard<std::mutex> lk(g_cache_mtx);
        g_dns_cache[ip] = ip; // placeholder
    }
    return ip;
}

// Execute ipconfig /displaydns without opening a console window
static std::string ExecIpconfig() {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";

    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    char cmd[] = "ipconfig /displaydns";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "";
    }
    CloseHandle(hWrite);

    std::string out;
    char buf[4096];
    DWORD read;
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &read, NULL) && read > 0) {
        buf[read] = 0;
        out += buf;
    }
    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 1000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}

static void UpdateCacheFromIpconfig() {
    std::string out = ExecIpconfig();
    std::istringstream iss(out);
    std::string line;
    std::string curName;

    std::map<std::string, std::string> newMap;

    while (std::getline(iss, line)) {
        // Strip \r
        if(!line.empty() && line.back() == '\r') line.pop_back();

        if (line.find("Record Name") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                curName = line.substr(pos + 1);
                // Trim
                curName.erase(0, curName.find_first_not_of(" \t"));
                curName.erase(curName.find_last_not_of(" \t") + 1);
            }
        }
        else if (line.find("A (Host) Record") != std::string::npos) {
            auto pos = line.find(':');
            if (pos != std::string::npos && !curName.empty()) {
                std::string ip = line.substr(pos + 1);
                ip.erase(0, ip.find_first_not_of(" \t"));
                ip.erase(ip.find_last_not_of(" \t") + 1);
                
                // Exclude reverse dns names from cache to keep clean domains
                if(curName.find(".in-addr.arpa") == std::string::npos &&
                   curName.find("mshome.net") == std::string::npos) {
                    newMap[ip] = curName;
                }
            }
        }
    }

    if(!newMap.empty()) {
        std::lock_guard<std::mutex> lk(g_cache_mtx);
        for(auto& pair : newMap) {
            g_dns_cache[pair.first] = pair.second;
        }
    }
}

static void DnsWorker() {
    auto lastIpconfig = std::chrono::steady_clock::now();
    UpdateCacheFromIpconfig();

    while (g_dns_running) {
        auto now = std::chrono::steady_clock::now();
        if(std::chrono::duration_cast<std::chrono::seconds>(now - lastIpconfig).count() >= 10) {
            UpdateCacheFromIpconfig();
            lastIpconfig = now;
        }
        std::string ip;
        {
            std::lock_guard<std::mutex> lk(g_queue_mtx);
            if (!g_dns_queue.empty()) {
                ip = g_dns_queue.front();
                g_dns_queue.pop();
            }
        }

        if (!ip.empty()) {
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

            char host[NI_MAXHOST] = {};
            int r = getnameinfo(reinterpret_cast<sockaddr*>(&sa),
                                sizeof(sa), host, NI_MAXHOST,
                                nullptr, 0, 0);

            std::string resolved = (r == 0 && host[0] != '\0') ? host : ip;

            std::lock_guard<std::mutex> lk(g_cache_mtx);
            g_dns_cache[ip] = resolved;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void StartDnsResolver() {
    g_dns_running = true;
    g_dns_thread = std::thread(DnsWorker);
}

void StopDnsResolver() {
    g_dns_running = false;
    if (g_dns_thread.joinable()) g_dns_thread.join();
}
