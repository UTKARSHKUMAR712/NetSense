#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <psapi.h>
#include <string>
#include <map>
#include <mutex>
#include "process_mapper.h"

static std::map<DWORD, std::string> g_proc_cache;
static std::mutex                   g_proc_mtx;

std::string GetProcessName(DWORD pid) {
    if (pid == 0 || pid == 4) return "System";

    {
        std::lock_guard<std::mutex> lk(g_proc_mtx);
        auto it = g_proc_cache.find(pid);
        if (it != g_proc_cache.end()) return it->second;
    }

    HANDLE h = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!h) return "Unknown";

    char buf[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    std::string name;

    if (QueryFullProcessImageNameA(h, 0, buf, &sz)) {
        std::string path(buf, sz);
        auto pos = path.find_last_of("\\/");
        name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
    } else {
        // Fallback
        if (GetModuleFileNameExA(h, nullptr, buf, MAX_PATH)) {
            std::string path(buf);
            auto pos = path.find_last_of("\\/");
            name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
        } else {
            name = "PID:" + std::to_string(pid);
        }
    }
    CloseHandle(h);

    // Strip .exe suffix for display
    if (name.size() > 4 &&
        name.substr(name.size() - 4) == ".exe") {
        name = name.substr(0, name.size() - 4);
    }

    {
        std::lock_guard<std::mutex> lk(g_proc_mtx);
        g_proc_cache[pid] = name;
    }
    return name;
}

void ClearProcessCache() {
    std::lock_guard<std::mutex> lk(g_proc_mtx);
    g_proc_cache.clear();
}
