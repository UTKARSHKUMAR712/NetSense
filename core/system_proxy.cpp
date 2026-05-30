#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wininet.h>
#include <string>
#include <cstdlib>
#include <string>
#include <cstdlib>
#include <thread>
#include "system_proxy.h"
#include "app_data.h"

// WinINet helper to notify the system of a proxy change
#pragma comment(lib, "wininet.lib")

// ─────────────────────────────────────────────────────────────
// Registry path for IE / WinINet proxy settings (applies system-wide)
// ─────────────────────────────────────────────────────────────
static const char* kRegPath =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

// ─────────────────────────────────────────────────────────────
// Snapshot of original settings
// ─────────────────────────────────────────────────────────────
struct ProxySnapshot {
    DWORD proxyEnable   = 0;
    std::string proxyServer;   // e.g. "http=host:port;https=host:port"
    std::string proxyOverride; // e.g. "<local>"
    bool valid = false;        // true if we saved something
};

static ProxySnapshot g_saved;
static bool          g_active = false;
static std::string   g_activeAddr;

// ─────────────────────────────────────────────────────────────
// Registry helpers
// ─────────────────────────────────────────────────────────────
static DWORD RegReadDword(HKEY hKey, const char* name, DWORD def = 0) {
    DWORD val = def, sz = sizeof(DWORD), type = REG_DWORD;
    RegQueryValueExA(hKey, name, nullptr, &type,
                     reinterpret_cast<LPBYTE>(&val), &sz);
    return val;
}

static std::string RegReadStr(HKEY hKey, const char* name) {
    char buf[2048] = {};
    DWORD sz = sizeof(buf), type = REG_SZ;
    RegQueryValueExA(hKey, name, nullptr, &type,
                     reinterpret_cast<LPBYTE>(buf), &sz);
    return buf;
}

static void RegWriteDword(HKEY hKey, const char* name, DWORD val) {
    RegSetValueExA(hKey, name, 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&val), sizeof(DWORD));
}

static void RegWriteStr(HKEY hKey, const char* name, const std::string& val) {
    RegSetValueExA(hKey, name, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(val.c_str()),
                   static_cast<DWORD>(val.size() + 1));
}

static void RegDeleteVal(HKEY hKey, const char* name) {
    RegDeleteValueA(hKey, name);
}

// ─────────────────────────────────────────────────────────────
// Notify WinINet that proxy settings changed (flushes DNS/conn cache)
// ─────────────────────────────────────────────────────────────
static void NotifyProxyChange() {
    // Tell all open WinINet handles to re-read proxy config.
    // Run in a detached thread because InternetSetOption broadcasts 
    // WM_SETTINGCHANGE which can block/freeze if any system window is hung.
    std::thread([](){
        InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
        InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    }).detach();
}

// ─────────────────────────────────────────────────────────────
// atexit() guard — ensures we always restore on crash/exit
// ─────────────────────────────────────────────────────────────
static void AtExitRestore() {
    SystemProxy::Restore();
}

// ═════════════════════════════════════════════════════════════
// Public API
// ═════════════════════════════════════════════════════════════
namespace SystemProxy {

bool Activate(int port) {
    if (g_active) return true;  // already set

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kRegPath, 0,
                      KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        g_state.addLog("[PROXY] ERROR: Could not open WinINet registry key.");
        return false;
    }

    // ── 1. Snapshot existing settings ─────────────────────────
    g_saved.proxyEnable   = RegReadDword(hKey, "ProxyEnable", 0);
    g_saved.proxyServer   = RegReadStr  (hKey, "ProxyServer");
    g_saved.proxyOverride = RegReadStr  (hKey, "ProxyOverride");
    g_saved.valid         = true;

    // ── 2. Set our proxy ──────────────────────────────────────
    std::string addr = "127.0.0.1:" + std::to_string(port);
    // Point ALL protocols through our proxy
    std::string server = "http=" + addr + ";https=" + addr +
                         ";ftp=" + addr + ";socks=" + addr;
    // Bypass localhost/LAN as usual
    std::string bypass = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";

    RegWriteDword(hKey, "ProxyEnable",   1);
    RegWriteStr  (hKey, "ProxyServer",   server);
    RegWriteStr  (hKey, "ProxyOverride", bypass);

    RegCloseKey(hKey);
    NotifyProxyChange();

    g_active     = true;
    g_activeAddr = addr;

    g_state.addLog("[PROXY] System proxy activated -> " + addr);
    g_state.addLog("[PROXY] All HTTP/HTTPS traffic now routed through NetSense+");

    // Register crash-safe restore
    std::atexit(AtExitRestore);
    return true;
}

void Restore() {
    if (!g_active) return;
    g_active = false;   // Prevent double-restore

    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kRegPath, 0,
                      KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        // Can't open key — nothing we can do
        return;
    }

    if (g_saved.valid) {
        // Restore exactly what was there
        RegWriteDword(hKey, "ProxyEnable", g_saved.proxyEnable);

        if (!g_saved.proxyServer.empty())
            RegWriteStr(hKey, "ProxyServer", g_saved.proxyServer);
        else
            RegDeleteVal(hKey, "ProxyServer");

        if (!g_saved.proxyOverride.empty())
            RegWriteStr(hKey, "ProxyOverride", g_saved.proxyOverride);
        else
            RegDeleteVal(hKey, "ProxyOverride");
    } else {
        // Nothing was saved — just disable the proxy
        RegWriteDword(hKey, "ProxyEnable", 0);
    }

    RegCloseKey(hKey);
    NotifyProxyChange();

    g_state.addLog("[PROXY] System proxy restored to original settings.");
}

bool IsActive() {
    return g_active;
}

std::string ActiveAddress() {
    return g_activeAddr;
}

} // namespace SystemProxy
