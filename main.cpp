// ============================================================
//  NetSense+ — main.cpp
//  Entry point: init Winsock, start threads, run UI
// ============================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include "core/app_data.h"
#include "core/network_monitor.h"
#include "core/proxy_reader.h"
#include "core/traffic_db.h"
#include "analysis/traffic_analyzer.h"
#include "dns/dns_resolver.h"
#include "ui/main_ui.h"
#include "rules/rule_manager.h"
#include <fstream>
#include "third_party/json/json.hpp"

// ─── Global state (definition) ──────────────────────────────
AppState g_state;
AppSettings g_settings;

// ─── WinMain ────────────────────────────────────────────────
void LoadSettings() {
    std::ifstream f("netsense_settings.json");
    if (f.is_open()) {
        try {
            nlohmann::json j;
            f >> j;
            if (j.contains("proxyPort")) g_settings.proxyPort = j["proxyPort"];
            if (j.contains("enableBodyPreview")) g_settings.enableBodyPreview = j["enableBodyPreview"];
            if (j.contains("storeFormData")) g_settings.storeFormData = j["storeFormData"];
            if (j.contains("encryptSensitiveFields")) g_settings.encryptSensitiveFields = j["encryptSensitiveFields"];
            if (j.contains("uiScale")) g_settings.uiScale = j["uiScale"];
        } catch(...) {}
    }
}

void SaveSettings() {
    try {
        nlohmann::json j;
        j["proxyPort"] = g_settings.proxyPort;
        j["enableBodyPreview"] = g_settings.enableBodyPreview;
        j["storeFormData"] = g_settings.storeFormData;
        j["encryptSensitiveFields"] = g_settings.encryptSensitiveFields;
        j["uiScale"] = g_settings.uiScale;
        std::ofstream f("netsense_settings.json");
        f << j.dump(4);
    } catch(...) {}
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE,
                   LPSTR, int nCmdShow)
{
    // 1. Init Winsock
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxA(nullptr,
            "Failed to initialise Winsock.\n"
            "NetSense+ cannot start.",
            "NetSense+ Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    // 2. Load settings & Start background services
    LoadSettings();
    RuleManager::Load();
    
    TrafficDB::Initialize(g_settings.dbPath);
    g_state.currentSessionId = TrafficDB::StartSession("Session - " + std::to_string(time(NULL)));
    StartDnsResolver();
    StartNetworkMonitor();
    StartProxyReader();
    StartTrafficAnalyzer();

    // 3. Run UI (blocks until window is closed)
    int result = RunUI();

    // 4. Cleanup
    SaveSettings();
    g_state.running = false;
    StopTrafficAnalyzer();
    StopProxyServer();
    StopProxyReader();
    StopNetworkMonitor();
    StopDnsResolver();
    if (g_state.currentSessionId != -1) {
        TrafficDB::EndSession(g_state.currentSessionId);
    }
    TrafficDB::Shutdown();
    WSACleanup();

    return result;
}
