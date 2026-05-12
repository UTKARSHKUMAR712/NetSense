// core/settings_persist.cpp — Save / Load AppSettings to settings.json
// Versioned: bumping SETTINGS_VERSION triggers a migration comment in log.
// Backup: previous settings.json saved as settings.json.bak before overwrite.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <fstream>
#include "app_data.h"
#include "../third_party/json/json.hpp"

using json = nlohmann::json;

// ── Bump this when fields are added/removed/renamed ──────────
static constexpr int SETTINGS_VERSION = 2;

static std::string SettingsPath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s(buf);
    auto slash = s.rfind('\\');
    if (slash != std::string::npos) s.resize(slash + 1);
    return s + "settings.json";
}

static void MigrateSettings(json& j, int fromVersion) {
    // Version 1 → 2: added mitmdumpPath, themeIndex
    if (fromVersion < 2) {
        if (!j.contains("mitmdumpPath")) j["mitmdumpPath"] = "";
        if (!j.contains("themeIndex"))   j["themeIndex"]   = 0;
    }
    // Future: if (fromVersion < 3) { ... }
}

void LoadSettings() {
    std::ifstream f(SettingsPath());
    if (!f.is_open()) return;
    try {
        json j;
        f >> j;

        // Version check + migration
        int fileVer = j.value("version", 1);
        if (fileVer < SETTINGS_VERSION) {
            MigrateSettings(j, fileVer);
            // Will be saved with new version on next SaveSettings()
        }

        g_settings.proxyPort              = j.value("proxyPort",              g_settings.proxyPort);
        g_settings.uiScale                = j.value("uiScale",                g_settings.uiScale);
        g_settings.enableBodyPreview      = j.value("enableBodyPreview",      g_settings.enableBodyPreview);
        g_settings.storeFormData          = j.value("storeFormData",          g_settings.storeFormData);
        g_settings.encryptSensitiveFields = j.value("encryptSensitiveFields", g_settings.encryptSensitiveFields);
        g_settings.maxLiveFlows           = j.value("maxLiveFlows",           g_settings.maxLiveFlows);
        g_settings.maxLogLines            = j.value("maxLogLines",            g_settings.maxLogLines);
        g_settings.enableSQLite           = j.value("enableSQLite",           g_settings.enableSQLite);
        g_settings.mitmdumpPath           = j.value("mitmdumpPath",           g_settings.mitmdumpPath);
        g_settings.themeIndex             = j.value("themeIndex",             g_settings.themeIndex);
    } catch (...) {
        // Corrupted settings.json — rename as .corrupt and use defaults
        std::string path = SettingsPath();
        MoveFileA(path.c_str(), (path + ".corrupt").c_str());
    }
}

void SaveSettings() {
    std::string path    = SettingsPath();
    std::string bakPath = path + ".bak";

    // Backup existing file before overwrite (crash recovery)
    if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        CopyFileA(path.c_str(), bakPath.c_str(), FALSE);
    }

    json j;
    j["version"]              = SETTINGS_VERSION;  // always write version
    j["proxyPort"]            = g_settings.proxyPort;
    j["uiScale"]              = g_settings.uiScale;
    j["enableBodyPreview"]    = g_settings.enableBodyPreview;
    j["storeFormData"]        = g_settings.storeFormData;
    j["encryptSensitiveFields"] = g_settings.encryptSensitiveFields;
    j["maxLiveFlows"]         = g_settings.maxLiveFlows;
    j["maxLogLines"]          = g_settings.maxLogLines;
    j["enableSQLite"]         = g_settings.enableSQLite;
    j["mitmdumpPath"]         = g_settings.mitmdumpPath;
    j["themeIndex"]           = g_settings.themeIndex;

    std::ofstream f(path);
    if (f.is_open()) f << j.dump(4);
}
