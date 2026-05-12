// core/settings_persist.cpp — Save / Load AppSettings to settings.json
// Placed alongside NetSense.exe in the release/ directory.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <fstream>
#include "app_data.h"
#include "../third_party/json/json.hpp"

using json = nlohmann::json;

static std::string SettingsPath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s(buf);
    auto slash = s.rfind('\\');
    if (slash != std::string::npos) s.resize(slash + 1);
    return s + "settings.json";
}

void LoadSettings() {
    std::ifstream f(SettingsPath());
    if (!f.is_open()) return;
    try {
        json j;
        f >> j;
        g_settings.proxyPort            = j.value("proxyPort",            g_settings.proxyPort);
        g_settings.uiScale              = j.value("uiScale",              g_settings.uiScale);
        g_settings.enableBodyPreview    = j.value("enableBodyPreview",    g_settings.enableBodyPreview);
        g_settings.storeFormData        = j.value("storeFormData",        g_settings.storeFormData);
        g_settings.encryptSensitiveFields = j.value("encryptSensitiveFields", g_settings.encryptSensitiveFields);
        g_settings.maxLiveFlows         = j.value("maxLiveFlows",         g_settings.maxLiveFlows);
        g_settings.maxLogLines          = j.value("maxLogLines",          g_settings.maxLogLines);
        g_settings.enableSQLite         = j.value("enableSQLite",         g_settings.enableSQLite);
        g_settings.mitmdumpPath         = j.value("mitmdumpPath",         g_settings.mitmdumpPath);
        g_settings.themeIndex           = j.value("themeIndex",           g_settings.themeIndex);
    } catch (...) {}
}

void SaveSettings() {
    json j;
    j["proxyPort"]              = g_settings.proxyPort;
    j["uiScale"]                = g_settings.uiScale;
    j["enableBodyPreview"]      = g_settings.enableBodyPreview;
    j["storeFormData"]          = g_settings.storeFormData;
    j["encryptSensitiveFields"] = g_settings.encryptSensitiveFields;
    j["maxLiveFlows"]           = g_settings.maxLiveFlows;
    j["maxLogLines"]            = g_settings.maxLogLines;
    j["enableSQLite"]           = g_settings.enableSQLite;
    j["mitmdumpPath"]           = g_settings.mitmdumpPath;
    j["themeIndex"]             = g_settings.themeIndex;

    std::ofstream f(SettingsPath());
    if (f.is_open()) f << j.dump(4);
}
