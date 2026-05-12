#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../core/traffic_db.h"
#include <windows.h>
#include <commdlg.h>  // GetOpenFileNameA
#include <string>

// Helper: returns the directory that contains NetSense.exe (with trailing backslash)
static std::string ExeDir() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s(buf);
    auto slash = s.rfind('\\');
    if (slash != std::string::npos) s.resize(slash + 1);
    return s;
}

// Wipe every file matching pattern (supports wildcards via FindFirstFile)
static void DeleteGlob(const std::string& pattern) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string dir = pattern.substr(0, pattern.rfind('\\') + 1);
    do {
        DeleteFileA((dir + fd.cFileName).c_str());
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void RenderSettingsPanel() {
    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "NetSense+ Settings");
    ImGui::Separator();

    {
        std::lock_guard<std::mutex> lk(g_state.mtx);

        ImGui::Text("Core Settings");
        ImGui::InputInt("Proxy Port", &g_settings.proxyPort);

        if (ImGui::SliderFloat("UI Font Size Scale", &g_settings.uiScale, 0.5f, 2.5f, "%.2fx")) {
            ImGui::GetIO().FontGlobalScale = g_settings.uiScale * 0.5f;
        }

        ImGui::Spacing();
        ImGui::Text("Privacy & Capture");
        ImGui::Checkbox("Capture Body Content", &g_settings.enableBodyPreview);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Warning: Capturing body increases memory/disk usage.");
        ImGui::Checkbox("Capture Form Data", &g_settings.storeFormData);
        ImGui::Checkbox("XOR Encrypt Session Payloads (WIP)", &g_settings.encryptSensitiveFields);
    } // lock released before file ops below

    // ── Proxy Configuration ──────────────────────────────────
    ImGui::Spacing();
    ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "Proxy Configuration");
    ImGui::Separator();

    // mitmdump path
    {
        ImGui::Text("mitmdump.exe Path");
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Leave blank to auto-detect alongside NetSense.exe");
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 160);
        static char mitmBuf[MAX_PATH] = {};
        // Sync buffer from settings on first call
        static bool mitmBufInit = false;
        if (!mitmBufInit) {
            strncpy(mitmBuf, g_settings.mitmdumpPath.c_str(), MAX_PATH - 1);
            mitmBufInit = true;
        }
        if (ImGui::InputText("##mitmpath", mitmBuf, MAX_PATH))
            g_settings.mitmdumpPath = mitmBuf;

        ImGui::SameLine();
        if (ImGui::Button("Browse...", ImVec2(80, 0))) {
            OPENFILENAMEA ofn = {};
            char fileBuf[MAX_PATH] = {};
            strncpy(fileBuf, mitmBuf, MAX_PATH - 1);
            ofn.lStructSize  = sizeof(ofn);
            ofn.hwndOwner    = NULL;
            ofn.lpstrFilter  = "Executables (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile    = fileBuf;
            ofn.nMaxFile     = MAX_PATH;
            ofn.lpstrTitle   = "Select mitmdump.exe";
            ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&ofn)) {
                strncpy(mitmBuf, fileBuf, MAX_PATH - 1);
                g_settings.mitmdumpPath = fileBuf;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Auto", ImVec2(50, 0))) {
            mitmBuf[0] = '\0';
            g_settings.mitmdumpPath = "";
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Clear path and use auto-detect (mitmdump.exe next to NetSense.exe)");
    }

    // Detected/active path preview
    {
        std::string base = ExeDir();
        std::string autoPath = base + "mitmdump.exe";
        bool found = GetFileAttributesA(
            g_settings.mitmdumpPath.empty() ? autoPath.c_str()
                                            : g_settings.mitmdumpPath.c_str()
        ) != INVALID_FILE_ATTRIBUTES;
        if (found)
            ImGui::TextColored(ImVec4(0.2f,0.9f,0.3f,1), "  Status: mitmdump.exe found %s",
                g_settings.mitmdumpPath.empty() ? "(auto-detected)" : "(manual)");
        else
            ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "  Status: NOT FOUND — place mitmdump.exe at: %s",
                autoPath.c_str());
    }

    ImGui::Spacing();
    if (ImGui::Button("Save Settings", ImVec2(160, 0))) {
        SaveSettings();
        g_state.addLog("[SETTINGS] Settings saved to settings.json");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Saves all settings to release/settings.json (persists across restarts)");

    ImGui::Spacing();
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Data Management");
    ImGui::Separator();
    ImGui::TextDisabled("All paths are relative to the NetSense.exe directory.");
    ImGui::Spacing();

    std::string base = ExeDir();
    std::string proxyDir = base + "proxy\\";

    if (ImGui::Button("Delete Logs Only", ImVec2(170, 0))) {
        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            g_state.logLines.clear();
        }
        // Proxy log
        DeleteFileA((proxyDir + "netsense_proxy.log").c_str());
        DeleteFileA((proxyDir + "netsense_alerts.log").c_str());
        DeleteFileA((proxyDir + "netsense_saved_matches.jsonl").c_str());
        // Recording logs
        DeleteGlob(base + "recordings\\*.txt");
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Deletes: netsense_proxy.log, netsense_alerts.log, saved_matches.jsonl, recordings/*.txt");

    ImGui::SameLine();
    if (ImGui::Button("Delete DB Only", ImVec2(170, 0))) {
        TrafficDB::ClearDatabase();
        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            g_state.currentSessionId = -1;
        }
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Clears all sessions and flows from the SQLite database.");

    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button("Master Clean", ImVec2(170, 0))) {
        // 1. Clear in-memory state
        {
            std::lock_guard<std::mutex> lk(g_state.mtx);
            g_state.logLines.clear();
            g_state.proxyFlows.clear();
            g_state.currentSessionId = -1;
        }
        // 2. Wipe all log files
        DeleteFileA((proxyDir + "netsense_proxy.log").c_str());
        DeleteFileA((proxyDir + "netsense_alerts.log").c_str());
        DeleteFileA((proxyDir + "netsense_saved_matches.jsonl").c_str());
        DeleteGlob(base + "recordings\\*.txt");
        // 3. Clear database
        TrafficDB::ClearDatabase();
    }
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("WARNING: Deletes ALL logs, proxy history, saved matches, recordings, and database records.");
}
