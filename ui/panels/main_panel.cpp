#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../core/proxy_reader.h"
#include "../../core/system_proxy.h"
#include <string>
#include <vector>
#include <algorithm>
#include <deque>
#include <fstream>
#include <filesystem>

static DWORD g_selectedPID = 0;
static bool g_filterReq = true;
static bool g_filterRsp = true;



static std::string FmtSpeed(uint64_t bps) {
    char buf[32];
    if(bps >= 1024*1024) snprintf(buf,sizeof(buf),"%.1fMB/s", bps/(1024.0*1024.0));
    else if(bps >= 1024) snprintf(buf,sizeof(buf),"%.1fKB/s", bps/1024.0);
    else                 snprintf(buf,sizeof(buf),"%lluB/s",(unsigned long long)bps);
    return buf;
}

#include "panels.h"

void RenderNetworkPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);

    static bool showRecordModal = false;
    static bool showViewerModal = false;
    static std::vector<ProcessEntry> modalProcs;
    static std::vector<std::string> viewerFiles;
    static std::vector<std::string> viewerLogLines;
    static int viewerSelectedFile = -1;
    static char logSearch[128] = "";

    // Top split: left = Process List, right = Domains
    ImGui::Columns(2, "main_columns", true);
    ImGui::SetColumnWidth(0, 350.0f);

    // --- LEFT PANEL: Process List ---
    ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.6f, 1.0f), "Active Processes");
    ImGui::Separator();
    
    std::vector<ProcessEntry> procs;
    for(auto& [pid, pe] : g_state.processes) procs.push_back(pe);
    std::sort(procs.begin(), procs.end(), [](auto& a, auto& b){ return a.bpsIn > b.bpsIn; });

    uint64_t maxBw = 1;
    for(const auto& pe : procs) {
        if(pe.bpsIn > maxBw) maxBw = pe.bpsIn;
        if(pe.bpsOut > maxBw) maxBw = pe.bpsOut;
    }

    if (ImGui::Selectable("Show All (Clear Focus)", g_selectedPID == 0)) {
        g_selectedPID = 0;
    }

    ImGui::BeginChild("ProcessList", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.6f), true);
    
    ImGui::Columns(3, "proc_cols", false);
    ImGui::SetColumnWidth(0, 150.0f);
    ImGui::SetColumnWidth(1, 100.0f);
    
    for (const auto& pe : procs) {
        bool isSelected = (g_selectedPID == pe.pid);
        
        // Col 1: Name (with hidden PID for unique ImGui ID)
        std::string selectableLabel = pe.name + "##" + std::to_string(pe.pid);
        if (ImGui::Selectable(selectableLabel.c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
            g_selectedPID = pe.pid;
        }
        ImGui::NextColumn();
        
        // Col 2: Native GPU Rectangle Bar
        float maxW = 100.0f;
        float barWidth = (maxBw > 0) ? ((float)pe.bpsIn / (float)maxBw) * maxW : 0;
        if (pe.bpsIn > 0 && barWidth < 2.0f) barWidth = 2.0f; // min visible bar
        
        ImVec2 p = ImGui::GetCursorScreenPos();
        float barHeight = ImGui::GetTextLineHeight() * 0.8f;
        ImGui::GetWindowDrawList()->AddRectFilled(
            ImVec2(p.x, p.y + 2), 
            ImVec2(p.x + barWidth, p.y + 2 + barHeight), 
            IM_COL32(0, 210, 140, 255)
        );
        ImGui::Dummy(ImVec2(maxW, barHeight)); // Advance cursor safely
        ImGui::NextColumn();
        
        // Col 3: Speed
        ImGui::Text("%s", FmtSpeed(pe.bpsIn).c_str());
        ImGui::NextColumn();
    }
    ImGui::Columns(1);
    ImGui::EndChild();

    ImGui::NextColumn();

    // --- RIGHT TOP PANEL: Domains ---
    ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.6f, 1.0f), g_selectedPID == 0 ? "All Active Domains" : ("Domains: " + g_state.processes[g_selectedPID].name).c_str());
    ImGui::Separator();
    
    ImGui::BeginChild("DomainList", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.4f), true);
    if (ImGui::BeginTable("domains_table", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Process");
        ImGui::TableSetupColumn("Domain / IP");
        ImGui::TableSetupColumn("Port");
        ImGui::TableSetupColumn("Connections");
        ImGui::TableHeadersRow();

        auto renderDomains = [&](const ProcessEntry& pe) {
            for (const auto& ds : pe.domainStats) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(pe.name.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(ds.domain.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%u", ds.port);
                ImGui::TableSetColumnIndex(3); ImGui::Text("%d", ds.count);
            }
        };

        if (g_selectedPID == 0) {
            for (const auto& pe : procs) renderDomains(pe);
        } else {
            renderDomains(g_state.processes[g_selectedPID]);
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::Columns(1);
    ImGui::Separator();

    // --- BOTTOM PANEL: Requests & Insights ---
    ImGui::TextColored(ImVec4(0.0f, 0.8f, 0.6f, 1.0f), "Network & Proxy Logs");
    ImGui::SameLine();
    ImGui::Checkbox("REQ", &g_filterReq); ImGui::SameLine();
    ImGui::Checkbox("RESP", &g_filterRsp);
    
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 450);
    ImGui::SetNextItemWidth(150);
    ImGui::InputText("##Search", logSearch, sizeof(logSearch));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Search logs...");
    
    // Moved Record Button here
    ImGui::SameLine();
    if (ImGui::Button(g_state.recording ? "Stop Record" : "[REC] Record")) {
        if(g_state.recording) {
            g_state.recording = false;
            if(g_state.recordStream.is_open()) g_state.recordStream.close();
        } else {
            showRecordModal = true;
            modalProcs = procs; // Freeze list for the modal dropdown
        }
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Record traffic to a text file");
    
    ImGui::SameLine();
    if (ImGui::Button("[DIR] Recordings")) {
        showViewerModal = true;
        viewerFiles.clear();
        viewerSelectedFile = -1;
        viewerLogLines.clear();
        
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA("recordings\\*.txt", &fd);
        if(hFind != INVALID_HANDLE_VALUE) {
            do {
                if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) viewerFiles.push_back(fd.cFileName);
            } while(FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    if (g_state.recording) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "[RECORDING]");
    }
    
    ImGui::BeginChild("LogPanel", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysVerticalScrollbar);
    
    for (const auto& line : g_state.logLines) {
        if (!g_filterReq && line.find("[REQ]") != std::string::npos) continue;
        if (!g_filterRsp && line.find("[RSP]") != std::string::npos) continue;
        
        // Search Filter
        if (logSearch[0] != '\0') {
            std::string lowerLine = line;
            std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
            std::string lowerSearch = logSearch;
            std::transform(lowerSearch.begin(), lowerSearch.end(), lowerSearch.begin(), ::tolower);
            if (lowerLine.find(lowerSearch) == std::string::npos) continue;
        }
        
        // Strict Focus Mode Filtering
        if (g_selectedPID != 0) {
            const auto& pe = g_state.processes[g_selectedPID];
            
            if (line.find(pe.name) != std::string::npos || line.find("INSIGHT") != std::string::npos) {
                // Network logs mentioning process pass cleanly
            } else if (line.find("MITM") != std::string::npos) {
                // For proxy logs, check if URL touches any domain this process owns
                bool domainMatched = false;
                for(const auto& ds : pe.domainStats) {
                    if (line.find(ds.domain) != std::string::npos) {
                        domainMatched = true; break;
                    }
                }
                if (!domainMatched) continue; // Hide unrelated proxy traffic
            } else {
                continue;
            }
        }

        ImVec4 col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
        if (line.find("INSIGHT") != std::string::npos) col = ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
        else if (line.find("MITM REQ") != std::string::npos) col = ImVec4(0.0f, 1.0f, 1.0f, 1.0f);
        else if (line.find("MITM RSP") != std::string::npos) col = ImVec4(0.6f, 0.8f, 1.0f, 1.0f);
        else if (line.find("[REQ]") != std::string::npos) col = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);
        else if (line.find("[RSP]") != std::string::npos) col = ImVec4(0.5f, 1.0f, 0.5f, 1.0f);
        
        ImGui::TextColored(col, "%s", line.c_str());
    }
    
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
        
    ImGui::EndChild();

    // --- Recording Modal Logic ---
    if (showRecordModal) {
        ImGui::OpenPopup("Start Recording");
        showRecordModal = false;
    }
    
    // Dim background for modal
    ImVec4* colors = ImGui::GetStyle().Colors;
    colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.7f);
    
    if (ImGui::BeginPopupModal("Start Recording", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Select Application to Record:");
        ImGui::Separator();
        
        static int item_current = 0;
        std::vector<std::string> items;
        std::vector<std::string> displayItems;
        
        items.push_back("All Traffic");
        displayItems.push_back("All Traffic");
        for(auto& p : modalProcs) {
            items.push_back(p.name);
            displayItems.push_back(p.name + " (PID: " + std::to_string(p.pid) + ")");
        }
        
        if (ImGui::BeginCombo("Target", displayItems[item_current].c_str())) {
            for (int n = 0; n < displayItems.size(); n++) {
                bool is_selected = (item_current == n);
                // Unique display label
                if (ImGui::Selectable(displayItems[n].c_str(), is_selected)) item_current = n;
                if (is_selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        
        ImGui::Spacing();
        if (ImGui::Button("Start Recording", ImVec2(120, 0))) {
            system("mkdir recordings 2>nul");
            char fname[256];
            snprintf(fname, sizeof(fname), "recordings\\capture_%llu.txt", (unsigned long long)time(NULL));
            g_state.recordStream.open(fname);
            g_state.recordTarget = (item_current == 0) ? "" : items[item_current];
            g_state.recording = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    
    // --- Recordings Viewer Modal ---
    if (showViewerModal) {
        ImGui::OpenPopup("Recordings Viewer");
        showViewerModal = false;
    }
    
    ImGui::SetNextWindowSize(ImVec2(800, 500), ImGuiCond_FirstUseEver);
    if (ImGui::BeginPopupModal("Recordings Viewer", NULL, ImGuiWindowFlags_NoSavedSettings)) {
        ImGui::Columns(2, "viewer_columns", true);
        ImGui::SetColumnWidth(0, 200.0f);
        
        ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "Capture Files");
        ImGui::Separator();
        ImGui::BeginChild("FileList", ImVec2(0, ImGui::GetContentRegionAvail().y - 40), true);
        for (int i = 0; i < viewerFiles.size(); i++) {
            if (ImGui::Selectable(viewerFiles[i].c_str(), viewerSelectedFile == i)) {
                viewerSelectedFile = i;
                viewerLogLines.clear();
                std::string path = "recordings\\" + viewerFiles[i];
                std::ifstream ifs(path);
                if (ifs.is_open()) {
                    std::string line;
                    while (std::getline(ifs, line)) {
                        if (!line.empty()) viewerLogLines.push_back(line);
                    }
                }
            }
        }
        ImGui::EndChild();
        ImGui::NextColumn();
        
        ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "File Contents");
        ImGui::Separator();
        ImGui::BeginChild("FileContent", ImVec2(0, ImGui::GetContentRegionAvail().y - 40), true, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_HorizontalScrollbar);
        for (const auto& line : viewerLogLines) {
            ImVec4 col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
            if (line.find("INSIGHT") != std::string::npos) col = ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
            else if (line.find("MITM REQ") != std::string::npos) col = ImVec4(0.0f, 1.0f, 1.0f, 1.0f);
            else if (line.find("MITM RSP") != std::string::npos) col = ImVec4(0.6f, 0.8f, 1.0f, 1.0f);
            else if (line.find("[REQ]") != std::string::npos) col = ImVec4(1.0f, 0.5f, 0.0f, 1.0f);
            else if (line.find("[RSP]") != std::string::npos) col = ImVec4(0.5f, 1.0f, 0.5f, 1.0f);
            ImGui::TextColored(col, "%s", line.c_str());
        }
        ImGui::EndChild();
        ImGui::Columns(1);
        
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 100);
        if (ImGui::Button("Close", ImVec2(80, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void RenderMainPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    
    ImGui::Begin("Dashboard", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
    ImGui::PopStyleVar(2);

    if (ImGui::BeginMenuBar()) {
        ImGui::TextColored(ImVec4(0, 1, 0.6f, 1), "NetSense+ v3.0");
        ImGui::Separator();
        bool filterOn = g_state.filterEstablished.load();
        if (ImGui::Checkbox("Established Only", &filterOn)) {
            g_state.filterEstablished.store(filterOn);
        }
        ImGui::Separator();

        // ── Live proxy status indicator ──────────────────────
        if (SystemProxy::IsActive()) {
            ImGui::TextColored(ImVec4(0.1f, 1.0f, 0.4f, 1.0f),
                "[PROXY ACTIVE]  %s", SystemProxy::ActiveAddress().c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip(
                    "All system traffic is routed through NetSense+.\n"
                    "Proxy will auto-restore when you close the app.");
            ImGui::SameLine();
            // Power-user manual stop
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f,0.15f,0.15f,1.0f));
            if (ImGui::SmallButton("Stop")) {
                SystemProxy::Restore();
                StopProxyServer();
            }
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Manually stop proxy and restore system settings.");
        } else {
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "[PROXY OFF]");
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Proxy is not active. Click Restart to re-enable.");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.1f,0.5f,0.2f,1.0f));
            if (ImGui::SmallButton("Restart Proxy")) {
                StartProxyServer();
                SystemProxy::Activate(g_settings.proxyPort);
            }
            ImGui::PopStyleColor();
        }

        ImGui::Separator();
        if (ImGui::Button("Clear Logs")) g_state.logLines.clear();
        ImGui::EndMenuBar();
    }

    if (ImGui::BeginTabBar("MainTabs")) {
        if (ImGui::BeginTabItem("[NET] Network")) {
            g_state.mtx.unlock();
            RenderNetworkPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("[PROXY] Inspector")) {
            g_state.mtx.unlock();
            RenderInspectorPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("[RULES] Rules")) {
            g_state.mtx.unlock();
            RenderRulesPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("[RT] Runtime")) {
            g_state.mtx.unlock();
            RenderRuleRuntimePanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("[SESSION] History")) {
            g_state.mtx.unlock();
            RenderSessionPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("[CATCHER] Vault")) {
            g_state.mtx.unlock();
            RenderCatcherPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("[>_] Settings")) {
            g_state.mtx.unlock();
            RenderSettingsPanel();
            g_state.mtx.lock();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}
