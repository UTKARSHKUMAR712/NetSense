#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include <string>
#include <vector>
#include "../../third_party/json/json.hpp"

static std::string g_inspectorFilter = "";
static std::string g_selectedFlowId = "";
static bool g_prettyReqH = true;
static bool g_prettyRspH = true;
static bool g_prettyBody = true;
static bool g_showFullscreen = false;
static std::string g_fullscreenText = "";
static std::string g_fullscreenTitle = "";

void RenderInspectorPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);

    // --- Top: Filter bar ---
    char filterBuf[256];
    strncpy(filterBuf, g_inspectorFilter.c_str(), sizeof(filterBuf));
    ImGui::Text("Filter:"); ImGui::SameLine();
    ImGui::SetNextItemWidth(300);
    if (ImGui::InputText("##InspectorFilter", filterBuf, sizeof(filterBuf))) {
        g_inspectorFilter = filterBuf;
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        g_inspectorFilter = "";
    }
    
    ImGui::Separator();

    // --- Middle: Flow table ---
    ImGui::BeginChild("FlowTableChild", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.5f), true);
    if (ImGui::BeginTable("InspectorFlows", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.2f);
        ImGui::TableSetupColumn("URL", ImGuiTableColumnFlags_WidthStretch, 0.6f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("ms", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();

        ProxyFlow* selectedFlow = nullptr;
        
        // Reverse iterate ring buffer for latest flows first
        for (auto it = g_state.proxyFlows.rbegin(); it != g_state.proxyFlows.rend(); ++it) {
            auto& f = *it;
            if (f.type != "RSP") continue; // Show only completed requests for now
            
            // Apply filter
            if (!g_inspectorFilter.empty()) {
                if (f.host.find(g_inspectorFilter) == std::string::npos && 
                    f.url.find(g_inspectorFilter) == std::string::npos &&
                    f.insight_tags.find(g_inspectorFilter) == std::string::npos) {
                    continue;
                }
            }

            ImGui::TableNextRow();
            
            // Make row selectable
            ImGui::TableSetColumnIndex(0);
            char timeBuf[64];
            time_t rawtime = (time_t)f.ts;
            struct tm* timeinfo = localtime(&rawtime);
            strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", timeinfo);
            
            bool is_selected = (g_selectedFlowId == f.id);
            if (ImGui::Selectable((std::string(timeBuf) + "##" + f.id).c_str(), is_selected, ImGuiSelectableFlags_SpanAllColumns)) {
                g_selectedFlowId = f.id;
            }
            if (is_selected) selectedFlow = &f;

            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(f.method.c_str());
            
            ImGui::TableSetColumnIndex(2);
            ImVec4 statusCol = ImVec4(1,1,1,1);
            if(f.status >= 200 && f.status < 300) statusCol = ImVec4(0,1,0,1);
            else if(f.status >= 300 && f.status < 400) statusCol = ImVec4(1,1,0,1);
            else if(f.status >= 400) statusCol = ImVec4(1,0,0,1);
            ImGui::TextColored(statusCol, "%d", f.status);
            
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(f.host.c_str());
            ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(f.url.c_str());
            ImGui::TableSetColumnIndex(5); ImGui::Text("%lld B", f.rsp_size);
            ImGui::TableSetColumnIndex(6); ImGui::Text("%.0f", f.duration_ms);
        }
        ImGui::EndTable();
        
        // --- Bottom: Expanded detail pane ---
        ImGui::EndChild();
        ImGui::Separator();
        
        ImGui::BeginChild("DetailPane", ImVec2(0, 0), true);
        if (selectedFlow) {
            ImGui::TextColored(ImVec4(0, 1, 0.6f, 1), "URL:"); ImGui::SameLine();
            ImGui::TextWrapped("%s", selectedFlow->url.c_str());
            ImGui::SameLine();
            if (ImGui::Button("Copy URL")) {
                ImGui::SetClipboardText(selectedFlow->url.c_str());
            }
            
            if (!selectedFlow->insight_tags.empty()) {
                ImGui::TextColored(ImVec4(1, 0.8f, 0, 1), "Tags: %s", selectedFlow->insight_tags.c_str());
            }

            ImGui::Spacing();
            if (ImGui::BeginTabBar("DetailTabs")) {
                
                auto RenderJsonTab = [](const char* label, const std::string& rawData, bool& prettyToggle) {
                    if (ImGui::BeginTabItem(label)) {
                        ImGui::Checkbox("Pretty Print JSON", &prettyToggle);
                        ImGui::SameLine();
                        if (ImGui::Button("Fullscreen")) {
                            g_fullscreenTitle = std::string(label) + " (Fullscreen)";
                            g_showFullscreen = true;
                        }
                        ImGui::SameLine();
                        if (ImGui::Button("Copy")) {
                            ImGui::SetClipboardText(rawData.c_str());
                        }
                        ImGui::Separator();
                        
                        std::string displayText = rawData;
                        if (prettyToggle && (displayText.rfind("{", 0) == 0 || displayText.rfind("[", 0) == 0)) {
                            try {
                                auto j = nlohmann::json::parse(displayText);
                                displayText = j.dump(4);
                            } catch (...) {
                                // Not valid JSON, keep original
                            }
                        }
                        
                        if (g_showFullscreen && g_fullscreenTitle.find(label) != std::string::npos) {
                            g_fullscreenText = displayText;
                        }
                        
                        ImGui::BeginChild((std::string(label) + "_child").c_str(), ImVec2(0, 0), true);
                        ImGui::InputTextMultiline("##content", (char*)displayText.c_str(), displayText.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
                        ImGui::EndChild();
                        ImGui::EndTabItem();
                    }
                };

                RenderJsonTab("Request Headers", selectedFlow->raw_req_headers, g_prettyReqH);
                RenderJsonTab("Response Headers", selectedFlow->raw_rsp_headers, g_prettyRspH);
                RenderJsonTab("Body Preview", selectedFlow->body_preview, g_prettyBody);

                ImGui::EndTabBar();
            }
        } else {
            ImGui::TextDisabled("Select a flow to view details.");
        }
        ImGui::EndChild();
    }
    
    if (g_showFullscreen) {
        ImGui::OpenPopup(g_fullscreenTitle.c_str());
    }
    
    ImGui::SetNextWindowSize(ImVec2(ImGui::GetIO().DisplaySize.x * 0.9f, ImGui::GetIO().DisplaySize.y * 0.9f), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal(g_fullscreenTitle.c_str(), &g_showFullscreen)) {
        ImGui::BeginChild("FS_Content", ImVec2(0, ImGui::GetContentRegionAvail().y - 40), true);
        ImGui::InputTextMultiline("##fs_txt", (char*)g_fullscreenText.c_str(), g_fullscreenText.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
        ImGui::EndChild();
        
        if (ImGui::Button("Close", ImVec2(120, 0))) {
            g_showFullscreen = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}
