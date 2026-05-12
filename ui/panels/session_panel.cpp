#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../core/traffic_db.h"
#include <vector>
#include <string>

static int g_selectedSessionId = -1;
static std::vector<ProxyFlow> g_sessionFlows;

void RenderSessionPanel() {
    // Only lock to query data, but actually SQLite queries shouldn't block the UI lock 
    // too long. For now we just query simply.
    
    ImGui::Columns(2, "session_columns", true);
    ImGui::SetColumnWidth(0, 250.0f);

    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "SQLite Sessions");
    ImGui::Separator();
    
    ImGui::BeginChild("SessionList", ImVec2(0, 0), true);
    auto sessions = TrafficDB::GetAllSessions();
    for (const auto& s : sessions) {
        bool is_selected = (g_selectedSessionId == s.first);
        std::string label = s.second + " (ID: " + std::to_string(s.first) + ")";
        if (ImGui::Selectable(label.c_str(), is_selected)) {
            g_selectedSessionId = s.first;
            g_sessionFlows = TrafficDB::LoadFlowsForSession(s.first, 1000, 0); // Load up to 1000 flows
        }
    }
    ImGui::EndChild();
    
    ImGui::NextColumn();
    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "Session Data (max 1000)");
    ImGui::Separator();
    
    ImGui::BeginChild("SessionDataList", ImVec2(0, 0), true);
    if (g_selectedSessionId == -1) {
        ImGui::TextDisabled("Select a session from the left.");
    } else {
        if (ImGui::BeginTable("SessionFlows", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Method");
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupColumn("Host");
            ImGui::TableSetupColumn("URL");
            ImGui::TableSetupColumn("ms");
            ImGui::TableHeadersRow();

            for (const auto& f : g_sessionFlows) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(f.method.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::Text("%d", f.status);
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(f.host.c_str());
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(f.url.c_str());
                ImGui::TableSetColumnIndex(4); ImGui::Text("%.0f", f.duration_ms);
            }
            ImGui::EndTable();
        }
    }
    ImGui::EndChild();
    
    ImGui::Columns(1);
}
