#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../third_party/json/json.hpp"
#include <fstream>
#include <vector>

struct TrafficRule {
    std::string type = "BLOCK";
    std::string match = "domain";
    std::string pattern = "";
    std::string key = "";
    std::string value = "";
    bool enabled = true;
};

static std::vector<TrafficRule> g_rules;
static bool g_rulesLoaded = false;

void LoadRules() {
    g_rules.clear();
    std::ifstream f("proxy/rules.json");
    if (f.is_open()) {
        try {
            nlohmann::json j;
            f >> j;
            for (auto& item : j) {
                TrafficRule r;
                r.type = item.value("type", "BLOCK");
                r.match = item.value("match", "domain");
                r.pattern = item.value("pattern", "");
                r.key = item.value("key", "");
                r.value = item.value("value", "");
                r.enabled = item.value("enabled", true);
                g_rules.push_back(r);
            }
        } catch(...) {}
    }
    g_rulesLoaded = true;
}

void SaveRules() {
    nlohmann::json j = nlohmann::json::array();
    for (const auto& r : g_rules) {
        nlohmann::json item;
        item["type"] = r.type;
        item["match"] = r.match;
        item["pattern"] = r.pattern;
        if (!r.key.empty()) item["key"] = r.key;
        if (!r.value.empty()) item["value"] = r.value;
        item["enabled"] = r.enabled;
        j.push_back(item);
    }
    std::ofstream f("proxy/rules.json");
    f << j.dump(4);
}

void RenderRulesPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);
    if (!g_rulesLoaded) LoadRules();

    ImGui::TextColored(ImVec4(0, 0.8f, 0.6f, 1), "Traffic Rules (Phase 6)");
    ImGui::SameLine(ImGui::GetWindowWidth() - 250);
    if (ImGui::Button("Reload from Disk")) LoadRules();
    ImGui::SameLine();
    if (ImGui::Button("Save to Disk")) SaveRules();
    
    ImGui::Separator();
    
    if (ImGui::Button("+ Add Rule")) {
        g_rules.push_back(TrafficRule());
    }

    ImGui::BeginChild("RulesTableChild", ImVec2(0, 0), true);
    if (ImGui::BeginTable("RulesTable", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Enabled", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Match", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Pattern (e.g. domain.com)", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Key (Header)", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        int deleteIdx = -1;
        for (int i = 0; i < g_rules.size(); ++i) {
            auto& r = g_rules[i];
            ImGui::PushID(i);
            
            ImGui::TableNextRow();
            
            // Enabled
            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox("##enabled", &r.enabled);
            
            // Type
            ImGui::TableSetColumnIndex(1);
            const char* types[] = { "BLOCK", "BLOCK_KEYWORD", "INJECT_HEADER", "REWRITE_URL", "THROTTLE", "LOG_ONLY" };
            int current_type = 0;
            for (int t = 0; t < 6; ++t) { if (r.type == types[t]) current_type = t; }
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::Combo("##type", &current_type, types, 6)) r.type = types[current_type];
            
            // Match
            ImGui::TableSetColumnIndex(2);
            const char* matches[] = { "domain", "url", "header" };
            int current_match = 0;
            for (int m = 0; m < 3; ++m) { if (r.match == matches[m]) current_match = m; }
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::Combo("##match", &current_match, matches, 3)) r.match = matches[current_match];
            
            // Pattern
            ImGui::TableSetColumnIndex(3);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char patBuf[256];
            strncpy(patBuf, r.pattern.c_str(), sizeof(patBuf));
            if (ImGui::InputText("##pattern", patBuf, sizeof(patBuf))) r.pattern = patBuf;
            
            // Key
            ImGui::TableSetColumnIndex(4);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char keyBuf[128];
            strncpy(keyBuf, r.key.c_str(), sizeof(keyBuf));
            if (ImGui::InputText("##key", keyBuf, sizeof(keyBuf))) r.key = keyBuf;
            
            // Value
            ImGui::TableSetColumnIndex(5);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char valBuf[256];
            strncpy(valBuf, r.value.c_str(), sizeof(valBuf));
            if (ImGui::InputText("##value", valBuf, sizeof(valBuf))) r.value = valBuf;
            
            // Actions
            ImGui::TableSetColumnIndex(6);
            if (ImGui::Button("X")) deleteIdx = i;
            
            ImGui::PopID();
        }
        
        if (deleteIdx != -1) {
            g_rules.erase(g_rules.begin() + deleteIdx);
        }
        
        ImGui::EndTable();
    }
    ImGui::EndChild();
}
