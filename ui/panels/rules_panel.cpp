#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../rules/rule_manager.h"
#include "../../rules/rule_types.h"
#include "../../third_party/json/json.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <ctime>

// ──────────────────────────────────────────────────────────────
//  Predefined pack data (loaded from proxy/predefined_packs.json)
// ──────────────────────────────────────────────────────────────
struct PredefPack {
    std::string id;
    std::string name;
    std::string category;
    std::string description;
    std::vector<nlohmann::json> rules;
    bool enabled    = false;
    bool expanded   = false;
    int  hitCount   = 0;  // sum of all rule hits in pack
};

static std::vector<PredefPack> g_packs;
static bool g_packsLoaded = false;
static char g_packSearch[128] = {};

static void LoadPredefinedPacks() {
    g_packs.clear();
    std::ifstream f("proxy/predefined_packs.json");
    if (!f.is_open()) return;
    try {
        nlohmann::json j;
        f >> j;
        for (auto& item : j) {
            PredefPack p;
            p.id          = item.value("id", "");
            p.name        = item.value("name", "?");
            p.category    = item.value("category", "");
            p.description = item.value("description", "");
            if (item.contains("rules") && item["rules"].is_array()) {
                for (auto& r : item["rules"]) p.rules.push_back(r);
            }
            g_packs.push_back(p);
        }
    } catch (...) {}
    g_packsLoaded = true;
}

// Import all rules from a pack into the live custom rules list
static void ImportPackIntoCustomRules(const PredefPack& pack) {
    for (const auto& r : pack.rules) {
        TrafficRule rule;
        rule.id          = pack.id + "_" + std::to_string(RuleManager::g_rules.size());
        rule.type        = r.value("type", "BLOCK");
        rule.match       = r.value("match", "domain");
        rule.pattern     = r.value("pattern", "");
        rule.key         = r.value("key", "");
        rule.value       = r.value("value", "");
        rule.description = r.value("description", "");
        rule.category    = pack.category;
        rule.enabled     = true;
        rule.priority    = 50;
        RuleManager::g_rules.push_back(rule);
    }
    RuleManager::Save();
}

// ──────────────────────────────────────────────────────────────
//  Category → Color mapping
// ──────────────────────────────────────────────────────────────
static ImVec4 CategoryColor(const std::string& cat) {
    if (cat == "Privacy")         return ImVec4(0.2f, 0.8f, 0.4f, 1.0f);
    if (cat == "Security")        return ImVec4(0.3f, 0.6f, 1.0f, 1.0f);
    if (cat == "Gaming")          return ImVec4(1.0f, 0.6f, 0.0f, 1.0f);
    if (cat == "Analysis")        return ImVec4(0.8f, 0.8f, 0.2f, 1.0f);
    if (cat == "Monitoring")      return ImVec4(0.9f, 0.4f, 0.9f, 1.0f);
    if (cat == "Development")     return ImVec4(0.4f, 0.9f, 0.9f, 1.0f);
    if (cat == "Content Control") return ImVec4(1.0f, 0.4f, 0.4f, 1.0f);
    if (cat == "Protection")      return ImVec4(0.5f, 1.0f, 0.8f, 1.0f);
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f); // Custom / Default
}

// Rule type → Color
static ImVec4 RuleTypeColor(const std::string& type) {
    if (type == "BLOCK" || type == "BLOCK_KEYWORD" ||
        type == "BLOCK_METHOD" || type == "BLOCK_MEDIA" || type == "BLOCK_TRACKERS")
        return ImVec4(1.0f, 0.3f, 0.3f, 1.0f); // red
    if (type == "INJECT_HEADER" || type == "RESPONSE_HEADER_INJECT")
        return ImVec4(0.3f, 0.9f, 0.5f, 1.0f); // green
    if (type == "THROTTLE" || type == "LIMIT_BANDWIDTH")
        return ImVec4(1.0f, 0.7f, 0.0f, 1.0f); // orange
    if (type == "REDIRECT" || type == "REWRITE_URL")
        return ImVec4(0.4f, 0.6f, 1.0f, 1.0f); // blue
    if (type == "MODIFY_JSON")
        return ImVec4(1.0f, 0.5f, 1.0f, 1.0f); // purple
    if (type == "LOG_ONLY" || type == "ALERT_ON_MATCH" || type == "SAVE_MATCHES")
        return ImVec4(0.8f, 0.8f, 0.3f, 1.0f); // yellow
    return ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
}

// ──────────────────────────────────────────────────────────────
//  Custom Rules Sub-Tab
// ──────────────────────────────────────────────────────────────
static void RenderCustomRulesTab() {
    // Toolbar
    if (!RuleManager::g_rulesLoaded) RuleManager::Load();

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.6f, 0.3f, 1.0f));
    if (ImGui::Button("+ Add Rule")) {
        TrafficRule r;
        r.id = "rule_" + std::to_string(time(nullptr));
        RuleManager::g_rules.push_back(r);
    }
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::Button("Reload")) RuleManager::Load();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.2f, 0.2f, 1.0f));
    if (ImGui::Button("Save & Apply")) RuleManager::Save();
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu rules loaded)", RuleManager::g_rules.size());

    ImGui::Separator();

    // Table
    ImGui::BeginChild("CustomRulesChild", ImVec2(0, 0), true);
    const int COLS = 9;
    if (ImGui::BeginTable("CustomRulesTable", COLS,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_ScrollX)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("##en",      ImGuiTableColumnFlags_WidthFixed,   30.0f);
        ImGui::TableSetupColumn("Pri",       ImGuiTableColumnFlags_WidthFixed,   35.0f);
        ImGui::TableSetupColumn("Type",      ImGuiTableColumnFlags_WidthFixed,  160.0f);
        ImGui::TableSetupColumn("Match",     ImGuiTableColumnFlags_WidthFixed,  110.0f);
        ImGui::TableSetupColumn("Pattern",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Key",       ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Hits",      ImGuiTableColumnFlags_WidthFixed,   45.0f);
        ImGui::TableSetupColumn("Actions",   ImGuiTableColumnFlags_WidthFixed,   90.0f);
        ImGui::TableHeadersRow();

        int deleteIdx = -1;
        int dupIdx    = -1;

        std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);

        for (int i = 0; i < (int)RuleManager::g_rules.size(); ++i) {
            auto& r = RuleManager::g_rules[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();

            // Enabled toggle
            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox("##en", &r.enabled);

            // Priority
            ImGui::TableSetColumnIndex(1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputInt("##pri", &r.priority, 0, 0);

            // Type (colored combo)
            ImGui::TableSetColumnIndex(2);
            ImGui::SetNextItemWidth(-FLT_MIN);
            int cur_type = 0;
            for (int t = 0; t < RULE_TYPE_COUNT; ++t)
                if (r.type == RULE_TYPES[t]) { cur_type = t; break; }
            ImGui::PushStyleColor(ImGuiCol_Text, RuleTypeColor(r.type));
            if (ImGui::Combo("##type", &cur_type, RULE_TYPES, RULE_TYPE_COUNT))
                r.type = RULE_TYPES[cur_type];
            ImGui::PopStyleColor();

            // Match mode
            ImGui::TableSetColumnIndex(3);
            ImGui::SetNextItemWidth(-FLT_MIN);
            int cur_match = 0;
            for (int m = 0; m < MATCH_MODE_COUNT; ++m)
                if (r.match == MATCH_MODES[m]) { cur_match = m; break; }
            if (ImGui::Combo("##match", &cur_match, MATCH_MODES, MATCH_MODE_COUNT))
                r.match = MATCH_MODES[cur_match];

            // Pattern
            ImGui::TableSetColumnIndex(4);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char patBuf[256] = {}; strncpy(patBuf, r.pattern.c_str(), 255);
            if (ImGui::InputText("##pat", patBuf, sizeof(patBuf))) r.pattern = patBuf;
            if (!r.description.empty() && ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", r.description.c_str());

            // Key
            ImGui::TableSetColumnIndex(5);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char keyBuf[128] = {}; strncpy(keyBuf, r.key.c_str(), 127);
            if (ImGui::InputText("##key", keyBuf, sizeof(keyBuf))) r.key = keyBuf;

            // Value
            ImGui::TableSetColumnIndex(6);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char valBuf[256] = {}; strncpy(valBuf, r.value.c_str(), 255);
            if (ImGui::InputText("##val", valBuf, sizeof(valBuf))) r.value = valBuf;

            // Hit counter (colour-coded: green if hits, grey if 0)
            ImGui::TableSetColumnIndex(7);
            if (r.hitCount > 0)
                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.5f, 1.0f), "%d", r.hitCount);
            else
                ImGui::TextDisabled("0");

            // Actions: Duplicate + Delete
            ImGui::TableSetColumnIndex(8);
            if (ImGui::SmallButton("Dup")) dupIdx = i;
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.15f, 0.15f, 1.0f));
            if (ImGui::SmallButton("X")) deleteIdx = i;
            ImGui::PopStyleColor();

            ImGui::PopID();
        }

        if (dupIdx != -1) {
            TrafficRule copy = RuleManager::g_rules[dupIdx];
            copy.id += "_dup";
            copy.hitCount = 0;
            RuleManager::g_rules.insert(RuleManager::g_rules.begin() + dupIdx + 1, copy);
        }
        if (deleteIdx != -1)
            RuleManager::g_rules.erase(RuleManager::g_rules.begin() + deleteIdx);

        ImGui::EndTable();
    }
    ImGui::EndChild();
}

// ──────────────────────────────────────────────────────────────
//  Predefined Packs Sub-Tab
// ──────────────────────────────────────────────────────────────
static void RenderPredefinedPacksTab() {
    if (!g_packsLoaded) LoadPredefinedPacks();

    ImGui::Text("Predefined Rule Packs");
    ImGui::SameLine(ImGui::GetWindowWidth() - 300);
    if (ImGui::Button("Reload Packs")) { g_packsLoaded = false; LoadPredefinedPacks(); }
    ImGui::SameLine();
    if (ImGui::Button("Enable All")) for (auto& p : g_packs) p.enabled = true;
    ImGui::SameLine();
    if (ImGui::Button("Disable All")) for (auto& p : g_packs) p.enabled = false;

    ImGui::SetNextItemWidth(250);
    ImGui::InputText("Search##packs", g_packSearch, sizeof(g_packSearch));
    ImGui::Separator();

    ImGui::BeginChild("PacksChild", ImVec2(0, 0), false);

    std::string search = g_packSearch;
    for (auto& pack : g_packs) {
        // Filter by search
        if (!search.empty() &&
            pack.name.find(search) == std::string::npos &&
            pack.category.find(search) == std::string::npos &&
            pack.description.find(search) == std::string::npos)
            continue;

        ImVec4 catCol = CategoryColor(pack.category);

        // Pack header row
        ImGui::PushID(pack.id.c_str());
        ImGui::Checkbox("##en", &pack.enabled);
        ImGui::SameLine();
        ImGui::TextColored(catCol, "[%s]", pack.category.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 1, 1, 1), "%s", pack.name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(%zu rules)", pack.rules.size());
        if (pack.hitCount > 0) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.5f, 1.0f), "  Hits: %d", pack.hitCount);
        }
        ImGui::SameLine(ImGui::GetWindowWidth() - 240);
        if (ImGui::Button("Import to Custom##imp")) {
            ImportPackIntoCustomRules(pack);
        }
        ImGui::SameLine();
        if (ImGui::Button(pack.expanded ? "Collapse##exp" : "Expand##exp"))
            pack.expanded = !pack.expanded;

        // Description tooltip
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", pack.description.c_str());

        // Expanded rule preview
        if (pack.expanded) {
            ImGui::Indent(20.0f);
            ImGui::TextDisabled("%s", pack.description.c_str());
            ImGui::Spacing();
            for (const auto& r : pack.rules) {
                std::string rtype   = r.value("type", "?");
                std::string rmatch  = r.value("match", "?");
                std::string rpat    = r.value("pattern", "");
                std::string rdesc   = r.value("description", "");
                ImGui::TextColored(RuleTypeColor(rtype), "  %-22s", rtype.c_str());
                ImGui::SameLine();
                ImGui::TextDisabled("%-10s", rmatch.c_str());
                ImGui::SameLine();
                ImGui::Text("%s", rpat.empty() ? "(all)" : rpat.c_str());
                if (!rdesc.empty()) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("  // %s", rdesc.c_str());
                }
            }
            ImGui::Unindent(20.0f);
        }

        ImGui::Separator();
        ImGui::PopID();
    }

    ImGui::EndChild();
}

// ──────────────────────────────────────────────────────────────
//  Main entry point called by main_panel.cpp
// ──────────────────────────────────────────────────────────────
void RenderRulesPanel() {
    ImGui::TextColored(ImVec4(0.0f, 0.9f, 0.6f, 1.0f),
                       "Traffic Rules Engine  [Phase 6 — Live]");
    ImGui::Separator();

    if (ImGui::BeginTabBar("RulesSubTabs")) {
        if (ImGui::BeginTabItem("Custom Rules")) {
            RenderCustomRulesTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Predefined Packs")) {
            RenderPredefinedPacksTab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}
