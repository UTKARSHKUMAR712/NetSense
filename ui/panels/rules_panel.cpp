#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../rules/rule_manager.h"
#include "../../rules/rule_types.h"
#include "../../third_party/json/json.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <algorithm>

// Forward-declare to avoid circular includes
void InvalidateRuleCache();
void OpenRuleEditorModal(int idx);
void RenderRuleEditorModal();


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
    {
        std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);
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
    } // ← lock released BEFORE Save() to avoid double-lock deadlock
    RuleManager::Save();
}


// Called when a pack is toggled — writes custom rules + ALL enabled pack rules
// to rules.json so the Python engine sees them immediately.
static void OnPackToggled() {
    // 1. Collect custom rules via RuleManager::Save() first
    RuleManager::Save();

    // 2. Reload what was just saved, then append enabled pack rules
    static const char* RULES_FILE = "proxy/rules.json";
    nlohmann::json j = nlohmann::json::array();

    // Read existing custom rules
    {
        std::ifstream fi(RULES_FILE);
        if (fi.is_open()) {
            try { fi >> j; } catch (...) { j = nlohmann::json::array(); }
        }
    }

    // Append every rule from every enabled pack
    for (const auto& pack : g_packs) {
        if (!pack.enabled) continue;
        for (auto rule : pack.rules) {
            // Tag with pack origin so the runtime panel can show it
            if (!rule.contains("id") || rule["id"].get<std::string>().empty())
                rule["id"] = pack.id + "_" + rule.value("type", "rule");
            rule["category"] = pack.id;
            rule["enabled"]  = true;
            rule["priority"] = rule.value("priority", 10);
            j.push_back(rule);
        }
    }

    // Write the merged list
    std::ofstream fo(RULES_FILE);
    if (fo.is_open()) fo << j.dump(4);
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
        std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);
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

    static int g_pendingEdit = -1;  // deferred Edit index (set inside table, opened after)

    ImGui::BeginChild("CustomRulesChild", ImVec2(0, 0), true);

    // Compact summary table — no Key/Value overload
    const int COLS = 8;
    if (ImGui::BeginTable("CustomRulesTable", COLS,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("##en",     ImGuiTableColumnFlags_WidthFixed,  28.0f);
        ImGui::TableSetupColumn("Pri",      ImGuiTableColumnFlags_WidthFixed,  40.0f);
        ImGui::TableSetupColumn("Type",     ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Match",    ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Pattern",  ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Hits",     ImGuiTableColumnFlags_WidthFixed,  40.0f);
        ImGui::TableSetupColumn("Config",   ImGuiTableColumnFlags_WidthFixed,  65.0f);
        ImGui::TableSetupColumn("Actions",  ImGuiTableColumnFlags_WidthFixed,  75.0f);
        ImGui::TableHeadersRow();

        int deleteIdx = -1;
        int dupIdx    = -1;

        std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);

        for (int i = 0; i < (int)RuleManager::g_rules.size(); ++i) {
            auto& r = RuleManager::g_rules[i];
            ImGui::PushID(i);

            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::Checkbox(("##en" + std::to_string(i)).c_str(), &r.enabled);

            ImGui::TableSetColumnIndex(1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            ImGui::InputInt(("##pri" + std::to_string(i)).c_str(), &r.priority, 0, 0);

            ImGui::TableSetColumnIndex(2);
            ImGui::SetNextItemWidth(-FLT_MIN);
            int cur_type = 0;
            for (int t = 0; t < RULE_TYPE_COUNT; ++t)
                if (r.type == RULE_TYPES[t]) { cur_type = t; break; }
            ImGui::PushStyleColor(ImGuiCol_Text, RuleTypeColor(r.type));
            if (ImGui::Combo(("##type" + std::to_string(i)).c_str(), &cur_type, RULE_TYPES, RULE_TYPE_COUNT))
                r.type = RULE_TYPES[cur_type];
            ImGui::PopStyleColor();

            ImGui::TableSetColumnIndex(3);
            ImGui::SetNextItemWidth(-FLT_MIN);
            int cur_match = 0;
            for (int m = 0; m < MATCH_MODE_COUNT; ++m)
                if (r.match == MATCH_MODES[m]) { cur_match = m; break; }
            if (ImGui::Combo(("##match" + std::to_string(i)).c_str(), &cur_match, MATCH_MODES, MATCH_MODE_COUNT))
                r.match = MATCH_MODES[cur_match];

            ImGui::TableSetColumnIndex(4);
            ImGui::SetNextItemWidth(-FLT_MIN);
            char patBuf[256] = {}; strncpy(patBuf, r.pattern.c_str(), 255);
            if (ImGui::InputText(("##pat" + std::to_string(i)).c_str(), patBuf, sizeof(patBuf))) r.pattern = patBuf;
            if (!r.description.empty() && ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", r.description.c_str());

            ImGui::TableSetColumnIndex(5);
            if (r.hitCount > 0)
                ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f), "%d", r.hitCount);
            else
                ImGui::TextDisabled("0");

            ImGui::TableSetColumnIndex(6);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f,0.45f,0.8f,1.0f));
            if (ImGui::SmallButton(("> Edit##" + std::to_string(i)).c_str()))
                g_pendingEdit = i;  // defer: open popup after EndTable
            ImGui::PopStyleColor();

            ImGui::TableSetColumnIndex(7);
            if (ImGui::SmallButton(("Dup##" + std::to_string(i)).c_str())) dupIdx = i;
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f,0.15f,0.15f,1.0f));
            if (ImGui::SmallButton(("X##" + std::to_string(i)).c_str())) deleteIdx = i;
            ImGui::PopStyleColor();

            ImGui::PopID();
        }

        if (dupIdx != -1) {
            TrafficRule copy = RuleManager::g_rules[dupIdx];
            copy.id += "_dup"; copy.hitCount = 0; copy.expanded = false;
            RuleManager::g_rules.insert(RuleManager::g_rules.begin() + dupIdx + 1, copy);
        }
        if (deleteIdx != -1)
            RuleManager::g_rules.erase(RuleManager::g_rules.begin() + deleteIdx);

        ImGui::EndTable();
    }

    // Open deferred popup here — same window context as BeginPopupModal
    if (g_pendingEdit >= 0) {
        OpenRuleEditorModal(g_pendingEdit);
        g_pendingEdit = -1;
    }
    RenderRuleEditorModal();
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
    if (ImGui::Button("Enable All"))  { for (auto& p : g_packs) p.enabled = true;  OnPackToggled(); }
    ImGui::SameLine();
    if (ImGui::Button("Disable All")) { for (auto& p : g_packs) p.enabled = false; OnPackToggled(); }

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
        bool prevEnabled = pack.enabled;
        if (ImGui::Checkbox("##en", &pack.enabled) && pack.enabled != prevEnabled) {
            OnPackToggled();
        }
        ImGui::SameLine();
        ImGui::TextColored(catCol, "[%s]", pack.category.c_str());
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 1, 1, 1), "%s", pack.name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(%zu rules)", pack.rules.size());
        ImGui::SameLine();
        if (pack.enabled)
            ImGui::TextColored(ImVec4(0.1f,0.9f,0.3f,1.0f), " [ACTIVE]");
        else
            ImGui::TextDisabled(" [OFF]");
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
