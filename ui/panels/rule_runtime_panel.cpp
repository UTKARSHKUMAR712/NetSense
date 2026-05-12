// ============================================================
//  rule_runtime_panel.cpp — Runtime Rule Inspector
//  Shows live stats, loaded rules, regex cache info, and
//  execution counters without touching live traffic.
// ============================================================
#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../rules/rule_manager.h"
#include "../../rules/rule_types.h"
#include "../../third_party/json/json.hpp"
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <ctime>
#include <algorithm>

static double g_lastRuntimeRefresh = 0.0;

// Stats aggregated from rules.json on each refresh
struct RuntimeStats {
    int  totalRules    = 0;
    int  enabledRules  = 0;
    int  totalHits     = 0;
    int  activeTypes   = 0;
    std::map<std::string, int> hitsByType;
    std::map<std::string, int> hitsByRule;
    std::string lastHitUrl;
    double      lastHitTs = 0.0;
};

static RuntimeStats g_stats;

static void RefreshStats() {
    double now = (double)time(nullptr);
    if (now - g_lastRuntimeRefresh < 2.0) return;
    g_lastRuntimeRefresh = now;

    std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);
    g_stats = RuntimeStats{};
    g_stats.totalRules = (int)RuleManager::g_rules.size();

    std::set<std::string> seenTypes;
    for (const auto& r : RuleManager::g_rules) {
        if (r.enabled) ++g_stats.enabledRules;
        g_stats.totalHits += r.hitCount;
        g_stats.hitsByType[r.type] += r.hitCount;
        seenTypes.insert(r.type);
        if (r.hitCount > 0 && r.lastHitTs > g_stats.lastHitTs) {
            g_stats.lastHitTs = r.lastHitTs;
        }
    }
    g_stats.activeTypes = (int)seenTypes.size();
}

static ImVec4 TypeColor(const std::string& t) {
    if (t.find("BLOCK")    != std::string::npos) return ImVec4(1.0f,0.3f,0.3f,1.0f);
    if (t.find("INJECT")   != std::string::npos) return ImVec4(0.3f,0.9f,0.5f,1.0f);
    if (t.find("THROTTLE") != std::string::npos) return ImVec4(1.0f,0.7f,0.0f,1.0f);
    if (t.find("REDIRECT") != std::string::npos) return ImVec4(0.4f,0.6f,1.0f,1.0f);
    if (t.find("MODIFY")   != std::string::npos) return ImVec4(1.0f,0.5f,1.0f,1.0f);
    if (t.find("LOG")      != std::string::npos) return ImVec4(0.8f,0.8f,0.3f,1.0f);
    return ImVec4(0.7f,0.7f,0.7f,1.0f);
}

void RenderRuleRuntimePanel() {
    RefreshStats();

    ImGui::TextColored(ImVec4(0.0f, 0.9f, 0.6f, 1.0f), "Rule Engine Runtime Inspector");
    ImGui::SameLine(ImGui::GetWindowWidth() - 200);
    if (ImGui::Button("Force Reload")) {
        RuleManager::Load();
    }
    ImGui::SameLine();
    if (ImGui::Button("Save State")) {
        RuleManager::Save();
    }

    ImGui::Separator();

    // ── Summary Cards ──
    ImGui::Columns(4, "rt_summary", false);

    ImGui::TextColored(ImVec4(0.0f,0.9f,0.6f,1.0f), "Rules Loaded");
    ImGui::Text("%d", g_stats.totalRules);
    ImGui::NextColumn();

    ImGui::TextColored(ImVec4(0.3f,0.9f,0.5f,1.0f), "Enabled");
    ImGui::Text("%d", g_stats.enabledRules);
    ImGui::NextColumn();

    ImGui::TextColored(ImVec4(1.0f,0.8f,0.0f,1.0f), "Total Hits");
    ImGui::Text("%d", g_stats.totalHits);
    ImGui::NextColumn();

    ImGui::TextColored(ImVec4(0.8f,0.5f,1.0f,1.0f), "Rule Types Used");
    ImGui::Text("%d", g_stats.activeTypes);
    ImGui::Columns(1);

    ImGui::Separator();
    ImGui::Spacing();

    // ── Hits by Type ──
    if (!g_stats.hitsByType.empty()) {
        if (ImGui::CollapsingHeader("Hit Counters by Rule Type", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::BeginChild("HitsByType", ImVec2(0, 140), true);
            if (ImGui::BeginTable("HitTypeTbl", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("Rule Type", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableHeadersRow();

                // Sort by hits descending
                std::vector<std::pair<std::string,int>> sorted(
                    g_stats.hitsByType.begin(), g_stats.hitsByType.end());
                std::sort(sorted.begin(), sorted.end(),
                    [](const auto& a, const auto& b){ return a.second > b.second; });

                for (const auto& [type, cnt] : sorted) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextColored(TypeColor(type), "%s", type.c_str());
                    ImGui::TableSetColumnIndex(1);
                    if (cnt > 0)
                        ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f), "%d", cnt);
                    else
                        ImGui::TextDisabled("0");
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
        }
    }

    // ── Loaded Rules Table ──
    if (ImGui::CollapsingHeader("Loaded Rules (sorted by priority)", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginChild("LoadedRules", ImVec2(0, 0), true);

        std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);
        if (ImGui::BeginTable("LoadedRulesTbl", 7,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("En",      ImGuiTableColumnFlags_WidthFixed,  25.0f);
            ImGui::TableSetupColumn("Pri",     ImGuiTableColumnFlags_WidthFixed,  35.0f);
            ImGui::TableSetupColumn("Type",    ImGuiTableColumnFlags_WidthFixed, 160.0f);
            ImGui::TableSetupColumn("Match",   ImGuiTableColumnFlags_WidthFixed,  80.0f);
            ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Hits",    ImGuiTableColumnFlags_WidthFixed,  45.0f);
            ImGui::TableSetupColumn("Last Hit",ImGuiTableColumnFlags_WidthFixed,  75.0f);
            ImGui::TableHeadersRow();

            for (const auto& r : RuleManager::g_rules) {
                ImGui::TableNextRow();
                ImVec4 col = TypeColor(r.type);

                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(r.enabled ? ImVec4(0.2f,1.0f,0.4f,1.0f)
                                              : ImVec4(0.5f,0.5f,0.5f,1.0f),
                                   r.enabled ? "ON" : "--");
                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%d", r.priority);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(col, "%s", r.type.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", r.match.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(r.pattern.empty() ? "(all)" : r.pattern.c_str());
                ImGui::TableSetColumnIndex(5);
                if (r.hitCount > 0)
                    ImGui::TextColored(ImVec4(0.3f,1.0f,0.5f,1.0f), "%d", r.hitCount);
                else
                    ImGui::TextDisabled("0");
                ImGui::TableSetColumnIndex(6);
                if (r.lastHitTs > 0) {
                    time_t ts = (time_t)r.lastHitTs;
                    char buf[24];
                    struct tm* t = localtime(&ts);
                    strftime(buf, sizeof(buf), "%H:%M:%S", t);
                    ImGui::TextDisabled("%s", buf);
                } else {
                    ImGui::TextDisabled("-");
                }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
    }
}
