// ============================================================
//  rule_test_panel.cpp — Live Rule Test Console
//  Reads proxy/netsense_proxy.log and shows RULE_EVENT entries
//  with color-coded pass/fail status and timing.
// ============================================================
#include "../../imgui/imgui.h"
#include "../../core/app_data.h"
#include "../../third_party/json/json.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <algorithm>

struct RuleEvent {
    std::string tag;
    std::string rule_id;
    std::string rule_type;
    std::string url;
    std::string extra;
    double      ts = 0.0;
};

static std::vector<RuleEvent> g_events;
static double  g_lastReadTs    = 0.0;
static long    g_lastFilePos   = 0;
static bool    g_autoScroll    = true;
static char    g_eventFilter[128] = {};
static int     g_maxEvents     = 500;

static const char* LOG_FILE    = "proxy/netsense_proxy.log";

static ImVec4 TagColor(const std::string& tag) {
    if (tag.find("BLOCK")       != std::string::npos) return ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
    if (tag.find("REWRITE")     != std::string::npos) return ImVec4(0.4f, 0.6f, 1.0f, 1.0f);
    if (tag.find("HEADER")      != std::string::npos) return ImVec4(0.3f, 0.9f, 0.5f, 1.0f);
    if (tag.find("REDIRECT")    != std::string::npos) return ImVec4(0.4f, 0.6f, 1.0f, 1.0f);
    if (tag.find("MODIFY_JSON") != std::string::npos) return ImVec4(1.0f, 0.5f, 1.0f, 1.0f);
    if (tag.find("THROTTLE")    != std::string::npos) return ImVec4(1.0f, 0.7f, 0.0f, 1.0f);
    if (tag.find("ALERT")       != std::string::npos) return ImVec4(1.0f, 0.8f, 0.0f, 1.0f);
    if (tag.find("LOG_ONLY")    != std::string::npos) return ImVec4(0.6f, 0.8f, 0.6f, 1.0f);
    if (tag.find("SAVE")        != std::string::npos) return ImVec4(0.7f, 0.7f, 0.3f, 1.0f);
    if (tag == "STATUS_CODE_MATCH") return ImVec4(0.5f, 1.0f, 0.8f, 1.0f);
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

static void PollLogFile() {
    double now = (double)time(nullptr);
    if (now - g_lastReadTs < 0.5) return;  // poll max 2Hz
    g_lastReadTs = now;

    std::ifstream f(LOG_FILE, std::ios::in);
    if (!f.is_open()) return;

    f.seekg(g_lastFilePos);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        try {
            auto j = nlohmann::json::parse(line);
            std::string type = j.value("type", "");
            std::string tag  = j.value("tag", "");
            if (type == "RULE_EVENT" || type == "ALERT" ||
                tag == "STATUS_CODE_MATCH" || tag == "[RULE HIT]") {
                RuleEvent ev;
                ev.tag       = j.value("tag", type);
                ev.rule_id   = j.value("rule_id", "");
                ev.rule_type = j.value("rule_type", "");
                ev.url       = j.value("url", j.value("msg", ""));
                ev.extra     = j.value("extra", "");
                ev.ts        = j.value("ts", 0.0);
                g_events.push_back(ev);
                if ((int)g_events.size() > g_maxEvents)
                    g_events.erase(g_events.begin());
            }
        } catch (...) {}
    }
    g_lastFilePos = (long)f.tellg();
}

void RenderRuleTestPanel() {
    PollLogFile();

    // Toolbar
    ImGui::TextColored(ImVec4(0.0f, 0.9f, 0.6f, 1.0f), "Live Rule Event Console");
    ImGui::SameLine(ImGui::GetWindowWidth() - 360);
    if (ImGui::Button("Clear")) {
        g_events.clear();
        g_lastFilePos = 0;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &g_autoScroll);
    ImGui::SameLine();
    if (ImGui::Button("Export")) {
        std::ofstream out("proxy/rule_test_export.jsonl");
        for (const auto& ev : g_events) {
            nlohmann::json j;
            j["tag"] = ev.tag; j["rule_id"] = ev.rule_id;
            j["url"] = ev.url; j["ts"] = ev.ts;
            out << j.dump() << "\n";
        }
    }

    ImGui::SetNextItemWidth(280);
    ImGui::InputText("Filter##ev", g_eventFilter, sizeof(g_eventFilter));
    ImGui::SameLine();
    // Summary counts
    int blocks = 0, injects = 0, logs = 0, alerts = 0;
    for (const auto& e : g_events) {
        if (e.tag.find("BLOCK")  != std::string::npos) ++blocks;
        if (e.tag.find("INJECT") != std::string::npos || e.tag.find("HEADER") != std::string::npos) ++injects;
        if (e.tag.find("LOG")    != std::string::npos) ++logs;
        if (e.tag.find("ALERT")  != std::string::npos) ++alerts;
    }
    ImGui::TextColored(ImVec4(1,0.3f,0.3f,1), "BLK:%d", blocks);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.3f,0.9f,0.5f,1), "INJ:%d", injects);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.8f,0.8f,0.3f,1), "LOG:%d", logs);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1,0.8f,0,1), "ALT:%d", alerts);

    ImGui::Separator();

    ImGui::BeginChild("EventLog", ImVec2(0, 0), true);

    std::string filt = g_eventFilter;

    if (ImGui::BeginTable("EvTable", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Time",      ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableSetupColumn("Tag",       ImGuiTableColumnFlags_WidthFixed, 165.0f);
        ImGui::TableSetupColumn("Rule ID",   ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Type",      ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("URL / Info",ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (int i = (int)g_events.size() - 1; i >= 0; --i) {
            const auto& ev = g_events[i];
            if (!filt.empty() &&
                ev.tag.find(filt) == std::string::npos &&
                ev.url.find(filt) == std::string::npos &&
                ev.rule_id.find(filt) == std::string::npos)
                continue;

            ImGui::TableNextRow();
            ImVec4 col = TagColor(ev.tag);

            // Time
            ImGui::TableSetColumnIndex(0);
            char tbuf[32];
            time_t ts = (time_t)ev.ts;
            struct tm* t = localtime(&ts);
            strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
            ImGui::TextDisabled("%s", tbuf);

            // Tag
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(col, "%s", ev.tag.c_str());

            // Rule ID
            ImGui::TableSetColumnIndex(2);
            ImGui::TextDisabled("%s", ev.rule_id.c_str());

            // Rule Type
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(col, "%s", ev.rule_type.c_str());

            // URL / Info
            ImGui::TableSetColumnIndex(4);
            std::string info = ev.url;
            if (!ev.extra.empty()) info += "  [" + ev.extra + "]";
            ImGui::TextUnformatted(info.c_str());
        }

        if (g_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndTable();
    }
    ImGui::EndChild();
}
