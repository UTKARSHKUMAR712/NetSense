// rule_editor_modal.cpp — Dynamic Rule Config Modal Editor
#include "../../imgui/imgui.h"
#include "../../rules/rule_manager.h"
#include "../../rules/rule_types.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <regex>

static int         g_editIdx  = -1;
static TrafficRule g_editCopy;

void OpenRuleEditorModal(int idx) {
    // NOTE: caller (RenderCustomRulesTab) already holds g_rulesMtx.
    // Do NOT lock again — non-recursive mutex would deadlock.
    g_editIdx = idx;
    if (idx >= 0 && idx < (int)RuleManager::g_rules.size())
        g_editCopy = RuleManager::g_rules[idx];
    ImGui::OpenPopup("##rule_cfg");
}

static std::string PreviewText(const TrafficRule& r) {
    std::string s = "IF ";
    if      (r.match == "domain")  s += "domain == \"" + r.pattern + "\"";
    else if (r.match == "url")     s += "URL contains \"" + r.pattern + "\"";
    else if (r.match == "regex")   s += "URL ~ /" + r.pattern + "/";
    else if (r.match == "keyword") s += "traffic has keyword \"" + r.pattern + "\"";
    else                           s += r.match + " = \"" + r.pattern + "\"";

    auto cc = r.conditions;
    if (!cc.empty()) {
        if (cc.count("mime")    && !cc.at("mime").empty())    s += "\n  AND MIME  = \"" + cc.at("mime")    + "\"";
        if (cc.count("status")  && !cc.at("status").empty())  s += "\n  AND status = " + cc.at("status");
        if (cc.count("process") && !cc.at("process").empty()) s += "\n  AND process = \"" + cc.at("process") + "\"";
    }
    s += "\nTHEN ";
    auto cfg = r.config;
    auto cv  = [&](const char* k) -> std::string {
        return cfg.count(k) ? cfg.at(k) : "";
    };
    if (r.type == "BLOCK" || r.type == "BLOCK_KEYWORD")   s += "BLOCK";
    else if (r.type == "REDIRECT") {
        std::string tgt = cv("url");
        std::string cod = cv("code"); if (cod.empty()) cod = "302";
        s += "REDIRECT (" + cod + ") -> " + (tgt.empty() ? "(no URL set)" : tgt);
    }
    else if (r.type == "INJECT_HEADER")                    s += "INJECT " + cv("key") + ": " + cv("value");
    else if (r.type == "RESPONSE_HEADER_INJECT")           s += "RSP INJECT " + cv("key") + ": " + cv("value");
    else if (r.type == "REWRITE_URL") {
        std::string find = cv("find"); if (find.empty()) find = "<pattern>";
        std::string rep  = cv("replace"); if (rep.empty()) rep = "(not set)";
        s += "REWRITE: replace \"" + find + "\" with \"" + rep + "\"";
    }
    else if (r.type == "MODIFY_JSON")                      s += "SET " + cv("json_path") + " = " + cv("replace_value");
    else if (r.type == "THROTTLE")                         s += "DELAY " + cv("latency_ms") + " ms";
    else if (r.type == "LIMIT_BANDWIDTH")                  s += "CAP " + cv("max_kbps") + " KB/s";
    else if (r.type == "LOG_ONLY")                         s += "LOG request";
    else if (r.type == "ALERT_ON_MATCH")                   s += "EMIT ALERT";
    else if (r.type == "DROP_RESPONSE")                    s += "DROP response body";
    else                                                   s += r.type;
    return s;
}

static std::vector<std::string> Validate(const TrafficRule& r) {
    std::vector<std::string> errs;
    if (r.match == "regex" && !r.pattern.empty()) {
        try { std::regex rx(r.pattern); }
        catch (...) { errs.push_back("Invalid regex: " + r.pattern); }
    }
    if (r.type == "REDIRECT") {
        if (!r.config.count("url") || r.config.at("url").empty())
            errs.push_back("Redirect URL is required");
    }
    if (r.type == "MODIFY_JSON") {
        if (!r.config.count("json_path") || r.config.at("json_path").empty())
            errs.push_back("JSON Path is required");
    }
    if (r.type == "THROTTLE") {
        if (r.config.count("latency_ms") && !r.config.at("latency_ms").empty()) {
            try { std::stoi(r.config.at("latency_ms")); }
            catch (...) { errs.push_back("Latency must be a number"); }
        }
    }
    if (r.type == "INJECT_HEADER" || r.type == "RESPONSE_HEADER_INJECT") {
        if (!r.config.count("key") || r.config.at("key").empty())
            errs.push_back("Header name is required");
    }
    return errs;
}

// Tiny input helper
static bool CfgInput(const char* label, std::map<std::string,std::string>& m,
                     const char* key, const char* hint = "") {
    ImGui::Text("%-20s", label); ImGui::SameLine(185);
    ImGui::SetNextItemWidth(360);
    auto& v = m[key];
    char buf[512] = {}; strncpy(buf, v.c_str(), 511);
    std::string id = std::string("##m_") + key;
    bool changed = ImGui::InputText(id.c_str(), buf, sizeof(buf));
    if (changed) v = buf;
    if (hint[0] && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", hint);
    return changed;
}

void RenderRuleEditorModal() {
    ImGui::SetNextWindowSize(ImVec2(620, 520), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(),
                            ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (!ImGui::BeginPopupModal("##rule_cfg", nullptr,
                                ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
        return;

    if (g_editIdx < 0) { ImGui::EndPopup(); return; }
    auto& r = g_editCopy;

    // Header
    ImGui::TextColored(ImVec4(0,0.9f,0.6f,1), "Rule Editor");
    ImGui::SameLine(420);
    ImGui::TextDisabled("ID: %s", r.id.c_str());

    ImGui::Separator();

    // Base fields (always shown)
    int cur_type = 0;
    for (int t = 0; t < RULE_TYPE_COUNT; ++t)
        if (r.type == RULE_TYPES[t]) { cur_type = t; break; }
    ImGui::Text("%-20s", "Rule Type"); ImGui::SameLine(185);
    ImGui::SetNextItemWidth(200);
    if (ImGui::Combo("##et", &cur_type, RULE_TYPES, RULE_TYPE_COUNT))
        r.type = RULE_TYPES[cur_type];

    int cur_match = 0;
    for (int m = 0; m < MATCH_MODE_COUNT; ++m)
        if (r.match == MATCH_MODES[m]) { cur_match = m; break; }
    ImGui::Text("%-20s", "Match Mode"); ImGui::SameLine(185);
    ImGui::SetNextItemWidth(160);
    if (ImGui::Combo("##em", &cur_match, MATCH_MODES, MATCH_MODE_COUNT))
        r.match = MATCH_MODES[cur_match];

    ImGui::Text("%-20s", "Pattern"); ImGui::SameLine(185);
    ImGui::SetNextItemWidth(360);
    char patBuf[256] = {}; strncpy(patBuf, r.pattern.c_str(), 255);
    if (ImGui::InputText("##epat", patBuf, sizeof(patBuf))) r.pattern = patBuf;

    ImGui::Separator();

    // Scrollable type-specific area — BeginChild with ImGuiChildFlags_FrameStyle (no crash)
    ImGui::BeginChild("##ecfg", ImVec2(0, 200), ImGuiChildFlags_FrameStyle, 0);

    if (r.type == "INJECT_HEADER" || r.type == "RESPONSE_HEADER_INJECT") {
        CfgInput("Header Name",   r.config, "key",   "e.g. X-NetSense");
        CfgInput("Header Value",  r.config, "value", "e.g. HelloWorld");

    } else if (r.type == "REDIRECT") {
        CfgInput("Target URL",  r.config, "url",  "e.g. http://example.com  or  example.com");
        // HTTP code is optional — blank = 302 (temporary redirect)
        ImGui::Text("%-20s", "HTTP Code"); ImGui::SameLine(185);
        ImGui::SetNextItemWidth(360);
        auto& cv = r.config["code"];
        char cb[32] = {}; strncpy(cb, cv.c_str(), 31);
        if (ImGui::InputText("##m_code", cb, sizeof(cb)))
            cv = cb;
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("301 = Permanent, 302 = Temporary (default if blank)");

    } else if (r.type == "REWRITE_URL") {
        ImGui::TextColored(ImVec4(0.6f,0.8f,1.0f,1), "URL Rewrite Config");
        ImGui::TextDisabled("  Tip: 'Find Text' defaults to the Pattern above when left blank.");
        ImGui::TextDisabled("  e.g. Pattern=youtube.com  Find=http://  Replace=https://");
        ImGui::Spacing();
        CfgInput("Find Text",    r.config, "find",
                 "String to find in the full URL (leave blank to use Pattern)");
        CfgInput("Replace With", r.config, "replace",
                 "Replacement string (can be full URL or partial path)");

    } else if (r.type == "THROTTLE") {
        CfgInput("Latency (ms)",  r.config, "latency_ms", "e.g. 500");

    } else if (r.type == "LIMIT_BANDWIDTH") {
        CfgInput("Max KB/s",      r.config, "max_kbps",   "e.g. 100");

    } else if (r.type == "MODIFY_JSON") {
        ImGui::TextColored(ImVec4(1,0.5f,1,1), "JSON Modification");
        CfgInput("JSON Path",     r.config, "json_path",     "dot-notation: user.isPremium");
        CfgInput("Replace Value", r.config, "replace_value", "e.g. true or NetSense+");
        ImGui::Spacing();
        ImGui::TextDisabled("  Conditions:");
        CfgInput("  MIME filter",   r.conditions, "mime",   "e.g. application/json");
        CfgInput("  Status filter", r.conditions, "status", "e.g. 200");

    } else if (r.type == "BLOCK_METHOD") {
        CfgInput("HTTP Method",   r.config, "method", "POST  GET  DELETE  PUT");

    } else if (r.type == "ALERT_ON_MATCH") {
        ImGui::TextColored(ImVec4(1.0f,0.5f,0.2f,1), "Alert Configuration");
        CfgInput("Severity", r.config, "severity", "e.g. info, warning, critical");
        CfgInput("Message",  r.config, "message",  "Custom alert message to display");
        ImGui::Spacing();
        ImGui::TextDisabled("  Optional conditions:");
        CfgInput("  MIME filter",    r.conditions, "mime",    "Only match content type");
        CfgInput("  Status filter",  r.conditions, "status",  "Only match HTTP status");
        CfgInput("  Process filter", r.conditions, "process", "e.g. chrome.exe");

    } else if (r.type == "LOG_ONLY" || r.type == "SAVE_MATCHES") {
        ImGui::TextDisabled("  Optional conditions:");
        CfgInput("  MIME filter",    r.conditions, "mime",    "Only match content type");
        CfgInput("  Status filter",  r.conditions, "status",  "Only match HTTP status");
        CfgInput("  Process filter", r.conditions, "process", "e.g. chrome.exe");

    } else {
        ImGui::TextDisabled("No advanced config for this rule type.");
        ImGui::Spacing();
        ImGui::TextDisabled("Pattern above is sufficient.");
    }

    ImGui::EndChild();

    // Description
    ImGui::Text("%-20s", "Description"); ImGui::SameLine(185);
    ImGui::SetNextItemWidth(360);
    char descBuf[256] = {}; strncpy(descBuf, r.description.c_str(), 255);
    if (ImGui::InputText("##edsc", descBuf, sizeof(descBuf))) r.description = descBuf;

    ImGui::Checkbox("Stop processing after this rule", &r.stopProcessing);

    ImGui::Separator();

    // Preview
    ImGui::TextDisabled("Preview:");
    std::string prev = PreviewText(r);
    ImGui::TextWrapped("%s", prev.c_str());

    // Validation
    auto errs = Validate(r);
    for (const auto& e : errs)
        ImGui::TextColored(ImVec4(1,0.35f,0.35f,1), "  ! %s", e.c_str());

    ImGui::Separator();

    bool ok = errs.empty();
    if (!ok) ImGui::BeginDisabled();
    if (ImGui::Button("Save & Apply", ImVec2(130, 0))) {
        {
            std::lock_guard<std::mutex> lk(RuleManager::g_rulesMtx);
            if (g_editIdx < (int)RuleManager::g_rules.size())
                RuleManager::g_rules[g_editIdx] = r;
        }
        RuleManager::Save();
        ImGui::CloseCurrentPopup();
    }
    if (!ok) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(80, 0)))
        ImGui::CloseCurrentPopup();

    ImGui::EndPopup();
}
