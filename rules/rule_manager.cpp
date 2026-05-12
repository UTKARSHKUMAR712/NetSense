#include "rule_manager.h"
#include "../third_party/json/json.hpp"
#include <fstream>
#include <ctime>

namespace RuleManager {

std::vector<TrafficRule> g_rules;
std::mutex g_rulesMtx;
bool g_rulesLoaded = false;

static const char* RULES_FILE = "proxy/rules.json";

void Load() {
    std::lock_guard<std::mutex> lk(g_rulesMtx);
    g_rules.clear();
    std::ifstream f(RULES_FILE);
    if (!f.is_open()) return;
    try {
        nlohmann::json j;
        f >> j;
        for (auto& item : j) {
            TrafficRule r;
            r.id          = item.value("id", "");
            r.type        = item.value("type", "BLOCK");
            r.match       = item.value("match", "domain");
            r.pattern     = item.value("pattern", "");
            r.key         = item.value("key", "");
            r.value       = item.value("value", "");
            r.enabled     = item.value("enabled", true);
            r.priority    = item.value("priority", 0);
            r.stopProcessing = item.value("stop", false);
            r.description = item.value("description", "");
            r.category    = item.value("category", "Custom");
            // hitCount is runtime-only; seed it from saved file if present
            r.hitCount    = item.value("hit_count", 0);
            g_rules.push_back(r);
        }
        // Sort by priority ascending
        std::sort(g_rules.begin(), g_rules.end(),
                  [](const TrafficRule& a, const TrafficRule& b){ return a.priority < b.priority; });
    } catch(...) {}
    g_rulesLoaded = true;
}

void Save() {
    std::lock_guard<std::mutex> lk(g_rulesMtx);
    nlohmann::json j = nlohmann::json::array();
    int idx = 0;
    for (const auto& r : g_rules) {
        nlohmann::json item;
        item["id"]          = r.id.empty() ? ("rule_" + std::to_string(idx)) : r.id;
        item["type"]        = r.type;
        item["match"]       = r.match;
        item["pattern"]     = r.pattern;
        item["key"]         = r.key;
        item["value"]       = r.value;
        item["enabled"]     = r.enabled;
        item["priority"]    = r.priority;
        item["stop"]        = r.stopProcessing;
        item["description"] = r.description;
        item["category"]    = r.category;
        item["hit_count"]   = r.hitCount;
        j.push_back(item);
        idx++;
    }
    std::ofstream f(RULES_FILE);
    if (f.is_open()) f << j.dump(4);
}

void Touch() {
    // Touch the rules file to trigger mitmproxy hot-reload
    // even when no actual content changed (e.g., enable/disable toggle)
    Save();
}

void IncrementHit(const std::string& ruleId) {
    std::lock_guard<std::mutex> lk(g_rulesMtx);
    for (auto& r : g_rules) {
        if (r.id == ruleId) {
            r.hitCount++;
            r.lastHitTs = (double)time(nullptr);
            break;
        }
    }
}

} // namespace RuleManager
