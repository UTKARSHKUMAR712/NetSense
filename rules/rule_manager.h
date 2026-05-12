#pragma once
#include <vector>
#include <string>
#include <mutex>
#include "rule_types.h"

// RuleManager — thread-safe in-memory rule store with persistence.
// The C++ UI owns these rules. On every Save, it writes proxy/rules.json
// which the Python RulesAddon picks up via hot-reload.
namespace RuleManager {

    extern std::vector<TrafficRule> g_rules;
    extern std::mutex g_rulesMtx;
    extern bool g_rulesLoaded;

    void Load();   // Load from proxy/rules.json
    void Save();   // Write to proxy/rules.json (triggers mitmproxy hot-reload)

    // Notify mitmproxy of changes by touching the file timestamp
    void Touch();

    // Update live hit stats received from Python via log-back channel
    void IncrementHit(const std::string& ruleId);

} // namespace RuleManager
