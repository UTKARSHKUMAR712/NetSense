#pragma once
#include <string>
#include <map>
#include <atomic>

// All supported rule types — kept in sync with netsense_addon.py
static constexpr const char* RULE_TYPES[] = {
    "BLOCK",
    "BLOCK_KEYWORD",
    "INJECT_HEADER",
    "RESPONSE_HEADER_INJECT",
    "REWRITE_URL",
    "REDIRECT",
    "THROTTLE",
    "LIMIT_BANDWIDTH",
    "LOG_ONLY",
    "MODIFY_JSON",
    "DROP_RESPONSE",
    "REGEX_MATCH",
    "PROCESS_ONLY",
    "MIME_ONLY",
    "ALERT_ON_MATCH",
    "SAVE_MATCHES",
    "STATUS_CODE_MATCH",
    "BLOCK_METHOD",
    "BLOCK_MEDIA",
    "BLOCK_TRACKERS",
    nullptr
};
static constexpr int RULE_TYPE_COUNT = 20;

// All supported match modes
static constexpr const char* MATCH_MODES[] = {
    "domain", "url", "header", "keyword",
    "regex", "process", "mime", "method",
    "status", "body", "response_header",
    nullptr
};
static constexpr int MATCH_MODE_COUNT = 11;

struct TrafficRule {
    std::string id;
    std::string type    = "BLOCK";
    std::string match   = "domain";
    std::string pattern = "";
    std::string key     = "";   // header key (simple rules)
    std::string value   = "";   // replace value (simple rules)
    bool        enabled = true;
    int         priority = 0;
    bool        stopProcessing = false;
    std::string description = "";
    std::string category    = "";

    // Advanced type-specific config (serialized to JSON "config" block)
    // Examples: {"latency_ms":"500"}, {"json_path":"user.isPremium","replace_value":"true"}
    std::map<std::string, std::string> config;

    // Pre-conditions (serialized to JSON "conditions" block)
    // Examples: {"mime":"application/json"}, {"status":"200", "process":"chrome.exe"}
    std::map<std::string, std::string> conditions;

    // Runtime stats (not persisted)
    int    hitCount  = 0;
    double lastHitTs = 0.0;

    // UI state (not persisted)
    bool   expanded = false;
};
