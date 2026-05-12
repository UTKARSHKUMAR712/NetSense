#pragma once
#include <string>
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
    std::string id;          // UUID or index-based ID for cross-referencing
    std::string type   = "BLOCK";
    std::string match  = "domain";
    std::string pattern = "";
    std::string key    = "";    // header key, JSON path, etc.
    std::string value  = "";    // replacement value / inject value
    bool        enabled = true;
    int         priority = 0;   // lower number = higher priority
    bool        stopProcessing = false; // stop evaluating rules after this one hits
    std::string description = "";       // human-readable description
    std::string category = "";          // e.g. "Privacy", "Gaming"

    // Live stats (runtime only, not persisted)
    int         hitCount  = 0;
    double      lastHitTs = 0.0;
};
