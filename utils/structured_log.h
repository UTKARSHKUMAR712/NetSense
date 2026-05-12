#pragma once
// ============================================================
//  utils/structured_log.h — JSON-structured event logger
//  Writes machine-readable JSON-Lines to log files.
//  Human text goes to g_state.logLines for UI display.
//  Reusable: drop this header into any tool in the family.
// ============================================================
#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include "../utils/time_utils.h"

// ── Log channels (one file per channel) ─────────────────────
enum class LogChannel {
    PROXY,    // proxy.log  — HTTP traffic events
    RULES,    // rules.log  — rule hits/blocks/redirects
    ALERTS,   // alerts.log — ALERT_ON_MATCH events
    ERRORS,   // errors.log — startup/crash/parse errors
    ALL       // not a real channel, used for filtering only
};

// ── Log levels ───────────────────────────────────────────────
enum class LogLevel { Dbg, Info, Warn, Err };

// ── Structured log entry ─────────────────────────────────────
// Every entry is a single JSON object on one line.
// Format: {"ts":1234,"level":"INFO","channel":"RULES","msg":"...","data":{...}}
class StructuredLog {
public:
    // Initialize — call once at startup with the base log directory
    static void Init(const std::string& logDir);

    // Write a structured entry
    static void Write(LogChannel ch, LogLevel level,
                      const std::string& msg,
                      const std::string& jsonData = "{}");

    // Convenience wrappers
    static void Dbg  (LogChannel ch, const std::string& msg, const std::string& data = "{}");
    static void Info (LogChannel ch, const std::string& msg, const std::string& data = "{}");
    static void Warn (LogChannel ch, const std::string& msg, const std::string& data = "{}");
    static void Err  (LogChannel ch, const std::string& msg, const std::string& data = "{}");

    // Rule-specific helper (most common use case)
    static void RuleHit(const std::string& ruleId, const std::string& ruleType,
                        const std::string& url, bool blocked = false);

    static void Flush();

private:
    static std::string    _logDir;
    static std::mutex     _mtx;

    static std::string ChannelFile(LogChannel ch);
    static const char* LevelStr(LogLevel lv);
    static void        Append(const std::string& path, const std::string& line);
};
