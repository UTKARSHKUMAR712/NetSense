// ============================================================
//  utils/structured_log.cpp
// ============================================================
#include "structured_log.h"
#include <fstream>
#include <sstream>
#include <windows.h>

std::string StructuredLog::_logDir;
std::mutex  StructuredLog::_mtx;

void StructuredLog::Init(const std::string& logDir) {
    std::lock_guard<std::mutex> lk(_mtx);
    _logDir = logDir;
    // Ensure directory exists
    CreateDirectoryA(logDir.c_str(), NULL);
}

const char* StructuredLog::LevelStr(LogLevel lv) {
    switch (lv) {
        case LogLevel::Dbg:  return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Err: return "ERROR";
    }
    return "INFO";
}

std::string StructuredLog::ChannelFile(LogChannel ch) {
    switch (ch) {
        case LogChannel::PROXY:  return _logDir + "\\proxy.log";
        case LogChannel::RULES:  return _logDir + "\\rules.log";
        case LogChannel::ALERTS: return _logDir + "\\alerts.log";
        case LogChannel::ERRORS: return _logDir + "\\errors.log";
        default:                 return _logDir + "\\all.log";
    }
}

void StructuredLog::Append(const std::string& path, const std::string& line) {
    std::ofstream f(path, std::ios::app);
    if (f.is_open()) {
        f << line << '\n';
    }
}

void StructuredLog::Write(LogChannel ch, LogLevel level,
                           const std::string& msg,
                           const std::string& jsonData) {
    double ts = TimeUtils::NowSec();
    std::ostringstream ss;
    ss << '{'
       << "\"ts\":"       << static_cast<long long>(ts)        << ','
       << "\"ts_iso\":\""  << TimeUtils::ToISO8601(ts)         << "\","
       << "\"level\":\""   << LevelStr(level)                  << "\","
       << "\"channel\":\"" << ChannelFile(ch).substr(
              _logDir.size() + 1)                              << "\","
       << "\"msg\":"       << '\"' << msg                      << "\","
       << "\"data\":"      << jsonData
       << '}';

    std::lock_guard<std::mutex> lk(_mtx);
    Append(ChannelFile(ch), ss.str());
    // Always mirror errors to errors.log as well
    if (level == LogLevel::Err && ch != LogChannel::ERRORS)
        Append(ChannelFile(LogChannel::ERRORS), ss.str());
}

void StructuredLog::Dbg  (LogChannel ch, const std::string& msg, const std::string& d) {
    Write(ch, LogLevel::Dbg, msg, d);
}
void StructuredLog::Info (LogChannel ch, const std::string& msg, const std::string& d) {
    Write(ch, LogLevel::Info, msg, d);
}
void StructuredLog::Warn (LogChannel ch, const std::string& msg, const std::string& d) {
    Write(ch, LogLevel::Warn, msg, d);
}
void StructuredLog::Err  (LogChannel ch, const std::string& msg, const std::string& d) {
    Write(ch, LogLevel::Err, msg, d);
}

void StructuredLog::RuleHit(const std::string& ruleId, const std::string& ruleType,
                             const std::string& url, bool blocked) {
    std::ostringstream data;
    data << '{'
         << "\"rule_id\":\""   << ruleId   << "\","
         << "\"rule_type\":\"" << ruleType << "\","
         << "\"url\":\""       << url      << "\","
         << "\"blocked\":"     << (blocked ? "true" : "false")
         << '}';
    Write(LogChannel::RULES,
          blocked ? LogLevel::Warn : LogLevel::Info,
          blocked ? "RULE_BLOCK" : "RULE_HIT",
          data.str());
}

void StructuredLog::Flush() {
    // File streams are flushed on every write (ofstream::app mode).
    // This function exists for future buffered implementations.
}
