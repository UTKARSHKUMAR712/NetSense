#pragma once
// ============================================================
//  utils/time_utils.h — Unified monotonic + wall-clock time
//  Use ONLY these functions across the entire codebase.
//  Avoids mixed timing systems (time(), clock(), QueryPerf...).
//  Reusable: WiFi Analyzer, Interceptor, Packet Capture.
// ============================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <ctime>
#include <chrono>

namespace TimeUtils {

// ── Wall clock (Unix epoch, seconds, double precision) ───────
inline double NowSec() {
    return static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    ) / 1'000'000.0;
}

// ── Monotonic (for durations only, never for timestamps) ─────
inline double MonotonicMs() {
    return static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    ) / 1000.0;
}

// ── Format epoch seconds as ISO-8601 UTC string ──────────────
// Output: "2026-05-13T00:00:00Z"
inline std::string ToISO8601(double epochSec) {
    time_t t = static_cast<time_t>(epochSec);
    struct tm tm_buf = {};
    gmtime_s(&tm_buf, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return buf;
}

// ── Format for human-readable log lines ──────────────────────
// Output: "13/05/26 00:04:22"
inline std::string ToLogStamp(double epochSec) {
    time_t t = static_cast<time_t>(epochSec);
    struct tm tm_buf = {};
    localtime_s(&tm_buf, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%d/%m/%y %H:%M:%S", &tm_buf);
    return buf;
}

// ── Duration formatting ───────────────────────────────────────
inline std::string FmtDurationMs(double ms) {
    char buf[32];
    if (ms < 1000.0)        snprintf(buf, sizeof(buf), "%.0fms",   ms);
    else if (ms < 60000.0)  snprintf(buf, sizeof(buf), "%.2fs",    ms / 1000.0);
    else                    snprintf(buf, sizeof(buf), "%.1fmin",   ms / 60000.0);
    return buf;
}

} // namespace TimeUtils
