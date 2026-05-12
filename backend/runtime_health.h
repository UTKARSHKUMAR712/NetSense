#pragma once
// ============================================================
//  backend/runtime_health.h — Runtime Health Monitor
//  Tracks thread liveness, queue depths, memory, latency.
//  Inspectable from UI Runtime panel without touching backend.
//  Design: each subsystem calls Heartbeat(); Health panel reads
//  snapshot without locking the subsystem itself.
// ============================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <array>
#include <atomic>
#include <mutex>
#include <cstdint>

// ── Thread IDs ───────────────────────────────────────────────
enum class SubsystemId : int {
    ProxyReader     = 0,
    NetworkMonitor  = 1,
    TrafficAnalyzer = 2,
    DBWriter        = 3,
    EventBus        = 4,
    COUNT           = 5
};

// ── Per-subsystem health record ───────────────────────────────
struct SubsystemHealth {
    const char*  name         = "unknown";
    std::atomic<double> lastHeartbeatMs{0.0}; // MonotonicMs() of last beat
    std::atomic<int>    queueDepth{0};         // pending items in its queue
    std::atomic<int>    droppedEvents{0};      // events dropped due to overflow
    std::atomic<bool>   alive{false};
    std::atomic<double> avgLatencyMs{0.0};     // rolling average

    // Non-copyable (atomic members)
    SubsystemHealth() = default;
    SubsystemHealth(const SubsystemHealth&) = delete;
    SubsystemHealth& operator=(const SubsystemHealth&) = delete;
};

// ── Process-level stats ───────────────────────────────────────
struct ProcessStats {
    size_t   workingSetBytes   = 0;
    size_t   peakWorkingSet    = 0;
    uint64_t cpuKernelUs       = 0;
    uint64_t cpuUserUs         = 0;
};

// ── Snapshot (safe to copy, read from UI thread) ─────────────
struct HealthSnapshot {
    struct SubSnap {
        std::string name;
        double      lastBeatMs  = 0.0;
        int         queueDepth  = 0;
        int         dropped     = 0;
        bool        alive       = false;
        double      avgLatency  = 0.0;
        bool        stale       = false;  // no heartbeat > 5s
    };
    std::array<SubSnap, static_cast<int>(SubsystemId::COUNT)> subsystems;
    ProcessStats process;
    double       snapshotTs = 0.0;
};

// ── RuntimeHealthMonitor ─────────────────────────────────────
class RuntimeHealthMonitor {
public:
    // Called by each background thread every cycle to signal liveness
    static void Heartbeat(SubsystemId id);

    // Called by a subsystem to update its queue depth
    static void SetQueueDepth(SubsystemId id, int depth);

    // Record a dropped event
    static void RecordDrop(SubsystemId id);

    // Update rolling average latency
    static void UpdateLatency(SubsystemId id, double latencyMs);

    // Get a safe UI-readable snapshot (copies all atomics)
    static HealthSnapshot GetSnapshot();

    // True if a subsystem hasn't heartbeated in > thresholdMs
    static bool IsStale(SubsystemId id, double thresholdMs = 5000.0);

public:
    static std::array<SubsystemHealth,
                      static_cast<int>(SubsystemId::COUNT)> _health;
private:
    static ProcessStats RefreshProcessStats();
};
