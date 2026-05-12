// ============================================================
//  backend/runtime_health.cpp
// ============================================================
#include "runtime_health.h"
#include "../utils/time_utils.h"
#include <psapi.h>

// Static storage
std::array<SubsystemHealth, static_cast<int>(SubsystemId::COUNT)>
    RuntimeHealthMonitor::_health;

// Initialize names (called implicitly on first use — no explicit init needed)
struct HealthNamesInit {
    HealthNamesInit() {
        RuntimeHealthMonitor::_health[0].name = "ProxyReader";
        RuntimeHealthMonitor::_health[1].name = "NetworkMonitor";
        RuntimeHealthMonitor::_health[2].name = "TrafficAnalyzer";
        RuntimeHealthMonitor::_health[3].name = "DBWriter";
        RuntimeHealthMonitor::_health[4].name = "EventBus";
    }
} _healthNamesInit;

void RuntimeHealthMonitor::Heartbeat(SubsystemId id) {
    auto& h = _health[static_cast<int>(id)];
    h.lastHeartbeatMs.store(TimeUtils::MonotonicMs());
    h.alive.store(true);
}

void RuntimeHealthMonitor::SetQueueDepth(SubsystemId id, int depth) {
    _health[static_cast<int>(id)].queueDepth.store(depth);
}

void RuntimeHealthMonitor::RecordDrop(SubsystemId id) {
    _health[static_cast<int>(id)].droppedEvents.fetch_add(1);
}

void RuntimeHealthMonitor::UpdateLatency(SubsystemId id, double latencyMs) {
    auto& h   = _health[static_cast<int>(id)];
    double cur = h.avgLatencyMs.load();
    // Exponential moving average: alpha = 0.1
    h.avgLatencyMs.store(cur * 0.9 + latencyMs * 0.1);
}

bool RuntimeHealthMonitor::IsStale(SubsystemId id, double thresholdMs) {
    auto& h    = _health[static_cast<int>(id)];
    double now = TimeUtils::MonotonicMs();
    double last= h.lastHeartbeatMs.load();
    return (last > 0.0) && ((now - last) > thresholdMs);
}

ProcessStats RuntimeHealthMonitor::RefreshProcessStats() {
    ProcessStats ps{};
    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        ps.workingSetBytes = pmc.WorkingSetSize;
        ps.peakWorkingSet  = pmc.PeakWorkingSetSize;
    }
    FILETIME creation, exit, kernel, user;
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) {
        auto toUs = [](FILETIME ft) -> uint64_t {
            return ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10;
        };
        ps.cpuKernelUs = toUs(kernel);
        ps.cpuUserUs   = toUs(user);
    }
    return ps;
}

HealthSnapshot RuntimeHealthMonitor::GetSnapshot() {
    HealthSnapshot snap;
    snap.snapshotTs = TimeUtils::NowSec();
    double now      = TimeUtils::MonotonicMs();

    for (int i = 0; i < static_cast<int>(SubsystemId::COUNT); ++i) {
        auto& h  = _health[i];
        auto& ss = snap.subsystems[i];
        ss.name        = h.name;
        ss.lastBeatMs  = h.lastHeartbeatMs.load();
        ss.queueDepth  = h.queueDepth.load();
        ss.dropped     = h.droppedEvents.load();
        ss.alive       = h.alive.load();
        ss.avgLatency  = h.avgLatencyMs.load();
        ss.stale       = ss.alive && (ss.lastBeatMs > 0.0) &&
                         ((now - ss.lastBeatMs) > 5000.0);
    }
    snap.process = RefreshProcessStats();
    return snap;
}
