# Threading Model — NetSense+

## Thread Map

| Thread | Name | Owner | Mutex Used | Heartbeat ID |
|---|---|---|---|---|
| Main (UI) | ImGui render loop | `main.cpp` | `g_state.mtx` (read) | — |
| ProxyReader | Log tail + proxy watchdog | `core/proxy_reader.cpp` | `g_state.mtx`, `g_pendingLogMtx` | `SubsystemId::ProxyReader` |
| NetworkMonitor | TCP connection poll | `core/network_monitor.cpp` | `g_state.mtx` | `SubsystemId::NetworkMonitor` |
| TrafficAnalyzer | Flow insight tagging | `analysis/traffic_analyzer.cpp` | `g_state.mtx` | `SubsystemId::TrafficAnalyzer` |
| DB Worker | SQLite write queue | `core/traffic_db.cpp` | `g_dbMutex`, `g_queueMutex` | `SubsystemId::DBWriter` |

## Mutex Ownership Rules

### `g_state.mtx` (std::mutex, non-recursive)
- **Owner**: nobody — shared lock, acquired for the shortest possible window
- **UI thread**: locks during `RenderMainPanel()` for the outer frame, unlocks before calling each panel
- **Background threads**: lock only to push to `logLines`, `proxyFlows`, `connections`
- **NEVER**: lock `g_state.mtx` and then call any function that also tries to lock it

### `g_pendingLogMtx` (std::mutex)
- **Purpose**: decouple `StartProxyServer()` (UI thread) from `addLog()` (also needs `g_state.mtx`)
- **Pattern**: proxy startup writes to `g_pendingLogs` under this lock; `ProxyLoop` flushes under `g_state.mtx`

### `g_dbMutex` (std::mutex)
- **Owner**: `traffic_db.cpp` exclusively
- **Never exposed** outside that translation unit

### `g_rulesMtx` (std::mutex)
- **Owner**: `rules/rule_manager.cpp`
- **UI** acquires to display rule list
- **Python** does NOT use this mutex (Python has its own hot-reload)

## Critical Rule: No Re-Entrant Locks

`std::mutex` is **non-recursive**. The same thread locking the same mutex twice = deadlock.

### Known danger zone: `RenderMainPanel()`

```cpp
void RenderMainPanel() {
    std::lock_guard<std::mutex> lk(g_state.mtx);  // LOCKED
    ...
    if (Button("Start Proxy")) {
        StartProxyServer();  // ← MUST NOT call g_state.addLog() here!
    }
    // Tab panels: mutex is explicitly unlocked before calling each
    g_state.mtx.unlock();
    RenderInspectorPanel();  // safe to call g_state.addLog() here
    g_state.mtx.lock();
}
```

### Safe pattern for proxy startup messages

```cpp
// WRONG (deadlocks if called while UI holds g_state.mtx):
g_state.addLog("Starting proxy...");

// CORRECT (queued, flushed by ProxyLoop on next cycle):
ProxyLog("Starting proxy...");
```

## Proxy Crash Recovery

`ProxyLoop()` checks the mitmdump process every 5 seconds using:
```cpp
DWORD rc = WaitForSingleObject(g_hProxyProcess, 0);
if (rc == WAIT_OBJECT_0) { /* process died */ }
```
If dead → calls `StartProxyServer()` automatically.

## Adding a New Background Thread

1. Add its `SubsystemId` to `backend/runtime_health.h`
2. Call `RuntimeHealthMonitor::Heartbeat(SubsystemId::YourId)` in its loop
3. Use `g_state.mtx` only for reading/writing shared state, never for long operations
4. Never call `g_state.addLog()` while holding `g_state.mtx`
5. Document it in this file
