# Ownership Rules — NetSense+

> **Principle:** Every piece of data in the system has exactly ONE owner. All other subsystems access it through safe interfaces.

---

## Data Ownership Table

| Data | Owner | Safe Access API | Who Must NOT Access Directly |
|---|---|---|---|
| `g_state.proxyFlows` | `ProxyReader` thread (writes) | `g_state.mtx` lock (reads) | DB worker, rules engine |
| `g_state.connections` | `NetworkMonitor` thread | `g_state.mtx` lock | All UI panels |
| `g_state.logLines` | All (via `addLog()`) | `addLog()` only | Direct `push_back` forbidden |
| `g_state.processes` | `NetworkMonitor` thread | `g_state.mtx` lock | UI reads only |
| `g_rules` | `RuleManager` | `RuleManager::GetRules()` | UI panels, proxy_reader |
| `g_db` (SQLite handle) | `TrafficDB` worker | `TrafficDB::Queue*()` functions | Everywhere else |
| `g_hProxyProcess` | `ProxyReader` / `proxy_reader.cpp` | `StartProxyServer()`, `StopProxyServer()` | UI, any other thread |
| `settings.json` | `settings_persist.cpp` | `LoadSettings()`, `SaveSettings()` | Direct file I/O forbidden |
| `rules.json` | `RuleManager` (C++) / `RuleLoader` (Python) | `RuleManager::Save()` from C++ side | Direct file write from UI forbidden |

---

## UI Panels: Read-Only Contract

ImGui panels **must never**:
- Call `sqlite3_exec()` or any raw DB function
- Call `StartProxyServer()` directly *(use CommandQueue when implemented)*
- Write to `g_state.proxyFlows`, `g_state.connections` directly
- Open or write files directly (except exports via `RuleManager::Save()`)

ImGui panels **may**:
- Read `g_state.*` under `g_state.mtx`
- Call `g_state.addLog()` (acquires its own lock)
- Call `RuleManager::Add/Remove/Save()` (owns its own lock)
- Call `TrafficDB::Queue*()` (safe async write)
- Call `StartProxyServer()` only when `g_state.mtx` is NOT held

---

## Thread Ownership

| Thread | Owns exclusively |
|---|---|
| ProxyReader | `g_hProxyProcess`, `g_pendingLogs`, proxy log file handle |
| NetworkMonitor | Raw socket / iphlpapi iteration handle |
| DB Worker | `g_db` (SQLite handle), `g_writeQueue` |
| UI (main) | ImGui context, GLFW window, `g_settings` (read), all panel static state |
| TrafficAnalyzer | No exclusive ownership; reads `proxyFlows` snapshot |

---

## Rules: Who Writes `rules.json`?

Only two writers exist:

1. **C++ `RuleManager::Save()`** — triggered by UI "Save & Apply"
2. **C++ `OnPackToggled()`** in `rules_panel.cpp` — triggered by pack enable/disable

The Python addon **only reads** `rules.json`. It never writes to it.

---

## Settings: Who Writes `settings.json`?

Only **`SaveSettings()`** in `core/settings_persist.cpp` writes it.  
Always creates `.bak` first. Always writes a `"version"` field.

---

## What Happens When You Violate Ownership

| Violation | Consequence |
|---|---|
| UI holds `g_state.mtx`, calls `addLog()` | Deadlock → crash |
| Two threads write `rules.json` concurrently | Corrupted JSON → Python parse error → rules stop working |
| Panel calls raw `sqlite3_exec()` | DB state corruption, possible crash |
| ProxyReader closed by non-owner thread | Handle leak or double-free |
