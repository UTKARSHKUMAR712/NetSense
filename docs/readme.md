# NetSense+ — File Structure Guide

> **For new contributors:** This document explains every directory and key file in the project — what it does, who owns it, and how it connects to the rest of the system.

---

## Root Layout

```
Netsense/
├── analysis/          Traffic intelligence layer
├── backend/           Pure-logic subsystems (no UI dependency)
├── core/              System-level runtime (monitor, DB, proxy reader)
├── dns/               DNS resolution thread
├── docs/              Architecture documentation (you are here)
├── imgui/             Dear ImGui library (vendored)
├── process/           Process ↔ PID mapping
├── proxy/             Python mitmproxy integration
├── rules/             C++ rule storage and manager
├── third_party/       External libraries (sqlite3, nlohmann/json)
├── ui/                ImGui UI layer (panels, theme)
├── utils/             Shared utilities (time, logging, ring buffer)
├── build.sh           Build script (MSYS2/g++)
├── main.cpp           Entry point (WinMain)
├── README.md          Quick-start guide
└── release/           Build output (auto-created by build.sh)
```

---

## File-by-File Reference

### `main.cpp`
**Entry point.** Initializes Winsock, calls `LoadSettings()`, starts all background threads (DNS, network monitor, proxy reader, traffic analyzer), runs the ImGui UI loop, then tears down on exit.

**Key calls (in order):**
```
LoadSettings() → RuleManager::Load() → TrafficDB::Initialize()
→ StartDnsResolver() → StartNetworkMonitor()
→ StartProxyReader() → StartTrafficAnalyzer()
→ RunUI()                    ← blocks here
→ SaveSettings() → cleanup threads → TrafficDB::Shutdown()
```

---

### `core/`

| File | Purpose |
|---|---|
| `app_data.h` | **Global structs**: `AppState`, `AppSettings`, `ProxyFlow`, `ConnectionEntry`. Single source of truth for all shared data types. |
| `network_monitor.h/.cpp` | Background thread polling TCP connections via `iphlpapi`. Fills `g_state.connections`. |
| `proxy_reader.h/.cpp` | Two roles: (1) tails `proxy/netsense_proxy.log` and parses JSON-Lines into `g_state.proxyFlows`; (2) launches and monitors `mitmdump.exe`. Has crash-recovery auto-restart. |
| `traffic_db.h/.cpp` | SQLite3 write worker. Owns the async write queue. `QueueFlowInsert()` is the only safe way to write from background threads. |
| `settings_persist.cpp` | Versioned load/save of `settings.json` (always stored next to `NetSense.exe`). Creates `.bak` before overwrite. Handles schema migration. |

---

### `analysis/`

| File | Purpose |
|---|---|
| `traffic_analyzer.h/.cpp` | Background thread that post-processes `g_state.proxyFlows` to tag `insight_tags` (e.g. "streaming", "api", "tracking"). |

---

### `backend/`
> **No UI code allowed here.**

| File | Purpose |
|---|---|
| `runtime_health.h/.cpp` | Per-thread heartbeat tracking, queue depth, dropped event counts, process memory stats. UI reads a safe `HealthSnapshot` copy. |
| `plugin_caps.h` | Capability bitmask system for future addon sandboxing. 17 flags across traffic/storage/system/UI/network categories. |
| `event_bus.h/.cpp` | *(planned)* Centralized publish-subscribe for all runtime events. |
| `command_queue.h/.cpp` | *(planned)* Thread-safe UI→backend command pipe. Prevents UI from mutating backend state directly. |

---

### `dns/`

| File | Purpose |
|---|---|
| `dns_resolver.h/.cpp` | Background DNS lookup thread. Resolves hostnames from active connections. |

---

### `process/`

| File | Purpose |
|---|---|
| `process_mapper.h/.cpp` | Maps PIDs to process names using `psapi`. Called by network monitor to label connections. |

---

### `proxy/`
**Python mitmproxy integration.** All files here run inside `mitmdump.exe` as a mitmproxy addon.

| File | Purpose |
|---|---|
| `netsense_addon.py` | **Entry point for mitmproxy.** Thin orchestrator: loads rules, calls matcher, calls executor on each request/response. |
| `rule_engine.py` | All rule matching and execution logic (will be refactored into `proxy/rules/` submodules). |
| `rules.json` | Live active rules. Written by C++ UI on Save & Apply. Hot-reloaded by Python within 2 seconds. |
| `predefined_packs.json` | Library of 14 built-in rule packs (90+ rules). Read-only at runtime; merged into rules.json when a pack is enabled. |
| `netsense_proxy.log` | JSON-Lines traffic log written by the Python addon. Tailed by `proxy_reader.cpp`. |
| `netsense_alerts.log` | `ALERT_ON_MATCH` events. One JSON object per line. |
| `netsense_saved_matches.jsonl` | `SAVE_MATCHES` captures. One JSON object per line. |

---

### `rules/`

| File | Purpose |
|---|---|
| `rule_manager.h/.cpp` | Loads/saves `rules.json`. Owns the in-memory `g_rules` vector (protected by `g_rulesMtx`). Called by UI to add/edit/delete rules. |

---

### `ui/`

| File | Purpose |
|---|---|
| `main_ui.h/.cpp` | GLFW + ImGui init, render loop, window setup. Calls `RenderMainPanel()` each frame. |
| `main_window.cpp` | Top-level window layout (if separate from main_ui). |
| `theme.cpp` | ImGui color theme (Cyber Dark). |

### `ui/panels/`
Each file renders one tab. **Panels must be read-only** — they render snapshots of `g_state`, never mutate backend state directly.

| File | Tab |
|---|---|
| `main_panel.cpp` | Top toolbar + tab container |
| `inspector_panel.cpp` | `[PROXY] Inspector` — live HTTP flow list |
| `rules_panel.cpp` | `[RULES] Rules` — rule table + pack library |
| `rule_editor_modal.cpp` | Rule add/edit modal popup |
| `rule_runtime_panel.cpp` | `[RT] Runtime` — live rule hit counts |
| `session_panel.cpp` | `[SESSION] History` — SQLite session browser |
| `mobile_panel.cpp` | `[MOBILE] Mobile` — mobile device proxy setup |
| `settings_panel.cpp` | `[>_] Settings` — all configuration |

---

### `utils/`

| File | Purpose |
|---|---|
| `time_utils.h` | **Unified time source.** `NowSec()` (wall clock), `MonotonicMs()` (duration only), ISO-8601 formatter, log stamp. Use ONLY these functions. |
| `ring_buffer.h` | Template fixed-capacity ring buffer. Zero allocation. Used for flows, logs, alerts. |
| `structured_log.h/.cpp` | JSON-Lines structured logger. 4 channels (proxy/rules/alerts/errors), 4 levels. Machine-readable for future analytics. |

---

### `third_party/`

| Path | Library |
|---|---|
| `sqlite/sqlite3.h/.c` | SQLite 3 (amalgamation) |
| `json/json.hpp` | nlohmann/json (single-header) |

---

### `imgui/`
Dear ImGui library (vendored). Do not modify except `imgui.ini` (UI layout persistence, auto-generated in `release/`).

---

### `release/` (build output)
```
release/
├── NetSense.exe          ← Run as Administrator
├── mitmdump.exe          ← Place here (from pip install mitmproxy)
├── settings.json         ← Auto-saved by Settings panel
├── settings.json.bak     ← Auto-backup before each save
├── netsense.db           ← SQLite traffic database
├── proxy/
│   ├── netsense_addon.py
│   ├── rule_engine.py
│   ├── rules.json
│   ├── predefined_packs.json
│   ├── netsense_proxy.log
│   ├── netsense_alerts.log
│   └── netsense_saved_matches.jsonl
└── recordings/           ← Session text exports
```

---

## Data Flow Summary

```
Browser/App → [HTTPS] → mitmdump.exe
                             │
                    netsense_addon.py
                    ┌────────┴────────┐
                    │  rule_engine.py │  ← rules.json (hot-reload)
                    └────────┬────────┘
                             │ JSON-Lines
                    netsense_proxy.log
                             │
                    proxy_reader.cpp (C++ tail)
                             │
                    g_state.proxyFlows
                    ┌────────┴────────┐
                    │  TrafficDB      │  ← netsense.db
                    │  UI Inspector   │  ← render only
                    └─────────────────┘
```

---

## Adding a New Feature — Checklist

1. **New rule type**: → `proxy/rule_engine.py` (action) + `ui/panels/rule_editor_modal.cpp` (config UI) + `proxy/predefined_packs.json` (test rule)
2. **New UI panel**: → `ui/panels/yourpanel.cpp` + register in `ui/main_ui.cpp` + add tab in `main_panel.cpp`
3. **New background thread**: → Add heartbeat call `RuntimeHealthMonitor::Heartbeat(SubsystemId::YourId)` + add to threading model in `docs/threading.md`
4. **New setting**: → `core/app_data.h` (AppSettings) + `core/settings_persist.cpp` (save/load) + bump `SETTINGS_VERSION`
5. **New log channel**: → `utils/structured_log.h` (add to `LogChannel` enum) + `utils/structured_log.cpp` (`ChannelFile()`)
