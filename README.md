# NetSense+ — Real-Time Network Traffic Analyzer & Rule Engine

> **Version:** 3.0 — Phase 6 Live  
> **Platform:** Windows 10/11 (x64) — Requires Administrator  
> **Tech Stack:** C++20 / ImGui / OpenGL3 / SQLite3 / Python 3.10+ / mitmproxy

---

## What Is NetSense+?

NetSense+ is a standalone Windows desktop application that captures, inspects, and actively modifies live network traffic using a programmable rule engine. It combines a native C++ ImGui GUI with a mitmproxy Python addon for deep HTTP/HTTPS interception.

```
┌─────────────────────────────────────────────────────────┐
│                  NetSense.exe (ImGui)                   │
│  ┌─────────┬──────────┬─────────┬────────┬──────────┐  │
│  │ Network │ Inspector│  Rules  │Runtime │ Settings │  │
│  └────┬────┴────┬─────┴────┬────┴────────┴──────────┘  │
│       │         │          │                            │
│  ┌────▼─────────▼──────────▼──────────────────────┐   │
│  │              Core / Proxy Reader (C++)          │   │
│  └────────────────────┬───────────────────────────┘   │
└───────────────────────│───────────────────────────────┘
                         │  reads netsense_proxy.log (JSON-Lines)
                         │
┌───────────────────────▼───────────────────────────────┐
│          mitmdump.exe + netsense_addon.py             │
│   RuleLoader → RuleMatcher → RuleExecutor             │
│   (hot-reload from rules.json, no restart needed)     │
└───────────────────────────────────────────────────────┘
```

---

## Release Layout

```
release/
├── NetSense.exe              ← Main application (run as Admin)
├── mitmdump.exe              ← Place here after: pip install mitmproxy
├── proxy/
│   ├── netsense_addon.py     ← mitmproxy addon (auto-copied by build)
│   ├── rule_engine.py        ← Live rule execution engine
│   ├── rules.json            ← Active rules (auto-synced from UI)
│   ├── predefined_packs.json ← Built-in rule pack library
│   ├── netsense_proxy.log    ← JSON-Lines traffic log (runtime)
│   ├── netsense_alerts.log   ← ALERT_ON_MATCH events (runtime)
│   └── netsense_saved_matches.jsonl  ← SAVE_MATCHES captures
└── recordings/               ← Session export text files
```

---

## Building

### Prerequisites
- MSYS2 with UCRT64 toolchain: `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-glfw`
- Python 3.10+: `pip install mitmproxy`

### Build Command (MSYS2 terminal)
```bash
bash build.sh
```

The build script:
1. Compiles `NetSense.exe` → `release/`
2. Creates `release/proxy/` and `release/recordings/`
3. Copies all Python runtime files to `release/proxy/`
4. Copies `mitmdump.exe` from project root → `release/` (if present)

### First Run
1. Copy `mitmdump.exe` to `release/` (or run `build.sh` with it in the project root)
2. Run `release/NetSense.exe` **as Administrator**
3. Click **[Start Proxy]** — sets system proxy to `127.0.0.1:8080`
4. Install the mitmproxy CA cert (first run only): browse to `mitm.it`

---

## Features — What's Done ✅

### 🖥️ UI / UX
- [x] Dark ImGui theme with custom color palette, smooth tab layout
- [x] Global font size scale slider (persisted to settings)
- [x] Copy-to-clipboard on all text fields (Ctrl+C / copy buttons)
- [x] Pretty-print JSON in Inspector panel (request/response bodies)
- [x] Fullscreen JSON viewer with scrolling for large payloads
- [x] URL copy button in Inspector

### 🌐 Network Panel
- [x] Real-time active TCP connection listing (iphlpapi)
- [x] Process ↔ PID ↔ connection mapping (psapi)
- [x] Established-only filter toggle
- [x] Bandwidth history graph (in/out)

### 🔍 Inspector Panel
- [x] Live HTTP/HTTPS traffic stream (via mitmproxy JSON-Lines log)
- [x] Request + Response headers viewer
- [x] Body preview with pretty-print JSON option
- [x] Filter by host, method, status code
- [x] TLS/SNI metadata display
- [x] WebSocket frame capture

### 📋 Session / History Panel
- [x] SQLite3 database with sessions table + flows table
- [x] Start/Stop session recording
- [x] Paginated flow browser per session
- [x] Export session to text file

### 🎯 Rules Engine — Complete
All 16 rule types are implemented and live-tested:

| Rule Type | What It Does |
|---|---|
| `BLOCK` | Kill the connection (domain / URL / regex / keyword / wildcard) |
| `BLOCK_KEYWORD` | Block any URL containing a keyword string |
| `BLOCK_METHOD` | Block specific HTTP methods (DELETE, PATCH, etc.) |
| `BLOCK_TRACKERS` | Auto-block 17 known ad/tracker domains |
| `INJECT_HEADER` | Add/replace a request header |
| `RESPONSE_HEADER_INJECT` | Add/replace a response header |
| `REDIRECT` | Return HTTP 301/302 to a new URL (auto-adds `http://` if missing) |
| `REWRITE_URL` | String-replace inside the request URL |
| `THROTTLE` | Sleep N ms before forwarding (latency simulation) |
| `LIMIT_BANDWIDTH` | Chunk response body with delays to simulate bandwidth cap |
| `MODIFY_JSON` | Edit a field in a JSON response body (dot-notation path) |
| `LOG_ONLY` | Write to proxy log without modifying traffic |
| `ALERT_ON_MATCH` | Emit `[RULE ALERT]` to alerts log |
| `SAVE_MATCHES` | Append matched flow metadata to `netsense_saved_matches.jsonl` |
| `DROP_RESPONSE` | Zero out the response body |
| `BLOCK_MEDIA` | Block video/audio/image MIME type responses |

**Match modes:** `domain` (with subdomain wildcard), `url`, `regex`, `keyword`, `body`

**Hot-reload:** Rules apply within 2s of clicking **Save & Apply** — no proxy restart needed.

### 📦 Rule Editor (Modal UI)
- [x] Per-rule type dynamic config form (not a generic spreadsheet)
- [x] Live preview: `IF domain == "x.com" THEN REDIRECT (302) -> http://y.com`
- [x] Inline validation (regex syntax, required fields, numeric type check)
- [x] Save & Apply button (disabled until validation passes)
- [x] Deadlock-free popup (deferred index pattern, correct ImGui window context)

### 📦 Predefined Pack Library (14 packs, 90+ rules)
| Pack | Category | Rules |
|---|---|---|
| Ad Block | Privacy | 6 |
| Telemetry Block | Privacy | 5 |
| Privacy Mode | Security | 5 |
| Streaming Detection | Analysis | 5 |
| Social Media Detection | Monitoring | 6 |
| API Debug | Development | 4 |
| Gaming Detection | Gaming | 6 |
| Media Block | Content Control | 3 |
| Safe Browsing | Protection | 4 |
| **NetSense+ Test Suite** | Development | 16 |
| **Developer Tools** | Development | 10 |
| **Security Hardening** | Security | 12 |
| **API Traffic Inspector** | Analysis | 10 |
| **Streaming Control** | Content Control | 8 |

### ⚙️ Settings
- [x] Proxy port configuration
- [x] Font scale slider
- [x] Body/form data capture toggles
- [x] **Data Management** (all fixed with absolute exe-relative paths):
  - Delete Logs Only (proxy log, alerts log, saved matches, recordings)
  - Delete DB Only (SQLite sessions + flows)
  - Master Clean (everything above + in-memory state)

### 🏗️ Architecture
- [x] Modular C++ file structure (no god files)
- [x] Thread-safe `g_rulesMtx` protecting `g_rules` vector
- [x] Python `RuleLoader` with hot-reload via mtime polling
- [x] Python `RuleMatcher` (domain/subdomain/wildcard/regex/keyword/body)
- [x] Python `RuleConditionEvaluator` (MIME, status code, process hint)
- [x] Python `RuleExecutor` with per-phase request/response hooks
- [x] Async-safe hit counter batched write-back (every 25 hits)
- [x] `.gitignore` covering build artifacts, logs, db, venv

---

## What's Left / Future Work 🚧

### Short-Term (Polish)
- [ ] **Settings persistence** — save/load `settings.json` so proxy port, font scale, and toggles survive app restart
- [ ] **Rules persistence** — rules.json is written but not re-loaded on startup automatically; add auto-load on launch
- [ ] **Rule hit counter display** — currently incremented in Python but UI refresh from log-back needs wiring
- [ ] **Rule priority drag-drop** — allow reordering rules by drag in the table
- [ ] **Inspector search** — full-text search across all captured flows
- [ ] **Per-rule last-hit timestamp** — show when rule last fired in the Rules table

### Medium-Term (Features)
- [ ] **mitmproxy CA cert auto-installer** — launch `mitmdump` once to generate cert, then auto-install into Windows cert store via `certutil`
- [ ] **HTTPS decryption status indicator** — show which hosts are successfully intercepted vs. pinned
- [ ] **WebSocket frame rule actions** — currently captured but no rule types target WS messages
- [ ] **Rule import/export** — export selected rules to a JSON file, import from file or URL
- [ ] **Rule scheduling** — enable rules only during certain hours (e.g., throttle at peak hours)
- [ ] **Response body rule (MODIFY_BODY)** — regex/string replacement in non-JSON response bodies
- [ ] **DNS rule type (SPOOF_DNS)** — intercept DNS queries and return custom IPs

### Long-Term (Vision)
- [ ] **Plugin system** — load custom Python rule action handlers from `plugins/` folder
- [ ] **Network graph visualization** — real-time force-directed graph of host connections
- [ ] **Traffic diff mode** — compare before/after rule modification side-by-side
- [ ] **Distributed mode** — run mitmproxy on a separate machine, NetSense+ as remote dashboard
- [ ] **Mobile proxy companion** — Android/iOS companion app to route device traffic through NetSense+
- [ ] **AI-assisted rule suggestion** — analyze traffic patterns and suggest rules to block/modify
- [ ] **Packet-level capture** — integrate WinPcap/npcap for sub-TCP visibility (alongside HTTP layer)
- [ ] **Export to Burp/OWASP ZAP format** — bridge to pen-testing workflows

---

## Known Limitations

| Issue | Status |
|---|---|
| HTTPS sites with certificate pinning (e.g. some mobile apps) | Bypassed by BLOCK rule; deep inspection not possible |
| `openai.com` blocks mitmproxy TLS interception | Use `httpbin.org` for testing instead |
| Settings not persisted across app restarts | Planned (settings.json) |
| Rule hit counts reset on proxy restart | Hot-reload flushes the Python loader; counts restart from 0 |

---

## Developer Notes

### Adding a New Rule Type
1. Add the type string to `rules/rule_types.h` → `RULE_TYPES[]`
2. Add a UI config block in `ui/panels/rule_editor_modal.cpp` (CfgInput fields)
3. Add execution logic in `proxy/rule_engine.py` → `RuleExecutor.execute_request()` or `execute_response()`
4. Add a preview case in `rule_editor_modal.cpp` → `PreviewText()`
5. Add validation in `Validate()` if the type has required fields
6. Add a test rule to the Test Suite pack in `proxy/predefined_packs.json`

### Debugging Rules
- Enable the **NetSense+ Test Suite** pack → click **Enable All** → **Save & Apply**
- Browse to `http://httpbin.org/get` through the proxy
- Check **[RT] Runtime** tab for live rule hit counts
- Check `release/proxy/netsense_proxy.log` for `[RULE *]` tagged entries
- Check `release/proxy/netsense_alerts.log` for ALERT_ON_MATCH events

---

*NetSense+ is a personal/educational network analysis tool. Use responsibly and only on networks and devices you own or have permission to inspect.*
