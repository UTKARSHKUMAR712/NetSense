# NetSense+ Advanced Upgrade — Master Design Document

**Version:** 3.0 Advance  
**Status:** Approved — Ready for Phase 1 Execution  
**Architecture:** Extend-Only, No Rewrites

---

## Finalized Decisions

| Decision | Choice | Reason |
|---|---|---|
| SQLite | Bundled `sqlite3.c` amalgamation | Zero external deps, portable |
| Body Preview | **OFF by default** | Privacy-safe, lighter memory |
| Replay Engine | Bundled `curl.exe` (fallback to system) | Self-contained distribution |
| Architecture | Single EXE, feature flags per mode | Simpler deployment |
| Third-party | All tools under `third_party/` | Portable standalone build |

---

## Final Project Structure

```
Netsense/
│
├── main.cpp                        [MODIFY]   — shutdown order, DB init
│
├── core/
│   ├── app_data.h                  [MODIFY]   — ProxyFlow struct, settings, flow ring buffer
│   ├── network_monitor.cpp         [KEEP]
│   ├── proxy_reader.cpp            [MODIFY]   — rule file dispatch, rules.json I/O
│   └── traffic_db.cpp/.h          [NEW]      — SQLite session storage layer
│
├── analysis/
│   └── traffic_analyzer.cpp/.h    [NEW]      — smart insight tagging engine
│
├── replay/
│   └── replay_manager.cpp/.h      [NEW]      — replay abstraction (curl-backed)
│
├── ui/
│   ├── main_ui.cpp                 [KEEP]
│   ├── theme.cpp                   [MODIFY]   — richer cyber palette
│   └── panels/
│       ├── main_panel.cpp          [MODIFY]   — add top-level tab bar
│       ├── inspector_panel.cpp     [NEW]      — rich flow table + detail pane
│       ├── rules_panel.cpp         [NEW]      — block/intercept rule editor
│       ├── session_panel.cpp       [NEW]      — SQLite session explorer + replay
│       ├── mobile_panel.cpp        [NEW]      — mobile device setup helper
│       └── settings_panel.cpp     [NEW]      — cert, proxy port, body capture, privacy
│
├── proxy/
│   └── netsense_addon.py           [MAJOR UPGRADE] — rich JSON with all metadata
│
├── third_party/
│   ├── sqlite/
│   │   ├── sqlite3.c               [NEW]      — bundled amalgamation
│   │   └── sqlite3.h               [NEW]      — bundled header
│   ├── mitmproxy/
│   │   └── mitmdump.exe            [RUNTIME]  — downloaded by package.sh
│   └── tools/
│       └── curl.exe                [RUNTIME]  — downloaded by package.sh
│
├── build.sh                        [MODIFY]   — add sqlite3.c + new source files
├── package.sh                      [MODIFY]   — download curl.exe into third_party/tools/
└── upgrade.md                      [THIS FILE]
```

---

## Architecture: Live State vs Historical DB

```
mitmproxy addon
      │
      │ JSON line per event
      ▼
proxy_reader.cpp (background thread)
      │
      ├──► ProxyFlow ring buffer (g_state.proxyFlows, max 2000) ◄── Live ImGui reads this
      │
      └──► traffic_db.cpp async write queue
                │
                ▼
          netsense.db (SQLite)                         ◄── Session panel reads this
```

**Key rule:** ImGui always reads from the in-memory ring buffer for live speed.  
SQLite is written asynchronously and only queried by the Session History panel.

---

## Threading Model

```
Main Thread       — ImGui render loop (60fps) — READ ONLY from g_state
Network Thread    — network_monitor.cpp poll   — WRITE to g_state.processes (locked)
Proxy Thread      — proxy_reader.cpp tail loop — WRITE to g_state.proxyFlows + logLines (locked)
DB Write Thread   — traffic_db.cpp async queue — WRITE to SQLite (own mutex)
Analyzer Thread   — traffic_analyzer.cpp       — READ proxyFlows, WRITE logLines (locked)
```

---

## Data Flow Pipeline

```
Browser Request
      │
      ▼
mitmdump.exe (proxy intercept)
      │
      ▼
netsense_addon.py
  ├── parse headers, body, cookies, timing
  ├── apply rules.json (block / inject / rewrite)
  ├── tag insight_tags (streaming, api, analytics...)
  └── write JSON line to netsense_proxy.log
      │
      ▼
proxy_reader.cpp (C++ background thread)
  ├── tail-read netsense_proxy.log
  ├── parse JSON line → ProxyFlow struct
  ├── push to g_state.proxyFlows ring buffer
  ├── push formatted string to g_state.logLines
  └── push to DB write queue
      │
      ├──► Live: ImGui Inspector panel reads g_state.proxyFlows
      └──► Persistent: traffic_db.cpp inserts to netsense.db
```

---

## ProxyFlow Data Struct (Full)

```cpp
struct ProxyFlow {
    std::string id;              // flow UUID from Python
    double      ts;              // unix timestamp
    std::string type;            // "REQ", "RSP", "WS_MSG"
    std::string method;          // GET, POST, PUT...
    std::string url;             // full URL
    std::string host;            // hostname only
    int         port       = 0;
    int         status     = 0;  // HTTP status code
    double      duration_ms= 0;  // request round-trip time
    long long   req_size   = 0;  // bytes
    long long   rsp_size   = 0;  // bytes
    std::string content_type;    // MIME type
    std::string query_params;    // raw query string
    std::string cookies;         // key=value pairs
    std::string body_preview;    // first 512 bytes (only if enabled)
    std::string raw_req_headers; // raw headers blob
    std::string raw_rsp_headers;
    std::string insight_tags;    // comma-separated: "streaming,api"
    bool        is_websocket = false;
    std::string process_hint;    // best-guess process name
};
```

---

## SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    started_at REAL    NOT NULL,
    ended_at   REAL    DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS flows (
    id              TEXT    PRIMARY KEY,
    session_id      INTEGER NOT NULL,
    ts              REAL,
    type            TEXT,
    method          TEXT,
    url             TEXT,
    host            TEXT,
    port            INTEGER,
    status          INTEGER,
    duration_ms     REAL,
    req_size        INTEGER,
    rsp_size        INTEGER,
    content_type    TEXT,
    query_params    TEXT,
    cookies         TEXT,
    body_preview    TEXT,
    raw_req_headers TEXT,
    raw_rsp_headers TEXT,
    insight_tags    TEXT,
    process_hint    TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_host    ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_ts      ON flows(ts);
```

---

## Settings Model (AppSettings struct)

```cpp
struct AppSettings {
    // Proxy
    int    proxyPort           = 8080;
    bool   proxyAutoStart      = false;

    // Body Capture (OFF by default)
    bool   enableBodyPreview   = false;
    int    maxBodyBytes        = 512;
    bool   jsonOnlyPreview     = true;
    bool   ignoreBinaryRsp     = true;
    bool   ignoreMediaTraffic  = true;

    // Privacy
    bool   privateMode         = false;   // disables all body + cookie logging
    bool   maskAuthHeaders     = true;    // always mask Authorization

    // Performance
    int    maxLiveFlows        = 2000;    // ring buffer size
    int    maxLogLines         = 500;

    // Storage
    bool   enableSQLite        = true;
    std::string dbPath         = "netsense.db";

    // UI
    int    themeIndex          = 0;       // 0 = Cyber Dark, 1 = Minimal
};
extern AppSettings g_settings;
```

---

## Tab Layout (ImGui)

```
┌─────────────────────────────────────────────────────────────────────┐
│ NetSense+ v3.0  │ [NET] Network │ [PROXY] Inspector │ [RULES] Rules │
│                 │ [SESSION] History │ [MOBILE] Mobile │ [>_] Settings│
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [Network Tab]                                                       │
│  Left: Process list + bandwidth bars                                 │
│  Right: Domain connection table                                      │
│  Bottom: Live log panel (unchanged from current)                     │
│                                                                      │
│  [Inspector Tab]                                                     │
│  Top: Filter bar (method, host, status, tag filter)                  │
│  Middle: Flow table (Time | Method | Status | Host | URL | Size | ms)│
│  Bottom: Expanded detail pane for selected row                       │
│    - Full URL + query params                                         │
│    - Request headers (scrollable)                                    │
│    - Response headers (scrollable)                                   │
│    - Body preview (syntax-highlighted JSON)                          │
│    - Cookies                                                         │
│    - Insight tags (colored pills)                                    │
│    - [Replay] [Copy cURL] buttons                                    │
│                                                                      │
│  [Rules Tab]                                                         │
│  Table: Enable | Type | Match | Pattern | Action                     │
│  [+ Add Rule] [Delete] [Save to rules.json]                          │
│                                                                      │
│  [Session History Tab]                                               │
│  Left: Session list from SQLite                                      │
│  Right: Flow table for selected session                              │
│  [Export Session] [Replay All] [Delete Session]                      │
│                                                                      │
│  [Mobile Tab]                                                        │
│  Local IPs listed                                                    │
│  Proxy address: 192.168.x.x:8080                                    │
│  ASCII QR code block                                                 │
│  Step-by-step Android/iPhone setup instructions                      │
│                                                                      │
│  [Settings Tab]                                                      │
│  Proxy port, HTTPS cert status, [Install Cert] [Verify Cert]        │
│  Body capture toggles, Privacy mode, Max flows, Theme selector       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Insight Detection Rules

| Condition | Tag | Color |
|---|---|---|
| YouTube, Netflix, Twitch, Spotify CDN | `[STREAM]` | Cyan |
| steam.*, xbox.*, epicgames.* | `[GAMING]` | Purple |
| WhatsApp, Telegram, Signal domains | `[MSG]` | Green |
| doubleclick, analytics, hotjar, fb pixel | `[TRACK]` | Red |
| POST + application/json | `[API]` | Orange |
| rsp_size > 5MB | `[DOWNLOAD]` | Blue |
| req_size > 1MB | `[UPLOAD]` | Yellow |
| redirect chain > 2 | `[REDIRECT]` | Gray |
| Same URL repeated > 5x in 10s | `[POLL]` | Magenta |

---

## Rules Engine (rules.json format)

```json
[
  {
    "id": "rule_001",
    "enabled": true,
    "type": "BLOCK",
    "match": "domain",
    "pattern": "doubleclick.net",
    "comment": "Block Google Ads"
  },
  {
    "id": "rule_002",
    "enabled": false,
    "type": "INJECT_HEADER",
    "match": "url_regex",
    "pattern": ".*api\\.example\\.com.*",
    "header": "X-Debug",
    "value": "1",
    "comment": "Debug API calls"
  },
  {
    "id": "rule_003",
    "enabled": true,
    "type": "BLOCK",
    "match": "domain",
    "pattern": "hotjar.com",
    "comment": "Block Hotjar tracking"
  }
]
```

---

## Replay Manager Design

```
replay_manager.cpp
    ReplayRequest(ProxyFlow& flow, edit_headers, edit_url)
        1. Build curl command:
           "<third_party/tools/curl.exe>" -X METHOD "URL" \
             -H "Header: Value" ... \
             -d "body" \
             --max-time 30 -i -s
        2. Launch via CreateProcessA (hidden window, pipe stdout)
        3. Read stdout into string
        4. Show response in ReplayResultModal (ImGui popup)
        5. Optionally save replay to current session in SQLite
```

---

## Addon System (netsense_addon.py upgrades)

The Python addon acts as the modular addon host. It has an internal plugin list:

```python
ADDONS = [
    LoggerAddon(),        # always active — writes JSON to log file
    RulesAddon(),         # reads rules.json, applies block/inject/rewrite
    InsightAddon(),       # detects streaming/gaming/messaging/tracking
    WebSocketAddon(),     # captures WS frame events
]
```

Each addon class exposes standard mitmproxy hooks:
- `request(flow)`
- `response(flow)`
- `websocket_message(flow)`

---

## package.sh Upgrades Required

```bash
# Download bundled curl.exe into third_party/tools/
curl -L -o third_party/tools/curl.exe \
  "https://curl.se/windows/dl-8.7.1_3/curl-8.7.1_3-win64-mingw.zip"
# Extract only curl.exe from zip using PowerShell
powershell -Command "..."

# Copy mitmdump.exe into third_party/mitmproxy/ instead of release root
```

---

## build.sh Upgrades Required

Add to compilation sources:
```bash
SRC_SQLITE="third_party/sqlite/sqlite3.c"
SRC_ANALYSIS="analysis/traffic_analyzer.cpp"
SRC_REPLAY="replay/replay_manager.cpp"
SRC_DB="core/traffic_db.cpp"
SRC_UI_NEW="ui/panels/inspector_panel.cpp ui/panels/rules_panel.cpp ui/panels/session_panel.cpp ui/panels/mobile_panel.cpp ui/panels/settings_panel.cpp"
```

Add linker flags:
```bash
# SQLite requires no extra -l flags when compiled as .c directly
```

---

## Execution Phases

| Phase | Description | Deliverable |
|---|---|---|
| **Phase 1** | Python addon upgrade — rich JSON output | All metadata in log file |
| **Phase 2** | `ProxyFlow` struct + rich C++ parsing | In-memory flow ring buffer |
| **Phase 3** | SQLite amalgamation + `traffic_db.cpp` | Persistent `netsense.db` |
| **Phase 4** | `traffic_analyzer.cpp` insight engine | Smart insight events in UI |
| **Phase 5** | UI tab bar + Inspector + Settings panels | 6-tab dashboard |
| **Phase 6** | Rules panel + rules.json engine | Live traffic blocking/injection |
| **Phase 7** | Session History panel + SQLite explorer | Browsable history |
| **Phase 8** | Replay manager + curl bundling | One-click request replay |
| **Phase 9** | Mobile panel + package.sh upgrades | QR setup + portable bundle |

---

## What Is Never Changed

- `core/network_monitor.cpp` — process/connection enumeration unchanged
- `dns/dns_resolver.cpp` — DNS resolution unchanged  
- `process/process_mapper.cpp` — PID mapping unchanged
- `ui/main_ui.cpp` — GLFW/OpenGL init loop unchanged
- `imgui/` — ImGui source files unchanged
- Existing **Network tab** layout — preserved as Tab 1
- Existing **recording system** — preserved, moved into Settings
- Existing **log ring buffer** — preserved, max 500 lines

---

## Guiding Principles

1. **Proxy is always optional** — entire proxy subsystem idles when `g_proxyActive = false`
2. **Body capture is opt-in** — `g_settings.enableBodyPreview` defaults to `false`
3. **Async DB writes** — UI never blocks on SQLite I/O
4. **Ring buffer first** — live panel reads memory, not disk
5. **Local binaries first** — always prefer `third_party/` before PATH lookup
6. **Modular rules** — rules.json is reloaded without restarting the app
7. **Privacy by default** — Authorization headers always masked, cookies optional

---

## GAP FILLS — Missing Items Added Below

---

## ProxyFlow Struct — Additional Fields (Gaps Fixed)

The following fields were missing and are now added to the `ProxyFlow` struct:

```cpp
struct ProxyFlow {
    // ... existing fields ...

    // NEWLY ADDED — Gap Fix
    std::string http_version;    // "HTTP/1.1", "HTTP/2", "HTTP/3"
    bool        tls_valid = false; // true if TLS cert was valid
    std::string tls_sni;          // TLS SNI hostname
    std::string redirect_chain;   // pipe-separated redirect URLs "a|b|c"
    std::string form_data;        // application/x-www-form-urlencoded POST body
    std::string ws_message;       // WebSocket frame content (if is_websocket)
    int         ws_opcode = -1;   // 1=text, 2=binary
    long long   bandwidth_bps = 0; // calculated transfer speed bytes/sec
};
```

---

## HTTPS Decryption Support — Full Workflow (Gap Fixed)

### Certificate Auto-Detection
On `StartProxyServer()`, C++ checks Windows certificate store:
```cpp
bool IsMitmCertInstalled() {
    HCERTSTORE hStore = CertOpenSystemStoreA(0, "ROOT");
    // enumerate certs, look for "mitmproxy" in Subject CN
    // return true if found
}
```

### Settings Panel — HTTPS Section
```
[HTTPS / Certificate Status]
  Status: [RED] Not Installed  /  [GREEN] Trusted & Active
  [Install Certificate]   — runs: certutil -addstore Root <cert_path>
  [Verify Certificate]    — re-runs IsMitmCertInstalled()
  [Remove Certificate]    — runs: certutil -delstore Root mitmproxy
  [Open Cert Wizard]      — shows step-by-step modal if cert missing
```

### HTTPS Setup Wizard Modal
Auto-shown on first proxy start if cert not detected:
```
Step 1: Click [Start Proxy]
Step 2: Click [Install Certificate] below
Step 3: Accept the Windows UAC prompt
Step 4: Set browser proxy to 127.0.0.1:8080
Step 5: HTTPS traffic will now be fully decrypted
```

### Proxy Diagnostics Panel (inside Settings tab)
```
[Proxy Diagnostics]
  mitmdump PID:     12345  (or NOT RUNNING)
  Proxy Port:       8080
  Cert Installed:   YES / NO
  Log File Size:    1.2 MB
  Flows Captured:   3,412
  DB Size:          8.7 MB
  [Test Connection] — sends test HTTP request through proxy, shows result
```

---

## Rules Engine — Expanded Types (Gaps Fixed)

Add the following missing rule types to `rules.json` and the Python addon:

### Throttle Rule
```json
{
  "type": "THROTTLE",
  "match": "domain",
  "pattern": "videocdn.example.com",
  "delay_ms": 2000,
  "comment": "Throttle video CDN by 2 seconds"
}
```

### Keyword Block
```json
{
  "type": "BLOCK_KEYWORD",
  "match": "url_contains",
  "pattern": "track",
  "comment": "Block any URL containing 'track'"
}
```

### Status Code Filter
```json
{
  "type": "LOG_ONLY",
  "match": "status_code",
  "pattern": "404",
  "comment": "Only log 404 responses"
}
```

### Process Filter
```json
{
  "type": "BLOCK",
  "match": "process",
  "pattern": "msedge.exe",
  "comment": "Block all traffic from Edge browser"
}
```
> Note: Process filtering in Python requires C++ to pass the process hint via a header injected before the request reaches mitmdump — `X-NetSense-Process: brave.exe`

### Response Modification (JSON Field Override)
```json
{
  "type": "MODIFY_RESPONSE_JSON",
  "match": "url_regex",
  "pattern": ".*api\\.example\\.com/user.*",
  "json_key": "isPremium",
  "json_value": "true",
  "comment": "Override isPremium to true"
}
```
Python implementation:
```python
import json as _json
if rule["type"] == "MODIFY_RESPONSE_JSON":
    try:
        body = _json.loads(flow.response.text)
        body[rule["json_key"]] = rule["json_value"]
        flow.response.text = _json.dumps(body)
    except: pass
```

### Full Rule Types Table
| Type | What it does |
|---|---|
| `BLOCK` | Kill the request immediately |
| `BLOCK_KEYWORD` | Block if URL contains keyword |
| `INJECT_HEADER` | Add header to request |
| `REWRITE_URL` | Replace URL pattern with new URL |
| `THROTTLE` | Delay response by N milliseconds |
| `MODIFY_RESPONSE_JSON` | Override a JSON field in response body |
| `REWRITE_HTML` | Replace text in HTML response |
| `LOG_ONLY` | Don't block, just always log matching flows |
| `STATUS_FILTER` | Only show flows matching a status code |
| `PROCESS_FILTER` | Block/log only flows from specific process |

---

## Addon Manager UI Panel (Gap Fixed)

Add an **Addons** sub-section inside the Settings tab:

```
[Addon Manager]
  Name              Status    Description
  ─────────────────────────────────────────────────────────
  LoggerAddon       [ON]      Writes all flows to log file
  RulesAddon        [ON]      Applies rules.json
  InsightAddon      [ON]      Smart traffic tagging
  WebSocketAddon    [OFF]     Captures WebSocket frames
  ThrottleAddon     [OFF]     Traffic throttling support

  [Enable] [Disable] [Reload All Addons]
  Last reload: 14:32:01
```

Addon enable/disable state saved to `addons.json`. Python addon reads this on startup and hot-reloads when the file changes (using `mitmproxy`'s options API).

---

## Flow Export / Import (Gap Fixed)

### Export Flows
In Session History panel:
- **[Export as JSON]** — writes all flows in session to `export_<timestamp>.json`
- **[Export as CSV]** — writes `ts,method,url,status,size,duration_ms` table

### Import Flows
- **[Import JSON]** — reads a previously exported flows JSON, creates a new "Imported" session in SQLite, loads flows into inspector

### JSON Export Format
```json
{
  "session": "My Session - 2026-05-06",
  "exported_at": 1746571200.0,
  "flows": [
    {
      "id": "abc123",
      "method": "GET",
      "url": "https://api.example.com/users",
      "status": 200,
      "duration_ms": 142.3
    }
  ]
}
```

---

## Session Timeline Visualization (Gap Fixed)

Inside Session History tab, add a **Timeline View** toggle:

```
[Table View] [Timeline View]

Timeline View:
  14:00  ──────────────────────────────────────────────────
         GET https://github.com              200  [API]
         GET https://cdn.github.com/...      200  [DOWNLOAD]
  14:01  ──────────────────────────────────────────────────
         POST https://api.github.com/...     201  [API]
         GET https://www.google-analytics... 200  [TRACK]
  14:02  ──────────────────────────────────────────────────
         ...
```

Rendered as a scrollable `ImGui::BeginChild` block with time-grouped entries.

---

## ImPlot Bandwidth Graphs (Gap Fixed — CRITICAL MISSING ITEM)

> [!IMPORTANT]
> ImPlot was completely missing from the upgrade plan. It is required for bandwidth graph visualization per Section 10.

### Integration
- Add `imgui/implot.cpp` + `imgui/implot.h` to the project (single-file, header-only compatible)
- Add `imgui/implot_items.cpp` for plot rendering primitives

### Usage in Network Tab
```cpp
// In ui/panels/main_panel.cpp — Network tab
if (ImPlot::BeginPlot("##BandwidthGraph", ImVec2(-1, 120))) {
    ImPlot::SetupAxes("Time", "KB/s", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
    ImPlot::PlotLine("Download", g_bwHistory_in.data(), g_bwHistory_in.size());
    ImPlot::PlotLine("Upload",   g_bwHistory_out.data(), g_bwHistory_out.size());
    ImPlot::EndPlot();
}
```

### History Buffer (in AppState)
```cpp
std::deque<float> bwHistoryIn;   // last 120 samples = 2 min at 1s interval
std::deque<float> bwHistoryOut;
```

Updated every second by `network_monitor.cpp`.

### Build Integration
Add to `build.sh`:
```bash
SRC_IMPLOT="imgui/implot.cpp imgui/implot_items.cpp"
```

---

## Live Request Timeline Panel (Gap Fixed)

Add **Timeline** as an optional sub-view in the Inspector tab (toggle button):

```
[Inspector Tab] → [Flow Table] | [Live Timeline]

Live Timeline:
  ▶ 14:32:01.123  GET   https://api.github.com/repos  200  142ms  [API]
  ▶ 14:32:01.456  GET   https://avatars.github.com/   200  89ms   [DOWNLOAD]
  ▶ 14:32:02.001  POST  https://api.github.com/...    201  201ms  [API]
```

Renders as a live auto-scrolling list using `g_state.proxyFlows` ring buffer.  
Color-coded by method and insight tag.

---

## Suspicious Bandwidth Spike Detection (Gap Fixed)

Add to `analysis/traffic_analyzer.cpp`:

```cpp
// Spike detection: if bps jumps > 5x average in last 10s → alert
void CheckBandwidthSpike(uint64_t currentBps, uint64_t avgBps) {
    if (currentBps > avgBps * 5 && currentBps > 5 * 1024 * 1024) {
        g_state.addLog("[ALERT] Suspicious bandwidth spike: " + FmtSpeed(currentBps));
    }
}
```

Also add to insight detection table:
| Condition | Tag | Color |
|---|---|---|
| bps > 5x 10s average AND > 5MB/s | `[SPIKE]` | Bright Red |
| Same host > 20 requests in 5s | `[FLOOD]` | Red |
| Repeated identical POST > 5x | `[RETRY]` | Orange |

---

## Security + Privacy Controls — Full Implementation (Gap Fixed)

### Missing Items Added

**Encrypted Session Storage (Optional)**
- `AppSettings::encryptDB = false` by default
- When enabled, uses SQLite's SQLCipher-compatible XOR key on `body_preview` and `cookies` columns only
- Key stored in Windows Credential Manager via `CryptProtectData()`

**Clear Session Tools**
In Settings tab:
```
[Privacy Controls]
  [Clear Live Logs]        — clears g_state.logLines + proxyFlows
  [Clear Current Session]  — deletes current session rows from SQLite
  [Delete All Sessions]    — drops and recreates all SQLite tables
  [Wipe Addon Cache]       — deletes netsense_proxy.log
```

**AppSettings additions:**
```cpp
bool   encryptSensitiveFields = false;
bool   storeCookies           = false; // OFF by default
bool   storeFormData          = false; // OFF by default
```

---

## Performance — Batched UI Updates + Lazy Loading (Gap Fixed)

### Batched UI Updates
- `g_state.proxyFlows` is only copied to a local render snapshot **once per frame**, not per-widget
- Analyzer thread pushes insight strings into a `std::queue<std::string> g_pendingInsights` (lock-free SPSC queue)
- Main thread drains `g_pendingInsights` at start of each frame (max 20 items per frame)

### Lazy Loading
- Inspector detail pane only parses `raw_req_headers` / `raw_rsp_headers` when a row is **actually selected**
- Session History panel uses **paginated SQLite queries** (`LIMIT 100 OFFSET N`) — never loads entire DB into RAM
- Flow table uses `ImGuiListClipper` to only render visible rows, not all 2000

### Lightweight Idle Mode
- When proxy is stopped and no flows are incoming, analyzer thread sleeps for 500ms between checks
- Network monitor poll rate drops from 2s to 5s when no UI tab is focused (detected via `glfwGetWindowAttrib GLFW_FOCUSED`)

---

## Section 13: Future-Ready Expansion (COMPLETELY MISSING — Now Added)

> [!NOTE]
> These are architecture hooks and stubs — not implemented in current phases, but the code structure must not block them.

### Npcap Integration Hook
- Add `core/packet_capture.h` with stub: `bool StartNpcapCapture()` / `StopNpcapCapture()`
- When Npcap is installed, this replaces the `iphlpapi` TCP table poll with real packet sniffing
- Enables: DNS packet inspection, UDP traffic, ICMP, raw protocol detection

### DNS Packet Inspection
- Stub: `dns/dns_inspector.cpp` — listens for DNS queries and maps them to PIDs
- Feeds into domain stats for processes that don't go through the HTTP proxy
- Future: show DNS query history per process in Network tab

### Protocol Categorization Engine
- Add `analysis/protocol_classifier.cpp`
- Uses port + domain + TLS SNI + content-type to classify flows as:
  `HTTP_API | STREAMING | GAMING | VOIP | FILE_TRANSFER | UNKNOWN`
- Feeds into a future Protocol Distribution pie chart

### Activity Timeline Engine
- `storage/timeline_engine.cpp` — time-indexed event store separate from flows
- Stores: `{ts, event_type, process, detail}` — lightweight, fast insert
- Powers a future "Activity Heatmap" view (what was active at what time)

### Background Monitoring Agent
- Future architecture option: separate lightweight `NetSenseAgent.exe`
- Runs without UI, monitors traffic, writes to shared SQLite DB
- `NetSenseUI.exe` connects to the same DB for historical viewing
- IPC via named pipe or shared memory segment

### Historical Analytics (Future)
- Session comparison: compare two sessions side-by-side
- Domain frequency charts (most-contacted hosts over time)
- Bandwidth usage by app over days/weeks
- Powered by the existing SQLite schema — no schema changes needed

### Expanded Project Structure for Future Modules
```
Netsense/
├── core/
│   └── packet_capture.h     [STUB]  — Npcap hook
├── analysis/
│   ├── traffic_analyzer.cpp [CURRENT]
│   └── protocol_classifier.cpp [FUTURE STUB]
├── storage/
│   ├── traffic_db.cpp        [CURRENT]
│   └── timeline_engine.cpp   [FUTURE STUB]
├── dns/
│   ├── dns_resolver.cpp      [KEEP]
│   └── dns_inspector.cpp     [FUTURE STUB]
└── agent/                    [FUTURE]
    └── netsense_agent.cpp
```

---

## Complete Gap Checklist — All 13 Sections Verified

| Req | Section | Status |
|---|---|---|
| 1 | Advanced Request Inspection | ✅ ProxyFlow struct + Inspector panel + http_version + TLS fields added |
| 2 | HTTPS Decryption Support | ✅ Cert auto-detect + wizard + diagnostics panel added |
| 3 | Real-Time Traffic Modification | ✅ Rules engine + response JSON override + throttle + rewrite added |
| 4 | Blocking + Filtering Engine | ✅ All rule types added: domain/keyword/regex/MIME/status/process |
| 5 | Request Replay System | ✅ Replay manager + export/import + duplicate + modify-then-replay |
| 6 | Session Recording | ✅ SQLite sessions + timeline view + export JSON/CSV + bandwidth field |
| 7 | Advanced Python Addon System | ✅ Modular addons + Addon Manager UI panel + hot-reload |
| 8 | Smart Traffic Analysis | ✅ Insight engine + spike detection + retry/flood detection |
| 9 | Mobile Device Interception | ✅ Mobile panel + QR + IP detection + Android/iPhone instructions |
| 10 | UI Upgrade | ✅ 6-tab layout + ImPlot graphs + live timeline + expandable inspector |
| 11 | Performance + Architecture | ✅ Threading model + batched updates + lazy loading + idle mode |
| 12 | Security + Privacy Controls | ✅ Private mode + encrypted fields + clear-session tools + masking |
| 13 | Future-Ready Expansion | ✅ Npcap hooks + DNS inspector + protocol classifier + timeline engine |

