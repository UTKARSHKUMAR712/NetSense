# NetSense+ Advanced Implementation Guide

**Version:** 3.0 Advanced  
**Architecture:** Extend-only — no rewrites, fully modular  

> For the complete technical design, see [upgrade.md](./upgrade.md)

---

## What NetSense+ v3.0 Adds

| Feature | Status |
|---|---|
| Rich HTTP/HTTPS traffic inspection | Phase 1-2 |
| Smart insight tagging (streaming, gaming, tracking) | Phase 4 |
| SQLite session history | Phase 3 |
| Live blocking/filtering/modification rules | Phase 6 |
| Request replay (one-click resend) | Phase 8 |
| Mobile device proxying + QR setup | Phase 9 |
| ImPlot bandwidth graphs | Phase 5 |
| HTTPS certificate wizard | Phase 5 |
| Modular Python addon system | Phase 1 |
| Encrypted sensitive field storage | Phase 7 |

---

## Prerequisites

### Required (already in your repo)
- MSYS2 UCRT64 with `g++` 15+
- `libglfw3`, `libopengl32` (already linked)
- `imgui/` source files (already present)

### New — Auto-handled by `package.sh`
- `mitmdump.exe` → bundled in `third_party/mitmproxy/`
- `curl.exe` → bundled in `third_party/tools/`
- `sqlite3.c` + `sqlite3.h` → bundled in `third_party/sqlite/`
- `implot.cpp` + `implot.h` → added to `imgui/`

### One-Time User Setup (HTTPS only)
1. Run `NetSense.exe` as Administrator
2. Click **Start Proxy**
3. Go to **Settings → Install Certificate**
4. Accept the Windows UAC prompt
5. Done — all HTTPS traffic is now decryptable

---

## Build

```bash
# Build + bundle everything in one command
bash package.sh
```

Output: `release/` folder with `NetSense.exe` + `mitmdump.exe` + `curl.exe`

### Manual build only
```bash
bash build.sh
```

---

## Project Structure

```
Netsense/
├── core/
│   ├── app_data.h          — AppState, ProxyFlow, AppSettings structs
│   ├── network_monitor.cpp — TCP/process enumeration (UNCHANGED)
│   ├── proxy_reader.cpp    — mitmproxy log tail + JSON parsing
│   └── traffic_db.cpp      — SQLite async write layer
│
├── analysis/
│   └── traffic_analyzer.cpp — Smart insight tagging engine
│
├── replay/
│   └── replay_manager.cpp   — curl-backed request replay
│
├── ui/panels/
│   ├── main_panel.cpp        — Tab bar + Network tab (existing)
│   ├── inspector_panel.cpp   — Rich flow table + detail pane
│   ├── rules_panel.cpp       — Block/intercept rule editor
│   ├── session_panel.cpp     — SQLite history + timeline view
│   ├── mobile_panel.cpp      — Mobile device QR setup
│   └── settings_panel.cpp   — Cert, proxy, privacy, addons
│
├── proxy/
│   └── netsense_addon.py     — mitmproxy addon (rich JSON output)
│
└── third_party/
    ├── sqlite/               — sqlite3.c amalgamation (no DLL needed)
    ├── mitmproxy/            — mitmdump.exe standalone
    └── tools/                — curl.exe standalone
```

---

## UI Tabs Overview

| Tab | Key Features |
|---|---|
| **[NET] Network** | Process list, bandwidth bars, domain table, live log |
| **[PROXY] Inspector** | Flow table, expandable detail, [Replay], [Copy cURL] |
| **[RULES] Rules** | Add/edit/delete traffic rules, save to rules.json |
| **[SESSION] History** | Browse past sessions, timeline view, export JSON/CSV |
| **[MOBILE] Mobile** | Local IPs, proxy address, QR code, setup guide |
| **[>_] Settings** | Cert install, proxy port, body capture, privacy, addons |

---

## Traffic Rules (rules.json)

Rules are applied by the Python addon in real-time. Edit from the UI or manually.

### Rule Types
| Type | Effect |
|---|---|
| `BLOCK` | Drop the request immediately |
| `BLOCK_KEYWORD` | Block if URL contains text |
| `INJECT_HEADER` | Add custom header to request |
| `REWRITE_URL` | Redirect request to different URL |
| `THROTTLE` | Delay response by N milliseconds |
| `MODIFY_RESPONSE_JSON` | Override a JSON field in response |
| `REWRITE_HTML` | Replace text in HTML response body |
| `LOG_ONLY` | Log matching flows without blocking |
| `STATUS_FILTER` | Only surface flows with specific status code |
| `PROCESS_FILTER` | Apply rule only for a specific process |

### Example: Block All Tracking
```json
[
  {"type":"BLOCK","match":"domain","pattern":"doubleclick.net","enabled":true},
  {"type":"BLOCK","match":"domain","pattern":"hotjar.com","enabled":true},
  {"type":"BLOCK_KEYWORD","match":"url_contains","pattern":"analytics","enabled":true}
]
```

### Example: JSON Modification
```json
[
  {
    "type": "MODIFY_RESPONSE_JSON",
    "match": "url_regex",
    "pattern": ".*api\\.example\\.com/user.*",
    "json_key": "isPremium",
    "json_value": "true",
    "enabled": true
  }
]
```

---

## Smart Insights

The analyzer automatically tags every captured flow:

| Tag | Trigger |
|---|---|
| `[STREAM]` | YouTube, Netflix, Twitch, Spotify CDNs |
| `[GAMING]` | Steam, Xbox, Epic Games |
| `[MSG]` | WhatsApp, Telegram, Signal |
| `[TRACK]` | Google Analytics, Hotjar, Facebook Pixel |
| `[API]` | POST with application/json |
| `[DOWNLOAD]` | Response > 5MB |
| `[UPLOAD]` | Request body > 1MB |
| `[POLL]` | Same URL > 5 times in 10 seconds |
| `[SPIKE]` | Bandwidth > 5× 10-second average |
| `[FLOOD]` | Same host > 20 requests in 5 seconds |
| `[RETRY]` | Identical POST repeated > 5 times |
| `[REDIRECT]` | Redirect chain length > 2 |

---

## Session Recording

1. Go to **Settings → Start New Session** (or auto-starts with proxy)
2. Browse normally — all flows saved to `netsense.db`
3. Open **Session History** tab
4. Select a session → browse, search, filter flows
5. Click **[Export as JSON]** or **[Export as CSV]**
6. Click **[Replay]** on any flow to resend it

---

## Request Replay

1. Open **Inspector** tab
2. Select any captured flow
3. Click **[Replay]** — sends the original request via bundled `curl.exe`
4. View response in the Replay Result modal
5. Edit headers/URL before replaying if needed
6. Click **[Copy cURL]** to get the exact terminal command

---

## Python Addon System

The proxy is powered by a modular Python addon in `proxy/netsense_addon.py`.

### Built-in Addons
| Addon | Purpose |
|---|---|
| `LoggerAddon` | Always active — writes rich JSON to log file |
| `RulesAddon` | Reads `rules.json`, applies all rule types |
| `InsightAddon` | Tags flows with streaming/gaming/tracking labels |
| `WebSocketAddon` | Captures WebSocket frame events |
| `ThrottleAddon` | Implements throttle rules |

### Addon Manager (UI)
In Settings → Addon Manager:
- Enable/disable each addon with a toggle
- Click **[Reload All Addons]** after changing `addons.json`
- Addon state persists across proxy restarts

---

## Privacy & Security

| Setting | Default | Description |
|---|---|---|
| Body Preview | OFF | Capture request/response bodies |
| Store Cookies | OFF | Save cookie values to DB |
| Store Form Data | OFF | Save POST form submissions |
| Mask Auth Headers | ON | Always hide Authorization values |
| Private Mode | OFF | Disables ALL body/cookie logging |
| Encrypt Sensitive Fields | OFF | XOR-encrypt body/cookie in SQLite |

### Clear Data
Settings → Privacy Controls:
- **[Clear Live Logs]** — clears current session from memory
- **[Clear Current Session]** — removes DB rows for current session
- **[Delete All Sessions]** — full DB wipe
- **[Wipe Addon Cache]** — deletes `netsense_proxy.log`

---

## Mobile Device Setup

1. Open **Mobile** tab
2. Note the proxy address shown: e.g. `192.168.1.42:8080`
3. Scan the QR code or enter manually in phone WiFi settings
4. For HTTPS: visit `mitm.it` on the device to install the cert

### Android
Settings → WiFi → Long-press network → Modify → Advanced → Manual Proxy

### iPhone
Settings → WiFi → (i) → Configure Proxy → Manual

---

## Performance Notes

- **Live panel** reads from in-memory ring buffer (max 2000 flows) — always fast
- **SQLite writes** are async — UI never blocks on disk I/O
- **Inspector detail pane** parses headers only when a row is selected (lazy)
- **Session History** uses paginated queries (100 rows at a time) — never loads full DB
- **Flow table** uses `ImGuiListClipper` — only renders visible rows

---

## Future Expansion Hooks

The architecture is ready for:
- **Npcap** — replace TCP table poll with real packet capture (`core/packet_capture.h` stub)
- **DNS Inspection** — map DNS queries to PIDs (`dns/dns_inspector.cpp` stub)
- **Protocol Classifier** — classify flows beyond HTTP (`analysis/protocol_classifier.cpp` stub)
- **Background Agent** — headless `NetSenseAgent.exe` writing to shared DB
- **Historical Analytics** — session comparison, domain frequency, bandwidth heatmaps

---

## Execution Phases

| Phase | What Changes | Result |
|---|---|---|
| 1 | Python addon → rich JSON | Full metadata captured |
| 2 | `ProxyFlow` struct + parsing | In-memory flow buffer |
| 3 | SQLite + `traffic_db.cpp` | Persistent sessions |
| 4 | `traffic_analyzer.cpp` | Smart insight tags |
| 5 | UI tab bar + Inspector + Settings | 6-tab dashboard |
| 6 | Rules panel + `rules.json` engine | Live blocking/modification |
| 7 | Session History + timeline | Browsable history + export |
| 8 | Replay manager + curl | One-click request replay |
| 9 | Mobile panel + package.sh | QR setup + portable bundle |
