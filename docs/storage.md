# Storage Architecture — NetSense+

## Storage Subsystems

```
NetSense+ Storage
├── SQLite (netsense.db)        ← structured, queryable
│   ├── sessions table
│   └── flows table
│
├── rules.json                  ← live rules (C++ owned)
├── predefined_packs.json       ← read-only pack library
├── settings.json               ← user preferences (versioned)
│
├── Logs (JSON-Lines)           ← append-only
│   ├── proxy/netsense_proxy.log
│   ├── proxy/netsense_alerts.log
│   └── proxy/netsense_saved_matches.jsonl
│
└── recordings/                 ← text session exports
```

---

## SQLite Schema

### `sessions` table
```sql
CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    started_at REAL    NOT NULL,   -- Unix epoch (double)
    ended_at   REAL    DEFAULT NULL
);
```

### `flows` table
```sql
CREATE TABLE flows (
    id              TEXT    PRIMARY KEY,   -- UUID from mitmproxy
    session_id      INTEGER NOT NULL,
    ts              REAL,                  -- Unix epoch
    type            TEXT,                  -- REQ / RSP / WS_MSG
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
    insight_tags    TEXT,                  -- comma-separated
    process_hint    TEXT,
    http_version    TEXT,
    tls_valid       INTEGER,               -- 0/1
    tls_sni         TEXT,
    redirect_chain  TEXT,
    form_data       TEXT,
    ws_message      TEXT,
    ws_opcode       INTEGER,
    bandwidth_bps   INTEGER,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);
CREATE INDEX idx_flows_session ON flows(session_id);
CREATE INDEX idx_flows_host    ON flows(host);
CREATE INDEX idx_flows_ts      ON flows(ts);
```

---

## Write Pattern (Thread Safety)

**Never** call `sqlite3_exec()` from UI or background threads directly.

**Always** use the async queue:
```cpp
TrafficDB::QueueFlowInsert(sessionId, flow);
```

The DB worker thread drains the queue in batches (inside a single transaction for performance).

---

## settings.json (Versioned)

```json
{
  "version": 2,
  "proxyPort": 8080,
  "uiScale": 1.0,
  "enableBodyPreview": false,
  "storeFormData": false,
  "encryptSensitiveFields": false,
  "maxLiveFlows": 2000,
  "maxLogLines": 500,
  "enableSQLite": true,
  "mitmdumpPath": "",
  "themeIndex": 0
}
```

### Migration
When `SETTINGS_VERSION` in `settings_persist.cpp` > file's `version` field:
- `MigrateSettings()` fills in missing fields with defaults
- Next `SaveSettings()` writes the new version number
- Old `settings.json` is backed up as `settings.json.bak`

### Recovery
If `settings.json` is invalid JSON:
- Renamed to `settings.json.corrupt`
- Application starts with defaults
- No crash

---

## Log Files (JSON-Lines)

Each line is one parseable JSON object. Never use raw text for machine-readable logs.

### `netsense_proxy.log`
Written by: Python `netsense_addon.py`  
Read by: C++ `proxy_reader.cpp`  
Format: See `docs/proxy_pipeline.md`

### `netsense_alerts.log`
Written by: Python `ALERT_ON_MATCH` action  
Format:
```json
{"ts": 1778601234, "ts_iso": "2026-05-13T00:00:00Z", "rule_id": "sh_alert_login", "url": "evil.com/login", "method": "POST"}
```

### `netsense_saved_matches.jsonl`
Written by: Python `SAVE_MATCHES` action  
Format: Same as alert but includes flow metadata

### `logs/` (Structured C++ Logs)
Written by: `utils/structured_log.cpp`  
One file per channel: `proxy.log`, `rules.log`, `alerts.log`, `errors.log`  
Format:
```json
{"ts": 1778601234, "ts_iso": "2026-05-13T00:00:00Z", "level": "INFO", "channel": "rules.log", "msg": "RULE_HIT", "data": {"rule_id": "dt_log_api", "url": "/api/users"}}
```

---

## Data Management (Settings Panel)

| Button | Action |
|---|---|
| **Delete Logs Only** | Deletes `netsense_proxy.log`, `alerts.log`, `saved_matches.jsonl`, `recordings/*.txt`. Clears `g_state.logLines`. |
| **Delete DB Only** | Runs `DELETE FROM flows; DELETE FROM sessions;`. Resets `currentSessionId`. |
| **Master Clean** | All of the above + clears `g_state.proxyFlows`. |

All operations use `GetModuleFileNameA` for exe-relative absolute paths — no CWD dependency.

---

## Future: Storage Abstraction

Planned `storage/` directory:
```cpp
// storage/session_store.h
namespace SessionStore {
    int  Create(const std::string& name);
    void End(int id);
    std::vector<SessionMeta> GetAll();
    void Delete(int id);
}

// storage/flow_store.h
namespace FlowStore {
    void Insert(int sessionId, const ProxyFlow&);
    std::vector<ProxyFlow> Query(int sessionId, FlowFilter);
    void DeleteOlderThan(double epochSec);
    size_t Count(int sessionId);
}
```

This wraps all `sqlite3_*` calls behind typed interfaces, making it safe to replace SQLite with any other backend later.
