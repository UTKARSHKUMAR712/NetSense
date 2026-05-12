# Proxy Pipeline — NetSense+

## Full Request/Response Lifecycle

```
Client (browser/app)
        │  HTTPS request
        ▼
  mitmdump.exe  (port 8080)
        │
   TLS termination
        │
   netsense_addon.py  (mitmproxy addon)
        │
   ┌────▼────────────────────────────────────────┐
   │  1. RuleLoader.rules()  ← rules.json        │
   │  2. Sort by priority                        │
   │  3. For each rule:                          │
   │     a. RuleConditionEvaluator.check()       │
   │     b. RuleMatcher.matches()                │
   │     c. RuleExecutor.execute_request()       │
   │        → may BLOCK, REDIRECT, INJECT, etc.  │
   │        → returns True → stop processing     │
   └─────────────────────────────────────────────┘
        │  (modified) request
        ▼
   Origin server
        │  response
        ▼
   ┌────▼────────────────────────────────────────┐
   │  Same pipeline for execute_response()       │
   │  (MODIFY_JSON, INJECT_RSP_HEADER, etc.)     │
   └─────────────────────────────────────────────┘
        │
   Log to netsense_proxy.log (JSON-Lines)
        │
   Client receives response
```

---

## Log Format (JSON-Lines)

Each line in `netsense_proxy.log` is one JSON object:

**Request entry (type=REQ):**
```json
{
  "type": "REQ",
  "id": "abc123",
  "ts": 1778601234.5,
  "method": "GET",
  "url": "https://httpbin.org/get",
  "host": "httpbin.org",
  "port": 443,
  "http_version": "HTTP/2.0",
  "req_size": 512,
  "query_params": "?foo=bar",
  "cookies": {},
  "req_headers": {"User-Agent": "..."},
  "tls_valid": true,
  "tls_sni": "httpbin.org",
  "insight_tags": ["api"],
  "is_websocket": false
}
```

**Response entry (type=RSP):**
```json
{
  "type": "RSP",
  "id": "abc123",
  "ts": 1778601234.9,
  "status": 200,
  "duration_ms": 342.1,
  "rsp_size": 1024,
  "content_type": "application/json",
  "body_preview": "{\"uuid\":\"...\"}",
  "rsp_headers": {"Content-Type": "application/json"}
}
```

---

## How C++ Reads the Log

`core/proxy_reader.cpp` runs `ProxyLoop()` in a background thread:
1. Opens `proxy/netsense_proxy.log` and seeks to end (skips old data)
2. Every 500ms: reads new lines, parses JSON, fills `ProxyFlow` structs
3. Pushes to `g_state.proxyFlows` (ring buffer, max 2000 entries)
4. If SQLite is enabled, queues for async DB write

---

## Proxy Startup Sequence

1. User clicks **Start Proxy** (UI thread — holds `g_state.mtx`)
2. `StartProxyServer()` is called:
   - Resolves `mitmdump.exe` path (user setting → auto-detect → error)
   - Verifies `proxy/netsense_addon.py` exists
   - Calls `CreateProcessA` to launch `mitmdump.exe --listen-port 8080 -s addon.py`
   - Returns `true/false` immediately (non-blocking)
3. Startup log messages queued in `g_pendingLogs` (own mutex, no deadlock)
4. `ProxyLoop` flushes pending logs to UI on next iteration

---

## Proxy Crash Recovery

`ProxyLoop()` polls every 5 seconds:
```
WaitForSingleObject(g_hProxyProcess, 0)
  → WAIT_OBJECT_0 = process exited unexpectedly
  → Auto-restart: calls StartProxyServer() again
  → Logs "[PROXY] Auto-restart successful" or error
```

---

## mitmproxy CA Certificate

Required for HTTPS interception. Install once:
1. Run `mitmdump.exe` once manually — generates cert in `%USERPROFILE%\.mitmproxy\`
2. Browse to `http://mitm.it` through the proxy and install the certificate
3. OR: run `certutil -addstore root mitmproxy-ca-cert.cer` (Administrator)

Sites with certificate pinning (mobile apps, some desktop apps) will not be intercepted — they will fail to connect or bypass the proxy.

---

## Future: Python Submodule Refactor

`rule_engine.py` will be split into `proxy/rules/`:

```
proxy/rules/
├── __init__.py
├── loader.py       ← RuleLoader (hot-reload)
├── matcher.py      ← RuleMatcher (domain/regex/wildcard)
├── conditions.py   ← RuleConditionEvaluator
├── actions.py      ← RuleExecutor (16 actions)
├── validator.py    ← RuleValidator
└── hit_counter.py  ← batched hit count write-back
```

`netsense_addon.py` becomes a thin 30-line orchestrator.
