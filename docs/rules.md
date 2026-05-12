# Rules Engine — NetSense+

## Architecture Overview

```
C++ UI (rules_panel.cpp)
    │ user adds/edits rule
    ▼
RuleManager::Save() → rules.json
                           │
                    [2s hot-reload]
                           │
                    Python RuleLoader
                           │
                    ┌──────┴────────┐
               RuleMatcher     RuleConditionEvaluator
                    │
               RuleExecutor
                    │
             mitmproxy flow (modified)
```

---

## Rule JSON Schema

```json
{
  "id":          "unique_rule_id",
  "type":        "BLOCK | INJECT_HEADER | REDIRECT | ...",
  "match":       "domain | url | regex | keyword | body",
  "pattern":     "example.com",
  "enabled":     true,
  "priority":    1,
  "description": "Human-readable description",
  "config": {
    "key":   "optional config key",
    "value": "optional config value"
  },
  "conditions": {
    "mime":    "application/json",
    "status":  200,
    "method":  "GET"
  }
}
```

---

## All 16 Rule Types

| Type | Phase | Effect |
|---|---|---|
| `BLOCK` | Request | Kill connection (407 response) |
| `BLOCK_KEYWORD` | Request | Block if URL contains keyword |
| `BLOCK_METHOD` | Request | Block specific HTTP method |
| `BLOCK_TRACKERS` | Request | Auto-block 17 known tracker domains |
| `INJECT_HEADER` | Request | Add/replace request header |
| `RESPONSE_HEADER_INJECT` | Response | Add/replace response header |
| `REDIRECT` | Request | Return 301/302 to new URL |
| `REWRITE_URL` | Request | String-replace in URL (`config.find` → `config.replace`) |
| `THROTTLE` | Request | Sleep N ms before forwarding |
| `LIMIT_BANDWIDTH` | Response | Chunk body with delays |
| `MODIFY_JSON` | Response | Edit JSON field (dot-notation path) |
| `LOG_ONLY` | Request | Write to `proxy.log`, no modification |
| `ALERT_ON_MATCH` | Request | Write to `alerts.log` |
| `SAVE_MATCHES` | Request | Append to `saved_matches.jsonl` |
| `DROP_RESPONSE` | Response | Zero out response body |
| `BLOCK_MEDIA` | Response | Block video/audio/image MIME types |

---

## Match Modes

| Mode | Matches against | Example pattern |
|---|---|---|
| `domain` | `flow.request.host` | `example.com`, `*.example.com` |
| `url` | Full URL string | `example.com/api/v2` |
| `regex` | Full URL (re.search) | `\\.(m3u8|ts)(\\?|$)` |
| `keyword` | Full URL (substring) | `/admin`, `tracking_pixel` |
| `body` | Response body text | `"error":true` |

Wildcard `*` in domain mode matches any subdomain: `*.evil.com` matches `ads.evil.com`.

---

## Rule Priority and Stop-Processing

Rules are sorted by `priority` (ascending) before execution. Lower number = runs first.

Actions that return `True` from `execute_request()` / `execute_response()` stop further rule processing for that flow. This applies to: `BLOCK`, `REDIRECT`, `REWRITE_URL`.

---

## Hot-Reload

`RuleLoader` polls `rules.json` file mtime every 2 seconds. No proxy restart required.

```python
if os.path.getmtime(RULES_FILE) > self._last_mtime:
    self._load()
```

---

## Adding a New Rule Type

1. **Python** (`proxy/rule_engine.py`): Add a case in `RuleExecutor.execute_request()` or `execute_response()`
2. **C++ UI** (`ui/panels/rule_editor_modal.cpp`): Add config fields in the `CfgInput` block for that type
3. **C++ Validation** (`rule_editor_modal.cpp` `Validate()`): Add required field checks
4. **Preview** (`rule_editor_modal.cpp` `PreviewText()`): Add human-readable preview
5. **Test rule**: Add to `proxy/predefined_packs.json` in the Test Suite pack
6. **Docs**: Add row to the table above

---

## Predefined Packs

14 packs, 90+ rules. Stored in `proxy/predefined_packs.json`.

When a pack is enabled via UI:
1. `OnPackToggled()` in `rules_panel.cpp` is called
2. Pack rules are merged with custom rules
3. Merged set written to `rules.json`
4. Python hot-reloads within 2 seconds

Packs do NOT overwrite custom rules — merge preserves both.

---

## rules.json Backup / Recovery

If `rules.json` is corrupted (invalid JSON):
- Python `RuleLoader` catches the parse exception and retains the last valid rule set
- C++ `RuleManager::Load()` catches parse exceptions and resets to empty

To manually recover:
```bash
echo "[]" > release/proxy/rules.json
```
