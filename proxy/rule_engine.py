"""
NetSense+ rule_engine.py  — Phase 6 Refactored
===============================================
Live rule execution engine for mitmproxy.

Architecture:
  RuleLoader   — thread-safe hot-reload from rules.json
  RuleMatcher  — all match modes with subdomain/regex support
  RuleConditionEvaluator — MIME_ONLY / PROCESS_ONLY / STATUS_CODE_MATCH
                           as pre-conditions, not standalone rules
  RuleExecutor — action execution per phase (request / response)
  HitCounter   — async-safe batched write-back to rules.json

IMPORTANT: Do NOT run standalone. Loaded by netsense_addon.py.
"""

import json
import os
import re
import time
import threading
from typing import Optional

# pyrefly: ignore [missing-import]
from mitmproxy import http

# ──────────────────────────────────────────────────────────────
#  File paths
# ──────────────────────────────────────────────────────────────
_DIR        = os.path.dirname(os.path.abspath(__file__))
_RULES_FILE = os.path.join(_DIR, "rules.json")
_LOG_FILE   = os.path.join(_DIR, "netsense_proxy.log")
_ALERT_FILE = os.path.join(_DIR, "netsense_alerts.log")
_SAVES_FILE = os.path.join(_DIR, "netsense_saved_matches.jsonl")

# ──────────────────────────────────────────────────────────────
#  Known tracker domains and media types (shared constants)
# ──────────────────────────────────────────────────────────────
TRACKER_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "adservice.google.com",
    "hotjar.com", "analytics.google.com", "scorecardresearch.com",
    "comscore.com", "quantserve.com", "advertising.com", "adnxs.com",
    "rlcdn.com", "moatads.com", "amazon-adsystem.com", "pubmatic.com",
    "rubiconproject.com", "openx.net", "criteo.com",
}
TRACKER_KEYWORDS = frozenset([
    "telemetry", "analytics", "metrics", "tracking",
    "fingerprint", "beacon", "pixel", "collect",
])
MEDIA_MIME = ("video/", "audio/", "image/")


# ══════════════════════════════════════════════════════════════
#  RuleLoader — thread-safe, hot-reload
# ══════════════════════════════════════════════════════════════
class RuleLoader:
    def __init__(self):
        self._lock       = threading.Lock()
        self._rules      = []          # enabled rules sorted by priority
        self._regex_cache: dict        = {}
        self._last_mtime = -1.0
        self._writing    = False       # flag: suppress reload during hit-count write
        self._hit_counts: dict         = {}
        self._hit_dirty  = 0           # incremented each hit; flush every N

    def _compile(self, pattern: str) -> re.Pattern:
        if pattern not in self._regex_cache:
            try:
                self._regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                self._regex_cache[pattern] = re.compile(re.escape(pattern), re.IGNORECASE)
        return self._regex_cache[pattern]

    def reload(self):
        """Check mtime and reload rules if file changed. Thread-safe."""
        if not os.path.exists(_RULES_FILE):
            return
        try:
            mtime = os.path.getmtime(_RULES_FILE)
        except OSError:
            return

        with self._lock:
            if mtime == self._last_mtime or self._writing:
                return
            try:
                with open(_RULES_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            except Exception as e:
                _log({"type": "RULE_ENGINE_ERROR", "tag": "[RULE LOAD]", "msg": str(e), "ts": time.time()})
                return

            # Only keep enabled rules; sort by priority ascending
            self._rules = sorted(
                [r for r in raw if r.get("enabled", True)],
                key=lambda r: r.get("priority", 0)
            )
            # Pre-compile regex patterns
            self._regex_cache.clear()
            for r in self._rules:
                if r.get("match") == "regex":
                    pat = r.get("pattern", "") or r.get("match_config", {}).get("pattern", "")
                    if pat:
                        self._compile(pat)

            self._last_mtime = mtime
            _log({
                "type": "RULE_EVENT",
                "tag": "[RULE LOAD]",
                "count": len(self._rules),
                "ts": time.time(),
            })

    def rules(self) -> list:
        with self._lock:
            return list(self._rules)

    def inc_hit(self, rule: dict):
        rid = rule.get("id", "")
        if not rid:
            return
        with self._lock:
            self._hit_counts[rid] = self._hit_counts.get(rid, 0) + 1
            self._hit_dirty += 1
            if self._hit_dirty >= 25:
                self._hit_dirty = 0
                self._flush_hits_locked()

    def _flush_hits_locked(self):
        """Write hit_count updates back. Called inside _lock."""
        if not self._hit_counts or not os.path.exists(_RULES_FILE):
            return
        try:
            self._writing = True
            with open(_RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            changed = False
            for item in data:
                rid = item.get("id", "")
                if rid in self._hit_counts:
                    item["hit_count"] = self._hit_counts[rid]
                    changed = True
            if changed:
                tmp = _RULES_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
                os.replace(tmp, _RULES_FILE)
                self._last_mtime = os.path.getmtime(_RULES_FILE)
        except Exception:
            pass
        finally:
            self._writing = False

    def force_flush_hits(self):
        with self._lock:
            self._flush_hits_locked()

    def invalidate(self):
        """Force next reload regardless of mtime (e.g., after pack disable)."""
        with self._lock:
            self._last_mtime = -1.0


# ══════════════════════════════════════════════════════════════
#  RuleMatcher — all match modes
# ══════════════════════════════════════════════════════════════
class RuleMatcher:
    def __init__(self, loader: RuleLoader):
        self._loader = loader

    @staticmethod
    def subdomain_match(pattern: str, host: str) -> bool:
        """'youtube.com' matches www.youtube.com, m.youtube.com, music.youtube.com"""
        p = pattern.lower().strip("*").strip(".")
        h = host.lower()
        return h == p or h.endswith("." + p)

    def matches(self, rule: dict, flow: http.HTTPFlow, phase: str) -> bool:
        # Support both flat schema {"match":"domain","pattern":"x"} 
        # and nested {"match":{"mode":"domain","pattern":"x"}}
        match_node = rule.get("match", "domain")
        if isinstance(match_node, dict):
            mode    = match_node.get("mode", "domain")
            pattern = match_node.get("pattern", "")
        else:
            mode    = match_node
            pattern = rule.get("pattern", "")

        req = flow.request
        rsp = flow.response

        # Special rules that self-match (no pattern needed)
        if rule.get("type") in ("BLOCK_TRACKERS",):
            return True

        # Pattern-required modes
        if not pattern and mode not in ("body",):
            return False

        if mode == "domain":
            return self.subdomain_match(pattern, req.pretty_host)

        elif mode == "url":
            return pattern.lower() in req.pretty_url.lower()

        elif mode == "keyword":
            haystack = req.pretty_url
            haystack += " " + " ".join(f"{k}: {v}" for k, v in req.headers.items())
            if rsp and phase == "response":
                haystack += " " + " ".join(f"{k}: {v}" for k, v in rsp.headers.items())
            return pattern.lower() in haystack.lower()

        elif mode == "regex":
            rx = self._loader._compile(pattern)
            return bool(rx.search(req.pretty_url)) or bool(rx.search(req.pretty_host))

        elif mode == "header":
            for k, v in req.headers.items():
                if pattern.lower() in k.lower() or pattern.lower() in v.lower():
                    return True
            return False

        elif mode == "response_header":
            if not rsp:
                return False
            for k, v in rsp.headers.items():
                if pattern.lower() in k.lower() or pattern.lower() in v.lower():
                    return True
            return False

        elif mode == "method":
            return req.method.upper() == pattern.upper()

        elif mode == "mime":
            ct = (rsp.headers.get("content-type", "") if rsp
                  else req.headers.get("content-type", ""))
            if "*" in pattern:
                prefix = pattern.split("*")[0].lower()
                return ct.lower().startswith(prefix)
            return pattern.lower() in ct.lower()

        elif mode == "status":
            if not rsp:
                return False
            return str(rsp.status_code) == pattern

        elif mode == "body":
            body = b""
            try:
                if phase == "request":
                    body = req.content or b""
                else:
                    body = (rsp.content if rsp else b"") or b""
                return pattern.lower() in body.decode("utf-8", errors="replace").lower()
            except Exception:
                return False

        elif mode == "process":
            proc = flow.metadata.get("process_hint", "").lower()
            return pattern.lower() in proc

        return False


# ══════════════════════════════════════════════════════════════
#  RuleConditionEvaluator — MIME_ONLY / PROCESS_ONLY / STATUS_CODE_MATCH
#  These are PRECONDITIONS, not standalone executable rules.
# ══════════════════════════════════════════════════════════════
class RuleConditionEvaluator:
    """
    Evaluates the optional 'conditions' block of a rule.
    If conditions are present and NOT met, the rule action is skipped.
    
    Schema:
      "conditions": {
        "mime":    "application/json",   # response Content-Type must contain this
        "status":  200,                  # response status must equal this
        "process": "brave.exe",          # process hint must contain this
        "method":  "POST"                # request method must match
      }
    """

    @staticmethod
    def evaluate(rule: dict, flow: http.HTTPFlow, phase: str) -> bool:
        """Returns True if all conditions pass (rule should execute)."""
        conds = rule.get("conditions", {})
        if not conds:
            return True

        rsp = flow.response

        # MIME condition
        mime_req = conds.get("mime", "")
        if mime_req:
            ct = (rsp.headers.get("content-type", "") if rsp
                  else flow.request.headers.get("content-type", ""))
            if "*" in mime_req:
                prefix = mime_req.split("*")[0].lower()
                if not ct.lower().startswith(prefix):
                    return False
            elif mime_req.lower() not in ct.lower():
                return False

        # Status condition — emit STATUS_CODE_MATCH tag so tests can detect it
        status_req = conds.get("status")
        if status_req is not None:
            expected = int(status_req) if str(status_req).isdigit() else 0
            if not rsp or rsp.status_code != expected:
                return False
            # Emit detectable log entry
            _log({
                "type": "RULE_EVENT",
                "tag": "STATUS_CODE_MATCH",
                "rule_id": rule.get("id", "?"),
                "status": rsp.status_code,
                "url": flow.request.pretty_url,
                "ts": time.time(),
            })

        # Process condition
        proc_req = conds.get("process", "")
        if proc_req:
            proc = flow.metadata.get("process_hint", "").lower()
            if proc_req.lower() not in proc:
                return False

        # Method condition
        method_req = conds.get("method", "")
        if method_req:
            if flow.request.method.upper() != method_req.upper():
                return False

        return True


# ══════════════════════════════════════════════════════════════
#  RuleExecutor — action execution
# ══════════════════════════════════════════════════════════════
class RuleExecutor:
    def __init__(self, loader: RuleLoader):
        self._loader = loader

    # ── Request-phase actions ────────────────────────────────
    def execute_request(self, rule: dict, flow: http.HTTPFlow) -> bool:
        """Returns True if flow was killed (stop processing)."""
        rtype = rule.get("type", "")
        cfg   = rule.get("config", {})  # new-schema config block

        if rtype in ("BLOCK", "BLOCK_KEYWORD"):
            _rule_log("[RULE BLOCK]", rule, flow)
            self._loader.inc_hit(rule)
            flow.kill()
            return True

        elif rtype == "BLOCK_TRACKERS":
            host = flow.request.pretty_host.lower()
            url  = flow.request.pretty_url.lower()
            if any(RuleMatcher.subdomain_match(d, host) for d in TRACKER_DOMAINS):
                _rule_log("[RULE BLOCK]", rule, flow, "BLOCK_TRACKERS domain")
                self._loader.inc_hit(rule)
                flow.kill()
                return True
            if any(kw in url for kw in TRACKER_KEYWORDS):
                _rule_log("[RULE BLOCK]", rule, flow, "BLOCK_TRACKERS keyword")
                self._loader.inc_hit(rule)
                flow.kill()
                return True

        elif rtype == "BLOCK_METHOD":
            target_method = cfg.get("method") or rule.get("value", "")
            if flow.request.method.upper() == target_method.upper():
                _rule_log("[RULE BLOCK]", rule, flow, f"Method={flow.request.method}")
                self._loader.inc_hit(rule)
                flow.kill()
                return True

        elif rtype == "INJECT_HEADER":
            k = cfg.get("key") or rule.get("key", "X-NetSense")
            v = cfg.get("value") or rule.get("value", "true")
            flow.request.headers[k] = v
            _rule_log("[RULE HEADER INJECT]", rule, flow, f"{k}: {v}")
            self._loader.inc_hit(rule)

        elif rtype == "REWRITE_URL":
            # find = explicit find-text config, or fall back to the match pattern
            find    = cfg.get("find") or rule.get("key", "") or rule.get("pattern", "")
            replace = cfg.get("replace") or cfg.get("new_url") or rule.get("value", "")
            old     = flow.request.pretty_url
            if find and replace and find in old:
                flow.request.url = old.replace(find, replace, 1)
                _rule_log("[RULE REWRITE]", rule, flow, f"{old} -> {flow.request.url}")
                self._loader.inc_hit(rule)

        elif rtype == "REDIRECT":
            target = cfg.get("url") or rule.get("value", "")
            # Default to 302 Found (most transparent proxies use 302)
            raw_code = cfg.get("code", "") or rule.get("redirect_code", "")
            try:
                code = int(raw_code) if raw_code else 302
            except (ValueError, TypeError):
                code = 302
            if target:
                # Auto-add protocol if user omitted it
                if not target.startswith(("http://", "https://")):
                    target = "http://" + target
                flow.response = http.Response.make(
                    code, b"",
                    {"Location": target, "Content-Type": "text/html",
                     "Content-Length": "0"}
                )
                _rule_log("[RULE REDIRECT]", rule, flow, f"-> {target} ({code})")
                self._loader.inc_hit(rule)
                return True  # stop processing; response already set

        elif rtype == "THROTTLE":
            ms = int(cfg.get("latency_ms") or rule.get("value", 500))
            time.sleep(ms / 1000.0)
            _rule_log("[RULE THROTTLE]", rule, flow, f"{ms}ms")
            self._loader.inc_hit(rule)

        elif rtype == "LOG_ONLY":
            # Write to proxy log AND signal the C++ UI log channel
            _rule_log("[RULE LOG_ONLY]", rule, flow)
            _log({
                "type": "RSP",  # use RSP type so proxy_reader.cpp picks it up
                "tag": "[RULE HIT]",
                "ts": time.time(),
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "method": flow.request.method,
                "status": 0,
                "rule_id": rule.get("id", "?"),
            })
            self._loader.inc_hit(rule)

        elif rtype == "ALERT_ON_MATCH":
            self._emit_alert(rule, flow, "REQUEST")

        elif rtype == "SAVE_MATCHES":
            self._save_match(rule, flow, phase="request")

        # Conditional-only types — silently skip in request phase
        elif rtype in ("MIME_ONLY", "STATUS_CODE_MATCH", "PROCESS_ONLY",
                       "RESPONSE_HEADER_INJECT", "DROP_RESPONSE",
                       "MODIFY_JSON", "LIMIT_BANDWIDTH", "BLOCK_MEDIA"):
            pass  # These are response-phase or condition-only rules

        return False

    # ── Response-phase actions ───────────────────────────────
    def execute_response(self, rule: dict, flow: http.HTTPFlow) -> bool:
        """Returns True if processing should stop."""
        rtype = rule.get("type", "")
        rsp   = flow.response
        cfg   = rule.get("config", {})
        if not rsp:
            return False

        if rtype == "BLOCK_MEDIA":
            # FIX: check the actual response Content-Type, NOT request Accept
            ct = rsp.headers.get("content-type", "")
            if any(ct.startswith(m) for m in MEDIA_MIME):
                _rule_log("[RULE BLOCK]", rule, flow, f"BLOCK_MEDIA ct={ct}")
                self._loader.inc_hit(rule)
                # Replace with empty 403
                rsp.content = b""
                rsp.status_code = 403
                return False  # don't kill; let response be sent back

        elif rtype == "RESPONSE_HEADER_INJECT":
            k = cfg.get("key") or rule.get("key", "X-NetSense-Rsp")
            v = cfg.get("value") or rule.get("value", "true")
            rsp.headers[k] = v
            _rule_log("[RULE HEADER INJECT]", rule, flow, f"RSP {k}: {v}")
            self._loader.inc_hit(rule)

        elif rtype == "DROP_RESPONSE":
            rsp.content = b""
            rsp.status_code = 204
            rsp.headers.pop("content-type", None)
            _rule_log("[RULE DROP_RESPONSE]", rule, flow)
            self._loader.inc_hit(rule)

        elif rtype == "THROTTLE":
            ms = int(cfg.get("latency_ms") or rule.get("value", 500))
            time.sleep(ms / 1000.0)
            _rule_log("[RULE THROTTLE]", rule, flow, f"{ms}ms RSP")
            self._loader.inc_hit(rule)

        elif rtype == "LIMIT_BANDWIDTH":
            try:
                cap_kbps = int(cfg.get("max_kbps") or rule.get("value", 100))
                data = rsp.content
                if not data:          # guard: content may be None or empty
                    return False
                chunk = 4096
                delay = chunk / (cap_kbps * 1024)
                out = bytearray()
                for i in range(0, len(data), chunk):
                    out += data[i:i + chunk]
                    time.sleep(delay)
                rsp.content = bytes(out)
                _rule_log("[RULE THROTTLE]", rule, flow, f"LIMIT_BW {cap_kbps}KB/s")
                self._loader.inc_hit(rule)
            except Exception as e:
                _rule_log("[RULE LIMIT_BANDWIDTH ERROR]", rule, flow, str(e))

        elif rtype == "MODIFY_JSON":
            ct = rsp.headers.get("content-type", "")
            if "json" not in ct.lower():
                return False
            k = cfg.get("json_path") or rule.get("key", "")
            v = cfg.get("replace_value")
            if v is None:
                v = rule.get("value", "")
            if not k:
                return False
            raw = rsp.content
            if not raw:               # guard: content may be None
                return False
            try:
                body = json.loads(raw.decode("utf-8"))
                parts = k.split(".")
                target = body
                for p in parts[:-1]:
                    if isinstance(target, dict) and p in target:
                        target = target[p]
                    elif isinstance(target, list):
                        try:
                            target = target[int(p)]
                        except Exception:
                            target = None
                            break
                    else:
                        target = None
                        break
                if target is not None and parts:
                    leaf = parts[-1]
                    # Type coercion: try JSON parse first
                    if isinstance(v, str):
                        try:
                            v = json.loads(v)
                        except Exception:
                            pass
                    if isinstance(target, dict):
                        target[leaf] = v
                    elif isinstance(target, list):
                        try:
                            target[int(leaf)] = v
                        except Exception:
                            pass
                rsp.content = json.dumps(body, separators=(",", ":")).encode("utf-8")
                _rule_log("[RULE MODIFY_JSON]", rule, flow, f"{k}={v}")
                self._loader.inc_hit(rule)
            except Exception as e:
                _rule_log("[RULE MODIFY_JSON ERROR]", rule, flow, str(e))

        elif rtype == "LOG_ONLY":
            _rule_log("[RULE LOG_ONLY]", rule, flow)
            _log({
                "type": "RSP",
                "tag": "[RULE HIT]",
                "ts": time.time(),
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "method": flow.request.method,
                "status": rsp.status_code,
                "rule_id": rule.get("id", "?"),
            })
            self._loader.inc_hit(rule)

        elif rtype == "ALERT_ON_MATCH":
            self._emit_alert(rule, flow, "RESPONSE")

        elif rtype == "SAVE_MATCHES":
            self._save_match(rule, flow, phase="response")

        # STATUS_CODE_MATCH — acts as a condition, not an action
        # Already evaluated in RuleConditionEvaluator before we reach here

        return False

    # ── Helpers ──────────────────────────────────────────────
    @staticmethod
    def _emit_alert(rule: dict, flow: http.HTTPFlow, phase: str):
        msg = (f"[ALERT] Rule '{rule.get('id','?')}' matched {phase}: "
               f"{flow.request.pretty_url}")
        # Emit as RULE_EVENT so the runtime panel + test suite can detect it
        _log({
            "type":      "RULE_EVENT",
            "tag":       "[RULE ALERT]",
            "rule_id":   rule.get("id", "?"),
            "rule_type": "ALERT_ON_MATCH",
            "url":       flow.request.pretty_url,
            "host":      flow.request.pretty_host,
            "method":    flow.request.method,
            "msg":       msg,
            "ts":        time.time(),
        })
        # Also write to dedicated alerts file
        try:
            with open(_ALERT_FILE, "a", encoding="utf-8") as af:
                af.write(json.dumps({"ts": time.time(), "msg": msg}) + "\n")
        except Exception:
            pass

    @staticmethod
    def _save_match(rule: dict, flow: http.HTTPFlow, phase: str):
        rsp = flow.response
        entry = {
            "ts":      time.time(),
            "phase":   phase,
            "url":     flow.request.pretty_url,
            "host":    flow.request.pretty_host,
            "method":  flow.request.method,
            "status":  rsp.status_code if rsp else 0,
            "rule_id": rule.get("id", "?"),
        }
        try:
            with open(_SAVES_FILE, "a", encoding="utf-8") as sf:
                sf.write(json.dumps(entry) + "\n")
        except Exception:
            pass
        _rule_log("[RULE SAVE_MATCHES]", rule, flow)


# ══════════════════════════════════════════════════════════════
#  Shared logging helper (module-level, used by all classes)
# ══════════════════════════════════════════════════════════════
def _log(entry: dict):
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _rule_log(tag: str, rule: dict, flow: http.HTTPFlow, extra: str = ""):
    _log({
        "type":       "RULE_EVENT",
        "tag":        tag,
        "rule_id":    rule.get("id", "?"),
        "rule_type":  rule.get("type", "?"),
        "url":        flow.request.pretty_url,
        "host":       flow.request.pretty_host,
        "method":     flow.request.method,
        "ts":         time.time(),
        "extra":      extra,
    })


# ══════════════════════════════════════════════════════════════
#  Module-level singletons (used by netsense_addon.py)
# ══════════════════════════════════════════════════════════════
_loader    = RuleLoader()
_matcher   = RuleMatcher(_loader)
_conditions = RuleConditionEvaluator()
_executor  = RuleExecutor(_loader)


def apply_request_rules(flow: http.HTTPFlow):
    _loader.reload()
    for rule in _loader.rules():
        if not rule.get("enabled", True):
            continue
        # Skip response-only rule types in request phase
        if rule.get("type") in ("MIME_ONLY", "STATUS_CODE_MATCH",
                                 "RESPONSE_HEADER_INJECT", "DROP_RESPONSE",
                                 "LIMIT_BANDWIDTH", "MODIFY_JSON", "BLOCK_MEDIA"):
            continue
        if not _matcher.matches(rule, flow, "request"):
            continue
        if not _conditions.evaluate(rule, flow, "request"):
            continue
        killed = _executor.execute_request(rule, flow)
        if killed or rule.get("stop", False):
            break


def apply_response_rules(flow: http.HTTPFlow):
    _loader.reload()
    for rule in _loader.rules():
        if not rule.get("enabled", True):
            continue
        # Skip request-only rule types in response phase
        if rule.get("type") in ("BLOCK", "BLOCK_KEYWORD", "BLOCK_TRACKERS",
                                  "BLOCK_METHOD", "INJECT_HEADER",
                                  "REWRITE_URL", "REDIRECT"):
            continue
        if not _matcher.matches(rule, flow, "response"):
            continue
        if not _conditions.evaluate(rule, flow, "response"):
            continue
        stopped = _executor.execute_response(rule, flow)
        if stopped or rule.get("stop", False):
            break
    _loader.force_flush_hits()


def invalidate_cache():
    """Called by predefined pack enable/disable to force immediate reload."""
    _loader.invalidate()
