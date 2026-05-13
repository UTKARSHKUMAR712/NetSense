import json
import time
from mitmproxy import http
from .loader import RuleLoader
from .matcher import RuleMatcher
from .shared import _ALERT_FILE, _SAVES_FILE, TRACKER_DOMAINS, TRACKER_KEYWORDS, MEDIA_MIME, _log, _rule_log

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


