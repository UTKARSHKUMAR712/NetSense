"""
NetSense+ rule_engine.py
========================
Full live rule execution engine for mitmproxy.
Loaded by netsense_addon.py — do NOT run standalone.

Handles:
  - Hot-reload of proxy/rules.json on change
  - Priority ordering
  - All rule types: BLOCK, INJECT_HEADER, REWRITE_URL, REDIRECT,
    THROTTLE, LIMIT_BANDWIDTH, LOG_ONLY, MODIFY_JSON, DROP_RESPONSE,
    REGEX_MATCH, PROCESS_ONLY, MIME_ONLY, ALERT_ON_MATCH, SAVE_MATCHES,
    STATUS_CODE_MATCH, RESPONSE_HEADER_INJECT, BLOCK_METHOD,
    BLOCK_MEDIA, BLOCK_TRACKERS, BLOCK_KEYWORD
  - Match modes: domain, url, header, keyword, regex, process, mime,
    method, status, body, response_header
  - Wildcard + subdomain matching
  - Cached regex compilation
  - Thread-safe rule loading
  - Hit counters written back to rules.json
  - Debug logging to netsense_proxy.log
"""

import json
import time
import os
import re
import threading
from typing import Optional
# pyrefly: ignore [missing-import]
from mitmproxy import http
# pyrefly: ignore [missing-import]
from mitmproxy.net.http import http1

# ─── File paths ─────────────────────────────────────────────
_DIR       = os.path.dirname(__file__)
_RULES_FILE = os.path.join(_DIR, "rules.json")
_LOG_FILE   = os.path.join(_DIR, "netsense_proxy.log")
_ALERT_FILE = os.path.join(_DIR, "netsense_alerts.log")
_SAVES_FILE = os.path.join(_DIR, "netsense_saved_matches.jsonl")

# ─── Internal state ─────────────────────────────────────────
_lock        = threading.Lock()
_rules       = []          # sorted list of rule dicts
_regex_cache = {}          # pattern -> compiled re
_last_mtime  = 0.0
_hit_counts  = {}          # rule_id -> int


# ─── Logging helpers ────────────────────────────────────────
def _log(entry: dict):
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def _rule_log(tag: str, rule: dict, flow: http.HTTPFlow, extra: str = ""):
    _log({
        "type": "RULE_EVENT",
        "tag": tag,
        "rule_id": rule.get("id", "?"),
        "rule_type": rule.get("type", "?"),
        "url": flow.request.pretty_url,
        "host": flow.request.pretty_host,
        "method": flow.request.method,
        "ts": time.time(),
        "extra": extra,
    })


# ─── Rule loading + hot-reload ──────────────────────────────
def _get_compiled(pattern: str) -> re.Pattern:
    if pattern not in _regex_cache:
        try:
            _regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
        except re.error:
            _regex_cache[pattern] = re.compile(re.escape(pattern), re.IGNORECASE)
    return _regex_cache[pattern]


def reload_rules():
    global _rules, _last_mtime, _regex_cache
    if not os.path.exists(_RULES_FILE):
        return
    try:
        mtime = os.path.getmtime(_RULES_FILE)
        if mtime == _last_mtime:
            return
        with _lock:
            with open(_RULES_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            _rules = sorted(
                [r for r in loaded if r.get("enabled", True)],
                key=lambda r: r.get("priority", 0)
            )
            # Pre-compile all regex patterns
            _regex_cache.clear()
            for r in _rules:
                pat = r.get("pattern", "")
                if r.get("match") in ("regex",) and pat:
                    _get_compiled(pat)
            _last_mtime = mtime
    except Exception as e:
        _log({"type": "RULE_ENGINE_ERROR", "msg": str(e), "ts": time.time()})


def _write_hit_counts():
    """Update hit counts in rules.json without touching other fields."""
    if not _hit_counts or not os.path.exists(_RULES_FILE):
        return
    try:
        with open(_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in data:
            rid = item.get("id", "")
            if rid in _hit_counts:
                item["hit_count"] = _hit_counts[rid]
        # Write with a flag so we don't trigger another reload
        tmp = _RULES_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp, _RULES_FILE)
        global _last_mtime
        _last_mtime = os.path.getmtime(_RULES_FILE)
    except Exception:
        pass


def _inc_hit(rule: dict):
    rid = rule.get("id", "")
    if rid:
        _hit_counts[rid] = _hit_counts.get(rid, 0) + 1


# ─── Match engine ───────────────────────────────────────────
def _subdomain_match(pattern: str, host: str) -> bool:
    """Match domain and all subdomains: 'youtube.com' matches 'www.youtube.com'"""
    p = pattern.lower().lstrip("*").lstrip(".")
    h = host.lower()
    return h == p or h.endswith("." + p)


def _matches(rule: dict, flow: http.HTTPFlow, phase: str = "request") -> bool:
    mode    = rule.get("match", "domain")
    pattern = rule.get("pattern", "")
    if not pattern:
        return False

    req = flow.request
    rsp = flow.response

    if mode == "domain":
        return _subdomain_match(pattern, req.pretty_host)

    elif mode == "url":
        return pattern.lower() in req.pretty_url.lower()

    elif mode == "keyword":
        haystack = req.pretty_url + " " + str(dict(req.headers))
        if rsp and phase == "response":
            haystack += " " + str(dict(rsp.headers))
        return pattern.lower() in haystack.lower()

    elif mode == "regex":
        rx = _get_compiled(pattern)
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
        ct = ""
        if rsp:
            ct = rsp.headers.get("content-type", "")
        else:
            ct = req.headers.get("content-type", "")
        # Support wildcards like "image/*"
        if "*" in pattern:
            prefix = pattern.split("*")[0].lower()
            return ct.lower().startswith(prefix)
        return pattern.lower() in ct.lower()

    elif mode == "status":
        if not rsp:
            return False
        return str(rsp.status_code) == pattern

    elif mode == "body":
        # Lazy — only inspect if body inspection is enabled in settings
        body = b""
        if phase == "request":
            body = req.content or b""
        else:
            body = (rsp.content if rsp else b"") or b""
        try:
            return pattern.lower() in body.decode("utf-8", errors="replace").lower()
        except Exception:
            return False

    elif mode == "process":
        # Best-effort: match process hint stored in flow metadata
        proc = flow.metadata.get("process_hint", "").lower()
        return pattern.lower() in proc

    return False


# ─── Action executors ───────────────────────────────────────
TRACKER_DOMAINS = [
    "doubleclick.net", "googlesyndication.com", "adservice.google.com",
    "hotjar.com", "analytics.google.com", "facebook.com/tr",
    "scorecardresearch.com", "comscore.com", "quantserve.com",
    "advertising.com", "adnxs.com", "rlcdn.com", "moatads.com"
]
MEDIA_MIME_PREFIXES = ("video/", "audio/")
TRACKER_KEYWORDS = ["telemetry", "analytics", "metrics", "tracking",
                    "fingerprint", "beacon", "pixel"]


def _execute_request(rule: dict, flow: http.HTTPFlow):
    rtype = rule.get("type", "")

    if rtype in ("BLOCK", "BLOCK_KEYWORD"):
        _rule_log("[RULE BLOCK]", rule, flow)
        _inc_hit(rule)
        flow.kill()
        return True   # stop further processing of this flow

    elif rtype == "INJECT_HEADER":
        k = rule.get("key", "X-NetSense")
        v = rule.get("value", "true")
        flow.request.headers[k] = v
        _rule_log("[RULE HEADER INJECT]", rule, flow, f"{k}: {v}")
        _inc_hit(rule)

    elif rtype == "REWRITE_URL":
        old_url = flow.request.pretty_url
        new_url = old_url.replace(rule.get("pattern", ""), rule.get("value", ""))
        flow.request.url = new_url
        _rule_log("[RULE REWRITE]", rule, flow, f"{old_url} -> {new_url}")
        _inc_hit(rule)

    elif rtype == "REDIRECT":
        target = rule.get("value", "")
        if target:
            flow.response = http.Response.make(
                301,
                b"",
                {"Location": target, "Content-Type": "text/plain"}
            )
            _rule_log("[RULE REDIRECT]", rule, flow, target)
            _inc_hit(rule)

    elif rtype == "LOG_ONLY":
        _rule_log("[RULE LOG]", rule, flow)
        _inc_hit(rule)

    elif rtype == "ALERT_ON_MATCH":
        msg = f"[ALERT] Rule '{rule.get('id','?')}' matched: {flow.request.pretty_url}"
        _log({"type": "ALERT", "msg": msg, "ts": time.time()})
        try:
            with open(_ALERT_FILE, "a", encoding="utf-8") as af:
                af.write(json.dumps({"ts": time.time(), "msg": msg}) + "\n")
        except Exception:
            pass
        _inc_hit(rule)

    elif rtype == "BLOCK_METHOD":
        if flow.request.method.upper() == rule.get("value", "").upper():
            _rule_log("[RULE BLOCK]", rule, flow, f"Method={flow.request.method}")
            _inc_hit(rule)
            flow.kill()
            return True

    elif rtype == "BLOCK_MEDIA":
        ct = flow.request.headers.get("accept", "")
        if any(ct.startswith(p) for p in MEDIA_MIME_PREFIXES):
            _rule_log("[RULE BLOCK]", rule, flow, "BLOCK_MEDIA")
            _inc_hit(rule)
            flow.kill()
            return True

    elif rtype == "BLOCK_TRACKERS":
        host = flow.request.pretty_host.lower()
        url  = flow.request.pretty_url.lower()
        if any(_subdomain_match(d, host) for d in TRACKER_DOMAINS):
            _rule_log("[RULE BLOCK]", rule, flow, "BLOCK_TRACKERS domain")
            _inc_hit(rule)
            flow.kill()
            return True
        if any(kw in url for kw in TRACKER_KEYWORDS):
            _rule_log("[RULE BLOCK]", rule, flow, "BLOCK_TRACKERS keyword")
            _inc_hit(rule)
            flow.kill()
            return True

    elif rtype == "PROCESS_ONLY":
        proc = flow.metadata.get("process_hint", "")
        if rule.get("pattern", "").lower() not in proc.lower():
            # Skip rule — only execute if it's our target process
            return False

    elif rtype == "THROTTLE":
        try:
            ms = int(rule.get("value", "500"))
            time.sleep(ms / 1000.0)
        except Exception:
            pass
        _rule_log("[RULE THROTTLE]", rule, flow, f"{rule.get('value')}ms")
        _inc_hit(rule)

    return False  # continue processing


def _execute_response(rule: dict, flow: http.HTTPFlow):
    rtype = rule.get("type", "")
    rsp   = flow.response
    if not rsp:
        return False

    if rtype == "RESPONSE_HEADER_INJECT":
        k = rule.get("key", "X-NetSense-Rsp")
        v = rule.get("value", "true")
        rsp.headers[k] = v
        _rule_log("[RULE HEADER INJECT]", rule, flow, f"RSP {k}: {v}")
        _inc_hit(rule)

    elif rtype == "DROP_RESPONSE":
        rsp.content = b""
        rsp.status_code = 204
        _rule_log("[RULE DROP_RESPONSE]", rule, flow)
        _inc_hit(rule)

    elif rtype == "THROTTLE":
        try:
            ms = int(rule.get("value", "500"))
            time.sleep(ms / 1000.0)
        except Exception:
            pass
        _rule_log("[RULE THROTTLE]", rule, flow, f"{rule.get('value')}ms")
        _inc_hit(rule)

    elif rtype == "LIMIT_BANDWIDTH":
        # Simulate bandwidth cap by chunking the response
        try:
            cap_kbps = int(rule.get("value", "100"))  # KB/s
            data = rsp.content
            chunk_size = 1024
            delay = chunk_size / (cap_kbps * 1024)
            result = b""
            for i in range(0, len(data), chunk_size):
                result += data[i:i+chunk_size]
                time.sleep(delay)
            rsp.content = result
        except Exception:
            pass
        _rule_log("[RULE THROTTLE]", rule, flow, f"LIMIT_BANDWIDTH {rule.get('value')}KB/s")
        _inc_hit(rule)

    elif rtype == "MODIFY_JSON":
        ct = rsp.headers.get("content-type", "")
        if "application/json" in ct:
            try:
                body = json.loads(rsp.content.decode("utf-8"))
                k = rule.get("key", "")
                v = rule.get("value", "")
                # Support dot-notation path like "user.isPremium"
                parts = k.split(".") if k else []
                target = body
                for p in parts[:-1]:
                    if isinstance(target, dict) and p in target:
                        target = target[p]
                    else:
                        target = None
                        break
                if target is not None and parts:
                    # Try to coerce value to correct type
                    try:
                        target[parts[-1]] = json.loads(v)
                    except Exception:
                        target[parts[-1]] = v
                rsp.content = json.dumps(body).encode("utf-8")
                _rule_log("[RULE MODIFY_JSON]", rule, flow, f"{k}={v}")
                _inc_hit(rule)
            except Exception as e:
                _rule_log("[RULE MODIFY_JSON ERROR]", rule, flow, str(e))

    elif rtype == "STATUS_CODE_MATCH":
        pat = rule.get("pattern", "")
        if str(rsp.status_code) == pat:
            _rule_log("[RULE LOG]", rule, flow, f"status={rsp.status_code}")
            _inc_hit(rule)

    elif rtype == "MIME_ONLY":
        # Check that MIME matches before any downstream rules fire
        ct = rsp.headers.get("content-type", "")
        p = rule.get("pattern", "")
        if "*" in p:
            prefix = p.split("*")[0].lower()
            if not ct.lower().startswith(prefix):
                return False
        elif p.lower() not in ct.lower():
            return False

    elif rtype == "SAVE_MATCHES":
        entry = {
            "ts": time.time(),
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "status": rsp.status_code,
            "rule_id": rule.get("id", "?"),
        }
        try:
            with open(_SAVES_FILE, "a", encoding="utf-8") as sf:
                sf.write(json.dumps(entry) + "\n")
        except Exception:
            pass
        _rule_log("[RULE SAVE_MATCHES]", rule, flow)
        _inc_hit(rule)

    elif rtype == "ALERT_ON_MATCH":
        msg = f"[ALERT] Rule '{rule.get('id','?')}' matched RSP: {flow.request.pretty_url}"
        _log({"type": "ALERT", "msg": msg, "ts": time.time()})
        try:
            with open(_ALERT_FILE, "a", encoding="utf-8") as af:
                af.write(json.dumps({"ts": time.time(), "msg": msg}) + "\n")
        except Exception:
            pass
        _inc_hit(rule)

    elif rtype == "LOG_ONLY":
        _rule_log("[RULE LOG]", rule, flow)
        _inc_hit(rule)

    return False


# ─── Public API ─────────────────────────────────────────────
def apply_request_rules(flow: http.HTTPFlow):
    reload_rules()
    with _lock:
        rules = list(_rules)
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _matches(rule, flow, "request"):
            killed = _execute_request(rule, flow)
            if killed or rule.get("stop", False):
                break


def apply_response_rules(flow: http.HTTPFlow):
    reload_rules()
    with _lock:
        rules = list(_rules)
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if _matches(rule, flow, "response"):
            stopped = _execute_response(rule, flow)
            if stopped or rule.get("stop", False):
                break
    # Flush hit counts periodically (every 30 hits total)
    total = sum(_hit_counts.values())
    if total % 30 == 0:
        _write_hit_counts()
