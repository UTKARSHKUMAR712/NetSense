"""
NetSense+ Phase 6 — netsense_addon.py
======================================
Main mitmproxy addon entry point.
Delegates rule execution to rule_engine.py (hot-reloaded).
Exports predefined pack metadata on startup.

Usage:
    mitmdump --listen-port 8080 -s netsense_addon.py
"""

import json
import time
import os
import sys

# Add proxy/ directory to path so rule_engine and predefined_packs import cleanly
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

# pyrefly: ignore [missing-import]
from mitmproxy import http, ctx
import rule_engine
import predefined_packs

LOG_FILE = os.path.join(_DIR, "netsense_proxy.log")

# ─── Startup ────────────────────────────────────────────────
predefined_packs.export_packs_json()


# ─── Helpers ────────────────────────────────────────────────
def _write(entry: dict):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def get_headers(headers) -> dict:
    d = {}
    SENSITIVE = {"authorization", "x-api-key", "x-auth-token", "cookie", "set-cookie"}
    for k, v in headers.items():
        d[k] = "[MASKED]" if k.lower() in SENSITIVE else v
    return d


def get_cookies(cookies) -> dict:
    return {k: v[0] for k, v in cookies.items()} if cookies else {}


def get_body_preview(content: bytes, max_len: int = 5 * 1024 * 1024) -> str:
    if not content:
        return ""
    try:
        text = content.decode("utf-8", errors="replace")
        return text[:max_len] + ("\n... [TRUNCATED 5MB+]" if len(text) > max_len else "")
    except Exception:
        return "[binary data]"


def tag_insights(flow: http.HTTPFlow) -> list:
    tags = []
    host = flow.request.pretty_host.lower()
    ct = ""
    if flow.response:
        ct = flow.response.headers.get("content-type", "").lower()
    else:
        ct = flow.request.headers.get("content-type", "").lower()

    if any(x in host for x in ["youtube.com", "googlevideo.com", "netflix.com",
                                 "twitch.tv", "spotify.com"]):
        tags.append("[STREAM]")
    if any(x in host for x in ["steampowered.com", "epicgames.com", "riotgames.com",
                                 "valve.net", "ea.com"]):
        tags.append("[GAMING]")
    if any(x in host for x in ["whatsapp.com", "telegram.org", "signal.org"]):
        tags.append("[MSG]")
    if any(x in host for x in ["doubleclick", "analytics", "hotjar", "adnxs"]):
        tags.append("[TRACK]")
    if "application/json" in ct and flow.request.method == "POST":
        tags.append("[API]")
    if flow.response and flow.response.content and len(flow.response.content) > 5 * 1024 * 1024:
        tags.append("[DOWNLOAD]")
    if flow.request.content and len(flow.request.content) > 1024 * 1024:
        tags.append("[UPLOAD]")
    return tags


# ─── Addons ─────────────────────────────────────────────────
class InsightAddon:
    def request(self, flow: http.HTTPFlow):
        if "insight_tags" not in flow.metadata:
            flow.metadata["insight_tags"] = set()
        for tag in tag_insights(flow):
            flow.metadata["insight_tags"].add(tag)

    def response(self, flow: http.HTTPFlow):
        if "insight_tags" not in flow.metadata:
            flow.metadata["insight_tags"] = set()
        for tag in tag_insights(flow):
            flow.metadata["insight_tags"].add(tag)


class WebSocketAddon:
    def websocket_message(self, flow: http.HTTPFlow):
        msg = flow.websocket.messages[-1]
        tags = list(flow.metadata.get("insight_tags", set())) + ["[WS]"]
        _write({
            "type": "WS_MSG",
            "ts": time.time(),
            "method": "WS",
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "is_websocket": True,
            "ws_opcode": 2 if msg.is_binary else 1,
            "ws_message": get_body_preview(msg.content, 256),
            "insight_tags": tags,
        })


class LoggerAddon:
    def request(self, flow: http.HTTPFlow):
        tags = list(flow.metadata.get("insight_tags", set()))
        _write({
            "type": "REQ",
            "ts": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "http_version": flow.request.http_version,
            "req_size": len(flow.request.content) if flow.request.content else 0,
            "content_type": flow.request.headers.get("content-type", ""),
            "req_headers": get_headers(flow.request.headers),
            "query_params": str(flow.request.query),
            "cookies": get_cookies(flow.request.cookies),
            "is_websocket": False,
            "tls_valid": bool(flow.client_conn.tls_established),
            "tls_sni": flow.client_conn.sni or "",
            "form_data": json.dumps(list(flow.request.urlencoded_form.items()))
                         if flow.request.urlencoded_form else "",
            "insight_tags": tags,
        })

    def response(self, flow: http.HTTPFlow):
        tags = list(flow.metadata.get("insight_tags", set()))
        duration = 0.0
        if flow.request.timestamp_start and flow.response.timestamp_end:
            duration = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
        _write({
            "type": "RSP",
            "ts": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "status": flow.response.status_code,
            "http_version": flow.response.http_version,
            "duration_ms": duration,
            "req_size": len(flow.request.content) if flow.request.content else 0,
            "rsp_size": len(flow.response.content) if flow.response.content else 0,
            "content_type": flow.response.headers.get("content-type", ""),
            "req_headers": get_headers(flow.request.headers),
            "rsp_headers": get_headers(flow.response.headers),
            "query_params": str(flow.request.query),
            "cookies": get_cookies(flow.request.cookies),
            "body_preview": get_body_preview(flow.response.content),
            "insight_tags": tags,
            "is_websocket": False,
            "tls_valid": bool(flow.client_conn.tls_established),
            "tls_sni": flow.client_conn.sni or "",
            "redirect_chain": flow.response.headers.get("location", "")
                              if flow.response.status_code in (301, 302, 307, 308) else "",
        })


class RulesAddon:
    """Delegates all rule execution to rule_engine.py (hot-reloaded)."""

    def request(self, flow: http.HTTPFlow):
        rule_engine.apply_request_rules(flow)

    def response(self, flow: http.HTTPFlow):
        rule_engine.apply_response_rules(flow)


addons = [
    InsightAddon(),
    WebSocketAddon(),
    LoggerAddon(),
    RulesAddon(),
]
