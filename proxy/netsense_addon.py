"""
NetSense+ Phase 5 — mitmproxy addon
Writes captured HTTP/HTTPS requests to netsense_proxy.log (one JSON line per event).

Usage:
    pip install mitmproxy
    mitmproxy --listen-port 8080 -s netsense_addon.py
  OR:
    mitmdump --listen-port 8080 -s netsense_addon.py

Configure browser/app to use HTTP proxy 127.0.0.1:8080
For HTTPS: install mitmproxy cert  ->  mitmproxy  -> Options -> Install Certificates
"""

import json
import time
import os
import re
from typing import List, Dict, Any
from mitmproxy import http, ctx

LOG_FILE = os.path.join(os.path.dirname(__file__), "netsense_proxy.log")

def _write(entry: dict):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except: pass

def get_headers(headers) -> dict:
    d = {}
    for k, v in headers.items():
        if k.lower() == "authorization":
            d[k] = "[MASKED]"
        else:
            d[k] = v
    return d

def get_cookies(cookies) -> dict:
    return {k: v[0] for k, v in cookies.items()} if cookies else {}

def get_body_preview(content: bytes, max_len=5*1024*1024) -> str:
    if not content: return ""
    try:
        text = content.decode('utf-8', errors='replace')
        return text[:max_len] + ("\n... [TRUNCATED 5MB+]" if len(text) > max_len else "")
    except:
        return "[binary data]"

def tag_insights(flow: http.HTTPFlow) -> List[str]:
    tags = []
    host = flow.request.pretty_host.lower()
    ct = flow.response.headers.get("content-type", "").lower() if flow.response else flow.request.headers.get("content-type", "").lower()
    
    if any(x in host for x in ["youtube.com", "googlevideo.com", "netflix.com", "twitch.tv", "spotify.com"]):
        tags.append("[STREAM]")
    if any(x in host for x in ["steam", "xbox", "epicgames"]):
        tags.append("[GAMING]")
    if any(x in host for x in ["whatsapp", "telegram", "signal"]):
        tags.append("[MSG]")
    if any(x in host for x in ["doubleclick", "analytics", "hotjar", "facebook.com/tr"]):
        tags.append("[TRACK]")
    if "application/json" in ct and flow.request.method == "POST":
        tags.append("[API]")
    
    if flow.response and flow.response.content and len(flow.response.content) > 5*1024*1024:
        tags.append("[DOWNLOAD]")
    if flow.request.content and len(flow.request.content) > 1024*1024:
        tags.append("[UPLOAD]")
        
    return tags

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
        tags = list(flow.metadata.get("insight_tags", set()))
        tags.append("[WS]")
        
        entry = {
            "type": "WS_MSG",
            "ts": time.time(),
            "method": "WS",
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "is_websocket": True,
            "ws_opcode": 2 if msg.is_binary else 1,
            "ws_message": get_body_preview(msg.content, 256),
            "insight_tags": tags
        }
        _write(entry)

class LoggerAddon:
    def request(self, flow: http.HTTPFlow):
        tags = list(flow.metadata.get("insight_tags", set()))
        entry = {
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
            "tls_sni": flow.client_conn.sni if flow.client_conn.sni else "",
            "form_data": json.dumps(list(flow.request.urlencoded_form.items())) if flow.request.urlencoded_form else "",
            "insight_tags": tags
        }
        _write(entry)

    def response(self, flow: http.HTTPFlow):
        tags = list(flow.metadata.get("insight_tags", set()))
        duration = 0
        if flow.request.timestamp_start and flow.response.timestamp_end:
            duration = (flow.response.timestamp_end - flow.request.timestamp_start) * 1000

        entry = {
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
            "tls_sni": flow.client_conn.sni if flow.client_conn.sni else "",
            "redirect_chain": flow.response.headers.get("location", "") if flow.response.status_code in [301, 302, 307, 308] else ""
        }
        _write(entry)

class RulesAddon:
    def __init__(self):
        self.rules_file = os.path.join(os.path.dirname(__file__), "rules.json")
        self.rules = []
        self.last_mtime = 0
        self._load_rules()

    def _load_rules(self):
        try:
            if not os.path.exists(self.rules_file):
                return
            mtime = os.path.getmtime(self.rules_file)
            if mtime != self.last_mtime:
                with open(self.rules_file, "r") as f:
                    self.rules = json.load(f)
                self.last_mtime = mtime
        except:
            pass

    def request(self, flow: http.HTTPFlow):
        self._load_rules()
        for r in self.rules:
            if not r.get("enabled", False): continue
            rtype = r.get("type", "")
            rmatch = r.get("match", "")
            rpat = r.get("pattern", "")
            
            matches = False
            if rmatch == "domain" and rpat in flow.request.pretty_host: matches = True
            elif rmatch == "url" and rpat in flow.request.pretty_url: matches = True
            elif rmatch == "header":
                for k,v in flow.request.headers.items():
                    if rpat in k or rpat in v: matches = True
                    
            if matches:
                if rtype == "BLOCK" or rtype == "BLOCK_KEYWORD":
                    flow.kill()
                elif rtype == "INJECT_HEADER":
                    flow.request.headers[r.get("key", "X-Injected")] = r.get("value", "")
                elif rtype == "REWRITE_URL":
                    flow.request.url = flow.request.url.replace(rpat, r.get("value", ""))

    def response(self, flow: http.HTTPFlow):
        self._load_rules()
        for r in self.rules:
            if not r.get("enabled", False): continue
            rtype = r.get("type", "")
            rmatch = r.get("match", "")
            rpat = r.get("pattern", "")
            
            matches = False
            if rmatch == "domain" and rpat in flow.request.pretty_host: matches = True
            elif rmatch == "url" and rpat in flow.request.pretty_url: matches = True
                    
            if matches:
                if rtype == "THROTTLE":
                    try:
                        ms = int(r.get("value", "1000"))
                        time.sleep(ms / 1000.0)
                    except: pass


addons = [
    InsightAddon(),
    WebSocketAddon(),
    LoggerAddon(),
    RulesAddon()
]
