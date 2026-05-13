import os
import json
import time

_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RULES_FILE = os.path.join(_DIR, "rules.json")
_LOG_FILE   = os.path.join(_DIR, "netsense_proxy.log")
_ALERT_FILE = os.path.join(_DIR, "netsense_alerts.log")
_SAVES_FILE = os.path.join(_DIR, "netsense_saved_matches.jsonl")

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

def _log(entry: dict):
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def _rule_log(tag: str, rule: dict, flow, extra: str = ""):
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
