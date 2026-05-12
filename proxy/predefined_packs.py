"""
NetSense+ predefined_packs.py
==============================
All built-in predefined rule packs.
Loaded by netsense_addon.py and exposed to the C++ UI via packs.json.

Each pack is a dict with:
  id         - unique pack ID
  name       - display name
  category   - Privacy / Gaming / Analysis / etc.
  description- one-liner
  rules      - list of rule dicts (same schema as rules.json)
"""

import json
import os

_DIR       = os.path.dirname(__file__)
_PACKS_OUT = os.path.join(_DIR, "predefined_packs.json")

PREDEFINED_PACKS = [
    {
        "id": "ad_block",
        "name": "Ad Block Pack",
        "category": "Privacy",
        "description": "Blocks major advertising networks and tracking domains.",
        "rules": [
            {"type": "BLOCK", "match": "domain", "pattern": "doubleclick.net",
             "description": "Block Google Ads DoubleClick"},
            {"type": "BLOCK", "match": "domain", "pattern": "googlesyndication.com",
             "description": "Block Google AdSense"},
            {"type": "BLOCK", "match": "domain", "pattern": "adservice.google.com",
             "description": "Block Google AdService"},
            {"type": "BLOCK", "match": "domain", "pattern": "adnxs.com",
             "description": "Block AppNexus ads"},
            {"type": "BLOCK", "match": "keyword", "pattern": "ads.js",
             "description": "Block ads.js scripts"},
            {"type": "BLOCK", "match": "keyword", "pattern": "/ads/",
             "description": "Block /ads/ URL segments"},
        ]
    },
    {
        "id": "telemetry_block",
        "name": "Telemetry Block Pack",
        "category": "Privacy",
        "description": "Blocks telemetry, analytics and metrics endpoints.",
        "rules": [
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "telemetry",
             "description": "Block telemetry endpoints"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "analytics",
             "description": "Block analytics endpoints"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "metrics",
             "description": "Block metrics collection"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "tracking",
             "description": "Block tracking beacons"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "beacon",
             "description": "Block ping/beacon requests"},
        ]
    },
    {
        "id": "privacy_mode",
        "name": "Privacy Mode Pack",
        "category": "Security",
        "description": "Comprehensive privacy: blocks trackers, fingerprinting & telemetry.",
        "rules": [
            {"type": "BLOCK_TRACKERS", "match": "domain", "pattern": "",
             "description": "Block all known tracker domains"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "fingerprint",
             "description": "Block fingerprinting scripts"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "telemetry",
             "description": "Block telemetry"},
            {"type": "BLOCK", "match": "domain", "pattern": "hotjar.com",
             "description": "Block Hotjar session recordings"},
            {"type": "BLOCK", "match": "domain", "pattern": "mouseflow.com",
             "description": "Block Mouseflow recordings"},
        ]
    },
    {
        "id": "streaming_detect",
        "name": "Streaming Detection Pack",
        "category": "Analysis",
        "description": "Tags and logs streaming platform traffic.",
        "rules": [
            {"type": "LOG_ONLY", "match": "domain", "pattern": "youtube.com",
             "description": "Log YouTube traffic"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "netflix.com",
             "description": "Log Netflix traffic"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "twitch.tv",
             "description": "Log Twitch traffic"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "spotify.com",
             "description": "Log Spotify traffic"},
            {"type": "ALERT_ON_MATCH", "match": "domain", "pattern": "googlevideo.com",
             "description": "Alert on YouTube video streams"},
        ]
    },
    {
        "id": "social_media",
        "name": "Social Media Detection Pack",
        "category": "Monitoring",
        "description": "Detects and logs social media platform traffic.",
        "rules": [
            {"type": "LOG_ONLY", "match": "domain", "pattern": "whatsapp.com",
             "description": "Log WhatsApp"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "instagram.com",
             "description": "Log Instagram"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "facebook.com",
             "description": "Log Facebook"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "discord.com",
             "description": "Log Discord"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "telegram.org",
             "description": "Log Telegram"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "x.com",
             "description": "Log X/Twitter"},
        ]
    },
    {
        "id": "api_debug",
        "name": "API Debug Pack",
        "category": "Development",
        "description": "Enables deep inspection of API traffic, JSON, and POST requests.",
        "rules": [
            {"type": "LOG_ONLY", "match": "mime", "pattern": "application/json",
             "description": "Log all JSON API responses"},
            {"type": "SAVE_MATCHES", "match": "method", "pattern": "POST",
             "description": "Save all POST requests"},
            {"type": "ALERT_ON_MATCH", "match": "status", "pattern": "4",
             "description": "Alert on 4xx client errors (partial match)"},
            {"type": "LOG_ONLY", "match": "mime", "pattern": "application/graphql",
             "description": "Log GraphQL queries"},
        ]
    },
    {
        "id": "gaming_detect",
        "name": "Gaming Detection Pack",
        "category": "Gaming",
        "description": "Detects and tags gaming platform traffic.",
        "rules": [
            {"type": "LOG_ONLY", "match": "domain", "pattern": "steampowered.com",
             "description": "Log Steam"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "epicgames.com",
             "description": "Log Epic Games"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "riotgames.com",
             "description": "Log Riot Games"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "valve.net",
             "description": "Log Valve CDN"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "ea.com",
             "description": "Log EA"},
            {"type": "LOG_ONLY", "match": "domain", "pattern": "ubisoft.com",
             "description": "Log Ubisoft"},
        ]
    },
    {
        "id": "media_block",
        "name": "Media Block Pack",
        "category": "Content Control",
        "description": "Blocks video/audio streams and large media MIME types.",
        "rules": [
            {"type": "BLOCK_MEDIA", "match": "mime", "pattern": "video/*",
             "description": "Block video/* MIME"},
            {"type": "BLOCK", "match": "domain", "pattern": "googlevideo.com",
             "description": "Block YouTube video CDN"},
            {"type": "BLOCK", "match": "domain", "pattern": "nflxvideo.net",
             "description": "Block Netflix video CDN"},
        ]
    },
    {
        "id": "safe_browsing",
        "name": "Safe Browsing Pack",
        "category": "Protection",
        "description": "Blocks known suspicious redirect and tracking patterns.",
        "rules": [
            {"type": "BLOCK", "match": "domain", "pattern": "malvertising.com",
             "description": "Block malvertising"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "click.php?url=",
             "description": "Block open redirect patterns"},
            {"type": "BLOCK_KEYWORD", "match": "keyword", "pattern": "redirect?to=",
             "description": "Block redirect exploits"},
            {"type": "BLOCK_TRACKERS", "match": "domain", "pattern": "",
             "description": "Block all trackers"},
        ]
    },
]


def export_packs_json():
    """Write predefined_packs.json for C++ UI to read."""
    try:
        with open(_PACKS_OUT, "w", encoding="utf-8") as f:
            json.dump(PREDEFINED_PACKS, f, indent=4)
    except Exception:
        pass


def get_pack_rules(pack_id: str) -> list:
    """Get all rules for a pack, enriched with source pack metadata."""
    for pack in PREDEFINED_PACKS:
        if pack["id"] == pack_id:
            out = []
            for i, r in enumerate(pack["rules"]):
                rule = dict(r)
                rule["id"]       = f"{pack_id}_{i}"
                rule["enabled"]  = True
                rule["category"] = pack["category"]
                rule["priority"] = 50  # predefined rules have mid-priority
                rule["hit_count"] = 0
                out.append(rule)
            return out
    return []


def get_all_active_rules(enabled_pack_ids: list) -> list:
    """Merge rules from all enabled packs, return sorted list."""
    merged = []
    for pid in enabled_pack_ids:
        merged.extend(get_pack_rules(pid))
    return sorted(merged, key=lambda r: r.get("priority", 50))
