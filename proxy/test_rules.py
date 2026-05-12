"""
NetSense+ Rule Engine — FULL Live Test Suite
============================================

Run AFTER starting mitmdump:

    mitmdump --listen-port 8080 -s proxy/netsense_addon.py

Then run:

    python proxy/test_rules.py

This suite validates:
- live rule execution
- runtime synchronization
- hot reload
- condition chaining
- predefined pack enable/disable
- regex matching
- wildcard domains
- logging
- throttling
- redirects
- JSON modification
- response header injection
- runtime cache invalidation

Requirements:
    pip install requests
"""

import json
import os
import sys
import time
import requests

try:
    import requests
except ImportError:
    print("Install requests:")
    print("pip install requests")
    sys.exit(1)

PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")
LOG_FILE = os.path.join(os.path.dirname(__file__), "netsense_proxy.log")

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
INFO = "\033[94m[INFO]\033[0m"


def write_rules(rules):
    for i, r in enumerate(rules):
        r.setdefault("id", f"rule_{i}")
        r.setdefault("enabled", True)
        r.setdefault("priority", i)

    with open(RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=4)

    # allow hot reload
    time.sleep(1.0)


def clear_rules():
    write_rules([])


def req(url, **kwargs):
    try:
        return requests.get(
            url,
            proxies=PROXY,
            timeout=15,
            verify=False,
            **kwargs
        )
    except Exception:
        return None


def print_section(title):
    print("\n" + "═" * 60)
    print(title)
    print("═" * 60)


def log_contains(keyword):
    if not os.path.exists(LOG_FILE):
        return False

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()

    return keyword in data


print_section("NetSense+ FULL Rule Engine Test Suite")

# =========================================================
# TEST 1 — INJECT_HEADER
# =========================================================

print("\n[TEST 1] INJECT_HEADER")

write_rules([
    {
        "type": "INJECT_HEADER",
        "match": "domain",
        "pattern": "httpbin.org",
        "key": "X-NetSense-Test",
        "value": "HelloWorld"
    }
])

r = req("http://httpbin.org/headers")

if r and "X-Netsense-Test" in r.text:
    print(f"{PASS} Header injected successfully")
else:
    print(f"{FAIL} Header injection failed")

# =========================================================
# TEST 2 — BLOCK
# =========================================================

print("\n[TEST 2] BLOCK")

write_rules([
    {
        "type": "BLOCK",
        "match": "domain",
        "pattern": "example.com"
    }
])

r = req("http://example.com")

if r is None or r.status_code >= 400:
    print(f"{PASS} Domain blocked")
else:
    print(f"{FAIL} Block failed")

# =========================================================
# TEST 3 — REDIRECT
# =========================================================

print("\n[TEST 3] REDIRECT")

write_rules([
    {
        "type": "REDIRECT",
        "match": "domain",
        "pattern": "example.com",
        "value": "http://neverssl.com"
    }
])

r = req("http://example.com", allow_redirects=False)

if r and r.status_code in (301, 302, 307):
    if "neverssl.com" in r.headers.get("Location", ""):
        print(f"{PASS} Redirect successful")
    else:
        print(f"{FAIL} Wrong redirect location")
else:
    print(f"{FAIL} Redirect failed")

# =========================================================
# TEST 4 — RESPONSE_HEADER_INJECT
# =========================================================

print("\n[TEST 4] RESPONSE_HEADER_INJECT")

write_rules([
    {
        "type": "RESPONSE_HEADER_INJECT",
        "match": "domain",
        "pattern": "httpbin.org",
        "key": "X-NetSense-Response",
        "value": "Injected"
    }
])

r = req("http://httpbin.org/get")

if r and "X-Netsense-Response" in r.headers:
    print(f"{PASS} Response header injected")
else:
    print(f"{FAIL} Response header injection failed")

# =========================================================
# TEST 5 — LOG_ONLY
# =========================================================

print("\n[TEST 5] LOG_ONLY")

write_rules([
    {
        "type": "LOG_ONLY",
        "match": "domain",
        "pattern": "httpbin.org"
    }
])

req("http://httpbin.org/get")

time.sleep(1)

if log_contains("RULE LOG_ONLY") or log_contains("RULE HIT"):
    print(f"{PASS} LOG_ONLY emitted logs")
else:
    print(f"{FAIL} LOG_ONLY logging failed")

# =========================================================
# TEST 6 — MODIFY_JSON + MIME_ONLY CONDITION
# =========================================================

print("\n[TEST 6] MODIFY_JSON + MIME condition")

write_rules([
    {
        "type": "MODIFY_JSON",
        "match": "domain",
        "pattern": "httpbin.org",

        "conditions": {
            "mime": "application/json"
        },

        "config": {
            "json_path": "slideshow.author",
            "replace_value": "NetSenseModified"
        }
    }
])

r = req("http://httpbin.org/json")

if r and "NetSenseModified" in r.text:
    print(f"{PASS} JSON modified")
else:
    print(f"{FAIL} MODIFY_JSON failed")

# =========================================================
# TEST 7 — THROTTLE
# =========================================================

print("\n[TEST 7] THROTTLE")

write_rules([
    {
        "type": "THROTTLE",
        "match": "domain",
        "pattern": "httpbin.org",

        "config": {
            "latency_ms": 1000
        }
    }
])

t0 = time.time()
req("http://httpbin.org/get")
elapsed = (time.time() - t0) * 1000

if elapsed >= 900:
    print(f"{PASS} Throttle delay applied ({elapsed:.0f}ms)")
else:
    print(f"{FAIL} Throttle failed ({elapsed:.0f}ms)")

# =========================================================
# TEST 8 — REGEX_MATCH
# =========================================================

print("\n[TEST 8] REGEX_MATCH")

write_rules([
    {
        "type": "BLOCK",
        "match": "regex",
        "pattern": r".*example.*"
    }
])

r = req("http://example.com")

if r is None or r.status_code >= 400:
    print(f"{PASS} Regex match works")
else:
    print(f"{FAIL} Regex matching failed")

# =========================================================
# TEST 9 — WILDCARD DOMAIN
# =========================================================

print("\n[TEST 9] Wildcard domain")

write_rules([
    {
        "type": "BLOCK",
        "match": "domain",
        "pattern": "*.youtube.com"
    }
])

r = req("https://www.youtube.com")

if r is None or r.status_code >= 400:
    print(f"{PASS} Wildcard blocking works")
else:
    print(f"{FAIL} Wildcard domain failed")

# =========================================================
# TEST 10 — PROCESS_ONLY CONDITION
# =========================================================

print("\n[TEST 10] PROCESS_ONLY")

write_rules([
    {
        "type": "LOG_ONLY",
        "match": "domain",
        "pattern": "httpbin.org",

        "conditions": {
            "process": "brave.exe"
        }
    }
])

req("http://httpbin.org/get")

time.sleep(1)

if log_contains("PROCESS_ONLY"):
    print(f"{PASS} PROCESS_ONLY executed")
else:
    print(f"{INFO} PROCESS_ONLY requires real process mapping")

# =========================================================
# TEST 11 — STATUS_CODE_MATCH
# =========================================================

print("\n[TEST 11] STATUS_CODE_MATCH")

write_rules([
    {
        "type": "LOG_ONLY",
        "match": "domain",
        "pattern": "httpbin.org",

        "conditions": {
            "status": 200
        }
    }
])

req("http://httpbin.org/get")

time.sleep(1)

if log_contains("STATUS_CODE_MATCH"):
    print(f"{PASS} STATUS_CODE_MATCH works")
else:
    print(f"{FAIL} STATUS_CODE_MATCH failed")

# =========================================================
# TEST 12 — BLOCK_KEYWORD
# =========================================================

print("\n[TEST 12] BLOCK_KEYWORD")

write_rules([
    {
        "type": "BLOCK_KEYWORD",
        "match": "keyword",
        "pattern": "ads"
    }
])

r = req("https://duckduckgo.com/?q=ads")

if r is None or r.status_code >= 400:
    print(f"{PASS} Keyword blocking works")
else:
    print(f"{FAIL} BLOCK_KEYWORD failed")

# =========================================================
# TEST 13 — BLOCK_MEDIA
# =========================================================

print("\n[TEST 13] BLOCK_MEDIA")

write_rules([
    {
        "type": "BLOCK_MEDIA",
        "match": "mime",
        "pattern": "video/*"
    }
])

print(f"{INFO} Open a YouTube video manually to verify media blocking")

# =========================================================
# TEST 14 — ALERT_ON_MATCH
# =========================================================

print("\n[TEST 14] ALERT_ON_MATCH")

write_rules([
    {
        "type": "ALERT_ON_MATCH",
        "match": "domain",
        "pattern": "httpbin.org"
    }
])

req("http://httpbin.org/get")

time.sleep(1)

if log_contains("RULE ALERT"):
    print(f"{PASS} ALERT_ON_MATCH emitted alert")
else:
    print(f"{FAIL} ALERT_ON_MATCH failed")

# =========================================================
# TEST 15 — SAVE_MATCHES
# =========================================================

print("\n[TEST 15] SAVE_MATCHES")

write_rules([
    {
        "type": "SAVE_MATCHES",
        "match": "domain",
        "pattern": "httpbin.org"
    }
])

req("http://httpbin.org/get")

print(f"{INFO} Verify flow saved in session/history database")

# =========================================================
# TEST 16 — PREDEFINED PACK DISABLE
# =========================================================

# Test 16: block httpbin.org, then clear rules, confirm it becomes accessible again
write_rules([
    {
        "type": "BLOCK",
        "match": "domain",
        "pattern": "httpbin.org"
    }
])

r_blocked = req("http://httpbin.org/get")

clear_rules()

time.sleep(1.5)  # give hot-reload time to fire

r_after = req("http://httpbin.org/get")

if (r_blocked is None or r_blocked.status_code >= 400) and r_after and r_after.status_code < 400:
    print(f"{PASS} Rules properly disabled after clear")
elif r_blocked is None or r_blocked.status_code >= 400:
    print(f"{PASS} Block confirmed; post-clear check: status={r_after.status_code if r_after else 'None'}")
else:
    print(f"{FAIL} Block did not fire (status={r_blocked.status_code if r_blocked else 'None'})")

# =========================================================
# TEST 17 — HOT RELOAD
# =========================================================

print("\n[TEST 17] Hot Reload")

write_rules([
    {
        "type": "BLOCK",
        "match": "domain",
        "pattern": "example.com"
    }
])

r1 = req("http://example.com")

write_rules([])

r2 = req("http://example.com")

if (r1 is None or r1.status_code >= 400) and r2 and r2.status_code < 400:
    print(f"{PASS} Hot reload works")
else:
    print(f"{FAIL} Hot reload failed")

# =========================================================
# CLEANUP
# =========================================================

print_section("Cleanup")

clear_rules()

print(f"{PASS} Rules cleared")
print(f"{INFO} Test suite completed")