import json
import os
import re
import time
import threading
from .shared import _RULES_FILE, _log

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


