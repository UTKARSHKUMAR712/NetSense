from mitmproxy import http
from .loader import RuleLoader
from .shared import TRACKER_DOMAINS, TRACKER_KEYWORDS

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


