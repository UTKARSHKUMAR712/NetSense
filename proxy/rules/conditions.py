import time
from mitmproxy import http
from .shared import _log

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


