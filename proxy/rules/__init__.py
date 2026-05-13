from .loader import RuleLoader
from .matcher import RuleMatcher
from .conditions import RuleConditionEvaluator
from .actions import RuleExecutor

_loader    = RuleLoader()
_matcher   = RuleMatcher(_loader)
_conditions = RuleConditionEvaluator()
_executor  = RuleExecutor(_loader)

def apply_request_rules(flow):
    _loader.reload()
    for rule in _loader.rules():
        if not rule.get("enabled", True):
            continue
        if rule.get("type") in ("MIME_ONLY", "STATUS_CODE_MATCH",
                                 "RESPONSE_HEADER_INJECT", "DROP_RESPONSE",
                                 "LIMIT_BANDWIDTH", "MODIFY_JSON", "BLOCK_MEDIA"):
            continue
        if not _matcher.matches(rule, flow, "request"):
            continue
        if not _conditions.evaluate(rule, flow, "request"):
            continue
        killed = _executor.execute_request(rule, flow)
        if killed or rule.get("stop", False):
            break

def apply_response_rules(flow):
    _loader.reload()
    for rule in _loader.rules():
        if not rule.get("enabled", True):
            continue
        if rule.get("type") in ("BLOCK", "BLOCK_KEYWORD", "BLOCK_TRACKERS",
                                  "BLOCK_METHOD", "INJECT_HEADER",
                                  "REWRITE_URL", "REDIRECT"):
            continue
        if not _matcher.matches(rule, flow, "response"):
            continue
        if not _conditions.evaluate(rule, flow, "response"):
            continue
        stopped = _executor.execute_response(rule, flow)
        if stopped or rule.get("stop", False):
            break
    _loader.force_flush_hits()

def invalidate_cache():
    _loader.invalidate()
