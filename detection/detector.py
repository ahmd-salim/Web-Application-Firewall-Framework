import os
from functools import lru_cache
import re
from typing import Any, Dict, List, Optional

from normalization.normalizer import normalize_payload

from .loaders import RuleSet, load_rules


DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


@lru_cache(maxsize=1)
def _ruleset(rules_dir: str = DEFAULT_RULES_DIR) -> RuleSet:
    return load_rules(rules_dir)


def _match(rule_type: str, normalized_payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Optional[str]:
    rs = _ruleset(rules_dir)
    rules = rs.normalized_rules.get(rule_type, [])
    raw_rules = rs.rules.get(rule_type, [])

    for idx, nrule in enumerate(rules):
        if not nrule:
            continue
        raw = raw_rules[idx]
        if raw.startswith("re:"):
            m = re.match(r"^re:(?:score=(\\d+);)?pattern=(.+)$", raw)
            if not m:
                continue
            pattern = m.group(2)
            if re.search(pattern, normalized_payload, re.IGNORECASE):
                return raw
        else:
            if nrule in normalized_payload:
                return raw

    return None


def _match_with_score(rule_type: str, normalized_payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Optional[Dict[str, Any]]:
    rs = _ruleset(rules_dir)
    rules = rs.normalized_rules.get(rule_type, [])
    raw_rules = rs.rules.get(rule_type, [])

    for idx, nrule in enumerate(rules):
        if not nrule:
            continue
        raw = raw_rules[idx]
        if raw.startswith("re:"):
            m = re.match(r"^re:(?:score=(\\d+);)?pattern=(.+)$", raw)
            if not m:
                continue
            score = int(m.group(1) or 0)
            pattern = m.group(2)
            if re.search(pattern, normalized_payload, re.IGNORECASE):
                return {"rule": raw, "score": score}
        else:
            if nrule in normalized_payload:
                return {"rule": raw, "score": 0}

    return None


def detect_sqli(payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    matched = _match("SQLi", normalized, rules_dir)
    detected = matched is not None
    return {
        "detected": detected,
        "type": "SQLi",
        "rule": matched,
        "score": 90 if detected else 0,
        "normalized_payload": normalized,
    }


def detect_xss(payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    matched = _match("XSS", normalized, rules_dir)
    detected = matched is not None
    return {
        "detected": detected,
        "type": "XSS",
        "rule": matched,
        "score": 80 if detected else 0,
        "normalized_payload": normalized,
    }


def detect_command_injection(payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    hit = _match_with_score("CommandInjection", normalized, rules_dir)
    matched = hit["rule"] if hit else None
    score = int(hit["score"]) if hit else 0
    detected = matched is not None
    return {
        "detected": detected,
        "type": "CommandInjection",
        "rule": matched,
        "score": score if detected else 0,
        "normalized_payload": normalized,
    }


def detect_path_traversal(payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    matched = _match("PathTraversal", normalized, rules_dir)
    detected = matched is not None
    return {
        "detected": detected,
        "type": "PathTraversal",
        "rule": matched,
        "score": 85 if detected else 0,
        "normalized_payload": normalized,
    }


def detect_all(payload: str, rules_dir: str = DEFAULT_RULES_DIR) -> List[Dict[str, Any]]:
    detectors = [
        detect_sqli,
        detect_xss,
        detect_command_injection,
        detect_path_traversal,
    ]

    hits: List[Dict[str, Any]] = []
    for det in detectors:
        result = det(payload, rules_dir=rules_dir)
        if result.get("detected"):
            hits.append(result)

    return hits
