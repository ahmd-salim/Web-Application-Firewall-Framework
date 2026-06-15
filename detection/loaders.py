import os
from dataclasses import dataclass
from typing import Dict, List

from normalization.normalizer import normalize_payload


@dataclass(frozen=True)
class RuleSet:
    rules: Dict[str, List[str]]
    normalized_rules: Dict[str, List[str]]


def _read_rule_file(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip().strip("\r\n").strip()
            if not s:
                continue
            if s.startswith("#"):
                continue
            out.append(s)
    return out


def load_rules(rules_dir: str) -> RuleSet:
    rule_files = {
        "SQLi": "sqli.txt",
        "XSS": "xss.txt",
        "CommandInjection": "command_injection.txt",
        "PathTraversal": "path_traversal.txt",
    }

    rules: Dict[str, List[str]] = {}
    normalized_rules: Dict[str, List[str]] = {}

    for rule_type, filename in rule_files.items():
        path = os.path.join(rules_dir, filename)
        raw_rules = _read_rule_file(path)
        rules[rule_type] = raw_rules
        normalized_rules[rule_type] = [normalize_payload(r) for r in raw_rules]

    return RuleSet(rules=rules, normalized_rules=normalized_rules)

