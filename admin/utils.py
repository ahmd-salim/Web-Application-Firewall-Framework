from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(__file__))


def _attacks_log_path() -> str:
    return os.path.join(_project_root(), "logs", "attacks.log")


def load_attacks() -> List[Dict[str, Any]]:
    path = _attacks_log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()

    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                out.append(obj)
            except Exception:
                # skip malformed
                continue

    # Ensure timestamps present and sort newest first
    def _ts(a: Dict[str, Any]) -> float:
        t = a.get("timestamp") or a.get("time") or ""
        try:
            return datetime.fromisoformat(t).timestamp()
        except Exception:
            return 0.0

    out.sort(key=_ts, reverse=True)
    return out


def get_attack_by_id(attack_id: str) -> Optional[Dict[str, Any]]:
    attacks = load_attacks()
    for a in attacks:
        if str(a.get("id")) == str(attack_id):
            return a
    return None


def get_statistics(attacks: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    attacks = attacks if attacks is not None else load_attacks()
    total = len(attacks)
    blocked = sum(1 for a in attacks if str(a.get("action") or "").upper() == "BLOCKED")
    detected = sum(1 for a in attacks if str(a.get("action") or "").upper() == "DETECTED")
    unique_ips = len(set(a.get("ip") for a in attacks if a.get("ip")))
    high_sev = sum(1 for a in attacks if int(a.get("score") or 0) >= 80)
    most_common = None
    if attacks:
        counter = Counter(a.get("attack_type") or "UNKNOWN" for a in attacks)
        most_common = counter.most_common(1)[0][0]

    return {
        "total": total,
        "blocked": blocked,
        "detected": detected,
        "unique_ips": unique_ips,
        "high_severity": high_sev,
        "most_common": most_common,
    }


def get_attack_distribution(attacks: Optional[List[Dict[str, Any]]] = None) -> Dict[str, int]:
    attacks = attacks if attacks is not None else load_attacks()
    counter = Counter(a.get("attack_type") or "UNKNOWN" for a in attacks)
    return dict(counter)


def get_top_ips(attacks: Optional[List[Dict[str, Any]]] = None, top_n: int = 10) -> List[Tuple[str, int]]:
    attacks = attacks if attacks is not None else load_attacks()
    counter = Counter(a.get("ip") or "UNKNOWN" for a in attacks)
    return counter.most_common(top_n)


def get_targeted_paths(attacks: Optional[List[Dict[str, Any]]] = None, top_n: int = 10) -> List[Tuple[str, int]]:
    attacks = attacks if attacks is not None else load_attacks()
    counter = Counter(a.get("path") or "UNKNOWN" for a in attacks)
    return counter.most_common(top_n)
