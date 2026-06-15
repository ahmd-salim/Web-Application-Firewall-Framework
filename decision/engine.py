import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Decision:
    action: str  # BLOCKED | DETECTED | ALLOWED | OFF
    threshold: int
    max_score: int
    hit: Optional[Dict[str, Any]]


def waf_mode() -> str:
    return os.getenv("WAF_MODE", "block").strip().lower()


def waf_threshold() -> int:
    raw = os.getenv("WAF_THRESHOLD", "80").strip()
    try:
        return int(raw)
    except Exception:
        return 80


def decide(detections: List[Dict[str, Any]], mode: Optional[str] = None, threshold: Optional[int] = None) -> Decision:
    m = (mode or waf_mode()).strip().lower()
    t = waf_threshold() if threshold is None else int(threshold)

    if m in {"off", "disabled", "0", "false"}:
        return Decision(action="OFF", threshold=t, max_score=0, hit=None)

    max_hit: Optional[Dict[str, Any]] = None
    max_score = 0
    for d in detections:
        score = int(d.get("score") or 0)
        if score > max_score:
            max_score = score
            max_hit = d

    if not max_hit:
        return Decision(action="ALLOWED", threshold=t, max_score=0, hit=None)

    if m in {"detect", "log", "monitor"}:
        return Decision(action="DETECTED", threshold=t, max_score=max_score, hit=max_hit)

    if max_score >= t:
        return Decision(action="BLOCKED", threshold=t, max_score=max_score, hit=max_hit)

    return Decision(action="DETECTED", threshold=t, max_score=max_score, hit=max_hit)

