from __future__ import annotations
from zoneinfo import ZoneInfo
from datetime import datetime, timezone
import json
import os
import re
from typing import Any, Dict

def _utc_now_iso() -> str:
    return datetime.now(
        ZoneInfo("Asia/Kolkata")
    ).isoformat(timespec="seconds")

_JWT_LIKE_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_BEARER_RE = re.compile(r"^\s*bearer\s+.+$", re.IGNORECASE)


def _redact_value(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        return value

    v = value
    if _BEARER_RE.match(v):
        return "Bearer [REDACTED]"
    v = _JWT_LIKE_RE.sub("[REDACTED_JWT]", v)
    return v


def redact_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    e = dict(entry)

    key = str(e.get("key") or "").lower()
    surface = str(e.get("surface") or "").lower()

    if surface in {"header", "response_header"}:
        if key in {"authorization", "cookie", "set-cookie"}:
            e["payload"] = "[REDACTED]"
            e["normalized_payload"] = "[REDACTED]"
            return e

    if key in {"password", "passwd", "pass"}:
        e["payload"] = "[REDACTED]"
        e["normalized_payload"] = "[REDACTED]"
        return e

    if "payload" in e:
        e["payload"] = _redact_value(e.get("payload"))
    if "normalized_payload" in e:
        e["normalized_payload"] = _redact_value(e.get("normalized_payload"))

    return e


def append_attack_log(path: str, entry: Dict[str, Any]) -> None:
    payload = redact_entry(entry)
    payload.setdefault("timestamp", _utc_now_iso())

    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        return
