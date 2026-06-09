from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response, PlainTextResponse
from fastapi.templating import Jinja2Templates
import httpx

import json
import os
import uuid
import re
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl

from normalization.normalizer import normalize_payload
from detection.detector import detect_all, detect_xss
from decision.engine import decide
from waf_logging import append_attack_log


app = FastAPI()

TARGET = os.getenv("WAF_TARGET", "http://localhost:8001")
RULES_DIR = os.getenv("WAF_RULES_DIR", os.path.join(os.path.dirname(__file__), "detection", "rules"))
ATTACK_LOG_PATH = os.getenv("ATTACK_LOG_PATH", os.path.join(os.path.dirname(__file__), "logs", "attacks.log"))

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", str(1024 * 1024)))  # 1 MiB default
MAX_RESPONSE_INSPECT_BYTES = int(os.getenv("MAX_RESPONSE_INSPECT_BYTES", str(256 * 1024)))  # 256 KiB default
DEBUG_WAF = os.getenv("DEBUG_WAF", "0").strip().lower() in {"1", "true", "yes"}

BACKEND_TIMEOUT = httpx.Timeout(
    timeout=10.0,
    connect=10.0,
    read=10.0,
    write=10.0,
    pool=10.0,
)

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_BINARY_CT_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "font/",
)

_SUSPECT_XSS_CHARS_RE = re.compile(r"[<>\"']|%3c|%3e", re.IGNORECASE)

SAFE_BROWSER_HEADERS = {
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
}

_LIGHT_HEADER_XSS_RE = re.compile(r"(?i)<\\s*script|javascript:|onerror\\s*=|onload\\s*=|<\\s*svg|<\\s*img")
_CRLF_RE = re.compile(r"(\\r\\n|%0d%0a)", re.IGNORECASE)
_SSRF_URL_RE = re.compile(r"(?i)https?://(?:127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|169\\.254\\.169\\.254)\\b")

_SQL_ERROR_RE = re.compile(
    r"(?i)\b("
    r"sqlite\s*error|sqlite3\."
    r"|mysql\s+error|you have an error in your sql syntax"
    r"|sql syntax"
    r"|unclosed quotation mark"
    r"|odbc|sqlstate"
    r"|postgres(?:ql)?\s+error|pg::"
    r"|syntax error at or near"
    r")\b"
)

_STACKTRACE_RE = re.compile(
    r"(?is)\b(traceback\s*\(most recent call last\)|werkzeug debug traceback|exception in thread|stack trace)\b"
)

_SENSITIVE_RE = re.compile(
    r"(?is)\b("
    r"AKIA[0-9A-Z]{16}"
    r"|BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY"
    r"|BEGIN\s+OPENSSH\s+PRIVATE\s+KEY"
    r"|DATABASE_URL\s*="
    r"|SECRET_KEY\s*="
    r"|GITHUB_TOKEN\s*="
    r"|GH[pousr]_[A-Za-z0-9_]{20,}"
    r")\b"
)


def _walk_json_strings(value: Any, path: str = "$") -> Iterable[Tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if isinstance(key, str) else f"{path}.[{repr(key)}]"
            yield from _walk_json_strings(child, child_path)
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json_strings(child, f"{path}[{index}]")
        return

    if isinstance(value, str):
        yield path, value


def _extract_request_values(request: Request, body: bytes) -> List[Tuple[str, str, str]]:
    values: List[Tuple[str, str, str]] = []

    # Inspect all headers except hop-by-hop/noisy headers.
    # Attackers frequently abuse headers for payload delivery and evasion.
    for key, value in request.headers.items():
        lk = key.lower()
        if lk in _HOP_BY_HOP_HEADERS:
            continue
        values.append(("header", key, value))

    # Query params must preserve duplicates (HPP); we inspect and forward using multi_items().
    for key, value in request.query_params.multi_items():
        values.append(("query", key, value))

    content_type = (request.headers.get("content-type") or "").lower()
    body_text = body.decode(errors="ignore")
    parsed_structured = False

    if "application/x-www-form-urlencoded" in content_type:
        for key, value in parse_qsl(body_text, keep_blank_values=True):
            values.append(("form", key, value))
        parsed_structured = True
    elif "application/json" in content_type:
        try:
            parsed = json.loads(body_text) if body_text.strip() else None
        except Exception:
            parsed = None

        if parsed is not None:
            for json_path, value in _walk_json_strings(parsed):
                values.append(("json", json_path, value))
            parsed_structured = True

    if body_text.strip() and not parsed_structured:
        values.append(("body", "(raw)", body_text[:4096]))

    return values


def _extract_response_values(backend_response: httpx.Response) -> List[Tuple[str, str, str]]:
    values: List[Tuple[str, str, str]] = []

    content_type = (backend_response.headers.get("content-type") or "").lower()
    if content_type.startswith(_BINARY_CT_PREFIXES):
        return values

    # Response inspection is restricted to text-bearing content types only.
    # Do not reuse request-side attack signatures on full HTML pages (high false positives).
    if any(
        x in content_type
        for x in (
            "text/html",
            "application/json",
            "application/javascript",
            "text/javascript",
        )
    ):
        raw = backend_response.content or b""
        snippet = raw[:MAX_RESPONSE_INSPECT_BYTES]
        if snippet:
            values.append(("response_body", "(raw)", snippet.decode(errors="ignore")))

    return values


async def _read_body_limited(request: Request) -> bytes:
    """
    Read request body in chunks with a hard size limit.
    This prevents memory exhaustion attacks while still supporting inspection/forwarding.
    """
    total = 0
    chunks: List[bytes] = []
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_BODY_SIZE:
            raise ValueError("body_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _make_reflection_fingerprint(value: str) -> str:
    """
    Normalization is used on a COPY for detection/correlation only.
    We never mutate the forwarded traffic based on normalization.
    """
    return normalize_payload(value)[:512]


def _is_reflected(request_fingerprints: List[str], response_text: str) -> bool:
    hay = normalize_payload(response_text)
    for fp in request_fingerprints:
        if fp and fp in hay:
            return True
    return False


def _inspect_response_body(
    response_text: str,
    request_xss_fingerprints: List[str],
    rules_dir: str,
) -> List[Dict[str, Any]]:
    """
    Dedicated response inspection.

    - Do not scan full HTML with request-side signatures (CommandInjection/PathTraversal/SQLi payloads).
    - Detect contextual response issues instead:
      * reflected XSS (request/response correlation)
      * SQL error leakage
      * stack trace leakage
      * sensitive information exposure
    """
    findings: List[Dict[str, Any]] = []

    normalized_response = normalize_payload(response_text)

    reflected = _is_reflected(request_xss_fingerprints, response_text)
    if reflected:
        xss = detect_xss(response_text, rules_dir=rules_dir)
        if xss.get("detected"):
            findings.append(
                {
                    "location": "response_body",
                    "key": "(raw)",
                    "payload": response_text[:2000],
                    "normalized_payload": xss.get("normalized_payload"),
                    "attack_type": "ReflectedXSS",
                    "matched_rule": xss.get("rule"),
                    "score": 95,
                }
            )

    m = _SQL_ERROR_RE.search(normalized_response)
    if m:
        findings.append(
            {
                "location": "response_body",
                "key": "(raw)",
                "payload": response_text[:2000],
                "normalized_payload": normalized_response[:2000],
                "attack_type": "SQLErrorLeak",
                "matched_rule": m.group(0)[:120],
                "score": 85,
            }
        )

    m = _STACKTRACE_RE.search(response_text)
    if m:
        findings.append(
            {
                "location": "response_body",
                "key": "(raw)",
                "payload": response_text[:2000],
                "normalized_payload": normalized_response[:2000],
                "attack_type": "StackTraceLeak",
                "matched_rule": m.group(0)[:120],
                "score": 90,
            }
        )

    m = _SENSITIVE_RE.search(response_text)
    if m:
        # Sensitive leak detection is intentionally restricted to high-confidence secret formats
        # that should never be rendered into HTML/JSON/plaintext. Do not treat auth cookies,
        # CSRF tokens, or JWT-like session artifacts as "leaks" on the response path.
        findings.append(
            {
                "location": "response_body",
                "key": "(raw)",
                "payload": response_text[:2000],
                "normalized_payload": normalize_payload(m.group(0))[:200],
                "attack_type": "SensitiveDataExposure",
                "matched_rule": m.group(0)[:120],
                "score": 95,
            }
        )

    return findings


async def _forward(path: str, request: Request) -> Response:
    url = f"{TARGET}/{path}" if path else TARGET
    try:
        body = await _read_body_limited(request)
    except ValueError:
        return PlainTextResponse("Request body too large", status_code=413)

    # Preserve ORIGINAL query params exactly as received when forwarding.
    # Normalized copies are used ONLY for detection.
    original_params: List[Tuple[str, str]] = list(request.query_params.multi_items())

    detections: List[Dict[str, Any]] = []
    request_xss_fingerprints: List[str] = []
    for location, key, value in _extract_request_values(request, body):
        raw_value = str(value)
        normalized_value = normalize_payload(raw_value)
        header_name = key.lower() if location == "header" and isinstance(key, str) else ""

        # Surface-specific inspection profiles:
        # - Headers contain browser negotiation tokens (including semicolons); naked metacharacter matching is dangerous.
        # - Query/Form/JSON/Raw bodies are attacker-controlled inputs; inspect aggressively using the full rule packs.
        if location == "header" and header_name in SAFE_BROWSER_HEADERS:
            if _CRLF_RE.search(raw_value):
                detections.append(
                    {
                        "location": location,
                        "key": key,
                        "payload": raw_value,
                        "normalized_payload": normalized_value,
                        "attack_type": "CRLFInjection",
                        "matched_rule": "CRLF",
                        "score": 85,
                    }
                )
            if _LIGHT_HEADER_XSS_RE.search(raw_value) or _SUSPECT_XSS_CHARS_RE.search(raw_value):
                for hit in (detect_xss(normalized_value, rules_dir=RULES_DIR),):
                    if hit.get("detected"):
                        detections.append(
                            {
                                "location": location,
                                "key": key,
                                "payload": raw_value,
                                "normalized_payload": hit.get("normalized_payload", normalized_value),
                                "attack_type": hit.get("type"),
                                "matched_rule": hit.get("rule"),
                                "score": hit.get("score"),
                            }
                        )
            if _SSRF_URL_RE.search(raw_value):
                detections.append(
                    {
                        "location": location,
                        "key": key,
                        "payload": raw_value,
                        "normalized_payload": normalized_value,
                        "attack_type": "SSRFIndicator",
                        "matched_rule": "localhost/metadata url",
                        "score": 60,
                    }
                )
            if _SUSPECT_XSS_CHARS_RE.search(raw_value):
                request_xss_fingerprints.append(_make_reflection_fingerprint(raw_value))
            continue

        for hit in detect_all(normalized_value, rules_dir=RULES_DIR):
            detections.append(
                {
                    "location": location,
                    "key": key,
                    "payload": raw_value,
                    "normalized_payload": hit.get("normalized_payload", normalized_value),
                    "attack_type": hit.get("type"),
                    "matched_rule": hit.get("rule"),
                    "score": hit.get("score"),
                }
            )
        # Collect candidate fingerprints to correlate reflected XSS on the response.
        if _SUSPECT_XSS_CHARS_RE.search(raw_value):
            request_xss_fingerprints.append(_make_reflection_fingerprint(raw_value))

    request_id = str(uuid.uuid4())
    decision = decide([{"score": d["score"]} for d in detections])

    if decision.action in {"BLOCKED", "DETECTED"} and detections:
        action = "BLOCKED" if decision.action == "BLOCKED" else "DETECTED"
        client_ip = request.client.host if request.client else None
        req_path = str(request.url.path)

        for d in detections:
            if DEBUG_WAF:
                snippet = str(d.get("payload") or "")[:180].replace("\n", "\\n")
                print(
                    f"[WAF][debug] request trigger type={d.get('attack_type')} rule={d.get('matched_rule')} "
                    f"surface={d.get('location')} key={d.get('key')} snippet={snippet}"
                )
            append_attack_log(
                ATTACK_LOG_PATH,
                {
                    "id": request_id,
                    "ip": client_ip,
                    "path": req_path,
                    "payload": d.get("payload"),
                    "normalized_payload": d.get("normalized_payload"),
                    "attack_type": d.get("attack_type"),
                    "matched_rule": d.get("matched_rule"),
                    "score": d.get("score"),
                    "action": action,
                    "source": "request",
                    "surface": d.get("location"),
                    "key": d.get("key"),
                },
            )

        if decision.action == "BLOCKED":
            top = max(detections, key=lambda x: int(x.get("score") or 0))
            return templates.TemplateResponse(
                "blocked.html",
                {
                    "request": request,
                    "attack_type": top.get("attack_type"),
                    "action": action,
                    "request_id": request_id,
                },
                status_code=403,
            )

    try:
        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in {"host", *_HOP_BY_HOP_HEADERS}
        }
        async with httpx.AsyncClient(follow_redirects=False, timeout=BACKEND_TIMEOUT) as client:
            backend_response = await client.request(
                method=request.method,
                url=url,
                params=original_params,
                headers=forward_headers,
                content=body,
            )
    except httpx.TimeoutException:
        return PlainTextResponse("Upstream timeout", status_code=504)
    except httpx.RequestError:
        return PlainTextResponse("Upstream unavailable", status_code=502)

    # Redirects are a normal part of authentication/session flows (e.g., POST /login -> 302 /dashboard).
    # Response-body leakage detection is skipped for redirects to avoid breaking successful logins.
    if backend_response.status_code in {301, 302, 303, 307, 308}:
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )

    response_detections: List[Dict[str, Any]] = []
    for location, key, value in _extract_response_values(backend_response):
        if location != "response_body":
            continue
        response_detections.extend(
            _inspect_response_body(
                response_text=str(value),
                request_xss_fingerprints=request_xss_fingerprints,
                rules_dir=RULES_DIR,
            )
        )

    if response_detections:
        decision = decide([{"score": d["score"]} for d in response_detections])
        if decision.action in {"BLOCKED", "DETECTED"}:
            action = "BLOCKED" if decision.action == "BLOCKED" else "DETECTED"
            client_ip = request.client.host if request.client else None
            req_path = str(request.url.path)
            for d in response_detections:
                if DEBUG_WAF:
                    snippet = str(d.get("payload") or "")[:180].replace("\n", "\\n")
                    print(
                        f"[WAF][debug] response trigger type={d.get('attack_type')} rule={d.get('matched_rule')} "
                        f"snippet={snippet}"
                    )
                append_attack_log(
                    ATTACK_LOG_PATH,
                    {
                        "id": request_id,
                        "ip": client_ip,
                        "path": req_path,
                        "payload": d.get("payload"),
                        "normalized_payload": d.get("normalized_payload"),
                        "attack_type": d.get("attack_type"),
                        "matched_rule": d.get("matched_rule"),
                        "score": d.get("score"),
                        "action": action,
                        "source": "response",
                        "surface": d.get("location"),
                        "key": d.get("key"),
                    },
                )
            if decision.action == "BLOCKED":
                top = max(response_detections, key=lambda x: int(x.get("score") or 0))
                return templates.TemplateResponse(
                    "blocked.html",
                    {
                        "request": request,
                        "attack_type": top.get("attack_type"),
                        "action": action,
                        "request_id": request_id,
                    },
                    status_code=403,
                )

    content_type = backend_response.headers.get("content-type") or ""
    if "text/html" in content_type.lower():
        return HTMLResponse(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=dict(backend_response.headers),
        )

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers),
    )


@app.api_route("/", methods=["GET", "POST"])
async def reverse_proxy_root(request: Request) -> Response:
    return await _forward("", request)


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def reverse_proxy_path(path: str, request: Request) -> Response:
    return await _forward(path, request)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)
