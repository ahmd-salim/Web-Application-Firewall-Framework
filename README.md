# Pre-WAF HTTP Normalization and Attack Detection Framework

This project is a demo WAF reverse-proxy that sits in front of an intentionally vulnerable Flask web application.

## Components

- `main.py` (FastAPI reverse proxy WAF) on `http://localhost:8000`
- `backend.py` (Flask vulnerable demo app) on `http://localhost:8001`
- `normalization/` request normalization (double URL decode + lowercase)
- `detection/` rule-file-driven detection engine
- `decision/` mode/threshold decision engine
- `templates/blocked.html` modern block page
- `logs/attacks.log` JSON lines detections log

## Install

From the project folder:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

Terminal 1 (backend):

```bash
python3 backend.py
```

Terminal 2 (proxy WAF):

```bash
python3 main.py
```

Open:

- Without WAF: `http://localhost:8001`
- With WAF: `http://localhost:8000`

## WAF Mode / Threshold

Environment variables:

- `WAF_MODE=block` (default): block and show block page
- `WAF_MODE=detect`: log only, allow request
- `WAF_MODE=off`: bypass WAF logic
- `WAF_THRESHOLD=80` (default): score threshold for blocking
- `ATTACK_LOG_PATH=logs/attacks.log`
- `WAF_RULES_DIR=detection/rules`
- `WAF_TARGET=http://localhost:8001`

## Rule Files

Rules live in `detection/rules/` (one signature per line):

- `sqli.txt`
- `xss.txt`
- `command_injection.txt`
- `path_traversal.txt`

## Test Payload Examples

SQLi (login bypass):

- Username: `admin`
- Password: `' OR 1=1--`

Command injection:

- This is demonstrated via the dashboard Ping feature (POST `/ping` host field), not via `/login`.
- Example host: `127.0.0.1; ls`

Reflected XSS:

- `GET /search?q=<script>alert(1)</script>`

Stored XSS:

- Post comment: `<img src=x onerror=alert(1)>`

Command injection:

- POST `/ping` host: `127.0.0.1; whoami`

Path traversal:

- `GET /download?file=../../etc/passwd`
