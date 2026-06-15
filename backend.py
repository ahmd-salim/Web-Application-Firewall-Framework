from __future__ import annotations

from flask import Flask, redirect, render_template, request, session
import os
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional


def _project_root() -> str:
    return os.path.dirname(__file__)


def _db_path() -> str:
    webapp_db = os.path.join(_project_root(), "webapp", "users.db")
    legacy_db = os.path.join(_project_root(), "users.db")
    return webapp_db if os.path.exists(webapp_db) else legacy_db


def get_db() -> sqlite3.Connection:
    return sqlite3.connect(_db_path())


def init_db() -> None:
    db = get_db()
    db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, comment TEXT)")

    exists = db.execute("SELECT 1 FROM users WHERE username='admin' LIMIT 1").fetchone()
    if not exists:
        db.execute("INSERT INTO users VALUES ('admin','password')")

    db.commit()
    db.close()


app = Flask(
    __name__,
    template_folder=os.path.join(_project_root(), "webapp", "templates"),
    static_folder=os.path.join(_project_root(), "webapp", "static"),
    static_url_path="/static",
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# Also include top-level `templates/` so admin templates can live at project root.
try:
    from jinja2 import ChoiceLoader, FileSystemLoader

    app.jinja_loader = ChoiceLoader(
        [
            FileSystemLoader(os.path.join(_project_root(), "webapp", "templates")),
            FileSystemLoader(os.path.join(_project_root(), "templates")),
        ]
    )
except Exception:
    pass

# Register admin blueprint if available
# Register admin blueprint if available
try:
    from admin.routes import admin_bp

    app.register_blueprint(admin_bp, url_prefix="/admin")
    print("[+] Admin blueprint loaded successfully")

except Exception as e:
    print("[!] Admin blueprint failed to load:")
    print(e)


def _require_login() -> Optional[str]:
    user = session.get("user")
    if not user:
        return None
    return str(user)


def _latest_comments(limit: int = 10) -> List[Dict[str, Any]]:
    db = get_db()
    rows = db.execute(
        "SELECT id, user, comment FROM comments ORDER BY id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    db.close()
    return [{"id": r[0], "user": r[1], "comment": r[2]} for r in rows]


@app.route("/")
def home():
    return redirect("/login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""

        db = get_db()

        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        result = db.execute(query).fetchone()
        db.close()

        if result:
            session["user"] = username
            return redirect("/dashboard")

        return render_template("login.html", error="Invalid credentials", title="Login")

    return render_template("login.html", error=None, title="Login")


@app.route("/dashboard")
def dashboard():
    user = _require_login()
    if not user:
        return redirect("/login")

    ping_output = session.pop("ping_output", None)
    download_preview = session.pop("download_preview", None)
    download_error = session.pop("download_error", None)
    comments = _latest_comments()

    return render_template(
        "dashboard.html",
        user=user,
        ping_output=ping_output,
        download_preview=download_preview,
        download_error=download_error,
        comments=comments,
        title="Dashboard",
    )


@app.route("/search")
def search():
    user = _require_login()
    if not user:
        return redirect("/login")

    q = request.args.get("q", "")
    return render_template("search.html", q=q, title="Search")


@app.route("/comment", methods=["POST"])
def comment():
    user = _require_login()
    if not user:
        return redirect("/login")

    comment_text = request.form.get("comment") or ""
    db = get_db()
    db.execute("INSERT INTO comments(user, comment) VALUES (?, ?)", (user, comment_text))
    db.commit()
    db.close()
    return redirect("/dashboard")


@app.route("/ping", methods=["POST"])
def ping():
    user = _require_login()
    if not user:
        return redirect("/login")

    host = request.form.get("host") or ""

    cmd = f"ping -c 1 {host}"
    output = subprocess.getoutput(cmd)
    session["ping_output"] = output
    return redirect("/dashboard")


@app.route("/download")
def download():
    user = _require_login()
    if not user:
        return redirect("/login")

    file_path = request.args.get("file", "")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(6000)
        session["download_preview"] = content
        session["download_error"] = None
    except Exception as e:
        session["download_preview"] = None
        session["download_error"] = str(e)

    return redirect("/dashboard")


if __name__ == "__main__":
    init_db()
    app.run(port=8001, debug=True)

