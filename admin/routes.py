from __future__ import annotations

import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from typing import Any, Dict

from .utils import (
    load_attacks,
    get_attack_by_id,
    get_statistics,
    get_attack_distribution,
    get_top_ips,
    get_targeted_paths,
)


# compute project root for blueprint assets
PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))


admin_bp = Blueprint(
    "admin",
    __name__,
    template_folder=os.path.join(PROJECT_ROOT, "templates"),
    static_folder=os.path.join(PROJECT_ROOT, "static"),
    static_url_path="/admin/static",
)


def _require_login() -> bool:
    return bool(session.get("admin_logged_in"))


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""
        if username == "admin" and password == "admin123":
            session["admin_logged_in"] = True
            return redirect(url_for("admin.dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("admin_login.html")


@admin_bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin.login"))


@admin_bp.before_request
def protect():
    if request.endpoint and request.endpoint.startswith("admin."):
        if request.path.endswith("/login"):
            return None
        if not _require_login():
            return redirect(url_for("admin.login"))


@admin_bp.route("/")
def dashboard():
    attacks = load_attacks()
    stats = get_statistics(attacks)
    distribution = get_attack_distribution(attacks)
    top_ips = get_top_ips(attacks, top_n=10)
    top_paths = get_targeted_paths(attacks, top_n=10)
    # Pass first page of attacks (pagination via client-side or next route)
    page = int(request.args.get("page", "1"))
    per_page = 25
    start = (page - 1) * per_page
    end = start + per_page
    paged = attacks[start:end]
    # Provide a reduced attacks payload for client-side charting (keeps page responsive)
    attacks_for_charts = attacks[:500]
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        attacks=paged,
        attacks_chart=attacks_for_charts,
        distribution=distribution,
        top_ips=top_ips,
        top_paths=top_paths,
        page=page,
    )


@admin_bp.route("/attacks")
def attacks():
    attacks = load_attacks()
    # filtering
    attack_type = request.args.get("attack_type")
    action = request.args.get("action")
    ip = request.args.get("ip")
    q = request.args.get("q")
    if attack_type:
        attacks = [a for a in attacks if a.get("attack_type") == attack_type]
    if action:
        attacks = [a for a in attacks if str(a.get("action") or "").upper() == action.upper()]
    if ip:
        attacks = [a for a in attacks if a.get("ip") == ip]
    if q:
        attacks = [a for a in attacks if q.lower() in str(a.get("payload", "")).lower() or q.lower() in str(a.get("matched_rule", "")).lower() or q.lower() in str(a.get("path", "")).lower()]

    # pagination
    page = int(request.args.get("page", "1"))
    per_page = 25
    total = len(attacks)
    start = (page - 1) * per_page
    end = start + per_page
    paged = attacks[start:end]

    # additional context expected by dashboard template
    stats = get_statistics(load_attacks())
    distribution = get_attack_distribution(load_attacks())
    top_ips = get_top_ips(load_attacks(), top_n=10)
    top_paths = get_targeted_paths(load_attacks(), top_n=10)
    attacks_for_charts = load_attacks()[:500]

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        attacks=paged,
        attacks_chart=attacks_for_charts,
        distribution=distribution,
        top_ips=top_ips,
        top_paths=top_paths,
        page=page,
        total=total,
    )


@admin_bp.route("/attack/<attack_id>")
def attack_detail(attack_id: str):
    attack = get_attack_by_id(attack_id)
    if not attack:
        return render_template("attack_detail.html", attack=None), 404
    return render_template("attack_detail.html", attack=attack)
