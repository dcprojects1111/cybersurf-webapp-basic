#!/usr/bin/env python3
"""
CyberSurf — Internal Breach Check Web App
Password-protected dashboard for running Basic Breach Checks.
"""

import os
import sys
import json
import requests
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, session, redirect, url_for, jsonify

# Allow importing from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DEHASHED_API_KEY, PCLOUD_AUTH_TOKEN, PCLOUD_FOLDER

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-this-in-railway-env")

# Dashboard login password — set APP_PASSWORD in Railway environment variables
APP_PASSWORD = os.environ.get("APP_PASSWORD", "CyberSurf2026!")

DEHASHED_URL  = "https://api.dehashed.com/v2/search"
PCLOUD_UPLOAD = "https://api.pcloud.com/uploadfile"


# ─────────────────────────── Auth ─────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == APP_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("index"))
        error = "Incorrect password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def require_auth():
    if not session.get("authenticated"):
        return redirect(url_for("login"))


# ─────────────────────────── Dehashed ─────────────────────────────────────

def query_dehashed(email):
    headers = {
        "Content-Type":     "application/json",
        "DeHashed-Api-Key": DEHASHED_API_KEY,
    }
    payload = {
        "query":    f'email:"{email}"',
        "page":     1,
        "size":     100,
        "wildcard": False,
        "regex":    False,
        "de_dupe":  True,
    }
    resp = requests.post(DEHASHED_URL, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()


def summarise_entries(entries):
    breaches = defaultdict(lambda: {"count": 0, "exposed_fields": set()})
    for entry in entries:
        source = entry.get("database_name") or "Unknown Source"
        breaches[source]["count"] += 1
        if entry.get("password"):          breaches[source]["exposed_fields"].add("password")
        if entry.get("hashed_password"):   breaches[source]["exposed_fields"].add("hashed password")
        if entry.get("username"):          breaches[source]["exposed_fields"].add("username")
        if entry.get("name"):              breaches[source]["exposed_fields"].add("full name")
        if entry.get("phone"):             breaches[source]["exposed_fields"].add("phone number")
        if entry.get("address"):           breaches[source]["exposed_fields"].add("physical address")
        if entry.get("ip_address"):        breaches[source]["exposed_fields"].add("IP address")
    # Convert sets to sorted lists for JSON serialisation
    return {k: {"count": v["count"], "exposed_fields": sorted(v["exposed_fields"])} for k, v in breaches.items()}


def risk_level(total, has_passwords):
    if total == 0:      return "CLEAR",  "No known breaches found."
    if has_passwords and total >= 3: return "HIGH",   "Multiple breaches including password exposures. Immediate action required."
    if has_passwords:   return "MEDIUM", "Breach found with password exposure. Password change recommended."
    if total >= 5:      return "MEDIUM", "Multiple breaches found. No passwords exposed but personal data is circulating."
    return "LOW", "Breach found but no passwords exposed."


# ─────────────────────────── Report ───────────────────────────────────────

def build_report_text(customer_name, results):
    now  = datetime.now().strftime("%d %B %Y")
    sep  = "=" * 64
    lines = [
        sep,
        "  CYBERSURF SECURITY — BASIC BREACH CHECK REPORT",
        sep,
        f"  Customer   : {customer_name}",
        f"  Date       : {now}",
        f"  Prepared by: Darryl Wessling, CyberSurf Security",
        sep, "",
        "WHAT THIS REPORT COVERS", "-" * 40,
        "We checked your email address(es) against Dehashed — one of the",
        "world's largest breach intelligence databases.",
        "This report tells you which breaches your email appeared in and",
        "what type of data was exposed. It does NOT include raw passwords.",
        "",
    ]
    for r in results:
        risk, risk_desc = r["risk"]
        symbol = {"CLEAR": "✓", "LOW": "!", "MEDIUM": "!!", "HIGH": "!!!"}[risk]
        lines += [
            sep, f"  EMAIL: {r['email']}", sep,
            f"  RISK LEVEL : [{symbol}] {risk}",
            f"  SUMMARY    : {risk_desc}",
            f"  BREACHES   : {r['total']} record(s) across {len(r['breaches'])} source(s)", "",
        ]
        if r["total"] == 0:
            lines += ["  No records found for this address.", ""]
        else:
            lines += ["  BREACH DETAILS", "  " + "-" * 40]
            for source, info in sorted(r["breaches"].items()):
                fields = ", ".join(info["exposed_fields"]) if info["exposed_fields"] else "email address only"
                lines += [f"  Source  : {source}", f"  Records : {info['count']}", f"  Exposed : {fields}", ""]

    any_pw = any(
        "password" in f or "hashed password" in f
        for r in results for info in r["breaches"].values() for f in info["exposed_fields"]
    )
    total_all = sum(r["total"] for r in results)
    lines += [sep, "  RECOMMENDED ACTIONS", sep]
    n = 1
    if any_pw:
        lines += [f"  {n}. CHANGE PASSWORDS IMMEDIATELY — password data was exposed.", ""]
        n += 1
    lines += [
        f"  {n}. Enable MFA on email, banking, and cloud accounts.", "",
        f"  {n+1}. Check for suspicious logins on affected accounts.", "",
        f"  {n+2}. Use a password manager (Bitwarden is free) for unique passwords.", "",
        sep, "  ABOUT THIS REPORT", sep,
        "  CyberSurf does not store your email addresses or breach data.",
        "  Zero retention policy applies.",
        "",
        "  Questions: hello@cybersurf.com.au | cybersurf.com.au",
        sep, "",
    ]
    return "\n".join(lines)


def upload_to_pcloud(filename, content):
    try:
        resp = requests.post(
            PCLOUD_UPLOAD,
            params={"path": PCLOUD_FOLDER, "auth": PCLOUD_AUTH_TOKEN},
            files={"file": (filename, content.encode(), "text/plain")},
            timeout=30,
        )
        data = resp.json()
        return data.get("result") == 0, data.get("error", "unknown error")
    except Exception as e:
        return False, str(e)


# ─────────────────────────── Routes ───────────────────────────────────────

@app.route("/")
def index():
    auth = require_auth()
    if auth: return auth
    return render_template("index.html")


@app.route("/run-check", methods=["POST"])
def run_check():
    auth = require_auth()
    if auth: return auth

    customer_name = request.form.get("name", "").strip()
    email1        = request.form.get("email1", "").strip().lower()
    email2        = request.form.get("email2", "").strip().lower()

    if not customer_name or not email1:
        return render_template("index.html", error="Name and at least one email are required.")

    emails  = [e for e in [email1, email2] if e]
    results = []
    balance = None

    try:
        for email in emails:
            data     = query_dehashed(email)
            balance  = data.get("balance")
            total    = data.get("total", 0)
            entries  = data.get("entries") or []
            breaches = summarise_entries(entries)
            any_pw   = any(
                "password" in f or "hashed password" in f
                for info in breaches.values() for f in info["exposed_fields"]
            )
            risk, risk_desc = risk_level(total, any_pw)
            results.append({
                "email":   email,
                "total":   total,
                "breaches": breaches,
                "risk":    (risk, risk_desc),
            })
    except Exception as e:
        return render_template("index.html", error=f"Dehashed API error: {e}")

    # Build report and upload to pCloud
    report_text = build_report_text(customer_name, results)
    safe_name   = customer_name.replace(" ", "_")
    date_str    = datetime.now().strftime("%Y-%m-%d")
    filename    = f"{safe_name}_{date_str}.txt"

    uploaded, pcloud_error = upload_to_pcloud(filename, report_text)

    return render_template("report.html",
        customer_name=customer_name,
        results=results,
        report_text=report_text,
        filename=filename,
        uploaded=uploaded,
        pcloud_error=pcloud_error,
        balance=balance,
    )


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
