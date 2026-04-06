#!/usr/bin/env python3
"""
CyberSurf — Internal Breach Check Web App
Password-protected dashboard for running Basic Breach Checks.
Includes exposed credentials in report, delivered via pCloud secure link.
"""

import os
import requests
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-this-in-production")

# Credentials — set these as environment variables in Render
APP_PASSWORD      = os.environ.get("APP_PASSWORD", "CyberSurf2026!")
DEHASHED_API_KEY  = os.environ.get("DEHASHED_API_KEY", "")
PCLOUD_AUTH_TOKEN = os.environ.get("PCLOUD_AUTH_TOKEN", "")
PCLOUD_FOLDER     = os.environ.get("PCLOUD_FOLDER", "/CyberSurf Reports")

HIBP_API_KEY    = os.environ.get("HIBP_API_KEY", "")

DEHASHED_URL    = "https://api.dehashed.com/v2/search"
HIBP_URL        = "https://haveibeenpwned.com/api/v3"
PCLOUD_UPLOAD   = "https://api.pcloud.com/uploadfile"
PCLOUD_PUBLINK  = "https://api.pcloud.com/getfilepublink"


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


def query_hibp(email):
    """
    Query HaveIBeenPwned v3 for verified breach data.
    Returns list of breach dicts, empty list if clean, or None if key not configured.
    """
    if not HIBP_API_KEY:
        return None  # skip gracefully if no key

    try:
        resp = requests.get(
            f"{HIBP_URL}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent":   "CyberSurf-BreachCheck",
            },
            timeout=15,
        )
        if resp.status_code == 404:
            return []   # clean — no breaches found
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None  # don't let HIBP failure break the whole check


def process_entries(entries):
    """
    Group entries by breach source.
    Captures exposed field types AND actual credential values for the report.
    """
    breaches = defaultdict(lambda: {
        "count": 0,
        "exposed_fields": set(),
        "credentials": [],
    })

    seen_creds = set()

    for entry in entries:
        source   = entry.get("database_name") or "Unknown Source"
        breaches[source]["count"] += 1

        # Track field types
        if entry.get("password"):        breaches[source]["exposed_fields"].add("password")
        if entry.get("hashed_password"): breaches[source]["exposed_fields"].add("hashed password")
        if entry.get("username"):        breaches[source]["exposed_fields"].add("username")
        if entry.get("name"):            breaches[source]["exposed_fields"].add("full name")
        if entry.get("phone"):           breaches[source]["exposed_fields"].add("phone number")
        if entry.get("address"):         breaches[source]["exposed_fields"].add("physical address")
        if entry.get("ip_address"):      breaches[source]["exposed_fields"].add("IP address")

        # Capture unique credential pairs
        password = entry.get("password") or ""
        username = entry.get("username") or ""
        if password or username:
            key = (source, username, password)
            if key not in seen_creds:
                seen_creds.add(key)
                breaches[source]["credentials"].append({
                    "username": username,
                    "password": password,
                })

    return {
        k: {
            "count":          v["count"],
            "exposed_fields": sorted(v["exposed_fields"]),
            "credentials":    v["credentials"],
        }
        for k, v in breaches.items()
    }


def risk_level(total, has_passwords):
    if total == 0:                       return "CLEAR",  "No known breaches found."
    if has_passwords and total >= 3:     return "HIGH",   "Multiple breaches including password exposures. Immediate action required."
    if has_passwords:                    return "MEDIUM", "Breach found with password exposure. Password change recommended."
    if total >= 5:                       return "MEDIUM", "Multiple breaches found. No passwords exposed but personal data is circulating."
    return "LOW", "Breach found but no passwords exposed."


# ─────────────────────────── Report Builder ───────────────────────────────

def build_report_text(customer_name, results):
    now = datetime.now().strftime("%d %B %Y %H:%M AEST")
    sep = "=" * 64

    lines = [
        sep,
        "  CYBERSURF SECURITY — BASIC BREACH CHECK REPORT",
        "  CONFIDENTIAL — FOR AUTHORISED RECIPIENT ONLY",
        sep,
        f"  Customer   : {customer_name}",
        f"  Date       : {now}",
        f"  Prepared by: Darryl Wessling, CyberSurf Security",
        sep,
        "",
        "IMPORTANT — READ FIRST",
        "-" * 40,
        "This report was prepared with your explicit consent and contains",
        "personal credential data found in known data breaches.",
        "Do not share this report. Delete it after you have reviewed it",
        "and changed any exposed passwords.",
        "",
        "This report reflects data available in the Dehashed breach",
        "intelligence database at the time of this search.",
        "",
    ]

    for r in results:
        risk, risk_desc = r["risk"]
        symbol = {"CLEAR": "✓", "LOW": "!", "MEDIUM": "!!", "HIGH": "!!!"}[risk]

        lines += [
            sep,
            f"  EMAIL: {r['email']}",
            sep,
            f"  RISK LEVEL : [{symbol}] {risk}",
            f"  SUMMARY    : {risk_desc}",
            f"  BREACHES   : {r['total']} record(s) across {len(r['breaches'])} source(s)",
            "",
        ]

        if r["total"] == 0:
            lines += ["  No records found for this address in the database.", ""]
        else:
            lines += ["  BREACH DETAILS", "  " + "-" * 40]
            for source, info in sorted(r["breaches"].items()):
                fields = ", ".join(info["exposed_fields"]) if info["exposed_fields"] else "email address only"
                lines += [
                    f"  Source  : {source}",
                    f"  Records : {info['count']}",
                    f"  Exposed : {fields}",
                ]
                # Include actual credentials if present
                if info["credentials"]:
                    lines.append("  Credentials found:")
                    for cred in info["credentials"][:10]:  # cap at 10 per source
                        parts = []
                        if cred["username"]: parts.append(f"username: {cred['username']}")
                        if cred["password"]: parts.append(f"password: {cred['password']}")
                        lines.append(f"    → {' | '.join(parts)}")
                lines.append("")

    # HIBP verified breach summary per email
    any_hibp = any(r.get("hibp") for r in results)
    if any_hibp:
        lines += [sep, "  HAVE I BEEN PWNED — VERIFIED BREACH RECORDS", sep]
        for r in results:
            hibp = r.get("hibp")
            lines.append(f"  EMAIL: {r['email']}")
            if hibp is None:
                lines += ["  (HIBP check not available)", ""]
            elif len(hibp) == 0:
                lines += ["  No verified breaches found (HIBP).", ""]
            else:
                lines.append(f"  Found in {len(hibp)} verified breach(es):")
                for b in sorted(hibp, key=lambda x: x.get("BreachDate", ""), reverse=True):
                    classes = ", ".join(b.get("DataClasses", [])) or "unknown"
                    lines += [
                        f"    • {b.get('Name', 'Unknown')} ({b.get('BreachDate', 'unknown date')})",
                        f"      Domain    : {b.get('Domain', '—')}",
                        f"      Data types: {classes}",
                    ]
                lines.append("")

    # Recommendations
    any_pw = any(
        "password" in f or "hashed password" in f
        for r in results for info in r["breaches"].values() for f in info["exposed_fields"]
    )

    lines += [sep, "  RECOMMENDED ACTIONS", sep]
    n = 1
    if any_pw:
        lines += [
            f"  {n}. CHANGE PASSWORDS IMMEDIATELY",
            "     Change the password on every account that used any of the",
            "     passwords listed above — especially email, banking, and",
            "     social media accounts.",
            "",
        ]
        n += 1

    lines += [
        f"  {n}. Enable multi-factor authentication (MFA) on all important accounts.",
        "",
        f"  {n+1}. Check for suspicious logins — look for unknown devices or locations.",
        "",
        f"  {n+2}. Use a password manager (Bitwarden is free) — unique password for",
        "     every account, never reuse.",
        "",
        sep,
        "  ABOUT CYBERSURF",
        sep,
        "  CyberSurf does not retain your email addresses, credentials,",
        "  or any breach data after this report is generated.",
        "  Zero retention policy — all data discarded after report delivery.",
        "",
        "  This report was delivered with your explicit consent under",
        "  CyberSurf Terms of Service.",
        "",
        "  Questions: hello@cybersurf.com.au | cybersurf.com.au",
        "  Sunshine Coast, QLD, Australia",
        sep,
        "",
    ]

    return "\n".join(lines)


# ─────────────────────────── pCloud ───────────────────────────────────────

def upload_to_pcloud(filename, content):
    """Upload report to pCloud. Returns (success, file_path, error_msg)."""
    try:
        resp = requests.post(
            PCLOUD_UPLOAD,
            params={"path": PCLOUD_FOLDER, "auth": PCLOUD_AUTH_TOKEN},
            files={"file": (filename, content.encode(), "text/plain")},
            timeout=30,
        )
        data = resp.json()
        if data.get("result") == 0:
            file_path = f"{PCLOUD_FOLDER}/{filename}"
            return True, file_path, None
        return False, None, data.get("error", "unknown error")
    except Exception as e:
        return False, None, str(e)


def get_pcloud_share_link(file_path):
    """Generate a public share link for a file in pCloud."""
    try:
        resp = requests.get(
            PCLOUD_PUBLINK,
            params={"path": file_path, "auth": PCLOUD_AUTH_TOKEN},
            timeout=15,
        )
        data = resp.json()
        if data.get("result") == 0:
            code = data.get("code", "")
            link = data.get("link") or f"https://u.pcloud.link/publink/show?code={code}"
            # Ensure HTTPS
            link = link.replace("http://", "https://")
            return link, None
        return None, data.get("error", "could not generate link")
    except Exception as e:
        return None, str(e)


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
            breaches = process_entries(entries)
            any_pw   = any(
                "password" in f or "hashed password" in f
                for info in breaches.values() for f in info["exposed_fields"]
            )
            risk, risk_desc = risk_level(total, any_pw)

            # HIBP verified breach list (runs independently — failure is non-fatal)
            hibp_breaches = query_hibp(email)

            results.append({
                "email":        email,
                "total":        total,
                "breaches":     breaches,
                "risk":         (risk, risk_desc),
                "hibp":         hibp_breaches,   # list, [], or None
            })
    except Exception as e:
        return render_template("index.html", error=f"Dehashed API error: {e}")

    # Build report
    report_text = build_report_text(customer_name, results)
    safe_name   = customer_name.replace(" ", "_")
    date_str    = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename    = f"{safe_name}_{date_str}.txt"

    # Upload to pCloud
    uploaded, file_path, pcloud_error = upload_to_pcloud(filename, report_text)

    # Generate share link
    share_link = None
    link_error = None
    if uploaded:
        share_link, link_error = get_pcloud_share_link(file_path)

    return render_template("report.html",
        customer_name = customer_name,
        results       = results,
        filename      = filename,
        uploaded      = uploaded,
        pcloud_error  = pcloud_error,
        share_link    = share_link,
        link_error    = link_error,
        balance       = balance,
    )


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
