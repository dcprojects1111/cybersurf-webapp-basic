#!/usr/bin/env python3
"""
CyberSurf — Internal Breach Check Web App
Password-protected dashboard for running Basic Breach Checks.
Includes exposed credentials in report, delivered via pCloud secure link.
"""

import os
import json
import hashlib
import smtplib
import stripe
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Flask, render_template, request, session, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "change-this-in-production")

# Credentials — set these as environment variables in Render
APP_PASSWORD      = os.environ.get("APP_PASSWORD", "")
DEHASHED_API_KEY  = os.environ.get("DEHASHED_API_KEY", "")
PCLOUD_AUTH_TOKEN = os.environ.get("PCLOUD_AUTH_TOKEN", "")
PCLOUD_FOLDER     = os.environ.get("PCLOUD_FOLDER", "/CyberSurf Reports")

HIBP_API_KEY          = os.environ.get("HIBP_API_KEY", "")
STRIPE_SECRET_KEY     = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
APP_BASE_URL          = os.environ.get("APP_BASE_URL", "https://cybersurf-webapp-basic.onrender.com")

# Dark Web Monitoring
DWM_PRICE_ID        = os.environ.get("DWM_PRICE_ID", "")        # Stripe recurring price ID ($15/mo)
DWM_2MONTH_PRICE_ID = "price_1TLKpjBMlmXoVl2K53kWW4Kg"         # Stripe one-time price ID ($30 / 2 months)
MONITOR_SECRET      = os.environ.get("MONITOR_SECRET", "")     # Secret to protect /run-monitoring

# Bookable Services
TFA_PRICE_ID                  = os.environ.get("TFA_PRICE_ID", "")                  # 2FA Activation Service — $49
LOCK_CHANGE_PRICE_ID          = os.environ.get("LOCK_CHANGE_PRICE_ID", "")          # Lock Change Session — $79
HOME_SCAN_PRICE_ID            = os.environ.get("HOME_SCAN_PRICE_ID", "")            # Home Security Scan — $229 (3 devices)
HOME_SCAN_EXTENDED_PRICE_ID   = os.environ.get("HOME_SCAN_EXTENDED_PRICE_ID", "")  # Home Security Scan — $269 (6 devices)
HOME_SCAN_BUNDLE_PRICE_ID     = os.environ.get("HOME_SCAN_BUNDLE_PRICE_ID", "")    # Complete Home Security Check — $299

# Fix Session launch offer
FREE_FIX_SLOTS = int(os.environ.get("FREE_FIX_SLOTS", "7"))

# Email alerts (SMTP)
SMTP_HOST  = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER  = os.environ.get("SMTP_USER", "")
SMTP_PASS  = os.environ.get("SMTP_PASS", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@cybersurf.au")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


def init_db():
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    session_id   TEXT PRIMARY KEY,
                    name         TEXT,
                    phone        TEXT,
                    email1       TEXT,
                    email2       TEXT,
                    paid_at      TEXT,
                    amount       TEXT,
                    consent      TEXT,
                    consent_passwords TEXT,
                    consented_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS service_bookings (
                    id         SERIAL PRIMARY KEY,
                    session_id TEXT UNIQUE,
                    service    TEXT,
                    name       TEXT,
                    email      TEXT,
                    phone      TEXT,
                    paid_at    TEXT,
                    amount     TEXT,
                    status     TEXT DEFAULT 'pending'
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS subscribers (
                    id                     SERIAL PRIMARY KEY,
                    name                   TEXT,
                    email                  TEXT NOT NULL,
                    monitor_email1         TEXT NOT NULL,
                    monitor_email2         TEXT,
                    stripe_subscription_id TEXT UNIQUE,
                    stripe_customer_id     TEXT,
                    plan                   TEXT DEFAULT 'monthly',
                    status                 TEXT DEFAULT 'active',
                    created_at             TEXT,
                    created_date           DATE,
                    last_checked           TEXT,
                    last_breach_hash       TEXT,
                    reminder_55_sent       BOOLEAN DEFAULT FALSE,
                    reminder_60_sent       BOOLEAN DEFAULT FALSE
                )
            """)


init_db()

DEHASHED_URL    = "https://api.dehashed.com/v2/search"
HIBP_URL        = "https://haveibeenpwned.com/api/v3"
PCLOUD_UPLOAD   = "https://api.pcloud.com/uploadfile"
PCLOUD_PUBLINK  = "https://api.pcloud.com/getfilepublink"


# ─────────────────────────── Health Check ────────────────────────────────

@app.route("/health")
def health():
    status = {"app": "ok", "database": "not configured"}
    if DATABASE_URL:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            status["database"] = "ok"
        except Exception as e:
            status["database"] = f"error: {e}"
    from flask import jsonify
    return jsonify(status), 200 if status["database"] in ("ok", "not configured") else 500


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

class DehashedUnavailable(Exception):
    """Raised when Dehashed API key is missing or subscription has lapsed."""
    pass


def query_dehashed(email):
    if not DEHASHED_API_KEY:
        raise DehashedUnavailable("No Dehashed API key configured.")
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
    if resp.status_code in (401, 402, 403):
        raise DehashedUnavailable(f"Dehashed subscription inactive or key invalid (HTTP {resp.status_code}).")
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
        source = entry.get("database_name") or "Unknown Source"
        if isinstance(source, list): source = source[0] if source else "Unknown Source"
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
        # Dehashed v2 can return fields as lists — flatten to string
        password = entry.get("password") or ""
        username = entry.get("username") or ""
        if isinstance(password, list): password = password[0] if password else ""
        if isinstance(username, list): username = username[0] if username else ""
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

def _e(s):
    """HTML-escape a value safely."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def build_report_html(customer_name, results, dehashed_unavailable=False):
    now = datetime.now().strftime("%d %B %Y %H:%M AEST")

    risk_colours = {
        "HIGH":   ("#ff4757", "rgba(255,71,87,.12)",  "rgba(255,71,87,.35)"),
        "MEDIUM": ("#ffa500", "rgba(255,165,0,.10)",  "rgba(255,165,0,.35)"),
        "LOW":    ("#ffd200", "rgba(255,210,0,.08)",  "rgba(255,210,0,.3)"),
        "CLEAR":  ("#00d264", "rgba(0,210,100,.08)",  "rgba(0,210,100,.3)"),
    }

    any_pw = any(
        "password" in f or "hashed password" in f
        for r in results for info in r["breaches"].values() for f in info["exposed_fields"]
    )

    # ── Per-email cards ────────────────────────────────────────────────────
    cards_html = ""
    for r in results:
        risk, risk_desc = r["risk"]
        fg, bg, border = risk_colours.get(risk, ("#fcfdf2", "rgba(255,255,255,.05)", "rgba(255,255,255,.15)"))

        breach_rows = ""
        if r["total"] == 0:
            breach_rows = '<p style="color:#00d264;font-size:14px;margin:16px 0 0;">&#10003; No breach records found for this address.</p>'
        else:
            for source, info in sorted(r["breaches"].items()):
                fields = ", ".join(info["exposed_fields"]) if info["exposed_fields"] else "email address only"
                cred_html = ""
                if info["credentials"]:
                    pills = ""
                    for cred in info["credentials"][:10]:
                        parts = []
                        if cred["username"]: parts.append(f"user: {_e(cred['username'])}")
                        if cred["password"]: parts.append(f"pw: {_e(cred['password'])}")
                        if parts:
                            pills += f'<span style="display:inline-block;background:rgba(255,71,87,.12);border:1px solid rgba(255,71,87,.25);border-radius:5px;padding:3px 9px;font-family:monospace;font-size:12px;margin:2px 2px 2px 0;color:#ffcdd2;">{" &nbsp;|&nbsp; ".join(parts)}</span>'
                    if info["credentials"].__len__() > 10:
                        pills += f'<span style="font-size:11px;color:rgba(252,253,242,.3);margin-left:6px;">+{len(info["credentials"])-10} more</span>'
                    cred_html = f'<div style="margin-top:6px;">{pills}</div>'

                breach_rows += f"""
                <tr>
                  <td style="padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);color:rgba(252,253,242,.85);vertical-align:top;">{_e(source)}</td>
                  <td style="padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);color:rgba(252,253,242,.7);vertical-align:top;">{_e(info['count'])}</td>
                  <td style="padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.05);color:rgba(252,253,242,.7);vertical-align:top;">{_e(fields)}{cred_html}</td>
                </tr>"""

            breach_rows = f"""
            <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:16px;">
              <tr>
                <th style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:rgba(0,210,255,.6);padding:8px 14px;text-align:left;border-bottom:1px solid rgba(0,210,255,.15);">Breach Source</th>
                <th style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:rgba(0,210,255,.6);padding:8px 14px;text-align:left;border-bottom:1px solid rgba(0,210,255,.15);">Records</th>
                <th style="font-size:10px;letter-spacing:1px;text-transform:uppercase;color:rgba(0,210,255,.6);padding:8px 14px;text-align:left;border-bottom:1px solid rgba(0,210,255,.15);">Data Exposed / Credentials</th>
              </tr>
              {breach_rows}
            </table>"""

        # HIBP section
        hibp = r.get("hibp")
        hibp_html = ""
        if hibp is not None:
            hibp_inner = ""
            if len(hibp) == 0:
                hibp_inner = '<p style="color:#00d264;font-size:13px;">&#10003; Not found in any verified breaches (HaveIBeenPwned).</p>'
            else:
                for b in sorted(hibp, key=lambda x: x.get("BreachDate",""), reverse=True):
                    classes = _e(", ".join(b.get("DataClasses", [])) or "unknown")
                    hibp_inner += f"""
                    <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:8px;padding:10px 14px;margin-bottom:8px;">
                      <span style="font-size:13px;color:rgba(252,253,242,.85);font-weight:500;">{_e(b.get('Name','Unknown'))}</span>
                      <span style="font-size:11px;color:rgba(252,253,242,.35);margin-left:10px;">{_e(b.get('BreachDate','unknown date'))}</span>
                      <div style="font-size:12px;color:rgba(252,253,242,.5);margin-top:4px;">Domain: {_e(b.get('Domain','—'))} &nbsp;·&nbsp; Data: {classes}</div>
                    </div>"""
            hibp_html = f"""
            <div style="margin-top:20px;padding-top:16px;border-top:1px solid rgba(255,255,255,.07);">
              <p style="font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:rgba(0,210,255,.5);margin-bottom:12px;">&#128737; Verified Breach Records</p>
              {hibp_inner}
            </div>"""

        cards_html += f"""
        <div style="background:{bg};border:1px solid {border};border-radius:14px;padding:24px 28px;margin-bottom:20px;">
          <div style="display:inline-block;background:rgba(0,0,0,.2);border:1px solid {border};color:{fg};font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:3px 12px;border-radius:20px;margin-bottom:12px;">{_e(risk)}</div>
          <div style="font-size:17px;font-weight:700;color:#fcfdf2;margin-bottom:4px;">{_e(r['email'])}</div>
          <div style="font-size:13px;color:rgba(252,253,242,.55);margin-bottom:4px;">{_e(risk_desc)}</div>
          <div style="font-size:12px;color:rgba(252,253,242,.35);">{r['total']} record(s) across {len(r['breaches'])} source(s)</div>
          {breach_rows}
          {hibp_html}
        </div>"""

    # ── Recommendations ────────────────────────────────────────────────────
    recs = []
    if any_pw:
        recs.append(("<span style='color:#ff4757;'>&#9888; Change your passwords immediately</span>",
                     "Change the password on every account that used any of the passwords listed above — especially email, banking, and social media. Do not reuse passwords."))
    recs += [
        ("Enable multi-factor authentication (MFA)",
         "Turn on 2-step verification on your email, banking, and social media accounts. Use an authenticator app (Google Authenticator or Aegis) rather than SMS where possible."),
        ("Check for suspicious logins",
         "Review recent login activity on your important accounts. Look for unknown devices or unfamiliar locations."),
        ("Use a password manager",
         "Bitwarden is free and open source. It generates strong, unique passwords for every account so a single breach never puts your other accounts at risk."),
    ]

    recs_html = ""
    for i, (title, body) in enumerate(recs, 1):
        recs_html += f"""
        <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:16px;">
          <div style="background:rgba(0,210,255,.15);color:#00d2ff;font-size:12px;font-weight:700;width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px;">{i}</div>
          <div>
            <div style="font-size:14px;font-weight:500;color:#fcfdf2;margin-bottom:4px;">{title}</div>
            <div style="font-size:13px;color:rgba(252,253,242,.6);line-height:1.6;">{body}</div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>CyberSurf Security — Breach Check Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:linear-gradient(160deg,#0a1628 0%,#0d2240 100%);min-height:100vh;padding:40px 20px;color:#fcfdf2;}}
    .page{{max-width:760px;margin:0 auto;}}
    @media print{{body{{background:#fff!important;color:#000!important;padding:0;}}}}
  </style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div style="background:rgba(0,0,0,.3);border:1px solid rgba(0,210,255,.2);border-radius:14px;padding:28px 32px;margin-bottom:20px;">
    <div style="font-size:22px;font-weight:800;color:#fff;margin-bottom:2px;">Cyber<span style="color:#00d2ff;">Surf</span> Security</div>
    <div style="font-size:13px;color:rgba(0,210,255,.7);font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:20px;">Basic Breach Check Report</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px;">
      <div><span style="color:rgba(252,253,242,.4);">Customer</span> &nbsp; <span style="color:#fcfdf2;font-weight:500;">{_e(customer_name)}</span></div>
      <div><span style="color:rgba(252,253,242,.4);">Date</span> &nbsp; <span style="color:#fcfdf2;">{_e(now)}</span></div>
      <div><span style="color:rgba(252,253,242,.4);">Prepared by</span> &nbsp; <span style="color:#fcfdf2;">Darryl Wessling, CyberSurf Security</span></div>
      <div><span style="color:rgba(252,253,242,.4);">Classification</span> &nbsp; <span style="color:#ff4757;font-weight:600;">CONFIDENTIAL</span></div>
    </div>
  </div>

  <!-- Warning banner -->
  <div style="background:rgba(255,165,0,.08);border:1px solid rgba(255,165,0,.3);border-radius:10px;padding:16px 20px;margin-bottom:24px;font-size:13px;color:rgba(252,253,242,.75);line-height:1.7;">
    <strong style="color:#ffa500;">&#9888; Important — Read First</strong><br/>
    This report was prepared with your explicit consent and contains personal credential data found in known data breach databases.
    <strong style="color:#fcfdf2;">Do not share this report.</strong> Delete it after you have reviewed it and changed any exposed passwords.
  </div>

  {"" if not dehashed_unavailable else '''
  <!-- Dehashed fallback notice -->
  <div style="background:rgba(0,119,190,.08);border:1px solid rgba(0,119,190,.35);border-radius:10px;padding:16px 20px;margin-bottom:24px;font-size:13px;color:rgba(252,253,242,.75);line-height:1.7;">
    <strong style="color:#00d2ff;">&#8505; Data Source Notice</strong><br/>
    Credential database (Dehashed) is currently unavailable. This report is based on <strong style="color:#fcfdf2;">publicly verified breach records only (HIBP)</strong> — exposed passwords are not included.
    The breach list below shows known data exposure events for this email address. For a full credential report including exposed passwords, please request a new check when the service is restored.
  </div>
  '''}

  <!-- Email result cards -->
  {cards_html}

  <!-- Recommendations -->
  <div style="background:rgba(255,255,255,.03);border:1px solid rgba(0,210,255,.15);border-radius:14px;padding:24px 28px;margin-bottom:20px;">
    <p style="font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:rgba(0,210,255,.6);margin-bottom:18px;">Recommended Actions</p>
    {recs_html}
  </div>

  <!-- Footer -->
  <div style="background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.07);border-radius:14px;padding:20px 28px;font-size:12px;color:rgba(252,253,242,.4);line-height:1.8;">
    <strong style="color:rgba(252,253,242,.6);">About CyberSurf</strong><br/>
    CyberSurf does not retain your email addresses, credentials, or any breach data after this report is generated.
    Zero retention policy — all data is discarded after report delivery.<br/>
    This report was delivered with your explicit consent under CyberSurf Terms of Service.<br/><br/>
    Questions: <span style="color:#00d2ff;">support@cybersurf.au</span> &nbsp;·&nbsp; cybersurf.com.au &nbsp;·&nbsp; Sunshine Coast, QLD, Australia
  </div>

</div>
</body>
</html>"""


# ─────────────────────────── pCloud ───────────────────────────────────────

def upload_to_pcloud(filename, content):
    """Upload report to pCloud. Returns (success, file_path, error_msg)."""
    try:
        resp = requests.post(
            PCLOUD_UPLOAD,
            params={"path": PCLOUD_FOLDER, "auth": PCLOUD_AUTH_TOKEN},
            files={"file": (filename, content.encode(), "text/html")},
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


# ─────────────────────────── Pending Orders ───────────────────────────────

def load_orders():
    if not DATABASE_URL:
        return []
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM orders ORDER BY paid_at DESC")
                return [dict(row) for row in cur.fetchall()]
    except Exception:
        return []

def save_order(order):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO orders
                    (session_id, name, phone, email1, email2, paid_at, amount, consent, consent_passwords, consented_at)
                VALUES
                    (%(session_id)s, %(name)s, %(phone)s, %(email1)s, %(email2)s, %(paid_at)s, %(amount)s, %(consent)s, %(consent_passwords)s, %(consented_at)s)
                ON CONFLICT (session_id) DO NOTHING
            """, order)

def delete_order(session_id):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM orders WHERE session_id = %s", (session_id,))


# ─────────────────────────── Subscribers ──────────────────────────────────

def save_subscriber(sub):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO subscribers
                    (name, email, monitor_email1, monitor_email2,
                     stripe_subscription_id, stripe_customer_id,
                     plan, status, created_at, created_date)
                VALUES
                    (%(name)s, %(email)s, %(monitor_email1)s, %(monitor_email2)s,
                     %(stripe_subscription_id)s, %(stripe_customer_id)s,
                     %(plan)s, 'active', %(created_at)s, CURRENT_DATE)
                ON CONFLICT (stripe_subscription_id) DO NOTHING
            """, sub)


def load_subscribers():
    if not DATABASE_URL:
        return []
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM subscribers ORDER BY created_at DESC")
                return [dict(row) for row in cur.fetchall()]
    except Exception:
        return []


def cancel_subscriber(stripe_subscription_id):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE subscribers SET status = 'cancelled' WHERE stripe_subscription_id = %s",
                (stripe_subscription_id,)
            )


def update_subscriber_check(sub_id, breach_hash):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE subscribers SET last_checked = %s, last_breach_hash = %s WHERE id = %s",
                (datetime.now().strftime("%d %b %Y %H:%M"), breach_hash, sub_id)
            )


# ─────────────────────────── Service Bookings ─────────────────────────────

def save_service_booking(booking):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO service_bookings
                    (session_id, service, name, email, phone, paid_at, amount)
                VALUES
                    (%(session_id)s, %(service)s, %(name)s, %(email)s,
                     %(phone)s, %(paid_at)s, %(amount)s)
                ON CONFLICT (session_id) DO NOTHING
            """, booking)


def load_service_bookings():
    if not DATABASE_URL:
        return []
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM service_bookings WHERE status = 'pending' ORDER BY paid_at DESC")
                return [dict(row) for row in cur.fetchall()]
    except Exception:
        return []


def count_fix_bookings():
    if not DATABASE_URL:
        return 0
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM service_bookings WHERE service = 'fix_session'")
                return cur.fetchone()[0]
    except Exception:
        return 0


def complete_service_booking(booking_id):
    if not DATABASE_URL:
        return
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE service_bookings SET status = 'completed' WHERE id = %s", (booking_id,))


def send_booking_confirmation(to_email, name, service_name, cal_link, price, free=False, upsell_note=None, upsell_title=None):
    if not SMTP_USER or not SMTP_PASS:
        return False, "SMTP not configured"
    try:
        if free:
            confirm_header = "&#10003; Spot secured — you're in for free"
            confirm_body   = (
                f"Hi {name}, your free spot for <strong>{service_name}</strong> is confirmed. "
                f"No payment required — just choose your session time below."
            )
        else:
            confirm_header = "&#10003; Payment received — you're booked in"
            confirm_body   = (
                f"Hi {name}, your payment of <strong>{price}</strong> for "
                f"<strong>{service_name}</strong> has been received."
            )
        body_html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             background:#0a1628;color:#fcfdf2;padding:40px 20px;margin:0;">
  <div style="max-width:520px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;margin-bottom:4px;">
      Cyber<span style="color:#00d2ff;">Surf</span> Security
    </div>
    <div style="font-size:12px;color:rgba(0,210,255,.7);letter-spacing:1px;
                text-transform:uppercase;margin-bottom:28px;">Booking Confirmation</div>

    <div style="background:rgba(0,210,100,.06);border:1px solid rgba(0,210,100,.3);
                border-radius:12px;padding:24px 28px;margin-bottom:24px;">
      <div style="font-size:16px;font-weight:700;color:#fcfdf2;margin-bottom:8px;">
        {confirm_header}
      </div>
      <p style="font-size:14px;color:rgba(252,253,242,.75);line-height:1.6;margin:0 0 6px;">
        {confirm_body}
      </p>
      <p style="font-size:14px;color:rgba(252,253,242,.75);line-height:1.6;margin:0 0 20px;">
        Click below to choose your session time — pick whatever works best for you.
      </p>
      <a href="{cal_link}"
         style="display:inline-block;background:linear-gradient(135deg,#00d2ff 0%,#0077be 100%);
                color:#fff;font-weight:800;font-size:14px;padding:12px 28px;
                border-radius:8px;text-decoration:none;">
        Choose your session time &rarr;
      </a>
    </div>

    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(0,210,255,.15);
                border-radius:12px;padding:20px 24px;margin-bottom:24px;">
      <p style="font-size:13px;font-weight:700;color:#00d2ff;
                text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">
        What happens next
      </p>
      <ol style="margin:0 0 0 18px;font-size:13px;color:rgba(252,253,242,.7);
                 line-height:1.9;padding:0;">
        <li>Click the link above and pick a time that suits you</li>
        <li>You'll receive a calendar invite with the Zoom link</li>
        <li>Darryl will run your session at the scheduled time</li>
      </ol>
    </div>

    {f'''<div style="background:rgba(255,200,0,.06);border:1px solid rgba(255,200,0,.2);
                border-radius:10px;padding:16px 20px;margin-bottom:24px;">
      <p style="font-size:13px;font-weight:700;color:#ffd200;margin-bottom:8px;">
        {upsell_title or "Want us to fix anything we find on the day?"}
      </p>
      <p style="font-size:13px;color:rgba(252,253,242,.7);line-height:1.7;margin:0;">
        {upsell_note}
      </p>
    </div>''' if upsell_note else ""}

    {"" if free else '''<div style="background:rgba(255,165,0,.06);border:1px solid rgba(255,165,0,.2);
                border-radius:10px;padding:14px 18px;margin-bottom:24px;
                font-size:12px;color:rgba(252,253,242,.6);line-height:1.7;">
      <strong style="color:#ffa500;">Cancellation policy:</strong>
      Cancel 48+ hours before — full refund.
      Cancel 24–48 hours — 50% refund or reschedule credit.
      Cancel under 24 hours / no-show — no refund, credit valid 60 days.
    </div>'''}

    <p style="font-size:13px;color:rgba(252,253,242,.4);line-height:1.7;">
      Questions? Reply to this email or contact
      <a href="mailto:support@cybersurf.au" style="color:#00d2ff;">support@cybersurf.au</a><br/>
      CyberSurf Security &nbsp;·&nbsp; Sunshine Coast, QLD
    </p>
  </div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"CyberSurf — {service_name} booking confirmed"
        msg["From"]    = f"CyberSurf Security <{FROM_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


# ─────────────────────────── Email Alert ──────────────────────────────────

def send_breach_alert(to_email, name, new_sources):
    if not SMTP_USER or not SMTP_PASS:
        return False, "SMTP not configured"
    try:
        sources_html = "".join(
            f'<li style="margin-bottom:6px;color:rgba(252,253,242,.8);">{s}</li>'
            for s in new_sources
        )
        body_html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             background:#0a1628;color:#fcfdf2;padding:40px 20px;margin:0;">
  <div style="max-width:520px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;margin-bottom:4px;">
      Cyber<span style="color:#00d2ff;">Surf</span> Security
    </div>
    <div style="font-size:12px;color:rgba(0,210,255,.7);letter-spacing:1px;
                text-transform:uppercase;margin-bottom:28px;">Dark Web Monitoring Alert</div>

    <div style="background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.35);
                border-radius:12px;padding:24px 28px;margin-bottom:24px;">
      <div style="font-size:16px;font-weight:700;color:#ff4757;margin-bottom:8px;">
        &#9888; New breach detected
      </div>
      <p style="font-size:14px;color:rgba(252,253,242,.75);line-height:1.6;margin:0;">
        Hi {name}, your monthly Dark Web Monitoring check found your details
        in a new data breach. Your information was found in:
      </p>
      <ul style="margin:14px 0 0 18px;font-size:14px;line-height:1.8;">
        {sources_html}
      </ul>
    </div>

    <div style="background:rgba(255,255,255,.04);border:1px solid rgba(0,210,255,.15);
                border-radius:12px;padding:20px 24px;margin-bottom:24px;">
      <p style="font-size:13px;font-weight:700;color:#00d2ff;
                text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;">
        What to do right now
      </p>
      <ol style="margin:0 0 0 18px;font-size:13px;color:rgba(252,253,242,.7);
                 line-height:1.9;padding:0;">
        <li>Change your password on the affected account immediately</li>
        <li>Change it on any other account using the same password</li>
        <li>Enable two-factor authentication (2FA) on your email and banking</li>
        <li>Check for suspicious login activity on your accounts</li>
      </ol>
    </div>

    <p style="font-size:13px;color:rgba(252,253,242,.4);line-height:1.7;">
      Need help? Reply to this email or contact
      <a href="mailto:support@cybersurf.au" style="color:#00d2ff;">support@cybersurf.au</a><br/>
      CyberSurf Security &nbsp;·&nbsp; Sunshine Coast, QLD
    </p>
  </div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "CyberSurf Alert — New breach detected on your account"
        msg["From"]    = f"CyberSurf Security <{FROM_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def send_renewal_reminder(to_email, name, days_left):
    if not SMTP_USER or not SMTP_PASS:
        return False, "SMTP not configured"
    try:
        if days_left == 5:
            subject = "Your Dark Web Monitoring expires in 5 days — want to continue?"
            headline = "Your 2-month pack expires in 5 days"
            body = "Your Dark Web Monitoring coverage expires in 5 days. If you'd like to continue being protected, click below to subscribe monthly for $15/month — cancel anytime."
        else:
            subject = "Last day — your Dark Web Monitoring expires today"
            headline = "Your coverage expires today"
            body = "Today is the last day of your 2-month Dark Web Monitoring pack. Subscribe monthly to keep your protection active — $15/month, cancel anytime."

        body_html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             background:#0a1628;color:#fcfdf2;padding:40px 20px;margin:0;">
  <div style="max-width:520px;margin:0 auto;">
    <div style="font-size:22px;font-weight:800;margin-bottom:4px;">
      Cyber<span style="color:#00d2ff;">Surf</span> Security
    </div>
    <div style="font-size:12px;color:rgba(0,210,255,.7);letter-spacing:1px;
                text-transform:uppercase;margin-bottom:28px;">Dark Web Monitoring</div>

    <div style="background:rgba(0,210,255,.06);border:1px solid rgba(0,210,255,.25);
                border-radius:12px;padding:24px 28px;margin-bottom:24px;">
      <div style="font-size:16px;font-weight:700;color:#fcfdf2;margin-bottom:8px;">
        {headline}
      </div>
      <p style="font-size:14px;color:rgba(252,253,242,.75);line-height:1.6;margin:0 0 20px;">
        Hi {name}, {body}
      </p>
      <a href="{APP_BASE_URL}/dark-web-monitoring"
         style="display:inline-block;background:linear-gradient(135deg,#00d2ff 0%,#0077be 100%);
                color:#fff;font-weight:800;font-size:14px;padding:12px 28px;
                border-radius:8px;text-decoration:none;">
        Continue for $15/month &rarr;
      </a>
    </div>

    <p style="font-size:13px;color:rgba(252,253,242,.4);line-height:1.7;">
      No action needed if you don't want to continue — your monitoring will simply stop.
      Questions? <a href="mailto:support@cybersurf.au" style="color:#00d2ff;">support@cybersurf.au</a>
    </p>
  </div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"CyberSurf Security <{FROM_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(body_html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)


def check_renewal_reminders():
    """Send day 55 and day 60 renewal reminders for 2-month pack subscribers."""
    if not DATABASE_URL:
        return {"reminders_sent": 0, "errors": []}

    summary = {"reminders_sent": 0, "errors": []}
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM subscribers
                    WHERE plan = 'two_month' AND status = 'active'
                    AND created_date IS NOT NULL
                """)
                subs = [dict(r) for r in cur.fetchall()]

        today = datetime.now().date()
        for sub in subs:
            days = (today - sub["created_date"]).days

            if days >= 55 and not sub["reminder_55_sent"]:
                ok, err = send_renewal_reminder(sub["email"], sub["name"] or "there", 5)
                if ok:
                    with get_db() as conn:
                        with conn.cursor() as cur:
                            cur.execute("UPDATE subscribers SET reminder_55_sent = TRUE WHERE id = %s", (sub["id"],))
                    summary["reminders_sent"] += 1
                else:
                    summary["errors"].append(f"day-55 email to {sub['email']}: {err}")

            elif days >= 60 and not sub["reminder_60_sent"]:
                ok, err = send_renewal_reminder(sub["email"], sub["name"] or "there", 0)
                if ok:
                    with get_db() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE subscribers SET reminder_60_sent = TRUE, status = 'expired' WHERE id = %s",
                                (sub["id"],)
                            )
                    summary["reminders_sent"] += 1
                else:
                    summary["errors"].append(f"day-60 email to {sub['email']}: {err}")

    except Exception as e:
        summary["errors"].append(str(e))

    return summary


def breach_hash(results):
    """Stable hash of current breach state — changes only when new sources appear."""
    sources = sorted(
        f"{email}:{source}"
        for r in results
        for source in r.get("breaches", {}).keys()
    )
    return hashlib.sha256("|".join(sources).encode()).hexdigest()


# ─────────────────────────── Monitoring Run ───────────────────────────────

@app.route("/run-monitoring")
def run_monitoring():
    secret = request.args.get("secret", "")
    if not MONITOR_SECRET or secret != MONITOR_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    subscribers = load_subscribers()
    active = [s for s in subscribers if s["status"] == "active"]

    summary = {"checked": 0, "alerts_sent": 0, "errors": []}

    for sub in active:
        emails = [e for e in [sub["monitor_email1"], sub["monitor_email2"]] if e]
        results = []
        try:
            for email in emails:
                data     = query_dehashed(email)
                total    = data.get("total", 0)
                entries  = data.get("entries") or []
                breaches = process_entries(entries)
                any_pw   = any(
                    "password" in f or "hashed password" in f
                    for info in breaches.values() for f in info["exposed_fields"]
                )
                risk, risk_desc = risk_level(total, any_pw)
                results.append({"email": email, "total": total,
                                 "breaches": breaches, "risk": (risk, risk_desc)})
        except DehashedUnavailable:
            summary["dehashed_skipped"] = True
            continue
        except Exception as e:
            summary["errors"].append(f"sub {sub['id']}: {e}")
            continue

        new_hash = breach_hash(results)
        old_hash = sub.get("last_breach_hash") or ""

        if old_hash and new_hash != old_hash:
            # Find new sources since last check
            old_sources = set(old_hash.split("|")) if old_hash else set()
            new_sources = [
                f"{r['email']} — {source}"
                for r in results
                for source in r["breaches"].keys()
            ]
            ok, err = send_breach_alert(sub["email"], sub["name"] or "there", new_sources)
            if ok:
                summary["alerts_sent"] += 1
            else:
                summary["errors"].append(f"email to {sub['email']}: {err}")

        update_subscriber_check(sub["id"], new_hash)
        summary["checked"] += 1

    renewal = check_renewal_reminders()
    summary["renewal_reminders_sent"] = renewal["reminders_sent"]
    summary["errors"] += renewal["errors"]

    return jsonify(summary), 200


# ─────────────────────────── Stripe ───────────────────────────────────────

@app.route("/create-checkout", methods=["POST"])
def create_checkout():
    name              = request.form.get("name", "").strip()
    phone             = request.form.get("phone", "").strip()
    email1            = request.form.get("email1", "").strip().lower()
    email2            = request.form.get("email2", "").strip().lower()
    consent           = request.form.get("consent", "")
    consent_passwords = request.form.get("consent_passwords", "")

    if not name or not email1:
        return "Name and at least one email address are required.", 400

    if consent != "yes" or consent_passwords != "yes":
        return "Both consent declarations are required.", 400

    if not STRIPE_SECRET_KEY:
        return "Stripe is not configured.", 500

    consented_at = datetime.now().strftime("%d %b %Y %H:%M AEST")

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "aud",
                "product_data": {
                    "name": "CyberSurf Basic Breach Check",
                    "description": "Credential exposure report for up to 2 email addresses. "
                                   "Delivered via secure link within 24 hours.",
                },
                "unit_amount": 3000,  # $30.00 AUD in cents
            },
            "quantity": 1,
        }],
        mode="payment",
        customer_email=email1,
        metadata={
            "customer_name":       name,
            "phone":               phone,
            "email1":              email1,
            "email2":              email2,
            "consent":             consent,
            "consent_passwords":   consent_passwords,
            "consented_at":        consented_at,
        },
        success_url=f"{APP_BASE_URL}/checkout-success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url="https://cybersurf.au",
    )
    return redirect(checkout_session.url, code=303)


@app.route("/checkout-success")
def checkout_success():
    return render_template("success.html")


@app.route("/dark-web-monitoring")
def monitoring_page():
    return render_template("monitoring.html")


@app.route("/subscribe-monitoring", methods=["POST"])
def subscribe_monitoring():
    name           = request.form.get("name", "").strip()
    email          = request.form.get("email", "").strip().lower()
    monitor_email1 = request.form.get("monitor_email1", "").strip().lower()
    monitor_email2 = request.form.get("monitor_email2", "").strip().lower()
    consent        = request.form.get("consent", "")
    plan           = request.form.get("plan", "monthly")  # "monthly" or "two_month"

    if not name or not email or not monitor_email1:
        return "Name, contact email, and at least one email to monitor are required.", 400

    if consent != "yes":
        return "You must agree to the Terms of Service to continue.", 400

    if not STRIPE_SECRET_KEY:
        return "Subscription service is not configured yet.", 500

    if plan == "two_month":
        if not DWM_2MONTH_PRICE_ID:
            return "2-month plan is not configured yet.", 500
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": DWM_2MONTH_PRICE_ID, "quantity": 1}],
            mode="payment",
            customer_email=email,
            metadata={
                "product":        "dark_web_monitoring",
                "plan":           "two_month",
                "customer_name":  name,
                "email":          email,
                "monitor_email1": monitor_email1,
                "monitor_email2": monitor_email2,
            },
            success_url=f"{APP_BASE_URL}/subscribe-success",
            cancel_url=f"{APP_BASE_URL}/dark-web-monitoring",
        )
    else:
        if not DWM_PRICE_ID:
            return "Monthly plan is not configured yet.", 500
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": DWM_PRICE_ID, "quantity": 1}],
            mode="subscription",
            customer_email=email,
            metadata={
                "product":        "dark_web_monitoring",
                "plan":           "monthly",
                "customer_name":  name,
                "email":          email,
                "monitor_email1": monitor_email1,
                "monitor_email2": monitor_email2,
            },
            success_url=f"{APP_BASE_URL}/subscribe-success",
            cancel_url=f"{APP_BASE_URL}/dark-web-monitoring",
        )
    return redirect(checkout_session.url, code=303)


@app.route("/subscribe-success")
def subscribe_success():
    return render_template("subscribe_success.html")


# ─────────────────────────── 2FA Activation Service ───────────────────────

@app.route("/book-2fa")
def book_2fa():
    return render_template("book_2fa.html")


@app.route("/checkout-2fa", methods=["POST"])
def checkout_2fa():
    name         = request.form.get("name", "").strip()
    email        = request.form.get("email", "").strip()
    phone        = request.form.get("phone", "").strip()
    session_type = request.form.get("session_type", "").strip()

    if not name or not email:
        return render_template("book_2fa.html", error="Name and email are required.")

    if not session_type:
        return render_template("book_2fa.html", error="Please select online or in-person.")

    if not TFA_PRICE_ID:
        return "2FA Activation Service is not configured yet.", 500

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": TFA_PRICE_ID, "quantity": 1}],
        mode="payment",
        customer_email=email,
        metadata={
            "product":       "2fa_service",
            "customer_name": name,
            "email":         email,
            "phone":         phone,
            "session_type":  session_type,
        },
        success_url=f"{APP_BASE_URL}/book-2fa-success",
        cancel_url=f"{APP_BASE_URL}/book-2fa",
    )
    return redirect(checkout_session.url, code=303)


@app.route("/book-2fa-success")
def book_2fa_success():
    return render_template("book_2fa_success.html")


@app.route("/book-lock-change")
def book_lock_change():
    return render_template("book_lock_change.html")


@app.route("/checkout-lock-change", methods=["POST"])
def checkout_lock_change():
    name  = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    if not name or not email:
        return render_template("book_lock_change.html", error="Name and email are required.")

    if not LOCK_CHANGE_PRICE_ID:
        return "Lock Change is not configured yet.", 500

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": LOCK_CHANGE_PRICE_ID, "quantity": 1}],
        mode="payment",
        customer_email=email,
        metadata={
            "product":       "lock_change",
            "customer_name": name,
            "email":         email,
            "phone":         phone,
        },
        success_url=f"{APP_BASE_URL}/book-lock-change-success",
        cancel_url=f"{APP_BASE_URL}/book-lock-change",
    )
    return redirect(checkout_session.url, code=303)


@app.route("/book-lock-change-success")
def book_lock_change_success():
    return render_template("book_lock_change_success.html")


@app.route("/book-home-scan")
def book_home_scan():
    tier = request.args.get("tier", "standard")
    return render_template("book_home_scan.html", preselected_tier=tier)


@app.route("/checkout-home-scan", methods=["POST"])
def checkout_home_scan():
    name       = request.form.get("name", "").strip()
    email      = request.form.get("email", "").strip()
    phone      = request.form.get("phone", "").strip()
    device_tier = request.form.get("device_tier", "standard").strip()  # "standard" or "extended"

    if not name or not email:
        return render_template("book_home_scan.html", error="Name and email are required.")

    if device_tier == "extended":
        price_id = HOME_SCAN_EXTENDED_PRICE_ID
        if not price_id:
            return "Home Security Scan (extended) is not configured yet.", 500
        price_label = "$269"
    else:
        price_id = HOME_SCAN_PRICE_ID
        if not price_id:
            return "Home Security Scan is not configured yet.", 500
        price_label = "$229"

    checkout_session = stripe.checkout.Session.create(
        line_items=[{"price": price_id, "quantity": 1}],
        mode="payment",
        customer_email=email,
        metadata={
            "product":       "home_scan",
            "customer_name": name,
            "email":         email,
            "phone":         phone,
            "device_tier":   device_tier,
            "price_label":   price_label,
        },
        success_url=f"{APP_BASE_URL}/book-home-scan-success",
        cancel_url=f"{APP_BASE_URL}/book-home-scan",
    )
    return redirect(checkout_session.url, code=303)


@app.route("/book-home-scan-success")
def book_home_scan_success():
    return render_template("book_home_scan_success.html")


@app.route("/book-home-scan-bundle")
def book_home_scan_bundle():
    return render_template("book_home_scan_bundle.html")


@app.route("/checkout-home-scan-bundle", methods=["POST"])
def checkout_home_scan_bundle():
    name  = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    if not name or not email:
        return render_template("book_home_scan_bundle.html", error="Name and email are required.")

    if not HOME_SCAN_BUNDLE_PRICE_ID:
        return "Home Security Scan Bundle is not configured yet.", 500

    checkout_session = stripe.checkout.Session.create(
        line_items=[{"price": HOME_SCAN_BUNDLE_PRICE_ID, "quantity": 1}],
        mode="payment",
        customer_email=email,
        metadata={
            "product":       "home_scan_bundle",
            "customer_name": name,
            "email":         email,
            "phone":         phone,
        },
        success_url=f"{APP_BASE_URL}/book-home-scan-bundle-success",
        cancel_url=f"{APP_BASE_URL}/book-home-scan-bundle",
    )
    return redirect(checkout_session.url, code=303)


@app.route("/book-home-scan-bundle-success")
def book_home_scan_bundle_success():
    return render_template("book_home_scan_bundle_success.html")


@app.route("/book-fix-session")
def book_fix_session():
    used = count_fix_bookings()
    remaining = max(0, FREE_FIX_SLOTS - used)
    return render_template("book_fix_session.html", spots_remaining=remaining, total_spots=FREE_FIX_SLOTS)


@app.route("/checkout-fix-session", methods=["POST"])
def checkout_fix_session():
    name         = request.form.get("name", "").strip()
    email        = request.form.get("email", "").strip()
    phone        = request.form.get("phone", "").strip()
    session_type = request.form.get("session_type", "").strip()

    used      = count_fix_bookings()
    remaining = max(0, FREE_FIX_SLOTS - used)

    if not name or not email:
        return render_template("book_fix_session.html", error="Name and email are required.",
                               spots_remaining=remaining, total_spots=FREE_FIX_SLOTS)

    if not session_type:
        return render_template("book_fix_session.html", error="Please select Zoom or in-person.",
                               spots_remaining=remaining, total_spots=FREE_FIX_SLOTS)

    import uuid
    save_service_booking({
        "session_id": str(uuid.uuid4()),
        "service":    "fix_session",
        "name":       name,
        "email":      email,
        "phone":      phone,
        "paid_at":    datetime.now().strftime("%d %b %Y %H:%M"),
        "amount":     "FREE" if remaining > 0 else "$149",
    })

    send_booking_confirmation(
        to_email     = email,
        name         = name,
        service_name = "Home Security Fix Session",
        cal_link     = "https://cal.com/cybersurf/fix",
        price        = "FREE" if remaining > 0 else "$149",
        free         = remaining > 0,
    )

    return redirect("/book-fix-session-success")


@app.route("/book-fix-session-success")
def book_fix_session_success():
    return render_template("book_fix_session_success.html")


@app.route("/schedule")
def schedule():
    """Gate the Cal.com booking link behind a valid paid session token."""
    token = request.args.get("token", "").strip()
    if not token or not DATABASE_URL:
        return render_template("payment_required.html")
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT service FROM service_bookings WHERE session_id = %s AND paid_at IS NOT NULL",
                    (token,)
                )
                row = cur.fetchone()
    except Exception:
        return render_template("payment_required.html")
    if not row:
        return render_template("payment_required.html")
    return redirect("https://cal.com/cybersurf/home-security-scan")


@app.route("/webhook", methods=["POST"])
def webhook():
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        except Exception:
            return "", 400
    else:
        try:
            event = json.loads(payload)
        except Exception:
            return "", 400

    event_type = event.get("type")

    if event_type == "checkout.session.completed":
        sess = event["data"]["object"]
        meta = sess.get("metadata", {})

        if meta.get("product") == "dark_web_monitoring":
            plan = meta.get("plan", "monthly")
            save_subscriber({
                "name":                    meta.get("customer_name", ""),
                "email":                   meta.get("email", ""),
                "monitor_email1":          meta.get("monitor_email1", ""),
                "monitor_email2":          meta.get("monitor_email2", "") or None,
                "stripe_subscription_id":  sess.get("subscription") or sess.get("id"),
                "stripe_customer_id":      sess.get("customer"),
                "plan":                    plan,
                "created_at":              datetime.now().strftime("%d %b %Y %H:%M"),
            })
        elif meta.get("product") == "2fa_service":
            name  = meta.get("customer_name", "")
            email = meta.get("email", "")
            save_service_booking({
                "session_id": sess["id"],
                "service":    "2FA Activation",
                "name":       name,
                "email":      email,
                "phone":      meta.get("phone", ""),
                "paid_at":    datetime.now().strftime("%d %b %Y %H:%M"),
                "amount":     f"${sess.get('amount_total', 4900) / 100:.2f} AUD",
            })
            send_booking_confirmation(
                to_email     = email,
                name         = name,
                service_name = "2FA Activation Service",
                cal_link     = "https://cal.com/cybersurf/2fa-activation",
                price        = "$49",
            )
        elif meta.get("product") == "lock_change":
            name  = meta.get("customer_name", "")
            email = meta.get("email", "")
            save_service_booking({
                "session_id": sess["id"],
                "service":    "Lock Change",
                "name":       name,
                "email":      email,
                "phone":      meta.get("phone", ""),
                "paid_at":    datetime.now().strftime("%d %b %Y %H:%M"),
                "amount":     f"${sess.get('amount_total', 7900) / 100:.2f} AUD",
            })
            send_booking_confirmation(
                to_email     = email,
                name         = name,
                service_name = "Lock Change Session",
                cal_link     = "https://cal.com/cybersurf/lock-change",
                price        = "$79",
            )
        elif meta.get("product") == "home_scan":
            name        = meta.get("customer_name", "")
            email       = meta.get("email", "")
            device_tier = meta.get("device_tier", "standard")
            price_label = meta.get("price_label", "$229")
            service_label = "Home Security Scan (up to 6 devices)" if device_tier == "extended" else "Home Security Scan (up to 3 devices)"
            save_service_booking({
                "session_id": sess["id"],
                "service":    service_label,
                "name":       name,
                "email":      email,
                "phone":      meta.get("phone", ""),
                "paid_at":    datetime.now().strftime("%d %b %Y %H:%M"),
                "amount":     f"${sess.get('amount_total', 22900) / 100:.2f} AUD",
            })
            send_booking_confirmation(
                to_email     = email,
                name         = name,
                service_name = service_label,
                cal_link     = f"{APP_BASE_URL}/schedule?token={sess['id']}",
                price        = price_label,
                upsell_note  = "If we find malware or vulnerabilities, we can fix everything before we leave — $149, payable on the day. Or next time, consider the Complete Home Security Check ($299) which includes the Fix Session free. Just reply to this email to add it on.",
            )
        elif meta.get("product") == "home_scan_bundle":
            name  = meta.get("customer_name", "")
            email = meta.get("email", "")
            save_service_booking({
                "session_id": sess["id"],
                "service":    "Home Security Scan Bundle",
                "name":       name,
                "email":      email,
                "phone":      meta.get("phone", ""),
                "paid_at":    datetime.now().strftime("%d %b %Y %H:%M"),
                "amount":     f"${sess.get('amount_total', 29900) / 100:.2f} AUD",
            })
            send_booking_confirmation(
                to_email     = email,
                name         = name,
                service_name = "Complete Home Security Check",
                cal_link     = f"{APP_BASE_URL}/schedule?token={sess['id']}",
                price        = "$299",
                upsell_title = "Your Fix Session is included free.",
                upsell_note  = "After your in-person scan, if we find malware or vulnerabilities, we fix everything before we leave — same day, no extra charge. We'll send you the Fix Session booking link once your scan is confirmed.",
            )
        else:
            save_order({
                "session_id":          sess["id"],
                "name":                meta.get("customer_name", "Unknown"),
                "phone":               meta.get("phone", ""),
                "email1":              meta.get("email1", ""),
                "email2":              meta.get("email2", ""),
                "paid_at":             datetime.now().strftime("%d %b %Y %H:%M"),
                "amount":              f"${sess.get('amount_total', 3000) / 100:.2f} AUD",
                "consent":             meta.get("consent", ""),
                "consent_passwords":   meta.get("consent_passwords", ""),
                "consented_at":        meta.get("consented_at", ""),
            })

    elif event_type == "customer.subscription.deleted":
        sub_id = event["data"]["object"].get("id")
        if sub_id:
            cancel_subscriber(sub_id)

    return "", 200


@app.route("/complete-order/<session_id>", methods=["POST"])
def complete_order(session_id):
    auth = require_auth()
    if auth: return auth
    delete_order(session_id)
    return redirect(url_for("index"))


# ─────────────────────────── Routes ───────────────────────────────────────

@app.route("/")
def index():
    auth = require_auth()
    if auth: return auth
    return render_template("index.html", pending_orders=load_orders(), subscribers=load_subscribers(), service_bookings=load_service_bookings())


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
    dehashed_unavailable = False

    for email in emails:
        # Try Dehashed — fall back to HIBP-only if subscription is inactive
        try:
            data     = query_dehashed(email)
            balance  = data.get("balance")
            total    = data.get("total", 0)
            entries  = data.get("entries") or []
            breaches = process_entries(entries)
        except DehashedUnavailable:
            dehashed_unavailable = True
            total    = 0
            breaches = {}
        except Exception as e:
            return render_template("index.html", error=f"Dehashed API error: {e}")

        any_pw = any(
            "password" in f or "hashed password" in f
            for info in breaches.values() for f in info["exposed_fields"]
        )
        risk, risk_desc = risk_level(total, any_pw)

        # HIBP verified breach list (runs independently — failure is non-fatal)
        hibp_breaches = query_hibp(email)

        # If Dehashed found nothing but HIBP found verified breaches, upgrade from CLEAR
        if risk == "CLEAR" and hibp_breaches:
            risk      = "LOW"
            risk_desc = "Breach found in verified public records. No passwords exposed but your data is circulating."

        results.append({
            "email":        email,
            "total":        total,
            "breaches":     breaches,
            "risk":         (risk, risk_desc),
            "hibp":         hibp_breaches,   # list, [], or None
        })

    # Build report
    report_text = build_report_html(customer_name, results, dehashed_unavailable=dehashed_unavailable)
    safe_name   = customer_name.replace(" ", "_")
    date_str    = datetime.now().strftime("%Y-%m-%d_%H%M")
    filename    = f"{safe_name}_{date_str}.html"

    # Upload to pCloud
    uploaded, file_path, pcloud_error = upload_to_pcloud(filename, report_text)

    # Generate share link
    share_link = None
    link_error = None
    if uploaded:
        share_link, link_error = get_pcloud_share_link(file_path)

    return render_template("report.html",
        customer_name        = customer_name,
        results              = results,
        filename             = filename,
        uploaded             = uploaded,
        pcloud_error         = pcloud_error,
        share_link           = share_link,
        link_error           = link_error,
        balance              = balance,
        dehashed_unavailable = dehashed_unavailable,
    )


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
