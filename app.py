"""DANGER ZONE backend (Flask): real email login + optional Google/Discord login.
Run:  pip install flask requests   ->   python app.py   ->   open http://localhost:5000
Keep danger-zone.html in the same folder.
Optional env vars for social login:
  SECRET_KEY, BASE_URL (default http://localhost:5000),
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET
Redirect URI to register on each provider: BASE_URL/auth/google/callback and BASE_URL/auth/discord/callback
"""
import os
import re
import secrets
import sqlite3

import requests
from flask import Flask, jsonify, redirect, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "users.db"
BASE = os.environ.get("BASE_URL", "http://localhost:5000")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

PROVIDERS = {
    "google": dict(
        auth="https://accounts.google.com/o/oauth2/v2/auth",
        token="https://oauth2.googleapis.com/token",
        info="https://openidconnect.googleapis.com/v1/userinfo",
        scope="openid email",
    ),
    "discord": dict(
        auth="https://discord.com/oauth2/authorize",
        token="https://discord.com/api/oauth2/token",
        info="https://discord.com/api/users/@me",
        scope="identify email",
    ),
}


def conf(name):
    key = name.upper()
    return os.environ.get(key + "_CLIENT_ID"), os.environ.get(key + "_CLIENT_SECRET")


def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, pw TEXT)")
    return c


def creds():
    d = request.get_json(silent=True) or {}
    return str(d.get("email", "")).strip().lower(), str(d.get("password", ""))


@app.route("/")
def home():
    return send_from_directory(".", "index.htm")


@app.post("/api/signup")
def signup():
    email, pw = creds()
    if not EMAIL_RE.match(email) or len(pw) < 4:
        return jsonify(error="Enter a valid email and a 4+ character password"), 400
    try:
        with db() as c:
            c.execute("INSERT INTO users VALUES(?,?)", (email, generate_password_hash(pw)))
    except sqlite3.IntegrityError:
        return jsonify(error="Email already registered"), 409
    session["email"] = email
    return jsonify(ok=True, email=email)


@app.post("/api/login")
def login():
    email, pw = creds()
    row = db().execute("SELECT pw FROM users WHERE email=?", (email,)).fetchone()
    if not row or not row[0] or not check_password_hash(row[0], pw):
        return jsonify(error="Wrong email or password"), 401
    session["email"] = email
    return jsonify(ok=True, email=email)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    return jsonify(email=session.get("email"))


@app.get("/api/providers")
def providers():
    return jsonify({n: bool(conf(n)[0]) for n in PROVIDERS})


@app.get("/auth/<n>")
def oauth_start(n):
    cid, _ = conf(n) if n in PROVIDERS else (None, None)
    if not cid:
        return jsonify(error="Not configured"), 404
    session["st"] = secrets.token_urlsafe(16)
    p = PROVIDERS[n]
    url = requests.Request(
        "GET", p["auth"],
        params=dict(client_id=cid, redirect_uri=f"{BASE}/auth/{n}/callback",
                    response_type="code", scope=p["scope"], state=session["st"]),
    ).prepare().url
    return redirect(url)


@app.get("/auth/<n>/callback")
def oauth_cb(n):
    cid, secret = conf(n) if n in PROVIDERS else (None, None)
    if not cid or request.args.get("state") != session.pop("st", None):
        return "Login failed", 400
    p = PROVIDERS[n]
    tok = requests.post(p["token"], data=dict(
        client_id=cid, client_secret=secret, code=request.args.get("code", ""),
        grant_type="authorization_code", redirect_uri=f"{BASE}/auth/{n}/callback"), timeout=10).json()
    u = requests.get(p["info"], headers={"Authorization": f"Bearer {tok.get('access_token', '')}"}, timeout=10).json()
    email = (u.get("email") or "").lower()
    if not email:
        return "No email returned by provider", 400
    with db() as c:
        c.execute("INSERT OR IGNORE INTO users VALUES(?,?)", (email, ""))
    session["email"] = email
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
