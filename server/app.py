"""MedGate Sentinel API: real accounts + per-user report history.

Auth: bcrypt password hashes, itsdangerous signed bearer tokens (30-day TTL).
Storage: SQLite in WAL mode. Data: saved lab reports + their parsed results.

Design note: the analyzer logic itself runs client-side on purpose (no lab
data leaves the browser unless the user signs in and chooses to save a
report). The server only stores what a signed-in user explicitly saves.
"""
import datetime as dt
import json
import os
import sqlite3
import threading
import time
from functools import wraps

import bcrypt
from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from itsdangerous import BadSignature, URLSafeTimedSerializer

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "medgate_sentinel.db")
SECRET = os.environ.get("MEDGATE_SENTINEL_SECRET_KEY") or os.urandom(32).hex()

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB body cap

_ALLOWED_ORIGINS = {
    "https://shlokgit-04.github.io",
    "https://shlok.is-a.dev",
    "http://localhost:8081",
    "http://localhost:8080",
    "http://127.0.0.1:8081",
}
CORS(app, origins=list(_ALLOWED_ORIGINS),
     allow_headers=["Content-Type", "Authorization"], methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     max_age=86400)

serializer = URLSafeTimedSerializer(SECRET, salt="medgate-sentinel-auth")
TOKEN_TTL_SECONDS = 30 * 24 * 3600

_lock = threading.Lock()


def db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=8000")
        g.db = conn
    return g.db


@app.teardown_appcontext
def _close(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                pw_hash TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                report_text TEXT NOT NULL,
                results_json TEXT NOT NULL DEFAULT '[]',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS rate_limits (
                bucket TEXT PRIMARY KEY,
                window_start REAL NOT NULL,
                count INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
            """
        )
        conn.commit()
    finally:
        conn.close()


# --- security headers -------------------------------------------------------
@app.after_request
def _headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'none'; frame-ancestors 'none'")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# --- rate limiting ----------------------------------------------------------
LIMITS = {  # name -> (max_requests, window_seconds)
    "auth": (20, 300),      # register/login per IP per 5 min
    "read": (120, 60),      # reads per IP per minute
    "write": (60, 60),      # writes per IP per minute
}


def _rate_bucket(name, window_s, max_n):
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or "unknown"
    bucket = f"{name}:{ip}"
    now = time.time()
    with _lock:
        conn = db()
        row = conn.execute("SELECT window_start, count FROM rate_limits WHERE bucket=?", (bucket,)).fetchone()
        if row is None or now - row["window_start"] > window_s:
            conn.execute("INSERT INTO rate_limits(bucket, window_start, count) VALUES(?,?,1) "
                         "ON CONFLICT(bucket) DO UPDATE SET window_start=excluded.window_start, count=1", (bucket, now))
            conn.commit()
            return True
        if row["count"] >= max_n:
            return False
        conn.execute("UPDATE rate_limits SET count=count+1 WHERE bucket=?", (bucket,))
        conn.commit()
        return True


def rate_limited(name):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            max_n, window_s = LIMITS[name]
            if not _rate_bucket(name, window_s, max_n):
                return jsonify(error="Too many requests. Try again shortly."), 429
            return fn(*a, **kw)
        return wrapper
    return deco


# --- helpers ----------------------------------------------------------------
def _valid_email(email):
    return isinstance(email, str) and 3 <= len(email) <= 254 and "@" in email and " " not in email


def _new_user_id():
    return os.urandom(16).hex()


def _token_for(user_id):
    return serializer.dumps({"uid": user_id})


def _user_from_token():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    try:
        payload = serializer.loads(token, max_age=TOKEN_TTL_SECONDS)
    except BadSignature:
        return None
    row = db().execute("SELECT id, email, name, created_at FROM users WHERE id=?", (payload.get("uid"),)).fetchone()
    return row


def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = _user_from_token()
        if user is None:
            return jsonify(error="Not signed in."), 401
        g.user = user
        return fn(*a, **kw)
    return wrapper


# --- service endpoints ------------------------------------------------------
@app.route("/")
def _root():
    return jsonify(service="medgate-sentinel-api", ok=True), 200


@app.route("/api/health")
def _health():
    try:
        db().execute("SELECT 1")
        return jsonify(ok=True, db="up"), 200
    except sqlite3.Error:
        return jsonify(ok=False, db="down"), 503


# --- auth -------------------------------------------------------------------
@app.post("/api/auth/register")
@rate_limited("auth")
def _register():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    name = (body.get("name") or "").strip()[:60]
    if not _valid_email(email):
        return jsonify(error="Enter a valid email address."), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    if len(password) > 200:
        return jsonify(error="Password too long."), 400
    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="That email already has an account. Sign in instead."), 409
    uid = _new_user_id()
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    conn.execute("INSERT INTO users(id, email, pw_hash, name, created_at) VALUES(?,?,?,?,?)",
                 (uid, email, pw_hash, name, dt.datetime.utcnow().isoformat(timespec="seconds")))
    conn.commit()
    return jsonify(token=_token_for(uid), user={"id": uid, "email": email, "name": name}), 201


@app.post("/api/auth/login")
@rate_limited("auth")
def _login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    row = db().execute("SELECT id, email, pw_hash, name FROM users WHERE email=?", (email,)).fetchone()
    if row is None or not bcrypt.checkpw(password.encode(), row["pw_hash"].encode()):
        return jsonify(error="Wrong email or password."), 401
    return jsonify(token=_token_for(row["id"]), user={"id": row["id"], "email": row["email"], "name": row["name"]}), 200


@app.get("/api/auth/me")
@require_auth
def _me():
    u = g.user
    return jsonify(user={"id": u["id"], "email": u["email"], "name": u["name"]}), 200


# --- report history ---------------------------------------------------------
MAX_SAVED_REPORTS = 100


def _valid_results(results):
    """Parsed-result rows the frontend saves back. Kept small and typed."""
    if not isinstance(results, list) or len(results) > 200:
        return None
    clean = []
    for r in results:
        if not isinstance(r, dict):
            return None
        key = r.get("key")
        val = r.get("val")
        lo = r.get("lo")
        hi = r.get("hi")
        status = r.get("status")
        if not (isinstance(key, str) and 0 < len(key) <= 40):
            return None
        for n in (val, lo, hi):
            if not isinstance(n, (int, float)) or n != n or abs(n) > 1e9:
                return None
        if status not in ("high", "low", "border", "normal"):
            return None
        clean.append({"key": key, "val": val, "lo": lo, "hi": hi, "status": status})
    return clean


@app.get("/api/reports")
@require_auth
@rate_limited("read")
def _list_reports():
    rows = db().execute(
        "SELECT id, created_at, title, results_json FROM reports WHERE user_id=? ORDER BY created_at DESC LIMIT 100",
        (g.user["id"],)).fetchall()
    out = []
    for r in rows:
        try:
            results = json.loads(r["results_json"])
        except (ValueError, TypeError):
            results = []
        out.append({"id": r["id"], "created_at": r["created_at"], "title": r["title"], "results": results})
    return jsonify(reports=out), 200


@app.post("/api/reports")
@require_auth
@rate_limited("write")
def _save_report():
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()[:120]
    text = body.get("report_text")
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Report text is empty."), 400
    if len(text) > 50000:
        return jsonify(error="Report text is too long (50,000 character limit)."), 400
    results = _valid_results(body.get("results"))
    if results is None:
        return jsonify(error="Bad results payload."), 400
    conn = db()
    count = conn.execute("SELECT COUNT(*) c FROM reports WHERE user_id=?", (g.user["id"],)).fetchone()["c"]
    if count >= MAX_SAVED_REPORTS:
        return jsonify(error=f"Report history is full ({MAX_SAVED_REPORTS} saved reports). Delete some first."), 409
    rid = _new_user_id()
    conn.execute("INSERT INTO reports(id, user_id, created_at, title, report_text, results_json) VALUES(?,?,?,?,?,?)",
                 (rid, g.user["id"], dt.datetime.utcnow().isoformat(timespec="seconds"),
                  title, text, json.dumps(results)))
    conn.commit()
    return jsonify(report={"id": rid, "created_at": dt.datetime.utcnow().isoformat(timespec="seconds"),
                           "title": title, "results": results}), 201


@app.get("/api/reports/<rid>")
@require_auth
@rate_limited("read")
def _get_report(rid):
    row = db().execute("SELECT id, created_at, title, report_text, results_json FROM reports "
                       "WHERE id=? AND user_id=?", (rid, g.user["id"])).fetchone()
    if row is None:
        return jsonify(error="Report not found."), 404
    try:
        results = json.loads(row["results_json"])
    except (ValueError, TypeError):
        results = []
    return jsonify(report={"id": row["id"], "created_at": row["created_at"], "title": row["title"],
                           "report_text": row["report_text"], "results": results}), 200


@app.delete("/api/reports/<rid>")
@require_auth
@rate_limited("write")
def _delete_report(rid):
    conn = db()
    cur = conn.execute("DELETE FROM reports WHERE id=? AND user_id=?", (rid, g.user["id"]))
    conn.commit()
    if cur.rowcount == 0:
        return jsonify(error="Report not found."), 404
    return jsonify(ok=True), 200


# --- account data rights ----------------------------------------------------
@app.get("/api/auth/export")
@require_auth
@rate_limited("read")
def _export():
    u = g.user
    rows = db().execute("SELECT id, created_at, title, report_text, results_json FROM reports WHERE user_id=?",
                        (u["id"],)).fetchall()
    reports = []
    for r in rows:
        try:
            results = json.loads(r["results_json"])
        except (ValueError, TypeError):
            results = []
        reports.append({"id": r["id"], "created_at": r["created_at"], "title": r["title"],
                        "report_text": r["report_text"], "results": results})
    return jsonify(user={"email": u["email"], "name": u["name"], "created_at": u["created_at"]},
                   reports=reports), 200


@app.delete("/api/auth/me")
@require_auth
def _delete_account():
    conn = db()
    conn.execute("DELETE FROM reports WHERE user_id=?", (g.user["id"],))
    conn.execute("DELETE FROM users WHERE id=?", (g.user["id"],))
    conn.commit()
    return jsonify(ok=True), 200


# Initialize the schema on every import, so gunicorn workers get it too.
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
