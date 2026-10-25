"""User authentication system: registration, login, protected routes, RBAC.

Security features:
- Passwords hashed with scrypt (werkzeug) with per-password random salt
- Server-signed session cookies (HttpOnly, SameSite=Lax, optional Secure)
- CSRF token required on every POST
- Parameterized SQL queries (no SQL injection)
- Generic login errors + constant-time-ish hash check to resist user enumeration
- Basic login throttling per username/IP
- Session ID rotation on login (session cleared first)
- Role-based access control via a decorator
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = os.environ.get("AUTH_DB", "auth.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_failed = {}  # key -> (count, first_failure_time); use Redis in production
# Dummy hash so unknown users cost the same time as known ones
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    db.commit()
    db.close()


# ---------- CSRF ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- auth helpers ----------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("user_id")
    if uid is not None:
        g.user = get_db().execute(
            "SELECT id, username, email, role FROM users WHERE id = ?", (uid,)
        ).fetchone()
        if g.user is None:  # user deleted -> invalidate session
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def safe_next(target):
    """Only allow relative, same-site redirects (prevents open redirect)."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard")


def validate_password(pw):
    errors = []
    if len(pw) < 10:
        errors.append("Password must be at least 10 characters.")
    if len(pw) > 128:
        errors.append("Password must be at most 128 characters.")
    if not re.search(r"[a-z]", pw) or not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw):
        errors.append("Password must include upper-case, lower-case and a digit.")
    return errors


def throttle_key(username):
    return f"{request.remote_addr}|{username.lower()}"


def is_locked(key):
    rec = _failed.get(key)
    if not rec:
        return False
    count, first = rec
    if time.time() - first > LOCKOUT_SECONDS:
        _failed.pop(key, None)
        return False
    return count >= MAX_ATTEMPTS


def record_failure(key):
    count, first = _failed.get(key, (0, time.time()))
    _failed[key] = (count + 1, first)


# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-30 characters: letters, digits, underscore.")
        if not EMAIL_RE.match(email) or len(email) > 254:
            errors.append("Enter a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")
        errors += validate_password(password)

        if not errors:
            db = get_db()
            try:
                # First registered user becomes admin; everyone else is 'user'.
                is_first = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
                db.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
                    (username, email, generate_password_hash(password),
                     "admin" if is_first else "user"),
                )
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
            else:
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username, email=email), 400
    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = throttle_key(username)

        if is_locked(key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429

        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ? OR email = ?",
            (username, username),
        ).fetchone()
        # Always run a hash check so timing doesn't reveal whether the user exists
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

        if user and ok:
            _failed.pop(key, None)
            session.clear()  # new session on privilege change (fixation defence)
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(safe_next(request.args.get("next")))

        record_failure(key)
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@role_required("admin")
def admin():
    users = get_db().execute(
        "SELECT id, username, email, role, created_at FROM users ORDER BY id"
    ).fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/role/<int:user_id>", methods=["POST"])
@role_required("admin")
def set_role(user_id):
    new_role = request.form.get("role")
    if new_role not in ("user", "admin"):
        abort(400)
    if user_id == g.user["id"]:
        flash("You cannot change your own role.", "error")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    flash("Role updated.", "success")
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You don't have permission to view this page."), 403


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=getattr(e, "description", "Bad request")), 400


init_db()

if __name__ == "__main__":
    app.run(debug=False)
