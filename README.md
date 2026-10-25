# Flask Authentication System

Registration, login, logout, protected routes and role-based access control (RBAC).

## Run

```bash
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py            # http://127.0.0.1:5000
pytest -q                # run the test suite
```

Set `COOKIE_SECURE=1` when serving over HTTPS. Set `SECRET_KEY` in production so sessions
survive restarts (otherwise a random key is generated per process).

## Routes

| Route | Access | Purpose |
|---|---|---|
| `GET/POST /register` | public | Create an account (first account becomes `admin`) |
| `GET/POST /login` | public | Log in with username or email |
| `POST /logout` | logged in | End the session |
| `GET /dashboard` | any authenticated user | Protected page |
| `GET /admin` | `admin` only | List users |
| `POST /admin/role/<id>` | `admin` only | Change a user's role |

## Security measures

- **Password hashing:** scrypt via `werkzeug.security`, random per-password salt; 10+ char policy.
- **Sessions:** signed cookies, `HttpOnly`, `SameSite=Lax`, optional `Secure`, 2h lifetime; session cleared and re-issued on login; user is re-loaded from the DB on each request so deleted users are logged out.
- **CSRF:** per-session token required on every POST.
- **SQL injection:** parameterized queries only.
- **User enumeration:** identical error message and a dummy hash check for unknown users.
- **Brute force:** 5 failures per IP+username locks login for 5 minutes (in-memory; use Redis or a DB table for multi-process deployments).
- **Open redirect:** `next` parameter restricted to same-site relative paths.
- **Headers:** CSP, `X-Frame-Options`, `nosniff`, `no-store`.
- **RBAC:** `@login_required` and `@role_required("admin")` decorators; admins can't change their own role.

## Production notes

Run behind HTTPS with a real WSGI server (e.g. `gunicorn app:app`), move the lockout store out of process memory, and consider email verification, password reset and MFA as next steps.
