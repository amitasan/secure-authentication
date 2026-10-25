import re
import sqlite3

import pytest

import app as appmod


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(appmod, "DATABASE", str(tmp_path / "t.db"))
    appmod._failed.clear()
    appmod.init_db()
    appmod.app.config["TESTING"] = True
    with appmod.app.test_client() as c:
        yield c


def token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def register(client, u="alice", e="alice@example.com", p="Str0ngPassw0rd"):
    return client.post("/register", data={
        "_csrf": token(client, "/register"), "username": u, "email": e,
        "password": p, "confirm": p})


def login(client, u="alice", p="Str0ngPassw0rd", follow=False):
    return client.post("/login", data={"_csrf": token(client), "username": u, "password": p},
                       follow_redirects=follow)


def test_protected_route_redirects_when_anonymous(client):
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_register_and_login_flow(client):
    assert register(client).status_code == 302
    r = login(client)
    assert r.status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_password_is_hashed(client):
    register(client)
    row = sqlite3.connect(appmod.DATABASE).execute("SELECT password_hash FROM users").fetchone()
    assert "Str0ngPassw0rd" not in row[0] and row[0].startswith("scrypt:")


def test_weak_password_rejected(client):
    assert register(client, p="short").status_code == 400
    assert register(client, p="alllowercase123").status_code == 400


def test_duplicate_user_rejected(client):
    register(client)
    assert register(client, e="other@example.com").status_code == 400


def test_wrong_password_and_unknown_user_same_response(client):
    register(client)
    a, b = login(client, p="WrongPassw0rd"), login(client, u="nobody")
    assert a.status_code == b.status_code == 401


def test_lockout_after_repeated_failures(client):
    register(client)
    for _ in range(appmod.MAX_ATTEMPTS):
        login(client, p="WrongPassw0rd")
    assert login(client).status_code == 429  # even the right password is blocked


def test_csrf_required(client):
    assert client.post("/login", data={"username": "a", "password": "b"}).status_code == 400


def test_logout_ends_session(client):
    register(client); login(client)
    client.post("/logout", data={"_csrf": token(client, "/dashboard")})
    assert client.get("/dashboard").status_code == 302


def test_rbac(client):
    register(client)                                   # first user -> admin
    client.post("/logout", data={"_csrf": token(client)})
    register(client, "bob", "bob@example.com")         # second -> user
    login(client, "bob")
    assert client.get("/dashboard").status_code == 200
    assert client.get("/admin").status_code == 403
    client.post("/logout", data={"_csrf": token(client, "/dashboard")})
    login(client, "alice")
    assert client.get("/admin").status_code == 200


def test_open_redirect_blocked(client):
    register(client)
    r = client.post("/login?next=//evil.com", data={
        "_csrf": token(client), "username": "alice", "password": "Str0ngPassw0rd"})
    assert r.headers["Location"].endswith("/dashboard")
