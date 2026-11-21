from app.extensions import db
from app.orm import User
from tests.conftest import register


def test_register_creates_user_hashes_password_and_logs_in(client):
    response = register(client, "Alice@Example.com", "correct-horse-battery")

    assert response.status_code == 201
    user = response.get_json()["user"]
    assert user["email"] == "alice@example.com"
    assert "password" not in user and "password_hash" not in user
    stored = db.session.execute(db.select(User)).scalar_one()
    assert stored.password_hash != "correct-horse-battery"
    assert stored.password_hash.startswith(("scrypt:", "pbkdf2:"))
    assert client.get("/api/v1/auth/me").status_code == 200


def test_register_rejects_invalid_input(client):
    response = register(client, "not-an-email", "short")

    assert response.status_code == 400
    errors = response.get_json()["error"]["errors"]
    assert set(errors) == {"email", "password"}


def test_register_rejects_non_json_body(client):
    response = client.post("/api/v1/auth/register", data="email=a@b.co")
    assert response.status_code == 400


def test_register_rejects_overlong_password(client):
    assert register(client, "a@b.co", "x" * 129).status_code == 400


def test_duplicate_email_rejected_case_insensitively(client, make_client):
    assert register(client, "bob@example.com").status_code == 201
    assert register(make_client(), "BOB@example.com").status_code == 409


def test_login_logout_cycle(client, make_client):
    register(make_client(), "carol@example.com", "correct-horse-battery")

    bad = client.post("/api/v1/auth/login", json={"email": "carol@example.com", "password": "wrong-password"})
    assert bad.status_code == 401

    ok = client.post("/api/v1/auth/login", json={"email": "carol@example.com", "password": "correct-horse-battery"})
    assert ok.status_code == 200
    assert client.get("/api/v1/auth/me").get_json()["user"]["email"] == "carol@example.com"

    assert client.post("/api/v1/auth/logout").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_unknown_user_gives_same_error_as_wrong_password(client, auth_client, make_client):
    other = make_client()
    unknown = other.post("/api/v1/auth/login", json={"email": "nobody@example.com", "password": "whatever-123"})
    wrong = other.post("/api/v1/auth/login", json={"email": "alice@example.com", "password": "whatever-123"})

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


def test_protected_api_routes_require_login(client):
    for method, path in [
        ("get", "/api/v1/auth/me"),
        ("get", "/api/v1/captures"),
        ("post", "/api/v1/captures"),
        ("get", "/api/v1/captures/00000000-0000-0000-0000-000000000000"),
        ("delete", "/api/v1/captures/00000000-0000-0000-0000-000000000000"),
        ("post", "/api/v1/captures/00000000-0000-0000-0000-000000000000/analyze"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code == 401, path
        assert response.get_json()["error"]["code"] == 401


def test_csrf_enforced_when_enabled(app, make_client):
    app.config["WTF_CSRF_ENABLED"] = True
    client = make_client()
    payload = {"email": "dave@example.com", "password": "correct-horse-battery"}

    assert client.post("/api/v1/auth/register", json=payload).status_code == 400

    token = client.get("/api/v1/auth/csrf").get_json()["csrf_token"]
    ok = client.post("/api/v1/auth/register", json=payload, headers={"X-CSRFToken": token})
    assert ok.status_code == 201
