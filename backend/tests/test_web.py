"""Serving the Vue single-page app, and the session/CSRF contract it relies on."""

import io
import uuid

import pytest

from app.web.spa import CONTENT_SECURITY_POLICY
from tests.conftest import register, upload

INDEX = "<!doctype html><title>NetScope</title><div id=app></div>"
ROUTES = ["/", "/login", "/register", "/dashboard", "/captures", "/compare", f"/captures/{uuid.uuid4()}/packets"]


@pytest.fixture
def dist(app, tmp_path):
    """A stand-in for the Vite build output, so these tests do not need Node."""
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX)
    (root / "assets" / "app-1a2b3c.js").write_text("console.log('app')")
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>")
    (tmp_path / "secret.txt").write_text("not for the web")
    app.config["FRONTEND_DIST_DIR"] = str(root)
    return root


@pytest.mark.parametrize("path", ROUTES)
def test_client_side_routes_receive_the_app_shell(client, dist, path):
    response = client.get(path)
    assert response.status_code == 200
    assert response.mimetype == "text/html" and INDEX in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-cache"


def test_shell_is_public_and_carries_no_user_data(auth_client, make_client, dist, pcap_bytes):
    cid = upload(auth_client, pcap_bytes, "private-name.pcap").get_json()["capture"]["id"]
    anonymous = make_client()
    owner_page = auth_client.get(f"/captures/{cid}").get_data(as_text=True)
    anon_page = anonymous.get(f"/captures/{cid}").get_data(as_text=True)
    assert owner_page == anon_page == INDEX  # access control lives in the API, not the shell
    assert "private-name" not in anon_page
    # ...and the API is what refuses the stranger
    assert anonymous.get(f"/api/v1/captures/{cid}").status_code == 401


def test_shell_sets_a_strict_content_security_policy(client, dist):
    headers = client.get("/dashboard").headers
    assert headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY and "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
    assert "unsafe-eval" not in CONTENT_SECURITY_POLICY
    assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"


def test_fingerprinted_assets_are_cached_and_real_files_served(client, dist):
    asset = client.get("/assets/app-1a2b3c.js")
    assert asset.status_code == 200 and "immutable" in asset.headers["Cache-Control"]
    assert client.get("/favicon.svg").status_code == 200


@pytest.mark.parametrize("path", [
    "/assets/missing.js",          # a missing asset must never become HTML
    "/something.png",
    "/assets/..%2f..%2fsecret.txt",  # path traversal
    "/..%2fsecret.txt",
    "/assets/%2e%2e/%2e%2e/secret.txt",
])
def test_missing_files_and_traversal_are_404(client, dist, path):
    response = client.get(path)
    assert response.status_code == 404
    assert b"not for the web" not in response.data and INDEX not in response.get_data(as_text=True)


def test_unknown_api_paths_are_json_404_not_the_shell(client, dist):
    for path in ("/api", "/api/v1", "/api/v1/nope", "/api/v2/anything"):
        response = client.get(path)
        assert response.status_code == 404, path
        assert INDEX not in response.get_data(as_text=True)
    body = client.get("/api/v1/nope").get_json()
    assert body["error"]["code"] == 404


def test_missing_build_gives_a_helpful_503(client, app, tmp_path):
    app.config["FRONTEND_DIST_DIR"] = str(tmp_path / "no-such-build")
    response = client.get("/dashboard")
    assert response.status_code == 503 and b"npm --prefix frontend run build" in response.data


def test_old_server_rendered_form_endpoints_are_gone(client, dist):
    for path in ("/login", "/register", "/logout"):
        assert client.post(path, data={"email": "a@b.co", "password": "x"}).status_code == 405


def test_protected_api_answers_401_json_never_a_redirect(client):
    for path in ("/api/v1/dashboard", "/api/v1/captures", "/api/v1/auth/me", "/api/v1/compare"):
        response = client.get(path)
        assert response.status_code == 401 and response.is_json, path
        assert response.get_json()["error"]["code"] == 401


# ---------------------------------------------------------------- the session + CSRF contract
# Everything below is exactly what the Vue client does, with CSRF protection switched ON.


@pytest.fixture
def csrf_app(app):
    app.config["WTF_CSRF_ENABLED"] = True
    return app


def _token(client):
    # The test fixture keeps a single app context open, so Flask-WTF's per-request cache on `g`
    # would leak between requests; a real request always starts with a clean `g`.
    from flask import g

    g.pop("csrf_token", None)
    return client.get("/api/v1/auth/csrf").get_json()["csrf_token"]


def test_register_login_logout_round_trip_with_csrf(csrf_app, make_client):
    client = make_client()
    creds = {"email": "vue@example.com", "password": "correct-horse-battery"}

    missing = client.post("/api/v1/auth/register", json=creds)  # no token
    assert missing.status_code == 400 and "CSRF" in missing.get_json()["error"]["message"]

    registered = client.post("/api/v1/auth/register", json=creds, headers={"X-CSRFToken": _token(client)})
    assert registered.status_code == 201
    assert client.get("/api/v1/auth/me").get_json()["user"]["email"] == "vue@example.com"

    # Registration replaced the session, so the old token is no longer valid for it...
    stale = client.post("/api/v1/auth/logout", headers={"X-CSRFToken": "not-the-token"})
    assert stale.status_code == 400
    # ...and a fresh one works.
    assert client.post("/api/v1/auth/logout", headers={"X-CSRFToken": _token(client)}).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401  # logout invalidated the session

    bad = client.post("/api/v1/auth/login", json={**creds, "password": "wrong-password"},
                      headers={"X-CSRFToken": _token(client)})
    assert bad.status_code == 401 and bad.get_json()["error"]["message"] == "Invalid email or password."
    good = client.post("/api/v1/auth/login", json=creds, headers={"X-CSRFToken": _token(client)})
    assert good.status_code == 200 and good.get_json()["user"]["email"] == "vue@example.com"


def test_registration_errors_expose_per_field_messages(csrf_app, make_client):
    client = make_client()
    response = client.post(
        "/api/v1/auth/register", json={"email": "nope", "password": "x"}, headers={"X-CSRFToken": _token(client)}
    )
    errors = response.get_json()["error"]["errors"]
    assert response.status_code == 400 and set(errors) == {"email", "password"}
    again = make_client()
    ok = {"email": "dup@example.com", "password": "correct-horse-battery"}
    assert again.post("/api/v1/auth/register", json=ok, headers={"X-CSRFToken": _token(again)}).status_code == 201
    other = make_client()
    assert other.post("/api/v1/auth/register", json=ok, headers={"X-CSRFToken": _token(other)}).status_code == 409


def test_upload_and_delete_require_the_csrf_header(csrf_app, make_client, pcap_bytes):
    client = make_client()
    register_headers = {"X-CSRFToken": _token(client)}
    client.post("/api/v1/auth/register", json={"email": "up@example.com", "password": "correct-horse-battery"},
                headers=register_headers)

    def post_file(headers):
        return client.post("/api/v1/captures", data={"file": (io.BytesIO(pcap_bytes), "a.pcap")},
                           content_type="multipart/form-data", headers=headers)

    assert post_file({}).status_code == 400
    created = post_file({"X-CSRFToken": _token(client)})
    assert created.status_code == 201
    cid = created.get_json()["capture"]["id"]
    assert client.delete(f"/api/v1/captures/{cid}").status_code == 400
    assert client.delete(f"/api/v1/captures/{cid}", headers={"X-CSRFToken": _token(client)}).status_code == 204


def test_session_cookie_is_not_readable_by_scripts(client):
    register(client)
    assert client.get_cookie("session").http_only is True
