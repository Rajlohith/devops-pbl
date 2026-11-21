import re
import uuid

import pytest

from app.extensions import db
from app.orm import CaptureRecord
from tests.conftest import register, upload

PAGES = ["/dashboard", "/captures", "/compare"]


def test_root_redirects_by_auth_state(client):
    assert client.get("/").headers["Location"].endswith("/login")
    register(client)
    assert client.get("/").headers["Location"].endswith("/dashboard")


@pytest.mark.parametrize("path", PAGES)
def test_protected_pages_redirect_to_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert f"/login?next={path}" in response.headers["Location"]


def test_capture_page_redirects_to_login_when_anonymous(client):
    response = client.get(f"/captures/{uuid.uuid4()}")
    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_register_login_logout_pages(client):
    assert b"Create an account" in client.get("/register").data

    bad = client.post("/register", data={"email": "nope", "password": "x"})
    assert bad.status_code == 400 and b"valid email" in bad.data

    ok = client.post("/register", data={"email": "web@example.com", "password": "correct-horse-battery"})
    assert ok.status_code == 302 and ok.headers["Location"].endswith("/dashboard")
    assert b"web@example.com" in client.get("/dashboard").data

    client.post("/logout")
    assert client.get("/dashboard").status_code == 302

    wrong = client.post("/login", data={"email": "web@example.com", "password": "wrong-password"})
    assert wrong.status_code == 401 and b"Invalid email or password" in wrong.data
    good = client.post("/login", data={"email": "web@example.com", "password": "correct-horse-battery"})
    assert good.status_code == 302 and good.headers["Location"].endswith("/dashboard")


def test_login_returns_to_the_requested_page(client):
    register(client, "next@example.com")
    client.post("/logout")
    response = client.post(
        "/login?next=/compare", data={"email": "next@example.com", "password": "correct-horse-battery"}
    )
    assert response.headers["Location"].endswith("/compare")


def test_login_next_param_rejects_external_redirects(client):
    register(client, "next@example.com")
    client.post("/logout")
    for evil in ["https://evil.example/", "//evil.example", "/\\evil.example"]:
        response = client.post(
            f"/login?next={evil}",
            data={"email": "next@example.com", "password": "correct-horse-battery"},
        )
        assert response.headers["Location"].endswith("/dashboard"), evil
        client.post("/logout")


def test_web_forms_require_csrf_token(app, make_client):
    app.config["WTF_CSRF_ENABLED"] = True
    client = make_client()
    assert client.post("/login", data={"email": "a@b.co", "password": "x"}).status_code == 400

    page = client.get("/login").data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = client.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": token})
    assert response.status_code == 401  # got past CSRF; credentials simply wrong


@pytest.mark.parametrize("path, script", [
    ("/dashboard", "dashboard.js"), ("/captures", "captures.js"), ("/compare", "compare.js"),
])
def test_pages_load_their_scripts_and_a_csrf_token(client, path, script):
    register(client)
    html = client.get(path).data.decode()
    assert f"js/{script}" in html and "js/ns.js" in html and "vendor/chart.umd.js" in html
    assert re.search(r'<meta name="csrf-token" content="[^"]+">', html)
    assert "cdn." not in html  # no third-party runtime dependencies


def test_static_assets_are_served(client):
    for path in ("/static/css/app.css", "/static/js/ns.js", "/static/js/capture.js", "/static/vendor/chart.umd.js"):
        response = client.get(path)
        assert response.status_code == 200 and len(response.data) > 1000, path


def test_capture_page_shell_for_the_owner(auth_client, pcap_bytes):
    cid = upload(auth_client, pcap_bytes, "mine.pcap").get_json()["capture"]["id"]
    response = auth_client.get(f"/captures/{cid}")
    assert response.status_code == 200
    html = response.data.decode()
    assert f'data-capture-id="{cid}"' in html and "mine.pcap" in html and "js/capture.js" in html


def test_other_users_capture_page_is_404(auth_client, make_client, pcap_bytes):
    cid = upload(auth_client, pcap_bytes, "mine.pcap").get_json()["capture"]["id"]
    other = make_client()
    register(other, "other@example.com")
    assert other.get(f"/captures/{cid}").status_code == 404
    assert other.get(f"/captures/{uuid.uuid4()}").status_code == 404
    assert auth_client.get(f"/captures/{cid}").status_code == 200


def test_filename_is_escaped_in_the_page_title(auth_client, pcap_bytes):
    cid = upload(auth_client, pcap_bytes, "mine.pcap").get_json()["capture"]["id"]
    record = db.session.get(CaptureRecord, uuid.UUID(cid))
    record.original_filename = "<script>alert(1)</script>.pcap"  # as if a hostile name had been stored
    db.session.commit()
    html = auth_client.get(f"/captures/{cid}").data.decode()
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html
