import io
import re

from tests.conftest import register


def _csrf_enabled(app):
    app.config["WTF_CSRF_ENABLED"] = True


def test_root_redirects_by_auth_state(client):
    assert client.get("/").headers["Location"].endswith("/login")
    register(client)
    assert client.get("/").headers["Location"].endswith("/captures")


def test_protected_page_redirects_to_login(client):
    response = client.get("/captures")
    assert response.status_code == 302
    assert "/login?next=/captures" in response.headers["Location"]


def test_register_login_logout_pages(client):
    assert b"Create an account" in client.get("/register").data

    bad = client.post("/register", data={"email": "nope", "password": "x"})
    assert bad.status_code == 400 and b"valid email" in bad.data

    ok = client.post("/register", data={"email": "web@example.com", "password": "correct-horse-battery"})
    assert ok.status_code == 302
    assert b"web@example.com" in client.get("/captures").data

    client.post("/logout")
    assert client.get("/captures").status_code == 302

    wrong = client.post("/login", data={"email": "web@example.com", "password": "wrong-password"})
    assert wrong.status_code == 401 and b"Invalid email or password" in wrong.data
    good = client.post("/login", data={"email": "web@example.com", "password": "correct-horse-battery"})
    assert good.status_code == 302


def test_login_next_param_rejects_external_redirects(client):
    register(client, "next@example.com")
    client.post("/logout")
    for evil in ["https://evil.example/", "//evil.example", "/\\evil.example"]:
        response = client.post(
            f"/login?next={evil}",
            data={"email": "next@example.com", "password": "correct-horse-battery"},
        )
        assert response.headers["Location"].endswith("/captures"), evil
        client.post("/logout")


def test_web_upload_detail_analyze_delete_flow(client, pcap_bytes):
    register(client)
    empty = client.get("/captures")
    assert b"No captures yet" in empty.data

    response = client.post(
        "/captures/upload",
        data={"file": (io.BytesIO(pcap_bytes), "web.pcap"), "analyze": "on"},
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    detail_url = response.headers["Location"]

    detail = client.get(detail_url)
    assert b"web.pcap" in detail.data and b"completed" in detail.data
    assert b"web.pcap" in client.get("/captures").data

    delete_url = re.sub(r"/captures/([0-9a-f-]+)$", r"/captures/\1/delete", detail_url)
    assert client.post(delete_url).status_code == 302
    assert client.get(detail_url).status_code == 404


def test_web_upload_rejection_is_shown_to_user(client):
    register(client)
    client.post(
        "/captures/upload",
        data={"file": (io.BytesIO(b"junk" * 20), "bad.pcap")},
        content_type="multipart/form-data",
    )
    assert b"Not a valid PCAP" in client.get("/captures").data


def test_web_forms_require_csrf_token(app, make_client):
    _csrf_enabled(app)
    client = make_client()
    assert client.post("/login", data={"email": "a@b.co", "password": "x"}).status_code == 400

    page = client.get("/login").data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = client.post("/login", data={"email": "a@b.co", "password": "x", "csrf_token": token})
    assert response.status_code == 401  # got past CSRF; credentials simply wrong


def test_other_users_capture_page_is_404(client, make_client, pcap_bytes):
    register(client)
    detail_url = client.post(
        "/captures/upload",
        data={"file": (io.BytesIO(pcap_bytes), "mine.pcap")},
        content_type="multipart/form-data",
    ).headers["Location"]

    other = make_client()
    register(other, "other@example.com")
    assert other.get(detail_url).status_code == 404
    assert other.post(detail_url + "/delete").status_code == 404
    assert client.get(detail_url).status_code == 200


def test_filenames_are_escaped_in_html(client, pcap_bytes):
    register(client)
    client.post(
        "/captures/upload",
        data={"file": (io.BytesIO(pcap_bytes), "<script>alert(1)</script>.pcap")},
        content_type="multipart/form-data",
    )
    assert b"<script>alert(1)" not in client.get("/captures").data
