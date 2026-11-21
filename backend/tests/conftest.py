import io

import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db


@pytest.fixture
def app(tmp_path):
    class Cfg(TestingConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        UPLOAD_FOLDER = str(tmp_path / "uploads")

    app = create_app(Cfg)

    @app.before_request
    def _isolate_login_cache():
        # The fixture keeps one app context open so tests can use db.session, and
        # Flask reuses it for every test-client request. That would share g (where
        # Flask-Login caches the current user) between clients; production requests
        # each get a fresh context, so reset it per request here.
        from flask import g

        g.pop("_login_user", None)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_client(app):
    """Independent clients, each with its own cookie jar (i.e. its own user)."""
    return app.test_client


def register(client, email="alice@example.com", password="correct-horse-battery"):
    return client.post("/api/v1/auth/register", json={"email": email, "password": password})


@pytest.fixture
def auth_client(client):
    assert register(client).status_code == 201
    return client


@pytest.fixture
def pcap_bytes(tmp_path):
    """A small real capture (3 packets) written by Scapy."""
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

    path = tmp_path / "fixture.pcap"
    wrpcap(
        str(path),
        [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"),
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5353) / DNS(qd=DNSQR()),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / ICMP(),
        ],
    )
    return path.read_bytes()


def upload(client, data: bytes, filename="trace.pcap", **form):
    return client.post(
        "/api/v1/captures",
        data={"file": (io.BytesIO(data), filename), **form},
        content_type="multipart/form-data",
    )
