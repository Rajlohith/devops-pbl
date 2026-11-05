import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to NetScope"}


def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_packet_filter_endpoint_with_protocol(client):
    response = client.post("/packets/filter", json={"protocol": "TCP"})

    assert response.status_code == 200
    assert response.json() == {
        "message": "Filter applied successfully",
        "filters": {"protocol": "TCP", "source_ip": None},
        "packets": [
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
            },
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.30",
            },
        ],
    }


def test_packet_filter_endpoint_with_protocol_and_source_ip(client):
    response = client.post(
        "/packets/filter",
        json={"protocol": "TCP", "source_ip": "192.168.1.10"},
    )

    assert response.status_code == 200
    assert len(response.json()["packets"]) == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"protocol": 123},
        {"source_ip": ["192.168.1.10"]},
    ],
)
def test_packet_filter_endpoint_rejects_invalid_payload(client, payload):
    response = client.post("/packets/filter", json=payload)

    assert response.status_code == 422
