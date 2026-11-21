import pytest

from app import create_app
from app.config import get_config


def test_health_endpoint(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy"}


def test_unknown_api_path_returns_json_error(client):
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    body = response.get_json()
    assert body["error"]["code"] == 404


def test_wrong_method_returns_json_405(client):
    response = client.post("/api/v1/health")

    assert response.status_code == 405
    assert response.get_json()["error"]["code"] == 405


def test_testing_config_applied(app):
    assert app.config["TESTING"] is True


def test_production_requires_secret_key(monkeypatch):
    monkeypatch.delenv("NETSCOPE_SECRET_KEY", raising=False)
    config = get_config("production")
    config.SECRET_KEY = None

    with pytest.raises(RuntimeError, match="NETSCOPE_SECRET_KEY"):
        create_app(config)


def test_unknown_environment_rejected():
    with pytest.raises(RuntimeError, match="Unknown NETSCOPE_ENV"):
        get_config("staging")
