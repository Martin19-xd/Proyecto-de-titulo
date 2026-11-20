import pytest
from fastapi.testclient import TestClient
from app import app


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "missing.joblib"))
    # Nueva pila para que cada prueba tenga su limitador independiente.
    app.middleware_stack = None
    with TestClient(app) as c:
        yield c


def test_analyze_no_model(client):
    r = client.post("/api/analyze", json={"url": "https://www.bancoestado.cl"})
    assert r.status_code == 200
    assert r.json()["p_phishing"] is None


def test_validation(client):
    assert client.post("/api/analyze", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/analyze", json={"url": {"$ne": ""}}).status_code == 422
    assert client.post("/api/analyze", json={"url": "https://a.test", "extra": 1}).status_code == 422


def test_body_limit(client):
    assert client.post("/api/analyze", content=b"x" * 17000,
                       headers={"content-type": "application/json"}).status_code == 413


def test_rate_limit(client):
    for _ in range(30):
        assert client.post("/api/analyze", json={"url": "https://example.com"}).status_code == 200
    assert client.post("/api/analyze", json={"url": "https://example.com"}).status_code == 429


def test_static_files(client):
    for path in ("/", "/app.js", "/style.css"):
        r = client.get(path)
        assert r.status_code == 200
        assert "Content-Security-Policy" in r.headers
    assert client.get("/health").json()["model_loaded"] is False

