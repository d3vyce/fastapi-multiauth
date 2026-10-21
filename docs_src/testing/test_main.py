from fastapi.testclient import TestClient

from .main import admin, app


def test_admin_with_override():
    app.dependency_overrides[admin] = lambda: "alice"
    try:
        response = TestClient(app).get("/admin")
    finally:
        app.dependency_overrides.clear()
    assert response.json() == {"admin": "alice"}


def test_admin_requires_a_token():
    response = TestClient(app).get("/admin")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


def test_login_then_me():
    client = TestClient(app, base_url="https://testserver")
    client.post("/login")
    assert client.get("/me").json() == {"username": "alice"}
