from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from . import idp

HTTPS = "https://testserver"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_sessions_and_tokens():
    from docs_src.recipes.sessions_and_tokens import app

    client = TestClient(app, base_url=HTTPS)
    token = client.get("/me", headers=_bearer("user_alice-script-token"))
    assert token.json() == {"name": "alice"}
    assert client.get("/me").status_code == 401
    client.post("/login", json={"username": "alice", "password": "wonderland"})
    assert client.get("/me").json() == {"name": "alice"}


def test_personal_access_tokens():
    from docs_src.recipes.personal_access_tokens import app, session

    client = TestClient(app, base_url=HTTPS)
    from fastapi import Response

    response = Response()
    session.set_cookie(response, "alice")
    name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, value)

    created = client.post("/tokens", params={"name": "ci"}).json()
    assert client.get("/whoami", headers=_bearer(created["token"])).json() == {
        "owner": "alice"
    }
    assert client.get("/tokens").json() == [{"id": created["id"], "name": "ci"}]
    client.delete(f"/tokens/{created['id']}")
    assert client.get("/whoami", headers=_bearer(created["token"])).status_code == 401


def test_role_gated_routes():
    from fastapi import Response

    from docs_src.recipes.role_gated_routes import app, session

    def login(username: str) -> TestClient:
        client = TestClient(app, base_url=HTTPS)
        response = Response()
        session.set_cookie(response, username)
        name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
        client.cookies.set(name, value)
        return client

    assert login("bob").get("/admin/stats").status_code == 403
    assert login("alice").get("/admin/stats").status_code == 200


def test_sign_out_everywhere():
    from docs_src.recipes.sign_out_everywhere import app

    laptop = TestClient(app, base_url=HTTPS, headers={"user-agent": "laptop"})
    phone = TestClient(app, base_url=HTTPS, headers={"user-agent": "phone"})
    laptop.post("/login", params={"username": "alice"})
    phone.post("/login", params={"username": "alice"})

    sessions = laptop.get("/sessions").json()
    assert {"device": "laptop", "current": True} in sessions
    assert {"device": "phone", "current": False} in sessions

    laptop.post("/sessions/revoke-others")
    assert phone.get("/sessions").status_code == 401
    assert laptop.get("/sessions").status_code == 200
    laptop.post("/logout")
    assert laptop.get("/sessions").status_code == 401


def test_oidc_sign_in(provider):
    from docs_src.recipes.oidc_sign_in import CLIENT_ID, app

    client = TestClient(app, base_url="https://app.example.com", follow_redirects=False)
    login = client.get("/oauth/login", params={"next": "/dashboard"})
    query = parse_qs(urlsplit(login.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"]

    id_token = idp.sign(
        iss=idp.ISSUER, aud=CLIENT_ID, sub="42", nonce=query["nonce"][0]
    )
    provider.post(idp.TOKEN_URL).respond(
        json={"access_token": "at", "token_type": "Bearer", "id_token": id_token}
    )
    callback = client.get(
        "/oauth/callback", params={"code": "abc", "state": query["state"][0]}
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/dashboard"
    assert client.get("/me").json() == {"user_id": "1"}


def test_oidc_sign_in_refuses_forged_state(provider):
    from docs_src.recipes.oidc_sign_in import app

    client = TestClient(app, base_url="https://app.example.com", follow_redirects=False)
    client.get("/oauth/login")
    forged = client.get("/oauth/callback", params={"code": "abc", "state": "forged"})
    assert forged.headers["location"] == "/login?error=oauth"


def test_websocket_tickets():
    from fastapi import Response

    from docs_src.recipes.websocket_tickets import app, session

    client = TestClient(app, base_url=HTTPS)
    response = Response()
    session.set_cookie(response, "alice")
    name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, value)
    ticket = client.post("/ws-ticket").json()["ticket"]

    with client.websocket_connect(f"/ws?ticket={ticket}") as ws:
        assert ws.receive_json() == {"hello": "alice"}
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect(f"/ws?ticket={ticket}"),
    ):
        pass


def test_audit_routes():
    from docs_src.recipes.test_audit_routes import test_no_unguarded_routes

    test_no_unguarded_routes()
