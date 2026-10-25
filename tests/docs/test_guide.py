import base64
import importlib
import time
from pathlib import Path

import pytest
from fastapi import Response
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from . import idp

HTTPS = "https://testserver"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _client(module: str, **kwargs) -> TestClient:
    return TestClient(importlib.import_module(f"docs_src.{module}").app, **kwargs)


def test_quickstart():
    client = _client("quickstart", base_url=HTTPS)
    assert client.get("/me").status_code == 401
    assert (
        client.get("/me", headers=_bearer("user_alice-token")).json()["name"] == "alice"
    )
    assert client.get("/me", headers=_bearer("user_nope")).status_code == 401

    from docs_src.quickstart import session

    response = Response()
    session.set_cookie(response, "1")
    name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, value)
    assert client.get("/me").json()["name"] == "alice"


def test_readme_quickstart_matches_docs_src():
    readme = Path("README.md").read_text()
    code = readme.split("## Quick start\n\n```python\n", 1)[1].split("```", 1)[0]
    assert code == Path("docs_src/quickstart.py").read_text()


def test_validators_contract():
    client = _client("validators.contract")
    assert client.get("/me", headers=_bearer("alice-token")).status_code == 200
    assert client.get("/me", headers=_bearer("bob-token")).status_code == 403
    response = client.get("/me", headers=_bearer("nope"))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_validators_require():
    client = _client("validators.require")
    assert client.get("/me", headers=_bearer("bob-token")).status_code == 200
    assert client.get("/admin", headers=_bearer("bob-token")).status_code == 403
    assert client.get("/admin", headers=_bearer("alice-token")).status_code == 200


def test_validators_request():
    client = _client("validators.request")
    response = client.get("/me", headers=_bearer("alice-token"))
    assert response.json() == {"name": "alice", "token_id": 7}


def _adopt_cookie(client: TestClient, response: Response) -> None:
    name, cookie = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, cookie)


def _sign_in(client: TestClient, session, value: str) -> None:
    response = Response()
    session.set_cookie(response, value)
    _adopt_cookie(client, response)


def test_bearer_issue():
    from docs_src.bearer_tokens.issue import session

    client = _client("bearer_tokens.issue", base_url=HTTPS)
    assert client.post("/tokens").status_code == 401
    _sign_in(client, session, "alice")
    token = client.post("/tokens").json()["token"]
    assert token.startswith("user_")
    assert client.get("/me", headers=_bearer(token)).json() == {"owner": "alice"}
    client.cookies.clear()
    assert client.post("/tokens", headers=_bearer(token)).status_code == 401


def test_bearer_checksum():
    from docs_src.bearer_tokens.checksum import TOKEN_HASHES, user_tokens
    from fastapi_multiauth import hash_token

    token = user_tokens.generate_token()
    TOKEN_HASHES[hash_token(token)] = "alice"
    client = _client("bearer_tokens.checksum")
    assert client.get("/me", headers=_bearer(token)).json() == {"owner": "alice"}
    typo = token[:-1] + ("a" if token[-1] != "a" else "b")
    assert client.get("/me", headers=_bearer(typo)).status_code == 401


def test_cookie_login():
    client = _client("cookie_sessions.login", base_url=HTTPS)
    bad = {"username": "alice", "password": "nope"}
    assert client.post("/login", json=bad).status_code == 401
    good = {"username": "alice", "password": "wonderland"}
    assert client.post("/login", json=good).status_code == 200
    assert client.get("/me").json() == {"id": "1", "name": "alice"}
    client.post("/logout")
    assert client.get("/me").status_code == 401
    unknown = {"username": "mallory", "password": ""}
    assert client.post("/login", json=unknown).status_code == 401


def test_cookie_revocable():
    from docs_src.cookie_sessions.revocable import start_session

    client = _client("cookie_sessions.revocable", base_url=HTTPS)
    response = Response()
    assert start_session(response, "1")
    name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, value)
    cookies = dict(client.cookies)
    assert client.get("/me").status_code == 200
    client.post("/logout")
    client.cookies.update(cookies)
    assert client.get("/me").status_code == 401


def test_api_key_header():
    client = _client("api_keys.header")
    ok = client.get("/reports", headers={"X-API-Key": "key-for-reporting"})
    assert ok.json() == {"client": "reporting-service"}
    assert client.get("/reports").status_code == 401


def test_basic():
    client = _client("api_keys.basic")
    response = client.get("/metrics")
    assert response.headers["www-authenticate"] == 'Basic realm="metrics"'
    creds = base64.b64encode(b"prometheus:scraper-password").decode()
    response = client.get("/metrics", headers={"Authorization": f"Basic {creds}"})
    assert response.json() == {"scraped_by": "prometheus"}
    accented = base64.b64encode("prometheus:pässword".encode()).decode()
    response = client.get("/metrics", headers={"Authorization": f"Basic {accented}"})
    assert response.status_code == 401


def test_jwt_jwks(provider):
    client = _client("jwt.jwks")
    token = idp.sign(iss=idp.REALM, aud="my-api", sub="42")
    assert client.get("/me", headers=_bearer(token)).json() == {"sub": "42"}
    other = idp.sign(iss=idp.REALM, aud="another-app", sub="42")
    assert client.get("/me", headers=_bearer(other)).status_code == 401


def test_jwt_oauth2_source(provider):
    client = _client("jwt.oauth2_source")
    scheme = client.get("/openapi.json").json()["components"]["securitySchemes"]
    flow = next(iter(scheme.values()))["flows"]["authorizationCode"]
    assert flow["scopes"] == {"invoices:read": "Read invoices"}
    granted = idp.sign(iss=idp.REALM, aud="my-api", sub="42", scope="invoices:read")
    assert client.get("/invoices", headers=_bearer(granted)).status_code == 200
    denied = idp.sign(iss=idp.REALM, aud="my-api", sub="42", scope="profile")
    assert client.get("/invoices", headers=_bearer(denied)).status_code == 403


def test_multiauth():
    client = _client("multiauth.multiauth", base_url=HTTPS)
    ok = client.get("/me", headers=_bearer("user_alice-token"))
    assert ok.json() == {"username": "alice"}
    response = client.get("/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_optional():
    client = _client("multiauth.optional")
    assert client.get("/articles/a").json()["show_drafts"] is False
    editor = client.get("/articles/a", headers=_bearer("editor-token"))
    assert editor.json()["show_drafts"] is True
    assert client.get("/articles/a", headers=_bearer("bad")).status_code == 401


def test_scopes():
    client = _client("scopes.scopes")
    assert client.get("/posts", headers=_bearer("reader-token")).status_code == 200
    assert client.post("/posts", headers=_bearer("reader-token")).status_code == 403
    assert client.post("/posts", headers=_bearer("writer-token")).status_code == 200


def test_step_up_fresh(monkeypatch):
    client = _client("step_up.fresh", base_url=HTTPS)
    from docs_src.step_up.fresh import session

    response = Response()
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 3600)
    session.set_cookie(response, "alice:0")
    monkeypatch.setattr(time, "time", real_time)
    name, value = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)
    client.cookies.set(name, value)

    body = {"password": "new-password"}
    stale = client.post("/me/password", json=body)
    assert stale.status_code == 401
    assert stale.json()["detail"] == "Insufficient user authentication"
    assert (
        client.post("/me/re-auth", json={"password": "wonderland"}).status_code == 200
    )
    other_device = _client("step_up.fresh", base_url=HTTPS)
    other_device.cookies.update(client.cookies)
    assert client.post("/me/password", json=body).status_code == 200
    assert other_device.post("/me/re-auth", json=body).status_code == 401
    assert client.post("/me/re-auth", json=body).status_code == 200


def test_step_up_acr(provider):
    client = _client("step_up.stepped_up")
    weak = idp.sign(iss=idp.REALM, aud="my-api", sub="42", acr="urn:password")
    response = client.post("/payouts", headers=_bearer(weak))
    assert response.status_code == 401
    assert 'acr_values="urn:mfa"' in response.headers["www-authenticate"]
    strong = idp.sign(iss=idp.REALM, aud="my-api", sub="42", acr="urn:mfa")
    assert client.post("/payouts", headers=_bearer(strong)).status_code == 200


def test_step_up_second_factor():
    from docs_src.step_up.second_factor import sign_in

    client = _client("step_up.second_factor", base_url=HTTPS)
    response = Response()
    sign_in(response, "alice")
    _adopt_cookie(client, response)

    weak = client.post("/payouts")
    assert weak.status_code == 401
    assert weak.json()["detail"] == "Insufficient user authentication"
    assert client.post("/login/otp", json={"code": "000000"}).status_code == 401
    assert client.post("/login/otp", json={"code": "123456"}).status_code == 200
    assert client.post("/payouts").json() == {"approved_by": "alice"}


def test_websocket():
    from docs_src.websockets.ws import app, session

    response = Response()
    session.set_cookie(response, "alice")
    cookie = response.headers["set-cookie"].split(";", 1)[0]
    client = TestClient(app)
    same_origin = {"cookie": cookie, "origin": "https://app.example.com"}
    with client.websocket_connect("/ws", headers=same_origin) as ws:
        assert ws.receive_json() == {"hello": "alice"}
    foreign = {"cookie": cookie, "origin": "https://evil.example"}
    with (
        pytest.raises(WebSocketDisconnect),
        client.websocket_connect("/ws", headers=foreign),
    ):
        pass
    with pytest.raises(WebSocketDisconnect), client.websocket_connect("/ws"):
        pass


def test_custom_source():
    client = _client("custom_sources.client_cert", client=("10.0.0.1", 50000))
    ok = client.get("/invoices", headers={"X-Client-Cert": "ab:cd:ef"})
    assert ok.json() == {"client": "billing-service"}
    assert client.get("/invoices").status_code == 401
    direct = _client("custom_sources.client_cert")
    spoofed = direct.get("/invoices", headers={"X-Client-Cert": "ab:cd:ef"})
    assert spoofed.status_code == 401
    schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
    assert "ClientCert" in schemes


def test_auditing(capsys):
    from docs_src.auditing.surface import print_surface
    from docs_src.quickstart import app

    print_surface(app)
    assert "/me" in capsys.readouterr().out


def test_testing_page():
    from docs_src.testing import test_main

    test_main.test_admin_with_override()
    test_main.test_admin_requires_a_token()
    test_main.test_login_then_me()


def test_every_example_is_shown_in_the_docs():
    pages = "".join(p.read_text() for p in Path("docs").rglob("*.md"))
    examples = [
        p.as_posix() for p in Path("docs_src").rglob("*.py") if p.name != "__init__.py"
    ]
    assert "--8 <" not in pages, "a snippet include line was reformatted"
    unused = [e for e in examples if f'--8<-- "{e}' not in pages]
    assert not unused, unused
