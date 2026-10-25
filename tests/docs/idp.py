"""A fake identity provider for the documentation examples."""

import hashlib
import json
import secrets
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from fastapi_multiauth.sources.dpop import _jwk_thumbprint
from fastapi_multiauth.utils import b64url_encode

ISSUER = "https://idp.example.com"
REALM = f"{ISSUER}/realms/main"
REALM_JWKS_URL = f"{REALM}/protocol/openid-connect/certs"
OIDC_JWKS_URL = f"{ISSUER}/jwks"
TOKEN_URL = f"{ISSUER}/token"
INTROSPECTION_URL = f"{REALM}/protocol/openid-connect/token/introspect"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CLIENT_KEY = ec.generate_private_key(ec.SECP256R1())


def client_jwk() -> dict[str, Any]:
    return json.loads(ECAlgorithm.to_jwk(_CLIENT_KEY.public_key()))


def client_thumbprint() -> str | None:
    return _jwk_thumbprint(client_jwk())


def dpop_proof(method: str, url: str, token: str) -> str:
    claims = {
        "jti": secrets.token_urlsafe(),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "ath": b64url_encode(hashlib.sha256(token.encode()).digest()),
    }
    headers = {"typ": "dpop+jwt", "jwk": client_jwk()}
    return jwt.encode(claims, _CLIENT_KEY, algorithm="ES256", headers=headers)


def jwks() -> dict[str, Any]:
    entry = json.loads(RSAAlgorithm.to_jwk(_KEY.public_key()))
    entry.update(kid="key-1", alg="RS256", use="sig")
    return {"keys": [entry]}


def sign(**claims: Any) -> str:
    now = int(time.time())
    payload = {"iat": now, "exp": now + 300, **claims}
    return jwt.encode(payload, _KEY, algorithm="RS256", headers={"kid": "key-1"})


def discovery() -> dict[str, Any]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": TOKEN_URL,
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": OIDC_JWKS_URL,
    }
