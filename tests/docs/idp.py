"""A fake identity provider for the documentation examples."""

import json
import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://idp.example.com"
REALM = f"{ISSUER}/realms/main"
REALM_JWKS_URL = f"{REALM}/protocol/openid-connect/certs"
OIDC_JWKS_URL = f"{ISSUER}/jwks"
TOKEN_URL = f"{ISSUER}/token"
INTROSPECTION_URL = f"{REALM}/protocol/openid-connect/token/introspect"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


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
