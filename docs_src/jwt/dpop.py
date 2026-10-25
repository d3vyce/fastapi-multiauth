import time

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPDPoPAuth, JWTValidator

ISSUER = "https://idp.example.com/realms/main"
SEEN_PROOFS: dict[str, float] = {}  # use Redis SET NX across processes


def remember_proof(jti: str, expires_at: float) -> bool:
    now = time.time()
    for old in [j for j, until in SEEN_PROOFS.items() if until < now]:
        del SEEN_PROOFS[old]
    if jti in SEEN_PROOFS:
        return False
    SEEN_PROOFS[jti] = expires_at
    return True


dpop = HTTPDPoPAuth(
    validator=JWTValidator(
        jwks_url=f"{ISSUER}/protocol/openid-connect/certs",
        audience="my-api",
        issuer=ISSUER,
    ),
    replay_check=remember_proof,
)

app = FastAPI()


@app.get("/me")
async def me(claims: dict = Security(dpop)):
    return {"sub": claims["sub"]}
