from typing import Annotated

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, JWTValidator

ISSUER = "https://idp.example.com/realms/main"

bearer = HTTPBearerAuth(
    JWTValidator(
        jwks_url=f"{ISSUER}/protocol/openid-connect/certs",
        audience="my-api",
        issuer=ISSUER,
    )
)
StrongClaims = Annotated[
    dict,
    Security(bearer.stepped_up(["urn:mfa"], acr=lambda claims: claims.get("acr"))),
]

app = FastAPI()


@app.post("/payouts")
async def payout(claims: StrongClaims):
    return {"approved_by": claims["sub"]}
