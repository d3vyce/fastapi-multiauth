from fastapi import FastAPI, Request, Security
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from fastapi_multiauth import APIKeyCookieAuth
from fastapi_multiauth.oauth import (
    OAuthError,
    oauth_build_authorization_redirect,
    oauth_decode_state,
    oauth_exchange_code,
    oauth_generate_nonce,
    oauth_generate_pkce_pair,
    oauth_generate_state_token,
    oauth_resolve_provider_urls,
    oauth_validate_id_token,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration"
CLIENT_ID = "my-app"
CLIENT_SECRET = "my-app-secret"
REDIRECT_URI = "https://app.example.com/oauth/callback"
USERS: dict[tuple[str, str], str] = {}


async def validate_session(user_id: str) -> str:
    return user_id


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="__Host-oauth-flow",
    max_age=600,
    https_only=True,
)


# --8<-- [start:login]
@app.get("/oauth/login")
async def oauth_login(request: Request, next: str = "/"):
    endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)
    verifier, challenge = oauth_generate_pkce_pair()
    flow = {
        "state": oauth_generate_state_token(),
        "nonce": oauth_generate_nonce(),
        "verifier": verifier,
    }
    request.session["oauth"] = flow
    return oauth_build_authorization_redirect(
        endpoints.authorization_endpoint,
        client_id=CLIENT_ID,
        scopes="openid email profile",
        redirect_uri=REDIRECT_URI,
        destination=next,
        state_token=flow["state"],
        code_challenge=challenge,
        nonce=flow["nonce"],
    )


# --8<-- [end:login]


# --8<-- [start:callback]
@app.get("/oauth/callback")
async def oauth_callback(request: Request, code: str, state: str | None = None):
    endpoints = await oauth_resolve_provider_urls(DISCOVERY_URL)
    flow = request.session.pop("oauth", {})
    try:
        destination = oauth_decode_state(
            state, expected_state_token=flow.get("state", ""), fallback="/"
        )
        token = await oauth_exchange_code(
            token_url=endpoints.token_endpoint,
            code=code,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            redirect_uri=REDIRECT_URI,
            code_verifier=flow.get("verifier"),
        )
        if endpoints.issuer is None or endpoints.jwks_uri is None:
            raise OAuthError("the provider does not support OpenID Connect")
        claims = await oauth_validate_id_token(
            token.get("id_token", ""),
            issuer=endpoints.issuer,
            jwks_uri=endpoints.jwks_uri,
            client_id=CLIENT_ID,
            nonce=flow.get("nonce", ""),
        )
    except OAuthError:
        return RedirectResponse("/login?error=oauth", status_code=303)

    key = (claims["iss"], claims["sub"])
    user_id = USERS.setdefault(key, str(len(USERS) + 1))
    response = RedirectResponse(destination, status_code=303)
    session.set_cookie(response, user_id)
    return response


# --8<-- [end:callback]


@app.get("/me")
async def me(user_id: str = Security(session)):
    return {"user_id": user_id}
