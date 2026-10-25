import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import FastAPI, HTTPException, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import (
    APIKeyCookieAuth,
    UnauthorizedError,
    hash_token,
    totp_generate_secret,
    totp_provisioning_uri,
    totp_verify,
    verify_token_hash,
)
from fastapi_multiauth import AuthenticationMethodReference as AMR

SECRET_KEY = os.environ["SECRET_KEY"]
MAX_FAILURES = 5
LOCKOUT_SECONDS = 900


def hash_password(password: str, salt: bytes | None = None) -> bytes:
    salt = salt or secrets.token_bytes(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def check_password(password: str, stored: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, stored[:16]), stored)


@dataclass
class Account:
    password: bytes
    totp_secret: str | None = None
    pending_secret: str | None = None
    last_step: int | None = None
    recovery_hashes: list[str] = field(default_factory=list)
    failures: int = 0
    locked_until: float = 0.0


ACCOUNTS = {"alice": Account(password=hash_password("wonderland"))}
NO_PASSWORD = hash_password("")


class Credentials(BaseModel):
    username: str
    password: str


class Code(BaseModel):
    code: str


async def validate_user(username: str) -> str:
    if username not in ACCOUNTS:
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_user, secret_key=SECRET_KEY
)
mfa_pending = APIKeyCookieAuth(
    name="__Host-mfa-pending", validator=validate_user, secret_key=SECRET_KEY, ttl=300
)
strong = session.stepped_up(["mfa"])
CurrentUser = Annotated[str, Security(session)]
FreshUser = Annotated[str, Security(session.fresh(max_age=300))]
PendingUser = Annotated[str, Security(mfa_pending)]
StrongUser = Annotated[str, Security(strong)]
StrongFreshUser = Annotated[str, Security(strong.fresh(max_age=300))]

app = FastAPI()


def sign_in_with_mfa(response: Response, username: str, second: AMR) -> None:
    mfa_pending.delete_cookie(response)
    session.set_cookie(response, username, acr="mfa", amr=[AMR.PASSWORD, second])


def claim_step(account: Account, step: int) -> bool:
    if account.last_step is not None and step <= account.last_step:
        return False
    account.last_step = step
    return True


def record_failure(account: Account) -> None:
    account.failures += 1
    if account.failures >= MAX_FAILURES:
        account.failures = 0
        account.locked_until = time.time() + LOCKOUT_SECONDS


@app.post("/login")
async def login(credentials: Credentials, response: Response):
    account = ACCOUNTS.get(credentials.username)
    stored = account.password if account else NO_PASSWORD
    if not check_password(credentials.password, stored) or account is None:
        raise UnauthorizedError()
    if account.totp_secret is None:
        session.set_cookie(response, credentials.username, amr=[AMR.PASSWORD])
        return {"mfa_required": False}
    mfa_pending.set_cookie(response, credentials.username)
    return {"mfa_required": True}


@app.post("/login/verify")
async def verify(body: Code, response: Response, username: PendingUser):
    account = ACCOUNTS[username]
    if account.locked_until > time.time():
        raise HTTPException(status_code=429, detail="Too many attempts")
    secret, code = account.totp_secret, body.code.strip().lower()
    step = totp_verify(secret, code, last_step=account.last_step) if secret else None
    used = next(
        (h for h in account.recovery_hashes if verify_token_hash(code, h)), None
    )
    if step is not None and claim_step(account, step):
        second = AMR.ONE_TIME_PASSWORD
    elif used is not None:
        account.recovery_hashes.remove(used)
        second = AMR.MULTI_FACTOR
    else:
        record_failure(account)
        raise UnauthorizedError()
    account.failures = 0
    sign_in_with_mfa(response, username, second)
    return {"recovery_codes_left": len(account.recovery_hashes)}


@app.post("/2fa/enroll")
async def enroll(username: FreshUser):
    account = ACCOUNTS[username]
    if account.totp_secret is not None:
        raise HTTPException(status_code=409, detail="2FA is already on")
    account.pending_secret = totp_generate_secret()
    uri = totp_provisioning_uri(account.pending_secret, username, "Example")
    return {"uri": uri}


@app.post("/2fa/confirm")
async def confirm(body: Code, response: Response, username: CurrentUser):
    account = ACCOUNTS[username]
    secret = account.pending_secret
    step = totp_verify(secret, body.code) if secret else None
    if step is None:
        raise HTTPException(status_code=400, detail="Invalid code")
    account.totp_secret = secret
    account.pending_secret = None
    account.last_step = step
    codes = [secrets.token_hex(10) for _ in range(10)]
    account.recovery_hashes = [hash_token(code) for code in codes]
    sign_in_with_mfa(response, username, AMR.ONE_TIME_PASSWORD)
    return {"recovery_codes": codes}


@app.post("/2fa/disable")
async def disable(username: StrongFreshUser):
    ACCOUNTS[username] = Account(password=ACCOUNTS[username].password)
    return {"ok": True}


@app.post("/payouts")
async def payout(username: StrongUser):
    return {"approved_by": username}
