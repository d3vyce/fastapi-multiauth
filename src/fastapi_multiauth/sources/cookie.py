"""Cookie-based authentication source."""

import hashlib
import secrets
from collections.abc import Callable, Sequence
from typing import Any, Literal

from fastapi import Request, Response
from fastapi.security import APIKeyCookie
from itsdangerous import BadSignature, TimestampSigner

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource, _accepts_kwarg

_MIN_SECRET_KEY_BYTES = 32
_SALT_PREFIX = "fastapi-multiauth.cookie."

SameSite = Literal["lax", "strict", "none"]


def _normalize_secret_keys(secret_key: str | Sequence[str] | None) -> list[str]:
    """Validate and normalize ``secret_key`` into a list of keys."""
    if secret_key is None:
        return []
    keys = [secret_key] if isinstance(secret_key, str) else list(secret_key)
    if not keys:
        raise ValueError("secret_key must contain at least one key")
    for key in keys:
        if len(key.encode()) < _MIN_SECRET_KEY_BYTES:
            raise ValueError(
                f"each secret_key must be at least {_MIN_SECRET_KEY_BYTES} "
                "bytes of high-entropy material (e.g. secrets.token_urlsafe(32)); "
                "an empty or short key would weaken cookie signing"
            )
    return keys


class APIKeyCookieAuth(ValidatedAuthSource):
    """Cookie-based authentication source (wraps ``APIKeyCookie`` for OpenAPI).

    When ``secret_key`` is set, the cookie is signed (HMAC-SHA256 with an
    embedded timestamp, salted by the cookie name) for stateless, tamper-proof
    sessions; otherwise the raw cookie value is passed through.

    Args:
        name: Cookie name.
        validator: Sync or async callable receiving the cookie value (plain,
            after signature verification when signed) and returning the identity.
        secret_key: One key or a sequence to rotate (first signs, all verify);
            each at least 32 bytes. When ``None``, the cookie is not signed.
        session_id: Mint a random id per :meth:`set_cookie` and inject it into
            the validator as ``session_id``. Requires ``secret_key`` and a
            validator declaring that parameter; changing it invalidates
            existing cookies.
        ttl: Cookie lifetime in seconds (default 24 h); also enforced
            server-side when the cookie is signed.
        secure: Set the ``Secure`` flag (default ``True``); disable only in local dev.
        samesite: ``SameSite`` cookie attribute (default ``"lax"``).
        domain: Optional ``Domain`` cookie attribute.
        path: ``Path`` cookie attribute (default ``"/"``).
        scheme_name: OpenAPI security scheme name (default ``APIKeyCookie_{name}``).
        **kwargs: Extra keyword arguments forwarded to the validator on every call.
    """

    def __init__(
        self,
        name: str,
        validator: Callable[..., Any],
        *,
        secret_key: str | Sequence[str] | None = None,
        session_id: bool = False,
        ttl: int = 86400,
        secure: bool = True,
        samesite: SameSite = "lax",
        domain: str | None = None,
        path: str = "/",
        scheme_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be a positive number of seconds")
        self._name = name
        self._secret_keys = _normalize_secret_keys(secret_key)
        if session_id:
            if not self._secret_keys:
                raise ValueError(
                    "session_id requires secret_key: without a signature the "
                    "client could forge or swap the session id"
                )
            if not _accepts_kwarg(validator, "session_id"):
                raise ValueError(
                    "session_id requires a validator declaring a 'session_id' "
                    "parameter: the minted id is injected on every call"
                )
        self._session_id = session_id
        # itsdangerous verifies against every key in the list but signs with
        # the last one — reverse so the first configured key is the signer.
        # The salt also separates the two payload layouts.
        self._signer = (
            TimestampSigner(
                list(reversed(self._secret_keys)),
                salt=f"{_SALT_PREFIX}{name}{'.sid' if session_id else ''}",
                digest_method=hashlib.sha256,
            )
            if self._secret_keys
            else None
        )
        self._ttl = ttl
        self._secure = secure
        self._samesite: SameSite = samesite
        self._domain = domain
        self._path = path
        super().__init__(
            validator,
            APIKeyCookie(
                name=name,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyCookie_{name}",
            ),
            **kwargs,
        )

    def _sign(self, value: str) -> str:
        if self._signer is None:
            raise RuntimeError("_sign called without secret_key configured")
        return self._signer.sign(value.encode()).decode()

    def _verify(self, cookie_value: str) -> str:
        """Return the plain value, verifying signature + expiry when signed."""
        if self._signer is None:
            return cookie_value
        try:
            return self._signer.unsign(
                cookie_value.encode(), max_age=self._ttl
            ).decode()
        except BadSignature:
            raise UnauthorizedError() from None

    @property
    def name(self) -> str:
        """Cookie name. Read-only: the signing salt is derived from it."""
        return self._name

    @property
    def ttl(self) -> int:
        """Cookie lifetime in seconds: use it to derive your session's expiry."""
        return self._ttl

    async def extract(self, request: Request) -> str | None:
        """Return the raw cookie value, or ``None`` when absent or empty."""
        return request.cookies.get(self._name) or None

    def session_id_of(self, request: Request) -> str | None:
        """Return *request*'s session id without running the validator.

        ``None`` when ``session_id`` is off, or the cookie is absent, expired
        or forged.
        """
        if not self._session_id:
            return None
        cookie_value = request.cookies.get(self._name)
        if not cookie_value:
            return None
        try:
            return self._verify(cookie_value).partition(".")[0]
        except UnauthorizedError:
            return None

    async def authenticate_scoped(self, credential: str, scopes: list[str]) -> Any:
        """Verify the cookie, forwarding route-declared scopes to the validator."""
        plain = self._verify(credential)
        if not self._session_id:
            return await self._call_validator(plain, scopes=scopes)
        sid, _, value = plain.partition(".")
        return await self._call_validator(value, scopes=scopes, session_id=sid)

    def set_cookie(self, response: Response, value: str) -> str | None:
        """Attach the cookie to *response*, signing it when ``secret_key`` is set.

        Returns the minted session id: always a ``str`` when ``session_id`` is
        on, always ``None`` when it is off.
        """
        sid = secrets.token_urlsafe(16) if self._session_id else None
        if sid is not None:
            value = f"{sid}.{value}"
        cookie_value = self._sign(value) if self._signer else value
        response.set_cookie(
            self._name,
            cookie_value,
            httponly=True,
            samesite=self._samesite,
            secure=self._secure,
            max_age=self._ttl,
            domain=self._domain,
            path=self._path,
        )
        return sid

    def delete_cookie(
        self, response: Response, request: Request | None = None
    ) -> str | None:
        """Clear the session cookie (logout) from this client only.

        Returns *request*'s session id when it verifies (revoke it server-side
        for a hard logout), ``None`` otherwise.
        """
        response.delete_cookie(
            self._name,
            httponly=True,
            samesite=self._samesite,
            secure=self._secure,
            domain=self._domain,
            path=self._path,
        )
        return self.session_id_of(request) if request is not None else None
