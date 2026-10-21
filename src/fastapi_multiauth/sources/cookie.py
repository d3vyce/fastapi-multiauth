"""Cookie-based authentication source."""

import hashlib
import secrets
from collections.abc import Callable, Sequence
from typing import Any, Literal

from fastapi import Response
from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyCookie
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource, _accepts_kwarg
from ..utils import refusal

_MIN_SECRET_KEY_BYTES = 32
_SALT_PREFIX = "fastapi-multiauth.cookie."

SameSite = Literal["lax", "strict", "none"]


def _normalize_secret_keys(secret_key: str | Sequence[str] | None) -> list[str]:
    """Validate and normalize `secret_key` into a list of keys."""
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


def _check_name_prefix(
    name: str, *, secure: bool, domain: str | None, path: str
) -> None:
    """Refuse settings that make browsers drop a `__Secure-`/`__Host-` cookie."""
    lowered = name.lower()
    if lowered.startswith(("__secure-", "__host-")) and not secure:
        raise ValueError(
            f"cookie {name!r} requires secure=True: browsers drop a prefixed "
            "cookie without the Secure attribute"
        )
    if lowered.startswith("__host-") and (domain is not None or path != "/"):
        raise ValueError(
            f'cookie {name!r} requires path="/" and no domain: browsers drop a '
            "__Host- cookie otherwise"
        )


def _precomputed_signer(keys: list[str], salt: str) -> TimestampSigner:
    """A `TimestampSigner` deriving its keys once here instead of per `unsign`."""
    probe = TimestampSigner(keys, salt=salt, digest_method=hashlib.sha256)
    return TimestampSigner(
        [probe.derive_key(key) for key in keys],
        digest_method=hashlib.sha256,
        key_derivation="none",
    )


class APIKeyCookieAuth(ValidatedAuthSource):
    """Authentication source for cookies, signed into sessions with a `secret_key`.

    With a `secret_key`, the cookie is signed with HMAC-SHA256, bound to its
    name, and expires after `ttl`: a session without a session table. The
    validator receives the plain value once the signature checks out.

    Args:
        name: Cookie name. Prefer a `__Host-` name, which a subdomain
            cannot overwrite.
        validator: Sync or async callable returning the identity, or raising to refuse.
        secret_key: Signing key of at least 32 bytes, or a list to rotate
            keys (the first signs, all verify). `None` disables signing.
        session_id: Give each session a random id, passed to the validator
            as `session_id`, so sessions can be revoked. Needs a
            `secret_key`; turning it on or off logs existing sessions out.
        ttl: Lifetime in seconds, also checked server-side when signed.
        secure: Send the cookie over HTTPS only. Turn off for local HTTP only.
        samesite: The `SameSite` attribute: `"lax"`, `"strict"` or `"none"`.
        domain: The `Domain` attribute. Leave unset for a `__Host-` cookie.
        path: The `Path` attribute.
        scheme_name: Name of the security scheme in OpenAPI, `APIKeyCookie_{name}` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.

    Raises:
        ValueError: On an invalid configuration, such as a short key or a
            `__Host-` name with settings a browser would refuse.
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
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be a positive number of seconds")
        _check_name_prefix(name, secure=secure, domain=domain, path=path)
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
        # the last one, so reverse them to make the first configured key the signer.
        # The salt also separates the two payload layouts.
        self._signer = (
            _precomputed_signer(
                list(reversed(self._secret_keys)),
                f"{_SALT_PREFIX}{name}{'.sid' if session_id else ''}",
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
                description=description,
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
        except SignatureExpired:
            raise refusal(UnauthorizedError(), "expired") from None
        except BadSignature:
            raise refusal(UnauthorizedError(), "invalid_signature") from None

    def authenticated_at(self, credential: str) -> float | None:
        """Return when the signed cookie was set, `None` when it does not verify."""
        if self._signer is None:
            return None
        try:
            _, signed_at = self._signer.unsign(
                credential.encode(), max_age=self._ttl, return_timestamp=True
            )
        except BadSignature:
            return None
        return signed_at.timestamp()

    def _dates_credentials(self) -> bool:
        """Only a signed cookie carries the timestamp `fresh()` needs."""
        return self._signer is not None

    @property
    def name(self) -> str:
        """The cookie name."""
        return self._name

    @property
    def ttl(self) -> int:
        """The cookie lifetime in seconds, to derive a stored session's expiry from."""
        return self._ttl

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the cookie value, or `None` when absent or empty."""
        return request.cookies.get(self._name) or None

    def session_id_of(self, request: HTTPConnection) -> str | None:
        """Return the session id of the request's cookie, without the validator.

        Returns:
            The id, or `None` when `session_id` is off or the cookie is absent,
            expired or forged.
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

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Verify the cookie, then pass its value on to the validator."""
        plain = self._verify(credential)
        if not self._session_id:
            return await self._call_validator(plain, scopes=scopes, request=request)
        sid, _, value = plain.partition(".")
        return await self._call_validator(
            value, scopes=scopes, request=request, session_id=sid
        )

    def set_cookie(self, response: Response, value: str) -> str | None:
        """Set the cookie on `response`, signed when a `secret_key` is configured.

        Each call stamps the current time, so the caller counts as freshly
        authenticated for `fresh()`.

        Args:
            response: The response to set the cookie on.
            value: The value to store, typically a user id.

        Returns:
            The new session id when `session_id` is on, otherwise `None`.
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
        self, response: Response, request: HTTPConnection | None = None
    ) -> str | None:
        """Clear the cookie on `response`, signing this browser out.

        The signed cookie itself stays valid until it expires. With
        `session_id` on, revoke the returned id to end the session for real.

        Args:
            response: The response to clear the cookie on.
            request: The current request, to read its session id from.

        Returns:
            The request's session id when its cookie verifies, otherwise `None`.
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
