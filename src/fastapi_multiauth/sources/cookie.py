"""Cookie-based authentication source."""

import hashlib
import json
import secrets
from collections.abc import Callable, Sequence
from typing import Any, Literal, NamedTuple
from urllib.parse import urlsplit

from fastapi import Response
from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyCookie
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

from fastapi_multiauth.exceptions import ForbiddenError, UnauthorizedError

from ..abc import ValidatedAuthSource, _accepts_kwarg, _is_header_token
from ..utils import (
    b64url_decode,
    b64url_encode,
    normalize_origin,
    normalize_secret_keys,
    refusal,
)

_MIN_SECRET_KEY_BYTES = 32
_SALT_PREFIX = "fastapi-multiauth.cookie."
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_OPENED = "fastapi_multiauth.cookie"

SameSite = Literal["lax", "strict", "none"]


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


def _normalize_origins(origins: Sequence[str]) -> frozenset[str]:
    """Validate `trusted_origins` as serialized origins: `scheme://host[:port]`."""
    if isinstance(origins, str):
        raise TypeError("trusted_origins must be a sequence of origins, not a string")
    return frozenset(
        normalize_origin(origin, "each trusted_origins entry") for origin in origins
    )


def _origin_host(origin: str) -> str | None:
    """The `host[:port]` of an `Origin` header, `None` when it has none."""
    try:
        return urlsplit(origin).netloc.lower() or None
    except ValueError:
        return None


def _encode_assurance(acr: str | None, amr: Sequence[str] | None) -> str:
    """The acr/amr header of a cookie payload, empty when neither is set."""
    claims: dict[str, Any] = {}
    if acr is not None:
        if not _is_header_token(acr):
            raise ValueError(
                f"acr must be non-empty printable US-ASCII without spaces, "
                f"quotes or backslashes (got {acr!r}): it is compared against "
                "the acr_values of stepped_up()"
            )
        claims["acr"] = acr
    if amr is not None:
        if isinstance(amr, str):
            raise TypeError("amr must be a sequence of strings, not a string")
        methods = list(amr)
        if not methods or not all(_is_header_token(method) for method in methods):
            raise ValueError(
                f"amr must list at least one method, each non-empty printable "
                f"US-ASCII without spaces, quotes or backslashes (got {amr!r})"
            )
        claims["amr"] = methods
    if not claims:
        return ""
    return b64url_encode(json.dumps(claims, separators=(",", ":")).encode())


def _decode_assurance(header: str) -> dict[str, Any]:
    """The acr/amr stored by `_encode_assurance`."""
    if not header:
        return {}
    return json.loads(b64url_decode(header))


class _Opened(NamedTuple):
    """A verified cookie: its acr/amr header, plain value and signing time if asked."""

    assurance: str
    value: str
    signed_at: float | None


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
        csrf: Refuse cross-origin requests with a 403, judged from the
            `Sec-Fetch-Site` and `Origin` headers browsers send. Applies to
            every method but `GET`, `HEAD` and `OPTIONS`, and to WebSocket
            handshakes. A request carrying neither header is refused too.
        trusted_origins: Other origins the CSRF check lets through, such as
            `"https://app.example.com"`. Needs `csrf=True`.
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
        csrf: bool = False,
        trusted_origins: Sequence[str] = (),
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
        self._secret_keys = (
            []
            if secret_key is None
            else normalize_secret_keys(secret_key, min_bytes=_MIN_SECRET_KEY_BYTES)
        )
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
        self._trusted_origins = _normalize_origins(trusted_origins)
        if self._trusted_origins and not csrf:
            raise ValueError(
                "trusted_origins requires csrf=True: without the check every "
                "origin is let through"
            )
        self._csrf = csrf
        # itsdangerous verifies against every key in the list but signs with
        # the last one, so reverse them to make the first configured key the signer.
        # The salt also separates the payload layouts.
        keys = list(reversed(self._secret_keys))
        salt = f"{_SALT_PREFIX}{name}{'.sid' if session_id else ''}"
        self._signer = _precomputed_signer(keys, f"{salt}.v2") if keys else None
        self._legacy_signer = _precomputed_signer(keys, salt) if keys else None
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

    def _sign(self, value: str, assurance: str = "") -> str:
        if self._signer is None:
            raise RuntimeError("_sign called without secret_key configured")
        return self._signer.sign(f"{assurance}.{value}".encode()).decode()

    def _unsign(self, cookie_value: str, *, dated: bool = False) -> _Opened:
        """Verify signature + expiry, reading payloads from before acr/amr too.

        The signing time is only read when `dated`.
        """
        if self._signer is None or self._legacy_signer is None:
            raise RuntimeError("_unsign called without secret_key configured")
        data = cookie_value.encode()
        legacy = False
        try:
            result = self._signer.unsign(
                data, max_age=self._ttl, return_timestamp=dated
            )
        except SignatureExpired:
            raise
        except BadSignature:
            legacy = True
            result = self._legacy_signer.unsign(
                data, max_age=self._ttl, return_timestamp=dated
            )
        signed_at = None
        if isinstance(result, tuple):
            result, stamp = result
            signed_at = stamp.timestamp()
        if legacy:
            return _Opened("", result.decode(), signed_at)
        assurance, _, value = result.decode().partition(".")
        return _Opened(assurance, value, signed_at)

    def _open(self, cookie_value: str, *, dated: bool = False) -> _Opened:
        """Verify a signed cookie, refusing it with a 401 when it does not verify."""
        try:
            return self._unsign(cookie_value, dated=dated)
        except SignatureExpired:
            raise refusal(UnauthorizedError(), "expired") from None
        except BadSignature:
            raise refusal(UnauthorizedError(), "invalid_signature") from None

    def _verify(self, cookie_value: str) -> str:
        """Return the plain value of a signed cookie, verifying signature + expiry."""
        return self._open(cookie_value).value

    def _assurance_of(self, cookie_value: str | None) -> dict[str, Any]:
        """Return the acr/amr of a signed cookie, empty when it does not verify."""
        if self._signer is None or not cookie_value:
            return {}
        try:
            assurance = self._unsign(cookie_value).assurance
        except BadSignature:
            return {}
        return _decode_assurance(assurance)

    def _opened_for(
        self, credential: str, request: HTTPConnection | None
    ) -> _Opened | None:
        """The cookie verified earlier in `request`, when it is `credential`."""
        opened = request.scope.get(_OPENED) if request is not None else None
        if opened is None or opened[0] is not self._signer or opened[1] != credential:
            return None
        return opened[2]

    def _credential_authenticated_at(
        self, credential: str, request: HTTPConnection | None
    ) -> float | None:
        """`authenticated_at()`, reusing what `authenticate_scoped()` verified."""
        opened = self._opened_for(credential, request)
        if opened is None or opened.signed_at is None:
            return self.authenticated_at(credential)
        return opened.signed_at

    def _credential_acr(
        self, credential: str, request: HTTPConnection | None
    ) -> str | None:
        """`authenticated_acr()`, reusing what `authenticate_scoped()` verified."""
        opened = self._opened_for(credential, request)
        if opened is None:
            return self.authenticated_acr(credential)
        return _decode_assurance(opened.assurance).get("acr")

    def authenticated_at(self, credential: str) -> float | None:
        """Return when the signed cookie was set, `None` when it does not verify."""
        if self._signer is None:
            return None
        try:
            return self._unsign(credential, dated=True).signed_at
        except BadSignature:
            return None

    def _dates_credentials(self) -> bool:
        """Only a signed cookie carries the timestamp `fresh()` needs."""
        return self._signer is not None

    def authenticated_acr(self, credential: str) -> str | None:
        """Return the `acr` passed to `set_cookie()`, `None` when absent or forged."""
        return self._assurance_of(credential).get("acr")

    def _carries_acr(self) -> bool:
        """Only a signed cookie carries the level `stepped_up()` needs."""
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

    def acr_of(self, request: HTTPConnection) -> str | None:
        """Return the `acr` of the request's cookie, without the validator.

        Returns:
            The level passed to `set_cookie()`, or `None` when none was passed
            or the cookie is absent, expired or forged.
        """
        return self._assurance_of(request.cookies.get(self._name)).get("acr")

    def amr_of(self, request: HTTPConnection) -> tuple[str, ...] | None:
        """Return the `amr` of the request's cookie, without the validator.

        Returns:
            The methods passed to `set_cookie()`, or `None` when none were
            passed or the cookie is absent, expired or forged.
        """
        amr = self._assurance_of(request.cookies.get(self._name)).get("amr")
        return tuple(amr) if amr is not None else None

    def _check_origin(self, request: HTTPConnection | None) -> None:
        """Refuse a request sent from another origin, as a CSRF attack is."""
        if request is None:
            raise refusal(ForbiddenError(), "missing_origin")
        if request.scope["type"] == "http" and request.scope["method"] in _SAFE_METHODS:
            return
        site = request.headers.get("sec-fetch-site")
        origin = request.headers.get("origin")
        if site in ("same-origin", "none") or origin in self._trusted_origins:
            return
        if site is None:
            if origin is None:
                raise refusal(ForbiddenError(), "missing_origin")
            host = request.headers.get("host")
            if host and _origin_host(origin) == host.lower():
                return
        raise refusal(ForbiddenError(), "cross_origin")

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Verify the cookie and its origin, then pass its value on to the validator."""
        if self._signer is None:
            plain = credential
        else:
            opened = self._open(credential, dated=self._freshness is not None)
            plain = opened.value
            if request is not None and (
                self._freshness is not None or self._assurance is not None
            ):
                request.scope[_OPENED] = (self._signer, credential, opened)
        if self._csrf:
            self._check_origin(request)
        if not self._session_id:
            return await self._call_validator(plain, scopes=scopes, request=request)
        sid, _, value = plain.partition(".")
        return await self._call_validator(
            value, scopes=scopes, request=request, session_id=sid
        )

    def set_cookie(
        self,
        response: Response,
        value: str,
        *,
        acr: str | None = None,
        amr: Sequence[str] | None = None,
    ) -> str | None:
        """Set the cookie on `response`, signed when a `secret_key` is configured.

        Each call stamps the current time, so the caller counts as freshly
        authenticated for `fresh()`.

        Args:
            response: The response to set the cookie on.
            value: The value to store, typically a user id.
            acr: The level the user just authenticated at, checked by
                `stepped_up()`. Needs a `secret_key`.
            amr: The methods the user just authenticated with, e.g.
                `[AuthenticationMethodReference.PASSWORD]`. Needs a `secret_key`.

        Returns:
            The new session id when `session_id` is on, otherwise `None`.

        Raises:
            TypeError: If `amr` is a bare string.
            ValueError: If `acr` or `amr` is passed without a `secret_key`, or
                holds a value with whitespace, quotes, backslashes or
                non-ASCII characters.
        """
        if self._signer is None and (acr is not None or amr is not None):
            raise ValueError(
                "acr and amr require secret_key: without a signature the "
                "client could raise its own level"
            )
        assurance = _encode_assurance(acr, amr)
        sid = secrets.token_urlsafe(16) if self._session_id else None
        if sid is not None:
            value = f"{sid}.{value}"
        cookie_value = self._sign(value, assurance) if self._signer else value
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
