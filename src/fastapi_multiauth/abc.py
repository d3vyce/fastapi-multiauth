"""Abstract base classes for authentication sources."""

import copy
import inspect
import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Self

from fastapi import HTTPException
from fastapi.requests import HTTPConnection
from fastapi.security import SecurityScopes
from fastapi.security.base import SecurityBase

from fastapi_multiauth.exceptions import (
    InsufficientAuthenticationError,
    StaleCredentialError,
    UnauthorizedError,
)
from fastapi_multiauth.utils import (
    add_challenge,
    challenge_headers,
    credential_age,
    ensure_async,
    log_decision,
    refusal,
    refusal_reason,
    require_nonnegative_seconds,
    require_positive_seconds,
    step_up_challenge,
)

logger = logging.getLogger(__name__)

_RESERVED_KWARGS = {
    "scopes": "injected from the route by Security(..., scopes=[...])",
    "session_id": "injected by APIKeyCookieAuth(session_id=True)",
    "request": "injected when the validator declares a 'request' parameter",
}


def _reject_reserved_kwargs(kwargs: dict[str, Any]) -> None:
    """Reject validator kwargs the library injects itself."""
    for name, injected in _RESERVED_KWARGS.items():
        if name in kwargs:
            raise ValueError(
                f"'{name}' is a reserved validator kwarg ({injected}): "
                "the library sets it. Use a different keyword name."
            )


def _signature_params(
    fn: Callable[..., Any],
) -> Mapping[str, inspect.Parameter] | None:
    """The parameters of `fn`, `None` when it has no inspectable signature."""
    try:
        return inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return None


def _accepts_kwarg(fn: Callable[..., Any], name: str) -> bool:
    """Return whether `fn` declares a `name` parameter, `False` when uninspectable."""
    parameters = _signature_params(fn)
    if parameters is None:
        return False
    param = parameters.get(name)
    return param is not None and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def _override_accepts_request(method: Callable[..., Any]) -> bool:
    """Whether an `authenticate_scoped` override can be handed the request."""
    parameters = _signature_params(method)
    if parameters is None:  # not introspectable: take the override at its word
        return True
    return any(
        (
            param.name == "request"
            and param.kind is not inspect.Parameter.POSITIONAL_ONLY
        )
        or param.kind is inspect.Parameter.VAR_KEYWORD
        for param in parameters.values()
    )


def _unenforceable_scopes_error(
    owner: object, scopes: list[str], reason: str | None = None
) -> RuntimeError:
    """Error for scopes declared on a route that this source cannot check.

    Args:
        owner: The source (or combination) refusing the route.
        scopes: The scopes the route declared.
        reason: Why they cannot be checked, when it is not simply that this
            source's own validator does not accept them.
    """
    why = reason or "its validator does not declare a 'scopes' parameter"
    return RuntimeError(
        f"{type(owner).__name__} cannot enforce the security scopes "
        f"{scopes!r} declared on this route: {why}. "
        "Add one to the validator (or override authenticate_scoped()), "
        "or remove scopes=... from Security()."
    )


def _anonymous_scopes_error(owner: object, scopes: list[str]) -> RuntimeError:
    """Error for scopes declared on a route that also allows anonymous callers."""
    return RuntimeError(
        f"{type(owner).__name__} is optional() but this route declares the "
        f"security scopes {scopes!r}: an anonymous caller can never satisfy "
        "them, so the route would be gated or not depending on whether a "
        "credential was sent. Drop optional() or drop scopes=... from Security()."
    )


def _step_up_optional_error(owner: object, guard: str) -> ValueError:
    """Error for a dependency asking for both anonymous callers and a step-up."""
    return ValueError(
        f"{type(owner).__name__} cannot be both optional() and {guard}: an "
        "anonymous caller has proven no factor at all"
    )


def _step_up_optional_guard(owner: Any) -> str | None:
    """The step-up guard that keeps `owner` from being optional, if any."""
    if owner._freshness is not None:
        return "fresh()"
    if owner._assurance is not None:
        return "stepped_up()"
    return None


def _is_header_token(value: Any) -> bool:
    """Whether `value` fits a space-separated list inside a quoted-string."""
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and value.isprintable()
        and not any(char in value for char in ' "\\')
    )


def _validate_acr_values(acr_values: Sequence[str]) -> tuple[str, ...]:
    """Check `acr_values` can travel in the step-up challenge's quoted string."""
    if isinstance(acr_values, str):
        raise TypeError("acr_values must be a sequence of strings, not a string")
    values = tuple(acr_values)
    if not values:
        raise ValueError("acr_values must list at least one value")
    for value in values:
        if not _is_header_token(value):
            raise ValueError(
                f"each acr_values entry must be non-empty printable US-ASCII "
                f"without spaces, quotes or backslashes (got {value!r}): the "
                "values are space-separated inside a quoted-string (RFC 9470)"
            )
    return values


def _undeclared_scopes_error(
    owner: object, unknown: list[str], catalogue: dict[str, str]
) -> RuntimeError:
    """Error for route scopes missing from the source's published catalogue."""
    known = ", ".join(sorted(catalogue)) or "nothing"
    return RuntimeError(
        f"{type(owner).__name__} does not publish the security scopes "
        f"{unknown!r} declared on this route: its catalogue lists {known}. "
        "Add them to scopes={...} on the source, or correct the route."
    )


class _DocOnlyScheme(SecurityBase):
    """Inert stand-in for a `fastapi.security` scheme.

    Carries the scheme's OpenAPI metadata but never executes its parsing, so
    there is no second authentication path diverging from `extract()`.
    """

    def __init__(self, scheme: Any) -> None:
        self.model = scheme.model
        self.scheme_name = scheme.scheme_name

    async def __call__(self, request: HTTPConnection) -> None:
        return None


_SCHEME_CLASSES: dict[type, type] = {}


def _carry_scheme(dependency: Any, scheme: SecurityBase) -> None:
    """Make `dependency` itself the security scheme FastAPI puts in OpenAPI."""
    cls = type(dependency)
    promoted = _SCHEME_CLASSES.get(cls)
    if promoted is None:
        promoted = _SCHEME_CLASSES[cls] = type(
            cls.__name__,
            (cls, SecurityBase),
            {"__module__": cls.__module__, "__doc__": cls.__doc__},
        )
    dependency.__class__ = promoted
    dependency.model = scheme.model
    dependency.scheme_name = scheme.scheme_name


@dataclass(frozen=True, slots=True)
class _Freshness:
    """The window set by `fresh()`."""

    max_age: float
    leeway: float
    read: Callable[[Any], Awaitable[Any]] | None
    """Caller-supplied reader of the instant, `None` to use the source's own."""


@dataclass(frozen=True, slots=True)
class _Assurance:
    """The levels set by `stepped_up()`."""

    acr_values: tuple[str, ...]
    read: Callable[[Any], Awaitable[Any]] | None
    """Caller-supplied reader of the identity's `acr`, `None` to use the source's own."""


class AuthSource(ABC):
    """Base class for authentication sources.

    Subclass it to read a credential the built-in sources do not handle.
    Implement `extract()` and `authenticate()`; override `www_authenticate()`,
    `authenticated_at()`, `authenticated_acr()` or `authenticate_scoped()`
    when the source needs them.

    Args:
        scheme: A `fastapi.security` scheme describing the source in OpenAPI.
            Only its metadata is used; `extract()` always reads the credential.
    """

    scheme: SecurityBase | None
    _optional: bool = False
    _scope_catalogue: dict[str, str] | None = None
    """The scopes this source publishes to OpenAPI, `None` when it has none."""
    _freshness: _Freshness | None = None
    _assurance: _Assurance | None = None
    _csrf: bool | None = None
    """Whether cross-origin requests are refused, `None` when the source does not say."""
    _logger: ClassVar[logging.Logger] = logger
    """Where this source logs its decisions: its module's logger."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Log a library source under its own module's logger."""
        super().__init_subclass__(**kwargs)
        if cls.__module__.startswith(f"{__package__}."):
            cls._logger = logging.getLogger(cls.__module__)

    def __init__(self, scheme: Any = None) -> None:
        self._scoped_takes_request = _override_accepts_request(
            type(self).authenticate_scoped
        )
        self.scheme = _DocOnlyScheme(scheme) if scheme is not None else None
        if self.scheme is not None:
            _carry_scheme(self, self.scheme)

        parameters = [
            inspect.Parameter(
                "request",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=HTTPConnection,
            ),
            inspect.Parameter(
                "security_scopes",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=SecurityScopes,
            ),
        ]
        self.__signature__ = inspect.Signature(parameters, return_annotation=Any)

    @abstractmethod
    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the credential found in the request, without validating it.

        Return `None`, never an empty string, when the credential is absent,
        empty, or belongs to another source: this is what lets `MultiAuth` try
        the next source and `optional()` serve an anonymous caller.
        """

    @abstractmethod
    async def authenticate(self, credential: str) -> Any:
        """Validate a credential and return the identity, or raise to refuse it."""

    def www_authenticate(self) -> str | None:
        """Return the `WWW-Authenticate` challenge sent with this source's 401s.

        Returns:
            The challenge, or `None` when the scheme has none (cookies, API keys).
        """
        return None

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Validate a credential against the scopes the route declares.

        The default refuses any route that declares scopes, since
        `authenticate()` cannot check them. Override it to enforce scopes or
        to use the request.

        Args:
            credential: The credential returned by `extract()`.
            scopes: The scopes declared on the route, empty when there are none.
            request: The request or WebSocket being authenticated, `None`
                when called outside one.
        """
        if scopes:  # fail closed: plain authenticate() cannot check scopes
            raise _unenforceable_scopes_error(self, scopes)
        return await self.authenticate(credential)

    def _enforces_scopes(self) -> bool:
        """Whether route-declared scopes reach an actual check in this source."""
        return type(self).authenticate_scoped is not AuthSource.authenticate_scoped

    async def _call_scoped(
        self, credential: str, scopes: list[str], *, request: HTTPConnection | None
    ) -> Any:
        """Call `authenticate_scoped()`, honouring overrides predating `request`."""
        if self._scoped_takes_request:
            return await self.authenticate_scoped(credential, scopes, request=request)
        return await self.authenticate_scoped(credential, scopes)

    async def _authenticate_with_challenge(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Authenticate, attaching this source's challenge to any 401 raised.

        Freshness is checked after the credential: an invalid one is refused as
        invalid, not as stale. Every outcome is logged.
        """
        try:
            identity = await self._call_scoped(credential, scopes, request=request)
            await self._enforce_step_up(credential, identity, request)
        except HTTPException as exc:
            add_challenge(exc, self.www_authenticate())
            self._log(logging.WARNING, refusal_reason(exc), exc.status_code)
            raise
        if self._logger.isEnabledFor(logging.DEBUG):
            self._log(logging.DEBUG, "authenticated")
        return identity

    def _log(self, level: int, reason: str, status: int | None = None) -> None:
        """Log one decision of this source."""
        log_decision(
            self._logger,
            level,
            reason,
            source=type(self).__name__,
            scheme=self.scheme.scheme_name if self.scheme is not None else None,
            status=status,
        )

    def optional(self) -> Self:
        """Return a copy that yields `None` instead of a 401 when no credential is sent.

        A credential that is sent and refused still gets its 401 or 403.

        Raises:
            ValueError: On a copy made by `fresh()` or `stepped_up()`.
        """
        guard = _step_up_optional_guard(self)
        if guard is not None:
            raise _step_up_optional_error(self, guard)
        clone = copy.copy(self)
        clone._optional = True
        return clone

    def authenticated_at(self, credential: str) -> Any:
        """Return when a credential was proven, for `fresh()`.

        Override it in a source that can date its own credentials, as the
        signed cookie does.

        Args:
            credential: The credential returned by `extract()`.

        Returns:
            Epoch seconds or a `datetime`, `None` when the source cannot tell.
        """
        return None

    def _dates_credentials(self) -> bool:
        """Whether this source can date a credential without a caller's help."""
        return type(self).authenticated_at is not AuthSource.authenticated_at

    def fresh(
        self,
        max_age: float,
        *,
        authenticated_at: Callable[..., Any] | None = None,
        leeway: float = 0.0,
    ) -> Self:
        """Return a copy that refuses a credential proven more than `max_age` ago.

        The refusal is a 401 with the [RFC 9470](https://datatracker.ietf.org/doc/html/rfc9470)
        `max_age` challenge. Composes with `stepped_up()` into one challenge.

        Args:
            max_age: Freshness window in seconds.
            authenticated_at: Sync or async callable taking the identity and
                returning when it was proven, as epoch seconds or a `datetime`
                (naive means UTC). Required when the source cannot date its
                credentials, and overrides `authenticated_at()` when given.
                A `None` result refuses the request.
            leeway: Clock-skew tolerance in seconds. It applies both ways: an
                instant further than `leeway` in the future is refused too.

        Raises:
            ValueError: If `max_age` is not positive, `leeway` is negative,
                either is not finite, the copy is `optional()` or already has
                a window, or the credential cannot be dated.
        """
        require_positive_seconds(max_age, "max_age")
        require_nonnegative_seconds(leeway, "leeway")
        if self._optional:
            raise _step_up_optional_error(self, "fresh()")
        if self._freshness is not None:
            raise ValueError(
                f"{type(self).__name__} already has a freshness window: call "
                "fresh() once, on the source or on the MultiAuth"
            )
        if authenticated_at is None and not self._dates_credentials():
            raise ValueError(
                f"{type(self).__name__} cannot date a credential: "
                "fresh() needs authenticated_at=..."
            )
        clone = copy.copy(self)
        clone._freshness = _Freshness(
            max_age=max_age,
            leeway=leeway,
            read=ensure_async(authenticated_at) if authenticated_at else None,
        )
        return clone

    def authenticated_acr(self, credential: str) -> Any:
        """Return the `acr` a credential was proven at, for `stepped_up()`.

        Override it in a source that carries the level in its own
        credentials, as the signed cookie does.

        Args:
            credential: The credential returned by `extract()`.

        Returns:
            The level, `None` when the source cannot tell.
        """
        return None

    def _carries_acr(self) -> bool:
        """Whether this source can read a credential's level without a caller's help."""
        return type(self).authenticated_acr is not AuthSource.authenticated_acr

    def stepped_up(
        self,
        acr_values: Sequence[str],
        *,
        acr: Callable[..., Any] | None = None,
    ) -> Self:
        """Return a copy that refuses a credential not proven at one of `acr_values`.

        The refusal is a 401 with the [RFC 9470](https://datatracker.ietf.org/doc/html/rfc9470)
        `acr_values` challenge. Composes with `fresh()` into one challenge.

        Args:
            acr_values: The accepted authentication context class references;
                any one of them passes.
            acr: Sync or async callable taking the identity and returning the
                `acr` it achieved, e.g. `lambda claims: claims.get("acr")`.
                Required when the source cannot read the level itself, and
                overrides `authenticated_acr()` when given. Any value outside
                `acr_values`, `None` included, refuses the request.

        Raises:
            TypeError: If `acr_values` is a bare string.
            ValueError: If `acr_values` is empty or holds a value that cannot
                be sent in a header (whitespace, quotes, backslashes,
                non-ASCII), the copy is `optional()` or already has levels,
                or the level cannot be read.
        """
        values = _validate_acr_values(acr_values)
        if self._optional:
            raise _step_up_optional_error(self, "stepped_up()")
        if self._assurance is not None:
            raise ValueError(
                f"{type(self).__name__} already has acr_values: call "
                "stepped_up() once, on the source or on the MultiAuth"
            )
        if acr is None and not self._carries_acr():
            raise ValueError(
                f"{type(self).__name__} cannot read a credential's level: "
                "stepped_up() needs acr=..."
            )
        clone = copy.copy(self)
        clone._assurance = _Assurance(
            acr_values=values, read=ensure_async(acr) if acr else None
        )
        return clone

    async def _enforce_step_up(
        self, credential: str, identity: Any, request: HTTPConnection | None = None
    ) -> None:
        """Refuse an identity outside the `fresh()` window or `stepped_up()` levels."""
        freshness, assurance = self._freshness, self._assurance
        if freshness is not None and not await self._is_fresh(
            freshness, credential, identity, request
        ):
            raise refusal(self._step_up_error(StaleCredentialError), "stale")
        if assurance is not None:
            if assurance.read is not None:
                achieved = await assurance.read(identity)
            else:
                achieved = self._credential_acr(credential, request)
            if achieved not in assurance.acr_values:
                raise refusal(
                    self._step_up_error(InsufficientAuthenticationError),
                    "insufficient_acr",
                )

    async def _is_fresh(
        self,
        freshness: _Freshness,
        credential: str,
        identity: Any,
        request: HTTPConnection | None,
    ) -> bool:
        """Whether the credential was proven inside the window."""
        if freshness.read is not None:
            instant = await freshness.read(identity)
        else:
            instant = self._credential_authenticated_at(credential, request)
        age = credential_age(instant)
        return age is not None and (
            -freshness.leeway <= age <= freshness.max_age + freshness.leeway
        )

    def _credential_authenticated_at(
        self, credential: str, request: HTTPConnection | None
    ) -> Any:
        """`authenticated_at()` for the guards, which also know the request."""
        return self.authenticated_at(credential)

    def _credential_acr(self, credential: str, request: HTTPConnection | None) -> Any:
        """`authenticated_acr()` for the guards, which also know the request."""
        return self.authenticated_acr(credential)

    def _step_up_error(
        self, error_cls: type[InsufficientAuthenticationError]
    ) -> InsufficientAuthenticationError:
        """The refusal, its challenge listing every step-up requirement."""
        max_age = self._freshness.max_age if self._freshness else None
        acr_values = self._assurance.acr_values if self._assurance else None
        return error_cls(
            headers=step_up_challenge(
                self.www_authenticate(),
                error_cls.error_description,
                max_age=max_age,
                acr_values=acr_values,
            ),
            max_age=max_age,
            acr_values=acr_values,
        )

    def _reject_undeclared_scopes(self, scopes: list[str]) -> None:
        """Refuse a route declaring scopes this source never published."""
        catalogue = self._scope_catalogue
        if not catalogue:
            return
        unknown = [scope for scope in scopes if scope not in catalogue]
        if unknown:
            raise _undeclared_scopes_error(self, unknown, catalogue)

    async def dispatch(self, request: HTTPConnection, scopes: list[str]) -> Any:
        """Authenticate a request: extract the credential, then validate it.

        Args:
            request: The request or WebSocket being authenticated.
            scopes: The scopes declared on the route.

        Raises:
            UnauthorizedError: If no credential is present. Every 401 carries
                this source's `WWW-Authenticate` challenge.
            RuntimeError: If an `optional()` copy guards a route declaring
                scopes, which an anonymous caller could never satisfy.
        """
        if scopes:
            if self._optional:
                raise _anonymous_scopes_error(self, scopes)
            self._reject_undeclared_scopes(scopes)
        credential = await self.extract(request)
        if credential is None:
            if self._optional:
                self._log(logging.DEBUG, "anonymous")
                return None
            self._log(logging.INFO, "missing_credential", 401)
            raise UnauthorizedError(headers=challenge_headers(self.www_authenticate()))
        return await self._authenticate_with_challenge(
            credential, scopes, request=request
        )

    async def __call__(self, **kwargs: Any) -> Any:
        """FastAPI dependency dispatch."""
        return await self.dispatch(kwargs["request"], kwargs["security_scopes"].scopes)


class ValidatedAuthSource(AuthSource):
    """Base class for sources that hand their credential to a validator.

    It provides the validator plumbing shared by the built-in sources:
    sync and async validators, `require()`, and the `scopes`,
    `session_id` and `request` arguments. Subclasses implement `extract()`.

    Args:
        validator: Sync or async callable returning the identity, or raising to refuse.
        scheme: A `fastapi.security` scheme describing the source in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        scheme: Any = None,
        /,
        **kwargs: Any,
    ) -> None:
        _reject_reserved_kwargs(kwargs)
        self._validator = ensure_async(validator)
        self._accepts_scopes = _accepts_kwarg(validator, "scopes")
        self._accepts_request = _accepts_kwarg(validator, "request")
        self._kwargs = kwargs
        super().__init__(scheme)

    async def _call_validator(
        self,
        *args: Any,
        scopes: list[str],
        request: HTTPConnection | None = None,
        **injected: Any,
    ) -> Any:
        """Invoke the validator with scope, request and configured kwargs forwarding."""
        if self._accepts_scopes:
            injected["scopes"] = scopes
        elif scopes:  # fail closed: the validator cannot check them
            raise _unenforceable_scopes_error(self, scopes)
        if self._accepts_request:
            injected["request"] = request
        return await self._validator(*args, **self._kwargs, **injected)

    async def authenticate(
        self, credential: str, *, request: HTTPConnection | None = None
    ) -> Any:
        """Validate a credential and return the identity, ignoring route scopes."""
        return await self._call_scoped(credential, [], request=request)

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Validate a credential, passing the route's scopes and request on."""
        return await self._call_validator(credential, scopes=scopes, request=request)

    def _enforces_scopes(self) -> bool:
        """The validator is the authority: every source funnels into it."""
        return self._accepts_scopes

    def require(self, **kwargs: Any) -> Self:
        """Return a copy that passes extra keyword arguments to the validator.

        Args:
            **kwargs: Keyword arguments added to, or overriding, the source's own.

        Raises:
            ValueError: If a reserved name (`scopes`, `session_id`, `request`)
                is passed.
        """
        _reject_reserved_kwargs(kwargs)
        clone = copy.copy(self)
        clone._kwargs = {**self._kwargs, **kwargs}
        return clone
