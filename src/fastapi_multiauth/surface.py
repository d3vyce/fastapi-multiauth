"""Introspection of an application's authentication surface."""

import dataclasses
import itertools
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from fastapi import FastAPI, routing
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.utils import get_dependant
from fastapi.security.base import SecurityBase

from .abc import AuthSource
from .sources import MultiAuth


@dataclasses.dataclass(frozen=True, slots=True)
class SchemeRequirement:
    """One authentication scheme a route accepts, with the scopes it checks.

    Args:
        scheme_name: OpenAPI security scheme name, `None` for a source
            without a `fastapi.security` scheme.
        source: Class name of the source, e.g. `"HTTPBearerAuth"`.
        scopes: Scopes this scheme checks, in declaration order; the union
            when the dependency is declared in several places.
        optional: Whether a request without a credential passes, `None`
            when the scheme does not say. Always `False` inside a
            required `MultiAuth`.
        csrf: Whether the scheme refuses cross-origin requests, as a
            cookie source does; `False` for one with `csrf=False`, `None`
            when the scheme does not say.
        validated: Whether a validator checks the credential. `False` for a
            plain `fastapi.security` scheme, which only reads the credential
            and lets any value through, and for a guard replaced in
            `app.dependency_overrides`.
        overridden: Whether `app.dependency_overrides` replaces the guard,
            so what the route declares is not what runs.
    """

    scheme_name: str | None
    source: str
    scopes: tuple[str, ...]
    optional: bool | None
    csrf: bool | None = None
    validated: bool = True
    overridden: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class RouteAuth:
    """What guards one route.

    Args:
        path: Full path of the route, router prefix included.
        methods: HTTP methods, sorted; empty for a WebSocket route.
        alternatives: The ways to satisfy the route. Entries are
            alternatives (OR); the schemes inside one entry must all pass
            (AND). A `MultiAuth` gives one entry per source; separate
            `Security()` dependencies share one, and dependencies that
            resolve alike count once. Empty when nothing guards the route.
        scopes: Every scope named on the route, in first-seen order. What a
            credential must carry is the scope list of its own entry.
        unguarded: Whether a request without a credential reaches the
            route, including through `optional()` sources, a scheme that
            does not say (`optional=None`) or a guard replaced in
            `app.dependency_overrides`. A plain `fastapi.security` scheme
            refuses a missing credential but checks no value: see
            `SchemeRequirement.validated`.
        include_in_schema: Whether the route appears in `app.openapi()`;
            `False` for WebSocket routes.
    """

    path: str
    methods: tuple[str, ...]
    alternatives: tuple[tuple[SchemeRequirement, ...], ...]
    scopes: tuple[str, ...]
    unguarded: bool
    include_in_schema: bool


def _dedupe(scopes: Iterable[str]) -> tuple[str, ...]:
    """Drop repeats from `scopes`, keeping first-seen order."""
    return tuple(dict.fromkeys(scopes))


def _declared_scopes(dependant: Dependant) -> tuple[str, ...]:
    """Return the scopes reaching `dependant` from the route and its parents."""
    return _dedupe(
        (
            *(dependant.parent_oauth_scopes or ()),
            *(dependant.own_oauth_scopes or ()),
        )
    )


def _requirements(
    unit: "_Unit", scopes: tuple[str, ...]
) -> tuple[SchemeRequirement, ...]:
    """Describe each source of `unit` as a requirement carrying `scopes`."""
    return tuple(
        SchemeRequirement(
            scheme_name=getattr(source, "scheme_name", None),
            source=type(source).__name__,
            scopes=scopes,
            optional=unit.optional,
            csrf=source._csrf if isinstance(source, AuthSource) else None,
            validated=unit.validated and isinstance(source, AuthSource),
            overridden=unit.overridden,
        )
        for source in unit.sources
    )


_Guard = AuthSource | MultiAuth | SecurityBase


def _is_optional(source: _Guard) -> bool | None:
    """Say whether `source` on its own lets a credential-less request through."""
    if isinstance(source, (AuthSource, MultiAuth)):
        return source._optional
    auto_error = getattr(source, "auto_error", None)
    return None if auto_error is None else not auto_error


_Resolution = tuple[tuple["AuthSource | SecurityBase", ...], bool | None, bool, bool]
_Overrides = dict[Callable[..., Any], Callable[..., Any]]


@dataclasses.dataclass(slots=True)
class _Unit:
    """The schemes one dependency accepts and the scopes it checks."""

    sources: tuple[AuthSource | SecurityBase, ...]
    scopes: list[str]
    optional: bool | None
    validated: bool = True
    overridden: bool = False

    @property
    def key(self) -> _Resolution:
        """What decides how this unit resolves: units sharing it fold together."""
        return (self.sources, self.optional, self.validated, self.overridden)


def _sources_of(guard: _Guard) -> tuple[AuthSource | SecurityBase, ...]:
    """The schemes `guard` accepts: a `MultiAuth`'s members, or itself."""
    return tuple(guard._sources) if isinstance(guard, MultiAuth) else (guard,)


def _positions(dependant: Dependant, overrides: _Overrides) -> Iterator[_Unit]:
    """Yield each security dependency below `dependant`, as FastAPI runs it.

    `app.dependency_overrides` decides what runs: a guard replaced by a plain
    callable checks nothing, and a plain dependency replaced by another one
    runs the replacement's own dependencies, not the declared ones.
    """
    for sub in dependant.dependencies:
        declared = sub.call
        override = overrides.get(declared) if declared is not None else None
        call = declared if override is None else override
        scopes = list(_declared_scopes(sub))
        if isinstance(call, _Guard):
            yield _Unit(
                _sources_of(call),
                scopes,
                _is_optional(call),
                overridden=override is not None,
            )
        elif isinstance(declared, _Guard):
            yield _Unit(
                _sources_of(declared), scopes, None, validated=False, overridden=True
            )
        else:
            if override is not None:
                sub = get_dependant(
                    path=sub.path or "", call=override, parent_oauth_scopes=scopes
                )
            yield from _positions(sub, overrides)


def _auth_units(
    dependant: Dependant, overrides: _Overrides
) -> list[tuple[SchemeRequirement, ...]]:
    """Collect the groups of interchangeable schemes a request must satisfy."""
    by_resolution: dict[_Resolution, _Unit] = {}
    for unit in _positions(dependant, overrides):
        merged = by_resolution.setdefault(unit.key, unit)
        if merged is not unit:
            merged.scopes.extend(unit.scopes)
    requirements = [
        _requirements(unit, _dedupe(unit.scopes)) for unit in by_resolution.values()
    ]
    return list(dict.fromkeys(requirements))


def _effective_route(context: Any) -> Any:
    """Return `context`, or the merged route 0.137.2 to 0.143.0 leave off it."""
    if getattr(context, "dependant", None) is not None:
        return context
    effective = getattr(
        getattr(context, "_route_context", None), "starlette_route", None
    )
    return context if effective is None else effective


def _routes_of(app: FastAPI) -> Iterable[Any]:
    """Yield the app's routes, expanding the lazily included routers of 0.137.2+."""
    expand = getattr(routing, "iter_route_contexts", None)
    if expand is None:
        return app.routes
    return (_effective_route(context) for context in expand(app.routes))


def auth_surface(app: FastAPI) -> list[RouteAuth]:
    """Report what guards every route of `app`.

    Reads the routes themselves rather than the OpenAPI schema, so hidden
    routes are included, and honours `app.dependency_overrides`, so a guard
    a test replaced and forgot is reported as not running.

    Args:
        app: The application to inspect. Mounted sub-applications are not
            inspected; call this on them separately.

    Returns:
        One `RouteAuth` per route, in registration order, but FastAPI's own
        documentation and schema routes. A route FastAPI does not manage,
        such as `app.add_route()` or a mount, runs no dependency, so it is
        reported unguarded.
    """
    surface: list[RouteAuth] = []
    docs_paths = {
        url
        for url in (
            app.openapi_url,
            app.docs_url,
            app.redoc_url,
            app.swagger_ui_oauth2_redirect_url,
        )
        if url
    }
    for route in _routes_of(app):
        path = getattr(route, "path", None) or ""
        dependant = getattr(route, "dependant", None)
        if dependant is None and path in docs_paths:
            continue
        units = (
            _auth_units(dependant, app.dependency_overrides)
            if dependant is not None
            else []
        )
        alternatives = tuple(itertools.product(*units)) if units else ()
        surface.append(
            RouteAuth(
                path=path,
                methods=tuple(sorted(getattr(route, "methods", None) or ())),
                alternatives=alternatives,
                scopes=_dedupe(
                    scope for unit in units for req in unit for scope in req.scopes
                ),
                unguarded=all(
                    any(req.optional is not False for req in unit) for unit in units
                ),
                include_in_schema=dependant is not None
                and bool(getattr(route, "include_in_schema", False)),
            )
        )
    return surface
