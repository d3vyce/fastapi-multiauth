"""Introspection of an application's authentication surface."""

import dataclasses
import itertools
from collections.abc import Iterable, Iterator
from typing import Any

from fastapi import FastAPI, routing
from fastapi.dependencies.models import Dependant
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
        csrf: Whether the scheme refuses cross-origin requests, as
            `APIKeyCookieAuth(csrf=True)` does; `False` for a cookie without
            the check, `None` when the scheme does not say.
    """

    scheme_name: str | None
    source: str
    scopes: tuple[str, ...]
    optional: bool | None
    csrf: bool | None = None


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
            route, including through `optional()` sources or a scheme
            that does not say (`optional=None`).
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
    sources: Iterable[AuthSource | SecurityBase],
    scopes: tuple[str, ...],
    optional: bool | None,
) -> tuple[SchemeRequirement, ...]:
    """Describe each of `sources` as a requirement carrying `scopes`."""
    return tuple(
        SchemeRequirement(
            scheme_name=getattr(source, "scheme_name", None),
            source=type(source).__name__,
            scopes=scopes,
            optional=optional,
            csrf=source._csrf if isinstance(source, AuthSource) else None,
        )
        for source in sources
    )


def _is_optional(source: AuthSource | MultiAuth | SecurityBase) -> bool | None:
    """Say whether `source` on its own lets a credential-less request through."""
    if isinstance(source, (AuthSource, MultiAuth)):
        return source._optional
    auto_error = getattr(source, "auto_error", None)
    return None if auto_error is None else not auto_error


_Resolution = tuple[
    type["AuthSource | MultiAuth | SecurityBase"],
    tuple["AuthSource | SecurityBase", ...],
    bool | None,
]


@dataclasses.dataclass(slots=True)
class _Unit:
    """The schemes one dependency accepts and the scopes it checks."""

    sources: tuple[AuthSource | SecurityBase, ...]
    scopes: list[str]
    optional: bool | None


def _positions(dependant: Dependant) -> Iterator[tuple[_Resolution, _Unit]]:
    """Yield each security dependency below `dependant`, keyed by resolution.

    Dependencies sharing a key resolve alike, so their scopes fold together.
    """
    for sub in dependant.dependencies:
        call = sub.call
        if isinstance(call, MultiAuth):
            sources = tuple(call._sources)
        elif isinstance(call, (AuthSource, SecurityBase)):
            sources = (call,)
        else:
            yield from _positions(sub)
            continue
        optional = _is_optional(call)
        yield (
            (type(call), sources, optional),
            _Unit(sources, list(_declared_scopes(sub)), optional),
        )


def _auth_units(dependant: Dependant) -> list[tuple[SchemeRequirement, ...]]:
    """Collect the groups of interchangeable schemes a request must satisfy."""
    by_resolution: dict[_Resolution, _Unit] = {}
    for key, unit in _positions(dependant):
        merged = by_resolution.get(key)
        if merged is None:
            by_resolution[key] = unit
        else:
            merged.scopes.extend(unit.scopes)
    requirements = [
        _requirements(unit.sources, _dedupe(unit.scopes), unit.optional)
        for unit in by_resolution.values()
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
    routes are included.

    Args:
        app: The application to inspect. Mounted sub-applications are not
            inspected; call this on them separately.

    Returns:
        One `RouteAuth` per route, in registration order. Routes without
        dependencies, such as `/docs`, are skipped.
    """
    surface: list[RouteAuth] = []
    for route in _routes_of(app):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        units = _auth_units(dependant)
        alternatives = tuple(itertools.product(*units)) if units else ()
        surface.append(
            RouteAuth(
                path=getattr(route, "path", None) or "",
                methods=tuple(sorted(getattr(route, "methods", None) or ())),
                alternatives=alternatives,
                scopes=_dedupe(
                    scope for unit in units for req in unit for scope in req.scopes
                ),
                unguarded=all(
                    any(req.optional is not False for req in unit) for unit in units
                ),
                include_in_schema=bool(getattr(route, "include_in_schema", False)),
            )
        )
    return surface
