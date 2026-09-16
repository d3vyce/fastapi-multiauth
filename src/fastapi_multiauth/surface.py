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
        scheme_name: OpenAPI security scheme name, ``None`` for a source
            carrying no ``fastapi.security`` scheme.
        source: Name of the class enforcing it, e.g. ``"HTTPBearerAuth"``.
        scopes: Scopes this scheme must check, in declaration order. A
            dependency declared in several positions carries the union.
        optional: Whether an absent credential is accepted, ``None`` when the
            scheme does not say. Read from ``auto_error``, and always ``False``
            inside a required :class:`MultiAuth`.
    """

    scheme_name: str | None
    source: str
    scopes: tuple[str, ...]
    optional: bool | None


@dataclasses.dataclass(frozen=True, slots=True)
class RouteAuth:
    """What guards one route.

    Args:
        path: Full routed path, including any router prefix.
        methods: HTTP methods, sorted; empty for a WebSocket route.
        alternatives: Ways to satisfy the route, OR-ed; the schemes within one
            are AND-ed. A :class:`MultiAuth` contributes one entry per source,
            separate ``Security()`` dependencies share an entry, and
            dependencies that resolve alike count once. Empty when nothing
            guards the route.
        scopes: Every scope named on the route, first-seen order. An inventory
            for filtering, not a requirement: what one credential must carry is
            the scope list of the entry in ``alternatives`` it satisfies.
        unguarded: Whether a credential-less request reaches the endpoint. True
            when nothing guards the route, and when every AND-ed position
            offers a scheme that does not refuse it. An ``optional`` of
            ``None`` counts as one, so an unreadable guard is reported.
        include_in_schema: Whether the route appears in ``app.openapi()``.
            ``False`` for ``include_in_schema=False`` and for WebSocket routes.
    """

    path: str
    methods: tuple[str, ...]
    alternatives: tuple[tuple[SchemeRequirement, ...], ...]
    scopes: tuple[str, ...]
    unguarded: bool
    include_in_schema: bool


def _dedupe(scopes: Iterable[str]) -> tuple[str, ...]:
    """Drop repeats from *scopes*, keeping first-seen order."""
    return tuple(dict.fromkeys(scopes))


def _declared_scopes(dependant: Dependant) -> tuple[str, ...]:
    """Return the scopes reaching *dependant* from the route and its parents."""
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
    """Describe each of *sources* as a requirement carrying *scopes*."""
    return tuple(
        SchemeRequirement(
            scheme_name=getattr(source, "scheme_name", None),
            source=type(source).__name__,
            scopes=scopes,
            optional=optional,
        )
        for source in sources
    )


def _is_optional(source: AuthSource | MultiAuth | SecurityBase) -> bool | None:
    """Say whether *source* on its own lets a credential-less request through."""
    if isinstance(source, (AuthSource, MultiAuth)):
        return source._optional
    auto_error = getattr(source, "auto_error", None)
    return None if auto_error is None else not auto_error


def _may_admit_anonymous(requirement: SchemeRequirement) -> bool:
    """Say whether *requirement* fails to refuse a credential-less request."""
    return requirement.optional is not False


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
    """Yield each security dependency below *dependant*, keyed by resolution.

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


def _routes_of(app: FastAPI) -> Iterable[Any]:
    """Yield the app's routes, expanding the lazily included routers of 0.141+."""
    expand = getattr(routing, "iter_route_contexts", None)
    return expand(app.routes) if expand else app.routes


def auth_surface(app: FastAPI) -> list[RouteAuth]:
    """Report the authentication requirements of every route in *app*.

    Args:
        app: The application to inspect. A mounted sub-application is opaque,
            so call this on the sub-application as well.

    Returns:
        One :class:`RouteAuth` per routed endpoint, in registration order.
        WebSocket routes are included with no methods; routes carrying no
        dependency tree, such as ``/docs``, are skipped.
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
                    any(_may_admit_anonymous(req) for req in unit) for unit in units
                ),
                include_in_schema=bool(getattr(route, "include_in_schema", False)),
            )
        )
    return surface
