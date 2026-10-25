# Contributing

Bug reports, documentation fixes and pull requests are welcome. To report a vulnerability, follow the [security policy](SECURITY.md) instead of opening an issue.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

The project uses [uv](https://docs.astral.sh/uv/). Clone the repository, then:

```bash
uv sync --group dev
uv run prek install
```

The second command installs the Git hooks: Ruff, ty and whitespace fixes run on every commit.

## Checks

CI runs these on every pull request; run them before pushing:

```bash
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

CI also runs the tests on Python 3.11 to 3.15, and against the oldest FastAPI release the project supports (0.123.0).

## Tests

- `tests/test_multiauth.py` holds the unit tests. Cover each new behaviour, refusals included, and check error messages with `pytest.raises(..., match=...)`.
- `tests/docs/` runs every documentation example, so an example that stops working fails the build.
- For a change on a hot path, run the benchmarks with `uv run pytest benchmarks --codspeed`. CodSpeed compares them on each pull request.

## Documentation

Pages live in `docs/`, and their code examples in `docs_src/`, pulled in with `--8<-- "docs_src/..."`. Put new examples in `docs_src/` with a test in `tests/docs/`, rather than inline in the page. Preview the site with:

```bash
uv run zensical serve
```

## Pull requests

- Branch from `main`, and keep each pull request to one change, with its tests and documentation.
- Write commit messages as `type: subject`, for example `fix: refuse an empty cookie value`, with `feat`, `fix`, `perf`, `test`, `docs` or `chore` as the type.
- Contributions are licensed under the [MIT License](LICENSE).
