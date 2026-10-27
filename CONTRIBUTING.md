# Contributing to oaax-manager

Please read the [general OAAX contributing guide](https://github.com/OAAX-standard/OAAX/blob/main/CONTRIBUTING.md) first (code style, commit format, DCO sign-off: `git commit -s`).

## How to contribute

1. Open an issue to discuss the change.
2. Fork (or, while the repository is private, branch), then commit with sign-off.
3. Open a pull request against `main`.

## Development environment

```bash
uv sync && uv run pytest
```

The project uses [uv](https://docs.astral.sh/uv/); commit `uv.lock` together with any change to `pyproject.toml` dependencies.
Standard library only: a new runtime dependency needs a good reason. Python 3.9 stays supported (`uv run --python 3.9 pytest`).

Before a pull request: tests pass, a bug fix has a regression test, and `CHANGELOG.md` mentions anything users will notice.
If the artifacts in the store changed, regenerate the index with `uv run tools/gen_index.py` (maintainers with bucket access; see the README).
