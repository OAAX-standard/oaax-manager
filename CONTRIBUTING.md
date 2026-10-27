# Contributing to oaax-manager

Please read the [general OAAX contributing guide](https://github.com/OAAX-standard/OAAX/blob/main/CONTRIBUTING.md) first (code style, commit format, DCO sign-off: `git commit -s`).

## How to contribute

1. Open an issue to discuss the change.
2. Fork (or, while the repository is private, branch), then commit with sign-off.
3. Open a pull request against `main`.

Before a pull request: tests pass, a bug fix has a regression test, and `CHANGELOG.md` mentions anything users will notice.

## Development environment

```bash
uv sync                          # dev environment from uv.lock
uv run pytest                    # tests
uv run --python 3.9 pytest       # the oldest supported Python
uv run tools/gen_index.py        # refresh the index (needs s3cmd with read access; downloads whatever changed)
```

- The project uses [uv](https://docs.astral.sh/uv/); commit `uv.lock` together with any change to `pyproject.toml` dependencies.
- Standard library only: a new runtime dependency needs a good reason. Python 3.9 stays supported.

## How the artifact index works

The artifact bucket does not allow public listing, so the package ships `src/oaax_manager/index.json` (kind, vendor, platform, size, sha256, URL).

- **Regenerate** it with `uv run tools/gen_index.py` (maintainers with `s3cmd` read access). It lists the bucket, derives vendor, platform and variant from the key layout (no hand-written catalogue), and hashes whatever is new or changed.
- **Check** it with `--check`: exit 1 if the index no longer matches the bucket (any field but the etag), exit 2 if it could not check (no `s3cmd`, network).
- **Variant names** (`cuda12`, `jetson-cuda12`, `ubuntu22.04-trt11-cuda13`, `hailort4.20.0`, ...) are derived from the key and kept stable.
- The NVIDIA TensorRT conversion `.whl` in the bucket is not indexed (it is a Python package, not a Docker toolchain).
- **Stale pins:** today the vendor CI re-uploads `2.0.0` artifacts on every build, so a pinned hash can go stale. The CLI then fails with a clear message instead of installing something unverified. Immutable per-release artifacts are the real fix.

## Builds and release assets

CI (`.github/workflows/build.yml`) builds a reproducible wheel and `oaax-manager.pyz` on every push to `main` and every pull request:

- uv, the build backend and every action are pinned; a second build must give identical bytes.
- The files are kept for 30 days as workflow artifacts, with `SHA256SUMS`. Nothing is published to PyPI.
- "Run workflow" on any branch is a dry run of everything except the release job.

To check a release asset yourself, on a clean clone of the tag, then compare with `SHA256SUMS`:

```bash
umask 022                        # the wheel keeps the file modes of the checkout, so the umask matters
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv build --wheel
uv run --no-project python tools/build_pyz.py
```

## Releasing (maintainers)

1. Set `__version__` in `src/oaax_manager/__init__.py`.
2. Give the `CHANGELOG.md` section its date.
3. Run `uv run tools/gen_index.py --check`. If it reports changes, re-run without `--check` and merge the index first.
4. Merge to `main`.
5. `git tag vX.Y.Z && git push origin vX.Y.Z`.
6. The workflow checks that the tag is a commit of `main` and equals the version, runs the tests on the tag, and creates a **draft** GitHub Release (wheel, `.pyz`, `SHA256SUMS`, changelog section, checksums).
7. Review the draft and press Publish.
