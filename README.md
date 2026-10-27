# oaax-manager

Command-line tool to list and fetch OAAX **2.0** runtimes and conversion toolchains from the OAAX artifact store.
Pure Python (standard library only), works on Linux, Windows and macOS.

**Status: 0.1.0 is release-ready; the repository is private until the maintainers publish it.**

## Install

Needs [uv](https://docs.astral.sh/uv/) (it also provides Python 3.9+ if you have none). No dependencies. Pick one:

```bash
uv tool install git+https://github.com/OAAX-standard/oaax-manager@v0.1.0     # puts `oaax-manager` on PATH, isolated
uvx --from git+https://github.com/OAAX-standard/oaax-manager@v0.1.0 oaax-manager list   # or run it once, nothing installed
uv tool install ./oaax_manager-0.1.0-py3-none-any.whl                        # or the wheel from the GitHub Release
python oaax-manager.pyz list                                                 # or the single-file .pyz from the Release (any Python 3.9+, no uv)
```

Release assets are listed with their sha256 in the release notes (and in `SHA256SUMS`): `sha256sum -c SHA256SUMS`.
While the repository is private, git and release downloads need access to it.

**Pin a version.** Always give the tag (`@v0.1.0`) or the file you downloaded; without `@vX.Y.Z` you get the latest `main`. The artifact index is part of the
release, so the same version always fetches the same bytes. To upgrade, install the newer tag (`uv tool install --reinstall git+...@v0.2.0`) and read `CHANGELOG.md`.
From a clone: `uv tool install .`; build your own `.pyz`: `uv run --no-project python tools/build_pyz.py`.

## Use

```bash
oaax-manager list                                  # everything available; * marks runtimes built for this OS/CPU (several variants may match)
oaax-manager list --kind toolchain --vendor intel

oaax-manager fetch runtime cpu                     # picks this machine's OS/arch, extracts to ./runtime-cpu-2.0.0-<os>-<arch>/
oaax-manager fetch runtime nvidia-ort --variant cuda12   # several builds exist: you must choose (the error lists them)
oaax-manager fetch runtime cpu --os linux --arch aarch64 -o ./runtimes
oaax-manager fetch runtime cpu --artifact-version 2.0.0     # default: the newest version available for your platform
oaax-manager fetch toolchain intel -o ./toolchains # saves <name>-<version>.tar, then: docker load -i <file>
# an existing runtime directory is never overwritten; delete it to fetch again. Running the same command again re-checks its files against
# the sha256 and permissions recorded at extraction and fails, naming the file, if one is missing or changed (files you added are not checked).
```

What it guarantees:
- Every download is verified against the sha256 pinned in the package's `index.json`; a mismatch is an error and nothing is extracted.
- Interrupted downloads resume (`*.part` file) and transient network errors are retried; run the same command again if it still fails. A link slower than 10 KB/s (averaged over 60 s) is reported once, not retried: the `.part` is kept for the next run.
- A size that differs from the pinned one (a vendor re-upload) is reported as such: upgrade oaax-manager. The `-o` directory, or a toolchain `.tar` in it, may be a link to another disk.
- Known limitation: if a run is killed (`kill -9`) between the download and the end of the extraction, the verified archive stays in the output directory and the next run downloads it again; delete the leftover `runtime-*.tar.gz` yourself.
- Runtimes are extracted all-or-nothing (into a temporary directory, renamed only on success) and the disk space is checked before downloading.
- The same command on the same release always fetches the same bytes; the index is part of the release, never fetched at run time.
- Runtime archives are checked before extraction: absolute paths, `..`, and links pointing outside the target are refused.
- The archive rules are strict on purpose and identical on every OS: links must be relative and point down (no `..`), nothing is written through an archive link, and names that collide on Windows/macOS (case or Unicode variants, `CON`, `aux.*`, trailing dots/spaces, `:` or `\`) are refused. A future vendor archive that breaks them fails with a clear message instead of extracting something ambiguous; relax the rule in `src/oaax_manager/download.py` deliberately if a legitimate archive needs it.
- A hidden `.<name>.lock` file stays next to each target: it stops two fetches of the same target running at once. Leave it, or delete it when no fetch is running.
- It never picks between builds for you (CUDA version, HailoRT version): it lists the choices.
- `fetch toolchain` only downloads the tar. It does not touch Docker; run `docker load` yourself. Gated vendor SDKs are not handled.

macOS: no OAAX runtime is published for macOS yet, so `fetch runtime` says so; toolchains are Docker images and work wherever Docker runs.

## How the index works

The artifact bucket does not allow public listing, so the package ships `src/oaax_manager/index.json` (kind, vendor, platform, size, sha256, URL).
Maintainers regenerate it with `uv run tools/gen_index.py` (needs `s3cmd` with read access): it lists the bucket, derives vendor, platform and
variant from the key layout (no hand-written catalogue), and hashes whatever is new or changed. `--check` exits 1 if the index no longer matches the bucket (any field but the etag), and 2 if it could not check (no `s3cmd`, network).
Variant names (`cuda12`, `jetson-cuda12`, `ubuntu22.04-trt11-cuda13`, `hailort4.20.0`, ...) are derived from the key and kept stable.
The NVIDIA TensorRT conversion `.whl` in the bucket is not indexed (it is a Python package, not a Docker toolchain).
Today the vendor CI re-uploads `2.0.0` artifacts on every build, so a pinned hash can go stale: the CLI then fails with a clear
message instead of installing something unverified. Immutable per-release artifacts are the real fix.

## Builds and releases

CI (`.github/workflows/build.yml`) builds a reproducible wheel and `oaax-manager.pyz` on every push to `main` and every pull request (uv, the build backend and every
action are pinned; a second build must give identical bytes) and keeps them for 30 days as workflow artifacts with `SHA256SUMS`. Nothing is published to PyPI.
"Run workflow" on any branch is a dry run of everything except the release job.
To check a release asset yourself: `umask 022; export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct); uv build --wheel; uv run --no-project python tools/build_pyz.py` on a clean clone of the tag
(the wheel keeps the file modes of the checkout, so the umask matters), and compare with `SHA256SUMS`.

To release (maintainers): set `__version__` in `src/oaax_manager/__init__.py`, give the `CHANGELOG.md` section its date, run `uv run tools/gen_index.py --check` (re-run without
`--check` and merge the index first if it reports changes), merge to `main`, then `git tag vX.Y.Z && git push origin vX.Y.Z`. The workflow checks that the tag equals the version and
creates a **draft** GitHub Release (wheel, `.pyz`, `SHA256SUMS`, changelog section, checksums); review it and press Publish.

## Development

```bash
uv sync                          # dev environment from uv.lock
uv run pytest                    # tests
uv run --python 3.9 pytest       # the oldest supported Python
uv run tools/gen_index.py        # refresh the index (needs s3cmd with read access; downloads whatever changed)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
