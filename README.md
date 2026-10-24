# oaax-manager

Command-line tool to list and fetch OAAX **2.0** runtimes and conversion toolchains from the OAAX artifact store.
Pure Python (standard library only), works on Linux, Windows and macOS.

**Status: early development, private until ready.**

## Install

Python 3.9+, no dependencies.

```bash
pipx install git+https://github.com/OAAX-standard/oaax-manager   # isolated, puts `oaax-manager` on PATH (needs repo access while private)
pip install .                                                     # or from a clone
python tools/build_pyz.py                                         # or one self-contained file: python oaax-manager.pyz list
```

## Use

```bash
oaax-manager list                                  # everything available; * marks runtimes for this machine
oaax-manager list --kind toolchain --vendor intel

oaax-manager fetch runtime cpu                     # picks this machine's OS/arch, extracts to ./runtime-cpu-2.0.0-<os>-<arch>/
oaax-manager fetch runtime nvidia-ort --variant cuda12   # several builds exist: you must choose (the error lists them)
oaax-manager fetch runtime cpu --os linux --arch aarch64 -o ./runtimes
oaax-manager fetch toolchain intel -o ./toolchains # saves the Docker image tar, then: docker load -i <file>
# an existing runtime directory is never overwritten; delete it to fetch again
```

What it guarantees:
- Every download is verified against the sha256 pinned in the package's `index.json`; a mismatch is an error and nothing is extracted.
- Interrupted downloads resume (`*.part` file) and transient network errors are retried; run the same command again if it still fails.
- Runtimes are extracted all-or-nothing (into a temporary directory, renamed only on success) and the disk space is checked before downloading.
- The same command on the same release always fetches the same bytes; the index is part of the release, never fetched at run time.
- Runtime archives are checked before extraction: absolute paths, `..`, and links pointing outside the target are refused.
- It never picks between builds for you (CUDA version, HailoRT version): it lists the choices.
- `fetch toolchain` only downloads the tar. It does not touch Docker; run `docker load` yourself. Gated vendor SDKs are not handled.

macOS: no OAAX runtime is published for macOS yet, so `fetch runtime` says so; toolchains are Docker images and work wherever Docker runs.

## How the index works

The artifact bucket does not allow public listing, so the package ships `src/oaax_manager/index.json` (kind, vendor, platform, size, sha256, URL).
Maintainers regenerate it with `python tools/gen_index.py` (needs `s3cmd` with read access): it lists the bucket, derives vendor, platform and
variant from the key layout (no hand-written catalogue), and hashes whatever is new or changed. `--check` exits 1 if the index no longer matches the bucket.
Variant names (`cuda12`, `jetson-cuda12`, `ubuntu22.04-trt11-cuda13`, `hailort4.20.0`, ...) are derived from the key and kept stable.
The NVIDIA TensorRT conversion `.whl` in the bucket is not indexed (it is a Python package, not a Docker toolchain).
Today the vendor CI re-uploads `2.0.0` artifacts on every build, so a pinned hash can go stale: the CLI then fails with a clear
message instead of installing something unverified. Immutable per-release artifacts are the real fix.

## Builds and releases

CI (`.github/workflows/build.yml`) builds a reproducible wheel and `oaax-manager.pyz` on every push to `main` and keeps them for 30 days as workflow
artifacts (with `SHA256SUMS`). Pushing a tag `vX.Y.Z` (must equal `__version__`) also attaches them to a GitHub Release. Nothing is published to PyPI.

## Development

```bash
pip install -e '.[test]' && pytest
python tools/gen_index.py          # refresh hashes (downloads whatever changed)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
