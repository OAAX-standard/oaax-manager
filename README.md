# oaax-manager

Command-line tool to list and fetch OAAX **2.0** runtimes and conversion toolchains from the OAAX artifact store.
Pure Python (standard library only), works on Linux, Windows and macOS.

> **Status: 0.1.0 is release-ready; the repository is private until the maintainers publish it.**

## Install

Needs [uv](https://docs.astral.sh/uv/) (it also provides Python 3.9+ if you have none), except for the `.pyz`. No dependencies. Pick one:

| You want | Command |
| -------- | ------- |
| `oaax-manager` on your PATH, isolated | `uv tool install git+https://github.com/OAAX-standard/oaax-manager@v0.1.0` |
| to run it once, installing nothing | `uvx --from git+https://github.com/OAAX-standard/oaax-manager@v0.1.0 oaax-manager list` |
| the wheel from the GitHub Release | `uv tool install ./oaax_manager-0.1.0-py3-none-any.whl` |
| a single file, any Python 3.9+, no uv | `python oaax-manager.pyz list` (from the Release) |
| to install from a clone | `uv tool install .` |

- **Pin a version.** Always give the tag (`@v0.1.0`) or the file you downloaded; without `@vX.Y.Z` you get the latest `main`. The artifact index is part of the release, so the same version always fetches the same bytes.
- **Upgrade** by installing the newer tag (`uv tool install --reinstall git+...@v0.2.0`) and reading [CHANGELOG.md](CHANGELOG.md).
- **Verify a release asset**: `sha256sum -c SHA256SUMS` (the sums are also in the release notes). While the repository is private, git and release downloads need access to it.

## Use

| Command | What it does |
| ------- | ------------ |
| `oaax-manager list [--kind K] [--vendor V]` | everything available; `*` marks runtimes built for this OS/CPU (several variants may match) |
| `oaax-manager fetch runtime <vendor>` | picks this machine's OS/arch, extracts to `./runtime-<vendor>-<version>-<os>-<arch>/` |
| `oaax-manager fetch toolchain <vendor>` | saves `<name>-<version>.tar`; then `docker load -i <file>` |

```bash
oaax-manager list --kind toolchain --vendor intel
oaax-manager fetch runtime nvidia-ort --variant cuda12      # several builds exist: you must choose (the error lists them)
oaax-manager fetch runtime cpu --os linux --arch aarch64 -o ./runtimes
oaax-manager fetch runtime cpu --artifact-version 2.0.0     # default: the newest version available for your platform
oaax-manager fetch toolchain intel -o ./toolchains
```

An existing runtime directory is never overwritten: delete it to fetch again.
Running the same command again **re-checks** its files against the sha256 and permissions recorded at extraction, and fails, naming the file, if one is missing or changed (files you added are not checked).

## What it guarantees

**Integrity**
- Every download is verified against the sha256 pinned in the package's `index.json`. A mismatch is an error and nothing is extracted.
- A size that differs from the pinned one (a vendor re-upload) is reported as such: upgrade oaax-manager.
- The same command on the same release always fetches the same bytes; the index is part of the release and is never fetched at run time.

**Safe extraction**
- Runtimes are extracted all-or-nothing: into a temporary directory, renamed only on success. Disk space is checked before downloading.
- Archives are checked before extraction. The rules are strict on purpose and identical on every OS:
  - absolute paths and `..` are refused;
  - links must be relative and point down, and nothing is written through an archive link;
  - names that collide on Windows/macOS (case or Unicode variants, `CON`, `aux.*`, trailing dots/spaces, `:` or `\`) are refused.
- A future vendor archive that breaks the rules fails with a clear message instead of extracting something ambiguous. If a legitimate archive needs it, relax the rule deliberately in `src/oaax_manager/download.py`.

**Resilient downloads**
- Interrupted downloads resume (`*.part` file) and transient network errors are retried; run the same command again if it still fails.
- A link slower than 10 KB/s (averaged over 60 s) is reported once, not retried: the `.part` is kept for the next run.
- The `-o` directory, or a toolchain `.tar` in it, may be a link to another disk.

**No surprises**
- It never picks between builds for you (CUDA version, HailoRT version): it lists the choices.
- `fetch toolchain` only downloads the tar. It does not touch Docker; run `docker load` yourself.
- A hidden `.<name>.lock` file stays next to each target: it stops two fetches of the same target running at once. Leave it, or delete it when no fetch is running.

## Limits

- **After `kill -9`:** if a run is killed between the download and the end of the extraction, the verified archive stays in the output directory and the next run downloads it again. Delete the leftover `runtime-*.tar.gz` yourself.
- **macOS:** no OAAX runtime is published for macOS yet, so `fetch runtime` says so. Toolchains are Docker images and work wherever Docker runs.
- **Vendor SDKs** that are behind a login are not handled.

## More

- [CONTRIBUTING.md](CONTRIBUTING.md): development, how the artifact index works, building and verifying release assets, releasing.
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md).

## License

Apache 2.0, see [LICENSE](LICENSE).
