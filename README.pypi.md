# oaax-manager

Find and download the **runtimes** and **conversion toolchains** of [OAAX](https://docs.oaax.org), the Open AI Accelerator eXchange standard, with one command.
Pure Python, no dependencies, Linux, Windows and macOS.

OAAX runs an AI model on any accelerator (CPU, GPU, NPU, ...) through one interface: a **toolchain** (a Docker image) converts your ONNX model for a chip, and that chip's **runtime** (a shared library) runs it. `oaax-manager` fetches both, checked and ready to use.

## Install

```bash
uv tool install oaax-manager     # on your PATH
uvx oaax-manager list            # or run it once, installing nothing
```

Needs [uv](https://docs.astral.sh/uv/), which also provides Python 3.9+ if you have none.

No uv? Take the single-file `oaax-manager.pyz` from the [GitHub releases](https://github.com/OAAX-standard/oaax-manager/releases) and run `python oaax-manager.pyz list` (any Python 3.9+).

## Use

```bash
oaax-manager list                                           # everything available; * = built for this machine
oaax-manager list --kind toolchain --vendor intel
oaax-manager fetch runtime cpu                              # extracts ./runtime-cpu-<version>-<os>-<arch>/
oaax-manager fetch runtime nvidia-ort --variant cuda12      # several builds exist: you choose (the error lists them)
oaax-manager fetch toolchain intel -o ./toolchains          # saves a .tar: then `docker load -i <file>`
```

| Command | What it does |
| ------- | ------------ |
| `list [--kind K] [--vendor V]` | every runtime and toolchain of the OAAX 2.0 artifact store |
| `fetch runtime <vendor>` | picks this machine's OS and CPU, downloads, verifies and extracts |
| `fetch toolchain <vendor>` | downloads the Docker image as a `.tar` (it never touches Docker itself) |

## Why you can trust a fetch

- **Verified:** every download is checked against a sha256 pinned in the package. A mismatch is an error and nothing is extracted. The same version always fetches the same bytes.
- **Safe extraction:** all-or-nothing into a temporary directory; absolute paths, `..`, unsafe links and names that collide on Windows/macOS are refused.
- **Resilient:** interrupted downloads resume, transient errors are retried, and an existing directory is never overwritten.
- **No surprises:** it never picks between builds (CUDA version, HailoRT version) for you.

Pin a version for anything you script (`uv tool install oaax-manager==X.Y.Z`); upgrade with `uv tool upgrade oaax-manager`.

## Links

- [OAAX documentation](https://docs.oaax.org) · [Source and full README](https://github.com/OAAX-standard/oaax-manager) · [Issues](https://github.com/OAAX-standard/oaax-manager/issues) · [Changelog](https://github.com/OAAX-standard/oaax-manager/blob/main/CHANGELOG.md)
- Check a runtime or toolchain against the standard: [`oaax-conformance`](https://pypi.org/project/oaax-conformance/).

Apache 2.0.
