# oaax-manager

Command-line tool to list and fetch OAAX **2.0** runtimes, conversion toolchains and conversion wheels from the OAAX artifact store.
Pure Python (standard library only), works on Linux, Windows and macOS.

## Install

Needs [uv](https://docs.astral.sh/uv/) (it also provides Python 3.9+ if you have none), except for the `.pyz`. No dependencies. Pick one:

| You want | Command |
| -------- | ------- |
| `oaax-manager` on your PATH, isolated | `uv tool install oaax-manager` |
| to run it once, installing nothing | `uvx oaax-manager list` |
| a single file, any Python 3.9+, no uv | `python oaax-manager.pyz list` (from the [Release](https://github.com/OAAX-standard/oaax-manager/releases)) |
| the wheel from the GitHub Release | `uv tool install ./oaax_manager-<version>-py3-none-any.whl` |
| to install from a clone or a tag | `uv tool install .` or `uv tool install git+https://github.com/OAAX-standard/oaax-manager@v<version>` |

- **Pin a version** for anything you script: `uv tool install oaax-manager==<version>` (or the tag `@v<version>`; without it a git install gives you the latest `main`). The artifact index is part of the release, so the same version always fetches the same bytes.
- **Upgrade** with `uv tool upgrade oaax-manager` and read the [CHANGELOG](https://github.com/OAAX-standard/oaax-manager/blob/main/CHANGELOG.md).
- **Verify a release asset**: `sha256sum -c SHA256SUMS` (the sums are also in the release notes).

## Use

| Command | What it does |
| ------- | ------------ |
| `oaax-manager list [--kind K] [--vendor V]` | everything available; `*` marks runtimes that fit this OS/CPU (several variants may match: choose with `--variant`) |
| `oaax-manager scan [--vendor V] [--json]` | which accelerators this machine has and whether a runtime can use them: [details below](#scan-this-machine) |
| `oaax-manager fetch runtime <vendor>` | picks this machine's OS/arch, extracts to `./runtime-<vendor>-<version>-<os>-<arch>[-<variant>]/` (the hidden `.oaax-manager.json` inside records what was extracted) |
| `oaax-manager fetch toolchain <vendor>` | saves `<name>-<version>.tar`; then `docker load -i <file>` |
| `oaax-manager fetch wheel <vendor>` | saves the Python conversion wheel under its published name (no Docker; e.g. `nvidia-trt`); then `uv tool install <file>` |

```bash
oaax-manager list --kind toolchain --vendor intel
oaax-manager fetch runtime nvidia-ort --variant cuda12      # several builds exist: you must choose (the error lists them)
oaax-manager fetch runtime cpu --os linux --arch aarch64 -o ./runtimes
oaax-manager fetch runtime cpu --artifact-version 2.0.0     # default: the newest version available for your platform
oaax-manager fetch toolchain intel -o ./toolchains
oaax-manager fetch wheel nvidia-trt -o ./wheels             # Docker-free TensorRT conversion
```

An existing runtime directory is never overwritten: delete it to fetch again.
Running the same command again **re-checks** its files against the sha256 and permissions recorded at extraction, and fails, naming the file, if one is missing or changed (files you added are not checked).

## Scan this machine

`oaax-manager scan` answers "which chips do I have, and can an OAAX runtime use them?" for the CPU, Intel, NVIDIA (ONNX Runtime and TensorRT, including Jetson and DGX Spark), Hailo and DeepX, on Linux and Windows. For each chip it lists what it found and what it checked (driver, OS, glibc, libraries, versions), the first thing to fix if something fails, and the `fetch` command to run:

```text
Hailo   READY       4x Hailo-8 (PCIe)
    [ok] driver: hailo_pci 4.20.0
    [ok] HailoRT: 4.20.0
    -> oaax-manager fetch runtime hailo --variant hailort4.20.0
NVIDIA  NOT USABLE  NVIDIA GPU (PCI 10de:24b0)
    [!!] driver: driver/library version mismatch: the kernel module is 580.178.04, the user library 595.99. Reboot; ...
```

- **`--variant auto`**: `oaax-manager fetch runtime nvidia-ort --variant auto` fetches the build the scan recommends and says which. Without it, `fetch` never guesses between variants. `auto` refuses, with the reason, when the runtime cannot be used here, and cannot be combined with `--os`/`--arch`.
- **Scripts**: `scan --json`; `scan --vendor V` exits 1 when `V` cannot be used here.
- **Read-only**: it reads `/sys`, `/proc`, `/etc/os-release`, `ldconfig -p`, and runs `nvidia-smi`, `hailortcli`, `dxrt-cli` and `modinfo` with a timeout, from an empty temporary directory. It needs no root, installs nothing and never loads a vendor library.
- **Rules** are the "Requirements" of each chip's page on [docs.oaax.org](https://docs.oaax.org). It tests what the docs list; a library installed where the loader does not look (`LD_LIBRARY_PATH` counts, other paths do not) shows as missing: choose `--variant` yourself then.
- **Not covered**: chips without an OAAX 2.0 runtime in the index (SiMa, MediaTek, ...), macOS, and a real model run (use [`oaax-conformance`](https://pypi.org/project/oaax-conformance/)).

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
- Exotic members (a hard link to a symbolic link) are extracted as the running Python's `tarfile` does, as a link or as a file; both are safe.
- A future vendor archive that breaks the rules fails with a clear message instead of extracting something ambiguous. If a legitimate archive needs it, relax the rule deliberately in `src/oaax_manager/download.py`.

**Resilient downloads**
- Interrupted downloads resume (`*.part` file) and transient network errors are retried; run the same command again if it still fails.
- A link slower than 10 KB/s (averaged over 60 s) is reported once, not retried: the `.part` is kept for the next run.
- The `-o` directory may be a link to another disk. A toolchain `.tar` that is already downloaded and verified may be a link too; a link to anything else is replaced by the download, so point `-o` at the bigger disk instead.

**No surprises**
- It never picks between builds for you (CUDA version, HailoRT version): it lists the choices.
- `fetch toolchain` only downloads the tar. It does not touch Docker; run `docker load` yourself.
- A hidden `.<name>.lock` file stays next to each target: it stops two fetches of the same target running at once. Leave it, or delete it when no fetch is running.

## Limits

- **Interrupted extraction** (Ctrl-C, `kill -9`): run the same command again. A leftover `<dir>.extracting` folder is removed, and the verified archive is reused without downloading it again. Only a kill right after the final rename can leave a `runtime-*.tar.gz` behind: delete it yourself.
- **macOS:** no OAAX runtime is published for macOS yet, so `fetch runtime` says so. Toolchains are Docker images and work wherever Docker runs.
- **Vendor SDKs** that are behind a login are not handled.

## More

- [CONTRIBUTING.md](https://github.com/OAAX-standard/oaax-manager/blob/main/CONTRIBUTING.md): development, how the artifact index works, building and verifying release assets, releasing.
- [CHANGELOG.md](https://github.com/OAAX-standard/oaax-manager/blob/main/CHANGELOG.md), [SECURITY.md](https://github.com/OAAX-standard/oaax-manager/blob/main/SECURITY.md).

## License

Apache 2.0, see [LICENSE](https://github.com/OAAX-standard/oaax-manager/blob/main/LICENSE).
