# Changelog

All notable changes to oaax-manager. Versions follow [semver](https://semver.org/); the artifact index (`index.json`) is part of each release.

## [0.2.0] - 2026-10-30

- `fetch wheel <vendor>` and `list --kind wheel`: the Python conversion wheel of the NVIDIA TensorRT toolchain (`nvidia-trt`) is indexed and downloaded with a pinned sha256, under its published name (pip and uv refuse a renamed wheel), then `uv tool install <file>`. The index has 44 artifacts (+1 wheel); the other 43 are identical. Needs this version: an older oaax-manager rejects an index with a `wheel` entry.
- `list` footer: `*` is said to mean "fits this OS and CPU", with the hint to choose with `--variant` when several are marked, instead of "runtime for this machine" (several CUDA, HailoRT or Ubuntu builds are starred together).
- README: no release version in the status line or the install examples (`<version>` placeholders); a test keeps it that way.

## [0.1.2] - 2026-10-30

- The PyPI project page has its own, shorter readme (`README.pypi.md`): what OAAX is, install, the commands, what a fetch guarantees, links. The GitHub README is unchanged. No code or index change: the artifact index is identical to 0.1.1.

## [0.1.1] - 2026-10-29

- Index refreshed: the nine Hailo 2.0.0 artifacts (8 runtimes, the toolchain) were re-uploaded on 2026-10-28 with the reselect and input-order fixes, so the pinned sha256 of 0.1.0 no longer matched and `fetch runtime hailo` failed verification. Nothing else changed: the other 34 entries are identical.

## [0.1.0] - 2026-10-27

First release.

- `oaax-manager list` shows every OAAX 2.0 runtime and conversion toolchain in the artifact store (43 artifacts: 37 runtimes, 6 toolchains), marking the runtimes that fit this machine.
- `oaax-manager fetch runtime|toolchain <vendor>` downloads with resume and retries, verifies the pinned sha256, and extracts runtimes all-or-nothing with strict archive rules.
- Downloads are cut off with a clear error when the server is stalled or slower than 10 KB/s for 60 s (run the same command again to resume).
- The index is shipped inside the package and regenerated with `tools/gen_index.py`; `--check` reports artifacts that were added, removed or re-uploaded.
- Single-file `oaax-manager.pyz` and wheel built reproducibly by CI.
- Published on PyPI as `oaax-manager` (trusted publishing from the release's own wheel).
