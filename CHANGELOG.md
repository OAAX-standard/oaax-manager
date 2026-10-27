# Changelog

All notable changes to oaax-manager. Versions follow [semver](https://semver.org/); the artifact index (`index.json`) is part of each release.

## [0.1.0] - unreleased

First release.

- `oaax-manager list` shows every OAAX 2.0 runtime and conversion toolchain in the artifact store (43 artifacts: 37 runtimes, 6 toolchains), marking the runtimes that fit this machine.
- `oaax-manager fetch runtime|toolchain <vendor>` downloads with resume and retries, verifies the pinned sha256, and extracts runtimes all-or-nothing with strict archive rules.
- Downloads are cut off with a clear error when the server is stalled or slower than 10 KB/s for 60 s (run the same command again to resume).
- The index is shipped inside the package and regenerated with `tools/gen_index.py`; `--check` reports artifacts that were added, removed or re-uploaded.
- Single-file `oaax-manager.pyz` and wheel built reproducibly by CI.
