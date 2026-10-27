#!/usr/bin/env python3
"""Print the GitHub release notes for a version: its CHANGELOG.md section plus the sha256 of every asset.

    uv run --no-project python tools/release_notes.py 0.1.0 dist/SHA256SUMS
CI runs it on every build (a dry run: it fails if CHANGELOG.md has no section for the version) and again to create the draft release.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def changelog_section(version: str, text: str) -> str:
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    if not match:
        raise SystemExit(f"CHANGELOG.md has no '## [{version}]' section: add one before releasing")
    return match[1].strip()


def notes(version: str, sums: str) -> str:
    section = changelog_section(version, (ROOT / "CHANGELOG.md").read_text())
    return (
        f"{section}\n\n"
        "## Checksums (sha256)\n\n"
        f"```\n{sums.strip()}\n```\n\n"
        "Install: `uv tool install oaax-manager-<version>-py3-none-any.whl`, or run `python oaax-manager.pyz list`.\n"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(notes(sys.argv[1], Path(sys.argv[2]).read_text()))
