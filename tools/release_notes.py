#!/usr/bin/env python3
"""Print the GitHub release notes for a version: its CHANGELOG.md section plus the sha256 of every asset.

    uv run --no-project python tools/release_notes.py 0.1.0 dist/SHA256SUMS [--final]
CI runs it on every build (a dry run: it fails if CHANGELOG.md has no section for the version). On a tag it adds --final, which also
refuses a section still headed "unreleased": the date must be set before the tag.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def changelog_section(version: str, text: str, final: bool = False) -> str:
    """The body of `## [version]`, up to the next `## ` heading that is not inside a code fence."""
    lines, body, heading, fenced = text.splitlines(), [], None, False
    for line in lines:
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if not fenced and line.startswith("## "):
            if heading is not None:
                break
            if re.match(rf"## \[{re.escape(version)}\]", line):
                heading = line
            continue
        if heading is not None:
            body.append(line)
    if heading is None:
        raise SystemExit(f"CHANGELOG.md has no '## [{version}]' section: add one before releasing")
    if final and not re.search(r"\d{4}-\d{2}-\d{2}", heading):
        raise SystemExit(f"CHANGELOG.md heading '{heading}' has no release date (YYYY-MM-DD): set it before tagging")
    section = "\n".join(body).strip()
    if not section:
        raise SystemExit(f"CHANGELOG.md section for {version} is empty")
    return section


def notes(version: str, sums: str, final: bool = False) -> str:
    section = changelog_section(version, (ROOT / "CHANGELOG.md").read_text(), final)
    return (
        f"{section}\n\n"
        "## Checksums (sha256)\n\n"
        f"```\n{sums.strip()}\n```\n\n"
        "Install: `uv tool install ./oaax_manager-<version>-py3-none-any.whl`, or run `python oaax-manager.pyz list`.\n"
    )


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--final"]
    if len(args) != 2:
        raise SystemExit(__doc__)
    print(notes(args[0], Path(args[1]).read_text(), final="--final" in sys.argv))
