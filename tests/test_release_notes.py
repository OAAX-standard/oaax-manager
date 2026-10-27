from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from oaax_manager import __version__

ROOT = Path(__file__).resolve().parent.parent


def release_notes(version: str, sums: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "release_notes.py"), version, str(sums)], capture_output=True, text=True)


def test_current_version_has_a_changelog_section_and_checksums(tmp_path):
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("ab" * 32 + "  oaax-manager.pyz\n")
    done = release_notes(__version__, sums)
    assert done.returncode == 0, done.stderr
    assert "## Checksums (sha256)" in done.stdout and "ab" * 32 + "  oaax-manager.pyz" in done.stdout


@pytest.mark.parametrize("version", ["9.9.9", "0.1"])
def test_unknown_version_is_refused(tmp_path, version):
    sums = tmp_path / "SHA256SUMS"
    sums.write_text("x")
    done = release_notes(version, sums)
    assert done.returncode != 0 and "no '## [" in done.stderr
