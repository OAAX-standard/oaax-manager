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


def run_tool(version: str, sums: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "release_notes.py"), version, str(sums), *extra], capture_output=True, text=True)


def test_final_refuses_a_section_still_headed_unreleased(tmp_path, monkeypatch):
    """adversary A5: the date must be set before the tag; a dry run (no --final) still passes so every build works before release day."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("release_notes", ROOT / "tools" / "release_notes.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    text = "# Changelog\n\n## [1.2.3] - unreleased\n\n- a change\n\n## [1.2.2] - 2026-01-01\n\n- old\n"
    assert tool.changelog_section("1.2.3", text) == "- a change"
    with pytest.raises(SystemExit, match="unreleased"):
        tool.changelog_section("1.2.3", text, final=True)
    assert tool.changelog_section("1.2.2", text, final=True) == "- old"
    with pytest.raises(SystemExit, match="empty"):
        tool.changelog_section("1.2.3", "## [1.2.3] - 2026-01-01\n\n## [1.2.2]\n- x\n")


def test_the_tool_exits_non_zero_and_prints_nothing_for_a_missing_section(tmp_path):
    sums = tmp_path / "S"
    sums.write_text("x")
    done = run_tool("9.9.9", sums, "--final")
    assert done.returncode != 0 and done.stdout == "" and "no '## [9.9.9]' section" in done.stderr
