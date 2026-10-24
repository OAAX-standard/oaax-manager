#!/usr/bin/env python3
"""Build a single-file oaax-manager.pyz from the package sources only (no caches, no egg-info).

    python tools/build_pyz.py [output]      # default: ./oaax-manager.pyz;  run it: python oaax-manager.pyz list
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "oaax_manager"


def build(output: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "oaax_manager"
        shutil.copytree(PACKAGE, target, ignore=shutil.ignore_patterns("__pycache__", "*.partial.json"))
        zipapp.create_archive(tmp, output, main="oaax_manager.cli:run")
    return output


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "oaax-manager.pyz")))
