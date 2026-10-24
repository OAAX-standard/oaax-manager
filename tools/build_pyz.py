#!/usr/bin/env python3
"""Build a single-file oaax-manager.pyz from the package sources only (no caches, no egg-info).

    python tools/build_pyz.py [output]      # default: ./oaax-manager.pyz;  run it: python oaax-manager.pyz list
    SOURCE_DATE_EPOCH=<unix time> python tools/build_pyz.py   # reproducible output
"""

from __future__ import annotations

import os
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
        # zipapp's own `main=` stamps __main__.py with the current time, so write it ourselves
        (Path(tmp) / "__main__.py").write_text("from oaax_manager.cli import run\n\nrun()\n")
        if epoch := os.environ.get("SOURCE_DATE_EPOCH"):  # reproducible: same bytes for the same commit
            for path in [Path(tmp), *Path(tmp).rglob("*")]:
                os.utime(path, (int(epoch), int(epoch)))
        zipapp.create_archive(tmp, output)
    return output


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "oaax-manager.pyz")))
