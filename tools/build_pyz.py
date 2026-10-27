#!/usr/bin/env python3
"""Build a single-file oaax-manager.pyz from the package sources only (no caches, no egg-info).

    uv run --no-project python tools/build_pyz.py [output]      # default: ./oaax-manager.pyz;  run it: python oaax-manager.pyz list
    SOURCE_DATE_EPOCH=<unix time> uv run --no-project python tools/build_pyz.py   # reproducible output
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "oaax_manager"
# zipapp would stamp local time, filesystem order and the umask into the archive: write it ourselves.
MAIN = b"from oaax_manager.cli import run\n\nrun()\n"


def build(output: Path) -> Path:
    """Deterministic zip: sorted entries, fixed mode, UTC timestamp from SOURCE_DATE_EPOCH, stored (no zlib-version dependence)."""
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    stamp = time.gmtime(max(epoch, 315532800))[:6]  # zip cannot store dates before 1980
    files = {"__main__.py": MAIN}
    for path in sorted(PACKAGE.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and not path.name.endswith(".partial.json"):
            files[f"oaax_manager/{path.relative_to(PACKAGE).as_posix()}"] = path.read_bytes()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, stamp)
            info.external_attr = 0o644 << 16
            info.create_system = 3  # Unix, whatever OS builds it
            archive.writestr(info, files[name])
    return Path(output)


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "oaax-manager.pyz")))
