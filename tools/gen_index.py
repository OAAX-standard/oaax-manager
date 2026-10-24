#!/usr/bin/env python3
"""Regenerate src/oaax_manager/index.json from the bucket: every runtime and toolchain of one OAAX version.

The public bucket does not allow listing, so this needs `s3cmd` configured with read access (maintainers only);
the listing can also be given as files. Hashes of unchanged objects (same size and ETag) are reused.

    uv run tools/gen_index.py                              # list s3://oaax/*/2.0.0 and update the index
    uv run tools/gen_index.py --version 2.1.0              # add another version (kept next to the others)
    uv run tools/gen_index.py --listing a.txt --listing b.txt   # use saved `s3cmd ls --recursive` output
    uv run tools/gen_index.py --check                      # exit 1 if the index is out of date (new, gone or changed)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE_URL = "https://nbg1.your-objectstorage.com/oaax"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from oaax_manager.index import validate_entry  # noqa: E402  (the loader's own rules: never write what it would reject)

INDEX = Path(__file__).resolve().parent.parent / "src" / "oaax_manager" / "index.json"
PARTIAL = INDEX.with_name("index.partial.json")  # finished entries of an interrupted run (git-ignored)

RUNTIME_KEY = re.compile(
    r"^runtimes/(?P<version>[^/]+)/(?P<dir>[A-Z_]+)/(?P<arch>x86_64|aarch64)(?:-(?P<flavor>[a-z]+))?/(?P<os>Ubuntu|Windows)"
    r"(?:/(?P<ubuntu>\d+\.\d+))?/(?P<file>library[^/]*\.tar\.gz)$"
)
TOOLCHAIN_KEY = re.compile(r"^conversion-toolchain/(?P<version>[^/]+)/[A-Z_]+/oaax-(?P<name>[a-z0-9-]+)-toolchain\.tar$")
VENDOR_ALIASES = {"nvidia-onnxruntime": "nvidia-ort", "nvidia-tensorrt": "nvidia-trt"}


def runtime_variant(m: re.Match) -> str | None:
    """Stable name of the build choice: platform flavor, Ubuntu version, then what the file name says."""
    stem = m["file"].removeprefix("library").removesuffix(".tar.gz").lstrip("-").replace("_", "")
    stem = re.sub(r"^(\d+(\.\d+)+)$", r"hailort\1", stem)  # Hailo: library-4.20.0
    stem = re.sub(r"^dxrt-v", "dxrt", stem)  # DeepX: library-dxrt-v3.3.2
    parts = [m["flavor"], f"ubuntu{m['ubuntu']}" if m["ubuntu"] else None, stem or None]
    return "-".join(p for p in parts if p) or None


def classify(key: str, size: int) -> dict | None:
    """Turn a bucket key into an index entry (without hash), or None if it is not a runtime/toolchain archive."""
    if m := RUNTIME_KEY.match(key):
        return dict(kind="runtime", vendor=m["dir"].lower().replace("_", "-"), version=m["version"],
                    os=m["os"].replace("Ubuntu", "linux").replace("Windows", "windows"), arch=m["arch"],
                    variant=runtime_variant(m), key=key, size=size)
    if m := TOOLCHAIN_KEY.match(key):
        vendor = VENDOR_ALIASES.get(m["name"], m["name"])
        return dict(kind="toolchain", vendor=vendor, version=m["version"], os="any", arch="any", variant=None,
                    key=key, size=size)
    return None


LISTING_LINE = re.compile(r"^\S+\s+\S+\s+(?P<size>\d+)\s+s3://[^/]+/(?P<key>.+)$")


def parse_listing(text: str) -> list[tuple[str, int]]:
    """Parse `s3cmd ls --recursive` output into (key, size); a line that mentions s3:// but does not parse is an error."""
    rows = []
    for line in text.splitlines():
        if "s3://" not in line:
            continue
        match = LISTING_LINE.match(line.strip())
        if not match:
            raise SystemExit(f"cannot parse listing line (use plain `s3cmd ls --recursive`, no -H): {line!r}")
        rows.append((match["key"], int(match["size"])))
    return rows


def catalog_from_listing(text: str) -> list[dict]:
    items, skipped = [], []
    for key, size in parse_listing(text):
        item = classify(key, size)
        if item:
            try:
                validate_entry({**item, "sha256": "0" * 64})
            except ValueError as exc:
                print(f"skipped (invalid name, the CLI would reject it): {exc}", file=sys.stderr)
                continue
        (items if item else skipped).append(item or key)
    for key in skipped:
        print(f"skipped (not a runtime/toolchain archive): {key}", file=sys.stderr)
    ids = [(i["kind"], i["vendor"], i["version"], i["os"], i["arch"], i["variant"]) for i in items]
    if len(ids) != len(set(ids)):
        raise SystemExit("two bucket keys map to the same (kind, vendor, version, os, arch, variant): fix classify()")
    return sorted(items, key=lambda i: i["key"])


def list_bucket(version: str) -> str:
    out = []
    for prefix in ("runtimes", "conversion-toolchain"):
        cmd = ["s3cmd", "ls", "--recursive", f"s3://oaax/{prefix}/{version}"]
        out.append(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)
    return "\n".join(out)


def head(key: str) -> tuple[int, str]:
    with urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/{key}", method="HEAD"), timeout=60) as r:
        return int(r.headers["Content-Length"]), r.headers["ETag"].strip('"')


def sha256_of(key: str, size: int, etag: str, attempts: int = 6) -> str:
    """Stream the object into a hash; after a dropped connection continue with a Range request."""
    digest, seen = hashlib.sha256(), 0
    for attempt in range(attempts):
        headers = {"If-Match": f'"{etag}"'}  # fail instead of hashing a mix of two uploads
        if seen:
            headers["Range"] = f"bytes={seen}-"
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{BASE_URL}/{key}", headers=headers), timeout=60) as r:
                if seen and r.status != 206:
                    raise RuntimeError(f"{key}: server ignored the Range header")
                while chunk := r.read(1 << 20):
                    digest.update(chunk)
                    seen += len(chunk)
        except OSError as exc:
            print(f"{key}: {exc}; resuming at {seen}", file=sys.stderr)
        if seen == size:
            return digest.hexdigest()
    raise RuntimeError(f"{key}: got {seen} of {size} bytes after {attempts} attempts")


def build_entry(item: dict, old: dict[str, dict]) -> dict:
    size, etag = head(item["key"])
    known = old.get(item["key"])
    if known and known["size"] == size and known["etag"] == etag:
        return {**item, "size": size, "etag": etag, "sha256": known["sha256"]}
    print(f"hashing {item['key']} ({size / 1e6:.0f} MB)", file=sys.stderr)
    return {**item, "size": size, "etag": etag, "sha256": sha256_of(item["key"], size, etag)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default="2.0.0", help="OAAX version to (re)index; other versions stay as they are")
    parser.add_argument("--listing", action="append", type=Path, help="saved `s3cmd ls --recursive` output instead of calling s3cmd")
    parser.add_argument("--check", action="store_true", help="only report differences, do not write")
    args = parser.parse_args()

    text = "\n".join(p.read_text() for p in args.listing) if args.listing else list_bucket(args.version)
    catalog = [i for i in catalog_from_listing(text) if i["version"] == args.version]
    if not catalog:
        raise SystemExit(f"no runtime/toolchain found for version {args.version}")

    previous = json.loads(INDEX.read_text())["artifacts"] if INDEX.exists() else []
    old = {a["key"]: a for a in previous}
    if PARTIAL.exists():
        old.update({a["key"]: a for a in json.loads(PARTIAL.read_text())["artifacts"]})
    done: dict[str, dict] = {}
    lock = threading.Lock()

    def work(item: dict) -> dict:
        entry = build_entry(item, old)
        with lock:  # keep finished hashes if a later artifact fails
            done[entry["key"]] = entry
            if not args.check:
                PARTIAL.write_text(json.dumps({"artifacts": list(done.values())}))
        return entry

    with ThreadPoolExecutor(max_workers=4) as pool:
        fresh = list(pool.map(work, catalog))

    before = {a["key"]: a["sha256"] for a in previous if a["version"] == args.version}
    after = {a["key"]: a["sha256"] for a in fresh}
    problems = [f"new:     {k}" for k in sorted(after.keys() - before.keys())]
    problems += [f"gone:    {k}" for k in sorted(before.keys() - after.keys())]
    problems += [f"CHANGED: {k}" for k in sorted(after.keys() & before.keys()) if after[k] != before[k]]
    if problems:
        print("index differs from the bucket:\n  " + "\n  ".join(problems), file=sys.stderr)
    if args.check:
        return 1 if problems else 0
    artifacts = [a for a in previous if a["version"] != args.version] + fresh
    data = {"schema": 1, "base_url": BASE_URL, "artifacts": artifacts}
    INDEX.write_text(json.dumps(data, indent=2) + "\n")
    PARTIAL.unlink(missing_ok=True)
    print(f"wrote {INDEX} ({len(artifacts)} artifacts)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
