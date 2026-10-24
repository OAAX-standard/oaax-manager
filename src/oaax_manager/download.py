"""Download with resume and sha256 verification; safe extraction of runtime archives."""

from __future__ import annotations

import hashlib
import shutil
import sys
import time
import tarfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath, PureWindowsPath

CHUNK = 1 << 20


class FetchError(Exception):
    """A user-facing failure (network, checksum, unsafe archive)."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _progress(done: int, total: int) -> None:
    if sys.stderr.isatty():
        print(f"\r  {done / 1e6:8.1f} / {total / 1e6:.1f} MB ({100 * done // max(total, 1)}%)", end="", file=sys.stderr)


def download(url: str, dest: Path, size: int, sha256: str) -> None:
    """Download `url` to `dest` (resuming `dest.part`), then verify size and sha256."""
    part = dest.with_name(dest.name + ".part")
    part.parent.mkdir(parents=True, exist_ok=True)
    have = part.stat().st_size if part.exists() else 0
    if have > size:
        part.unlink()
        have = 0
    if have < size:
        _transfer_with_retries(url, part, size)
    actual = sha256_file(part)
    if actual != sha256:
        part.unlink()
        raise FetchError(
            f"sha256 mismatch for {url}\n  expected {sha256}\n  got      {actual}\n"
            "The artifact changed upstream after this oaax-manager release (2.0.0 files are still re-uploaded on "
            "every vendor build): upgrade oaax-manager, or report it if it is already the latest."
        )
    part.replace(dest)


def _transfer_with_retries(url: str, part: Path, size: int, attempts: int = 3) -> None:
    """Retry transient failures; every attempt resumes from what is already in `part`."""
    for attempt in range(1, attempts + 1):
        try:
            return _transfer(url, part, part.stat().st_size if part.exists() else 0, size)
        except FetchError:
            if attempt == attempts:
                raise
            time.sleep(2 ** attempt)


def _transfer(url: str, part: Path, have: int, size: int) -> None:
    request = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if have and response.status != 206:  # server ignored the Range header: start over
                have = 0
            with part.open("ab" if have else "wb") as out:
                while chunk := response.read(CHUNK):
                    out.write(chunk)
                    have += len(chunk)
                    _progress(have, size)
    except (urllib.error.URLError, OSError) as exc:
        raise FetchError(f"download failed for {url}: {exc} (run the same command again to resume)") from exc
    finally:
        if sys.stderr.isatty():
            print(file=sys.stderr)
    if have != size:
        raise FetchError(f"incomplete download of {url}: got {have} of {size} bytes (run the same command again to resume)")


def _check_member(member: tarfile.TarInfo, root: Path) -> None:
    name = member.name
    if PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive or PureWindowsPath(name).root:
        raise FetchError(f"unsafe archive: absolute path {name!r}")
    if ":" in name or "\\" in name:  # drive letters, NTFS streams, Windows separators
        raise FetchError(f"unsafe archive: {name!r} has a character that is a path syntax on Windows")
    target = (root / name).resolve()
    if not target.is_relative_to(root):
        raise FetchError(f"unsafe archive: {name!r} escapes the target directory")
    if member.isdev() or member.isfifo():
        raise FetchError(f"unsafe archive: special file {name!r}")
    if member.issym() or member.islnk():
        base = root if member.islnk() else target.parent
        if not (base / member.linkname).resolve().is_relative_to(root):
            raise FetchError(f"unsafe archive: link {name!r} -> {member.linkname!r} points outside the target directory")


def safe_extract(archive: Path, dest: Path) -> list[str]:
    """Extract `archive` into a fresh `dest`, all or nothing.

    Every member is checked before anything is written; files go to a temporary sibling directory that is
    renamed to `dest` only when extraction fully succeeded, so `dest` never holds a half-extracted runtime.
    """
    if dest.exists():
        raise FetchError(f"{dest} already exists")
    tmp = dest.with_name(dest.name + ".extracting")
    if tmp.exists():
        shutil.rmtree(tmp)  # leftover of an interrupted run of this tool
    tmp.mkdir(parents=True)
    root = tmp.resolve()
    try:
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            for member in members:
                _check_member(member, root)
            for member in members:
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, root, filter="data")
                else:
                    member.mode &= 0o777
                    tar.extract(member, root)
        tmp.replace(dest)
    except (tarfile.TarError, OSError, FetchError) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        if isinstance(exc, FetchError):
            raise
        raise FetchError(f"cannot extract {archive.name}: {exc}") from exc
    return sorted(m.name for m in members if m.isfile())


def check_disk_space(directory: Path, needed: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(directory).free
    if free < needed:
        raise FetchError(f"not enough disk space in {directory}: need about {needed / 1e9:.1f} GB, {free / 1e9:.1f} GB free")
