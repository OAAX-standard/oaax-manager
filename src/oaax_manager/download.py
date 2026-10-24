"""Download with resume and sha256 verification; safe extraction of runtime archives."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import tarfile
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath, PureWindowsPath

CHUNK = 1 << 20


class FetchError(Exception):
    """A user-facing failure (network, checksum, unsafe archive)."""


def replace_with_retry(src: Path, dst: Path, attempts: int = 5) -> None:
    """os.replace that survives a transient PermissionError (Windows: antivirus or indexer holding the file)."""
    for attempt in range(1, attempts + 1):
        try:
            src.replace(dst)
            return
        except PermissionError:
            if attempt == attempts:
                raise
            time.sleep(0.2 * attempt)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


_last_decile = -1


def _size(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.1f} KB"


def _progress(done: int, total: int) -> None:
    """Live percentage on a terminal; one line per 10 % when output is piped or logged."""
    global _last_decile
    percent = 100 * done // max(total, 1)
    if sys.stderr.isatty():
        print(f"\r  {_size(done)} / {_size(total)} ({percent}%)", end="", file=sys.stderr)
    elif percent // 10 != _last_decile:
        _last_decile = percent // 10
        print(f"  {_size(done)} / {_size(total)} ({percent}%)", file=sys.stderr, flush=True)


@contextlib.contextmanager
def fetch_lock(target: Path):
    """Refuse to run twice for the same target: an advisory lock on `.<target>.lock` (flock / msvcrt, no stale locks)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    path = target.with_name(f".{target.name}.lock")
    handle = open(path, "a+b")
    try:
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise FetchError(f"another oaax-manager is already fetching {target.name} (lock: {path})") from None
        yield
    finally:
        handle.close()  # releases the lock; the empty file is never deleted (unlinking a held lock file is racy)


def download(url: str, dest: Path, size: int, sha256: str) -> None:
    """Download `url` to `dest` (resuming `dest.part`), then verify size and sha256.

    A resumed .part can mix bytes of two uploads (vendors re-upload 2.0.0): if it fails verification it is
    discarded and the file is fetched once more from byte 0 before the failure is blamed on upstream.
    """
    part = dest.with_name(dest.name + ".part")
    part.parent.mkdir(parents=True, exist_ok=True)
    for attempt in (1, 2):
        have = part.stat().st_size if part.exists() else 0
        resumed = 0 < have <= size
        if have > size:
            part.unlink()
        if not part.exists() or part.stat().st_size < size:
            _transfer_with_retries(url, part, size)
        actual = sha256_file(part)
        if actual == sha256:
            replace_with_retry(part, dest)
            return
        part.unlink()
        if not resumed:
            break
    raise FetchError(
        f"sha256 mismatch for {url}\n  expected {sha256}\n  got      {actual}\n"
        "The artifact changed upstream after this oaax-manager release (2.0.0 files are still re-uploaded on "
        "every vendor build): upgrade oaax-manager, or report it if it is already the latest."
    )


def _transfer_with_retries(url: str, part: Path, size: int, attempts: int = 3) -> None:
    """Retry transient failures; every attempt resumes from what is already in `part`."""
    for attempt in range(1, attempts + 1):
        try:
            return _transfer(url, part, part.stat().st_size if part.exists() else 0, size)
        except ServerError:
            raise
        except FetchError:
            if attempt == attempts:
                raise
            time.sleep(2 ** attempt)


def _resumes_at(response, have: int) -> bool:
    match = re.match(r"bytes (\d+)-", response.headers.get("Content-Range", ""))
    return response.status == 206 and bool(match) and int(match[1]) == have


class ServerError(FetchError):
    """A failure that retrying cannot fix (server misbehaves, HTTP 4xx, TLS trust, no space, no permission)."""


PERMANENT_ERRNO = {errno.ENOSPC, errno.EACCES, errno.EPERM, errno.EROFS, errno.EISDIR, errno.ENOTDIR, errno.EDQUOT}


def _transfer(url: str, part: Path, have: int, size: int) -> None:
    """Append to `part` until it holds exactly `size` bytes; never write more than the index promises."""
    global _last_decile
    _last_decile = -1
    request = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if have and not _resumes_at(response, have):  # Range ignored or answered for another offset: start over
                response.close()
                return _transfer(url, part, 0, size)
            announced = response.headers.get("Content-Length")
            if announced is not None and announced.isdigit() and int(announced) > size - have:
                part.unlink(missing_ok=True)
                raise ServerError(f"{url} announces {announced} bytes but only {size - have} are expected")
            with part.open("ab" if have else "wb") as out:
                while have < size:
                    chunk = response.read(min(CHUNK, size - have))
                    if not chunk:
                        break
                    out.write(chunk)
                    have += len(chunk)
                    _progress(have, size)
            if have == size and response.read(1):
                part.unlink(missing_ok=True)
                raise ServerError(f"{url} sent more data than the indexed size ({size} bytes)")
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            raise ServerError(f"download failed for {url}: HTTP {exc.code} {exc.reason}") from exc
        raise FetchError(f"download failed for {url}: HTTP {exc.code} {exc.reason} (run the same command again to resume)") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise ServerError(
                f"TLS certificate verification failed for {url}: {exc.reason}\n"
                "On macOS with a python.org Python, run its 'Install Certificates.command'; otherwise check the system clock and proxy."
            ) from exc
        raise FetchError(f"download failed for {url}: {exc.reason} (run the same command again to resume)") from exc
    except OSError as exc:
        if exc.errno in PERMANENT_ERRNO:
            raise ServerError(f"cannot write {part}: {exc.strerror}") from exc
        raise FetchError(f"download failed for {url}: {exc} (run the same command again to resume)") from exc
    finally:
        if sys.stderr.isatty():
            print(file=sys.stderr)
    if have != size:
        raise FetchError(f"incomplete download of {url}: got {have} of {size} bytes (run the same command again to resume)")


WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def _fold(name: str) -> str:
    """The name as a case-insensitive, Unicode-normalising, dot/space-trimming filesystem would see it."""
    parts = PurePosixPath(name).parts  # also collapses "./a" and "a//b"
    return "/".join(unicodedata.normalize("NFC", p).casefold().rstrip(". ") for p in parts)


def _check_member(member: tarfile.TarInfo, root: Path, links: set[str], seen: set[str]) -> None:
    """Strict rules, identical on every Python version (no reliance on tarfile's own filters).

    Links may only point *down* (relative, no `..`) and nothing may be written through a link of the archive,
    so no chain of links can leave the target directory.
    """
    name = member.name
    if PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive or PureWindowsPath(name).root:
        raise FetchError(f"unsafe archive: absolute path {name!r}")
    if ":" in name or "\\" in name:  # drive letters, NTFS streams, Windows separators
        raise FetchError(f"unsafe archive: {name!r} has a character that is a path syntax on Windows")
    parts = PurePosixPath(name).parts
    if ".." in parts or not (root / name).resolve().is_relative_to(root):
        raise FetchError(f"unsafe archive: {name!r} escapes the target directory")
    if PurePosixPath(name).parts == (MARKER,):
        raise FetchError(f"unsafe archive: {name!r} is reserved for oaax-manager")
    if member.isdev() or member.isfifo():
        raise FetchError(f"unsafe archive: special file {name!r}")
    if any(p != p.rstrip(". ") or p.split(".")[0].casefold() in WINDOWS_RESERVED for p in parts):
        raise FetchError(f"unsafe archive: {name!r} is not a valid file name on Windows")
    folded = _fold(name.rstrip("/"))
    if folded in seen:
        raise FetchError(f"unsafe archive: {name!r} collides with another member (duplicate or case/Unicode variant)")
    seen.add(folded)
    if any("/".join(parts[:i]) in links for i in range(1, len(parts) + 1)):
        raise FetchError(f"unsafe archive: {name!r} is written through a link of the archive")
    if member.issym() or member.islnk():
        target = member.linkname
        if PurePosixPath(target).is_absolute() or PureWindowsPath(target).drive or ".." in PurePosixPath(target).parts or "\\" in target:
            raise FetchError(f"unsafe archive: link {name!r} -> {target!r} must be a relative path without '..'")
        links.add("/".join(parts))


MARKER = ".oaax-manager.json"


def _normalise_modes(root: Path, members: list[tarfile.TarInfo]) -> None:
    """Same permissions on every Python and OS: 0755 for executables and directories, 0644 for the rest."""
    for member in members:
        if member.issym() or member.islnk():
            continue
        path = root / member.name
        executable = member.isdir() or bool(member.mode & 0o100)
        path.chmod(0o755 if executable else 0o644)


def safe_extract(archive: Path, dest: Path, sha256: str | None = None) -> list[str]:
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
            links: set[str] = set()
            seen: set[str] = set()
            for member in members:
                _check_member(member, root, links, seen)
            for member in members:
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, root, filter="data")
                else:
                    tar.extract(member, root)
        _normalise_modes(root, members)
        (root / MARKER).write_text(json.dumps({"archive_sha256": sha256}))  # proves "fully extracted from a verified archive"
        replace_with_retry(tmp, dest)
    except Exception as exc:  # tarfile/zlib raise EOFError, KeyError, zlib.error, ... on broken archives
        shutil.rmtree(tmp, ignore_errors=True)
        if isinstance(exc, FetchError):
            raise
        raise FetchError(f"cannot extract {archive.name}: {type(exc).__name__}: {exc}") from exc
    return sorted(m.name for m in members if m.isfile())


def check_disk_space(directory: Path, needed: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(directory).free
    if free < needed:
        raise FetchError(f"not enough disk space in {directory}: need about {needed / 1e9:.1f} GB, {free / 1e9:.1f} GB free")
