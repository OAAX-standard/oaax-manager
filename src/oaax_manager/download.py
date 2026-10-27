"""Download with resume and sha256 verification; safe extraction of runtime archives."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import stat
import sys
import tarfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath, PureWindowsPath

CHUNK = 1 << 20
# Slow-loris guard: `timeout=60` only limits silence, a server sending one byte a minute never trips it.
SLOW_WINDOW = 60  # seconds; in every window at least MIN_RATE bytes/s must arrive on average
MIN_RATE = 10_000


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


# What a lock that is held by someone else raises: flock(LOCK_NB) on POSIX, msvcrt.locking(LK_NBLCK) on Windows. Anything else is a different problem.
LOCKED_ERRNO = {errno.EAGAIN, errno.EWOULDBLOCK} | ({errno.EACCES, errno.EDEADLK} if sys.platform == "win32" else set())


def _try_lock(handle) -> None:
    if sys.platform == "win32":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextlib.contextmanager
def fetch_lock(target: Path):
    """Refuse to run twice for the same target: an advisory lock on `.<target>.lock` (flock / msvcrt, no stale locks)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    path = target.with_name(f".{target.name}.lock")
    try:  # never follow a link planted at the lock path: it would create or touch a file somewhere else
        if path.is_symlink():  # Windows has no O_NOFOLLOW
            raise OSError(errno.ELOOP, "is a symbolic link")
        handle = os.fdopen(os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o644), "a+b")
    except OSError as exc:
        hint = "a link there? delete it and run again" if exc.errno == errno.ELOOP else "check that the output directory, -o, is writable"
        raise FetchError(f"cannot use the lock file {path}: {exc.strerror} ({hint})") from exc
    try:
        try:
            _try_lock(handle)
        except OSError as exc:
            if exc.errno in LOCKED_ERRNO:
                raise FetchError(f"another oaax-manager is already fetching {target.name} (lock: {path})") from None
            raise FetchError(f"cannot lock {path}: {exc.strerror} (some network and FUSE file systems have no file locks: use -o on a local disk)") from exc
        yield
    finally:
        handle.close()  # releases the lock; the empty file is never deleted (unlinking a held lock file is racy)


STALE_PIN = (
    "The artifact changed upstream after this oaax-manager release (2.0.0 files are still re-uploaded on "
    "every vendor build): upgrade oaax-manager, or report it if it is already the latest."
)


def download(url: str, dest: Path, size: int, sha256: str) -> None:
    """Download `url` to `dest` (resuming `dest.part`), then verify size and sha256.

    A resumed .part can mix bytes of two uploads (vendors re-upload 2.0.0): if it fails verification it is
    discarded and the file is fetched once more from byte 0 before the failure is blamed on upstream.
    """
    part = dest.with_name(dest.name + ".part")
    part.parent.mkdir(parents=True, exist_ok=True)
    if part.is_symlink():  # someone else's file in a shared directory: never resume into whatever it points to
        part.unlink()
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
    raise FetchError(f"sha256 mismatch for {url}\n  expected {sha256}\n  got      {actual}\n{STALE_PIN}")


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """The index only allows https (http for localhost); a redirect must not lead anywhere else (http://, ftp://, file://)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed, origin = urllib.parse.urlparse(newurl), urllib.parse.urlparse(req.full_url)
        local = lambda u: u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")  # noqa: E731
        # http is only for tests against a localhost base_url: an https origin must never make us GET a local http service
        if parsed.scheme != "https" and not (local(parsed) and local(origin)):
            raise ServerError(f"{req.full_url} redirects to {newurl}: only https is allowed")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


urllib.request.install_opener(urllib.request.build_opener(_HttpsOnlyRedirects))  # this is a CLI process: every urlopen below uses it


def _more_data(response) -> bool:
    """Does the server send more than the indexed size? A connection that fails while we only ask is not evidence: the sha256 decides."""
    try:
        return bool(response.read(1))
    except (OSError, http.client.HTTPException):
        return False


def _open_part(part: Path, append: bool):
    """Open the .part for writing without following a symlink planted there."""
    if part.is_symlink():  # Windows has no O_NOFOLLOW; the flag below covers the race on POSIX
        raise OSError(errno.ELOOP, "refusing to write through a symbolic link", str(part))
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | (os.O_APPEND if append else os.O_TRUNC)
    return os.fdopen(os.open(part, flags, 0o644), "ab" if append else "wb")


def _transfer_with_retries(url: str, part: Path, size: int, attempts: int = 3) -> None:
    """Retry transient failures; every attempt resumes from what is already in `part`."""
    for attempt in range(1, attempts + 1):
        have = part.stat().st_size if part.exists() else 0
        if have == size:  # every byte arrived, only the confirmation of the end failed: asking for Range bytes=size- would answer 416
            return
        try:
            return _transfer(url, part, have, size)
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


class SlowDownload(ServerError):
    """Too slow for the guard: retrying the same link would only wait out the same window again (the .part is kept for the next run)."""


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
            if announced is not None and announced.isdigit() and int(announced) != size - have:  # larger or smaller than the pinned size: a re-upload
                part.unlink(missing_ok=True)
                raise ServerError(f"{url} announces {announced} bytes but {size - have} are expected\n{STALE_PIN}")
            window_start, window_bytes = time.monotonic(), 0
            with _open_part(part, append=bool(have)) as out:
                while have < size:
                    chunk = response.read1(min(CHUNK, size - have))  # read() would wait for the whole chunk
                    if not chunk:
                        break
                    out.write(chunk)
                    have += len(chunk)
                    window_bytes += len(chunk)
                    _progress(have, size)
                    now = time.monotonic()
                    if now - window_start >= SLOW_WINDOW:
                        if window_bytes < MIN_RATE * (now - window_start):
                            raise SlowDownload(
                                f"download of {url} is too slow (under {MIN_RATE // 1000} KB/s for {SLOW_WINDOW} s): "
                                "check the connection, then run the same command again to resume"
                            )
                        window_start, window_bytes = now, 0
            if have == size and _more_data(response):
                part.unlink(missing_ok=True)
                raise ServerError(f"{url} sent more data than the indexed size ({size} bytes)\n{STALE_PIN}")
    except urllib.error.HTTPError as exc:
        if exc.code == 416 and have:  # the object is shorter than the pinned size (a re-upload): the .part can never be completed
            part.unlink(missing_ok=True)
            raise ServerError(f"{url} cannot continue at byte {have} (HTTP 416): it is shorter than the {size} bytes this release pins\n{STALE_PIN}") from exc
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            raise ServerError(f"download failed for {url}: HTTP {exc.code} {exc.reason}") from exc
        raise FetchError(f"download failed for {url}: HTTP {exc.code} {exc.reason} (run the same command again to resume)") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise ServerError(
                f"TLS certificate verification failed for {url}: {exc.reason}\n"
                "On macOS with a python.org Python, run its 'Install Certificates.command'; otherwise check the system clock and proxy."
            ) from exc
        raise FetchError(f"download failed for {url}: {exc.reason} (check your network or proxy, then run the same command again to resume)") from exc
    except http.client.HTTPException as exc:  # IncompleteRead, BadStatusLine...: a proxy or server cut the response; resumable
        raise FetchError(f"download failed for {url}: {type(exc).__name__} (check your network or proxy, then run the same command again to resume)") from exc
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
    if _fold(name.rstrip("/")) == _fold(MARKER):  # case-insensitive file systems would let it overwrite the marker
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
    if tmp.is_symlink() or tmp.is_file():  # a planted link must not redirect the extraction: remove the link itself
        tmp.unlink()
    elif tmp.exists():
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
        manifest = _manifest(root, members)
        if not manifest["files"]:
            raise FetchError(f"{archive.name} contains no file (only directories or links): the artifact is broken upstream, nothing was installed; please report it")
        # Proves "fully extracted from a verified archive", and records what was extracted so a rerun can check it still is.
        (root / MARKER).write_text(json.dumps({"archive_sha256": sha256, **manifest}))
        replace_with_retry(tmp, dest)
    except Exception as exc:  # tarfile/zlib raise EOFError, KeyError, zlib.error, ... on broken archives
        shutil.rmtree(tmp, ignore_errors=True)
        if isinstance(exc, FetchError):
            raise
        raise FetchError(f"cannot extract {archive.name}: {type(exc).__name__}: {exc}") from exc
    return sorted(manifest["files"])  # the same list a rerun re-checks (hard links of the archive are plain files once extracted)


def _manifest(root: Path, members: list[tarfile.TarInfo]) -> dict:
    files, links = {}, {}
    for member in members:
        path = root / member.name
        if path.is_symlink():
            links[member.name] = os.readlink(path)
        elif path.is_file():  # also hard links of the archive, which are plain files once extracted
            files[member.name] = {"size": path.stat().st_size, "sha256": sha256_file(path), "mode": stat.S_IMODE(path.stat().st_mode)}
    return {"files": files, "links": links}


def verify_extracted(dest: Path, sha256: str) -> list[str] | None:
    """The files of a runtime directory completed earlier by this tool, re-checked against what was extracted.

    None: not completed by this tool for this archive. FetchError: completed, but a file is missing or was changed since.
    """
    try:
        marker = json.loads((dest / MARKER).read_text())
        files, links = marker["files"], marker["links"]
        for want in files.values():
            want["mode"]  # a marker without the permissions is the older format
        if marker["archive_sha256"] != sha256:
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not files:  # no archive of ours is empty: a marker listing no file was not written by an extraction
        return None
    for name, want in files.items():
        path = dest / name
        if path.is_symlink() or not path.is_file():
            raise FetchError(f"{path} is missing or no longer a regular file; delete {dest} and run again")
        try:
            changed = path.stat().st_size != want["size"] or sha256_file(path) != want["sha256"]
            if sys.platform != "win32" and stat.S_IMODE(path.stat().st_mode) != want["mode"]:  # e.g. a setuid or world-writable library
                raise FetchError(f"{path} has other permissions than when it was extracted ({oct(stat.S_IMODE(path.stat().st_mode))}, not {oct(want['mode'])}); delete {dest} and run again")
        except OSError as exc:
            raise FetchError(f"cannot read {path}: {exc.strerror}; fix its permissions, or delete {dest} and run again") from exc
        if changed:
            raise FetchError(f"{path} was modified after it was extracted; delete {dest} and run again")
    for name, target in links.items():
        path = dest / name
        if not path.is_symlink() or os.readlink(path) != target:
            raise FetchError(f"{path} is missing or no longer the link it was; delete {dest} and run again")
    return sorted(files)


def part_bytes(target: Path) -> int:
    """What an interrupted earlier run already downloaded for `target` (its .part), so the disk check does not ask for it twice."""
    part = target.with_name(target.name + ".part")
    return part.stat().st_size if part.is_file() and not part.is_symlink() else 0


def check_disk_space(directory: Path, needed: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(directory).free
    if free < max(needed, 0):
        raise FetchError(f"not enough disk space in {directory}: need about {needed / 1e9:.1f} GB, {free / 1e9:.1f} GB free")
