"""Command line: `oaax-manager list` and `oaax-manager fetch`."""

from __future__ import annotations

import argparse
import contextlib
import shlex
import subprocess
import sys
from pathlib import Path

from . import __version__
from .download import FetchError, check_disk_space, download, fetch_lock, part_bytes, safe_extract, sha256_file, verify_extracted
from .index import Artifact, IndexError_, host_platform, load_index, version_key


class UserError(Exception):
    """A mistake in the command line or an unsupported request: printed without traceback."""


def human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    raise AssertionError


def quote(path: Path) -> str:
    """Shell-safe spelling of a path for a command we print for the user to copy."""
    return subprocess.list2cmdline([str(path)]) if sys.platform == "win32" else shlex.quote(str(path))


def describe(a: Artifact) -> str:
    parts = [a.kind, a.vendor, a.version]
    if a.variant:
        parts.append(a.variant)
    if a.kind == "runtime":
        parts.append(f"{a.os}-{a.arch}")
    return " ".join(parts)


def cmd_list(args: argparse.Namespace, index: list[Artifact]) -> int:
    host_os, host_arch = host_platform()
    rows = [a for a in index if args.kind in (None, a.kind) and args.vendor in (None, a.vendor)]
    rows.sort(key=lambda a: (a.kind, a.vendor, a.os, a.arch, a.variant or "", version_key(a.version)))
    if not rows:
        raise UserError("no artifact matches this filter (run `oaax-manager list` to see everything)")
    header = ("KIND", "VENDOR", "VERSION", "VARIANT", "OS", "ARCH", "SIZE", "")
    table = [header] + [
        (a.kind, a.vendor, a.version, a.variant or "-", a.os, a.arch, human_size(a.size),
         "*" if a.kind == "runtime" and a.matches_host(host_os, host_arch) else "")
        for a in rows
    ]
    widths = [max(len(r[i]) for r in table) for i in range(len(header))]
    for row in table:
        print("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip())
    print(f"\n* = runtime for this machine ({host_os}-{host_arch}); toolchains are Docker images and run anywhere with Docker.")
    return 0


def resolve(args: argparse.Namespace, index: list[Artifact]) -> Artifact:
    """Pick exactly one artifact or explain what to specify; never guess between variants."""
    candidates = [a for a in index if a.kind == args.kind and a.vendor == args.vendor]
    if not candidates:
        known = sorted({a.vendor for a in index if a.kind == args.kind})
        other = sorted({a.kind for a in index if a.vendor == args.vendor})
        if other:
            raise UserError(f"no {args.kind} for vendor {args.vendor!r}, but it has a {' and a '.join(other)}: oaax-manager fetch {other[0]} {args.vendor}")
        raise UserError(f"no {args.kind} for vendor {args.vendor!r}. Available: {', '.join(known) or 'none in this index'}")
    where = ""
    if args.kind == "runtime":
        host_os, host_arch = host_platform()
        want_os, want_arch = args.os or host_os, args.arch or host_arch
        platforms = sorted({f"{a.os}-{a.arch}" for a in candidates})
        candidates = [a for a in candidates if a.os == want_os and a.arch == want_arch]
        where = f" for {want_os}-{want_arch}"
        if not candidates:
            raise UserError(
                f"no {args.vendor} runtime for {want_os}-{want_arch}. Available for {args.vendor}: {', '.join(platforms)}. "
                "Pass --os/--arch to fetch a build for another machine."
            )
    if args.version:
        versions = sorted({a.version for a in candidates}, key=version_key)
        candidates = [a for a in candidates if a.version == args.version]
        if not candidates:
            raise UserError(f"no {args.kind} {args.vendor} version {args.version}{where}. Versions available{where}: {', '.join(versions)}")
    if args.variant:  # before the newest-version pick: the newest version may not have the build you asked for
        wanted = [a for a in candidates if a.variant == args.variant]
        if not wanted:
            have = sorted({a.variant for a in candidates if a.variant})
            raise UserError(
                f"no {args.vendor} {args.kind} with variant {args.variant!r}{where}. "
                + (f"Variants available{where}: {', '.join(have)}." if have else "It has no variants: leave --variant out.")
                + (" Pass --os/--arch to look at another platform." if args.kind == "runtime" else "")
            )
        candidates = wanted
    if not args.version:  # default: the newest version that exists for this platform (and variant)
        newest = max(version_key(a.version) for a in candidates)
        candidates = [a for a in candidates if version_key(a.version) == newest]
    if len(candidates) > 1:
        options = ", ".join(sorted(a.variant or "-" for a in candidates))
        raise UserError(f"several builds match; choose one with --variant ({options})")
    return candidates[0]


def cmd_fetch(args: argparse.Namespace, index: list[Artifact]) -> int:
    if args.kind == "toolchain" and (args.os or args.arch):
        raise UserError("--os/--arch only apply to runtimes (toolchains are Docker images)")
    if args.kind == "runtime" and args.force:
        raise UserError("--force only applies to toolchains; delete the runtime directory to fetch it again")
    artifact = resolve(args, index)
    out = Path(args.output)
    if artifact.kind == "toolchain":
        return fetch_toolchain(artifact, out, args.force)
    return fetch_runtime(artifact, out)


def toolchain_filename(a: Artifact) -> str:
    """The version is part of the name, so fetching 2.1.0 into the same -o never replaces the verified 2.0.0 (nor shares its .part)."""
    path = Path(a.filename)
    return a.filename if a.version in a.filename else f"{path.stem}-{a.version}{path.suffix}"


def fetch_toolchain(a: Artifact, out: Path, force: bool) -> int:
    dest = out / toolchain_filename(a)
    if dest.parent.resolve() != out.resolve():  # the name's own directory, not where dest points: the tar may be a link to another disk
        raise FetchError(f"refusing to write outside {out}")
    if dest.is_dir():
        raise UserError(f"{dest} is a directory")
    with fetch_lock(dest):
        verified = False
        if dest.is_file() and not force and dest.stat().st_size == a.size:  # another size cannot match: no need to hash it
            print(f"Checking the existing {dest.name} ({human_size(a.size)}); hashing it can take a while ...")
            verified = sha256_file(dest) == a.sha256
        if verified:
            print(f"{dest} is already downloaded and verified")
        else:
            print(f"Downloading {describe(a)} ({human_size(a.size)})")
            check_disk_space(out, a.size - part_bytes(dest))
            download(a.url, dest, a.size, a.sha256)
            print(f"Verified sha256 and saved {dest}")
    print(f"Load it into Docker with:  docker load -i {quote(dest)}\n(the image name and tag come from the tar; check `docker image ls`)")
    return 0


def fetch_runtime(a: Artifact, out: Path) -> int:
    name = "-".join(["runtime", a.vendor, a.version, a.os, a.arch] + ([a.variant] if a.variant else []))
    dest = out / name
    if dest.parent.resolve() != out.resolve():
        raise FetchError(f"refusing to write outside {out}")
    with fetch_lock(dest):
        if dest.exists() or dest.is_symlink():
            return report_existing(dest, a)
        print(f"Downloading {describe(a)} ({human_size(a.size)})")
        archive = out / f"{name}-{a.filename}"
        check_disk_space(out, 3 * a.size - part_bytes(archive))  # archive + extracted files, minus what an interrupted run already downloaded
        download(a.url, archive, a.size, a.sha256)
        try:
            files = safe_extract(archive, dest, a.sha256)
        finally:
            with contextlib.suppress(OSError):  # a locked archive must not turn a good extraction into an error
                archive.unlink(missing_ok=True)  # verified, but useless once extracted or refused
    print(f"Verified and extracted {len(files)} files to {dest}")
    print_libraries(dest, files)
    return 0


def report_existing(dest: Path, a: Artifact) -> int:
    """An existing target counts as done only if this tool completed it for this exact build and its files are still what was extracted."""
    print(f"Checking the extracted files of {dest} (hashing them can take a while) ...")
    files = verify_extracted(dest, a.sha256)
    if files is None:
        raise UserError(f"{dest} exists but was not completed by this oaax-manager for this build; delete it and run again")
    print(f"{dest} is already fetched: its {len(files)} files still match the sha256 and permissions recorded when they were extracted "
          f"from the verified archive ({a.sha256[:12]}...); files you added are not checked; delete it to fetch again")
    print_libraries(dest, files)
    return 0


def print_libraries(dest: Path, files: list[str]) -> None:
    for lib in files:
        if Path(lib).name in ("libRuntimeLibrary.so", "RuntimeLibrary.dll"):
            print(f"Runtime library: {dest / lib}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oaax-manager", description="List and fetch OAAX runtimes and toolchains.")
    parser.add_argument("--version", action="version", version=f"oaax-manager {__version__}")
    parser.add_argument("--index", type=Path, help="use this index.json instead of the packaged one (mirrors, tests)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="show the available artifacts")
    p_list.add_argument("--kind", choices=("runtime", "toolchain"))
    p_list.add_argument("--vendor")
    p_list.set_defaults(func=cmd_list)

    p_fetch = sub.add_parser("fetch", help="download and verify one artifact")
    p_fetch.add_argument("kind", choices=("runtime", "toolchain"))
    p_fetch.add_argument("vendor", help="see `oaax-manager list` (e.g. cpu, intel, nvidia-ort, nvidia-trt, hailo, deepx)")
    p_fetch.add_argument("--artifact-version", dest="version", help="default: the newest version available for your platform")
    p_fetch.add_argument("--variant", help="needed when several builds exist (e.g. cuda12)")
    p_fetch.add_argument("--os", choices=("linux", "windows", "macos"), help="runtimes only; default: this machine")
    p_fetch.add_argument("--arch", choices=("x86_64", "aarch64"), help="runtimes only; default: this machine")
    p_fetch.add_argument("-o", "--output", default=".", help="directory to write into (default: current directory)")
    p_fetch.add_argument("--force", action="store_true", help="toolchains: download again even if already present and verified")
    p_fetch.set_defaults(func=cmd_fetch)
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 9):
        print(f"error: oaax-manager needs Python 3.9 or newer (this is {sys.version.split()[0]})", file=sys.stderr)
        return 1
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, load_index(args.index))
    except (UserError, FetchError, IndexError_) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:  # unwritable or conflicting output path, disk errors
        print(f"error: {exc} (check that the output directory, -o, exists and is writable)", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted (partial downloads are kept; run again to resume)", file=sys.stderr)
        return 130


def run() -> None:
    """Entry point for the zipapp (`-m oaax_manager.cli:run`): zipapp drops main()'s return value."""
    sys.exit(main())


if __name__ == "__main__":
    run()
