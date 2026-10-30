"""The artifact index (shipped inside the package) and host platform detection."""

from __future__ import annotations

import json
import platform
import re
from urllib.parse import urlparse
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

ARCH_ALIASES = {"amd64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
OS_NAMES = {"linux": "linux", "windows": "windows", "darwin": "macos"}


NAME = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")  # vendor, version, variant, arch: they become part of file names
SHA256 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^\d+(\.\d+)*$")  # releases only: orderable, no pre-release spellings
KEY_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
KINDS = ("runtime", "toolchain", "wheel")
OSES = ("linux", "windows", "macos", "any")


class IndexError_(Exception):
    """The index file is unreadable or malformed."""


@dataclass(frozen=True)
class Artifact:
    kind: str  # "runtime" | "toolchain" (Docker image) | "wheel" (Python conversion toolchain)
    vendor: str
    version: str
    os: str  # linux | windows | macos | any
    arch: str  # x86_64 | aarch64 | any
    variant: str | None
    key: str
    size: int
    sha256: str
    url: str

    @property
    def filename(self) -> str:
        return self.key.rsplit("/", 1)[-1]

    def matches_host(self, host_os: str, host_arch: str) -> bool:
        return self.os in ("any", host_os) and self.arch in ("any", host_arch)


def host_platform() -> tuple[str, str]:
    """Return (os, arch) of this machine in index spelling; unknown values are passed through."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    return OS_NAMES.get(system, system), ARCH_ALIASES.get(machine, machine)


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def validate_entry(a: dict) -> None:
    """Reject anything that could escape the output directory or make a verification meaningless."""
    checks = [
        (a["kind"] in KINDS, "kind"),
        (a["os"] in OSES, "os"),
        (a["arch"] == "any" or bool(NAME.match(a["arch"])), "arch"),
        (bool(NAME.match(a["vendor"])), "vendor"),
        (bool(VERSION.match(a["version"])), "version"),
        (a.get("variant") is None or bool(NAME.match(a["variant"])), "variant"),
        (type(a["size"]) is int and a["size"] > 0, "size"),
        (isinstance(a["sha256"], str) and bool(SHA256.match(a["sha256"])), "sha256"),
        (isinstance(a["key"], str) and all(KEY_PART.match(p) for p in a["key"].split("/")), "key"),
        (a["key"].rsplit("/", 1)[-1].split(".")[0].lower() not in WINDOWS_RESERVED, "key"),
    ]
    for ok, field in checks:
        if not ok:
            raise ValueError(f"invalid {field} in entry {a.get('key')!r}")


def load_index(path: Path | None = None) -> list[Artifact]:
    """Load the packaged index, or the file at `path` (used for tests and mirrors)."""
    try:
        text = path.read_text() if path else resources.files("oaax_manager").joinpath("index.json").read_text()
        data = json.loads(text)
        base = data["base_url"].rstrip("/")
        parsed = urlparse(base)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")):
            raise ValueError(f"base_url must be https (http only for localhost): {base}")
        for a in data["artifacts"]:
            validate_entry(a)
        return [
            Artifact(
                kind=a["kind"], vendor=a["vendor"], version=a["version"], os=a["os"], arch=a["arch"],
                variant=a.get("variant"), key=a["key"], size=a["size"], sha256=a["sha256"],
                url=f"{base}/{a['key']}",
            )
            for a in data["artifacts"]
        ]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IndexError_(f"cannot read the artifact index: {exc}") from exc
