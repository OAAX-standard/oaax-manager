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


class IndexError_(Exception):
    """The index file is unreadable or malformed."""


@dataclass(frozen=True)
class Artifact:
    kind: str  # "runtime" | "toolchain"
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


def version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.\-]", version))


def load_index(path: Path | None = None) -> list[Artifact]:
    """Load the packaged index, or the file at `path` (used for tests and mirrors)."""
    try:
        text = path.read_text() if path else resources.files("oaax_manager").joinpath("index.json").read_text()
        data = json.loads(text)
        base = data["base_url"].rstrip("/")
        parsed = urlparse(base)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")):
            raise ValueError(f"base_url must be https (http only for localhost): {base}")
        return [
            Artifact(
                kind=a["kind"], vendor=a["vendor"], version=a["version"], os=a["os"], arch=a["arch"],
                variant=a.get("variant"), key=a["key"], size=a["size"], sha256=a["sha256"],
                url=f"{base}/{a['key']}",
            )
            for a in data["artifacts"]
        ]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise IndexError_(f"cannot read the artifact index: {exc}") from exc
