"""Everything `scan` reads from the machine, in one place so tests can replace it with a fake.

Read-only and unprivileged: files under /sys, /proc and /etc, `ldconfig -p`, and a few vendor tools run with a fixed
argument list (never through a shell) and a timeout. No vendor library is ever loaded.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .index import ARCH_ALIASES, OS_NAMES

NOT_FOUND, TIMED_OUT = 127, 124  # the shell's exit codes for a missing program and for `timeout`


@dataclass(frozen=True)
class PciDevice:
    vendor: str  # lowercase hex without 0x, e.g. "10de"
    device: str
    pci_class: str  # first four hex digits of the class code ("0300" = VGA); "" when unknown (Windows)


class System:
    """The real machine. Methods never raise: a missing file or tool is an empty answer."""

    @property
    def os(self) -> str:
        return OS_NAMES.get(platform.system().lower(), platform.system().lower())

    @property
    def arch(self) -> str:
        machine = platform.machine().lower()
        return ARCH_ALIASES.get(machine, machine)

    @property
    def kernel(self) -> str:
        return platform.release()

    def env(self) -> dict[str, str]:
        return dict(os.environ)

    def run(self, argv: list[str], timeout: float = 15) -> tuple[int, str]:
        """(exit code, stdout+stderr). 127 if the program does not exist, 124 if it did not answer in time."""
        try:  # in an empty directory of its own: hailortcli writes hailort.log into the working directory
            with tempfile.TemporaryDirectory(prefix="oaax-scan-") as cwd:
                done = subprocess.run(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
                                      text=True, errors="replace", cwd=cwd)
        except FileNotFoundError:
            return NOT_FOUND, ""
        except subprocess.TimeoutExpired:
            return TIMED_OUT, ""
        except OSError as exc:  # permission denied, exec format error
            return NOT_FOUND, str(exc)
        return done.returncode, done.stdout + done.stderr

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def read(self, path: str) -> str | None:
        try:
            return Path(path).read_text(errors="replace")
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def listdir(self, path: str) -> list[str]:
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def libraries(self) -> str:
        """`ldconfig -p`: every shared library the dynamic loader finds ('' where there is none)."""
        if self.os != "linux":
            return ""
        ldconfig = self.which("ldconfig") or "/sbin/ldconfig"  # not on a normal user's PATH on Debian
        code, out = self.run([ldconfig, "-p"])
        return out if code == 0 else ""

    def glibc(self) -> tuple[int, int] | None:
        try:
            match = re.search(r"glibc (\d+)\.(\d+)", os.confstr("CS_GNU_LIBC_VERSION") or "")
        except (ValueError, OSError, AttributeError):
            return None
        return (int(match[1]), int(match[2])) if match else None

    def avx2(self) -> bool | None:
        """None when it cannot be told (not x86, or no way to ask)."""
        if self.arch != "x86_64":
            return None
        if self.os == "windows":
            try:
                import ctypes
                return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(40))  # PF_AVX2_INSTRUCTIONS_AVAILABLE
            except (AttributeError, OSError):
                return None
        cpuinfo = self.read("/proc/cpuinfo")
        return None if cpuinfo is None else bool(re.search(r"^flags\s*:.*\bavx2\b", cpuinfo, re.M))

    def device_model(self) -> str:
        """Board name from the device tree ('Raspberry Pi 5 Model B', 'NVIDIA Jetson Orin Nano ...'); '' on PCs."""
        return (self.read("/proc/device-tree/model") or "").strip("\x00 \n")

    def cpu_model(self) -> str:
        if self.os == "linux":
            match = re.search(r"^(?:model name|Model|Hardware)\s*:\s*(.+)$", self.read("/proc/cpuinfo") or "", re.M)
            if match:
                return match[1].strip()
        if self.os == "windows":  # platform.processor() there is "Intel64 Family 6 Model 183 ..."; the marketing name is in the registry
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                    return " ".join(winreg.QueryValueEx(key, "ProcessorNameString")[0].split())
            except (ImportError, OSError):
                pass
        return platform.processor() or platform.machine()

    def cpu_vendor(self) -> str:
        """'GenuineIntel' and friends ('' if unknown)."""
        if self.os == "linux":
            match = re.search(r"^vendor_id\s*:\s*(\S+)", self.read("/proc/cpuinfo") or "", re.M)
            return match[1] if match else ""
        return "GenuineIntel" if "Intel" in platform.processor() else ""

    def os_release(self) -> dict[str, str]:
        """/etc/os-release as a dict, lowercase keys ({} on Windows)."""
        fields = {}
        for line in (self.read("/etc/os-release") or "").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields[key.strip().lower()] = value.strip().strip('"')
        return fields

    def pci(self) -> list[PciDevice]:
        if self.os == "windows":
            return self._windows_pci()
        found = []
        for name in self.listdir("/sys/bus/pci/devices"):
            base = f"/sys/bus/pci/devices/{name}"
            vendor, device, code = (self.read(f"{base}/{f}") for f in ("vendor", "device", "class"))
            if vendor and device:
                found.append(PciDevice(vendor.strip()[2:].lower(), device.strip()[2:].lower(), (code or "")[2:6].lower()))
        return found

    def _windows_pci(self) -> list[PciDevice]:
        try:
            import winreg
            found = []
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\PCI") as key:
                for i in range(winreg.QueryInfoKey(key)[0]):  # subkeys look like VEN_10DE&DEV_24B0&SUBSYS_...
                    match = re.match(r"VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})", winreg.EnumKey(key, i), re.I)
                    if match:
                        found.append(PciDevice(match[1].lower(), match[2].lower(), ""))
            return found
        except (ImportError, OSError):
            return []
