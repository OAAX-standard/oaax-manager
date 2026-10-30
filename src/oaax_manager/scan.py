"""`oaax-manager scan`: which accelerators this machine has, and whether an OAAX runtime can use them.

The requirements are the ones of the OAAX docs (docs.oaax.org, one page per chip); the probes follow the AI Manager
plugin's `accl_manager`. Which builds exist comes from the packaged index, so a new variant there is considered
without a code change. Nothing is installed, loaded or changed: see `system.py` for what is read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .system import NOT_FOUND, TIMED_OUT, System

DOCS = "https://docs.oaax.org"
Version = tuple  # (major, minor, ...) as ints


class ScanError(Exception):
    """The machine cannot be scanned (an OS without any OAAX runtime)."""


@dataclass
class Check:
    name: str
    status: str  # ok | fail | warn | skip
    detail: str = ""
    fix: str = ""


@dataclass
class Runtime:
    """One `fetch runtime <vendor>` target. `usable` is best first; None stands for 'no variant'."""
    vendor: str
    usable: list = field(default_factory=list)
    rejected: dict = field(default_factory=dict)  # variant -> why not
    notes: dict = field(default_factory=dict)  # variant -> what to know when using it


@dataclass
class Chip:
    name: str
    found: bool = False
    hardware: str = ""
    checks: list = field(default_factory=list)
    runtimes: list = field(default_factory=list)
    docs: str = ""

    @property
    def status(self) -> str:
        if not self.found:
            return "absent"
        return "ready" if any(r.usable for r in self.runtimes) else "unusable"

    @property
    def problems(self) -> list:
        return [c for c in self.checks if c.status == "fail"]


@dataclass
class Report:
    machine: str
    docker: bool
    chips: list

    def runtime(self, vendor: str) -> Optional[Runtime]:
        return next((r for c in self.chips for r in c.runtimes if r.vendor == vendor), None)

    def why_not(self, vendor: str) -> str:
        """The first reason the chip of this vendor cannot be used, for an error message."""
        chip = next((c for c in self.chips if any(r.vendor == vendor for r in c.runtimes)), None)
        if chip is None or not chip.found:
            return "no such hardware found"
        runtime = self.runtime(vendor)
        reasons = [f"{c.name}: {c.detail}" for c in chip.problems] or list(runtime.rejected.values())
        return "; ".join(reasons[:2]) or "no build fits this machine"


def parse_version(text: str) -> Version:
    match = re.search(r"\d+(?:\.\d+)*", text or "")
    return tuple(int(p) for p in match[0].split(".")) if match else ()


def fmt(version: Version) -> str:
    return ".".join(map(str, version))


def ubuntu(version: Version) -> str:
    """(22, 4) -> '22.04', the spelling of Ubuntu releases and of the index variants."""
    return f"{version[0]}.{version[1]:02d}"


class Host:
    """What the checks know about the machine: the System plus values derived from it once."""

    def __init__(self, system: System, index: list):
        self.s = system
        self.os, self.arch = system.os, system.arch
        self.index = index
        self.libs = system.libraries()
        self.ubuntu = self._ubuntu_version()
        self.pci = system.pci()

    def _ubuntu_version(self) -> Version:
        """Ubuntu version this OS corresponds to (Debian 11/12/13 = Ubuntu 20.04/22.04/24.04, as the AI Manager does); () if neither."""
        info = self.s.os_release()
        version = parse_version(info.get("version_id", ""))
        if info.get("id") == "ubuntu":
            return version
        if info.get("id") == "debian":
            return {11: (20, 4), 12: (22, 4), 13: (24, 4)}.get(version[0] if version else 0, ())
        return ()

    @property
    def os_label(self) -> str:
        if self.os == "windows":
            return "Windows"
        info = self.s.os_release()
        return info.get("pretty_name") or info.get("id") or self.os

    def has_lib(self, soname: str) -> bool:
        tag = {"x86_64": "x86-64", "aarch64": "AArch64"}.get(self.arch, "")  # a 32-bit copy does not count
        pattern = rf"^\s*{re.escape(soname)}(?:\.\d+)* \(([^)]*)\)"  # CUDA 11 ships libcudart.so.11.0 for the soname libcudart.so.11
        if any(tag in m[1] for m in re.finditer(pattern, self.libs, re.M)):
            return True
        dirs = [d for d in self.s.env().get("LD_LIBRARY_PATH", "").split(":") if d]  # the loader also looks here
        return any(n == soname or n.startswith(soname + ".") for d in dirs for n in self.s.listdir(d))

    def variants(self, vendor: str) -> list:
        """Variant names of every indexed runtime of this vendor for this OS and CPU."""
        return sorted({a.variant for a in self.index
                       if a.kind == "runtime" and a.vendor == vendor and a.os == self.os and a.arch == self.arch},
                      key=lambda v: v or "")

    def pci_count(self, vendor: str, classes: tuple = (), unknown_ok: bool = False) -> int:
        """Devices of this vendor (and PCI class prefixes). Windows cannot tell the class: `unknown_ok` counts such devices."""
        return sum(1 for d in self.pci if d.vendor == vendor and (not classes or d.pci_class.startswith(classes) or (unknown_ok and not d.pci_class)))


def system_checks(h: Host, glibc: Version, min_ubuntu: Version, libs: tuple = ("libgomp.so.1",), avx2: bool = False) -> list:
    """What every runtime needs from the OS: version, glibc, shared libraries, AVX2."""
    if h.os == "windows":
        return [Check("system", "skip", "not checked on Windows (the runtime ships its DLLs)")] + avx2_checks(h, avx2)
    checks = []
    if not h.ubuntu:
        checks.append(Check("OS", "warn", f"{h.os_label}: the builds target Ubuntu/Debian, only glibc is checked"))
    elif h.ubuntu < min_ubuntu:
        checks.append(Check("OS", "fail", f"{h.os_label} is older than Ubuntu {ubuntu(min_ubuntu)}", f"Upgrade to Ubuntu {ubuntu(min_ubuntu)} or newer."))
    else:
        checks.append(Check("OS", "ok", h.os_label))
    have = h.s.glibc()
    if have is None:
        checks.append(Check("glibc", "fail", "not found (musl, as on Alpine?)", "The runtimes are built for glibc: use Ubuntu or Debian."))
    elif have < glibc:
        checks.append(Check("glibc", "fail", f"{fmt(have)}, needs {fmt(glibc)}", f"The OS is too old: glibc {fmt(glibc)} or newer is required."))
    else:
        checks.append(Check("glibc", "ok", fmt(have)))
    if not h.libs:
        checks.append(Check("libraries", "warn", "`ldconfig -p` gave no answer, not checked"))
    for lib in libs if h.libs else ():
        package = {"libgomp.so.1": "libgomp1", "libatomic.so.1": "libatomic1", "libstdc++.so.6": "libstdc++6"}.get(lib, lib)
        ok = h.has_lib(lib)
        checks.append(Check(lib, "ok" if ok else "fail", "found" if ok else "missing",
                            "" if ok else f"sudo apt-get install {package}"))
    return checks + avx2_checks(h, avx2)


def avx2_checks(h: Host, needed: bool) -> list:
    if not (needed and h.arch == "x86_64"):
        return []
    has = h.s.avx2()
    return [Check("AVX2", {True: "ok", False: "fail", None: "warn"}[has], {True: "supported", False: "not supported", None: "could not be read"}[has],
                  "The runtime is built for AVX2 and cannot run on this CPU." if has is False else "")]


def finish(chip: Chip, h: Host, runtime: Runtime, wanted: list) -> Runtime:
    """Keep the wanted variants that the index has for this machine; a failed check of the chip leaves none."""
    have = h.variants(runtime.vendor)
    for variant in wanted:
        if variant not in have:
            runtime.rejected.setdefault(variant, f"not in the index for {h.os}-{h.arch}")
    runtime.usable = [] if chip.problems else [v for v in wanted if v in have and v not in runtime.rejected]
    return runtime


# ---------------------------------------------------------------- CPU

def scan_cpu(h: Host) -> Chip:
    x86 = h.arch == "x86_64"
    model = h.s.device_model() or h.s.cpu_model()  # ARM's /proc/cpuinfo has no model name: the board's is the useful one
    chip = Chip("CPU", True, f"{model} ({h.arch})" if model not in ("", h.arch) else f"{h.arch} CPU", docs=f"{DOCS}/CPU/")
    libs = ("libstdc++.so.6",) + (("libgomp.so.1",) if x86 else ())
    chip.checks = system_checks(h, (2, 29), (20, 4), libs, avx2=True)
    chip.runtimes = [finish(chip, h, Runtime("cpu"), [None])]
    return chip


# ---------------------------------------------------------------- Intel

def scan_intel(h: Host) -> Chip:
    chip = Chip("Intel", docs=f"{DOCS}/Intel/")
    if h.arch != "x86_64":
        return chip
    gpu = h.pci_count("8086", ("03",))
    npu = h.pci_count("8086", ("1200",)) if h.os == "linux" else 0
    cpu = h.s.cpu_vendor() == "GenuineIntel"
    if not (cpu or gpu or npu):
        return chip
    chip.found = True
    chip.hardware = ", ".join(p for p in ("CPU: " + h.s.cpu_model() if cpu else "", f"{gpu} GPU" if gpu else "", f"{npu} NPU" if npu else "") if p)
    chip.checks = system_checks(h, (2, 34), (22, 4), avx2=True)
    if h.os == "linux":  # only the CPU is needed; the GPU and NPU run when their driver is there, else the runtime falls back to the CPU
        if gpu and not h.has_lib("libOpenCL.so.1"):
            chip.checks.append(Check("GPU driver", "warn", "no OpenCL: the runtime will use the CPU",
                                     "sudo apt-get install ocl-icd-libopencl1 intel-opencl-icd"))
        if npu and not h.s.exists("/dev/accel/accel0"):
            chip.checks.append(Check("NPU driver", "warn", "no /dev/accel/accel0: the runtime will use the CPU",
                                     "Install https://github.com/intel/linux-npu-driver (Ubuntu 22.04+, kernel 6.6+)."))
    chip.runtimes = [finish(chip, h, Runtime("intel"), [None])]
    return chip


# ---------------------------------------------------------------- NVIDIA

# Driver needed per CUDA major (docs.oaax.org/NVIDIA, "NVIDIA driver").
CUDA_MIN_DRIVER = {11: (450, 80), 12: (525, 60), 13: (580,)}
# GPU architectures (compute capability x10) each CUDA major can run: (first sm, last sm, first CUDA, last CUDA; 0 = no end).
# From NVIDIA's CUDA release notes, as in the AI Manager plugin. Newer than the table: assumed compatible.
SM_SUPPORT = ((35, 37, 11, 11), (50, 72, 11, 12), (75, 90, 11, 0), (100, 121, 12, 0))
CUFFT_SONAME = {11: 10, 12: 11, 13: 12}  # libcufft's own major differs from the CUDA major
DEFAULT_TRT = 10  # the Docker toolchain builds TensorRT 10 engines, and an engine only loads in the same TensorRT major
NVIDIA_VARIANT = re.compile(r"^(?:(?P<flavor>jetson|sbsa)-)?(?:ubuntu(?P<ubuntu>\d+\.\d+)-)?(?:trt(?P<trt>\d+)-)?cuda(?P<cuda>\d+)$")


@dataclass
class Smi:
    gpus: list  # [(name, sm as int or 0)]
    driver: Version
    cuda_max: Version
    error: str = ""
    driver_text: str = ""


def sm_supports(sm: int, cuda: int) -> bool:
    if not sm:
        return True  # unknown: do not guess
    if sm < SM_SUPPORT[0][0]:
        return False
    for first, last, low, high in SM_SUPPORT:
        if first <= sm <= last:
            return cuda >= low and (not high or cuda <= high)
    return True


def query_smi(h: Host) -> Smi:
    code, out = h.s.run(["nvidia-smi", "--query-gpu=name,compute_cap,driver_version", "--format=csv,noheader"])
    if code != 0:
        return Smi([], (), (), nvidia_smi_error(h, code, out))
    gpus, driver, driver_text = [], (), ""
    for line in out.strip().splitlines()[:64]:
        name, _, rest = line.partition(",")
        cap, _, drv = rest.partition(",")
        if not name.strip() or not re.fullmatch(r"\s*\d+(\.\d+)+\s*", drv):  # a driver we cannot read is never a pass
            continue
        gpus.append((name.strip(), int(round(float(cap) * 10)) if re.fullmatch(r"\s*\d+\.\d+\s*", cap) else 0))
        driver = driver or parse_version(drv)
        driver_text = driver_text or drv.strip()
    if not gpus:
        return Smi([], (), (), f"nvidia-smi answered but listed no GPU with a driver version: {out.strip()[:80] or 'empty output'}")
    _, xml = h.s.run(["nvidia-smi", "-q", "-x"])  # newer drivers report <cuda_umd_version> in place of <cuda_version>
    cuda = re.search(r"<cuda_umd_version>([^<]+)<", xml) or re.search(r"<cuda_version>([^<]+)<", xml)
    return Smi(gpus, driver, parse_version(cuda[1]) if cuda else (), driver_text=driver_text)


def nvidia_smi_error(h: Host, code: int, out: str) -> str:
    """Why nvidia-smi does not work, as an advice a person can act on."""
    if code == TIMED_OUT:
        return "nvidia-smi did not answer within 15 s (a hung driver: reboot)"
    if code == NOT_FOUND:
        return "nvidia-smi not found: the NVIDIA driver is not installed (`sudo ubuntu-drivers install`, or https://www.nvidia.com/drivers)"
    if "version mismatch" in out:
        kernel = (h.s.read("/sys/module/nvidia/version") or "").strip()
        library = re.search(r"NVML library version:\s*(\S+)", out)
        have = f": the kernel module is {kernel or '?'}, the user library {library[1] if library else '?'}"
        return (f"driver/library version mismatch{have}. Reboot; if it persists, reinstall one matching set of NVIDIA "
                "packages (`dpkg -l | grep -i nvidia`)")
    if "couldn't communicate" in out.lower() or "NVIDIA-SMI has failed" in out:
        return ("the driver is not loaded (a kernel update without rebuilding the module is the usual cause): "
                "reboot, or `sudo modprobe nvidia`; reinstall the driver if it fails")
    return f"nvidia-smi failed ({code}): {out.strip().splitlines()[0] if out.strip() else 'no output'}"


def cuda_roots(h: Host) -> dict:
    """Windows: {cuda major: install directory} from the CUDA_PATH_V<major>_<minor> variables the installer sets."""
    roots = {}
    for key, value in h.s.env().items():
        match = re.fullmatch(r"CUDA_PATH_V(\d+)_\d+", key.upper())
        if match:
            roots[int(match[1])] = value
    return roots


def cuda_installed(h: Host, major: int) -> tuple:
    """(ok, detail, fix): are the CUDA libraries of this major findable? ORT does not bundle them."""
    if h.os == "windows":
        root = cuda_roots(h).get(major)
        if not root:
            return False, f"CUDA {major} toolkit not installed", f"Install the CUDA {major} Toolkit."
        paths = [p.strip().lower().rstrip("\\/") for p in h.s.env().get("PATH", "").split(";")]
        if not any(p.startswith(root.lower().rstrip("\\/")) for p in paths):
            return False, f"{root} is not on PATH", f"Add {root}\\bin to PATH and restart."
        return True, root, ""
    libs = [f"libcudart.so.{major}", f"libcublas.so.{major}", f"libcublasLt.so.{major}"]
    if major in CUFFT_SONAME:
        libs.append(f"libcufft.so.{CUFFT_SONAME[major]}")
    missing = [lib for lib in libs if not h.has_lib(lib)]
    if missing:
        return False, f"{', '.join(missing)} missing", f"Install the CUDA {major} runtime libraries (libcudart, libcublas)."
    return True, f"CUDA {major} libraries found", ""


def nvidia_flavor(h: Host) -> str:
    if h.os == "linux" and h.arch == "aarch64":
        return "jetson" if h.s.exists("/etc/nv_tegra_release") else "sbsa"
    return ""


def scan_nvidia(h: Host) -> Chip:
    chip = Chip("NVIDIA", docs=f"{DOCS}/NVIDIA/")
    flavor = nvidia_flavor(h)
    no_pci = False
    if flavor == "jetson":
        chip.found, chip.hardware = True, h.s.device_model() or "NVIDIA Jetson"
    elif h.pci_count("10de", ("03",), unknown_ok=True):
        chip.found = True
    elif h.s.which("nvidia-smi"):  # WSL and containers show no PCI GPU: a nvidia-smi that lists one is the evidence
        chip.found = True
        no_pci = True
    else:
        return chip
    ort, trt = Runtime("nvidia-ort"), Runtime("nvidia-trt")
    chip.runtimes = [ort, trt]
    smi = Smi([], (), ())
    if flavor != "jetson":  # Jetson's nvidia-smi is limited or absent: JetPack provides the driver
        smi = query_smi(h)
        if smi.error and no_pci:  # only the tool was there, no card behind it
            return Chip("NVIDIA", docs=chip.docs)
        if smi.error:
            ids = ", ".join(f"10de:{d.device}" for d in h.pci if d.vendor == "10de" and d.pci_class.startswith("03"))
            chip.hardware = chip.hardware or f"NVIDIA GPU (PCI {ids})"
            chip.checks.append(Check("driver", "fail", smi.error))
            return finish_nvidia(chip, h, [], [])
        chip.hardware = ", ".join(f"{n} (SM {s / 10:g})" if s else n for n, s in smi.gpus)
        chip.checks.append(Check("driver", "ok", f"{smi.driver_text}, supports up to CUDA {fmt(smi.cuda_max) or '?'}"))
    chip.checks += system_checks(h, (2, 29), (20, 4))
    sm = smi.gpus[0][1] if smi.gpus else 0  # both runtimes use GPU 0
    return finish_nvidia(chip, h, nvidia_builds(h, "nvidia-ort", flavor, smi, sm, ort), nvidia_builds(h, "nvidia-trt", flavor, smi, sm, trt))


def finish_nvidia(chip: Chip, h: Host, ort_usable: list, trt_usable: list) -> Chip:
    for runtime, usable in zip(chip.runtimes, (ort_usable, trt_usable)):
        runtime.usable = [] if chip.problems else usable
    return chip


def nvidia_builds(h: Host, vendor: str, flavor: str, smi: Smi, sm: int, runtime: Runtime) -> list:
    """Check every indexed variant of this machine's platform; fill runtime.rejected/notes; return the usable ones, best first."""
    usable = []
    if not h.variants(vendor):
        runtime.rejected[None] = f"no {vendor} build for {h.os}-{h.arch}"
    for variant in h.variants(vendor):
        match = NVIDIA_VARIANT.match(variant or "")
        if not match:
            runtime.rejected[variant] = "unknown variant name: upgrade oaax-manager"
            continue
        if (match["flavor"] or "") != flavor:  # another kind of machine (Jetson, SBSA): not an option here
            continue
        cuda = int(match["cuda"])
        reason = reject_nvidia(h, vendor, flavor, smi, sm, match, cuda)
        if reason:
            runtime.rejected[variant] = reason
            continue
        usable.append(variant)
        if variant == "cuda12" and vendor == "nvidia-ort" and h.os == "linux":
            runtime.notes[variant] = "needs cuDNN 8 next to the runtime (known issue of this package, see the NVIDIA page)"
    prefer = lambda v: (int(NVIDIA_VARIANT.match(v)["trt"] or DEFAULT_TRT) != DEFAULT_TRT, -int(NVIDIA_VARIANT.match(v)["cuda"]), v)  # noqa: E731
    return sorted(usable, key=prefer)


def reject_nvidia(h: Host, vendor: str, flavor: str, smi: Smi, sm: int, match: re.Match, cuda: int) -> str:
    if flavor != "jetson":  # JetPack's driver cannot be queried; its CUDA is what the libraries say
        need = CUDA_MIN_DRIVER.get(cuda)
        if need is None:
            return f"the driver requirement of CUDA {cuda} is unknown: upgrade oaax-manager"
        if smi.driver and smi.driver < need:
            return f"CUDA {cuda} needs driver {fmt(need)} or newer, this is {smi.driver_text}"
    if not sm_supports(sm, cuda):
        return f"GPU architecture SM {sm / 10:g} is not supported by CUDA {cuda}"
    if match["ubuntu"] and h.os == "linux" and h.ubuntu and h.ubuntu < parse_version(match["ubuntu"]):
        return f"needs Ubuntu {match['ubuntu']} or newer, this is {ubuntu(h.ubuntu)}"
    if vendor == "nvidia-ort":
        if cuda >= 13 and h.os == "linux" and h.ubuntu and h.ubuntu < (22, 4):
            return "the CUDA 13 build needs Ubuntu 22.04 or newer"
        ok, detail, fix = cuda_installed(h, cuda)
        if not ok:
            return f"{detail}. {fix}"
    else:
        if sm and sm < 75:
            return f"the TensorRT toolchain, which builds the engine, needs compute capability 7.5 or newer (this GPU: {sm / 10:g})"
        if flavor == "jetson":  # JetPack provides CUDA and TensorRT; the TRT build is for JetPack 6 (CUDA 12, TensorRT 10)
            ok, detail, fix = cuda_installed(h, cuda)
            if not ok:
                return f"{detail}. {fix}"
            if not h.has_lib(f"libnvinfer.so.{match['trt']}"):
                have = sorted({m[1] for m in re.finditer(r"^\s*libnvinfer\.so\.(\d+)", h.libs, re.M)})
                return (f"the build needs TensorRT {match['trt']}, this JetPack has TensorRT {', '.join(have)}: update JetPack" if have
                        else f"TensorRT {match['trt']} (libnvinfer) is not installed: it comes with JetPack")
    return ""


# ---------------------------------------------------------------- Hailo

def scan_hailo(h: Host) -> Chip:
    chip = Chip("Hailo", docs=f"{DOCS}/Hailo/")
    if h.os != "linux":
        return chip
    nodes = [n for n in h.s.listdir("/sys/class/hailo_chardev")]
    cards = h.pci_count("1e60")
    if not (cards or nodes):
        return chip
    chip.found = True
    code, out = h.s.run(["hailortcli", "-v"])
    banner = re.search(r"HailoRT-CLI version (\d+\.\d+\.\d+)(?![\w.-])", out)  # not "4.20.0-rc1", not a number from a log line
    cli = parse_version(banner[1]) if code == 0 and banner else ()
    known = sorted({parse_version(v[len("hailort"):]) for v in h.variants("hailo") if v})
    identify = h.s.run(["hailortcli", "fw-control", "identify"], timeout=30)[1] if cli else ""
    kinds = {"HAILO8": "Hailo-8", "HAILO8L": "Hailo-8L"}
    names = [kinds.get(k, k) for k in re.findall(r"Device Architecture: (\w+)", identify)]
    counts = {n: names.count(n) for n in dict.fromkeys(names)}  # in order of appearance
    chip.hardware = (", ".join(f"{c}x {n}" for n, c in counts.items()) or f"{len(nodes) or cards}x Hailo") + (" (PCIe)" if cards else "")

    if any(n != "Hailo-8" for n in names):
        chip.checks.append(Check("chip", "warn", "only the Hailo-8 is verified with the OAAX runtime (not the Hailo-8L)"))
    driver = parse_version(h.s.read("/sys/module/hailo_pci/version") or "")
    loaded = h.s.exists("/sys/module/hailo_pci")
    chip.checks.append(Check("driver", "ok" if loaded else "fail", f"hailo_pci {(h.s.read('/sys/module/hailo_pci/version') or '').strip()}".strip() if loaded else "hailo_pci is not loaded",
                             "" if loaded else "Install hailort-pcie-driver (rebuild it after a kernel update), then reboot or `sudo modprobe hailo_pci`."))
    if loaded:  # without the driver there are no nodes either: one cause, one line
        chip.checks.append(Check("device nodes", "ok" if nodes else "fail", ", ".join(f"/dev/{n}" for n in nodes) if nodes else "no /dev/hailo*",
                                 "" if nodes else "The driver is not bound to the card: check `dmesg | grep -i hailo`."))
    if code == NOT_FOUND:
        chip.checks.append(Check("HailoRT", "fail", "hailortcli not found", "Install HailoRT (hailort_<version>_<arch>.deb) of the version of the driver."))
    elif not cli:
        chip.checks.append(Check("HailoRT", "fail", "`hailortcli -v` did not answer in time" if code == TIMED_OUT else "`hailortcli -v` gave no version"))
    else:
        supported = cli in known
        chip.checks.append(Check("HailoRT", "ok" if supported else "fail", fmt(cli) if supported else f"{fmt(cli)} has no OAAX runtime",
                                 "" if supported else f"Install HailoRT {', '.join(map(fmt, known))} (one runtime build per version)."))
        if loaded and driver and driver != cli:
            chip.checks.append(Check("driver = HailoRT", "fail", f"driver {fmt(driver)} but HailoRT {fmt(cli)}",
                                     "Install the same version of hailort and hailort-pcie-driver; each runtime bundles its own libhailort."))
    chip.checks += system_checks(h, (2, 29), (20, 4), ("libgomp.so.1", "libatomic.so.1"))
    chip.runtimes = [finish(chip, h, Runtime("hailo"), [f"hailort{fmt(cli)}"] if cli in known else [])]
    return chip


# ---------------------------------------------------------------- DeepX

def scan_deepx(h: Host) -> Chip:
    chip = Chip("DeepX", docs=f"{DOCS}/DEEPX/")
    if h.os != "linux":
        return chip
    nodes = [n for n in h.s.listdir("/dev") if n.startswith("dxrt")]
    cards = h.pci_count("1ff4")
    if not (cards or nodes):
        return chip
    chip.found = True
    chip.hardware = f"{cards or len(nodes)}x DEEPX NPU (PCIe)"
    loaded = h.s.exists("/sys/module/dxrt_driver")
    if loaded:
        chip.checks.append(Check("driver", "ok", "dxrt_driver loaded"))
    else:  # the module is built per kernel: after a kernel update the running one has none
        built = h.s.run([h.s.which("modinfo") or "/sbin/modinfo", "-n", "dxrt_driver"])[0] == 0  # /sbin is not on a user's PATH on Debian
        chip.checks.append(Check("driver", "fail", "dxrt_driver is not loaded" + ("" if built else f", and none is built for kernel {h.s.kernel}"),
                                 "Rebuild and install the NPU driver for this kernel (dx_rt_npu_linux_driver), see the DEEPX page." if not built
                                 else "sudo modprobe dxrt_driver"))
    if loaded:
        chip.checks.append(Check("device nodes", "ok" if nodes else "fail", ", ".join(f"/dev/{n}" for n in nodes) if nodes else "no /dev/dxrt*",
                                 "" if nodes else "The driver is not bound to the card: check `dmesg | grep -i dxrt`."))
    ok = False
    code, out = h.s.run(["dxrt-cli", "-i"])  # prints the version first, then aborts when there is no card: do not trust the exit code
    found = re.search(r"DXRT v(\d+\.\d+\.\d+)", out)
    if not found:
        chip.checks.append(Check("DX-RT", "fail", "dxrt-cli not found" if code == NOT_FOUND else "no DXRT version in `dxrt-cli -i`",
                                 "Install DX-RT (https://github.com/DEEPX-AI/dx_rt)."))
    else:
        version = parse_version(found[1])
        known = sorted({parse_version(v.split("dxrt")[-1]) for v in h.variants("deepx") if v})
        ok = version in known
        chip.checks.append(Check("DX-RT", "ok" if ok else "fail", found[1] if ok else f"{found[1]}, the runtime needs exactly {', '.join(map(fmt, known))}",
                                 "" if ok else f"Install DX-RT {fmt(known[-1])} and run `sudo ldconfig`."))
    chip.checks += system_checks(h, (2, 29), (20, 4))
    variant = f"ubuntu{ubuntu(h.ubuntu)}-dxrt{found[1]}" if h.ubuntu and found and ok else None
    if found and ok and not h.ubuntu:
        chip.checks.append(Check("OS", "fail", "the runtime is built per Ubuntu version (20.04, 22.04, 24.04)", "Use one of these Ubuntu versions."))
    chip.runtimes = [finish(chip, h, Runtime("deepx"), [variant] if variant else [])]
    return chip


# ---------------------------------------------------------------- report

SCANNERS: tuple = (scan_cpu, scan_intel, scan_nvidia, scan_hailo, scan_deepx)


def scan(system: System, index: list) -> Report:
    if system.os not in ("linux", "windows"):
        raise ScanError(f"cannot scan {system.os}: OAAX 2.0 runtimes exist for Linux and Windows only")
    h = Host(system, index)
    machine = f"{h.os_label} ({h.os}-{h.arch})" + (f", glibc {fmt(system.glibc())}" if system.glibc() and h.os == "linux" else "") \
        + (f", kernel {system.kernel}" if h.os == "linux" else "")
    return Report(machine, system.which("docker") is not None, [scan_chip(h, s) for s in SCANNERS])


def scan_chip(h: Host, scanner: Callable) -> Chip:
    try:
        return scanner(h)
    except Exception as exc:  # a probe bug must not hide the other chips
        name = scanner.__name__.removeprefix("scan_").upper()
        return Chip(name, True, "", [Check("scan", "fail", f"{type(exc).__name__}: {exc}")])


def to_dict(report: Report) -> dict:
    return {
        "machine": report.machine,
        "docker": report.docker,
        "chips": [{
            "name": c.name, "status": c.status, "hardware": c.hardware, "docs": c.docs,
            "checks": [vars(k) for k in c.checks],
            "runtimes": [{"vendor": r.vendor, "ready": bool(r.usable), "usable": [v or "" for v in r.usable],  # "" = a runtime without variants
                          "recommended": (r.usable[0] or "") if r.usable else None,
                          "rejected": {k or "": v for k, v in r.rejected.items()}, "notes": {k or "": v for k, v in r.notes.items()}}
                         for r in c.runtimes],
        } for c in report.chips],
    }


MARK = {"ok": "[ok]", "fail": "[!!]", "warn": "[? ]", "skip": "[--]"}


def render(report: Report, only: Optional[str] = None) -> str:
    lines = [f"Machine: {report.machine}",
             "Docker (needed to run the conversion toolchains): " + ("found" if report.docker else "not found"), ""]
    for chip in report.chips:
        if only and not any(r.vendor == only for r in chip.runtimes):
            continue
        status = {"ready": "READY", "unusable": "NOT USABLE", "absent": "not found"}[chip.status]
        lines.append(f"{chip.name:<7} {status:<11} {chip.hardware}".rstrip())
        for check in chip.checks:
            lines.append(f"    {MARK[check.status]} {check.name}: {check.detail}".rstrip())
            if check.fix and check.status in ("fail", "warn"):
                lines.append(f"         fix: {check.fix}")
        for runtime in chip.runtimes:
            lines += runtime_lines(runtime, chip)
        if chip.status == "unusable" and chip.docs:
            lines.append(f"    docs: {chip.docs}")
    return "\n".join(lines)


def runtime_lines(runtime: Runtime, chip: Chip) -> list:
    out = []
    for i, variant in enumerate(runtime.usable):
        command = f"oaax-manager fetch runtime {runtime.vendor}" + (f" --variant {variant}" if variant else "")
        out.append(f"    {'->' if i == 0 else '  '} {command}" + ("   (recommended)" if i == 0 and len(runtime.usable) > 1 else ""))
        if variant in runtime.notes:
            out.append(f"         note: {runtime.notes[variant]}")
    if chip.found and not runtime.usable and not chip.problems and not runtime.rejected:
        out.append(f"    -- {runtime.vendor}: no build fits")
    for variant, why in ({} if runtime.usable else runtime.rejected).items():  # the reasons matter when nothing is usable; kept in --json
        out.append(f"    -- {' '.join(filter(None, (runtime.vendor, variant)))}: {why}")
    return out
