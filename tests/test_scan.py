"""`scan` on fake machines: every verdict is checked against the OAAX docs, not against what the code happens to print."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import entry, make_tar
from oaax_manager import cli, scan as scanmod
from oaax_manager.index import load_index
from oaax_manager.system import NOT_FOUND, TIMED_OUT, PciDevice, System

INDEX = load_index()


class Fake(System):
    """A machine described by data: files, directories, tool outputs, PCI devices, ldconfig libraries."""

    def __init__(self, os="linux", arch="x86_64", release=("ubuntu", "22.04"), glibc=(2, 35), libs=(), files=None, dirs=None,
                 cmds=None, pci=(), cpu="Fake CPU", vendor="GenuineIntel", avx2=True, env=None, board=""):
        self._os, self._arch, self._glibc, self._avx2, self._cpu, self._vendor = os, arch, glibc, avx2, cpu, vendor
        self._pci, self._env, self._board = list(pci), env or {}, board
        self.files = {"/etc/os-release": f'ID={release[0]}\nVERSION_ID="{release[1]}"\nPRETTY_NAME="{release[0]} {release[1]}"\n'} if release else {}
        self.files.update(files or {})
        self.dirs, self.cmds, self.ran = dirs or {}, cmds or {}, []
        tag = {"x86_64": "libc6,x86-64", "aarch64": "libc6,AArch64"}[arch]
        self._libs = "".join(f"\t{lib} ({tag}) => /usr/lib/{lib}\n" for lib in libs)

    os = property(lambda self: self._os)
    arch = property(lambda self: self._arch)
    kernel = property(lambda self: "6.8.0-1-fake")

    def env(self): return self._env
    def which(self, name): return f"/usr/bin/{name}" if any(k[0] == name for k in self.cmds) else None
    def read(self, path): return self.files.get(path)
    def exists(self, path): return path in self.files or path in self.dirs
    def listdir(self, path): return self.dirs.get(path, [])
    def libraries(self): return self._libs
    def glibc(self): return self._glibc
    def avx2(self): return self._avx2 if self._arch == "x86_64" else None
    def cpu_model(self): return self._cpu
    def cpu_vendor(self): return self._vendor
    def device_model(self): return self._board
    def pci(self): return self._pci

    def run(self, argv, timeout=15):
        self.ran.append(argv)
        key = tuple(argv[:1] + argv[1:])
        for known, answer in self.cmds.items():
            if tuple(argv[:len(known)]) == known:
                return answer
        return NOT_FOUND, ""


BASE_LIBS = ("libstdc++.so.6", "libgomp.so.1", "libatomic.so.1")
SMI = ("nvidia-smi", "--query-gpu=name,compute_cap,driver_version")
SMI_XML = ("nvidia-smi", "-q", "-x")


def gpu(driver="580.178.04", cap="8.6", cuda="13.0", name="NVIDIA RTX A4000"):
    return {SMI: (0, f"{name}, {cap}, {driver}\n"), SMI_XML: (0, f"<cuda_version>{cuda}</cuda_version>")}


A4000 = [PciDevice("10de", "24b0", "0300")]
CUDA13 = ("libcudart.so.13", "libcublas.so.13", "libcublasLt.so.13", "libcufft.so.12")
CUDA12 = ("libcudart.so.12", "libcublas.so.12", "libcublasLt.so.12", "libcufft.so.11")


def scan(**kw):
    return scanmod.scan(Fake(**{"libs": BASE_LIBS, **kw}), INDEX)


def chip(report, name):
    return next(c for c in report.chips if c.name == name)


def usable(report, vendor):
    return report.runtime(vendor).usable


# ------------------------------------------------------------------ CPU, Intel

def test_plain_pc_has_only_cpu_and_intel():
    r = scan()
    assert chip(r, "CPU").status == "ready" and usable(r, "cpu") == [None]
    assert [c.status for c in r.chips if c.name not in ("CPU", "Intel")] == ["absent"] * 3


def test_amd_cpu_is_not_intel():
    assert chip(scan(vendor="AuthenticAMD"), "Intel").status == "absent"


@pytest.mark.parametrize("kw, check", [
    (dict(glibc=(2, 28)), "glibc"), (dict(avx2=False), "AVX2"), (dict(release=("ubuntu", "18.04"), glibc=(2, 27)), "OS"),
    (dict(glibc=None), "glibc"),  # A5: musl/Alpine has no glibc: the builds cannot run
])
def test_cpu_requirements(kw, check):
    c = chip(scan(**kw), "CPU")
    assert c.status == "unusable" and check in [k.name for k in c.problems]


def test_missing_libgomp_names_the_package():
    c = chip(scan(libs=("libstdc++.so.6",)), "CPU")
    assert c.status == "unusable" and "apt-get install libgomp1" in c.problems[0].fix


def test_intel_needs_ubuntu_2204_but_cpu_runtime_does_not():
    r = scan(release=("ubuntu", "20.04"), glibc=(2, 31))
    assert chip(r, "CPU").status == "ready" and chip(r, "Intel").status == "unusable"


def test_intel_gpu_without_opencl_is_a_warning_not_a_failure():
    r = scan(pci=[PciDevice("8086", "4680", "0300")])
    intel = chip(r, "Intel")
    assert intel.status == "ready" and [c.status for c in intel.checks if c.name == "GPU driver"] == ["warn"]


def test_debian_12_counts_as_ubuntu_2204():
    assert chip(scan(release=("debian", "12"), glibc=(2, 36)), "Intel").status == "ready"
    assert chip(scan(release=("debian", "11"), glibc=(2, 31)), "Intel").status == "unusable"


# ------------------------------------------------------------------ NVIDIA

def nv(libs=CUDA13, **kw):
    return scan(pci=A4000, cmds=kw.pop("cmds", gpu()), libs=BASE_LIBS + libs, **kw)


def test_healthy_gpu_recommends_the_newest_cuda_and_trt10():
    r = nv()
    assert usable(r, "nvidia-ort") == ["cuda13"]
    assert usable(r, "nvidia-trt")[0] == "ubuntu22.04-trt10-cuda13"  # trt10: the Docker toolchain's TensorRT
    assert "ubuntu22.04-trt11-cuda12" in usable(r, "nvidia-trt")


def test_old_driver_rejects_cuda13_with_the_documented_minimum():
    r = nv(libs=CUDA12 + CUDA13, cmds=gpu(driver="535.104.05", cuda="12.2"))
    assert usable(r, "nvidia-ort") == ["cuda12"] and "580" in r.runtime("nvidia-ort").rejected["cuda13"]
    assert usable(r, "nvidia-trt")[0].endswith("trt10-cuda12")
    assert "cuDNN 8" in r.runtime("nvidia-ort").notes["cuda12"]


def test_ort_needs_the_cuda_libraries_trt_bundles_them():
    r = nv(libs=())
    assert usable(r, "nvidia-ort") == [] and usable(r, "nvidia-trt")
    assert chip(r, "NVIDIA").status == "ready"


def test_ort_needs_libcufft(  ):  # A3
    r = nv(libs=("libcudart.so.13", "libcublas.so.13", "libcublasLt.so.13"))
    assert usable(r, "nvidia-ort") == [] and "libcufft.so.12" in r.runtime("nvidia-ort").rejected["cuda13"]


def test_cuda11_sonames_have_a_minor_suffix():  # found on a JetPack 5 board: libcudart.so.11.0
    libs = ("libcudart.so.11.0", "libcublas.so.11", "libcublasLt.so.11", "libcufft.so.10")
    assert usable(nv(libs=libs, cmds=gpu(driver="470.82.01", cuda="11.4")), "nvidia-ort") == ["cuda11"]


def test_cuda_libraries_in_ld_library_path_count():  # A12
    r = nv(libs=(), env={"LD_LIBRARY_PATH": "/opt/cuda/lib64"}, dirs={"/opt/cuda/lib64": [
        "libcudart.so.13", "libcublas.so.13", "libcublasLt.so.13", "libcufft.so.12"]})
    assert usable(r, "nvidia-ort") == ["cuda13"]


@pytest.mark.parametrize("answer", [(0, ""), (0, "NVIDIA RTX A4000, 8.6, [N/A]\n"), (0, "junk\n" * 1000), (0, "A, B, C\n")])
def test_nvidia_smi_that_succeeds_without_a_driver_version_is_never_a_pass(answer):  # A1
    r = nv(cmds={SMI: answer})
    assert chip(r, "NVIDIA").status == "unusable" and usable(r, "nvidia-ort") == []


def test_driver_library_mismatch_names_both_versions():
    out = "Failed to initialize NVML: Driver/library version mismatch\nNVML library version: 595.99\n"
    r = nv(cmds={SMI: (18, out)}, files={"/sys/module/nvidia/version": "580.178.04\n"})
    detail = chip(r, "NVIDIA").problems[0].detail
    assert "580.178.04" in detail and "595.99" in detail and "Reboot" in detail


@pytest.mark.parametrize("answer, words", [((NOT_FOUND, ""), "not installed"), ((TIMED_OUT, ""), "did not answer"),
                                           ((9, "NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver"), "not loaded")])
def test_nvidia_smi_failures_say_what_to_do(answer, words):  # A10
    assert words in chip(nv(cmds={SMI: answer}), "NVIDIA").problems[0].detail


def test_wsl_and_containers_have_no_pci_gpu_but_a_working_nvidia_smi():  # found on a WSL2 host with an RTX 4080 SUPER
    assert chip(scan(cmds=gpu(), libs=BASE_LIBS + CUDA13), "NVIDIA").status == "ready"
    assert chip(scan(cmds={SMI: (9, "couldn't communicate with the NVIDIA driver")}), "NVIDIA").status == "absent"  # tool installed, no card


def test_gpu_architecture_limits():
    kepler = nv(libs=("libcudart.so.11.0", "libcublas.so.11", "libcublasLt.so.11", "libcufft.so.10"), cmds=gpu(cap="3.5", driver="470.82.01", cuda="11.4"))
    assert usable(kepler, "nvidia-ort") == ["cuda11"]
    pascal = nv(libs=CUDA13 + CUDA12, cmds=gpu(cap="6.1"))
    assert usable(pascal, "nvidia-ort") == ["cuda12"] and "SM 6.1" in pascal.runtime("nvidia-ort").rejected["cuda13"]


def test_trt_needs_turing_or_newer():  # A4
    r = nv(cmds=gpu(cap="6.1"))
    assert usable(r, "nvidia-trt") == [] and "7.5" in next(iter(r.runtime("nvidia-trt").rejected.values()))


def test_trt_builds_are_for_ubuntu_2204_or_newer():
    assert usable(nv(release=("ubuntu", "20.04"), glibc=(2, 31)), "nvidia-trt") == []
    assert usable(nv(release=("ubuntu", "24.04"), glibc=(2, 39)), "nvidia-trt")


def test_only_gpu_zero_decides():
    smi = {SMI: (0, "NVIDIA RTX A4000, 8.6, 580.178.04\nNVIDIA GeForce GTX 1080, 6.1, 580.178.04\n"), SMI_XML: (0, "<cuda_version>13.0</cuda_version>")}
    assert usable(nv(cmds=smi), "nvidia-trt")


def test_jetpack_6_gets_jetson_builds_and_needs_jetpack_libs():
    jp6 = ("libcudart.so.12", "libcublas.so.12", "libcublasLt.so.12", "libcufft.so.11", "libnvinfer.so.10")
    r = scan(arch="aarch64", libs=BASE_LIBS + jp6, files={"/etc/nv_tegra_release": "# R36"}, board="NVIDIA Jetson Orin Nano")
    assert chip(r, "NVIDIA").hardware == "NVIDIA Jetson Orin Nano"
    assert usable(r, "nvidia-ort") == ["jetson-cuda12"] and usable(r, "nvidia-trt") == ["jetson-ubuntu22.04-trt10-cuda12"]


def test_jetson_with_tensorrt_8_says_what_it_found():  # JetPack 6.0 on a real Orin Nano ships TensorRT 8.6
    libs = ("libcudart.so.12", "libcublas.so.12", "libcublasLt.so.12", "libcufft.so.11", "libnvinfer.so.8")
    r = scan(arch="aarch64", libs=BASE_LIBS + libs, files={"/etc/nv_tegra_release": "# R36"})
    assert usable(r, "nvidia-ort") == ["jetson-cuda12"] and usable(r, "nvidia-trt") == []
    assert "TensorRT 8" in "".join(r.runtime("nvidia-trt").rejected.values())


def test_jetpack_7_has_no_trt_build_and_jetpack_5_neither():  # A2
    jp7 = scan(arch="aarch64", release=("ubuntu", "24.04"), glibc=(2, 39), files={"/etc/nv_tegra_release": "# R38"},
               libs=BASE_LIBS + CUDA13 + ("libnvinfer.so.10",))
    assert usable(jp7, "nvidia-ort") == ["jetson-cuda13"] and usable(jp7, "nvidia-trt") == []
    jp5 = scan(arch="aarch64", release=("ubuntu", "20.04"), glibc=(2, 31), files={"/etc/nv_tegra_release": "# R35"},
               libs=BASE_LIBS + ("libcudart.so.11.0", "libcublas.so.11", "libcublasLt.so.11", "libcufft.so.10"))
    assert usable(jp5, "nvidia-ort") == ["jetson-cuda11"] and usable(jp5, "nvidia-trt") == []


def test_sbsa_needs_ubuntu_2404_for_trt():
    spark = scan(arch="aarch64", release=("ubuntu", "24.04"), glibc=(2, 39), pci=[PciDevice("10de", "2e12", "0300")],
                 cmds=gpu(cap="12.1", driver="595.99.02", cuda="13.2", name="NVIDIA GB10"), libs=BASE_LIBS + CUDA13)
    assert usable(spark, "nvidia-ort") == ["sbsa-cuda13"] and usable(spark, "nvidia-trt")[0] == "sbsa-ubuntu24.04-trt10-cuda13"


def test_windows_nvidia_uses_cuda_path_and_has_no_trt():
    env = {"CUDA_PATH_V12_4": r"C:\CUDA\v12.4", "PATH": r"C:\Windows;C:\CUDA\v12.4\bin"}
    r = scanmod.scan(Fake(os="windows", release=None, glibc=None, pci=[PciDevice("10de", "24b0", "")], cmds=gpu(driver="552.22", cuda="12.4"), env=env), INDEX)
    assert usable(r, "nvidia-ort") == ["cuda12"] and usable(r, "nvidia-trt") == []
    assert "Windows" in "".join(r.runtime("nvidia-trt").rejected.values()) or "windows" in "".join(r.runtime("nvidia-trt").rejected.values())
    off_path = scanmod.scan(Fake(os="windows", release=None, glibc=None, pci=[PciDevice("10de", "24b0", "")], cmds=gpu(driver="552.22", cuda="12.4"),
                                 env={**env, "PATH": r"C:\Windows"}), INDEX)
    assert usable(off_path, "nvidia-ort") == [] and "PATH" in off_path.runtime("nvidia-ort").rejected["cuda12"]


def test_windows_checks_avx2_and_does_not_invent_gpus():  # A6
    r = scanmod.scan(Fake(os="windows", release=None, glibc=None, avx2=False, pci=[PciDevice("8086", "4680", "")]), INDEX)
    assert chip(r, "CPU").status == "unusable"
    assert "GPU" not in chip(r, "Intel").hardware


# ------------------------------------------------------------------ Hailo

HAILO_PCI = [PciDevice("1e60", "2864", "0b40")] * 2
HAILO_DIRS = {"/sys/class/hailo_chardev": ["hailo0", "hailo1"], "/sys/module/hailo_pci": []}
IDENT = "Executing on device: 0\nDevice Architecture: HAILO8\nExecuting on device: 1\nDevice Architecture: HAILO8\n"


def hailo(version="HailoRT-CLI version 4.20.0\n", driver="4.20.0\n", ident=IDENT, **kw):
    cmds = {("hailortcli", "-v"): (0, version), ("hailortcli", "fw-control"): (0, ident)}
    cmds.update(kw.pop("cmds", {}))
    return scan(pci=HAILO_PCI, dirs=HAILO_DIRS, cmds=cmds, files={"/sys/module/hailo_pci/version": driver}, **kw)


def test_hailo_ready_with_the_variant_of_the_installed_version():
    r = hailo()
    assert chip(r, "Hailo").hardware == "2x Hailo-8 (PCIe)" and usable(r, "hailo") == ["hailort4.20.0"]


@pytest.mark.parametrize("kw, check", [
    (dict(version="HailoRT-CLI version 4.16.0\n", driver="4.16.0\n"), "HailoRT"),
    (dict(driver="4.19.0\n"), "driver = HailoRT"),
    (dict(version="HailoRT-CLI version 4.20.0-rc1\n"), "HailoRT"),  # A7
    (dict(version="[warn] 2 devices busy\nno banner\n"), "HailoRT"),  # A7: a number from a log line is not a version
    (dict(cmds={("hailortcli", "-v"): (TIMED_OUT, "")}), "HailoRT"),
])
def test_hailo_failures(kw, check):
    r = hailo(**kw)
    assert chip(r, "Hailo").status == "unusable" and check in [c.name for c in chip(r, "Hailo").problems]
    assert usable(r, "hailo") == []


def test_hailo_timeout_is_named():
    r = hailo(cmds={("hailortcli", "-v"): (TIMED_OUT, "")})
    assert "did not answer" in chip(r, "Hailo").problems[0].detail


def test_hailo_8l_is_flagged_and_mixed_cards_are_listed():  # A8
    mixed = hailo(ident="Device Architecture: HAILO8\nDevice Architecture: HAILO8L\n")
    assert chip(mixed, "Hailo").hardware == "1x Hailo-8, 1x Hailo-8L (PCIe)"
    assert [c.status for c in chip(mixed, "Hailo").checks if c.name == "chip"] == ["warn"]


def test_card_without_driver_or_hailort_is_one_cause_not_three():
    r = scan(pci=HAILO_PCI)
    assert chip(r, "Hailo").status == "unusable"
    assert "device nodes" not in [c.name for c in chip(r, "Hailo").checks]


# ------------------------------------------------------------------ DeepX

DX_PCI = [PciDevice("1ff4", "0000", "1200")]


def deepx(version="DXRT v3.3.2\n", loaded=True, **kw):
    files = {"/sys/module/dxrt_driver": ""} if loaded else {}
    return scan(pci=DX_PCI, dirs={"/dev": ["dxrt0"]} if loaded else {}, files=files, cmds={("dxrt-cli", "-i"): (134, version), **kw.pop("cmds", {})}, **kw)


def test_deepx_variant_follows_the_ubuntu_version():
    assert usable(deepx(release=("ubuntu", "24.04"), glibc=(2, 39)), "deepx") == ["ubuntu24.04-dxrt3.3.2"]
    assert usable(deepx(release=("debian", "12"), glibc=(2, 36)), "deepx") == ["ubuntu22.04-dxrt3.3.2"]


def test_deepx_needs_exactly_the_documented_dxrt():
    for version in ("DXRT v2.0.3\n", "DXRT v3.3.20\n"):
        r = deepx(version=version)
        assert usable(r, "deepx") == [] and "exactly 3.3.2" in chip(r, "DeepX").problems[0].detail


def test_deepx_kernel_update_loses_the_driver():
    r = deepx(loaded=False, cmds={("/sbin/modinfo", "-n"): (1, "")})
    assert "none is built for kernel 6.8.0-1-fake" in chip(r, "DeepX").problems[0].detail
    built = deepx(loaded=False, cmds={("/sbin/modinfo", "-n"): (0, "/lib/modules/x/dxrt_driver.ko")})
    assert "modprobe" in chip(built, "DeepX").problems[0].fix


def test_no_card_means_no_deepx_even_with_the_tool_installed():
    assert chip(scan(cmds={("dxrt-cli", "-i"): (134, "DXRT v2.0.3\n")}), "DeepX").status == "absent"


# ------------------------------------------------------------------ report, JSON, probes

def test_a_crashing_probe_fails_one_chip_not_the_scan(monkeypatch):
    monkeypatch.setattr(scanmod, "SCANNERS", (scanmod.scan_cpu, lambda h: 1 / 0))
    r = scan()
    assert r.chips[0].status == "ready" and "ZeroDivisionError" in r.chips[1].problems[0].detail


def test_macos_is_refused_with_a_reason():
    with pytest.raises(scanmod.ScanError, match="Linux and Windows"):
        scanmod.scan(Fake(os="macos"), INDEX)


def test_json_says_readiness_explicitly():  # A9
    data = json.loads(json.dumps(scanmod.to_dict(nv(libs=()))))
    runtimes = {r["vendor"]: r for c in data["chips"] for r in c["runtimes"]}
    assert runtimes["cpu"]["ready"] is True and runtimes["cpu"]["usable"] == [""] and runtimes["cpu"]["recommended"] == ""
    assert runtimes["nvidia-ort"]["ready"] is False and runtimes["nvidia-ort"]["recommended"] is None
    assert "None" not in runtimes["cpu"]["rejected"]


def test_text_hides_rejected_builds_when_something_is_usable():  # A13
    text = scanmod.render(nv(libs=CUDA12 + CUDA13))
    assert "cuda13" in text and "-- nvidia-ort cuda11" not in text
    assert "-- nvidia-ort cuda13" in scanmod.render(nv(libs=()))


def test_every_indexed_variant_is_understood_by_the_scan():
    """If the index gains a variant the scan cannot name, a vendor build would silently never be recommended."""
    for a in INDEX:
        if a.kind != "runtime":
            continue
        if a.vendor.startswith("nvidia"):
            assert scanmod.NVIDIA_VARIANT.match(a.variant), a.variant
        elif a.vendor == "hailo":
            assert a.variant.startswith("hailort"), a.variant
        elif a.vendor == "deepx":
            assert a.variant.startswith("ubuntu") and "-dxrt" in a.variant, a.variant
        else:
            assert a.vendor in ("cpu", "intel") and a.variant is None


def test_real_machine_scan_does_not_crash_and_leaves_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    if sys.platform not in ("linux", "win32"):
        pytest.skip("scan refuses this OS")
    report = scanmod.scan(System(), INDEX)
    assert report.chips[0].name == "CPU" and json.dumps(scanmod.to_dict(report))
    assert list(tmp_path.iterdir()) == []


def test_tools_run_in_their_own_directory(tmp_path, monkeypatch):
    """hailortcli writes hailort.log into the working directory: the scan must not leave files in the user's."""
    monkeypatch.chdir(tmp_path)
    code, out = System().run([sys.executable, "-c", "import os, pathlib; pathlib.Path('x.log').write_text('1'); print(os.getcwd())"])
    assert code == 0 and out.strip() != str(tmp_path) and list(tmp_path.iterdir()) == []


def test_run_reports_missing_and_hung_tools():
    assert System().run(["no-such-tool-oaax"]) == (NOT_FOUND, "")
    assert System().run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.3) == (TIMED_OUT, "")


# ------------------------------------------------------------------ CLI

def run(*argv):
    return cli.main(["scan", *argv])


@pytest.fixture
def machine(monkeypatch):
    def use(**kw):
        fake = Fake(**{"libs": BASE_LIBS, **kw})
        monkeypatch.setattr(cli, "System", lambda: fake)
        monkeypatch.setattr(cli, "host_platform", lambda: (fake.os, fake.arch))  # fetch resolves the platform itself: pin it, or macOS runners differ
    return use


def test_scan_vendor_exit_code_is_for_scripts(machine, capsys):
    machine(pci=A4000, cmds=gpu(), libs=BASE_LIBS + CUDA13)
    assert run("--vendor", "nvidia-ort") == 0 and "fetch runtime nvidia-ort --variant cuda13" in capsys.readouterr().out
    machine()
    assert run("--vendor", "nvidia-ort") == 1 and run("--vendor", "cpu") == 0
    assert run("--vendor", "nope") == 1 and "Available:" in capsys.readouterr().err


def test_scan_json_is_the_only_thing_on_stdout(machine, capsys):
    machine()
    assert run("--json") == 0
    assert json.loads(capsys.readouterr().out)["chips"][0]["name"] == "CPU"


def test_scan_on_macos_is_a_clean_error(monkeypatch, capsys):
    monkeypatch.setattr(cli, "System", lambda: Fake(os="macos"))
    assert run() == 1 and "cannot scan macos" in capsys.readouterr().err


def fetch(index_path, *argv):
    return cli.main(["--index", str(index_path), "fetch", "runtime", *argv])


def test_variant_auto_fetches_the_build_scan_recommends(server, make_index, monkeypatch, tmp_path, capsys):
    root, _ = server
    (root / "rt").mkdir()
    for cuda in (12, 13):
        make_tar(root / f"rt/cuda{cuda}.tar.gz", {"libRuntimeLibrary.so": bytes([cuda])})
    index = make_index([entry(root, f"rt/cuda{c}.tar.gz", vendor="nvidia-ort", variant=f"cuda{c}") for c in (12, 13)])
    # driver 535 and CUDA 12 libraries: cuda13 would be refused, cuda12 is right
    monkeypatch.setattr(cli, "System", lambda: Fake(libs=BASE_LIBS + CUDA12, pci=A4000, cmds=gpu(driver="535.104.05", cuda="12.2")))
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    out = tmp_path / "out"
    assert cli.main(["--index", str(index), "fetch", "runtime", "nvidia-ort", "--variant", "auto", "-o", str(out)]) == 0
    assert (out / "runtime-nvidia-ort-2.0.0-linux-x86_64-cuda12" / "libRuntimeLibrary.so").read_bytes() == bytes([12])
    assert "--variant auto: using cuda12" in capsys.readouterr().out


def test_variant_auto_refuses_with_the_reason_and_a_way_out(machine, capsys):
    machine(pci=A4000, cmds={SMI: (NOT_FOUND, "")})
    assert cli.main(["fetch", "runtime", "nvidia-ort", "--variant", "auto", "-o", "."]) == 1
    err = capsys.readouterr().err
    assert "cannot be used on this machine" in err and "not installed" in err and "choose --variant yourself" in err


@pytest.mark.parametrize("extra", [["--os", "linux"], ["--arch", "x86_64"]])
def test_variant_auto_is_for_this_machine_only(machine, capsys, extra):
    machine()
    assert cli.main(["fetch", "runtime", "cpu", "--variant", "auto", *extra]) == 1
    assert "this machine" in capsys.readouterr().err


def test_variant_auto_for_toolchains_is_refused(machine, capsys):
    machine()
    assert cli.main(["fetch", "toolchain", "cpu", "--variant", "auto"]) == 1
    assert "only applies to runtimes" in capsys.readouterr().err
