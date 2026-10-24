import json
import os
import sys

import pytest

from conftest import entry, make_tar
from oaax_manager import cli
from oaax_manager.index import load_index


def run(index, *argv):
    return cli.main(["--index", str(index), *argv])


@pytest.fixture
def bucket(server, make_index):
    """A runtime (3 files), a toolchain, and two cuda variants on host-independent os/arch 'linux-x86_64'."""
    root, _ = server
    (root / "rt").mkdir()
    make_tar(root / "rt/library.tar.gz", {"libRuntimeLibrary.so": b"so", "dep.so": b"dep"})
    (root / "tc").mkdir()
    (root / "tc/tool.tar").write_bytes(b"docker-image" * 1000)
    for c in (11, 12):
        make_tar(root / f"rt/cuda{c}.tar.gz", {"libRuntimeLibrary.so": bytes([c])})
    return root, make_index([
        entry(root, "rt/library.tar.gz"),
        entry(root, "tc/tool.tar", kind="toolchain", os="any", arch="any"),
        entry(root, "rt/cuda11.tar.gz", vendor="nvidia", variant="cuda11"),
        entry(root, "rt/cuda12.tar.gz", vendor="nvidia", variant="cuda12"),
    ])


def host(monkeypatch, os_="linux", arch="x86_64"):
    monkeypatch.setattr(cli, "host_platform", lambda: (os_, arch))


def test_list_marks_host_runtimes(bucket, monkeypatch, capsys):
    host(monkeypatch)
    assert run(bucket[1], "list") == 0
    out = capsys.readouterr().out
    assert "toolchain  cpu" in out and "cuda11" in out
    assert [l for l in out.splitlines() if l.startswith("runtime") and l.rstrip().endswith("*")]
    assert not [l for l in out.splitlines() if l.startswith("toolchain") and l.rstrip().endswith("*")]


def test_list_filter_without_match_is_an_error(bucket, capsys):
    assert run(bucket[1], "list", "--vendor", "nope") == 1
    assert "no artifact matches" in capsys.readouterr().err


def test_fetch_runtime_extracts_and_removes_archive(bucket, monkeypatch, tmp_path, capsys):
    host(monkeypatch)
    out = tmp_path / "out"
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    target = out / "runtime-cpu-2.0.0-linux-x86_64"
    assert (target / "libRuntimeLibrary.so").read_bytes() == b"so"
    assert not list(out.glob("*.tar.gz*"))
    assert "Runtime library:" in capsys.readouterr().out


def test_fetch_toolchain_verifies_and_hints_docker(bucket, tmp_path, capsys):
    out = tmp_path / "out"
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool.tar").stat().st_size == 12000
    assert "docker load -i" in capsys.readouterr().out
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert "already downloaded" in capsys.readouterr().out


def test_sha_mismatch_fails_and_leaves_nothing(bucket, monkeypatch, tmp_path, capsys):
    host(monkeypatch)
    root, index = bucket
    (root / "rt/library.tar.gz").write_bytes((root / "rt/library.tar.gz").read_bytes()[:-1] + b"X")
    out = tmp_path / "out"
    assert run(index, "fetch", "runtime", "cpu", "-o", str(out)) == 1
    assert "mismatch" in capsys.readouterr().err
    assert not [p for p in out.rglob("*") if p.is_file()]


def test_ambiguous_variant_is_not_guessed(bucket, monkeypatch, capsys):
    host(monkeypatch)
    assert run(bucket[1], "fetch", "runtime", "nvidia") == 1
    assert "--variant (cuda11, cuda12)" in capsys.readouterr().err


def test_variant_selects(bucket, monkeypatch, tmp_path):
    host(monkeypatch)
    assert run(bucket[1], "fetch", "runtime", "nvidia", "--variant", "cuda12", "-o", str(tmp_path / "o")) == 0
    assert (tmp_path / "o/runtime-nvidia-2.0.0-linux-x86_64-cuda12/libRuntimeLibrary.so").read_bytes() == bytes([12])


def test_unsupported_platform_explains(bucket, monkeypatch, capsys):
    host(monkeypatch, "macos", "aarch64")
    assert run(bucket[1], "fetch", "runtime", "cpu") == 1
    assert "no cpu runtime for macos-aarch64" in capsys.readouterr().err


def test_os_arch_override(bucket, monkeypatch, tmp_path):
    host(monkeypatch, "macos", "aarch64")
    assert run(bucket[1], "fetch", "runtime", "cpu", "--os", "linux", "--arch", "x86_64", "-o", str(tmp_path / "o")) == 0


def test_unknown_vendor_lists_choices(bucket, capsys):
    assert run(bucket[1], "fetch", "toolchain", "zzz") == 1
    assert "Available: cpu" in capsys.readouterr().err


def test_existing_runtime_dir_is_left_alone(bucket, monkeypatch, tmp_path, capsys):
    host(monkeypatch)
    args = ("fetch", "runtime", "cpu", "-o", str(tmp_path / "o"))
    assert run(bucket[1], *args) == 0
    capsys.readouterr()
    assert run(bucket[1], *args) == 0
    assert "already exists" in capsys.readouterr().out


def test_resume_continues_partial_download(bucket, tmp_path):
    root, index = bucket
    data = (root / "tc/tool.tar").read_bytes()
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool.tar.part").write_bytes(data[:5000])
    assert run(index, "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool.tar").read_bytes() == data


def test_server_down_is_a_clean_error(bucket, monkeypatch, tmp_path, capsys):
    from oaax_manager import download
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    root, index_path = bucket
    cfg = json.loads(index_path.read_text())
    cfg["base_url"] = "http://127.0.0.1:1"
    index_path.write_text(json.dumps(cfg))
    assert run(index_path, "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 1
    assert "download failed" in capsys.readouterr().err


def test_packaged_index_is_wellformed():
    index = load_index()
    assert index
    keys = {(a.kind, a.vendor, a.version, a.os, a.arch, a.variant) for a in index}
    assert len(keys) == len(index)
    for a in index:
        assert len(a.sha256) == 64 and int(a.sha256, 16) >= 0
        assert a.size > 0 and a.url.startswith("https://")
        assert a.kind in ("runtime", "toolchain") and a.os in ("linux", "windows", "macos", "any")


def test_http_index_is_refused(bucket, tmp_path, capsys):
    cfg = json.loads(bucket[1].read_text())
    cfg["base_url"] = "http://example.com/oaax"
    bucket[1].write_text(json.dumps(cfg))
    assert run(bucket[1], "list") == 1
    assert "must be https" in capsys.readouterr().err


def test_not_enough_disk_space_fails_before_downloading(bucket, monkeypatch, tmp_path, capsys):
    import collections
    import shutil
    host(monkeypatch)
    usage = collections.namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: usage(10, 10, 1))
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(tmp_path / "o")) == 1
    assert "not enough disk space" in capsys.readouterr().err
    assert not list((tmp_path / "o").iterdir())


def test_transient_failure_is_retried_and_resumed(bucket, monkeypatch, tmp_path):
    import urllib.request
    from oaax_manager import download
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    real, calls = urllib.request.urlopen, []

    def flaky(request, timeout=None):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("connection reset")
        return real(request, timeout=timeout)

    monkeypatch.setattr(download.urllib.request, "urlopen", flaky)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 0
    assert len(calls) == 2


def test_zipapp_runs_with_its_packaged_index_and_keeps_exit_codes(tmp_path):
    import subprocess
    import sys as _sys
    from pathlib import Path
    _sys.path.insert(0, str(Path(cli.__file__).parents[2] / "tools"))
    import build_pyz
    pyz = build_pyz.build(tmp_path / "oaax-manager.pyz")
    import zipfile
    names = zipfile.ZipFile(pyz).namelist()
    assert "oaax_manager/index.json" in names and not [n for n in names if "__pycache__" in n or "egg-info" in n]
    ok = subprocess.run([sys.executable, str(pyz), "list"], capture_output=True, text=True, cwd=tmp_path)
    assert ok.returncode == 0 and "runtime" in ok.stdout, ok.stderr
    bad = subprocess.run([sys.executable, str(pyz), "fetch", "runtime", "nosuch"], capture_output=True, text=True, cwd=tmp_path)
    assert bad.returncode == 1 and "error:" in bad.stderr
