"""Regression tests for the adversary round 1 findings (F5-F14)."""

from __future__ import annotations

import json
import os
import sys
import tarfile

import pytest

from conftest import entry, make_tar
from oaax_manager import cli, download
from oaax_manager.download import FetchError, fetch_lock, safe_extract

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import gen_index  # noqa: E402

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")


def run(index, *argv):
    return cli.main(["--index", str(index), *argv])


@pytest.fixture
def bucket(server, make_index):
    root, _ = server
    (root / "rt").mkdir()
    make_tar(root / "rt/library.tar.gz", {"libRuntimeLibrary.so": b"so", "dep.so": b"dep"})
    (root / "tc").mkdir()
    (root / "tc/tool.tar").write_bytes(b"docker-image" * 1000)
    return root, make_index([
        entry(root, "rt/library.tar.gz"),
        entry(root, "tc/tool.tar", kind="toolchain", os="any", arch="any"),
    ])


@pytest.fixture(autouse=True)
def linux_host(monkeypatch):
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(download.time, "sleep", lambda s: None)


# F5: plain user mistakes are errors, not tracebacks
@pytest.mark.parametrize("kind, vendor", [("runtime", "cpu"), ("toolchain", "cpu")])
def test_output_path_is_a_file(bucket, tmp_path, capsys, kind, vendor):
    target = tmp_path / "afile"
    target.write_text("x")
    assert run(bucket[1], "fetch", kind, vendor, "-o", str(target)) == 1
    err = capsys.readouterr().err
    assert err.startswith("error:") or "\nerror:" in err
    assert "Traceback" not in err


@POSIX_ONLY
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")
def test_unwritable_output_parent(bucket, tmp_path, capsys):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(ro / "sub")) == 1
    finally:
        ro.chmod(0o700)
    assert "Traceback" not in capsys.readouterr().err


def test_toolchain_destination_is_a_directory(bucket, tmp_path, capsys):
    (tmp_path / "o" / "tool.tar").mkdir(parents=True)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 1
    assert "is a directory" in capsys.readouterr().err


# F6: a second fetch of the same target is refused, the lock is released afterwards
def test_concurrent_fetch_is_refused(bucket, tmp_path, capsys):
    out = tmp_path / "o"
    with fetch_lock(out / "tool.tar"):
        assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 1
        assert "another oaax-manager is already fetching" in capsys.readouterr().err
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0


def test_a_refused_run_does_not_free_the_lock_for_a_third(tmp_path):
    """Adversary F6b: B failing to lock must not delete the lock file, or C would get a fresh one."""
    target = tmp_path / "t.tar"
    with fetch_lock(target):
        for _ in range(2):  # B, then C
            with pytest.raises(FetchError, match="another oaax-manager"):
                with fetch_lock(target):
                    pass
    with fetch_lock(target):  # free again once A is done
        pass


# F7: a refused archive does not stay behind
def test_failed_extraction_removes_the_verified_archive(server, make_index, tmp_path):
    root, _ = server
    (root / "rt").mkdir()
    make_tar(root / "rt/library.tar.gz", {"ok.so": b"x", "../evil": b"y"})
    index = make_index([entry(root, "rt/library.tar.gz")])
    out = tmp_path / "o"
    for _ in range(2):
        assert run(index, "fetch", "runtime", "cpu", "-o", str(out)) == 1
        assert not [p for p in out.iterdir() if not p.name.endswith(".lock")]


# F8: a stale or foreign .part is replaced, not blamed on upstream
@pytest.mark.parametrize("stale", [b"\x00" * 12000, b"y" * 5000])
def test_stale_part_is_retried_from_zero(bucket, tmp_path, stale):
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool.tar.part").write_bytes(stale)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool.tar").read_bytes() == b"docker-image" * 1000


def test_resume_response_for_another_offset_is_not_trusted(bucket, tmp_path, monkeypatch):
    real = download._resumes_at
    monkeypatch.setattr(download, "_resumes_at", lambda r, have: False)  # server "answers for another offset"
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool.tar.part").write_bytes(b"docker-image" * 400)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool.tar").read_bytes() == b"docker-image" * 1000
    assert real  # the real check is exercised by test_resume_continues_partial_download


def test_real_mismatch_is_still_reported_as_upstream_change(bucket, tmp_path, capsys):
    root, index = bucket
    (root / "tc/tool.tar").write_bytes(b"changed" * 1714)  # 11998 bytes
    (root / "tc/tool.tar").write_bytes((root / "tc/tool.tar").read_bytes() + b"zz")
    assert run(index, "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 1
    assert "changed upstream" in capsys.readouterr().err


# F9: identical, safe permissions whatever the Python version
@POSIX_ONLY
@pytest.mark.parametrize("with_filter", [True, False])
def test_modes_are_normalised(tmp_path, monkeypatch, with_filter):
    if not with_filter:
        monkeypatch.delattr(tarfile, "data_filter", raising=False)
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        for name, mode in (("rw.so", 0o666), ("rwx.so", 0o777), ("suid", 0o4755), ("sticky.so", 0o1777), ("plain", 0o644)):
            info = tarfile.TarInfo(name)
            info.mode = mode
            tar.addfile(info)
    safe_extract(tmp_path / "a.tgz", tmp_path / "d", "a" * 64)
    modes = {n: (tmp_path / "d" / n).stat().st_mode & 0o7777 for n in ("rw.so", "rwx.so", "suid", "sticky.so", "plain")}
    assert modes == {"rw.so": 0o644, "rwx.so": 0o755, "suid": 0o755, "sticky.so": 0o755, "plain": 0o644}


# F10: "already there" means "completed by this tool for this build"
def test_existing_target_needs_the_completion_marker(bucket, tmp_path, capsys):
    out = tmp_path / "o"
    name = "runtime-cpu-2.0.0-linux-x86_64"
    out.mkdir()
    (out / name).write_text("a plain file")
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 1
    (out / name).unlink()
    (out / name).mkdir()
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 1  # empty dir
    assert "delete it and run again" in capsys.readouterr().err


def test_marker_of_another_build_is_refused_marker_of_this_build_is_accepted(bucket, tmp_path, capsys):
    out = tmp_path / "o"
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    capsys.readouterr()
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    assert "already fetched and verified" in capsys.readouterr().out
    marker = out / "runtime-cpu-2.0.0-linux-x86_64" / ".oaax-manager.json"
    marker.write_text(json.dumps({"archive_sha256": "0" * 64}))
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 1


# F11: platform first, then newest version; versions are plain numbers
def test_newest_version_is_chosen_among_those_for_this_platform(server, make_index, tmp_path):
    root, _ = server
    (root / "rt").mkdir()
    make_tar(root / "rt/a.tar.gz", {"libRuntimeLibrary.so": b"1"})
    make_tar(root / "rt/b.tar.gz", {"RuntimeLibrary.dll": b"2"})
    index = make_index([
        entry(root, "rt/a.tar.gz", version="2.0.0"),
        entry(root, "rt/b.tar.gz", version="2.1.0", os="windows"),
    ])
    assert run(index, "fetch", "runtime", "cpu", "-o", str(tmp_path / "o")) == 0
    assert (tmp_path / "o/runtime-cpu-2.0.0-linux-x86_64/libRuntimeLibrary.so").exists()


@pytest.mark.parametrize("version", ["2.0.0-rc1", "2.0.rc1", "v2", "", "2..0"])
def test_non_numeric_versions_are_rejected(tmp_path, capsys, version):
    path = tmp_path / "i.json"
    entry_ = dict(kind="toolchain", vendor="cpu", version=version, os="any", arch="any", variant=None,
                  key="tc/x.tar", size=1, sha256="a" * 64)
    path.write_text(json.dumps({"schema": 1, "base_url": "https://example.com", "artifacts": [entry_]}))
    assert run(path, "list") == 1
    assert "Traceback" not in capsys.readouterr().err


# F12: names that collide or are invalid on Windows/macOS
@pytest.mark.parametrize("names", [
    ["a", "a"], ["Lib.so", "lib.so"], ["café", "café"], ["x.txt", "x.txt."], ["d/x", "D/X"],
    ["CON"], ["nul.txt"], ["sub/aux.so"], ["trail. "], ["dot."], [".oaax-manager.json"],
])
def test_colliding_or_invalid_member_names_are_refused(tmp_path, names):
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        for n in names:
            tar.addfile(tarfile.TarInfo(n))
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert not (tmp_path / "d").exists()


# F13: piped output shows progress; old Python gets a plain message
def test_progress_lines_without_a_terminal(bucket, tmp_path, capsys):
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 0
    assert "(100%)" in capsys.readouterr().err


def test_old_python_message(monkeypatch, capsys):
    monkeypatch.setattr(sys, "version_info", (3, 8, 18))
    assert cli.main(["list"]) == 1
    assert "needs Python 3.9" in capsys.readouterr().err


# F14: the generator
def test_listing_with_human_sizes_is_an_error():
    with pytest.raises(SystemExit, match="cannot parse"):
        gen_index.parse_listing("2026-10-24 11:26  1.2M  s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/library.tar.gz")


def test_keys_with_spaces_and_unknown_architectures_are_skipped(capsys):
    text = ("2026-10-24 11:26  5  s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/my library.tar.gz\n"
            "2026-10-24 11:26  5  s3://oaax/runtimes/2.0.0/CPU/riscv64/Ubuntu/library.tar.gz\n"
            "2026-10-24 11:26  5  s3://oaax/runtimes/2.0.0/CPU/arm64/Ubuntu/library.tar.gz\n")
    assert gen_index.catalog_from_listing(text) == []
    assert capsys.readouterr().err.count("skipped") == 3


def test_check_writes_nothing_and_hashing_sends_if_match(tmp_path, monkeypatch):
    listing = tmp_path / "l.txt"
    listing.write_text("2026-10-24 11:26  5  s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/library.tar.gz\n")
    monkeypatch.setattr(gen_index, "INDEX", tmp_path / "index.json")
    monkeypatch.setattr(gen_index, "PARTIAL", tmp_path / "index.partial.json")
    monkeypatch.setattr(gen_index, "build_entry", lambda item, old: {**item, "etag": "e", "sha256": "a" * 64})
    monkeypatch.setattr(sys, "argv", ["gen_index", "--listing", str(listing), "--check"])
    gen_index.main()
    assert not list(tmp_path.glob("index*.json"))

    seen = {}

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b""

    monkeypatch.setattr(gen_index.urllib.request, "urlopen", lambda req, timeout=None: seen.update(req.headers) or Resp())
    with pytest.raises(RuntimeError):
        gen_index.sha256_of("k", 5, "abc", attempts=1)
    assert seen["If-match"] == '"abc"'


# F15: broken archives are a clean error and leave nothing behind
def test_truncated_gzip_is_a_clean_error(tmp_path):
    make_tar(tmp_path / "full.tgz", {f"f{i}.so": os.urandom(5000) for i in range(20)})
    data = (tmp_path / "full.tgz").read_bytes()
    (tmp_path / "cut.tgz").write_bytes(data[: len(data) // 2])
    with pytest.raises(FetchError, match="cannot extract"):
        safe_extract(tmp_path / "cut.tgz", tmp_path / "d")
    assert not (tmp_path / "d").exists() and not (tmp_path / "d.extracting").exists()


def test_hardlink_to_a_missing_member_is_a_clean_error(tmp_path):
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        info = tarfile.TarInfo("h")
        info.type = tarfile.LNKTYPE
        info.linkname = "later"
        tar.addfile(info)
    with pytest.raises(FetchError, match="cannot extract"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert not (tmp_path / "d").exists() and not (tmp_path / "d.extracting").exists()


# F16: duplicates are judged on path components, not raw strings
@pytest.mark.parametrize("names", [["./a", "a"], ["a//b", "a/b"], ["./A", "a"], ["a/./b", "a/b"]])
def test_duplicates_with_odd_spellings_are_refused(tmp_path, names):
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        for n in names:
            tar.addfile(tarfile.TarInfo(n))
    with pytest.raises(FetchError, match="collides"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")


# F17: the generator never writes what the loader rejects
@pytest.mark.parametrize("key", [
    "runtimes/2.1.0-rc1/CPU/x86_64/Ubuntu/library.tar.gz",
    "runtimes/2.0.0/NVIDIA_ORT/x86_64/Ubuntu/library-CUDA_12.tar.gz",
    "runtimes/2.0.0/NVIDIA_ORT/x86_64/Ubuntu/library-cuda 12.tar.gz",
    "runtimes/2.0.0/NVIDIA_ORT/x86_64/Ubuntu/library-v2~beta.tar.gz",
    "runtimes/2.0.0/NVIDIA_ORT/x86_64/Ubuntu/library-.hidden.tar.gz",
])
def test_generator_skips_names_the_loader_would_reject(capsys, key):
    text = f"2026-10-24 11:26  5  s3://oaax/{key}\n2026-10-24 11:26  5  s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/library.tar.gz\n"
    catalog = gen_index.catalog_from_listing(text)
    assert [i["key"] for i in catalog] == ["runtimes/2.0.0/CPU/x86_64/Ubuntu/library.tar.gz"]
    assert "skipped" in capsys.readouterr().err


def test_every_entry_the_generator_makes_from_the_real_listing_loads(tmp_path):
    from pathlib import Path
    data = Path(__file__).parent / "data"
    text = "\n".join(p.read_text() for p in sorted(data.glob("listing-*.txt")))
    entries = [{**i, "sha256": "a" * 64, "etag": "e"} for i in gen_index.catalog_from_listing(text)]
    path = tmp_path / "i.json"
    path.write_text(json.dumps({"schema": 1, "base_url": "https://example.com", "artifacts": entries}))
    from oaax_manager.index import load_index
    assert len(load_index(path)) == 43


# F18
def test_docker_load_hint_is_quoted(bucket, tmp_path, capsys):
    out = tmp_path / "my dir"
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    hint = [l for l in capsys.readouterr().out.splitlines() if "docker load" in l][0]
    import shlex
    assert shlex.split(hint.split("docker load -i ", 1)[1].split("\n")[0])[0] == str(out / "tool.tar")


def test_small_files_do_not_report_zero_megabytes(bucket, tmp_path, capsys):
    run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o"))
    err = capsys.readouterr().err
    assert "0.0 / 0.0 MB" not in err and "12.0 KB / 12.0 KB (100%)" in err


def test_permanent_errors_are_not_retried(bucket, tmp_path, monkeypatch, capsys):
    import ssl
    import urllib.error
    import urllib.request
    calls = []

    def fail(exc):
        def urlopen(request, timeout=None):
            calls.append(1)
            raise exc
        return urlopen

    cases = [
        (urllib.error.HTTPError("u", 404, "Not Found", {}, None), "HTTP 404"),
        (urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate")), "certificate verification failed"),
        (OSError(28, "No space left on device"), "No space left"),
    ]
    for exc, text in cases:
        calls.clear()
        monkeypatch.setattr(download.urllib.request, "urlopen", fail(exc))
        assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 1
        err = capsys.readouterr().err
        assert text in err and "resume" not in err and len(calls) == 1, (text, err, calls)


def test_a_5xx_is_retried(bucket, tmp_path, monkeypatch):
    import urllib.error
    calls = []
    real = download.urllib.request.urlopen

    def flaky(request, timeout=None):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.HTTPError("u", 503, "Unavailable", {}, None)
        return real(request, timeout=timeout)

    monkeypatch.setattr(download.urllib.request, "urlopen", flaky)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 0
    assert len(calls) == 2


def test_options_that_do_not_apply_are_errors_not_ignored(bucket, capsys):
    assert run(bucket[1], "fetch", "toolchain", "cpu", "--os", "windows") == 1
    assert "only apply to runtimes" in capsys.readouterr().err
    assert run(bucket[1], "fetch", "runtime", "cpu", "--force") == 1
    assert "only applies to toolchains" in capsys.readouterr().err
