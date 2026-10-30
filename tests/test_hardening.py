"""Regression tests for the adversary round 1 findings (F5-F14)."""

from __future__ import annotations

import http.server
import json
import os
import sys
import tarfile
import threading

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
    (tmp_path / "o" / "tool-2.0.0.tar").mkdir(parents=True)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")) == 1
    assert "is a directory" in capsys.readouterr().err


# F6: a second fetch of the same target is refused, the lock is released afterwards
def test_concurrent_fetch_is_refused(bucket, tmp_path, capsys):
    out = tmp_path / "o"
    with fetch_lock(out / "tool-2.0.0.tar"):
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
# ids matter: pytest puts the test id in an environment variable (32767 chars max on Windows)
@pytest.mark.parametrize("stale", [b"\x00" * 12000, b"y" * 5000], ids=["same-size-wrong-bytes", "shorter-foreign-part"])
def test_stale_part_is_retried_from_zero(bucket, tmp_path, stale):
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool-2.0.0.tar.part").write_bytes(stale)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool-2.0.0.tar").read_bytes() == b"docker-image" * 1000


def test_resume_response_for_another_offset_is_not_trusted(bucket, tmp_path, monkeypatch):
    real = download._resumes_at
    monkeypatch.setattr(download, "_resumes_at", lambda r, have: False)  # server "answers for another offset"
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool-2.0.0.tar.part").write_bytes(b"docker-image" * 400)
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (out / "tool-2.0.0.tar").read_bytes() == b"docker-image" * 1000
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
    assert "already fetched" in capsys.readouterr().out
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
    assert shlex.split(hint.split("docker load -i ", 1)[1].split("\n")[0])[0] == str(out / "tool-2.0.0.tar")


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


# adversary final report: transient Windows failures
def test_replace_retries_a_transient_permission_error(tmp_path, monkeypatch):
    src, dst = tmp_path / "a", tmp_path / "b"
    src.write_text("x")
    real, calls = type(src).replace, []

    def flaky(self, target):
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("locked by antivirus")
        return real(self, target)

    monkeypatch.setattr(type(src), "replace", flaky)
    download.replace_with_retry(src, dst)
    assert dst.read_text() == "x" and len(calls) == 3


def test_a_permanently_locked_replace_still_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(type(tmp_path), "replace", lambda self, t: (_ for _ in ()).throw(PermissionError("locked")))
    with pytest.raises(PermissionError):
        download.replace_with_retry(tmp_path / "a", tmp_path / "b", attempts=2)


def test_a_locked_archive_does_not_fail_a_good_extraction(bucket, tmp_path, monkeypatch, capsys):
    real_unlink = type(tmp_path).unlink

    def unlink(self, missing_ok=False):
        if self.name.endswith("library.tar.gz"):
            raise PermissionError("locked by antivirus")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(type(tmp_path), "unlink", unlink)
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(tmp_path / "o")) == 0
    assert (tmp_path / "o/runtime-cpu-2.0.0-linux-x86_64/libRuntimeLibrary.so").exists()


# adversary final report: mutations that survived (tests that could not fail)
def test_versions_order_numerically():
    from oaax_manager.index import version_key
    assert version_key("2.10.0") > version_key("2.9.0") > version_key("2.0.0")
    assert max(["2.9.0", "2.10.0", "2.2.0"], key=version_key) == "2.10.0"


@pytest.mark.parametrize("system, machine, expected", [
    ("Linux", "x86_64", ("linux", "x86_64")), ("Linux", "aarch64", ("linux", "aarch64")),
    ("Darwin", "arm64", ("macos", "aarch64")), ("Darwin", "x86_64", ("macos", "x86_64")),
    ("Windows", "AMD64", ("windows", "x86_64")), ("Windows", "ARM64", ("windows", "aarch64")),
    ("FreeBSD", "riscv64", ("freebsd", "riscv64")),
])
def test_host_platform_spellings(monkeypatch, system, machine, expected):
    import platform
    from oaax_manager import index
    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(platform, "machine", lambda: machine)
    assert index.host_platform() == expected


@pytest.mark.parametrize("base, ok", [
    ("https://example.com/b", True), ("http://127.0.0.1:8080/b", True), ("http://localhost:9/b", True),
    ("http://localhost.evil.com/b", False), ("http://127.0.0.1.evil.com/b", False),
    ("http://127.0.0.1@evil.com/b", False), ("http://evil.com/b", False), ("ftp://127.0.0.1/b", False),
    ("file:///etc/passwd", False),
])
def test_base_url_rules(tmp_path, base, ok):
    from oaax_manager.index import IndexError_, load_index
    path = tmp_path / "i.json"
    path.write_text(json.dumps({"schema": 1, "base_url": base, "artifacts": []}))
    if ok:
        assert load_index(path) == []
    else:
        with pytest.raises(IndexError_):
            load_index(path)


class FakeResponse:
    def __init__(self, status, content_range=None):
        self.status = status
        self.headers = {} if content_range is None else {"Content-Range": content_range}


@pytest.mark.parametrize("status, content_range, ok", [
    (206, "bytes 100-199/200", True), (206, "bytes 0-199/200", False), (206, "bytes 101-199/200", False),
    (206, None, False), (206, "garbage", False), (200, "bytes 100-199/200", False), (200, None, False),
])
def test_resume_requires_a_matching_content_range(status, content_range, ok):
    assert download._resumes_at(FakeResponse(status, content_range), 100) is ok


@POSIX_ONLY
def test_directory_and_file_modes(tmp_path):
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        for name, mode in (("d700", 0o700), ("d777", 0o777), ("d750", 0o750)):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = mode
            tar.addfile(info)
        for name, mode in (("d700/f600", 0o600), ("d777/f100", 0o100), ("d750/f444", 0o444)):
            info = tarfile.TarInfo(name)
            info.mode = mode
            tar.addfile(info)
    safe_extract(tmp_path / "a.tgz", tmp_path / "d", "a" * 64)
    mode = lambda n: (tmp_path / "d" / n).stat().st_mode & 0o7777  # noqa: E731
    assert [mode(n) for n in ("d700", "d777", "d750")] == [0o755] * 3
    assert [mode(n) for n in ("d700/f600", "d777/f100", "d750/f444")] == [0o644, 0o755, 0o644]


# adversary round A3: "already fetched" must mean the bytes on disk are still the extracted ones, not that a marker file exists
@pytest.fixture
def fetched(bucket, tmp_path):
    out = tmp_path / "o"
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    return bucket[1], out / "runtime-cpu-2.0.0-linux-x86_64"


def test_a_rerun_re_checks_the_files_and_prints_the_library_again(fetched, tmp_path, capsys):
    index, dest = fetched
    capsys.readouterr()
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 0
    out = capsys.readouterr().out
    assert "already fetched" in out and "2 files still match" in out and f"Runtime library: {dest / 'libRuntimeLibrary.so'}" in out


@pytest.mark.parametrize("damage", ["delete", "append", "same_size_other_bytes", "replace_by_link", "replace_by_dir"])
def test_a_damaged_runtime_directory_is_never_reported_as_verified(fetched, capsys, damage):
    index, dest = fetched
    lib = dest / "libRuntimeLibrary.so"
    if damage == "delete":
        lib.unlink()
    elif damage == "append":
        lib.write_bytes(lib.read_bytes() + b"x")
    elif damage == "same_size_other_bytes":
        lib.write_bytes(b"XX")
    elif damage == "replace_by_link":
        lib.unlink()
        lib.symlink_to(dest / "dep.so")
    else:
        lib.unlink()
        lib.mkdir()
    capsys.readouterr()
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 1
    captured = capsys.readouterr()
    assert "already fetched" not in captured.out and "delete" in captured.err and "run again" in captured.err


def test_a_marker_without_the_file_list_is_not_trusted(fetched, capsys):
    index, dest = fetched
    marker = dest / ".oaax-manager.json"
    sha = json.loads(marker.read_text())["archive_sha256"]
    marker.write_text(json.dumps({"archive_sha256": sha}))  # what an earlier version wrote
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 1
    assert "was not completed by this oaax-manager" in capsys.readouterr().err


# adversary round A7: a symlink planted in a shared output directory must never be written through
def test_a_symlinked_part_is_not_resumed_into(bucket, tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.write_text("PRECIOUS\n")
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool-2.0.0.tar.part").symlink_to(victim)
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert victim.read_text() == "PRECIOUS\n"
    assert (out / "tool-2.0.0.tar").read_bytes() == b"docker-image" * 1000


def test_the_part_is_opened_without_following_a_link(tmp_path):
    """The check-then-open race: even if a link appears after the stale-part check, nothing is written through it."""
    victim = tmp_path / "victim"
    victim.write_text("PRECIOUS\n")
    part = tmp_path / "x.part"
    part.symlink_to(victim)
    with pytest.raises(OSError):
        download._open_part(part, append=True)
    with pytest.raises(OSError):
        download._open_part(part, append=False)
    assert victim.read_text() == "PRECIOUS\n"


@pytest.mark.parametrize("plant", ["dangling_link", "link_to_dir", "file"])
def test_a_planted_extracting_entry_is_replaced_not_followed(bucket, tmp_path, monkeypatch, plant):
    out = tmp_path / "o"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = out / "runtime-cpu-2.0.0-linux-x86_64.extracting"
    if plant == "dangling_link":
        target.symlink_to(tmp_path / "nowhere")
    elif plant == "link_to_dir":
        target.symlink_to(elsewhere)
    else:
        target.write_text("junk")
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    assert list(elsewhere.iterdir()) == []
    assert (out / "runtime-cpu-2.0.0-linux-x86_64" / "libRuntimeLibrary.so").read_bytes() == b"so"


# adversary round A2/A4: proxies and servers that cut a response in ways urllib does not turn into OSError
import hashlib  # noqa: E402
import http.client  # noqa: E402
import http.server  # noqa: E402
import socketserver  # noqa: E402
import threading  # noqa: E402

DATA = bytes(range(256)) * 1000  # 256 000 bytes


class _Cutting(socketserver.StreamRequestHandler):
    """First request: a chunked 200 that sends `cut` bytes and closes without the final chunk. Later requests: the whole file, honest."""

    def handle(self):
        request = self.rfile.readline()
        headers = b""
        while (line := self.rfile.readline()) not in (b"\r\n", b""):
            headers += line
        self.server.requests.append(headers.lower())
        if self.server.cut is not None and (self.server.always or len(self.server.requests) == 1):
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            body = DATA[: self.server.cut]
            self.wfile.write(b"%x\r\n" % len(body) + body + b"\r\n")
            return  # close: the chunked body never ends
        if self.server.garbage:
            self.wfile.write(b"GARBAGE\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(DATA) + DATA)


@pytest.fixture
def cutting_server():
    servers = []

    def start(cut=None, garbage=False, always=False):
        httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Cutting)
        httpd.requests, httpd.cut, httpd.garbage, httpd.always = [], cut, garbage, always
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/f"

    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def test_a_response_cut_in_the_middle_is_a_clean_retryable_error_not_a_traceback(cutting_server, tmp_path, monkeypatch):
    httpd, url = cutting_server(cut=100_000, always=True)
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    with pytest.raises(FetchError, match="run the same command again"):  # not http.client.IncompleteRead
        download.download(url, tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
    assert len(httpd.requests) >= 3  # retried (resume asks with Range, a server that ignores it makes the tool restart), then reported


def test_a_cut_response_is_retried_and_ends_with_a_verified_file(cutting_server, tmp_path, monkeypatch):
    httpd, url = cutting_server(cut=100_000)  # only the first response is cut
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    download.download(url, tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
    assert (tmp_path / "f").read_bytes() == DATA
    assert any(b"range: bytes=" in r for r in httpd.requests[1:])  # the retry resumed


def test_garbage_instead_of_an_http_status_is_a_clean_error(cutting_server, tmp_path, monkeypatch):
    httpd, url = cutting_server(garbage=True)
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    with pytest.raises(FetchError, match="run the same command again"):
        download.download(url, tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
    assert len(httpd.requests) == 3  # retried, then reported


def test_a_complete_part_is_not_asked_for_again(tmp_path):
    """A4: all bytes arrived but the end of the chunked body never did; the retry asked for `Range: bytes=<size>-`, got 416 and failed for good."""
    part = tmp_path / "f.part"
    part.write_bytes(DATA)
    download._transfer_with_retries("http://127.0.0.1:9/never-contacted", part, len(DATA))  # would raise if it connected
    assert part.read_bytes() == DATA


def test_a_body_that_arrived_whole_succeeds_even_if_its_end_marker_never_does(cutting_server, tmp_path):
    httpd, url = cutting_server(cut=len(DATA))
    download.download(url, tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
    assert (tmp_path / "f").read_bytes() == DATA
    assert len(httpd.requests) == 1


# adversary round A6/A8/A9: smaller defects
def test_differences_compare_whole_entries_but_not_the_etag():
    """A6: --check compared only sha256, so a vendor id or variant that regeneration would rename went unnoticed."""
    a = dict(kind="runtime", vendor="nvidia-ort", version="2.0.0", os="linux", arch="x86_64", variant="cuda12", key="k", size=1, etag="e1", sha256="a" * 64)
    assert gen_index.differences([a], [{**a, "etag": "e2"}]) == []
    assert gen_index.differences([a], [{**a, "vendor": "nvidia-onnx"}]) == ["CHANGED: k (vendor)"]
    assert gen_index.differences([a], [{**a, "variant": None, "size": 2}]) == ["CHANGED: k (size, variant)"]
    assert gen_index.differences([a], []) == ["gone:    k"] and gen_index.differences([], [a]) == ["new:     k"]


def test_gen_index_exits_2_when_it_could_not_check(tmp_path):
    """A6: exit 1 means "the index differs"; a crash must not look like that."""
    import subprocess

    done = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "tools", "gen_index.py"), "--check", "--listing", str(tmp_path / "missing")], capture_output=True, text=True)
    assert done.returncode == 2 and "error:" in done.stderr


def test_two_toolchain_versions_can_share_one_output_directory(server, make_index, tmp_path, monkeypatch):
    """A8: the toolchain file was named after the key basename only, so fetching 2.1.0 replaced the verified 2.0.0 tar."""
    root, _ = server
    (root / "tc").mkdir()
    (root / "tc/tool.tar").write_bytes(b"v2.0" * 100)
    (root / "tc/tool21.tar").write_bytes(b"v2.1" * 100)
    index = make_index([entry(root, "tc/tool.tar", kind="toolchain", os="any", arch="any"),
                        entry(root, "tc/tool21.tar", kind="toolchain", os="any", arch="any", version="2.1.0")])
    out = tmp_path / "o"
    assert run(index, "fetch", "toolchain", "cpu", "--artifact-version", "2.0.0", "-o", str(out)) == 0
    assert run(index, "fetch", "toolchain", "cpu", "--artifact-version", "2.1.0", "-o", str(out)) == 0
    assert sorted(p.name for p in out.glob("*.tar")) == ["tool-2.0.0.tar", "tool21-2.1.0.tar"]
    assert (out / "tool-2.0.0.tar").read_bytes() == b"v2.0" * 100


def test_fetch_help_says_newest_for_this_platform(capsys):
    with pytest.raises(SystemExit):
        cli.main(["fetch", "--help"])
    assert "newest version available for your platform" in " ".join(capsys.readouterr().out.split())


# adversary round, second batch: variants, redirects, lock link, forged marker, unreadable file
def _two_version_index(server, make_index, tmp_path, variants_new, variants_old):
    root, _ = server
    (root / "rt").mkdir(exist_ok=True)
    entries = []
    for version, variants in (("2.0.0", variants_old), ("2.1.0", variants_new)):
        for variant in variants:
            key = f"rt/h-{version}-{variant}.tar.gz"
            make_tar(root / key, {"libRuntimeLibrary.so": f"{version}{variant}".encode()})
            entries.append(entry(root, key, vendor="hailo", version=version, variant=variant))
    return make_index(entries)


def test_a_variant_error_lists_the_real_variants_for_the_platform(server, make_index, tmp_path, monkeypatch, capsys):
    """A12a: the README's `--variant cuda12` example on another platform said only "no runtime with variant"."""
    index = _two_version_index(server, make_index, tmp_path, ["hailort4.18.0", "hailort4.19.0"], ["hailort4.17.0"])
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    assert run(index, "fetch", "runtime", "hailo", "--variant", "cuda99") == 1
    err = capsys.readouterr().err
    assert "variant 'cuda99' for linux-x86_64" in err and "hailort4.17.0, hailort4.18.0, hailort4.19.0" in err and "--os/--arch" in err


def test_the_variant_is_filtered_before_the_newest_version_is_picked(server, make_index, tmp_path, monkeypatch, capsys):
    """A12b: hailort4.17.0 exists only in 2.0.0; the newest version (2.1.0) lacks it, which used to read "no such variant"."""
    index = _two_version_index(server, make_index, tmp_path, ["hailort4.18.0", "hailort4.19.0"], ["hailort4.17.0", "hailort4.18.0"])
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    out = tmp_path / "o"
    assert run(index, "fetch", "runtime", "hailo", "--variant", "hailort4.17.0", "-o", str(out)) == 0
    assert (out / "runtime-hailo-2.0.0-linux-x86_64-hailort4.17.0" / "libRuntimeLibrary.so").exists()
    assert run(index, "fetch", "runtime", "hailo", "--variant", "hailort4.18.0", "-o", str(out)) == 0  # in both: the newest wins
    assert (out / "runtime-hailo-2.1.0-linux-x86_64-hailort4.18.0").is_dir()


def test_a_vendor_that_exists_only_as_the_other_kind_says_so(server, make_index, capsys):
    root, _ = server
    (root / "tc").mkdir()
    (root / "tc/t.tar").write_bytes(b"x" * 100)
    index = make_index([entry(root, "tc/t.tar", kind="toolchain", os="any", arch="any")])
    assert run(index, "fetch", "runtime", "cpu") == 1
    err = capsys.readouterr().err
    assert "oaax-manager fetch toolchain cpu" in err and "Available: \n" not in err and "Available: ," not in err


class _Redirect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", self.server.target)
        self.end_headers()

    log_message = lambda *a: None  # noqa: E731


@pytest.mark.parametrize("target", ["ftp://127.0.0.1:2121/x", "http://203.0.113.9/x"])
def test_a_redirect_to_anything_but_https_is_refused(tmp_path, target):
    """A11: urllib followed redirects to ftp:// and http://, so "base_url must be https" was bypassable by any redirect."""
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Redirect)
    httpd.target = target
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with pytest.raises(download.ServerError, match="only https is allowed"):
            download.download(f"http://127.0.0.1:{httpd.server_address[1]}/f", tmp_path / "f", 10, "0" * 64)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_redirect_to_a_file_url_is_refused_too(tmp_path, monkeypatch):
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Redirect)
    httpd.target = "file:///etc/hostname"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with pytest.raises(FetchError, match="not allowed"):  # urllib itself refuses this scheme
            download.download(f"http://127.0.0.1:{httpd.server_address[1]}/f", tmp_path / "f", 10, "0" * 64)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_dangling_lock_link_does_not_create_a_file_elsewhere(tmp_path):
    target = tmp_path / "elsewhere" / "created"
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / ".x.lock").symlink_to(target)
    with pytest.raises(FetchError, match="lock file"):
        with fetch_lock(tmp_path / "x"):
            pass
    assert not target.exists()


def test_a_forged_marker_without_files_is_not_trusted(fetched, capsys):
    index, dest = fetched
    marker = dest / ".oaax-manager.json"
    sha = json.loads(marker.read_text())["archive_sha256"]
    marker.write_text(json.dumps({"archive_sha256": sha, "files": {}, "links": {}}))
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 1
    assert "was not completed" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions and a non-root user")
def test_an_unreadable_extracted_file_says_which_one_and_what_to_do(fetched, capsys):
    index, dest = fetched
    (dest / "dep.so").chmod(0)
    try:
        assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 1
    finally:
        (dest / "dep.so").chmod(0o644)
    err = capsys.readouterr().err
    assert "cannot read" in err and "dep.so" in err and "permissions" in err and "output directory" not in err


# adversary round 2: B1 (a re-upload with another size) and B2 (https origin redirecting to a local http service)
class _Object(http.server.BaseHTTPRequestHandler):
    """Serves `self.server.data`; answers a Range request beyond the end with 416 (RFC 7233)."""

    def do_GET(self):
        data = self.server.data
        self.server.requests.append(self.headers.get("Range"))
        rng = self.headers.get("Range")
        if rng:
            start = int(rng.split("=")[1].rstrip("-"))
            if start >= len(data):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(data)}")
                self.end_headers()
                return
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
            body = data[start:]
        else:
            self.send_response(200)
            body = data
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    log_message = lambda *a: None  # noqa: E731


@pytest.fixture
def object_server():
    started = []

    def start(data):
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Object)
        httpd.data, httpd.requests = data, []
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        started.append(httpd)
        return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/f"

    yield start
    for httpd in started:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("served", [len(DATA) - 10, len(DATA) + 10])
def test_a_reupload_with_another_size_says_to_upgrade_and_leaves_no_part(object_server, tmp_path, monkeypatch, served):
    """B1: a smaller object looped on HTTP 416 forever with a stale .part; a larger one gave no upgrade hint. Only an equal size got the message."""
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    httpd, url = object_server((DATA + DATA)[:served])
    for _ in range(2):  # the second run must not be stuck on a leftover
        with pytest.raises(download.ServerError, match="upgrade oaax-manager"):
            download.download(url, tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
        assert not (tmp_path / "f.part").exists() and not (tmp_path / "f").exists()


def test_an_https_origin_cannot_make_us_request_a_local_http_service(tmp_path):
    """B2: any redirect to http://127.0.0.1:<port>/<path> was followed; the localhost exception is for a localhost base_url only."""
    victim = http.server.HTTPServer(("127.0.0.1", 0), _Object)
    victim.data, victim.requests = b"x", []
    threading.Thread(target=victim.serve_forever, daemon=True).start()
    handler = download._HttpsOnlyRedirects()
    req = download.urllib.request.Request("https://example.invalid/f")
    try:
        with pytest.raises(download.ServerError, match="only https is allowed"):
            handler.redirect_request(req, None, 302, "Found", {}, f"http://127.0.0.1:{victim.server_address[1]}/internal-admin/reset")
        # tests and mirrors on a localhost http base_url keep working
        local = download.urllib.request.Request("http://127.0.0.1:1/f")
        assert handler.redirect_request(local, None, 302, "Found", {}, "http://127.0.0.1:2/g") is not None
        assert victim.requests == []
    finally:
        victim.shutdown()
        victim.server_close()


# adversary round 2, batch B3-B12
class _LongChunked(socketserver.StreamRequestHandler):
    """A chunked body that is complete but two bytes LONGER than the pin (no Content-Length to compare)."""

    def handle(self):
        while self.rfile.readline() not in (b"\r\n", b""):
            pass
        body = DATA + b"zz"
        self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")


def test_b3_a_chunked_body_longer_than_the_pin_says_to_upgrade(tmp_path, monkeypatch):
    monkeypatch.setattr(download.time, "sleep", lambda s: None)
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _LongChunked)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with pytest.raises(download.ServerError, match="upgrade oaax-manager"):
            download.download(f"http://127.0.0.1:{httpd.server_address[1]}/f", tmp_path / "f", len(DATA), hashlib.sha256(DATA).hexdigest())
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("code,expect", [(11, "already fetching"), (35, "already fetching"), (37, "cannot lock")])
def test_b4_only_a_held_lock_means_already_fetching(tmp_path, monkeypatch, code, expect):
    """B4: any OSError of the lock call used to read "another oaax-manager is already fetching" (NFS/FUSE: ENOLCK)."""
    import errno

    chosen = {11: errno.EAGAIN, 35: errno.EWOULDBLOCK, 37: errno.ENOLCK}[code]
    monkeypatch.setattr(download, "_try_lock", lambda handle: (_ for _ in ()).throw(OSError(chosen, os.strerror(chosen))))
    with pytest.raises(FetchError, match=expect):
        with fetch_lock(tmp_path / "x"):
            pass


@pytest.mark.skipif(sys.platform == "win32", reason="creating symlinks needs a privilege on Windows")
def test_b5_a_toolchain_tar_that_is_a_link_to_another_disk_is_not_refused(bucket, tmp_path, capsys):
    other = tmp_path / "other-disk"
    other.mkdir()
    out = tmp_path / "o"
    out.mkdir()
    (other / "big.tar").write_bytes(b"docker-image" * 1000)  # already the right bytes
    (out / "tool-2.0.0.tar").symlink_to(other / "big.tar")
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert "already downloaded and verified" in capsys.readouterr().out
    assert (other / "big.tar").read_bytes() == b"docker-image" * 1000


@pytest.mark.skipif(sys.platform == "win32", reason="creating symlinks needs a privilege on Windows")
def test_b5_a_link_to_other_content_is_replaced_never_written_through(bucket, tmp_path):
    other = tmp_path / "other-disk"
    other.mkdir()
    out = tmp_path / "o"
    out.mkdir()
    (other / "precious").write_text("PRECIOUS")
    (out / "tool-2.0.0.tar").symlink_to(other / "precious")
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert (other / "precious").read_text() == "PRECIOUS"
    assert (out / "tool-2.0.0.tar").read_bytes() == b"docker-image" * 1000 and not (out / "tool-2.0.0.tar").is_symlink()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_b6_changed_permissions_or_extra_files(fetched, capsys):
    index, dest = fetched
    (dest / "extra.txt").write_text("mine")  # added by the user: tolerated and said so
    capsys.readouterr()
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 0
    assert "permissions" in capsys.readouterr().out
    (dest / "libRuntimeLibrary.so").chmod(0o4777)
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 1
    assert "other permissions" in capsys.readouterr().err


def _tar_with(path, build):
    with tarfile.open(path, "w:gz") as tar:
        build(tar)


def _add(tar, name, data=None, kind=tarfile.REGTYPE, linkname=""):
    import io

    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, linkname
    if kind == tarfile.REGTYPE:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    else:
        info.mode = 0o755
        tar.addfile(info)


def test_b7_an_archive_without_a_regular_file_installs_nothing(server, make_index, tmp_path, monkeypatch, capsys):
    root, _ = server
    (root / "rt").mkdir()
    _tar_with(root / "rt/empty.tar.gz", lambda t: (_add(t, "d", kind=tarfile.DIRTYPE), _add(t, "link", kind=tarfile.SYMTYPE, linkname="d")))
    index = make_index([entry(root, "rt/empty.tar.gz")])
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    out = tmp_path / "o"
    assert run(index, "fetch", "runtime", "cpu", "-o", str(out)) == 1
    assert "contains no file" in capsys.readouterr().err
    assert [p.name for p in out.iterdir() if not p.name.startswith(".")] == []


def test_b7_hard_links_are_counted_the_same_on_the_first_run_and_the_rerun(server, make_index, tmp_path, monkeypatch, capsys):
    root, _ = server
    (root / "rt").mkdir()
    _tar_with(root / "rt/hl.tar.gz", lambda t: (_add(t, "libRuntimeLibrary.so", b"so"), _add(t, "copy.so", kind=tarfile.LNKTYPE, linkname="libRuntimeLibrary.so")))
    index = make_index([entry(root, "rt/hl.tar.gz")])
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    out = tmp_path / "o"
    assert run(index, "fetch", "runtime", "cpu", "-o", str(out)) == 0
    first = capsys.readouterr().out
    assert run(index, "fetch", "runtime", "cpu", "-o", str(out)) == 0
    second = capsys.readouterr().out
    assert "extracted 2 files" in first and "its 2 files" in second


@pytest.mark.parametrize("name", [".OAAX-MANAGER.JSON", "./.Oaax-Manager.Json", ".oaax-manager.json"])
def test_b8_the_marker_name_is_reserved_in_any_case(tmp_path, name):
    archive = tmp_path / "a.tar.gz"
    _tar_with(archive, lambda t: _add(t, name, b"x"))
    with pytest.raises(FetchError, match="reserved"):
        safe_extract(archive, tmp_path / "dest", "0" * 64)


def test_b9_a_slow_link_is_reported_once_not_retried_silently(tmp_path, monkeypatch):
    calls = []

    def slow(url, part, have, size):
        calls.append(1)
        raise download.SlowDownload("download of x is too slow: check the connection, then run the same command again to resume")

    monkeypatch.setattr(download, "_transfer", slow)
    monkeypatch.setattr(download.time, "sleep", lambda s: pytest.fail("a slow link must not be retried"))
    with pytest.raises(download.SlowDownload, match="run the same command again"):
        download._transfer_with_retries("http://x/f", tmp_path / "f.part", 100)
    assert len(calls) == 1


def test_b10_the_release_waits_for_the_tests():
    root = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows")
    build, tests = (open(os.path.join(root, f)).read() for f in ("build.yml", "test.yml"))
    assert "workflow_call:" in tests and "uses: ./.github/workflows/test.yml" in build and "needs: [build, tests]" in build


def test_b11_an_existing_toolchain_of_another_size_is_not_hashed_and_the_part_counts_for_the_disk(bucket, tmp_path, monkeypatch, capsys):
    out = tmp_path / "o"
    out.mkdir()
    (out / "tool-2.0.0.tar").write_bytes(b"wrong size")
    (out / "tool-2.0.0.tar.part").write_bytes(b"x" * 5000)
    monkeypatch.setattr(cli, "sha256_file", lambda p: pytest.fail("a file of another size was hashed"))
    needed = []
    real = cli.check_disk_space
    monkeypatch.setattr(cli, "check_disk_space", lambda d, n: (needed.append(n), real(d, n))[1])
    assert run(bucket[1], "fetch", "toolchain", "cpu", "-o", str(out)) == 0
    assert needed == [12000 - 5000]


def test_b11_a_rerun_says_it_is_checking(fetched, capsys):
    index, dest = fetched
    capsys.readouterr()
    assert run(index, "fetch", "runtime", "cpu", "-o", str(dest.parent)) == 0
    assert "Checking the extracted files" in capsys.readouterr().out


def test_b12_an_unknown_version_lists_the_versions_that_exist(server, make_index, tmp_path, monkeypatch, capsys):
    index = _two_version_index(server, make_index, tmp_path, ["hailort4.18.0"], ["hailort4.18.0"])
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    assert run(index, "fetch", "runtime", "hailo", "--artifact-version", "2.0") == 1
    assert "Versions available for linux-x86_64: 2.0.0, 2.1.0" in capsys.readouterr().err


def test_every_yaml_file_under_dot_github_parses():
    """A backtick at the start of a plain scalar made bug_report.yml invalid: GitHub then silently drops the issue form, and a workflow with
    invalid YAML fails only when it is needed. Nothing else reads these files before a tag."""
    import pathlib

    import yaml

    files = [p for ext in ("yml", "yaml") for p in (pathlib.Path(__file__).resolve().parent.parent / ".github").rglob(f"*.{ext}")]
    assert len(files) >= 5
    for path in files:
        yaml.safe_load(path.read_text())


@pytest.mark.parametrize("name", ["README.md", "README.pypi.md"])
def test_the_readmes_have_no_relative_links(name):
    """PyPI renders README.pypi.md as the project page (and the GitHub README may be copied there): a relative link (CHANGELOG.md) is broken, so links are absolute URLs or in-page anchors."""
    import pathlib
    import re

    text = (pathlib.Path(__file__).resolve().parent.parent / name).read_text()
    relative = [t for t in re.findall(r"\]\(([^)\s]+)\)", text) if not t.startswith(("http://", "https://", "#", "mailto:"))]
    assert relative == []


def test_the_pypi_page_is_the_pypi_readme():
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    assert 'readme = "README.pypi.md"' in (root / "pyproject.toml").read_text()
    assert 'email = "pypi@oaax.org"' in (root / "pyproject.toml").read_text()  # the PyPI maintainer contact is the role mailbox
    for block in (root / "README.pypi.md").read_text().split("```")[1::2]:
        assert "](" not in block  # a markdown link inside a code block shows raw on PyPI


def test_a_read_only_output_directory_does_not_blame_a_link(tmp_path):
    """E3: the hint "a link there?" is for a symlink only; a permission error says to check that -o is writable."""
    import os
    import sys

    if sys.platform == "win32" or os.geteuid() == 0:
        pytest.skip("needs POSIX permissions and a non-root user")
    out = tmp_path / "ro"
    out.mkdir()
    out.chmod(0o555)
    try:
        with pytest.raises(FetchError) as caught:
            with fetch_lock(out / "x"):
                pass
    finally:
        out.chmod(0o755)
    assert "link" not in str(caught.value) and "writable" in str(caught.value)


# adversary final pass: E4 (Ctrl-C during extraction), E7 (piped output order), E8 (proxy hint)
def test_ctrl_c_during_extraction_removes_the_temp_dir_and_keeps_the_verified_archive(bucket, tmp_path, monkeypatch, capsys):
    """E4: `<dest>.extracting` was left behind and the verified archive deleted, so a 1 GB runtime was downloaded again after every Ctrl-C."""
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    out = tmp_path / "o"

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(download, "_normalise_modes", interrupted)  # called inside the extraction, after the temp dir exists
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 130
    assert not list(out.glob("*.extracting")) and not (out / "runtime-cpu-2.0.0-linux-x86_64").exists()
    archives = list(out.glob("runtime-*.tar.gz"))
    assert len(archives) == 1
    monkeypatch.undo()
    monkeypatch.setattr(cli, "host_platform", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(download, "download", lambda *a, **k: pytest.fail("the verified archive must be reused, not downloaded again"))
    monkeypatch.setattr(cli, "download", download.download)
    capsys.readouterr()
    assert run(bucket[1], "fetch", "runtime", "cpu", "-o", str(out)) == 0
    assert "verified archive left by an earlier run" in capsys.readouterr().out
    assert not list(out.glob("runtime-*.tar.gz")) and (out / "runtime-cpu-2.0.0-linux-x86_64" / "libRuntimeLibrary.so").exists()


def test_piped_output_keeps_the_header_before_the_progress_lines(bucket, tmp_path):
    """E7: stdout is block-buffered when piped, so "Downloading ..." came after the progress lines of stderr."""
    import subprocess

    done = subprocess.run([sys.executable, "-m", "oaax_manager", "--index", str(bucket[1]), "fetch", "toolchain", "cpu", "-o", str(tmp_path / "o")],
                          capture_output=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(tmp_path),
                          env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
    assert done.returncode == 0, done.stdout
    assert 0 <= done.stdout.index("Downloading") < done.stdout.index("%")


def test_a_hash_mismatch_also_names_a_proxy_or_captive_portal():
    assert "captive portal" in download.STALE_PIN and "upgrade oaax-manager" in download.STALE_PIN
