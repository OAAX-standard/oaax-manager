import os
import sys

import pytest

from conftest import make_tar
from oaax_manager.download import FetchError, safe_extract


def test_normal_archive(tmp_path):
    make_tar(tmp_path / "a.tgz", {"lib.so": b"x", "sub/dep.so": b"y"})
    assert safe_extract(tmp_path / "a.tgz", tmp_path / "d") == ["lib.so", "sub/dep.so"]
    assert (tmp_path / "d/sub/dep.so").read_bytes() == b"y"


@pytest.mark.parametrize("name", ["../escape.txt", "a/../../escape.txt", "/abs.txt", "C:/win.txt", "C:\\win.txt", "\\root.txt", "a\\b.txt", "file.txt:stream"])
def test_unsafe_paths_are_refused_before_writing(tmp_path, name):
    make_tar(tmp_path / "a.tgz", {"ok.so": b"x", name: b"evil"})
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert not (tmp_path / "d/ok.so").exists()
    assert not (tmp_path / "escape.txt").exists()


def test_symlink_escape_is_refused(tmp_path):
    make_tar(tmp_path / "a.tgz", {"ok.so": b"x"}, links={"libRuntimeLibrary.so": "/etc/passwd"})
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")


def test_symlink_then_write_through_it_is_refused(tmp_path):
    make_tar(tmp_path / "a.tgz", {"link/pwn.txt": b"evil"}, links={"link": "../outside"})
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert not (tmp_path / "outside").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_relative_symlink_inside_is_kept(tmp_path):
    make_tar(tmp_path / "a.tgz", {"libx.so.1": b"x"}, links={"libx.so": "libx.so.1"})
    safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert os.readlink(tmp_path / "d/libx.so") == "libx.so.1"


def test_corrupt_archive_is_a_clean_error(tmp_path):
    (tmp_path / "a.tgz").write_bytes(b"not a tar")
    with pytest.raises(FetchError, match="cannot extract"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")


def test_failure_midway_leaves_no_destination(tmp_path):
    # "a" is a file, so extracting "a/b" fails after "a" was written
    make_tar(tmp_path / "a.tgz", {"a": b"x", "a/b": b"y"})
    with pytest.raises(FetchError, match="cannot extract"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
    assert not (tmp_path / "d").exists()
    assert not (tmp_path / "d.extracting").exists()


def test_existing_destination_is_refused(tmp_path):
    make_tar(tmp_path / "a.tgz", {"x": b"x"})
    (tmp_path / "d").mkdir()
    with pytest.raises(FetchError, match="already exists"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")


def make_chain_tar(path):
    import io
    import tarfile
    with tarfile.open(path, "w:gz") as tar:
        d = tarfile.TarInfo("x")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        for name, target in (("x/y", ".."), ("c", "x/y/..")):
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
        f = tarfile.TarInfo("c/pwn.txt")
        f.size = 4
        tar.addfile(f, io.BytesIO(b"evil"))


@pytest.mark.parametrize("with_filter", [True, False])
def test_symlink_chain_write_through_is_refused_on_every_python(tmp_path, monkeypatch, with_filter):
    import tarfile
    if not with_filter:  # Pythons before 3.9.17 / 3.10.12 / 3.11.4 have no tarfile.data_filter
        monkeypatch.delattr(tarfile, "data_filter", raising=False)
    make_chain_tar(tmp_path / "a.tgz")
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", work / "d")
    assert not (tmp_path / "pwn.txt").exists() and not (work / "pwn.txt").exists()


@pytest.mark.parametrize("target", ["..", "../x", "a/../../x", "/etc/passwd", "C:/x", "a\\b"])
def test_links_must_point_down(tmp_path, target):
    make_tar(tmp_path / "a.tgz", {"ok.so": b"x"}, links={"l": target})
    with pytest.raises(FetchError, match="unsafe archive"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")


def test_nothing_is_written_through_an_archive_link(tmp_path):
    import io
    import tarfile
    with tarfile.open(tmp_path / "a.tgz", "w:gz") as tar:
        d = tarfile.TarInfo("real")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        link = tarfile.TarInfo("alias")
        link.type = tarfile.SYMTYPE
        link.linkname = "real"
        tar.addfile(link)
        f = tarfile.TarInfo("alias/file")
        f.size = 1
        tar.addfile(f, io.BytesIO(b"x"))
    with pytest.raises(FetchError, match="written through a link"):
        safe_extract(tmp_path / "a.tgz", tmp_path / "d")
