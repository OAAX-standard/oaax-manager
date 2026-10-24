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
