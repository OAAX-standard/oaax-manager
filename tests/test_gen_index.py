"""The index generator turns a real `s3cmd ls --recursive` listing (tests/data) into index entries."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import gen_index  # noqa: E402

DATA = Path(__file__).parent / "data"


@pytest.fixture(scope="module")
def catalog():
    text = "\n".join(p.read_text() for p in sorted(DATA.glob("listing-*.txt")))
    return gen_index.catalog_from_listing(text)


def find(catalog, **fields):
    hits = [i for i in catalog if all(i[k] == v for k, v in fields.items())]
    assert len(hits) == 1, hits
    return hits[0]


def test_every_archive_and_the_conversion_wheel_are_classified(catalog, capsys):
    assert len(catalog) == 44
    assert [i["kind"] for i in catalog].count("wheel") == 1
    assert capsys.readouterr().err == ""


def test_the_wheel_pairs_with_its_toolchain(catalog):
    wheel = find(catalog, kind="wheel")
    assert (wheel["vendor"], wheel["version"], wheel["os"], wheel["arch"]) == ("nvidia-trt", "2.0.0", "any", "any")
    assert wheel["key"].endswith("/oaax_nvidia_tensorrt_conversion-2.0.0-py3-none-any.whl")


def test_a_wheel_whose_version_differs_from_its_folder_is_skipped():
    key = "conversion-toolchain/2.0.0/NVIDIA/oaax_nvidia_tensorrt_conversion-1.0.0-py3-none-any.whl"
    assert gen_index.classify(key, 1) is None


def test_identities_are_unique(catalog):
    ids = [(i["kind"], i["vendor"], i["version"], i["os"], i["arch"], i["variant"]) for i in catalog]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("fields, variant", [
    (dict(vendor="cpu", os="linux", arch="aarch64"), None),
    (dict(vendor="hailo", arch="x86_64"), "hailort4.20.0"),
    (dict(vendor="deepx", arch="aarch64", variant="ubuntu24.04-dxrt3.3.2"), "ubuntu24.04-dxrt3.3.2"),
    (dict(vendor="nvidia-ort", os="windows", variant="cuda12"), "cuda12"),
    (dict(vendor="nvidia-ort", arch="aarch64", variant="jetson-cuda12"), "jetson-cuda12"),
    (dict(vendor="nvidia-ort", arch="aarch64", variant="sbsa-cuda13"), "sbsa-cuda13"),
    (dict(vendor="nvidia-trt", arch="x86_64", variant="ubuntu22.04-trt11-cuda13"), "ubuntu22.04-trt11-cuda13"),
])
def test_runtime_variants(catalog, fields, variant):
    if "variant" not in fields and variant:
        fields = {**fields, "variant": variant}
    assert find(catalog, kind="runtime", **fields)["variant"] == variant


def test_nvidia_toolchains_pair_with_their_runtimes(catalog):
    assert find(catalog, kind="toolchain", vendor="nvidia-ort")["key"].endswith("oaax-nvidia-onnxruntime-toolchain.tar")
    assert find(catalog, kind="toolchain", vendor="nvidia-trt")["key"].endswith("oaax-nvidia-tensorrt-toolchain.tar")


def test_sizes_come_from_the_listing(catalog):
    assert find(catalog, kind="toolchain", vendor="deepx")["size"] == 6123229696


def test_a_non_archive_or_unknown_layout_is_skipped_not_guessed():
    assert gen_index.classify("runtimes/2.0.0/CPU/x86_64/Ubuntu/readme.txt", 1) is None
    assert gen_index.classify("runtimes/2.0.0/CPU/riscv/FreeBSD/library.tar.gz", 1) is None
    assert gen_index.parse_listing("garbage\n2026-10-24 11:26  12  s3://oaax/a/b.tar") == [("a/b.tar", 12)]


def test_colliding_keys_abort():
    text = "2026-10-24 11:26 1 s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/library.tar.gz\n" \
           "2026-10-24 11:26 1 s3://oaax/runtimes/2.0.0/CPU/x86_64/Ubuntu/library-.tar.gz\n"
    with pytest.raises(SystemExit):
        gen_index.catalog_from_listing(text)
