from __future__ import annotations

import hashlib
import http.server
import io
import json
import re
import tarfile
import threading
from pathlib import Path

import pytest


class RangeHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler plus single-range GET, so resume can be tested."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        header = self.headers.get("Range")
        path = Path(self.translate_path(self.path))
        if not header or not path.is_file():
            return super().do_GET()
        start = int(re.match(r"bytes=(\d+)-", header).group(1))
        data = path.read_bytes()[start:]
        self.send_response(206)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def make_tar(path: Path, members: dict[str, bytes], links: dict[str, str] | None = None) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)


def entry(root: Path, key: str, **fields) -> dict:
    data = (root / key).read_bytes()
    base = dict(kind="runtime", vendor="cpu", version="2.0.0", os="linux", arch="x86_64", variant=None,
                key=key, size=len(data), etag="x", sha256=hashlib.sha256(data).hexdigest())
    return {**base, **fields}


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "bucket"
    root.mkdir()
    handler = lambda *a, **k: RangeHandler(*a, directory=str(root), **k)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture
def make_index(server, tmp_path):
    """Write index.json for the given entries (dicts) and return its path."""
    root, url = server

    def write(entries: list[dict]) -> Path:
        path = tmp_path / "index.json"
        path.write_text(json.dumps({"schema": 1, "base_url": url, "artifacts": entries}))
        return path

    return write
