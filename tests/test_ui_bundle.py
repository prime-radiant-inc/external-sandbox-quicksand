"""Detect local edits, missing files, or stale files in the pinned UI bundle."""

import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path


def test_ui_bundle_matches_recorded_release():
    bundle = Path(str(files("remote_sandbox_quicksand").joinpath("ui")))
    manifest = json.loads((bundle / "manifest.json").read_text())
    package = json.loads((bundle / "package.json").read_text())
    assert manifest["schemaVersion"] == 1
    assert manifest["name"] == package["name"] == "remote-sandbox-ui"
    assert manifest["version"] == package["version"]
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["sourceCommit"])
    assert not any(path.is_symlink() for path in bundle.rglob("*"))
    actual = {
        path.relative_to(bundle).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in bundle.rglob("*") if path.is_file() and path != bundle / "manifest.json"
    }
    assert {"assets/terminal.html", "assets/terminal.js", "assets/proxy.html", "package.json"} <= actual.keys()
    assert actual == manifest["files"], "Update the UI from remote-sandbox-ui; do not edit the vendored bundle"
