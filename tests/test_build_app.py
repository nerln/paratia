"""Bundle assembly fixtures: no compiler, signer, GUI or installer is run."""
from __future__ import annotations

import importlib.util
import json
import plistlib
import struct
import sys
from pathlib import Path

import pytest


@pytest.fixture()
def build(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / "strumenti" / "build-app.py"
    spec = importlib.util.spec_from_file_location("app_build_fixture", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = tmp_path.resolve()
    for name in module.MODULES:
        (module.ROOT / name).write_text("#!/usr/bin/env python3\nVALUE = 'synthetic'\n")
    (module.ROOT / "hookinstaller.py").write_text(
        "from pathlib import Path\ndef _runtime(): return Path('/protected/apple/python3')\n")
    for name in ("hooks/paratia-gate.py", "strumenti/banco-probe.py"):
        path = module.ROOT / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Synthetic resource\n")
    (module.ROOT / "macos").mkdir()
    (module.ROOT / "macos" / "Stub.swift").write_text("// Not compiled\n")
    monkeypatch.setattr(module.subprocess, "check_output", lambda *a, **k: "/synthetic-sdk\n")
    monkeypatch.setattr(sys, "argv", [str(script)])
    calls = []

    def run(argv):
        argv = list(map(str, argv))
        calls.append(argv)
        if argv[0] == "/usr/bin/xcrun":
            output = Path(argv[argv.index("-o") + 1])
            output.write_bytes(b"Synthetic compiler output; never executed")
        elif len(argv) > 1 and Path(argv[1]).name == "make-icon.py":
            output = Path(argv[argv.index("--output") + 1])
            # Encoding is tested separately. This fixture verifies placement,
            # Info.plist linkage and sealing order, with no native iconutil.
            output.write_bytes(b"icns" + struct.pack(">I", 16) + b"icp4" + struct.pack(">I", 8))

    monkeypatch.setattr(module, "run", run)
    return module, calls


def test_bundle_contains_linked_icon_before_codesign_in_noindex_output(build):
    module, calls = build
    module.main()
    app = module.ROOT / "build.noindex" / "Paratia.app"
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    icon = app / "Contents" / "Resources" / info["CFBundleIconFile"]
    assert info["CFBundleIconFile"] == "Paratia.icns"
    assert icon.is_file() and icon.read_bytes().startswith(b"icns")
    assert not (module.ROOT / "build").exists()
    icon_index = next(i for i, argv in enumerate(calls) if len(argv) > 1 and Path(argv[1]).name == "make-icon.py")
    sign_index = next(i for i, argv in enumerate(calls) if argv[:2] == ["/usr/bin/codesign", "--force"])
    assert icon_index < sign_index
    manifest = json.loads((app / "Contents" / "Resources" / "python" / "hooks" / "paratia-cli.json").read_text())
    assert manifest["cli"] == str(module.BOOTSTRAP_ROOT / "paratia.py")
    assert "ParatiaBootstrap.noindex/" in manifest["cli"]


def test_render_fixtures_uses_noindex_screenshots(build, monkeypatch):
    module, calls = build
    monkeypatch.setattr(sys, "argv", ["build-app.py", "--render-fixtures"])
    module.main()
    assert calls[-1][1:] == ["--render-fixtures", str(module.ROOT / "build.noindex" / "screenshots")]
