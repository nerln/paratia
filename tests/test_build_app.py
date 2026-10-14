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
    for lingua in ("it", "en", "es"):
        pasta = module.ROOT / "macos" / "lingue" / (lingua + ".lproj")
        pasta.mkdir(parents=True)
        (pasta / "Localizable.strings").write_text('"x" = "x";\n', encoding="utf-8")
        (pasta / "InfoPlist.strings").write_text('"NSDesktopFolderUsageDescription" = "x";\n', encoding="utf-8")
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
    for lingua in ("it", "en", "es"):
        atteso = ["--render-fixtures", str(module.ROOT / "build.noindex" / "screenshots" / lingua), "--lang", lingua]
        assert atteso in [c[1:] for c in calls]


def _firma_usata(calls):
    return [argv[argv.index("--sign") + 1] for argv in calls if argv[:2] == ["/usr/bin/codesign", "--force"]]


def test_default_signing_is_adhoc_and_the_plist_says_so(build, monkeypatch):
    module, calls = build
    monkeypatch.delenv("PARATIA_SIGN_IDENTITY", raising=False)
    module.main()
    assert _firma_usata(calls) == ["-"]
    info = plistlib.loads((module.ROOT / "build.noindex" / "Paratia.app" / "Contents" / "Info.plist").read_bytes())
    assert info["ParatiaFirma"] == "ad-hoc"


def test_empty_environment_variable_is_treated_as_absent(build, monkeypatch):
    module, calls = build
    monkeypatch.setenv("PARATIA_SIGN_IDENTITY", "   ")
    module.main()
    assert _firma_usata(calls) == ["-"]


def test_environment_variable_selects_a_stable_identity_without_signing_here(build, monkeypatch):
    module, calls = build
    monkeypatch.setenv("PARATIA_SIGN_IDENTITY", "Identita Test")
    module.main()
    assert _firma_usata(calls) == ["Identita Test"]
    info = plistlib.loads((module.ROOT / "build.noindex" / "Paratia.app" / "Contents" / "Info.plist").read_bytes())
    assert info["ParatiaFirma"] == "identita-stabile"


def test_flag_wins_over_the_environment_variable(build, monkeypatch):
    module, calls = build
    monkeypatch.setenv("PARATIA_SIGN_IDENTITY", "Dalla variabile")
    monkeypatch.setattr(sys, "argv", ["build-app.py", "--sign-identity", "Dal flag"])
    module.main()
    assert _firma_usata(calls) == ["Dal flag"]


def test_explicit_empty_flag_is_refused(build, monkeypatch):
    module, calls = build
    monkeypatch.setattr(sys, "argv", ["build-app.py", "--sign-identity", "  "])
    with pytest.raises(ValueError):
        module.main()
    assert _firma_usata(calls) == []


def test_locale_resources_are_copied_for_every_language(build):
    module, calls = build
    module.main()
    for lingua in ("it", "en", "es"):
        cartella = module.ROOT / "build.noindex" / "Paratia.app" / "Contents" / "Resources" / (lingua + ".lproj")
        assert (cartella / "Localizable.strings").is_file()
        assert (cartella / "InfoPlist.strings").is_file()
    info = plistlib.loads((module.ROOT / "build.noindex" / "Paratia.app" / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleLocalizations"] == ["it", "en", "es"]
    assert info["CFBundleDevelopmentRegion"] == "en"

