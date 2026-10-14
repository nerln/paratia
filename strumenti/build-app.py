#!/usr/bin/env python3
"""Build a local app: ad hoc signed by default, or with a stable identity from --sign-identity.

Never install it, never request authorization, never open a keychain to pick an identity.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINGUE = ("it", "en", "es")
TABELLE = ("Localizable.strings", "InfoPlist.strings")
BOOTSTRAP_ROOT = Path("/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app/Contents/Resources/python")
MODULES = ("paratia.py", "gui_worker.py", "cartelle.py", "etichette.py", "registro.py", "catena.py",
           "registro_installa.py", "registro_daemon.py", "banco.py", "hookinstaller.py", "messaggi.py")


def run(argv):
    subprocess.run([str(item) for item in argv], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render-fixtures", action="store_true")
    parser.add_argument("--lang", choices=LINGUE, default=None, help="lingua delle schermate di prova (default: tutte)")
    parser.add_argument("--sign-identity", default=None,
                        help="identita' di firma stabile del portachiavi; senza opzione si usa PARATIA_SIGN_IDENTITY, "
                             "e se anche quella e' vuota o assente la firma e' ad hoc ('-')")
    args = parser.parse_args()
    if args.sign_identity is not None:
        # Un'identita' indicata esplicitamente e' obbligatoria: un valore vuoto e' un errore.
        identita = args.sign_identity.strip()
    else:
        # Una variabile vuota e' come assente: la build resta ad hoc.
        identita = os.environ.get("PARATIA_SIGN_IDENTITY", "").strip() or "-"
    if not identita or "\n" in identita or "\0" in identita:
        raise ValueError("L'identita' di firma non e' valida.")
    build = ROOT / "build.noindex"
    app = build / "Paratia.app"
    contents = app / "Contents"
    binary = contents / "MacOS" / "Paratia"
    resources = contents / "Resources" / "python"
    build.mkdir(exist_ok=True)
    if app.exists():
        if app.is_symlink():
            raise ValueError("The app build path must not be a symlink.")
        shutil.rmtree(app)
    binary.parent.mkdir(parents=True)
    resources.mkdir(parents=True)
    sdk = subprocess.check_output(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    architecture = os.uname().machine
    if architecture not in ("arm64", "x86_64"):
        raise ValueError("Unsupported Mac architecture.")
    target = architecture + "-apple-macos13.0"
    cache = ROOT / ".swiftmodulecache"
    cache.mkdir(exist_ok=True)
    bridge = build / "AuthorizationBridge.o"
    run(["/usr/bin/xcrun", "clang", "-c", ROOT / "macos" / "AuthorizationBridge.c",
         "-isysroot", sdk, "-target", target, "-o", bridge])
    launcher = build / "RegistryLauncher.o"
    run(["/usr/bin/xcrun", "clang", "-c", ROOT / "macos" / "RegistryLauncher.c",
         "-isysroot", sdk, "-target", target, "-o", launcher])
    run(["/usr/bin/xcrun", "swiftc", "-parse-as-library", "-swift-version", "5", "-O", "-target", target,
         "-sdk", sdk, "-module-cache-path", cache, "-import-objc-header", ROOT / "macos" / "AuthorizationBridge.h",
         *sorted((ROOT / "macos").glob("*.swift")), bridge, launcher, "-framework", "SwiftUI", "-framework", "AppKit",
         "-framework", "Security", "-o", binary])
    run([sys.executable, ROOT / "strumenti" / "make-icon.py", "--output",
         contents / "Resources" / "Paratia.icns"])
    for name in MODULES:
        shutil.copyfile(ROOT / name, resources / name)
    for lingua in LINGUE:
        destinazione = contents / "Resources" / (lingua + ".lproj")
        destinazione.mkdir(parents=True, exist_ok=True)
        # Tabella dei testi della GUI e testo del permesso Desktop mostrato da macOS.
        for nome in TABELLE:
            origine = ROOT / "macos" / "lingue" / (lingua + ".lproj") / nome
            if not origine.is_file() or origine.is_symlink():
                raise ValueError("Manca la tabella " + nome + " per la lingua " + lingua + ".")
            shutil.copyfile(origine, destinazione / nome)
    for name in ("hooks/paratia-gate.py", "strumenti/banco-probe.py"):
        source = ROOT / name
        (resources / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, resources / name)
    # Only the manually prepared root-protected bootstrap is exempt from the
    # mount guard. The developer repository never becomes a trusted identity.
    cli_source = ROOT / "paratia.py"
    if cli_source.is_symlink() or not cli_source.is_file():
        raise ValueError("The source CLI must be a regular file.")
    (resources / "hooks" / "paratia-cli.json").write_text(
        json.dumps({"versione": 2, "cli": str(BOOTSTRAP_ROOT / "paratia.py"),
                    "hook_legacy": str((ROOT / "hooks" / "paratia-gate.py").resolve(strict=True))},
                   ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    # Use env's explicit split mode: kernels do not split multiple shebang
    # arguments. Only the bundled copy changes; the repository CLI is intact.
    spec = importlib.util.spec_from_file_location("paratia_build_hookinstaller", ROOT / "hookinstaller.py")
    hookinstaller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hookinstaller)
    runtime = hookinstaller._runtime()
    cli_copy = resources / "paratia.py"
    lines = cli_copy.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[0] = "#!/usr/bin/env -S " + str(runtime) + " -I -S -B\n"
    cli_copy.write_text("".join(lines), encoding="utf-8")
    cli_copy.chmod(0o755)
    info = {"CFBundleIdentifier": "it.paratia.app", "CFBundleName": "Paratia", "CFBundleDisplayName": "Paratia",
            "CFBundleExecutable": "Paratia", "CFBundleIconFile": "Paratia.icns",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1", "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
            "ParatiaRegistryLauncherVersion": 1,
            # Testo di base in inglese; it e es sono in InfoPlist.strings di ogni lproj.
            "NSDesktopFolderUsageDescription": "The test bench examines the metadata of the folder-test folder on the Desktop, only when you start it."}
    info.update({"CFBundleLocalizations": list(LINGUE), "CFBundleDevelopmentRegion": "en",
                 "ParatiaFirma": "ad-hoc" if identita == "-" else "identita-stabile"})
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    run(["/usr/bin/codesign", "--force", "--sign", identita, "--timestamp=none", "--deep", app])
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    if args.render_fixtures:
        for lingua in ((args.lang,) if args.lang else LINGUE):
            run([binary, "--render-fixtures", build / "screenshots" / lingua, "--lang", lingua])
    print("Built " + str(app))


if __name__ == "__main__":
    main()
