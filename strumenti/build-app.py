#!/usr/bin/env python3
"""Build a local ad-hoc signed app; never install it or request authorization."""
from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ("gui_worker.py", "cartelle.py", "etichette.py", "registro.py", "catena.py",
           "registro_installa.py", "registro_daemon.py", "banco.py", "hookinstaller.py")


def run(argv):
    subprocess.run([str(item) for item in argv], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render-fixtures", action="store_true")
    args = parser.parse_args()
    build = ROOT / "build"
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
    for name in MODULES:
        shutil.copyfile(ROOT / name, resources / name)
    for name in ("hooks/paratia-gate.py", "strumenti/banco-probe.py"):
        source = ROOT / name
        (resources / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, resources / name)
    info = {"CFBundleIdentifier": "it.paratia.app", "CFBundleName": "Paratia", "CFBundleDisplayName": "Paratia",
            "CFBundleExecutable": "Paratia", "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1", "LSMinimumSystemVersion": "13.0", "NSHighResolutionCapable": True,
            "ParatiaRegistryLauncherVersion": 1,
            "NSDesktopFolderUsageDescription": "Il banco di prova esamina i metadati della cartella folder-test sul Desktop, solo quando lo avvii."}
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream)
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--deep", app])
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    if args.render_fixtures:
        run([binary, "--render-fixtures", build / "screenshots"])
    print("Built " + str(app))


if __name__ == "__main__":
    main()
