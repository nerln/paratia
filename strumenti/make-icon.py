#!/usr/bin/env python3
"""Render the repository SVG with librsvg and assemble a macOS icon with iconutil.

Requires the command-line tools rsvg-convert and /usr/bin/iconutil. No Python
packages, Swift compilation, network access, or installation are performed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "macos" / "Assets" / "Paratia.svg"
ICONSET_VARIANTS = (
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
)


def _png_dimensions(path):
    """Reject a failed renderer before a partial icon can reach the bundle."""
    with Path(path).open("rb") as stream:
        header = stream.read(24)
    if len(header) != 24 or header[:16] != b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR":
        raise ValueError("The SVG renderer did not produce a PNG.")
    return struct.unpack(">II", header[16:24])


def render_iconset(iconset, *, renderer=None, source=SOURCE):
    """Render every required PNG variant without requiring native iconutil."""
    iconset = Path(iconset)
    source = Path(source)
    renderer = renderer or shutil.which("rsvg-convert")
    if not renderer:
        raise RuntimeError("rsvg-convert is required to render macos/Assets/Paratia.svg.")
    if source.is_symlink() or not source.is_file():
        raise ValueError("The icon source must be a regular SVG file.")
    if iconset.is_symlink():
        raise ValueError("The iconset output must not be a symlink.")
    iconset.mkdir(parents=True, exist_ok=True)
    for name, pixels in ICONSET_VARIANTS:
        png = iconset / name
        if png.is_symlink():
            raise ValueError("An iconset PNG must not be a symlink.")
        subprocess.run([str(renderer), "--width", str(pixels), "--height", str(pixels),
                        "--output", str(png), str(source)], check=True)
        if _png_dimensions(png) != (pixels, pixels):
            raise ValueError("The SVG renderer produced an incorrect icon size.")
    return iconset


def _copy_preview(iconset, preview):
    preview = Path(preview)
    if preview.is_symlink():
        raise ValueError("The preview output must not be a symlink.")
    preview.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(iconset / "icon_512x512@2x.png", preview)


def make_icon(output, *, preview=None, renderer=None, source=SOURCE,
              iconutil="/usr/bin/iconutil"):
    """Build a complete ICNS, replacing output only after every size succeeds."""
    output = Path(output)
    if output.suffix != ".icns":
        raise ValueError("The icon output must have the .icns extension.")
    if output.is_symlink():
        raise ValueError("The icon output must not be a symlink.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".paratia-icon-", dir=output.parent) as temp:
        staging = Path(temp)
        iconset = render_iconset(staging / "Paratia.iconset", renderer=renderer, source=source)
        icns = staging / "Paratia.icns"
        try:
            subprocess.run([str(iconutil), "--convert", "icns", "--output", str(icns), str(iconset)],
                           check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            # Retain the valid inputs for the supervisor's native tool check.
            # A failed encoder never changes an existing, complete app icon.
            diagnostic = Path(tempfile.mkdtemp(prefix="Paratia.failed.", suffix=".iconset", dir=output.parent))
            shutil.copytree(iconset, diagnostic, dirs_exist_ok=True)
            detail = (error.stderr or "Nessun dettaglio restituito.").strip()[:2048]
            raise RuntimeError("iconutil non ha generato l'icona (codice " + str(error.returncode)
                               + "): " + detail + "\nPNG conservati in " + str(diagnostic)) from error
        with icns.open("rb") as stream:
            header = stream.read(8)
        if (len(header) != 8 or header[:4] != b"icns" or icns.stat().st_size <= 8
                or struct.unpack(">I", header[4:])[0] != icns.stat().st_size):
            raise ValueError("iconutil did not produce a complete ICNS file.")
        if preview is not None:
            _copy_preview(iconset, preview)
        os.replace(icns, output)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path,
                             help="Destination .icns (normally Contents/Resources/Paratia.icns).")
    destination.add_argument("--iconset", type=Path,
                             help="Render PNGs only, without invoking iconutil.")
    parser.add_argument("--preview", type=Path,
                        help="Also write the 1024 px PNG used in the README.")
    parser.add_argument("--renderer", help="Explicit rsvg-convert executable, if absent from PATH.")
    args = parser.parse_args(argv)
    try:
        if args.iconset:
            result = render_iconset(args.iconset, renderer=args.renderer)
            if args.preview is not None:
                _copy_preview(result, args.preview)
        else:
            result = make_icon(args.output, preview=args.preview, renderer=args.renderer)
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")
    print("Built " + str(result))


if __name__ == "__main__":
    main()
