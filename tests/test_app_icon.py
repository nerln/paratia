"""Reproducible icon generation and failure safety, without compiling the app."""
from __future__ import annotations

import importlib.util
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def icon():
    spec = importlib.util.spec_from_file_location("paratia_icon_test", ROOT / "strumenti" / "make-icon.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def png_bytes(size):
    def chunk(kind, content):
        return struct.pack(">I", len(content)) + kind + content + struct.pack(">I", zlib.crc32(kind + content))
    # A complete synthetic RGBA PNG keeps image validity separate from the SVG
    # renderer's commands; the real repository preview is checked below.
    scanline = b"\0" + b"\x31\x5b\x64\xff" * size
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scanline * size)) + chunk(b"IEND", b""))


def pipeline(monkeypatch, icon, *, wrong_size=False, fail_iconutil=False, icns_header=None):
    calls = []

    def run(argv, *, check, capture_output=False, text=False):
        assert check is True
        calls.append(argv)
        output = Path(argv[argv.index("--output") + 1])
        if argv[0] == "/fixture tools/rsvg-convert":
            size = int(argv[argv.index("--width") + 1])
            assert argv[argv.index("--height") + 1] == str(size)
            assert argv[-1] == str(icon.SOURCE)
            output.write_bytes(png_bytes(size + 1 if wrong_size else size))
        else:
            assert argv[0] == "/usr/bin/iconutil"
            assert capture_output is True and text is True
            assert argv[1:3] == ["--convert", "icns"]
            assert len(list(Path(argv[-1]).glob("*.png"))) == 10
            if fail_iconutil:
                raise subprocess.CalledProcessError(1, argv, stderr="Invalid Iconset.")
            # The external encoder itself is not tested inside the sandbox.
            png = png_bytes(1024)
            payload = b"ic10" + struct.pack(">I", len(png) + 8) + png
            encoded = b"icns" + struct.pack(">I", len(payload) + 8) + payload
            output.write_bytes(icns_header if icns_header is not None else encoded)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(icon.subprocess, "run", run)
    return calls


def test_icon_generates_every_standard_variant_and_preview_before_publication(icon, monkeypatch, tmp_path):
    calls = pipeline(monkeypatch, icon)
    output = tmp_path / "App With Spaces.app" / "Contents" / "Resources" / "Paratia.icns"
    preview = tmp_path / "docs" / "paratia-icona.png"
    assert icon.make_icon(output, preview=preview, renderer="/fixture tools/rsvg-convert") == output
    assert output.read_bytes()[:4] == b"icns" and output.stat().st_size > 16
    assert icon._png_dimensions(preview) == (1024, 1024)
    assert len(calls) == 11
    sizes = {Path(argv[argv.index("--output") + 1]).name: int(argv[argv.index("--width") + 1])
             for argv in calls[:-1]}
    assert sizes == {
        "icon_16x16.png": 16, "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32, "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128, "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256, "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512, "icon_512x512@2x.png": 1024,
    }
    assert not list(output.parent.glob(".paratia-icon-*"))


def test_renderer_wrong_dimensions_never_replace_existing_icon(icon, monkeypatch, tmp_path):
    calls = pipeline(monkeypatch, icon, wrong_size=True)
    output = tmp_path / "Paratia.icns"
    output.write_bytes(b"previous complete icon")
    with pytest.raises(ValueError, match="incorrect icon size"):
        icon.make_icon(output, renderer="/fixture tools/rsvg-convert")
    assert output.read_bytes() == b"previous complete icon"
    assert len(calls) == 1
    assert not list(tmp_path.glob(".paratia-icon-*"))


def test_iconutil_failure_preserves_previous_icon_and_cleans_staging(icon, monkeypatch, tmp_path):
    pipeline(monkeypatch, icon, fail_iconutil=True)
    output = tmp_path / "Paratia.icns"
    output.write_bytes(b"previous complete icon")
    with pytest.raises(RuntimeError, match="codice 1.*Invalid Iconset"):
        icon.make_icon(output, renderer="/fixture tools/rsvg-convert")
    assert output.read_bytes() == b"previous complete icon"
    assert not list(tmp_path.glob(".paratia-icon-*"))
    retained = list(tmp_path.glob("Paratia.failed.*.iconset"))
    assert len(retained) == 1 and len(list(retained[0].glob("*.png"))) == 10


@pytest.mark.parametrize("header", [b"", b"invalid!", b"icns\x00\x00\x00\x64", b"icns\x00\x00\x00\x08"])
def test_truncated_encoder_output_is_not_published(icon, monkeypatch, tmp_path, header):
    pipeline(monkeypatch, icon, icns_header=header)
    output = tmp_path / "Paratia.icns"
    with pytest.raises(ValueError, match="complete ICNS"):
        icon.make_icon(output, renderer="/fixture tools/rsvg-convert")
    assert not output.exists()
    assert not list(tmp_path.glob(".paratia-icon-*"))


def test_png_only_mode_renders_preview_without_iconutil(icon, monkeypatch, tmp_path, capsys):
    calls = pipeline(monkeypatch, icon)
    iconset = tmp_path / "Paratia.iconset"
    preview = tmp_path / "preview.png"
    icon.main(["--iconset", str(iconset), "--preview", str(preview),
               "--renderer", "/fixture tools/rsvg-convert"])
    assert len(calls) == 10
    assert icon._png_dimensions(preview) == (1024, 1024)
    assert "Built " + str(iconset) in capsys.readouterr().out


def test_missing_renderer_explains_dependency_without_running_a_compiler(icon, monkeypatch, tmp_path):
    monkeypatch.setattr(icon.shutil, "which", lambda name: None)
    monkeypatch.setattr(icon.subprocess, "run", lambda *args, **kwargs: pytest.fail("No tool may run"))
    with pytest.raises(RuntimeError, match="rsvg-convert is required"):
        icon.make_icon(tmp_path / "Paratia.icns")


def test_preview_symlink_cannot_overwrite_another_file_or_publish_icon(icon, monkeypatch, tmp_path):
    pipeline(monkeypatch, icon)
    target = tmp_path / "preserve.png"
    target.write_bytes(b"keep")
    preview = tmp_path / "preview.png"
    preview.symlink_to(target)
    output = tmp_path / "Paratia.icns"
    with pytest.raises(ValueError, match="preview output must not be a symlink"):
        icon.make_icon(output, preview=preview, renderer="/fixture tools/rsvg-convert")
    assert target.read_bytes() == b"keep"
    assert not output.exists()


def test_readme_preview_is_a_real_1024px_render(icon):
    assert icon._png_dimensions(ROOT / "docs" / "immagini" / "paratia-icona.png") == (1024, 1024)
