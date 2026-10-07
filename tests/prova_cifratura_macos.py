#!/usr/bin/env python3
"""Opt-in real macOS check. Synthetic data and an ephemeral key held only in RAM."""
from __future__ import annotations

import json
import secrets
import subprocess
import tempfile
from pathlib import Path


def prova() -> dict:
    temporary = tempfile.TemporaryDirectory(prefix="paratia-native-", dir="/private/tmp")
    base = Path(temporary.name)
    bundle = base / "proof.sparsebundle"
    mount = base / "volume"
    mount.mkdir()
    key = secrets.token_urlsafe(48).encode()
    marker = b"DATI SINTETICI PARATIA: native ciphertext verification 2026.\n"

    def run(args, secret=None):
        return subprocess.run(["/usr/bin/hdiutil", *args],
                              input=secret + b"\n" if secret else None,
                              capture_output=True)

    def require(result, operation):
        if result.returncode:
            raise RuntimeError(f"{operation}: codice {result.returncode}")

    try:
        require(run(["create", "-size", "64m", "-type", "SPARSEBUNDLE", "-fs", "APFS",
                     "-encryption", "AES-256", "-stdinpass", "-volname", "ParatiaTest",
                     str(bundle)], key), "creazione")
        attach = ["attach", str(bundle), "-stdinpass", "-nobrowse", "-owners", "on",
                  "-mountpoint", str(mount)]
        require(run(attach, key), "apertura")
        (mount / "synthetic.txt").write_bytes(marker)
        require(run(["detach", str(mount)]), "chiusura")
        assert not (mount / "synthetic.txt").exists()
        assert all(marker not in band.read_bytes() for band in (bundle / "bands").iterdir())
        assert run(attach, secrets.token_urlsafe(48).encode()).returncode != 0
        require(run(attach, key), "riapertura")
        assert (mount / "synthetic.txt").read_bytes() == marker
        require(run(["detach", str(mount)]), "richiusura")
        return {"dati": "sintetici", "aes256": True, "chiusa_file_assente": True,
                "marker_assente_nei_band": True, "chiave_errata_rifiutata": True,
                "riapertura_verificata": True, "stato_finale": "chiuso"}
    finally:
        key = b""
        if mount.is_mount():
            require(run(["detach", str(mount)]), "pulizia: chiudere prima di eliminare")
        temporary.cleanup()


if __name__ == "__main__":
    print(json.dumps(prova(), ensure_ascii=False))
