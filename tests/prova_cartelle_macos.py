#!/usr/bin/env python3
"""Disposable native migration check; the production external-disk guard is tested separately."""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


def prova() -> dict:
    temporary = tempfile.TemporaryDirectory(prefix="paratia-migration-", dir="/private/tmp")
    base = Path(temporary.name)
    os.environ["PARATIA_HOME"] = str(base / "state")
    spec = importlib.util.spec_from_file_location("cartelle_native_test",
                                               Path(__file__).resolve().parents[1] / "cartelle.py")
    C = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = C
    spec.loader.exec_module(C)
    # This disposable test uses internal temporary storage, never the real bank.
    C._esterno = lambda path: None
    source, disk = base / "source", base / "temporary-disk"
    source.mkdir()
    disk.mkdir()
    (source / "subfolder").mkdir()
    (source / "synthetic.txt").write_text("DATI SINTETICI PARATIA.\n")
    (source / "subfolder" / "binary.bin").write_bytes(bytes(range(256)) * 1024)
    (source / "large.bin").write_bytes(b"\0" * (8 * 1024 * 1024))
    subprocess.run(["/usr/bin/xattr", "-w", "it.paratia.synthetic", "synthetic-metadata",
                    str(source / "synthetic.txt")], check=True, capture_output=True)
    with (source / "synthetic.txt" / "..namedfork" / "rsrc").open("wb") as fork:
        fork.write(b"SYNTHETIC RESOURCE FORK")
    expected = C._scansiona(source)
    original_verify = C._verifica

    def verify_with_diagnostics(root, manifest, metadir=None):
        try:
            return original_verify(root, manifest, metadir)
        except C.Rifiuto:
            ignored = {x for x in C.DIR_SISTEMA if x not in manifest} if metadir else set()
            if metadir:
                ignored.add(metadir)
            actual = C._contenuto(C._scansiona(root, ignored))
            wanted = C._contenuto(manifest)
            print(json.dumps({"metadata_diff": {
                name: {"actual": actual.get(name), "wanted": wanted.get(name)}
                for name in actual.keys() | wanted.keys() if actual.get(name) != wanted.get(name)
            }}), file=sys.stderr)
            raise

    C._verifica = verify_with_diagnostics
    key = secrets.token_urlsafe(48).encode()
    try:
        entry = C.proteggi(source, disk, key, 1)
        assert entry["stato"] == "chiusa"
        assert not (source / "synthetic.txt").exists()
        assert C.elenco()[0]["file"] == 3
        assert C.elenco()[0]["byte"] == C._totali(expected)[1]
        entry = C.apri(entry["id"], key, 1)
        assert entry["stato"] == "aperta"
        C._verifica(source, expected, entry.get("metadir"))
        C.chiudi(entry["id"])
        assert not (source / "synthetic.txt").exists()
        assert C.elenco()[0]["stato"] == "chiusa"
        return {"dati": "sintetici", "destinazione": "temporanea interna, solo test",
                "migrazione": True, "verifica_hash_conteggi_byte": True,
                "xattr_resource_fork": True, "timer_confermato": True,
                "riapertura": True, "stato_finale": "chiusa"}
    finally:
        key = b""
        for entry in C.elenco():
            C.chiudi(entry["id"])
        if any(Path(entry["montaggio"]).is_mount() for entry in C.elenco()):
            raise RuntimeError("Chiudere il volume temporaneo prima della pulizia")
        temporary.cleanup()


if __name__ == "__main__":
    print(json.dumps(prova(), ensure_ascii=False))
