#!/usr/bin/env python3
"""Standalone CLT Python 3.9 smoke: real worker query/CSV and temporary bank.

Only the image commands, timer, mdls, and collector health are simulated. Local
metadata writes, hash verification, worker framing, query/date parsing, CSV,
ditto, bank lifecycle, and the shell open/fstat helper are real. No pytest,
hdiutil, live collector, vendor CLI, Desktop, root, TCC, or keychain is used.
"""
from __future__ import annotations

import csv
import contextlib
import io
import json
import os
import plistlib
import secrets
import shutil
import subprocess
import struct
import sys
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Images:
    """Metadata-preserving simulated disks; no hdiutil process can be called."""

    def __init__(self, folders):
        self.folders, self.mounted, self.keys = folders, {}, {}
        self.real_command = folders._corri
        folders._corri = self.command
        folders._montato = lambda path: str(path) in self.mounted
        folders._avvia_timer = lambda *args: None

    def command(self, argv, passphrase=None):
        folders = self.folders
        if argv[0] == folders.DITTO:
            return self.real_command(argv, passphrase)
        if argv[0] != folders.HDIUTIL:
            raise AssertionError("Comando non previsto nella fixture")
        if argv[1] == "create":
            bundle = Path(argv[-1])
            bundle.mkdir()
            (bundle / "storage").mkdir()
            (bundle / "bands").mkdir()
            (bundle / "Info.plist").write_bytes(plistlib.dumps({
                "diskimage-bundle-type": "com.apple.diskimage.sparsebundle",
                "bundle-backingstore-version": 1, "band-size": 8388608, "size": 268435456}))
            token = bytearray(4096)
            token[:8] = b"encrcdsa"
            struct.pack_into(">I", token, 8, 2)
            struct.pack_into(">I", token, 52, 4096)
            struct.pack_into(">Q", token, 64, len(token))
            struct.pack_into(">I", token, 72, 1)
            struct.pack_into(">IQQ", token, 76, 1, 96, 128)
            (bundle / "token").write_bytes(token)
            (bundle / "token").chmod(0o600)
            self.keys[str(bundle)] = passphrase
        elif argv[1] == "isencrypted":
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"encrypted": True}), b"")
        elif argv[1] == "imageinfo":
            if passphrase != self.keys[str(Path(argv[2]))]:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"Properties": {"Encrypted": True}}), b"")
        elif argv[1] == "attach":
            bundle, mount = Path(argv[2]), Path(argv[argv.index("-mountpoint") + 1])
            if passphrase != self.keys[str(bundle)]:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            storage = bundle / "storage"
            folders._copia_metadati(storage, mount)
            for child in storage.iterdir():
                child.rename(mount / child.name)
            self.mounted[str(mount)] = bundle
        elif argv[1] == "detach":
            mount = Path(argv[2])
            storage = self.mounted.pop(str(mount)) / "storage"
            folders._copia_metadati(mount, storage)
            for child in mount.iterdir():
                child.rename(storage / child.name)
        else:
            raise AssertionError("Operazione immagine non prevista nella fixture")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def main():
    if not Path("/usr/bin/ditto").is_file():
        print(json.dumps({"eseguito": False, "errore": "La copia metadati richiede ditto Apple"}))
        return 2
    script = _load("smoke_bank_driver", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    base = script.new_fixture()
    (base / "home").mkdir()
    key = secrets.token_urlsafe(32).encode("ascii")
    environment = None
    report = {"python": "%d.%d.%d" % sys.version_info[:3], "query_reale": False, "csv_reale": False}
    try:
        with patch.dict(os.environ, {"HOME": str(base / "home"), "PARATIA_HOME": str(base / "local-state")}), patch.object(Path, "home", classmethod(lambda cls: base / "home")):
            registry = _load("smoke_registro", ROOT / "registro.py")
            registry.SYSTEM = base / "kernel-local"
            labels = _load("smoke_etichette", ROOT / "etichette.py")
            cli = _load("smoke_cli", ROOT / "paratia.py")
            worker = _load("smoke_worker", ROOT / "gui_worker.py")
            worker._MODULES["registro"] = registry
            watched = base / "watched"
            watched.mkdir()
            registry.sorveglia("smoke-watch", watched, "Smoke")
            target = watched / "synthetic.txt"
            target.write_text("DATI SINTETICI DELLA PROVA DI FUMO")
            current = registry.annota("smoke", cartella="smoke-watch", percorso=str(target))
            registry.appendi(registry.CATENA, {"evento": "smoke-legacy", "quando": "2026-10-10T05:11:37+0200", "percorso": str(target), "source": "paratia", "cartella": "smoke-watch"})
            labels.segna(target, "pubblico")
            cli.annota("smoke")
            for stamp in (current["quando"], labels.elenco()[0]["quando"], json.loads(cli.DIARIO.read_text())["quando"]):
                assert stamp[-3] == ":"
                registry._data(stamp)

            def call(action, params):
                out = io.StringIO()
                worker.main(["worker", action], io.BytesIO(script.frame(params, b"")), out)
                response = json.loads(out.getvalue())
                assert response["ok"], response.get("code")
                return response["result"]

            filters = {"folder": str(watched), "file": str(target), "since": "2000-01-01T00:00:00+0200", "until": "2100-01-01T00:00:00+0200"}
            rows = call("registro.query", {"filters": filters})
            assert rows["total"] == 2
            assert rows["kernel_active"] is False and rows["kernel_collection"]["coverage_guaranteed"] is False
            csv_file = base / "events.csv"
            exported = call("registro.export_csv", {"path": str(csv_file), "filters": filters})
            assert exported["kernel_active"] is False and exported["kernel_collection"]["coverage_guaranteed"] is False
            assert len(list(csv.DictReader(io.StringIO(csv_file.read_text())))) == 2
            cli_output = io.StringIO()
            cli_args = cli.costruisci().parse_args(["registro", "elenco", "--cartella", str(watched), "--file", str(target)])
            with contextlib.redirect_stdout(cli_output), contextlib.redirect_stderr(io.StringIO()):
                assert cli._esegui_registro(registry, cli_args) == 0
            assert len(json.loads(cli_output.getvalue())) == 2
            report.update(query_reale=True, csv_reale=True, eventi_locali=2, offset_legacy_accettato=True,
                          timestamp_colon_scrittori=3, cli_registro_reale=True, filtri_data_legacy_accettati=True,
                          metadati_raccolta_query_csv=True)
            report["filtro_cartella_percorso_reale"] = True

        with script.fixture(base, key, configure_disks=Images,
                            mock_mdls=lambda argv: {"rc": 0 if Path(argv[-1]).is_file() else 1,
                                                   "pid_launcher": os.getpid(), "timeout": False}) as environment:
            assert environment.bank.R.query is environment.registry.query
            payload = script.frame({"dove": str(environment.disk), "minutes": 1, "agenti_reali": False}, key)
            response = script.request(environment, payload)
            summary = script.summarize(environment, response, key)
            assert summary["flusso_banco_temporaneo_verificato"]
            assert environment.registry.query({"file": str(environment.source)})
            report["banco_temporaneo"] = summary
        assert all(environment.cleanup.values())
        report["ok"] = True
    except BaseException as error:
        report.update(ok=False, tipo_errore=type(error).__name__)
    finally:
        key = b""
        if environment is None or all(environment.cleanup.values()):
            shutil.rmtree(base)
            report["fixture_eliminata"] = True
        else:
            report["fixture_conservata"] = str(base)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
