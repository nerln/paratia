#!/usr/bin/env python3
"""Metadata privacy, conservative attribution, tamper detection, and install scope."""
from __future__ import annotations

import concurrent.futures
import copy
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import catena
import registro as R
import registro_installa as I


def processo(pid=101, versione=1, executable="/bin/cat", parent=None):
    return {"audit_token": {"pid": pid, "pidversion": versione, "euid": os.getuid()},
            "executable": {"path": executable}, "parent_audit_token": parent,
            "responsible_audit_token": parent, "ppid": parent.get("pid") if parent else 1}


def messaggio(tipo="open", percorso="/private/tmp/protetta/file", p=None, sequenza=1):
    dettagli = {"open": {"file": {"path": percorso}, "fflag": 1},
                "close": {"target": {"path": percorso}, "modified": False, "was_mapped_writable": True},
                "write": {"target": {"path": percorso}},
                "mount": {"statfs": {"f_mntonname": percorso}},
                "rename": {"source": {"path": percorso}, "destination": {"new_path": {"dir": {"path": "/private/tmp"}, "filename": "nuovo"}}},
                "exec": {"target": processo(99, 2, "/usr/local/bin/codex"), "args": ["SECRET_ARG"], "env": ["SECRET_ENV"]}}
    return {"schema_version": 1, "version": 7, "event_type": "ES_EVENT_TYPE_NOTIFY_" + tipo.upper(),
            "time": "2026-10-07T20:00:00+00:00", "global_seq_num": sequenza, "seq_num": sequenza,
            "process": p or processo(), "event": {tipo: dettagli[tipo]},
            "action": {"result_type": 1, "result": {"flags": 1}}}


class RegistroTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.old = R.CASA, R.CATENA, R.SYSTEM
        R.CASA, R.CATENA, R.SYSTEM = self.base, self.base / "registro" / "catena.jsonl", self.base / "kernel"

    def tearDown(self):
        R.CASA, R.CATENA, R.SYSTEM = self.old
        self.tmp.cleanup()

    def test_metadata_only_even_exec_and_gui_hostile_fields(self):
        m = messaggio()
        m["process"]["args"] = ["SECRET_ARG"]
        m["process"]["env"] = {"KEY": "SECRET_ENV"}
        m["event"]["open"]["contents"] = "SECRET_CONTENT"
        r = R.normalizza(m)[0]
        self.assertTrue(r["apertura_per_lettura"])
        self.assertNotIn("lettura", r["evento"])
        self.assertIsNone(r["agente"])
        self.assertNotIn("SECRET", json.dumps(r))
        ancestry = R.Discendenza()
        self.assertEqual(R.normalizza(messaggio("exec"), ancestry), [])
        self.assertNotIn("SECRET", json.dumps(list(ancestry.processi.values())))
        gui = R.annota("tentativo-fallito", cartella="a", azione="apri", percorso="/fake",
                       passphrase="SECRET_KEY", args="SECRET_ARG", password="SECRET_PASS", content="SECRET_CONTENT")
        self.assertEqual(gui["source"], "paratia")
        self.assertEqual(gui["cartella"], "a")
        self.assertEqual(gui["azione"], "apri")
        self.assertNotIn("SECRET", R.CATENA.read_text())

    def test_ancestry_pidversion_and_snapshot_uncertainty(self):
        a = R.Discendenza({99: {"processo": "/usr/local/bin/codex", "ppid": 1},
                           101: {"processo": "/bin/cat", "ppid": 99}})
        R.normalizza(messaggio("exec"), a)
        child = processo(parent={"pid": 99, "pidversion": 2})
        r = R.normalizza(messaggio(p=child), a)[0]
        self.assertTrue(r["agente"])
        self.assertEqual(r["nome_agente"], "Codex")
        self.assertEqual(r["app_responsabile"], "/usr/local/bin/codex")
        reused = processo(parent={"pid": 99, "pidversion": 9})
        r = R.normalizza(messaggio(p=reused), a)[0]
        self.assertIsNone(r["agente"])
        self.assertEqual(r["candidato_agente"], "Codex")
        self.assertEqual(r["evidenza_agente"], "snapshot-pid-non-verificato")

    def test_flags_are_es_decision_not_syscall_errno(self):
        m = messaggio()
        m["event_type"] = 10
        m["action"]["result"]["flags"] = 0
        r = R.normalizza(m)[0]
        self.assertEqual(r["esito"], "negato-da-es")
        self.assertNotIn("errno", r)
        closed = R.normalizza(messaggio("close"))[0]
        self.assertFalse(closed["modified"])
        self.assertTrue(closed["was_mapped_writable"])

    def test_requested_filesystem_event_paths_and_metadata(self):
        path = "/private/tmp/protetta/file"
        cases = [
            ("create", 13, {"destination_type": 0, "destination": {"existing_file": {"path": path}}}, path),
            ("create", 13, {"destination_type": 1, "destination": {"new_path": {"dir": {"path": "/private/tmp/protetta"}, "filename": "nuovo"}}}, "/private/tmp/protetta/nuovo"),
            ("unlink", 32, {"target": {"path": path}}, path),
            ("truncate", 41, {"target": {"path": path}}, path),
            ("lookup", 43, {"source_dir": {"path": "/private/tmp"}, "relative_target": "protetta/file"}, path),
            ("mmap", 20, {"source": {"path": path}, "protection": 3, "max_protection": 7}, path),
            ("mount", 22, {"statfs": {"f_mntonname": "/private/tmp/protetta", "f_mntfromname": "IGNORE_DEVICE"}}, "/private/tmp/protetta"),
            ("unmount", 23, {"statfs": {"f_mntonname": "/private/tmp/protetta"}}, "/private/tmp/protetta"),
            ("write", 33, {"target": {"path": path}}, path),
            ("rename", 25, {"source": {"path": "/outside"}, "destination": {"existing_file": {"path": path}}}, "/outside"),
        ]
        for tipo, numero, dettaglio, expected in cases:
            with self.subTest(tipo=tipo, dettaglio=dettaglio):
                m = messaggio()
                m["event_type"], m["event"] = numero, {tipo: {**dettaglio, "contents": "SECRET_CONTENT"}}
                r = R.normalizza(m)[0]
                self.assertEqual(r["evento"], tipo)
                self.assertEqual(r["percorso"], expected)
                self.assertTrue(R.corrisponde(r, [{"id": "a", "origine": "/private/tmp/protetta"}]))
                self.assertNotIn("SECRET", json.dumps(r))
                self.assertNotIn("IGNORE_DEVICE", json.dumps(r))
                self.assertNotIn("errno", r)

    def test_boundary_rename_and_collector_exclusion(self):
        self.assertTrue(R.corrisponde({"percorso": "/tmp/protetta/a"}, [{"id": "a", "origine": "/private/tmp/protetta"}]))
        self.assertFalse(R.corrisponde({"percorso": "/private/tmp/protetta-altro/a"}, [{"id": "a", "origine": "/private/tmp/protetta"}]))
        self.assertTrue(R.corrisponde({"percorso": "/outside", "destinazione": "/private/tmp/protetta/a"}, [{"origine": "/private/tmp/protetta"}]))
        self.assertFalse(R.corrisponde({"percorso": str(R.SYSTEM / "501" / "catena.jsonl")}, [{"origine": "/"}]))
        self.assertFalse(R.corrisponde({"percorso": str(R.SUPPORT / "registro.py")}, [{"origine": "/"}]))

    def test_sequence_gaps_unknown_schema_and_bounded_diagnostics(self):
        scritti = []
        o = R.Osservatore([{"id": "a", "origine": "/private/tmp/protetta"}], scritti.append)
        o.ricevi(messaggio(sequenza=1))
        o.ricevi(messaggio(sequenza=4))
        self.assertEqual(o.persi, 2)
        self.assertTrue(o.rileva_perdite)
        self.assertFalse(o.sano)
        for _ in range(100):
            o.ricevi({"schema_version": 99, "event_type": {}})
        self.assertTrue(o.schema_fatale)
        self.assertEqual(sum(r.get("motivo") == "schema-eslogger-non-supportato" for r in scritti), 1)

    def test_daemon_direct_diagnostic_paths_are_also_bounded(self):
        scritti = []
        sink = R.ScrittoreDiagnostici(scritti.append)
        for _ in range(100):
            for motivo in ("json-eslogger-non-valido", "riga-eslogger-troppo-grande", "registro-cartelle-illeggibile"):
                sink(R._diagnostico(motivo))
        self.assertEqual(len(scritti), 3)
        self.assertEqual(sink.contatori["json-eslogger-non-valido"], 100)
        sink({"evento": "open", "percorso": "/file"})
        sink({"evento": "open", "percorso": "/file"})
        self.assertEqual(len(scritti), 5)

    def test_chain_concurrent_append_tamper_and_partial_refusal(self):
        p = self.base / "catena.jsonl"
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda n: catena.appendi(p, {"n": n}), range(150)))
        self.assertEqual(catena.verifica(p)["voci"], 150)
        self.assertTrue(catena.verifica(p)["ok"])
        righe = p.read_text().splitlines()
        p.write_text("\n".join(righe[:20] + righe[21:]) + "\n")
        self.assertFalse(catena.verifica(p)["ok"])
        p.write_text('{"n":1}')
        with self.assertRaises(ValueError):
            catena.appendi(p, {"n": 2})
        symlink = self.base / "symlink"
        symlink.symlink_to(p)
        with self.assertRaises(OSError):
            catena.appendi(symlink, {})

    def test_query_filters_and_csv_formula_injection(self):
        for when, agent, proc, path in [("2026-10-07T20:00:00+00:00", True, "/bin/cat", "=danger"),
                                        ("2026-10-07T21:00:00+00:00", None, "/bin/ls", "file")]:
            catena.appendi(R.CATENA, {"quando": when, "cartella": "a", "agente": agent,
                                     "processo": proc, "percorso": path, "app_responsabile": "Paratia", "sorgente": "test"})
        self.assertEqual(len(R.query({"folder": "a", "agent": "unknown"})), 1)
        self.assertEqual(len(R.query({"process": "Paratia", "until": "2026-10-07T20:30:00Z"})), 1)
        rows = list(csv.DictReader(io.StringIO(R.export_csv({"agent": "true"}))))
        self.assertEqual(rows[0]["percorso"], "'=danger")
        self.assertTrue(R.verifica()["ok"])

    def test_capped_owned_registry_and_universal_or_symlink_refusal(self):
        source = self.base / "folder"
        source.mkdir()
        ident = "a" * 32
        v = {"id": ident, "nome": "folder", "origine": str(source), "montaggio": str(source),
             "bundle": str(self.base / ("folder-" + ident + ".sparsebundle"))}
        p = self.base / "cartelle.json"
        p.write_text(json.dumps({"versione": 1, "cartelle": {ident: v}}))
        self.assertEqual(R.leggi_cartelle(p, os.getuid())[0]["id"], ident)
        hostile = dict(v, origine="/", montaggio="/", bundle="/-" + ident + ".sparsebundle")
        p.write_text(json.dumps({"versione": 1, "cartelle": {ident: hostile}}))
        with self.assertRaises(ValueError):
            R.leggi_cartelle(p, os.getuid())
        p.unlink()
        p.symlink_to(source)
        with self.assertRaises(OSError):
            R.leggi_cartelle(p, os.getuid())

    def test_plaintext_watch_is_separate_metadata_and_reversible(self):
        folder = self.base / "plain"
        folder.mkdir()
        self.assertTrue(R.sorveglia("banco-before", folder, "Prima")["sorvegliata"])
        p = R.CASA / "registro" / "sorveglianza.json"
        self.assertEqual(R.leggi_sorveglianza(p, os.getuid())[0]["origine"], str(folder))
        self.assertFalse((R.CASA / "cartelle.json").exists())
        with self.assertRaises(ValueError):
            R.sorveglia("bad", "/")
        with self.assertRaises(ValueError):
            R.sorveglia("collector", R.SYSTEM)
        R.rimuovi_sorveglianza("banco-before")
        self.assertEqual(R.leggi_sorveglianza(p, os.getuid()), [])

    def test_migration_backup_and_residual_scope(self):
        source = self.base / "folder"
        source.mkdir()
        ident = "b" * 32
        backup = self.base / (".folder.paratia-" + ident)
        backup.mkdir()
        v = {"id": ident, "nome": "folder", "origine": str(source), "montaggio": str(source),
             "bundle": str(self.base / ("folder-" + ident + ".sparsebundle")),
             "backup": str(backup), "plaintext_residuo": str(backup)}
        p = self.base / "cartelle.json"
        p.write_text(json.dumps({"versione": 1, "cartelle": {ident: v}}))
        matches = R.corrisponde({"percorso": str(backup / "rimasto")}, R.leggi_cartelle(p, os.getuid()))
        self.assertEqual({r["tipo"] for r in matches}, {"backup", "plaintext_residuo"})
        for campo in ("backup", "plaintext_residuo"):
            with self.subTest(campo=campo):
                p.write_text(json.dumps({"versione": 1, "cartelle": {ident: dict(v, **{campo: str(self.base)})}}))
                with self.assertRaises(ValueError):
                    R.leggi_cartelle(p, os.getuid())

    def test_watcher_owner_size_and_symlink_refusal(self):
        p = self.base / "watch.json"
        p.write_text('{"versione":1,"percorsi":{}}')
        with self.assertRaises(ValueError):
            R.leggi_sorveglianza(p, os.getuid() + 1)
        p.write_bytes(b" " * 4194305)
        with self.assertRaises(ValueError):
            R.leggi_sorveglianza(p, os.getuid())
        p.unlink()
        p.symlink_to(self.base)
        with self.assertRaises(OSError):
            R.leggi_sorveglianza(p, os.getuid())

    def test_acl_metadata_reader_on_empty_fixture(self):
        if sys.platform != "darwin":
            self.skipTest("Native macOS ACL metadata API")
        p = self.base / "acl-fixture"
        p.write_text("synthetic")
        self.assertFalse(catena.acl_scrivibile(p))

    def test_installer_preparation_does_not_install(self):
        with mock.patch.object(I, "runtime", return_value="/protected/python"), \
                mock.patch.object(I, "_app_sorgente", return_value=(Path("/synthetic/Paratia.app"), "a" * 40)), \
                mock.patch.object(I, "installa") as install:
            piano = I.piano(Path(__file__).resolve().parent.parent)
            install.assert_not_called()
        self.assertEqual(piano["argv"][:3], ["/protected/python", "-I", "-S"])
        self.assertEqual(piano["plist"]["UserName"], "root")
        self.assertEqual(piano["plist"]["ProgramArguments"], [
            str(I.SUPPORT / "Paratia.app" / "Contents" / "MacOS" / "Paratia"),
            "--registro", "--uid", str(os.getuid())])
        self.assertEqual(piano["fda_entry"], "/Applications/Paratia.app")
        self.assertTrue(piano["fda_regrant_after_build"])
        self.assertNotIn("password", json.dumps(piano))
        with mock.patch.object(I.os, "geteuid", return_value=os.getuid() or 501):
            with self.assertRaises(PermissionError):
                I.installa(self.base, os.getuid() or 501)


if __name__ == "__main__":
    unittest.main()
