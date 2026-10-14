"""Bank privacy and lifecycle, using only owned temporary synthetic fixtures.

No test invokes disk tools, a real agent CLI, root, TCC, or the keychain. The
folder double copies only the synthetic test data and restores its metadata.
"""
from __future__ import annotations

import csv
import errno
import fcntl
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"bank-fixture-private-passphrase-123"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def bank(tmp_path, monkeypatch):
    area = tmp_path.resolve()
    home = area / "home"
    source = home / "Desktop" / "folder-test"
    source.mkdir(parents=True)
    disk = area / "external-fixture"
    disk.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PARATIA_HOME", str(home / ".paratia"))
    b = load("banco_test", ROOT / "banco.py")
    real_c, real_r = b.C, b.R
    real_r.SYSTEM = area / "kernel-fixture"
    events, entries, keys, kernel = [], {}, [], []
    protected = area / "protected-fixture"
    ident = "a" * 32

    def empty(path):
        for p in path.iterdir():
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()

    def copy_children(origin, destination):
        destination.mkdir(exist_ok=True)
        for p in origin.iterdir():
            if p.is_dir():
                shutil.copytree(p, destination / p.name, copy_function=shutil.copy2)
            else:
                shutil.copy2(p, destination / p.name)

    system_dir_on_open = []

    def protect(origin, destination, key, minutes):
        events.append(("protect", str(origin)))
        keys.append(key)
        assert origin == source and destination in (disk, None)
        assert not entries
        inventory = b._inventario(source)
        assert set(inventory) == {"LEGGIMI-SINTETICO.txt", "campione.bin", "grande.bin", "sottocartella", "sottocartella/note.txt"}
        copy_children(source, protected)
        empty(source)
        entries[ident] = {"id": ident, "origine": str(source), "bundle": str(disk / (ident + ".sparsebundle")),
                          "stato": "chiusa", "file": 4, "byte": sum(v["byte"] for v in inventory.values())}
        return dict(entries[ident])

    def open_folder(folder, key, minutes):
        events.append(("open", folder))
        keys.append(key)
        assert folder in entries
        copy_children(protected, source)
        if system_dir_on_open:
            # A real APFS volume shows a root-only .fseventsd once mounted.
            (source / ".fseventsd").mkdir(mode=0)
        entries[folder]["stato"] = "aperta"
        return dict(entries[folder])

    def close_folder(folder):
        events.append(("close", folder))
        if (source / ".fseventsd").exists():
            (source / ".fseventsd").rmdir()
        if entries[folder]["stato"] == "aperta":
            empty(protected)
            copy_children(source, protected)
            empty(source)
            entries[folder]["stato"] = "chiusa"
        return dict(entries[folder])

    def remove(folder, key):
        events.append(("remove", folder))
        keys.append(key)
        assert entries[folder]["stato"] == "chiusa" and not list(source.iterdir())
        copy_children(protected, source)
        empty(protected)
        del entries[folder]
        return {"id": folder, "stato": "non-protetta"}

    fake_c = SimpleNamespace(togli_protezione=remove, _chiave=real_c._chiave, _minuti=real_c._minuti,
                             DIR_SISTEMA=real_c.DIR_SISTEMA,
                             _disco_fisico=lambda p: events.append(("external", str(p))),
                             elenco=lambda: list(entries.values()), Rifiuto=real_c.Rifiuto,
                             proteggi=protect, apri=open_folder, chiudi=close_folder)
    watches = {}
    readiness = {"running": True, "healthy": True, "local_chain_ok": True}

    def status():
        events.append(("status", None))
        return {**readiness, "watched_ids": list(watches) + list(entries)}

    def watch(folder, path, name=""):
        events.append(("watch", folder))
        real_r.sorveglia(folder, path, name)
        watches[folder] = str(path)

    def unwatch(folder):
        events.append(("unwatch", folder))
        real_r.rimuovi_sorveglianza(folder)
        watches.pop(folder, None)

    def query(filters):
        events.append(("query", filters["file"]))
        return list(kernel)

    fake_r = SimpleNamespace(stato=status, sorveglia=watch, rimuovi_sorveglianza=unwatch,
                             annota=real_r.annota, query=query)
    b.C, b.R = fake_c, fake_r
    monkeypatch.setattr(b.time, "sleep", lambda _: None)

    def probe(actor, target, phase, directory, real_agents):
        events.append(("probe", phase, actor))
        pid = 500 + ("shell", "mdls", "codex", "claude").index(actor)
        exists = target.exists()
        row = {"attore": actor, "fase": phase, "quando": b._ora(), "percorso": str(target),
               "riuscito": exists, "errno": None if exists else errno.ENOENT, "pid": pid,
               "ppid": 450, "uid": os.getuid(), "byte": target.stat().st_size if exists else None,
               "processo": "/fixture/metadata-probe", "agente": None, "riscontri_kernel": [],
               "misurato": True, "rc": 0}
        kernel[:] = [{"source": "eslogger", "quando": row["quando"], "evento": "open", "pid": pid,
                      "percorso": str(target), "processo": row["processo"],
                      "agente": actor in ("codex", "claude"),
                      "nome_agente": {"codex": "Codex", "claude": "Claude Code"}.get(actor)}] if exists else []
        return row

    monkeypatch.setattr(b, "_probe", probe)
    return SimpleNamespace(b=b, home=home, source=source, disk=disk, events=events,
                           system_dir_on_open=system_dir_on_open,
                           entries=entries, keys=keys, kernel=kernel, watches=watches,
                           readiness=readiness, real_r=real_r, protected=protected, ident=ident,
                           original_probe=load("banco_probe_test", ROOT / "strumenti" / "banco-probe.py"))


@pytest.mark.parametrize("field", ["running", "healthy", "local_chain_ok"])
def test_unready_collector_refuses_before_desktop_or_watch(bank, monkeypatch, field):
    b = bank.b
    bank.readiness[field] = False
    monkeypatch.setattr(b, "_inventario", lambda *a, **k: pytest.fail("Desktop was accessed"))
    monkeypatch.setattr(b, "_sintetici", lambda *a: pytest.fail("Synthetic files were created"))
    monkeypatch.setattr(b.R, "sorveglia", lambda *a: pytest.fail("Watch was registered"))
    with pytest.raises(b.Rifiuto, match="registro non è pronto"):
        b.esegui(bank.disk, KEY)
    assert bank.events == [("status", None)]
    assert not b.ARCHIVIO.exists() and not list(bank.source.iterdir())


def test_fresh_ack_precedes_files_and_all_phases_close_with_private_key(bank, monkeypatch):
    b = bank.b
    original = b._sintetici
    acknowledged = []
    stale = "banco-" + "f" * 32
    bank.watches[stale] = str(bank.source)
    real_status = b.R.stato

    def status():
        state = real_status()
        fresh = [w for w in bank.watches if w != stale]
        if fresh and fresh[0] not in acknowledged:
            acknowledged.append(fresh[0])
            state["watched_ids"] = [stale]
        return state

    def synthetic(path):
        assert acknowledged and acknowledged[0] != stale
        assert sum(e[0] == "status" for e in bank.events) >= 3
        bank.events.append(("synthetic", str(path)))
        return original(path)

    monkeypatch.setattr(b.R, "stato", status)
    monkeypatch.setattr(b, "_sintetici", synthetic)
    result = b.esegui(bank.disk, KEY)
    assert result["stato"] == "completo" and result["stato_finale"] == "chiusa"
    assert [p["nome"] for p in result["fasi"]] == ["prima", "chiusa", "riaperta", "richiusa"]
    assert all(p["ok"] for p in result["fasi"])
    assert bank.entries[bank.ident]["stato"] == "chiusa" and not list(bank.source.iterdir())
    assert bank.watches == {stale: str(bank.source)}
    assert all(key is KEY for key in bank.keys)
    for path in (b.ARCHIVIO, bank.real_r.CATENA, bank.real_r.CASA / "registro" / "sorveglianza.json"):
        assert KEY not in path.read_bytes()
    rows = [json.loads(line) for line in bank.real_r.CATENA.read_text().splitlines()]
    assert len(rows) == 16 and all(r["source"] == "paratia" and r["fonte"] == "banco" for r in rows)
    assert all(r["errno"] == errno.ENOENT for r in rows if r["fase"] in ("chiusa", "richiusa"))


def test_reused_user_watch_is_acknowledged_and_survives_bank_cleanup(bank, monkeypatch):
    b = bank.b
    existing = "user-owned-watch"
    bank.real_r.sorveglia(existing, bank.source, "Sorveglianza scelta dalla persona")
    bank.watches[existing] = str(bank.source)

    def watch(identifier, path, name=""):
        result = bank.real_r.sorveglia(identifier, path, name)
        bank.watches[result["id"]] = str(path)
        return result

    monkeypatch.setattr(b.R, "sorveglia", watch)
    result = b.esegui(bank.disk, KEY)
    assert result["stato"] == "completo" and result["stato_finale"] == "chiusa"
    assert bank.watches == {existing: str(bank.source)}
    assert [row["id"] for row in bank.real_r.elenco_sorveglianza()] == [existing]
    assert bank.real_r.elenco_sorveglianza()[0]["nome"] == "Sorveglianza scelta dalla persona"
    assert ("unwatch", existing) not in bank.events


def test_handshake_failure_precedes_fixture_creation_and_cleans_watch(bank, monkeypatch):
    b = bank.b
    monkeypatch.setattr(b, "_attendi_sorveglianza", lambda _: (_ for _ in ()).throw(b.Rifiuto("nessun ack")))
    with pytest.raises(b.Rifiuto, match="nessun ack"):
        b.esegui(bank.disk, KEY)
    assert not list(bank.source.iterdir()) and not bank.entries and not bank.watches
    result = b.storico()
    assert result["stato"] == "incompleto" and result["fasi"] == [] and result["sintetici"] is False


def test_personal_files_are_only_inventoried_never_opened_or_migrated(bank, monkeypatch):
    b = bank.b
    personal = bank.source / "personale.txt"
    personal.write_bytes(b"PRIVATE-CONTENT-TEST-ONLY")
    before = personal.stat()
    original_open, original_path_open = os.open, Path.open

    def no_file_open(path, *args, **kwargs):
        if not isinstance(path, int) and os.fspath(path) in (str(personal), personal.name):
            pytest.fail("Personal file contents were opened")
        return original_open(path, *args, **kwargs)

    def no_path_open(path, *args, **kwargs):
        if path == personal:
            pytest.fail("Personal file contents were opened")
        return original_path_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_file_open)
    monkeypatch.setattr(Path, "open", no_path_open)
    assert b.anteprima()["file"] == 1
    with pytest.raises(b.Rifiuto, match="personali o non riconosciuti"):
        b.esegui(bank.disk, KEY)
    after = personal.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino)
    assert not bank.entries and not any(e[0] == "protect" for e in bank.events)
    assert b.storico()["sintetici"] is False and not bank.watches


def test_ancestor_and_child_symlinks_are_refused(bank):
    b = bank.b
    link = bank.home / "desktop-link"
    link.symlink_to(bank.home / "Desktop", target_is_directory=True)
    with pytest.raises(OSError):
        b._inventario(link / "folder-test")
    (bank.source / "linked").symlink_to(bank.disk, target_is_directory=True)
    with pytest.raises(b.Rifiuto, match="collegamenti"):
        b._inventario(bank.source)


def test_protected_inventory_ignores_only_new_system_root_directories(bank):
    b = bank.b
    # This pre-existing name belongs to the source and must stay in inventory.
    original = bank.source / ".Spotlight-V100"
    original.mkdir()
    (original / "personal.txt").write_text("synthetic source data")
    nested = bank.source / "nested"
    nested.mkdir()
    before = b._inventario(bank.source)
    created = bank.source / ".fseventsd"
    created.mkdir()
    (created / "events").write_bytes(b"synthetic system metadata")
    (nested / ".fseventsd").mkdir()
    (nested / ".fseventsd" / "personal.txt").write_text("synthetic nested data")

    actual = b._inventario(bank.source, sistema_assenti=b.C.DIR_SISTEMA - before.keys())
    assert ".fseventsd" not in actual and ".fseventsd/events" not in actual
    assert actual[".Spotlight-V100/personal.txt"] == before[".Spotlight-V100/personal.txt"]
    assert "nested/.fseventsd/personal.txt" in actual
    assert ".fseventsd/events" in b._inventario(bank.source)  # No default exclusion.


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_system_root_name_never_hides_a_file_or_alias(bank, kind):
    path = bank.source / ".fseventsd"
    if kind == "file":
        path.write_bytes(b"synthetic user file")
        actual = bank.b._inventario(bank.source, sistema_assenti=bank.b.C.DIR_SISTEMA)
        assert actual[".fseventsd"]["tipo"] == "file"
    else:
        path.symlink_to(bank.disk, target_is_directory=True)
        with pytest.raises(bank.b.Rifiuto, match="collegamenti"):
            bank.b._inventario(bank.source, sistema_assenti=bank.b.C.DIR_SISTEMA)


def test_synthetic_preparation_does_not_overwrite_a_racing_file(bank, monkeypatch):
    b = bank.b
    original = b._directory_fd
    sentinel = bank.source / "LEGGIMI-SINTETICO.txt"

    def race(path):
        sentinel.write_bytes(b"fixture-owned-racing-file")
        return original(path)

    monkeypatch.setattr(b, "_directory_fd", race)
    # The first directory open belongs to inventory; introduce the race only
    # after that inventory has returned empty.
    monkeypatch.setattr(b, "_inventario", lambda _: {})
    with pytest.raises(FileExistsError):
        b._sintetici(bank.source)
    assert sentinel.read_bytes() == b"fixture-owned-racing-file"
    assert set(p.name for p in bank.source.iterdir()) == {sentinel.name}


def test_new_file_between_baseline_and_protection_is_never_migrated(bank, monkeypatch):
    b = bank.b
    original = b._fase

    def phase(*args):
        original(*args)
        if args[1] == "prima":
            (bank.source / "nuovo-personale.txt").write_bytes(b"TEST-ONLY-PERSONAL")

    monkeypatch.setattr(b, "_fase", phase)
    with pytest.raises(b.Rifiuto, match="cambiata durante"):
        b.esegui(bank.disk, KEY)
    assert not bank.entries and (bank.source / "nuovo-personale.txt").exists()
    assert not any(e[0] in ("protect", "close") for e in bank.events)


def test_missing_kernel_evidence_remains_incomplete_with_actual_errno(bank, monkeypatch):
    b = bank.b
    monkeypatch.setattr(b.R, "query", lambda _: [])
    result = b.esegui(bank.disk, KEY)
    assert result["stato"] == "incompleto" and result["stato_finale"] == "chiusa"
    for phase in result["fasi"]:
        for row in phase["prove"]:
            assert row["riscontri_kernel"] == [] and row["agente"] is None
            assert row["errno"] == (errno.ENOENT if phase["atteso"] == "rifiuto" else None)
            assert row["copertura_verificata"] is (phase["atteso"] == "rifiuto")


def test_failed_measured_probe_keeps_kernel_evidence_when_available(bank, monkeypatch):
    b = bank.b
    original = b._probe

    def measured(*args):
        row = original(*args)
        if row["riuscito"] is False:
            bank.kernel[:] = [{"source": "eslogger", "quando": row["quando"], "evento": "lookup",
                               "pid": row["pid"], "percorso": row["percorso"], "agente": None}]
        return row

    monkeypatch.setattr(b, "_probe", measured)
    result = b.esegui(bank.disk, KEY)
    closed = [r for p in result["fasi"] if p["atteso"] == "rifiuto" for r in p["prove"]]
    assert all(r["errno"] == errno.ENOENT and r["riuscito"] is False for r in closed)
    assert all(r["riscontri_kernel"][0]["evento"] == "lookup" for r in closed)
    # ES metadata does not acquire an errno merely because our probe failed.
    assert all("errno" not in r["riscontri_kernel"][0] for r in closed)


def test_unindexed_mdls_is_visible_but_does_not_fail_other_confirmed_probes(bank, monkeypatch):
    b = bank.b
    original = b._probe

    def probe(*args):
        row = original(*args)
        if row["attore"] == "mdls":
            row.update(riuscito=False, rc=1, errno=None)
            bank.kernel[:] = []
        return row

    monkeypatch.setattr(b, "_probe", probe)
    result = b.esegui(bank.disk, KEY)
    assert result["stato"] == "completo" and all(p["ok"] for p in result["fasi"])
    for phase in result["fasi"]:
        row = next(r for r in phase["prove"] if r["attore"] == "mdls")
        assert row["riuscito"] is False and row["rc"] == 1 and row["errno"] is None
        assert row["obbligatoria"] is False and row["riscontri_kernel"] == []
        assert "informativa" in row["nota"]
        required = [r for r in phase["prove"] if r["obbligatoria"]]
        assert len(required) == 3 and all(r["esito_atteso"] and r["copertura_verificata"] for r in required)
    exported = list(csv.DictReader(io.StringIO(b.export_csv())))
    assert all(row["obbligatoria"] == "False" for row in exported if row["attore"] == "mdls")


def test_unmeasured_agent_never_becomes_a_successful_bank_phase(bank, monkeypatch):
    b = bank.b
    original = b._probe

    def probe(*args):
        row = original(*args)
        if row["attore"] == "claude":
            row.update(misurato=False, riuscito=None, errno=None, pid=None, agente=None)
            bank.kernel[:] = []
        return row

    monkeypatch.setattr(b, "_probe", probe)
    result = b.esegui(bank.disk, KEY)
    assert result["stato"] == "incompleto" and result["stato_finale"] == "chiusa"
    assert all(p["ok"] is False for p in result["fasi"])
    for phase in result["fasi"]:
        row = next(r for r in phase["prove"] if r["attore"] == "claude")
        assert row["riuscito"] is None and row["errno"] is None and row["riscontri_kernel"] == []
        assert row["esito_atteso"] is False and row["copertura_verificata"] is False


@pytest.mark.parametrize("error", [RuntimeError("fixture interruption"), KeyboardInterrupt()])
def test_interruption_after_reopen_always_closes_and_marks_history(bank, monkeypatch, error):
    b = bank.b
    original = b._fase

    def phase(*args):
        if args[1] == "riaperta":
            assert bank.entries[bank.ident]["stato"] == "aperta"
            raise error
        original(*args)

    monkeypatch.setattr(b, "_fase", phase)
    with pytest.raises(type(error)):
        b.esegui(bank.disk, KEY)
    result = b.storico()
    assert result["stato"] == "incompleto" and result["tipo_errore"] == type(error).__name__
    assert result["stato_finale"] == "chiusa" and not list(bank.source.iterdir()) and not bank.watches


def test_migration_failure_closes_only_its_explicit_created_id(bank, monkeypatch):
    b = bank.b
    original = b.C.proteggi

    def fail(*args):
        created = original(*args)
        bank.entries[created["id"]]["stato"] = "migrazione-incompleta"
        error = b.C.Rifiuto("migrazione sintetica interrotta")
        error.cartella_id = created["id"]
        raise error

    monkeypatch.setattr(b.C, "proteggi", fail)
    with pytest.raises(b.C.Rifiuto):
        b.esegui(bank.disk, KEY)
    result = b.storico()
    assert ("close", bank.ident) in bank.events and result["cartella_id"] == bank.ident
    assert result["stato"] == "incompleto" and result["stato_finale"] != "chiusa"


def test_unrelated_concurrent_folder_is_not_guessed_for_error_cleanup(bank, monkeypatch):
    b = bank.b
    outsider = "b" * 32

    def fail(*args):
        # A different GUI registered a folder while this call failed without
        # creating its own ID. Source matching must not confer cleanup rights.
        bank.entries[outsider] = {"id": outsider, "origine": str(bank.source), "stato": "aperta"}
        raise b.C.Rifiuto("fixture failed before any own registration")

    monkeypatch.setattr(b.C, "proteggi", fail)
    with pytest.raises(b.C.Rifiuto):
        b.esegui(bank.disk, KEY)
    assert not any(e[0] == "close" for e in bank.events)
    assert bank.entries[outsider]["stato"] == "aperta" and b.storico()["cartella_id"] is None


def test_close_failure_reports_unverified_state_and_cleans_watch(bank, monkeypatch):
    b = bank.b
    original_phase = b._fase
    original_close = b.C.chiudi

    def phase(*args):
        if args[1] == "riaperta":
            raise RuntimeError("fixture interruption")
        original_phase(*args)

    def close(folder):
        if bank.entries[folder]["stato"] == "aperta":
            raise b.C.Rifiuto("busy")
        return original_close(folder)

    monkeypatch.setattr(b, "_fase", phase)
    monkeypatch.setattr(b.C, "chiudi", close)
    with pytest.raises(RuntimeError):
        b.esegui(bank.disk, KEY)
    result = b.storico()
    assert result["stato_finale"] == "da-verificare" and "avviso_chiusura" in result
    assert result["stato"] == "incompleto" and not bank.watches


def test_rerun_accepts_only_its_known_metadata_and_folder_identity(bank, monkeypatch):
    b = bank.b
    first = b.esegui(bank.disk, KEY)
    monkeypatch.setattr(b.R, "sorveglia", lambda *a, **k: pytest.fail("A protected rerun must use its existing folder ID"))
    second = b.esegui(bank.disk, KEY)
    assert first["id"] != second["id"] and first["cartella_id"] == second["cartella_id"] == bank.ident
    assert first["inventario"] == second["inventario"] and second["stato"] == "completo"
    assert sum(e[0] == "protect" for e in bank.events) == 1
    changed = bank.protected / "campione.bin"
    os.utime(changed, ns=(changed.stat().st_atime_ns, changed.stat().st_mtime_ns + 1000000))
    with pytest.raises(b.Rifiuto, match="metadati.*cambiati"):
        b.esegui(bank.disk, KEY)
    assert not list(bank.source.iterdir()) and b.storico()["sintetici"] is False
    bank.entries[bank.ident]["id"] = "b" * 32
    prior = list(bank.events)
    with pytest.raises(b.Rifiuto, match="non appartiene"):
        b.esegui(bank.disk, KEY)
    assert not any(e[0] in ("open", "close", "protect") for e in bank.events[len(prior):])


def test_lock_failure_never_closes_another_run_folder(bank):
    b = bank.b
    b.esegui(bank.disk, KEY)
    bank.events.clear()
    lock = os.open(b.CASA / "banco" / "esecuzione.lock", os.O_RDWR)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(b.Rifiuto, match="già in corso"):
            b.esegui(bank.disk, KEY)
        assert not any(e[0] in ("watch", "open", "close", "protect") for e in bank.events)
        assert len(b.storico()["prove"]) == 1
    finally:
        os.close(lock)


@pytest.mark.parametrize("exists", [True, False])
def test_actual_probe_uses_only_open_fstat_and_real_errno(bank, monkeypatch, exists):
    probe = bank.original_probe
    target = bank.home / "probe-fixture"
    if exists:
        target.write_bytes(b"SYNTHETIC-BYTES-NOT-READ")
    output = bank.home / "probe-result.json"
    monkeypatch.setattr(sys, "argv", ["banco-probe", "--file", str(target), "--result", str(output), "--nonce", "test-nonce"])
    monkeypatch.setattr(probe.os, "read", lambda *a: pytest.fail("Probe read file bytes"))
    assert probe.main() == 0
    row = json.loads(output.read_text())
    assert row["riuscito"] is exists and row["errno"] == (None if exists else errno.ENOENT)
    assert row["byte"] == (target.stat().st_size if exists else None)
    assert row["pid"] == os.getpid() and row["uid"] == os.getuid()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert b"SYNTHETIC-BYTES" not in output.read_bytes()


def test_actual_probe_refuses_symlink_and_reports_the_system_errno(bank, monkeypatch):
    probe = bank.original_probe
    target = bank.home / "synthetic-target"
    target.write_bytes(b"TEST-ONLY")
    link = bank.home / "synthetic-link"
    link.symlink_to(target)
    output = bank.home / "symlink-result.json"
    monkeypatch.setattr(sys, "argv", ["banco-probe", "--file", str(link), "--result", str(output), "--nonce", "nonce"])
    probe.main()
    row = json.loads(output.read_text())
    assert row["riuscito"] is False and row["byte"] is None and row["errno"] == errno.ELOOP


@pytest.mark.parametrize("change", [
    {"nonce": "wrong"}, {"pid": 0}, {"pid": True}, {"ppid": -1},
    {"uid": -1}, {"processo": "relative"}, {"processo": "/nul\0name"},
    {"riuscito": "yes"}, {"byte": True}, {"byte": -1}, {"errno": errno.EACCES},
    {"riuscito": False, "errno": None, "byte": None},
    {"riuscito": False, "errno": 0, "byte": None},
])
def test_probe_protocol_rejects_invalid_identity_or_result(bank, change):
    row = {"nonce": "nonce", "pid": 12, "ppid": 1, "uid": os.getuid(), "processo": "/fixture/probe",
           "riuscito": True, "errno": None, "byte": 42, **change}
    path = bank.home / "result.json"
    path.write_text(json.dumps(row))
    assert bank.b._risultato_probe(path, "nonce") is None


def test_probe_protocol_drops_extra_raw_fields_and_refuses_symlink(bank):
    path = bank.home / "result.json"
    row = {"nonce": "nonce", "pid": 12, "ppid": 1, "uid": os.getuid(), "processo": "/fixture/probe",
           "riuscito": False, "errno": errno.EACCES, "byte": None,
           "args": ["private-fixture"], "env": {"KEY": "private-fixture"}, "passphrase": KEY.decode()}
    path.write_text(json.dumps(row))
    result = bank.b._risultato_probe(path, "nonce")
    assert result["errno"] == errno.EACCES and set(result) == {"pid", "ppid", "uid", "processo", "riuscito", "errno", "byte"}
    link = bank.home / "result-link"
    link.symlink_to(path)
    assert bank.b._risultato_probe(link, "nonce") is None


@pytest.mark.parametrize("exception", [OSError("fixture communication failed"), KeyboardInterrupt(), subprocess.TimeoutExpired("fixture", 1)])
def test_spawned_command_session_is_terminated_on_every_failure(bank, monkeypatch, exception):
    b = bank.b
    signals = []

    class Process:
        pid = 99123
        returncode = None

        def communicate(self, **kwargs):
            raise exception

        def poll(self):
            return self.returncode

        def wait(self, **kwargs):
            self.returncode = -signal.SIGTERM
            return self.returncode

    process = Process()
    monkeypatch.setattr(b.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(b.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    if isinstance(exception, subprocess.TimeoutExpired):
        assert b._comando(["/fixture/test-process"], bank.home)["timeout"] is True
    else:
        with pytest.raises(type(exception)):
            b._comando(["/fixture/test-process"], bank.home)
    assert signals == [(process.pid, signal.SIGTERM)]


def test_agent_without_consent_or_cli_is_unmeasured_without_replacement(bank, monkeypatch):
    b = bank.b
    real_probe = load("banco_protocol_test", ROOT / "banco.py")._probe
    # Bind the implementation to the same module globals used by this fixture.
    probe = type(real_probe)(real_probe.__code__, b.__dict__)
    monkeypatch.setattr(b, "_cli", lambda _: pytest.fail("Agent lookup without consent"))
    row = probe("codex", bank.source / "target", "prima", bank.home, False)
    assert row["misurato"] is False and row["riuscito"] is None and row["pid"] is None
    monkeypatch.setattr(b, "_cli", lambda _: None)
    monkeypatch.setattr(b, "_comando", lambda *a, **k: pytest.fail("Replacement process invoked"))
    row = probe("claude", bank.source / "target", "prima", bank.home, True)
    assert row["misurato"] is False and row["agente"] is None


def test_codex_probe_protocol_is_a_real_sandbox_child_with_no_key(bank, monkeypatch):
    b = bank.b
    real_probe = load("banco_codex_protocol_test", ROOT / "banco.py")._probe
    probe = type(real_probe)(real_probe.__code__, b.__dict__)
    commands = []
    monkeypatch.setattr(b, "_cli", lambda _: "/fixture/codex-cli-not-executed")

    def command(argv, cwd, **kwargs):
        commands.append(argv)
        output = Path(argv[argv.index("--result") + 1])
        nonce = argv[argv.index("--nonce") + 1]
        output.write_text(json.dumps({"nonce": nonce, "pid": 123, "ppid": 100, "uid": os.getuid(),
                                      "processo": sys.executable, "riuscito": True, "errno": None, "byte": 12}))
        return {"rc": 0, "pid_launcher": 100, "timeout": False}

    monkeypatch.setattr(b, "_comando", command)
    result = probe("codex", bank.source / "target", "prima", bank.home, True)
    assert commands[0][:5] == ["/fixture/codex-cli-not-executed", "sandbox", "-C", str(bank.home), "--"]
    assert commands[0][5:7] == [sys.executable, str(b.PROBE)]
    assert KEY.decode() not in json.dumps(commands) and result["misurato"] is True
    assert result["agente"] is None  # A launcher is not authoritative ancestry.


def test_mcp_protocol_requests_one_human_bash_command_and_refuses_extra_consent(bank, monkeypatch):
    b = bank.b
    commands, signals = [], []

    class Input(io.BytesIO):
        closed_by_bank = False

        def close(self):
            self.closed_by_bank = True

    class Output:
        def fileno(self):
            return 76543

    class Process:
        pid = 98765
        returncode = None
        stdin, stdout = Input(), Output()

        def poll(self):
            return self.returncode

        def wait(self, **kwargs):
            self.returncode = -signal.SIGTERM
            return self.returncode

    process = Process()
    raw = b"\n".join(json.dumps(msg).encode() for msg in [
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 90, "method": "requestPermission", "params": {"secret": "RAW-PRIVATE-FIXTURE"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "Bash"}]}},
        {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "RAW-PRIVATE-FIXTURE"}]}},
    ]) + b"\n"
    monkeypatch.setattr(b.subprocess, "Popen", lambda argv, **kwargs: commands.append(argv) or process)
    monkeypatch.setattr(b.os, "set_blocking", lambda *a: None)
    monkeypatch.setattr(b.os, "read", lambda *a: raw)
    monkeypatch.setattr(b.select, "select", lambda *a: ([process.stdout], [], []))
    monkeypatch.setattr(b.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    result = b._mcp_comando("/fixture/claude-cli-not-executed", ["/fixture/probe", "--file", "a b"], bank.home)
    sent = [json.loads(line) for line in process.stdin.getvalue().splitlines()]
    assert commands == [["/fixture/claude-cli-not-executed", "mcp", "serve"]]
    assert [r.get("method") for r in sent if "method" in r] == ["initialize", "notifications/initialized", "tools/list", "tools/call"]
    assert next(r for r in sent if r.get("id") == 90)["error"]["code"] == -32601
    call = next(r for r in sent if r.get("method") == "tools/call")
    assert call["params"]["name"] == "Bash" and call["params"]["arguments"]["command"] == "/fixture/probe --file 'a b'"
    assert "RAW-PRIVATE-FIXTURE" not in json.dumps(result) and KEY.decode() not in json.dumps(sent)
    assert process.stdin.closed_by_bank and signals == [(process.pid, signal.SIGTERM)]


@pytest.mark.parametrize("error", [OSError("fixture pipe setup failure"), KeyboardInterrupt()])
def test_mcp_setup_failure_always_closes_its_spawned_session(bank, monkeypatch, error):
    b = bank.b
    signals = []

    class Output:
        def fileno(self):
            return 12345

    class Process:
        pid = 54321
        stdin = io.BytesIO()
        stdout = Output()
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, **kwargs):
            self.returncode = -signal.SIGTERM
            return self.returncode

    process = Process()
    monkeypatch.setattr(b.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(b.os, "set_blocking", lambda *a: (_ for _ in ()).throw(error))
    monkeypatch.setattr(b.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    if isinstance(error, OSError):
        assert b._mcp_comando("/fixture/cli-not-executed", ["/fixture/probe"], bank.home)["rc"] is None
    else:
        with pytest.raises(type(error)):
            b._mcp_comando("/fixture/cli-not-executed", ["/fixture/probe"], bank.home)
    assert signals == [(process.pid, signal.SIGTERM)] and process.stdin.closed


def test_csv_quotes_formula_fields_and_empty_history_is_truthful(bank):
    b = bank.b
    assert b.storico()["stato"] == "non-eseguito"
    prova = {"id": "test", "fasi": [{"nome": "prima", "prove": [{"attore": "@formula", "percorso": "=formula", "processo": "\tformula", "riuscito": False, "errno": errno.ENOENT}]}]}
    b._salva(prova)
    rows = list(csv.DictReader(io.StringIO(b.export_csv())))
    assert rows[0]["attore"] == "'@formula" and rows[0]["percorso"] == "'=formula" and rows[0]["processo"] == "'\tformula"
    assert rows[0]["riuscito"] == "False" and rows[0]["errno"] == str(errno.ENOENT)


def test_without_a_key_the_bench_uses_a_one_time_key_and_restores_folder_test(bank):
    b = bank.b
    result = b.esegui(minutes=15, agenti_reali=True)
    assert result["stato"] == "completo" and result["stato_finale"] == "ripristinata"
    assert result["chiave_usa_e_getta"] is True and result["ripristinata"] is True
    assert [p["nome"] for p in result["fasi"]] == ["prima", "chiusa", "riaperta", "richiusa"]
    assert ("remove", bank.ident) in bank.events and not bank.entries
    assert "LEGGIMI-SINTETICO.txt" in {p.name for p in bank.source.iterdir()}
    assert not any(e[0] == "external" for e in bank.events)
    one_time = bank.keys[0]
    assert len(one_time) >= 32 and all(k is one_time for k in bank.keys)
    for path in (b.ARCHIVIO, bank.real_r.CATENA):
        assert one_time not in path.read_bytes()


def test_one_time_bench_refuses_a_folder_protected_with_a_persons_key(bank):
    b = bank.b
    b.esegui(bank.disk, KEY)
    assert bank.entries[bank.ident]["stato"] == "chiusa"
    with pytest.raises(b.Rifiuto, match="Togli la protezione"):
        b.esegui(minutes=15, agenti_reali=True)
    assert bank.entries[bank.ident]["stato"] == "chiusa"


def test_reopened_volume_with_a_root_only_system_directory_is_not_a_failure(bank):
    bank.system_dir_on_open.append(True)
    result = bank.b.esegui(minutes=15, agenti_reali=False)
    assert result["stato"] == "completo" and result["stato_finale"] == "ripristinata"
    assert [p["file_visibili"] for p in result["fasi"]] == [4, 0, 4, 0]


def test_preview_recognises_the_synthetic_files_of_an_earlier_test(bank):
    b = bank.b
    assert b.anteprima()["stato"] == "vuota"
    b.esegui(minutes=15, agenti_reali=False)
    preview = b.anteprima()
    assert preview["stato"] == "sintetici" and "riusa" in preview["messaggio"]
