"""Status and the gate describe every open folder, using metadata fixtures."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def app(tmp_path, monkeypatch):
    home = tmp_path / "state"
    monkeypatch.setenv("PARATIA_HOME", str(home))
    monkeypatch.setenv("PARATIA_MOUNT", str(tmp_path / "main-store"))
    spec = importlib.util.spec_from_file_location("status_cartelle_test", ROOT / "paratia.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entry(path, name="Cartella sintetica", state="aperta"):
    return {"id": "fixture", "nome": name, "origine": str(path), "montaggio": str(path),
            "bundle": str(path.parent / "fixture.sparsebundle"), "stato": state,
            "generation": "fixture-generation"}


def write_registry(app, row):
    app.CASA.mkdir()
    (app.CASA / "cartelle.json").write_text(json.dumps({"versione": 1, "cartelle": {"fixture": row}}))


def status(app, json_mode):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        rc = app.cmd_status(SimpleNamespace(json=json_mode))
    return rc, json.loads(output.getvalue()) if json_mode else output.getvalue()


def test_open_folder_is_listed_when_main_store_is_locked(app, tmp_path, monkeypatch):
    mount = tmp_path / "protected-folder"
    mount.mkdir()
    write_registry(app, entry(mount))
    monkeypatch.setattr(Path, "is_mount", lambda path: path == mount)
    rc, result = status(app, True)
    assert rc == 0 and result["aperto"] is True and result["forziere_aperto"] is False
    assert result["cartelle_aperte"][0]["montaggi_aperti"] == [str(mount)]
    assert result["cartelle_aperte"][0]["id"] == "fixture"
    rc, text = status(app, False)
    assert rc == 0 and "OPEN" in text and "Cartella sintetica" in text
    assert "paratia cartella chiudi-tutte" in text


def test_closed_folders_and_unused_home_remain_locked(app, tmp_path):
    rc, result = status(app, True)
    assert rc == 0 and result["aperto"] is False and result["cartelle_aperte"] == []
    assert not app.CASA.exists()
    mount = tmp_path / "closed-folder"
    mount.mkdir()
    write_registry(app, entry(mount, state="chiusa"))
    rc, result = status(app, True)
    assert rc == 0 and result["aperto"] is False and result["cartelle_aperte"] == []


def test_incomplete_migration_is_reported_for_recovery(app, tmp_path):
    mount = tmp_path / "incomplete"
    mount.mkdir()
    write_registry(app, entry(mount, state="migrazione-incompleta"))
    rc, result = status(app, True)
    assert rc == 0 and result["aperto"] is True
    assert result["cartelle_aperte"][0]["da_recuperare"]
    rc, text = status(app, False)
    assert "recovery required" in text


def test_unreadable_registry_is_unknown_instead_of_locked(app):
    app.CASA.mkdir()
    (app.CASA / "cartelle.json").write_text("{broken")
    rc, result = status(app, True)
    assert rc == 2 and result["cartelle_non_verificate"]
    rc, text = status(app, False)
    assert rc == 2 and "UNKNOWN" in text and "state        locked" not in text


def test_gate_refusal_names_folder_close_and_both_exact_commands_are_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("PARATIA_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("status_gate_test", ROOT / "hooks" / "paratia-gate.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    monkeypatch.setattr(gate, "compartimento_aperto", lambda: True)

    def run(command):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}
        output = io.StringIO()
        monkeypatch.setattr(gate.sys, "stdin", io.StringIO(json.dumps(payload)))
        with contextlib.redirect_stdout(output):
            assert gate.main() == 0
        return json.loads(output.getvalue()) if output.getvalue() else None

    refused = run("cat /fixture/secret")
    reason = refused["hookSpecificOutput"]["permissionDecisionReason"]
    assert "paratia cartella chiudi-tutte" in reason and "paratia lock" in reason
    assert run("paratia cartella chiudi-tutte") is None
    assert run("paratia status --json") is None
    assert run("paratia cartella chiudi-tutte; cat /fixture/secret") is not None
