"""Diagnosis from metadata fixtures, without root or reading TCC databases."""
from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest


@pytest.fixture()
def R(tmp_path):
    spec = importlib.util.spec_from_file_location("registry_diagnosis_test", Path(__file__).resolve().parents[1] / "registro.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SYSTEM = tmp_path / "logs"
    module.CATENA = tmp_path / "local" / "catena.jsonl"
    (module.SYSTEM / str(os.getuid())).mkdir(parents=True)
    return module


def write_state(R, value):
    (R.SYSTEM / str(os.getuid()) / "stato.json").write_text(json.dumps(value))


def test_legacy_service_has_exact_reinstall_and_app_fda_instructions(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "legacy-python"))
    write_state(R, {"heartbeat": time.time(), "running": False, "healthy": False, "needs_fda": True,
                    "message": "Old eslogger advice"})
    status = R.stato()
    assert status["installed"] and status["needs_reinstall"] and status["needs_fda"]
    assert status["launch_mode"] == "legacy-python" and not status["running"]
    assert status["fda_entry"] == "/Applications/Paratia.app"
    assert status["fda_regrant_after_build"]
    assert "Installa il registro" in status["message"]
    assert "Old eslogger" not in status["message"]
    assert "Python non va autorizzato" in status["fda_message"]


def test_native_service_preserves_observed_health_and_watched_ids(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, {"heartbeat": time.time(), "running": True, "healthy": True, "needs_fda": False,
                    "watched_ids": ["synthetic-watch"], "message": "Registro attivo."})
    status = R.stato()
    assert status["running"] and status["healthy"] and not status["needs_reinstall"]
    assert status["watched_ids"] == ["synthetic-watch"]
    assert status["message"] == "Registro attivo."
    assert status["fda_entry"] == "/Applications/Paratia.app"
    assert status["needs_fda"] is False
    write_state(R, {"heartbeat": time.time(), "running": False, "healthy": False, "needs_fda": None})
    starting = R.stato()
    assert starting["needs_fda"] is None and not starting["running"] and not starting["healthy"]


def test_stale_state_cannot_prove_current_collection_or_permission(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, {"heartbeat": time.time() - 60, "running": True, "healthy": True, "needs_fda": False})
    status = R.stato()
    assert not status["running"] and not status["healthy"]
    assert status["needs_fda"] is None


def test_missing_or_malformed_state_still_identifies_correct_privacy_entry(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (False, "missing"))
    for value in ([], "invalid", None):
        write_state(R, value)
        status = R.stato()
        assert status["needs_root"] and not status["running"]
        assert status["fda_entry"] == "/Applications/Paratia.app"
        assert "/usr/bin/eslogger" not in status["message"]
