"""Diagnosis from metadata fixtures, without root or reading TCC databases."""
from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest


@pytest.fixture()
def R(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("registry_diagnosis_test", Path(__file__).resolve().parents[1] / "registro.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SYSTEM = tmp_path / "logs"
    module.CATENA = tmp_path / "local" / "catena.jsonl"
    (module.SYSTEM / str(os.getuid())).mkdir(parents=True)
    monkeypatch.setattr(module, "_cdhash_app", lambda path: "a" * 40)
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
                    "watched_ids": ["synthetic-watch"], "installed_cdhash": "a" * 40,
                    "message": "Registro attivo."})
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


def healthy_state(**extra):
    return {"heartbeat": time.time(), "running": True, "healthy": True,
            "needs_fda": False, "schema_supported": True, "watched_ids": ["first"],
            "installed_cdhash": "a" * 40, "dropped_events": 0, **extra}


@pytest.mark.parametrize("extra,code", [
    ({"event_lag_seconds": 180}, "event_delay"),
    ({"dropped_events": 6}, "dropped_events"),
    ({"watch_status": [{"id": "second", "status": "rejected", "reason_code": "owner_mismatch"}]}, "rejected_watches"),
    ({"watch_status": [{"id": None, "status": "rejected", "reason_code": "invalid_entry"}]}, "rejected_watches"),
    ({"watched_ids": []}, "no_watched_folders"),
    ({"running": False}, "not_running"),
    ({"needs_fda": True}, "needs_fda"),
    ({"schema_supported": False}, "schema_unsupported"),
    ({"healthy": False}, "diagnostics"),
])
def test_every_unhealthy_cause_has_a_readable_safe_reason(R, monkeypatch, extra, code):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, healthy_state(**extra))
    status = R.stato()
    assert not status["healthy"]
    assert code in {reason["code"] for reason in status["health_reasons"]}
    assert all(reason["message"] for reason in status["health_reasons"])


def test_idle_stream_is_not_mistaken_for_a_delayed_event(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    now = time.time()
    write_state(R, healthy_state(last_event_received_at=now - 300,
                                event_lag_seconds=0.1, lines_per_second=0,
                                raw_lines=1200, filtered_lines=1100, parsed_lines=100))
    status = R.stato()
    assert status["healthy"] and status["health_reasons"] == []
    assert status["last_event_age_seconds"] >= 300
    assert status["event_lag_seconds"] == 0.1 and status["lines_per_second"] == 0
    assert status["raw_lines"] == 1200


@pytest.mark.parametrize("value", [True, -1, float("nan"), float("inf"), "123"])
def test_invalid_numeric_metrics_and_heartbeat_never_prove_health(R, monkeypatch, value):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, healthy_state(event_lag_seconds=value, lines_per_second=value))
    status = R.stato()
    assert status["event_lag_seconds"] is None and status["lines_per_second"] is None
    write_state(R, healthy_state(heartbeat=value))
    status = R.stato()
    assert not status["running"] and not status["healthy"]
    assert status["event_lag_seconds"] is None


def test_future_heartbeat_is_not_accepted_as_fresh(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, healthy_state(heartbeat=time.time() + 60))
    assert not R.stato()["running"]


def test_stale_confirmation_and_throughput_are_not_reused(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, healthy_state(heartbeat=time.time() - 60, lines_per_second=90000,
                                watch_status=[{"id": "first", "status": "confirmed"}]))
    status = R.stato()
    assert status["watched_ids"] == [] and status["watch_status"] == []
    assert status["lines_per_second"] is None


def test_watch_reasons_and_health_messages_do_not_echo_state_payload(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    write_state(R, healthy_state(watch_status=[
        {"id": "second", "status": "rejected", "reason_code": "owner_mismatch", "message": "RAW_PRIVATE_PAYLOAD"},
        {"id": "third", "status": "rejected", "reason_code": "RAW_PRIVATE_PAYLOAD"},
        {"id": "bad\nID", "status": "rejected", "message": "RAW_PRIVATE_PAYLOAD"},
    ], health_reasons=[{"code": "anything", "message": "RAW_PRIVATE_PAYLOAD"}]))
    status = R.stato()
    assert len(status["watch_status"]) == 2
    assert "RAW_PRIVATE_PAYLOAD" not in json.dumps(status)


def test_query_collection_metadata_includes_metrics_reasons_and_scoped_rejection(R, monkeypatch):
    state = healthy_state(event_lag_seconds=0.2, lines_per_second=42000,
                          last_event_received_at=123, last_event_age_seconds=4,
                          raw_lines=50000, filtered_lines=47500, parsed_lines=2500,
                          watch_status=[{"id": "second", "status": "rejected", "reason_code": "owner_mismatch",
                                         "message": "RAW_PRIVATE_PAYLOAD"}])
    state["health_reasons"] = R.motivi_salute(state)
    state["healthy"] = False
    monkeypatch.setattr(R, "stato", lambda: state)
    result = R.raccolta_kernel({"folder": "second"})
    collection = result["kernel_collection"]
    assert not result["kernel_active"] and collection["acknowledged"] is False
    assert "rifiutata dal raccoglitore" in collection["message"]
    assert collection["event_lag_seconds"] == 0.2 and collection["lines_per_second"] == 42000
    assert collection["raw_lines"] == 50000 and collection["filtered_lines"] == 47500
    assert collection["last_event_age_seconds"] == 4
    assert collection["health_reasons"][0]["code"] == "rejected_watches"
    assert "RAW_PRIVATE_PAYLOAD" not in json.dumps(result)


def test_anonymous_file_rejection_has_visible_specific_reason_once(R, monkeypatch):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    rejected = {"id": None, "status": "rejected", "reason_code": "config_unreadable",
                "message": "RAW_PRIVATE_PAYLOAD"}
    write_state(R, healthy_state(watch_status=[rejected, rejected]))
    status = R.stato()
    reasons = status["health_reasons"]
    assert len([value for value in reasons if value["code"] == "watch_config_unreadable"]) == 1
    assert any("file di configurazione" in value["message"] for value in reasons)
    assert "RAW_PRIVATE_PAYLOAD" not in json.dumps(reasons)
    assert not status["healthy"]


@pytest.mark.parametrize("installed_hash,current_hash,required,comparison", [
    ("a" * 40, "a" * 40, False, "equal"),
    ("a" * 40, "b" * 40, True, "different"),
    (None, "b" * 40, True, "unavailable"),
    ("a" * 40, None, False, "unavailable"),
])
def test_build_identity_comparison_and_minimal_ordered_update_steps(
        R, monkeypatch, installed_hash, current_hash, required, comparison):
    monkeypatch.setattr(R, "_servizio_installato", lambda uid: (True, "app"))
    monkeypatch.setattr(R, "_cdhash_app", lambda app: current_hash)
    write_state(R, healthy_state(installed_cdhash=installed_hash))
    status = R.stato()
    assert status["needs_update"] is required
    assert status["build_comparison"] == comparison
    if required:
        assert status["needs_reinstall"] and not status["healthy"]
        assert len(status["update_steps"]) == 6
        steps = status["update_steps"]
        assert "Chiudi" in steps[0] and "ParatiaBootstrap/Paratia.app" in steps[1]
        assert "Autorizza con macOS" in steps[2]
        assert "Chiudi" in steps[3]
        assert "rimuovi e aggiungi" in steps[4] and "Non autorizzare Python" in steps[4]
        assert "eslogger" in steps[5]
    if comparison == "unavailable":
        assert "diversa" not in status["update_message"]


def test_cdhash_is_read_only_and_limited_to_fixed_paratia_paths(R, monkeypatch):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["timeout"] == 2
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr":
            "Identifier=it.paratia.app\nCDHash=" + "a" * 40 + "\n"})()
    monkeypatch.undo()
    monkeypatch.setattr(R.subprocess, "run", run)
    assert R._cdhash_app("/Applications/Paratia.app") == "a" * 40
    assert R._cdhash_app("/tmp/user-app.app") is None
    assert len(calls) == 1
    assert calls[0][0][:3] == ["/usr/bin/codesign", "-d", "--verbose=4"]


@pytest.mark.parametrize("stderr", [
    "Identifier=elsewhere\nCDHash=" + "a" * 40,
    "Identifier=it.paratia.app\nCDHash=not-a-hash",
    "Identifier=it.paratia.app\nCDHash=" + "a" * 40 + "\nCDHash=" + "b" * 40,
    "Identifier=it.paratia.app\n" + "x" * 65536,
])
def test_malformed_or_unrelated_codesign_identity_is_unknown(R, monkeypatch, stderr):
    monkeypatch.undo()
    monkeypatch.setattr(R.subprocess, "run", lambda *a, **k: type("Result", (), {
        "returncode": 0, "stdout": "", "stderr": stderr})())
    assert R._cdhash_app("/Applications/Paratia.app") is None
