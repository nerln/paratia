"""The existing gate covers every protected folder, while still ignoring zones."""
import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("PARATIA_HOME", str(tmp_path))
    monkeypatch.setenv("PARATIA_MOUNT", str(tmp_path / "legacy"))
    source = Path(__file__).resolve().parents[1] / "hooks/paratia-gate.py"
    spec = importlib.util.spec_from_file_location("gate_folders", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_registered_mount_denies_even_when_legacy_is_closed(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {"montaggio": "/"}}
    }))
    assert gate.compartimento_aperto()


def test_corrupt_registry_fails_closed(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text("{broken")
    assert gate.compartimento_aperto()
    assert gate.chiudi_inizio_sessione() == 2


@pytest.mark.parametrize("data", [None, [], {"versione": 1, "cartelle": {"one": None}}])
def test_valid_json_with_wrong_structure_fails_closed(gate, tmp_path, data):
    (tmp_path / "cartelle.json").write_text(json.dumps(data))
    assert gate.compartimento_aperto()


def test_closed_registered_folder_does_not_block(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {"montaggio": str(tmp_path / "closed")}}
    }))
    assert not gate.compartimento_aperto()


def test_session_start_without_compartments_needs_no_privileges(gate):
    assert gate.chiudi_inizio_sessione() == 0


def test_incomplete_migration_blocks_session_even_if_no_volume_is_mounted(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {
            "montaggio": str(tmp_path / "closed"), "stato": "migrazione-incompleta",
            "plaintext_residuo": str(tmp_path / "original")
        }}
    }))
    assert gate.compartimento_aperto()
