"""Watch configuration and CLI output never imply a live kernel collector."""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def cli(tmp_path, monkeypatch):
    home = tmp_path.resolve()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PARATIA_HOME", str(home / "state"))
    p = load("registro_cli_test", ROOT / "paratia.py")
    r = load("registro_backend_cli_test", ROOT / "registro.py")
    r.SYSTEM = home / "kernel"
    state = {"running": False, "healthy": False, "watched_ids": []}
    monkeypatch.setattr(r, "stato", lambda: dict(state))
    folder = home / "caffè"
    folder.mkdir()
    return p, r, folder, state


def invoke(cli, arguments):
    p, r, _, _ = cli
    args = p.costruisci().parse_args(["registro", *arguments])
    return p._esegui_registro(r, args)


def test_cli_configured_watch_stays_inactive_until_healthy_ack(cli, capsys):
    _, _, folder, state = cli
    assert invoke(cli, ["sorveglia", str(folder), "--id", "first"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["configurata"] is True and result["raccolta_attiva"] is False and result["sorvegliata"] is False
    assert invoke(cli, ["sorveglia", str(folder), "--id", "second"]) == 0
    reused = json.loads(capsys.readouterr().out)
    assert reused["id"] == "first" and reused["riutilizzata"] is True
    state.update(running=True, healthy=True, watched_ids=["first"])
    assert invoke(cli, ["sorveglia", str(folder)]) == 0
    assert json.loads(capsys.readouterr().out)["raccolta_attiva"] is True


@pytest.mark.parametrize("verb", ["elenco", "esporta"])
def test_empty_cli_output_warns_that_collection_is_stopped(cli, capsys, verb):
    assert invoke(cli, [verb]) == 0
    output = capsys.readouterr()
    assert "raccolta kernel non attiva" in output.err and "vuoto non prova" in output.err
    if verb == "elenco":
        assert json.loads(output.out) == []
    else:
        assert list(csv.DictReader(io.StringIO(output.out))) == []
        assert "quando" in output.out


def test_missing_folder_and_unknown_remove_are_rejected_without_rewriting(cli, capsys):
    _, r, folder, _ = cli
    with pytest.raises(ValueError, match="esistente"):
        invoke(cli, ["sorveglia", str(folder.parent / "missing")])
    assert invoke(cli, ["sorveglia", str(folder), "--id", "first"]) == 0
    capsys.readouterr()
    before = (r.CASA / "registro" / "sorveglianza.json").read_bytes()
    with pytest.raises(ValueError, match="non è configurato"):
        invoke(cli, ["smetti", "unknown"])
    assert (r.CASA / "registro" / "sorveglianza.json").read_bytes() == before


def test_dedup_path_can_filter_and_remove_by_path_without_ambiguity(cli, capsys):
    _, r, folder, _ = cli
    for ident in ("first", "second"):
        invoke(cli, ["sorveglia", str(folder), "--id", ident])
        capsys.readouterr()
    r.annota("synthetic", cartella="first", percorso=str(folder / "file"))
    assert invoke(cli, ["elenco", "--cartella", str(folder) + "/"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1
    assert invoke(cli, ["smetti", str(folder)]) == 0
    assert json.loads(capsys.readouterr().out)["rimossa"] is True
    assert r.elenco_sorveglianza() == []


def test_new_registration_repairs_legacy_duplicates_and_does_not_reassign_other_id(cli):
    _, r, folder, _ = cli
    directory = r.CASA / "registro"
    directory.mkdir(parents=True)
    path = directory / "sorveglianza.json"
    path.write_text(json.dumps({"versione": 1, "percorsi": {"first": {"percorso": str(folder)}, "second": {"percorso": str(folder)}}}))
    assert r.sorveglia("third", folder)["id"] == "first"
    assert len(r.elenco_sorveglianza()) == 1
    other = folder.parent / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="un'altra cartella"):
        r.sorveglia("first", other)
    assert r.elenco_sorveglianza()[0]["origine"] == str(folder)


def test_cli_explicit_new_name_on_same_path_reports_existing_name(cli, capsys):
    _, r, folder, _ = cli
    invoke(cli, ["sorveglia", str(folder), "--id", "first", "--nome", "Nome conservato"])
    capsys.readouterr()
    invoke(cli, ["sorveglia", str(folder), "--id", "second", "--nome", "Nuovo nome"])
    result = json.loads(capsys.readouterr().out)
    assert result["id"] == "first" and result["nome"] == "Nome conservato"
    assert result["riutilizzata"] and "ID e nome conservati" in result["messaggio"]
    assert r.elenco_sorveglianza()[0]["nome"] == "Nome conservato"
