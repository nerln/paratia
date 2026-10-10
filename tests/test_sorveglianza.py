"""Plain-folder watches through the API, human CLI and framed GUI transport.

All stores, watched folders and subprocess HOME directories are temporary.
Only metadata fixtures are inspected: no Desktop, privileged collector, agents,
keychain or network is involved.
"""
from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"synthetic-watch-key-not-needed"
CONTENT = b"synthetic-content-must-not-be-read-by-watcher"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def R(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    home = base / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PARATIA_HOME", str(home / ".paratia"))
    module = load_module("registro_sorveglianza_test", ROOT / "registro.py")
    module.SYSTEM = base / "collector" / "logs"
    module.SUPPORT = base / "collector" / "support"
    return module


@pytest.fixture()
def folder(tmp_path):
    path = tmp_path.resolve() / "documenti"
    path.mkdir()
    (path / "sintetico.txt").write_bytes(CONTENT)
    return path


def watch_file(R):
    return R.CASA / "registro" / "sorveglianza.json"


def test_listing_is_metadata_only_and_watch_does_not_encrypt_or_move(R, folder, monkeypatch):
    real_open = io.open
    real_os_open = os.open

    def guard_open(path, *args, **kwargs):
        if isinstance(path, (str, bytes, Path)):
            candidate = Path(os.fsdecode(path))
            assert not (candidate == folder or folder in candidate.parents), "The watcher opened file contents"
        return real_open(path, *args, **kwargs)

    def guard_os_open(path, *args, **kwargs):
        if isinstance(path, (str, bytes, Path)):
            candidate = Path(os.fsdecode(path))
            assert not (candidate == folder or folder in candidate.parents), "The watcher opened file contents"
        return real_os_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(io, "open", guard_open)
        patch.setattr(os, "open", guard_os_open)
        result = R.sorveglia("documenti-1", folder, "Documenti di prova")
        rows = R.elenco_sorveglianza()
    assert result["id"] == "documenti-1" and result["percorso"] == str(folder)
    assert result["configurata"] is True
    assert result["sorvegliata"] is result["raccolta_attiva"] is False
    assert "raccolta non attiva" in result["messaggio"]
    assert rows == [{"id": "documenti-1", "nome": "Documenti di prova", "origine": str(folder),
                     "percorso": str(folder), "tipo": "sorveglianza", "esiste": True,
                     "configurata": True, "raccolta_attiva": False}]
    assert CONTENT.decode() not in json.dumps(rows)
    assert CONTENT not in watch_file(R).read_bytes()
    assert (folder / "sintetico.txt").read_bytes() == CONTENT
    assert not (R.CASA / "cartelle.json").exists()
    assert not list(R.CASA.rglob("*.sparsebundle"))
    assert R.rimuovi_sorveglianza("documenti-1")["sorvegliata"] is False
    assert R.elenco_sorveglianza() == []
    assert (folder / "sintetico.txt").read_bytes() == CONTENT


def test_listing_does_not_create_store_and_missing_folder_is_explicit_metadata(R, tmp_path):
    assert R.elenco_sorveglianza() == []
    assert not R.CASA.exists()
    missing = tmp_path.resolve() / "cartella-non-presente"
    with pytest.raises(ValueError, match="cartella esistente"):
        R.sorveglia("attesa", missing)
    assert not watch_file(R).exists()
    # Existing requests remain visible if their folder later disappears.
    missing.mkdir()
    R.sorveglia("attesa", missing)
    missing.rmdir()
    row = R.elenco_sorveglianza()[0]
    assert row["origine"] == row["percorso"] == str(missing)
    assert row["nome"] == missing.name
    assert row["esiste"] is False
    assert row["tipo"] == "sorveglianza"
    assert not {"stato", "healthy", "kernelhealthy", "protected", "contents"} & row.keys()
    assert not missing.exists()


def test_listing_projects_validated_metadata_from_user_configuration(R, folder):
    p = watch_file(R)
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"versione": 1, "percorsi": {"manuale": {
        "percorso": str(folder), "nome": "Nome umano", "contents": CONTENT.decode(),
        "password": KEY.decode(), "stato": "protetta", "healthy": True,
    }}}), encoding="utf-8")
    row = R.elenco_sorveglianza()[0]
    assert set(row) == {"id", "nome", "origine", "percorso", "tipo", "esiste", "configurata", "raccolta_attiva"}
    assert row["configurata"] is True and row["raccolta_attiva"] is False
    assert row["nome"] == "Nome umano"
    assert CONTENT.decode() not in json.dumps(row)
    assert KEY.decode() not in json.dumps(row)
    assert json.loads(p.read_text())["percorsi"]["manuale"]["contents"] == CONTENT.decode()


@pytest.mark.parametrize("data", [
    {"versione": 2, "percorsi": {}}, {"versione": 1, "percorsi": []},
    {"versione": 1, "percorsi": {"../escape": {"percorso": "/"}}},
    {"versione": 1, "percorsi": {"id": []}},
    {"versione": 1, "percorsi": {"id": {"percorso": "relative"}}},
    {"versione": 1, "percorsi": {"id": {"percorso": "/"}}},
])
def test_listing_refuses_invalid_user_store_without_rewriting(R, data):
    p = watch_file(R)
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(data), encoding="utf-8")
    before = p.read_bytes()
    with pytest.raises(ValueError):
        R.elenco_sorveglianza()
    assert p.read_bytes() == before


def test_listing_refuses_corrupt_oversized_or_wrong_owner_store(R, folder, monkeypatch):
    R.sorveglia("prova", folder)
    p = watch_file(R)
    valid = p.read_bytes()
    for contents in (b"{not-json", b" " * 4194305):
        p.write_bytes(contents)
        with pytest.raises(ValueError):
            R.elenco_sorveglianza()
        assert p.read_bytes() == contents
    p.write_bytes(valid)
    real_uid = os.getuid()
    with monkeypatch.context() as patch:
        patch.setattr(R.os, "getuid", lambda: real_uid + 1)
        with pytest.raises(ValueError):
            R.elenco_sorveglianza()
    assert p.read_bytes() == valid


@pytest.mark.parametrize("kind", ["folder", "ancestor", "store"])
def test_symlinks_are_refused_without_replacing_existing_configuration(R, folder, tmp_path, monkeypatch, kind):
    R.sorveglia("originale", folder)
    p = watch_file(R)
    original = p.read_bytes()
    link = tmp_path.resolve() / "alias"
    if kind == "folder":
        link.symlink_to(folder, target_is_directory=True)
        with pytest.raises(ValueError):
            R.sorveglia("alias", link)
        assert p.read_bytes() == original
    elif kind == "ancestor":
        link.symlink_to(R.CASA, target_is_directory=True)
        with monkeypatch.context() as patch:
            patch.setattr(R, "CASA", link)
            with pytest.raises(OSError):
                R.elenco_sorveglianza()
        assert p.read_bytes() == original
    else:
        preserved = p.with_name("sorveglianza-reale.json")
        p.rename(preserved)
        p.symlink_to(preserved)
        with pytest.raises(OSError):
            R.elenco_sorveglianza()
        with pytest.raises(OSError):
            R.sorveglia("nuova", folder)
        assert p.is_symlink()
        assert preserved.read_bytes() == original


@pytest.mark.parametrize("path", ["/", "/Users", "/Volumes", "/Library", "/private", "/private/tmp", "/private/var", "/Users/Shared"])
def test_system_roots_are_refused_without_mutating_watch_store(R, folder, path):
    R.sorveglia("originale", folder)
    before = watch_file(R).read_bytes()
    with pytest.raises(ValueError):
        R.sorveglia("troppo-ampia", path)
    assert watch_file(R).read_bytes() == before


def test_collector_scope_and_invalid_ids_are_refused(R, folder):
    R.sorveglia("originale", folder)
    before = watch_file(R).read_bytes()
    for path in (R.SYSTEM, R.SUPPORT, R.SYSTEM / "figlio", R.SYSTEM.parent):
        with pytest.raises(ValueError):
            R.sorveglia("collector", path)
        assert watch_file(R).read_bytes() == before
    for identifier in ("", "../escape", "con/slash", "è", "x" * 129):
        with pytest.raises(ValueError):
            R.sorveglia(identifier, folder)
        assert watch_file(R).read_bytes() == before


def add_records(R, folder):
    R.appendi(R.CATENA, {"quando": "2026-10-10T10:00:00+00:00", "evento": "open",
                        "percorso": str(folder / "sintetico.txt"), "processo": "=synthetic-formula",
                        "agente": True, "nome_agente": "Codex",
                        "cartelle": [{"id": "watch-1", "nome": "Cartella osservata", "origine": str(folder), "tipo": "sorveglianza"}]})
    R.appendi(R.CATENA, {"quando": "2026-10-10T11:00:00+00:00", "evento": "write",
                        "percorso": "/synthetic-other/file", "cartelle": [{"id": "other-1", "nome": "Altra"}]})


def test_watched_id_filter_and_csv_keep_only_matching_metadata(R, folder):
    R.sorveglia("watch-1", folder, "Cartella osservata")
    add_records(R, folder)
    records = R.query({"folder": "watch-1"})
    assert len(records) == 1 and records[0]["evento"] == "open"
    rows = list(csv.DictReader(io.StringIO(R.export_csv({"folder": "watch-1"}))))
    assert len(rows) == 1
    assert rows[0]["percorso"] == str(folder / "sintetico.txt")
    assert rows[0]["processo"] == "'=synthetic-formula"
    assert CONTENT.decode() not in json.dumps(rows)


@pytest.fixture()
def isolated_app(tmp_path):
    base = tmp_path.resolve()
    app, home = base / "app", base / "home"
    app.mkdir()
    home.mkdir()
    for name in ("paratia.py", "gui_worker.py", "registro.py", "catena.py"):
        shutil.copyfile(ROOT / name, app / name)
    # Preserve the production APIs and redirect only collector filesystem roots.
    # This prevents query/export from consulting the user's live kernel chain.
    with (app / "registro.py").open("a", encoding="utf-8") as output:
        output.write("\nSYSTEM = Path(" + repr(str(base / "collector" / "logs")) + ")\n")
        output.write("SUPPORT = Path(" + repr(str(base / "collector" / "support")) + ")\n")
    env = dict(os.environ, HOME=str(home), PARATIA_HOME=str(home / ".paratia"))
    return {"app": app, "home": home, "state": home / ".paratia", "env": env}


def cli(app, *args):
    return subprocess.run([sys.executable, "-I", "-S", str(app["app"] / "paratia.py"), "registro", *args],
                          env=app["env"], cwd=app["app"], capture_output=True, text=True, timeout=20, check=False)


def frame(params, key=b""):
    raw = json.dumps(params, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(key)) + key


def worker(app, action, params, key=b""):
    result = subprocess.run([sys.executable, "-I", "-S", str(app["app"] / "gui_worker.py"), action],
                            env=app["env"], cwd=app["app"], input=frame(params, key),
                            capture_output=True, timeout=20, check=False)
    assert result.returncode == 0
    assert result.stderr == b""
    assert len(result.stdout.splitlines()) == 1
    assert KEY not in result.stdout
    return json.loads(result.stdout)


def test_cli_watch_list_and_stop_with_explicit_id(isolated_app, folder):
    created = cli(isolated_app, "sorveglia", str(folder), "--id", "watch-cli", "--nome", "Documenti CLI")
    assert created.returncode == 0 and created.stderr == ""
    assert json.loads(created.stdout)["id"] == "watch-cli"
    listed = cli(isolated_app, "sorveglianza")
    assert listed.returncode == 0
    row = json.loads(listed.stdout)[0]
    assert row["id"] == "watch-cli" and row["nome"] == "Documenti CLI"
    assert row["origine"] == str(folder) and row["esiste"] is True
    stopped = cli(isolated_app, "smetti", "watch-cli")
    assert stopped.returncode == 0 and json.loads(stopped.stdout)["sorvegliata"] is False
    assert json.loads(cli(isolated_app, "sorveglianza").stdout) == []
    assert (folder / "sintetico.txt").read_bytes() == CONTENT
    assert not (isolated_app["state"] / "cartelle.json").exists()


def test_cli_generates_uuid_and_can_stop_by_existing_path(isolated_app, folder):
    created = cli(isolated_app, "sorveglia", str(folder))
    assert created.returncode == 0
    identifier = json.loads(created.stdout)["id"]
    assert uuid.UUID(identifier).hex
    assert json.loads(cli(isolated_app, "sorveglianza").stdout)[0]["id"] == identifier
    stopped = cli(isolated_app, "smetti", str(folder))
    assert stopped.returncode == 0 and json.loads(stopped.stdout)["sorvegliata"] is False
    assert json.loads(cli(isolated_app, "sorveglianza").stdout) == []


def test_cli_requires_watch_path_and_refuses_bad_id_without_traceback(isolated_app, folder):
    missing = cli(isolated_app, "sorveglia")
    assert missing.returncode != 0
    assert not (isolated_app["state"] / "registro" / "sorveglianza.json").exists()
    refused = cli(isolated_app, "sorveglia", str(folder), "--id", "../escape")
    assert refused.returncode != 0
    assert "Traceback" not in refused.stderr
    assert "identificatore" in refused.stderr.lower()
    assert not (isolated_app["state"] / "registro" / "sorveglianza.json").exists()


@pytest.mark.parametrize("by_path", [False, True])
def test_cli_query_and_csv_resolve_watched_folder_filter(isolated_app, folder, monkeypatch, by_path):
    created = cli(isolated_app, "sorveglia", str(folder), "--id", "watch-1", "--nome", "Cartella osservata")
    assert created.returncode == 0
    monkeypatch.setenv("PARATIA_HOME", str(isolated_app["state"]))
    R = load_module("registro_cli_records_test", isolated_app["app"] / "registro.py")
    add_records(R, folder)
    selected = str(folder) if by_path else "watch-1"
    queried = cli(isolated_app, "elenco", "--cartella", selected)
    assert queried.returncode == 0 and "raccolta kernel non attiva" in queried.stderr
    rows = json.loads(queried.stdout)
    assert len(rows) == 1 and rows[0]["evento"] == "open"
    named = cli(isolated_app, "elenco", "--cartella", selected, "--agente", "Codex")
    assert named.returncode == 0 and json.loads(named.stdout) == rows
    classified = cli(isolated_app, "elenco", "--cartella", selected, "--agente", "true")
    assert classified.returncode == 0 and json.loads(classified.stdout) == rows
    other = cli(isolated_app, "elenco", "--cartella", selected, "--agente", "Claude Code")
    assert other.returncode == 0 and json.loads(other.stdout) == []
    exported = cli(isolated_app, "esporta", "--cartella", selected)
    assert exported.returncode == 0 and "raccolta kernel non attiva" in exported.stderr
    csv_rows = list(csv.DictReader(io.StringIO(exported.stdout)))
    assert len(csv_rows) == 1
    assert csv_rows[0]["processo"] == "'=synthetic-formula"
    assert csv_rows[0]["percorso"] == str(folder / "sintetico.txt")


def test_worker_watch_list_remove_use_real_backend_routes(isolated_app, folder):
    created = worker(isolated_app, "registro.sorveglia", {"id": "watch-gui", "percorso": str(folder), "nome": "Documenti GUI"})
    assert created["ok"] is True and created["result"]["configurata"] is True
    assert created["result"]["sorvegliata"] is created["result"]["raccolta_attiva"] is False
    listed = worker(isolated_app, "registro.elenco_sorveglianza", {})
    assert listed["ok"] is True
    row = listed["result"][0]
    assert row["id"] == "watch-gui" and row["nome"] == "Documenti GUI"
    assert row["origine"] == str(folder) and row["esiste"] is True
    stopped = worker(isolated_app, "registro.rimuovi_sorveglianza", {"id": "watch-gui"})
    assert stopped["ok"] is True and stopped["result"]["sorvegliata"] is False
    assert worker(isolated_app, "registro.elenco_sorveglianza", {})["result"] == []
    assert (folder / "sintetico.txt").read_bytes() == CONTENT


@pytest.mark.parametrize("action,params", [
    ("registro.elenco_sorveglianza", {}),
    ("registro.sorveglia", {"id": "watch", "percorso": "/synthetic/path"}),
    ("registro.rimuovi_sorveglianza", {"id": "watch"}),
])
def test_watch_worker_actions_refuse_keys_before_backend_write(isolated_app, action, params):
    response = worker(isolated_app, action, params, KEY)
    assert response["ok"] is False and response["code"] == "unexpected_key"
    assert response["action"] == action
    assert not isolated_app["state"].exists()


@pytest.mark.parametrize("action,params", [
    ("registro.elenco_sorveglianza", {"home": "/synthetic"}),
    ("registro.sorveglia", {"percorso": "/synthetic"}),
    ("registro.sorveglia", {"id": "watch", "percorso": "relative"}),
    ("registro.sorveglia", {"id": "../escape", "percorso": "/synthetic"}),
    ("registro.sorveglia", {"id": "watch", "percorso": "/synthetic", "nome": 123}),
    ("registro.sorveglia", {"id": "watch", "percorso": "/synthetic", "password": "secret-extra"}),
    ("registro.rimuovi_sorveglianza", {}),
    ("registro.rimuovi_sorveglianza", {"id": "watch", "force": True}),
])
def test_watch_worker_schema_guards_precede_real_backend(isolated_app, action, params):
    response = worker(isolated_app, action, params)
    assert response["ok"] is False and response["code"] == "invalid_params"
    assert response["action"] == action
    assert not isolated_app["state"].exists()
