"""Native IPC framing, private keys, safe exports and backend routing.

Tests use temporary sibling modules or injected doubles. They never call the
real disk/keychain/agent tools or write to the user's Paratia configuration.
"""
from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"worker-fixture-passphrase-123"


def frame(params=None, key=b""):
    raw = json.dumps(params if params is not None else {}, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(key)) + key


def raw_frame(raw, key=b""):
    return struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(key)) + key


@pytest.fixture()
def W(monkeypatch):
    spec = importlib.util.spec_from_file_location("gui_worker_test", ROOT / "gui_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Main's fd isolation is verified in subprocess tests. Unit tests use an
    # injected context to leave pytest's own output streams alone.
    monkeypatch.setattr(module, "_muted_output", contextlib.nullcontext)
    return module


def run_main(W, action, payload):
    output = io.StringIO()
    assert W.main(["worker", action], io.BytesIO(payload), output) == 0
    lines = output.getvalue().splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def collection_fixture(active=False):
    return {"kernel_active": active, "kernel_collection": {
        "message": "Raccolta kernel attiva." if active else "Raccolta kernel inattiva.",
        "coverage_guaranteed": False,
    }}


@pytest.mark.parametrize("payload", [
    b"", b"\0", struct.pack(">I", 0), struct.pack(">I", 1048577),
    struct.pack(">I", 5) + b"{}", raw_frame(b"{"), raw_frame(b"[]"),
    raw_frame(b"null"), raw_frame(b"\xff"), raw_frame(b'{"x":NaN}'),
    raw_frame(b'{"x":Infinity}'), raw_frame(b'{"x":1,"x":2}'),
    frame()[:-1], frame() + b"trailing", raw_frame(b"{}")[:-4] + struct.pack(">I", 4097),
    raw_frame(b"{}", b"abc")[:-1],
])
def test_malformed_frames_are_structured_and_never_load_backend(W, monkeypatch, payload):
    monkeypatch.setattr(W, "_load", lambda *a, **k: pytest.fail("Malformed frame reached backend"))
    response = run_main(W, "cartelle.elenco", payload)
    assert response["ok"] is False
    assert response["code"] == "invalid_request"
    assert response["action"] == "cartelle.elenco"
    assert "Riprova" in response["message"]


def test_read_frame_accepts_partial_reads_and_bounds_header_before_body(W):
    class Chunked(io.BytesIO):
        def read(self, count=-1):
            return super().read(min(count, 3))

    params = {"id": "abc", "minutes": 5}
    assert W.read_frame(Chunked(frame(params, KEY))) == (params, KEY)

    class HeaderOnly(io.BytesIO):
        def read(self, count=-1):
            assert count == 4, "An oversized metadata payload was read"
            return super().read(count)

    with pytest.raises(W.RequestError):
        W.read_frame(HeaderOnly(struct.pack(">I", W.MAX_METADATA + 1)))


def test_frame_limits_accept_exact_boundaries(W):
    raw = b"{}" + b" " * (W.MAX_METADATA - 2)
    key = b"a" * W.MAX_KEY
    assert W.read_frame(io.BytesIO(raw_frame(raw, key))) == ({}, key)


@pytest.mark.parametrize("argv", [["worker"], ["worker", "__import__"],
                                       ["worker", "cartelle.elenco", "secret-extra"]])
def test_action_allowlist_never_echoes_untrusted_argv(W, monkeypatch, argv):
    monkeypatch.setattr(W, "_load", lambda *a, **k: pytest.fail("Unknown action reached backend"))
    output = io.StringIO()
    W.main(argv, io.BytesIO(frame()), output)
    response = json.loads(output.getvalue())
    assert response["code"] == "invalid_action"
    assert response["action"] == ""
    assert "secret-extra" not in output.getvalue()


@pytest.mark.parametrize("action,params,key,code", [
    ("cartelle.apri", {"id": "abc"}, b"", "missing_key"),
    ("cartelle.apri", {"id": "abc"}, b"short", "invalid_key"),
    ("cartelle.apri", {"id": "abc"}, KEY + b"\n", "invalid_key"),
    ("cartelle.apri", {"id": "abc"}, KEY + b"\0", "invalid_key"),
    ("cartelle.apri", {"id": "abc"}, KEY + b"\xff", "invalid_key"),
    ("cartelle.elenco", {}, KEY, "unexpected_key"),
    ("cartelle.apri", {"id": "abc", "passphrase": KEY.decode()}, KEY, "invalid_params"),
    ("cartelle.proteggi", {"origine": "/fake/" + KEY.decode(), "dove": "/fake/SSD"}, KEY, "invalid_params"),
    ("cartelle.apri", {"id": "abc", "minutes": True}, KEY, "invalid_params"),
    ("cartelle.apri", {"id": "abc", "minutes": 0}, KEY, "invalid_params"),
    ("cartelle.apri", {"id": "../abc"}, KEY, "invalid_params"),
    ("cartelle.chiudi", {"id": "abc", "force": "true"}, b"", "invalid_params"),
    ("registro.query", {"filters": {"limit": 1}}, b"", "invalid_params"),
    ("registro.query", {"filters": {"since": "not-a-date"}}, b"", "invalid_params"),
    ("registro.export_csv", {"path": "relative.csv"}, b"", "invalid_params"),
    ("etichette.segna", {"percorso": "/fake", "etichetta": "segreto"}, b"", "invalid_params"),
    ("banco.run", {"dove": "/fake/SSD"}, KEY, "invalid_params"),
    ("banco.run", {"dove": "/fake/SSD", "agenti_reali": "true"}, KEY, "invalid_params"),
    ("hooks.applica", {"home": "/fake"}, b"", "invalid_params"),
    ("hooks.ripristina", {"path": "relative.json"}, b"", "invalid_params"),
    ("hooks.ripristina", {"path": "/fake/backup.json", "home": "/fake"}, b"", "invalid_params"),
    ("hooks.ripristina", {"path": "/fake/backup.json"}, KEY, "unexpected_key"),
])
def test_schema_and_key_validation_precede_any_backend(W, monkeypatch, action, params, key, code):
    monkeypatch.setattr(W, "_load", lambda *a, **k: pytest.fail("Invalid schema reached backend"))
    response = run_main(W, action, frame(params, key))
    assert response["ok"] is False
    assert response["code"] == code
    assert KEY.decode() not in json.dumps(response)


def test_folder_keys_are_bytes_only_and_backend_warning_survives(W, monkeypatch):
    calls = []

    def apri(identifier, passphrase, minutes):
        calls.append((identifier, passphrase, minutes))
        assert isinstance(passphrase, bytes)
        assert passphrase == KEY
        assert KEY.decode() not in json.dumps(dict(os.environ))
        return {"id": identifier, "stato": "aperta", "avviso_registro": "Verifica il registro."}

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(apri=apri))
    params = {"id": "abc", "minutes": 27}
    response = run_main(W, "cartelle.apri", frame(params, KEY))
    assert calls == [("abc", KEY, 27)]
    assert response["result"]["avviso_registro"] == "Verifica il registro."
    assert KEY.decode() not in json.dumps(params)
    assert KEY.decode() not in json.dumps(response)


def test_returned_key_is_refused_instead_of_being_serialized(W, monkeypatch):
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(apri=lambda *a, **k: {"accident": KEY.decode()}))
    response = run_main(W, "cartelle.apri", frame({"id": "abc"}, KEY))
    assert response["code"] == "internal_error"
    assert KEY.decode() not in json.dumps(response)


@pytest.mark.parametrize("exception,code,word", [
    (PermissionError("English " + KEY.decode()), "permission_required", "Privacy"),
    (FileNotFoundError(KEY.decode()), "not_found", "disco"),
    (OSError(KEY.decode()), "io_error", "spazio"),
    (ValueError(KEY.decode()), "invalid_data", "Controlla"),
    (RuntimeError(KEY.decode()), "internal_error", "Riapri"),
])
def test_errors_are_italian_categories_without_exception_text(W, monkeypatch, exception, code, word):
    def failing(*a, **k):
        raise exception

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(apri=failing))
    response = run_main(W, "cartelle.apri", frame({"id": "abc"}, KEY))
    assert response["code"] == code
    assert word in response["message"]
    assert KEY.decode() not in json.dumps(response)
    assert "English" not in json.dumps(response)


def test_backend_refusal_text_is_never_forwarded(W, monkeypatch):
    class Rifiuto(Exception):
        pass

    def fail(*a, **k):
        raise Rifiuto("Incorrect password: " + KEY.decode())

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(apri=fail))
    response = run_main(W, "cartelle.apri", frame({"id": "abc"}, KEY))
    assert response["code"] == "refused"
    assert "proteggere i dati" in response["message"]
    assert "Incorrect" not in response["message"]


@pytest.mark.parametrize("interpreter", [sys.executable] + (["/usr/bin/python3"] if Path("/usr/bin/python3").is_file() else []))
def test_isolated_worker_suppresses_import_and_backend_stdout_stderr(tmp_path, interpreter):
    shutil.copyfile(ROOT / "gui_worker.py", tmp_path / "gui_worker.py")
    (tmp_path / "cartelle.py").write_text(
        "import os, sys\n"
        "print('IMPORT_NOISE')\n"
        "os.write(2, b'IMPORT_STDERR')\n"
        "def apri(identifier, key, minutes):\n"
        "    assert key not in '\\0'.join(sys.argv).encode()\n"
        "    assert key not in repr(dict(os.environ)).encode()\n"
        "    print(key.decode())\n"
        "    print(key.decode(), file=sys.stderr)\n"
        "    os.write(1, key)\n"
        "    os.write(2, key)\n"
        "    raise RuntimeError(key.decode())\n",
        encoding="utf-8",
    )
    result = subprocess.run([interpreter, "-I", "-S", str(tmp_path / "gui_worker.py"), "cartelle.apri"],
                            input=frame({"id": "abc"}, KEY), capture_output=True, check=False)
    assert result.returncode == 0
    assert result.stderr == b""
    assert KEY not in result.stdout
    assert b"IMPORT" not in result.stdout
    assert len(result.stdout.splitlines()) == 1
    assert json.loads(result.stdout)["code"] == "internal_error"


def test_query_passes_all_filters_and_truncates_only_display(W, monkeypatch):
    filters = {"folder": "cartella1", "file": "documento", "process": "123", "agent": "unknown",
               "since": "2026-10-07T10:00:00+02:00", "until": "2026-10-08T20:00:00Z"}
    seen = []
    rows = [{"pid": n} for n in range(3100)]
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        query=lambda f: seen.append(f) or rows, raccolta_kernel=lambda f: collection_fixture(True)))
    result = W.dispatch("registro.query", {"filters": filters})
    assert seen == [filters]
    assert result == {"rows": rows[:2500], "total": 3100, "truncated": True, **collection_fixture(True)}


def test_short_query_is_not_marked_truncated(W, monkeypatch):
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        query=lambda f: [], raccolta_kernel=lambda f: collection_fixture()))
    assert W.dispatch("registro.query", {}) == {"rows": [], "total": 0, "truncated": False,
                                              **collection_fixture()}


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("action", ["registro.query", "registro.export_csv"])
def test_empty_registry_results_preserve_kernel_state_for_query_and_csv(W, monkeypatch, tmp_path, active, action):
    filters = {"folder": "stable-folder"}
    seen = []

    def health(actual):
        seen.append(actual)
        return collection_fixture(active)

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        query=lambda f: [], export_csv=lambda f: "evento\n", raccolta_kernel=health))
    params = {"filters": filters}
    if action.endswith("export_csv"):
        params["path"] = str(tmp_path.resolve() / "empty.csv")
    response = run_main(W, action, frame(params))
    assert response["ok"] and response["result"]["kernel_active"] is active
    assert not response["result"]["kernel_collection"]["coverage_guaranteed"]
    assert seen == [filters]
    count = "total" if action.endswith("query") else "count"
    assert response["result"][count] == 0


@pytest.mark.parametrize("action,code,fragment", [
    ("registro.query", "folder_not_configured", "La cartella non è configurata nel registro"),
    ("registro.export_csv", "folder_not_configured", "La cartella non è configurata nel registro"),
    ("registro.query", "folder_ambiguous", "Il percorso corrisponde a più ID"),
    ("registro.export_csv", "folder_ambiguous", "Il percorso corrisponde a più ID"),
    ("registro.sorveglia", "protected_folder_watch", "cartella protetta già configurata"),
])
def test_registry_errors_reach_the_app_without_raw_diagnostics_or_export(W, monkeypatch, tmp_path, action, code, fragment):
    class ErroreRegistro(ValueError):
        def __init__(self):
            self.code = code
            self.message = "unsafe stream " + KEY.decode()
            super().__init__(self.message)

    def fail(*args, **kwargs):
        raise ErroreRegistro()

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        query=fail, export_csv=fail, sorveglia=fail))
    target = tmp_path.resolve() / "must-not-exist.csv"
    if action.endswith("sorveglia"):
        params = {"id": "stable-folder", "percorso": str(tmp_path.resolve())}
    else:
        params = {"filters": {"folder": "/fixture/configured-path"}}
        if action.endswith("export_csv"):
            params["path"] = str(target)
    response = run_main(W, action, frame(params))
    assert not response["ok"] and response["code"] == code and fragment in response["message"]
    assert KEY.decode() not in json.dumps(response) and "unsafe stream" not in json.dumps(response)
    assert not target.exists()


def test_registry_csv_uses_backend_escaping_and_complete_rows(W, monkeypatch, tmp_path):
    # Real CSV formatting, injected data source: no access to ~/.paratia.
    spec = importlib.util.spec_from_file_location("registro_gui_export_test", ROOT / "registro.py")
    registro = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(registro)
    malicious = ["=SUM(A1)", " +1", "\t@evil", "\r-1", "\n=1"]
    rows = [{"evento": value, "percorso": "/fake/path\nwith-newline"} for value in malicious]
    rows += [{"evento": "open"} for _ in range(2501)]
    seen = []
    monkeypatch.setattr(registro, "query", lambda filters: seen.append(filters) or rows)
    monkeypatch.setattr(registro, "raccolta_kernel", lambda filters: collection_fixture())
    monkeypatch.setattr(W, "_load", lambda name: registro)
    target = str(tmp_path.resolve() / "registro.csv")
    result = W.dispatch("registro.export_csv", {"path": target, "filters": {"agent": True}})
    exported = list(csv.DictReader(io.StringIO(Path(target).read_bytes().decode("utf-8"), newline="")))
    assert len(exported) == len(rows) == result["count"]
    assert [r["evento"] for r in exported[:5]] == ["'" + v for v in malicious]
    assert seen == [{"agent": True}]
    assert stat.S_IMODE(Path(target).stat().st_mode) == 0o600
    assert result["bytes"] == len(Path(target).read_bytes())
    assert result["kernel_active"] is False and not result["kernel_collection"]["coverage_guaranteed"]


@pytest.mark.parametrize("kind", ["file", "dangling", "ancestor"])
def test_exports_refuse_symlink_destinations_and_ancestors(W, monkeypatch, tmp_path, kind):
    base = tmp_path.resolve()
    real = base / "real"
    real.mkdir()
    original = real / "target.csv"
    original.write_text("existing")
    if kind == "ancestor":
        link = base / "linkdir"
        link.symlink_to(real, target_is_directory=True)
        target = link / "target.csv"
    else:
        target = base / "link.csv"
        target.symlink_to(original if kind == "file" else base / "absent.csv")
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        export_csv=lambda f: "evento\nopen\n", raccolta_kernel=lambda f: collection_fixture()))
    response = run_main(W, "registro.export_csv", frame({"path": str(target)}))
    assert response["code"] == "unsafe_path"
    assert original.read_text() == "existing"
    assert not list(base.rglob(".paratia-export-*"))


def test_export_replaces_atomically_and_cleans_up_on_write_failure(W, monkeypatch, tmp_path):
    target = tmp_path.resolve() / "registro.csv"
    target.write_text("original")
    target.chmod(0o644)
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(
        export_csv=lambda f: "evento\nopen\n", raccolta_kernel=lambda f: collection_fixture()))
    real_replace = os.replace
    inspected = []

    def inspect_replace(source, destination, **kwargs):
        assert target.read_text() == "original"
        inspected.append(os.stat(source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False).st_mode)
        real_replace(source, destination, **kwargs)

    monkeypatch.setattr(W.os, "replace", inspect_replace)
    result = W.dispatch("registro.export_csv", {"path": str(target)})
    assert result["count"] == 1
    assert stat.S_IMODE(inspected[0]) == stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text() == "evento\nopen\n"
    target.write_text("keep-on-failure")

    def fail_replace(*a, **k):
        raise PermissionError("sensitive diagnostic")

    monkeypatch.setattr(W.os, "replace", fail_replace)
    response = run_main(W, "registro.export_csv", frame({"path": str(target)}))
    assert response["code"] == "permission_required"
    assert target.read_text() == "keep-on-failure"
    assert not list(target.parent.glob(".paratia-export-*"))


def test_optional_backends_are_pending_without_fabricating_results(W, tmp_path, monkeypatch):
    monkeypatch.setattr(W, "RESOURCE_ROOT", tmp_path)
    for action in ("banco.storico", "hooks.stato", "hooks.install_plan", "hooks.applica"):
        response = run_main(W, action, frame())
        assert response["ok"] is False
        assert response["code"] == "pending"
        assert "result" not in response
    (tmp_path / "banco.py").write_text("VERSIONE = 1\n")
    assert run_main(W, "banco.storico", frame())["code"] == "pending"


def test_optional_bank_api_and_exports_use_actual_history(W, monkeypatch, tmp_path):
    calls = []
    history = {"versione": 1, "stato": "da-eseguire", "prove": [], "fasi": [], "limiti": ["Registro da autorizzare."]}

    def run(dove, key, minutes, agenti_reali):
        calls.append((dove, key, minutes, agenti_reali))
        return history

    bank = SimpleNamespace(storico=lambda: history, esegui=run,
                           anteprima=lambda **params: {"stato": "da-autorizzare", **params},
                           export_csv=lambda: "fase,esito\n'@fixture,da-autorizzare\n")
    monkeypatch.setattr(W, "_load", lambda name, **k: bank)
    assert W.dispatch("banco.run", {"dove": "/fake/SSD", "minutes": 5, "agenti_reali": False}, KEY) == history
    assert calls == [("/fake/SSD", KEY, 5, False)]
    assert W.dispatch("banco.anteprima", {"path": "/fake/cartella"})["stato"] == "da-autorizzare"
    json_path = tmp_path.resolve() / "storico.json"
    result = W.dispatch("banco.export_json", {"path": str(json_path)})
    assert result["count"] == 0
    assert json.loads(json_path.read_text()) == history
    csv_path = tmp_path.resolve() / "storico.csv"
    result = W.dispatch("banco.export_csv", {"path": str(csv_path)})
    assert result["count"] == 1
    assert csv_path.read_text() == bank.export_csv()
    assert stat.S_IMODE(json_path.stat().st_mode) == stat.S_IMODE(csv_path.stat().st_mode) == 0o600


def test_hooks_and_registry_install_plans_only_use_sibling_resources(W, monkeypatch):
    calls = []

    def planned(**kwargs):
        calls.append(kwargs)
        return {"configured": False, "needs_human_trust": True}

    monkeypatch.setattr(W, "_load", lambda name, **k: SimpleNamespace(stato=planned, piano=planned, installa=planned))
    for action in ("hooks.stato", "hooks.install_plan", "hooks.applica"):
        assert W.dispatch(action, {})["needs_human_trust"]
        assert calls[-1] == {"resource_root": W.RESOURCE_ROOT, "python_executable": None}
    W.dispatch("registro.install_plan", {})
    assert calls[-1] == {"resource_root": W.RESOURCE_ROOT}


def test_hook_restore_from_worker_preserves_original_and_refuses_later_edit(W, monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("hooks_gui_restore_test", ROOT / "hookinstaller.py")
    hooks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hooks)
    home = tmp_path.resolve()
    (home / ".claude").mkdir()
    original = b'{"env":{"existing":"retained"}}\n'
    target = home / ".claude" / "settings.json"
    target.write_bytes(original)
    # Hook installation chooses the protected Apple runtime. The pytest venv
    # interpreter is intentionally not an authorized hook runtime.
    installed = hooks.installa(resource_root=ROOT, home=home)
    backup = next(path for path in installed["backups"] if "/.claude/" in path)
    monkeypatch.setattr(W, "_load", lambda *a, **k: SimpleNamespace(
        ripristina=lambda path: hooks.ripristina(path, home=home)))
    result = run_main(W, "hooks.ripristina", frame({"path": backup}))
    assert result["ok"] and result["result"]["restored"]
    assert target.read_bytes() == original
    assert Path(result["result"]["backup"]).is_file()
    edited = b'{"env":{"new":"user edit"}}\n'
    target.write_bytes(edited)
    refused = run_main(W, "hooks.ripristina", frame({"path": backup}))
    assert refused["ok"] is False and refused["code"] == "refused"
    assert target.read_bytes() == edited


def test_remaining_folder_and_label_routes(W, monkeypatch):
    calls = []

    def record(name):
        def function(*args, **kwargs):
            calls.append((name, args, kwargs))
            return {"esito": name}
        return function

    module = SimpleNamespace(**{name: record(name) for name in (
        "elenco", "proteggi", "chiudi", "chiudi_tutte", "recupera", "annulla_migrazione",
        "sfoglia", "segna", "togli", "piano", "stato", "verifica")})
    monkeypatch.setattr(W, "_load", lambda name: module)
    examples = [
        ("cartelle.elenco", {}, b"", "elenco", (), {}),
        ("cartelle.proteggi", {"origine": "/fake/dir", "dove": "/fake/SSD"}, KEY, "proteggi", ("/fake/dir", "/fake/SSD", KEY), {"minutes": 15}),
        ("cartelle.chiudi", {"id": "abc"}, b"", "chiudi", ("abc",), {}),
        ("cartelle.chiudi_tutte", {}, b"", "chiudi_tutte", (), {}),
        ("cartelle.recupera", {"id": "abc"}, KEY, "recupera", ("abc", KEY), {}),
        ("cartelle.annulla", {"id": "abc"}, b"", "annulla_migrazione", ("abc",), {}),
        ("etichette.sfoglia", {"radice": "/fake", "mostra_nascosti": True}, b"", "sfoglia", ("/fake",), {"mostra_nascosti": True}),
        ("etichette.segna", {"percorso": "/fake", "etichetta": "zona:work", "nota": "nota"}, b"", "segna", ("/fake", "zona:work"), {"nota": "nota"}),
        ("etichette.togli", {"percorso": "/fake"}, b"", "togli", ("/fake",), {}),
        ("etichette.elenco", {}, b"", "elenco", (), {}),
        ("etichette.piano", {}, b"", "piano", (), {}),
        ("registro.stato", {}, b"", "stato", (), {}),
        ("registro.verifica", {}, b"", "verifica", (), {}),
    ]
    for action, params, key, name, args, kwargs in examples:
        assert W.dispatch(action, params, key) == {"esito": name}
        assert calls[-1] == (name, args, kwargs)
