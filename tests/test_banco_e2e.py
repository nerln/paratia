"""IPC -> actual bank workflow -> folder backend on disposable synthetic data.

Images and mdls are simulated here; ditto and shell open/fstat are real. The
separate native script is prepared, never invoked by pytest. No live agents,
kernel collector, Desktop, root, TCC, or keychain are used.
"""
from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEY = b"e2e-synthetic-only-passphrase-123"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def integration():
    if not Path("/usr/bin/ditto").is_file():
        pytest.skip("Metadata copy uses the existing macOS ditto fixture")
    script = load("banco_temporary_test", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    disks = load("banco_e2e_disks_fixture", ROOT / "tests" / "test_cartelle.py")
    base = Path(tempfile.mkdtemp(prefix="paratia-banco-e2e-", dir="/private/tmp")).resolve()
    (base / ".fixture").write_text(script.MARKER)
    configured = {}

    def configure(folders):
        fake = disks.Dischi(folders)
        configured["disks"] = fake
        folders._corri = fake.corri
        folders._montato = lambda path: str(path) in fake.montati
        folders._avvia_timer = lambda *args: fake.timer.append(args)

    def mdls(argv):
        return {"rc": 0 if Path(argv[-1]).is_file() else 1, "pid_launcher": os.getpid(),
                "timeout": False, "fixture": "mdls simulato"}

    try:
        yield SimpleNamespace(script=script, base=base, configure=configure, mdls=mdls, configured=configured)
    finally:
        # Fake images cannot mount a kernel volume. Still refuse removal if an
        # unexpected real mount exists under this owned temporary fixture.
        assert not any(p.is_mount() for p in base.rglob("*") if p.is_dir())
        shutil.rmtree(base)


def run_payload(environment, script):
    return script.frame({"dove": str(environment.disk), "minutes": 1, "agenti_reali": False}, KEY)


def test_ipc_bank_four_phases_really_open_fstat_restore_and_reclose(integration):
    s = integration.script
    home_before, env_before = Path.home(), os.environ.get("PARATIA_HOME")
    with s.fixture(integration.base, KEY, integration.configure, integration.mdls) as e:
        response = s.request(e, run_payload(e, s))
        assert response["ok"] is True
        result = response["result"]
        assert result["stato"] == "incompleto"  # No real agents or kernel evidence.
        assert result["stato_finale"] == "chiusa" and result["file"] == 4
        phases = result["fasi"]
        assert [p["nome"] for p in phases] == ["prima", "chiusa", "riaperta", "richiusa"]
        assert [p["file_visibili"] for p in phases] == [4, 0, 4, 0]
        assert [p["byte_visibili"] for p in phases] == [result["byte"], 0, result["byte"], 0]
        assert result["verifica_migrazione"] == {"file_prima": 4, "byte_prima": result["byte"],
                                                 "file_dopo": 4, "byte_dopo": result["byte"], "verificato": True}
        for p, expected in zip(phases, (True, False, True, False)):
            shell = next(r for r in p["prove"] if r["attore"] == "shell")
            assert shell["misurato"] is True and shell["riuscito"] is expected
            assert shell["errno"] == (None if expected else errno.ENOENT)
            assert shell["byte"] == (result["inventario"]["LEGGIMI-SINTETICO.txt"]["byte"] if expected else None)
            assert shell["pid"] > 0 and shell["uid"] == os.getuid()
            assert all(r["riscontri_kernel"] == [] and r["agente"] is None for r in p["prove"])
            assert all(not r["misurato"] and r["riuscito"] is None and r["errno"] is None
                       for r in p["prove"] if r["attore"] in ("codex", "claude"))
            assert p["ok"] is False
        assert not list(e.source.iterdir()) and not integration.configured["disks"].montati
        assert len(e.acknowledgements) == 2 and e.acknowledgements[0].startswith("banco-")
        assert e.acknowledgements[1] == result["cartella_id"]
        assert e.registry.leggi_sorveglianza(e.state / "registro" / "sorveglianza.json", os.getuid()) == []
        summary = s.summarize(e, response, KEY)
        assert summary["catena_locale_integra"] and summary["chiave_assente_da_metadati_argv_env"]
        assert summary["flusso_banco_temporaneo_verificato"] is True
        assert summary["immagini_disco"] == "simulate" and summary["mdls"] == "simulato"
        assert summary["hdiutil_aes256_apfs_richiesti"] and not any(p["riscontri_kernel"] for p in summary["fasi"])
        assert {"sh", "mdls", "hdiutil", "ditto"}.issubset({c["programma"] for c in e.calls})
        for argv, key in integration.configured["disks"].chiamate:
            assert KEY.decode() not in " ".join(argv)
            if key is not None:
                assert argv[0] == "/usr/bin/hdiutil" and "-stdinpass" in argv
        history = e.bank.storico()
        assert history["prove"][0]["id"] == result["id"] and len(history["fasi"]) == 4
        events = [json.loads(line) for line in e.registry.CATENA.read_text().splitlines()]
        assert len([r for r in events if r["evento"] == "banco-accesso"]) == 16
        assert all(r["source"] == "paratia" for r in events)
    assert e.cleanup == {"volumi_chiusi": True, "timer_terminati": True}
    assert Path.home() == home_before and os.environ.get("PARATIA_HOME") == env_before


def test_ipc_failure_after_real_reopen_closes_fixture_and_keeps_safe_history(integration):
    s = integration.script
    with s.fixture(integration.base, KEY, integration.configure, integration.mdls) as e:
        original = e.bank._probe

        def probe(actor, target, phase, *args):
            if phase == "riaperta":
                assert e.folders._montato(e.source)
                raise OSError(errno.EIO, KEY.decode())
            return original(actor, target, phase, *args)

        e.bank._probe = probe
        response = s.request(e, run_payload(e, s))
        assert response["ok"] is False and response["code"] == "io_error"
        assert KEY.decode() not in json.dumps(response)
        history = e.bank.storico()
        assert history["stato"] == "incompleto" and history["tipo_errore"] == "OSError"
        assert history["stato_finale"] == "chiusa" and not list(e.source.iterdir())
        assert not integration.configured["disks"].montati
        assert s.summarize(e, response, KEY)["catena_locale_integra"]
    assert e.cleanup == {"volumi_chiusi": True, "timer_terminati": True}


def test_worker_discards_backend_raw_output_through_the_actual_ipc_path(integration, capfd):
    s = integration.script
    with s.fixture(integration.base, KEY, integration.configure, integration.mdls) as e:
        original = e.folders._corri

        def noisy_command(argv, passphrase=None):
            print(KEY.decode())
            os.write(2, KEY)
            return original(argv, passphrase)

        e.folders._corri = noisy_command
        response = s.request(e, run_payload(e, s))
        assert response["ok"] is True
        captured = capfd.readouterr()
        assert KEY.decode() not in captured.out + captured.err + json.dumps(response)
        assert s.summarize(e, response, KEY)["chiave_assente_da_metadati_argv_env"]


def test_cleanup_does_not_claim_closed_when_fake_disk_refuses_detach(integration):
    s = integration.script

    def failing_disks(folders):
        integration.configure(folders)
        original = folders._corri

        def refuse_detach(argv, passphrase=None):
            if argv[0] == folders.HDIUTIL and argv[1] == "detach":
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            return original(argv, passphrase)

        folders._corri = refuse_detach

    with s.fixture(integration.base, KEY, failing_disks, integration.mdls) as e:
        response = s.request(e, run_payload(e, s))
        assert response["ok"] is False and integration.configured["disks"].montati
    assert e.cleanup["volumi_chiusi"] is False and e.cleanup["timer_terminati"] is True


@pytest.mark.parametrize("closed", [True, False])
def test_native_parent_removes_only_a_fixture_with_confirmed_cleanup(tmp_path, monkeypatch, closed, capsys):
    s = load("banco_e2e_parent_test", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    spawned = []
    monkeypatch.setattr(s.sys, "platform", "darwin")
    monkeypatch.setattr(s.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(KEY)))

    class Child:
        returncode = 0

        def communicate(self, input):
            params, key = s._load("e2e_parent_frame", ROOT / "gui_worker.py").read_frame(io.BytesIO(input))
            assert key == KEY and params["agenti_reali"] is False
            return json.dumps({"ipc_ok": True, "flusso_banco_temporaneo_verificato": True,
                               "cleanup": {"volumi_chiusi": closed, "timer_terminati": True}}).encode(), b""

        def poll(self):
            return 0

    def spawn(argv, **kwargs):
        assert KEY.decode() not in " ".join(argv) and "env" not in kwargs
        spawned.append(Path(argv[-1]))
        return Child()

    monkeypatch.setattr(s.subprocess, "Popen", spawn)
    # No actual hdiutil or child is invoked, including on non-macOS hosts.
    real_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p) in ("/usr/bin/hdiutil", "/usr/bin/ditto", "/usr/bin/mdls") else real_is_file(p))
    try:
        assert s.main([]) == (0 if closed else 1)
        report = json.loads(capsys.readouterr().out)
        assert bool(report.get("cartella_temporanea_eliminata")) is closed
        assert spawned[0].exists() is (not closed)
        assert KEY.decode() not in json.dumps(report)
    finally:
        for p in spawned:
            if p.exists():
                shutil.rmtree(p)


def test_native_entry_refuses_invalid_fixture_key_before_temporary_or_child(monkeypatch, capsys):
    s = load("banco_e2e_invalid_key_test", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    monkeypatch.setattr(s.sys, "platform", "darwin")
    monkeypatch.setattr(s.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"short")))
    monkeypatch.setattr(Path, "is_file", lambda p: True)
    monkeypatch.setattr(s.tempfile, "mkdtemp", lambda *a, **k: pytest.fail("Temporary root created before key validation"))
    monkeypatch.setattr(s.subprocess, "Popen", lambda *a, **k: pytest.fail("Child started before key validation"))
    assert s.main([]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["eseguito"] is False and "short" not in json.dumps(report)


def test_native_guard_tracks_only_the_exact_isolated_folder_timer(monkeypatch):
    s = load("banco_e2e_timer_guard_test", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    spawned, timers, calls = [], [], []

    def spawn(argv, **kwargs):
        process = object()
        spawned.append(process)
        return process

    monkeypatch.setattr(s.subprocess, "Popen", spawn)
    guard = s.SubprocessGuard(KEY, calls, timers)
    guard.Popen([sys.executable, "-I", "-S", "-B", str(ROOT / "cartelle.py"), "timer", "a" * 32, "b" * 32, "60"])
    guard.Popen([sys.executable, "-I", "-S", "-B", "/fixture/different.py", "timer", "a" * 32, "b" * 32, "60"])
    guard.Popen(["/bin/sh", "-c", "true"])
    assert timers == [spawned[0]] and len(calls) == 3


def test_parent_interruption_collects_child_cleanup_before_deleting(monkeypatch, capsys):
    s = load("banco_e2e_cancel_parent_test", ROOT / "strumenti" / "prova-banco-temporaneo.py")
    paths = []
    monkeypatch.setattr(s.sys, "platform", "darwin")
    monkeypatch.setattr(s.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(KEY)))
    real_is_file = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p) in ("/usr/bin/hdiutil", "/usr/bin/ditto", "/usr/bin/mdls") else real_is_file(p))

    class Child:
        count = 0
        terminated = False

        def communicate(self, **kwargs):
            self.count += 1
            if self.count == 1:
                raise KeyboardInterrupt
            assert self.terminated and kwargs["timeout"] == 30
            return json.dumps({"ipc_ok": False, "cleanup": {"volumi_chiusi": True, "timer_terminati": True}}).encode(), b""

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

    child = Child()

    def spawn(argv, **kwargs):
        paths.append(Path(argv[-1]))
        return child

    monkeypatch.setattr(s.subprocess, "Popen", spawn)
    try:
        assert s.main([]) == 1
        report = json.loads(capsys.readouterr().out)
        assert report["errore_fixture"] == "KeyboardInterrupt" and report["cartella_temporanea_eliminata"] is True
        assert child.terminated and not paths[0].exists()
    finally:
        for path in paths:
            if path.exists():
                shutil.rmtree(path)
