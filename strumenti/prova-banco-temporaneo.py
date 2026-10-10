#!/usr/bin/env python3
"""Disposable bank IPC integration check, never the operator's Desktop.

The native entry point reads a *fixture* passphrase from stdin and uses real
hdiutil/ditto/APFS on internal temporary storage. Kernel health/acknowledgement
are explicitly simulated, no kernel evidence is fabricated, and vendor CLIs
are disabled. pytest injects fake images into this same IPC/workflow fixture.
Nothing here is a production action or a permission/authentication workaround.
"""
from __future__ import annotations

import argparse
import contextlib
import errno
import importlib.util
import io
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MARKER = "paratia-banco-temporaneo-v1"


def _temporary_root():
    """Honor an explicit TMPDIR even if tempfile's default was already cached."""
    root = Path(os.environ.get("TMPDIR") or tempfile.gettempdir())
    if not root.is_absolute():
        raise ValueError("TMPDIR deve essere un percorso assoluto.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("TMPDIR deve essere una cartella esistente.")
    return root


def new_fixture():
    base = Path(tempfile.mkdtemp(prefix="paratia-banco-e2e-", dir=str(_temporary_root()))).resolve()
    (base / ".fixture").write_text(MARKER)
    return base


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def frame(params, key):
    metadata = json.dumps(params, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(metadata)) + metadata + struct.pack(">I", len(key)) + key


class SubprocessGuard:
    """Check transport without keeping stdin, environment, or the passphrase."""

    def __init__(self, key, calls, timers):
        self.key, self.calls, self.timers = key, calls, timers

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def check(self, argv, env=None):
        values = [os.fspath(value) for value in argv]
        key_text = self.key.decode("utf-8")
        if any(key_text in value for value in values):
            raise AssertionError("La chiave della fixture è negli argomenti")
        if any(key_text in str(value) for value in (os.environ if env is None else env).values()):
            raise AssertionError("La chiave della fixture è nell'ambiente")
        self.calls.append({"programma": Path(values[0]).name, "azione": values[1] if len(values) > 1 else None,
                           "stdinpass": "-stdinpass" in values,
                           "aes256": "AES-256" in values, "apfs": "APFS" in values})

    def run(self, argv, **kwargs):
        self.check(argv, kwargs.get("env"))
        data = kwargs.get("input")
        if isinstance(data, bytes) and self.key in data:
            if os.fspath(argv[0]) != "/usr/bin/hdiutil" or "-stdinpass" not in argv or data != self.key + b"\0":
                raise AssertionError("Trasporto della chiave inatteso")
        return subprocess.run(argv, **kwargs)

    def Popen(self, argv, **kwargs):
        self.check(argv, kwargs.get("env"))
        process = subprocess.Popen(argv, **kwargs)
        if (len(argv) == 9 and list(argv[1:4]) == ["-I", "-S", "-B"]
                and os.fspath(argv[4]) == str(ROOT / "cartelle.py") and argv[5] == "timer"):
            self.timers.append(process)
        return process


@contextlib.contextmanager
def fixture(base, key, configure_disks=None, mock_mdls=None):
    """Confine runtime overrides to one newly created, owned temporary root."""
    if Path(base).is_symlink():
        raise ValueError("La fixture rifiuta una radice con collegamento simbolico.")
    base = Path(base).resolve(strict=True)
    if base.parent != _temporary_root() or not base.name.startswith("paratia-banco-e2e-"):
        raise ValueError("La fixture richiede una nuova cartella paratia-banco-e2e-… sotto TMPDIR.")
    if base.stat().st_uid != os.getuid() or (base / ".fixture").read_text() != MARKER:
        raise ValueError("La cartella non appartiene a questa fixture")
    home, state, disk = base / "home", base / "state", base / "temporary-disk"
    source = home / "Desktop" / "folder-test"
    source.mkdir(parents=True, exist_ok=True)
    disk.mkdir(exist_ok=True)
    calls, timers, acknowledgements = [], [], []
    cleanup = {"volumi_chiusi": False, "timer_terminati": False}
    with patch.dict(os.environ, {"PARATIA_HOME": str(state)}), patch.object(Path, "home", classmethod(lambda cls: home)):
        worker = _load("banco_e2e_worker", ROOT / "gui_worker.py")
        bank = _load("banco_e2e_backend", ROOT / "banco.py")
        folders, registry = bank.C, bank.R
        # Both local rows and the kernel source stay inside the fixture. Query
        # is the real implementation, so Python 3.9 date parsing is exercised.
        registry.SYSTEM = base / "kernel-fixture"

        def only_fixture_external(path):
            if Path(path) != disk:
                raise folders.Rifiuto("Il test accetta soltanto il proprio disco temporaneo")

        folders._esterno = only_fixture_external
        if configure_disks is not None:
            configure_disks(folders)
        guard = SubprocessGuard(key, calls, timers)
        folders.subprocess = guard
        bank.subprocess = guard
        original_disk_command = folders._corri

        def disk_command(argv, passphrase=None):
            guard.check(argv)
            if passphrase is not None and (argv[0] != folders.HDIUTIL or "-stdinpass" not in argv):
                raise AssertionError("La chiave è destinata soltanto a hdiutil stdinpass")
            return original_disk_command(argv, passphrase)

        folders._corri = disk_command
        bank._cli = lambda _: (_ for _ in ()).throw(AssertionError("CLI vendor non consentita nella fixture"))
        # No daemon exists in this fixture. Polling an empty simulated source
        # needs no wall-clock delay; the matching code itself remains unchanged.
        bank.time = SimpleNamespace(monotonic=bank.time.monotonic, sleep=lambda _: None)

        def simulated_status():
            watched = registry.leggi_sorveglianza(state / "registro" / "sorveglianza.json", os.getuid())
            identifiers = [entry["id"] for entry in watched] + [entry["id"] for entry in folders.elenco()]
            acknowledgements.extend(identifier for identifier in identifiers if identifier not in acknowledgements)
            return {"running": True, "healthy": True, "local_chain_ok": True, "watched_ids": identifiers,
                    "fixture": "Registro simulato; nessuna raccolta kernel"}

        registry.stato = simulated_status
        bank.R = SimpleNamespace(stato=simulated_status, query=registry.query,
                                 sorveglia=registry.sorveglia, rimuovi_sorveglianza=registry.rimuovi_sorveglianza,
                                 annota=registry.annota)
        if mock_mdls is not None:
            original_command = bank._comando

            def command(argv, *args, **kwargs):
                if argv[0] == "/usr/bin/mdls":
                    guard.check(argv)
                    return mock_mdls(argv)
                return original_command(argv, *args, **kwargs)

            bank._comando = command
        worker._MODULES["banco"] = bank
        worker._MODULES["cartelle"] = folders
        result = SimpleNamespace(worker=worker, bank=bank, folders=folders, registry=registry,
                                 home=home, state=state, disk=disk, source=source, calls=calls,
                                 timers=timers, acknowledgements=acknowledgements, cleanup=cleanup,
                                 disk_mode="native" if configure_disks is None else "simulate",
                                 mdls_mode="nativo" if mock_mdls is None else "simulato")
        try:
            yield result
        finally:
            # Only entries of this private fixture can be closed. Never delete
            # a temporary root unless all possible mounts have been checked.
            closed = True
            try:
                entries = folders.elenco()
                for entry in entries:
                    for name in ("montaggio", "montaggio_temporaneo"):
                        if entry.get(name) and base not in Path(entry[name]).parents:
                            raise AssertionError("Un montaggio esce dalla fixture")
                    try:
                        folders.chiudi(entry["id"])
                    except Exception:
                        closed = False
                for entry in folders.elenco():
                    for name in ("montaggio", "montaggio_temporaneo"):
                        if entry.get(name) and folders._montato(Path(entry[name])):
                            closed = False
            except BaseException:
                closed = False
            cleanup["volumi_chiusi"] = closed
            stopped = True
            for timer in timers:
                try:
                    if timer.poll() is None:
                        timer.terminate()
                    timer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    timer.kill()
                    timer.wait(timeout=5)
                except BaseException:
                    stopped = False
            cleanup["timer_terminati"] = stopped and all(timer.poll() is not None for timer in timers)
            guard.key = b""


def request(environment, payload):
    output = io.StringIO()
    environment.worker.main(["worker", "banco.run"], io.BytesIO(payload), output)
    return json.loads(output.getvalue())


def summarize(environment, response, key):
    if key in json.dumps(response, ensure_ascii=False).encode("utf-8"):
        raise AssertionError("La chiave è nella risposta IPC")
    for p in environment.state.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl") and key in p.read_bytes():
            raise AssertionError("La chiave è nei metadati persistiti")
    value = response.get("result", {})
    phases = []
    for phase in value.get("fasi", []):
        shell = next((r for r in phase["prove"] if r["attore"] == "shell"), {})
        mdls = next((r for r in phase["prove"] if r["attore"] == "mdls"), {})
        phases.append({"nome": phase["nome"], "file_visibili": phase["file_visibili"],
                       "byte_visibili": phase["byte_visibili"], "shell_misurato": shell.get("misurato"),
                       "shell_riuscito": shell.get("riuscito"), "shell_errno": shell.get("errno"),
                       "mdls_misurato": mdls.get("misurato"), "mdls_rc": mdls.get("rc"),
                       "riscontri_kernel": sum(len(r["riscontri_kernel"]) for r in phase["prove"]),
                       "agenti_misurati": any(r["misurato"] for r in phase["prove"] if r["attore"] in ("codex", "claude"))})
    local = environment.registry.verifica_catena(environment.registry.CATENA)
    migration = value.get("verifica_migrazione", {})
    workflow_ok = (response.get("ok") is True and value.get("stato") == "incompleto"
                   and value.get("stato_finale") == "chiusa" and value.get("file") == 4
                   and [p["nome"] for p in phases] == ["prima", "chiusa", "riaperta", "richiusa"]
                   and migration.get("verificato") is True
                   and migration.get("file_prima") == migration.get("file_dopo") == 4
                   and migration.get("byte_prima") == migration.get("byte_dopo") == value.get("byte"))
    if workflow_ok:
        for phase, opened in zip(phases, (True, False, True, False)):
            workflow_ok = workflow_ok and (phase["shell_misurato"] is True and phase["shell_riuscito"] is opened
                                           and phase["shell_errno"] == (None if opened else errno.ENOENT)
                                           and not phase["agenti_misurati"] and phase["riscontri_kernel"] == 0
                                           and (phase["file_visibili"] >= 4 if opened else phase["file_visibili"] == 0))
    return {"prova": "Banco temporaneo tramite IPC, dati sintetici", "ipc_ok": response.get("ok", False),
            "errore_ipc": response.get("code"), "registro": "simulato, nessuna prova di copertura kernel",
            "immagini_disco": environment.disk_mode, "mdls": environment.mdls_mode,
            "cli_vendor": "disabilitate", "modelli_invocati": False, "stato": value.get("stato"),
            "stato_finale": value.get("stato_finale"), "file": value.get("file"), "byte": value.get("byte"),
            "verifica_migrazione": value.get("verifica_migrazione"), "fasi": phases,
            "catena_locale_integra": local["ok"], "chiave_assente_da_metadati_argv_env": True,
            "flusso_banco_temporaneo_verificato": bool(workflow_ok and local["ok"]),
            "hdiutil_aes256_apfs_richiesti": any(r["aes256"] and r["apfs"] and r["stdinpass"] for r in environment.calls),
            "cleanup": environment.cleanup}


def _worker(base):
    def interrupted(signum, stack):
        # Parent cancellation must pass through worker and fixture cleanup.
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    raw = sys.stdin.buffer.read(1024 * 1024 + 4096 + 9)
    reader = _load("banco_e2e_frame_reader", ROOT / "gui_worker.py")
    key = b""
    report = {"ipc_ok": False, "cleanup": {"volumi_chiusi": False, "timer_terminati": False}}
    try:
        params, key = reader.read_frame(io.BytesIO(raw))
        expected = {"dove": str(Path(base) / "temporary-disk"), "minutes": 1, "agenti_reali": False}
        if params != expected:
            raise ValueError("La fixture accetta soltanto la propria richiesta banco")
        with fixture(base, key) as environment:
            response = request(environment, raw)
            report = summarize(environment, response, key)
    except BaseException as error:
        report["errore_fixture"] = type(error).__name__
    finally:
        key, raw = b"", b""
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("flusso_banco_temporaneo_verificato") and all(report["cleanup"].values()) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", metavar="TEMP_ROOT", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        return _worker(args.worker)
    if sys.platform != "darwin" or not all(Path(p).is_file() for p in ("/usr/bin/hdiutil", "/usr/bin/ditto", "/usr/bin/mdls")):
        print(json.dumps({"eseguito": False, "errore": "Il controllo nativo richiede macOS e gli strumenti Apple"}))
        return 2
    key = sys.stdin.buffer.read(4097)
    if not 12 <= len(key) <= 4096 or any(c in key for c in (b"\n", b"\r", b"\0")):
        print(json.dumps({"eseguito": False, "errore": "Invia una chiave fittizia valida solo tramite stdin, senza newline"}))
        return 2
    try:
        key_text = key.decode("utf-8")
    except UnicodeError:
        print(json.dumps({"eseguito": False, "errore": "La chiave fittizia deve essere UTF-8"}))
        return 2
    if any(key_text in value for value in os.environ.values()):
        print(json.dumps({"eseguito": False, "errore": "La chiave fittizia è già presente nell'ambiente"}))
        return 2
    base = new_fixture()
    payload = frame({"dove": str(base / "temporary-disk"), "minutes": 1, "agenti_reali": False}, key)
    process = None
    report = {"ipc_ok": False, "cleanup": {"volumi_chiusi": False, "timer_terminati": False}}
    try:
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker", str(base)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output, _ = process.communicate(input=payload)
        if len(output) > 1024 * 1024 or key in output:
            raise ValueError("Risposta della fixture non valida")
        report = json.loads(output)
    except BaseException as error:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=30)
                if len(output) <= 1024 * 1024 and key not in output:
                    report = json.loads(output)
            except (OSError, ValueError, subprocess.SubprocessError):
                # Preserve the fixture if closure cannot be established. A
                # second force-kill could interrupt the only cleanup process.
                if process.poll() is None:
                    report["worker_ancora_attivo"] = process.pid
        report["errore_fixture"] = type(error).__name__
    finally:
        key, payload = b"", b""
        if all(report.get("cleanup", {}).get(k) is True for k in ("volumi_chiusi", "timer_terminati")):
            shutil.rmtree(base)
            report["cartella_temporanea_eliminata"] = True
        else:
            report["cartella_temporanea_conservata"] = str(base)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("flusso_banco_temporaneo_verificato") and report.get("cartella_temporanea_eliminata") and not report.get("errore_fixture") else 1


if __name__ == "__main__":
    raise SystemExit(main())
