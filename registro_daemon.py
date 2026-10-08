#!/usr/bin/python3
"""Privileged eslogger adapter. Prepared here; installed only with human consent."""
from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import pwd
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

SUPPORT = Path("/Library/Application Support/Paratia")
LOGS = Path("/Library/Logs/Paratia")
MAX_RIGA = 1048576


def codice_affidabile(directory):
    for p in [directory, *directory.parents]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Il percorso del demone deve appartenere a root e non essere scrivibile da altri.")
    for nome in ("registro_daemon.py", "registro.py", "catena.py"):
        s = (directory / nome).lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Il codice del demone non è protetto da root.")


def scrivi_stato(p, dati):
    fd = os.open(p, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "wb") as f:
        fcntl.flock(fd, fcntl.LOCK_EX)
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0:
            raise ValueError("Il file di stato non è protetto da root.")
        f.write(json.dumps({**dati, "heartbeat": time.time()}, sort_keys=True).encode())
        f.flush()
        f.truncate()
        os.fsync(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Registro kernel Paratia, solo metadati.")
    parser.add_argument("--uid", type=int, required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("Il demone richiede l'installazione autorizzata dalla GUI.", file=sys.stderr)
        return 2
    if args.uid <= 0:
        raise ValueError("Il registro richiede un utente umano distinto da root.")
    utente = pwd.getpwuid(args.uid)
    if Path(__file__).resolve().parent != SUPPORT:
        raise ValueError("Il demone deve partire dalla copia installata e protetta.")
    codice_affidabile(SUPPORT)
    # launchd uses the installer-verified canonical CLT executable, never the
    # /usr/bin launcher that may resolve through an admin-writable Xcode parent.
    codice_affidabile_runtime = [Path(sys.executable).resolve(), Path(sys.prefix).resolve()]
    for p in codice_affidabile_runtime:
        for q in [p, *p.parents]:
            s = q.lstat()
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise ValueError("Il runtime del demone non è protetto da root.")
    spec = importlib.util.spec_from_file_location("registro_root", SUPPORT / "registro.py")
    R = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(R)
    # Code directories are installer-owned; POSIX mode alone does not exclude
    # an inherited ACL permitting someone else to alter a sibling module.
    for p in [SUPPORT, *SUPPORT.parents, *(SUPPORT / n for n in ("registro_daemon.py", "registro.py", "catena.py"))]:
        if R.acl_scrivibile(p):
            raise ValueError("Le ACL del codice del demone consentono modifiche.")
    directory = LOGS / str(args.uid)
    # The installer creates files and grants only this user's read ACL.
    for p in (LOGS, directory):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Il percorso del registro non è protetto da root.")
    catena, stato = directory / "catena.jsonl", directory / "stato.json"
    for p in (catena, stato):
        s = p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077:
            raise ValueError("Un file del registro ha autorizzazioni POSIX non valide.")
    config = Path(utente.pw_dir) / ".paratia" / "cartelle.json"
    sorveglianza = Path(utente.pw_dir) / ".paratia" / "registro" / "sorveglianza.json"
    def protetti():
        return R.leggi_cartelle(config, args.uid) + R.leggi_sorveglianza(sorveglianza, args.uid)
    sink = R.ScrittoreDiagnostici(lambda record: R.appendi(catena, record))
    osservatore = R.Osservatore(protetti(), sink, R.snapshot_processi())
    sink(R._diagnostico("osservatore-avviato", uid=args.uid))
    informazioni = {"running": False, "healthy": False, "needs_fda": False,
                    "message": "Avvio del registro kernel in corso.", "dropped_events": 0,
                    "drop_detection_available": False, "watched_ids": [v["id"] for v in osservatore.protetti],
                    "schema_supported": None, "diagnostic_counts": {}}
    scrivi_stato(stato, informazioni)
    processo = subprocess.Popen(["/usr/bin/eslogger", *R.EVENTI], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    fermati = [False]
    for numero in (signal.SIGTERM, signal.SIGINT):
        signal.signal(numero, lambda *_: fermati.__setitem__(0, True))
    buffer, errori, scarta = b"", b"", False
    ultimo_stato, ultimo_config, visto = 0.0, 0.0, False
    fdout, fderr = processo.stdout.fileno(), processo.stderr.fileno()
    aperti = {fdout, fderr}
    try:
        while not fermati[0]:
            ora = time.monotonic()
            if ora - ultimo_config >= 5:
                try:
                    osservatore.protetti = protetti()
                    informazioni["watched_ids"] = [v["id"] for v in osservatore.protetti]
                except (OSError, ValueError):
                    osservatore.sano = False
                    sink(R._diagnostico("registro-cartelle-illeggibile"))
                    # Keep last valid paths; never silently broaden to all files.
                ultimo_config = ora
            leggibili, _, _ = select.select(list(aperti), [], [], 1)
            for fd in leggibili:
                pezzo = os.read(fd, 65536)
                if not pezzo:
                    aperti.discard(fd)
                    continue
                if fd == fderr:
                    errori = (errori + pezzo)[-65536:]
                    continue
                for parte in pezzo.splitlines(keepends=True):
                    termina = parte.endswith(b"\n")
                    if not scarta:
                        buffer += parte
                        if len(buffer) > MAX_RIGA:
                            buffer, scarta = b"", True
                            osservatore.sano = False
                            sink(R._diagnostico("riga-eslogger-troppo-grande"))
                    if termina:
                        if not scarta:
                            try:
                                msg = json.loads(buffer)
                                osservatore.ricevi(msg)
                                visto = True
                            except (ValueError, TypeError):
                                osservatore.sano = False
                                sink(R._diagnostico("json-eslogger-non-valido"))
                        buffer, scarta = b"", False
            if osservatore.schema_fatale:
                break
            if ora - ultimo_stato >= 5:
                informazioni.update(running=processo.poll() is None and visto,
                                     healthy=osservatore.sano and visto,
                                     dropped_events=osservatore.persi,
                                     drop_detection_available=osservatore.rileva_perdite,
                                     schema_supported=not osservatore.schema_fatale if visto else None,
                                     diagnostic_counts={k: max(sink.contatori.get(k, 0), osservatore.diagnostici.get(k, 0))
                                                        for k in set(sink.contatori) | set(osservatore.diagnostici)},
                                     message="Registro attivo." if osservatore.sano and visto else "Registro in avvio o con copertura incompleta: consulta i diagnostici.")
                scrivi_stato(stato, informazioni)
                ultimo_stato = ora
            if processo.poll() is not None and not aperti:
                break
    finally:
        if processo.poll() is None:
            processo.terminate()
            try:
                processo.wait(timeout=5)
            except subprocess.TimeoutExpired:
                processo.kill()
                processo.wait(timeout=5)
        else:
            processo.wait()
        if buffer:
            sink(R._diagnostico("riga-eslogger-incompleta"))
        # Retain only the permission category, never the stderr text itself.
        bisogno = any(x in errori.lower() for x in (b"tcc", b"full disk access", b"not permitted", b"not_permitted"))
        informazioni.update(running=False, healthy=False, needs_fda=bisogno,
                             schema_supported=not osservatore.schema_fatale if visto else None,
                             diagnostic_counts={k: max(sink.contatori.get(k, 0), osservatore.diagnostici.get(k, 0))
                                                for k in set(sink.contatori) | set(osservatore.diagnostici)},
                             message="Autorizza /usr/bin/eslogger in Accesso completo al disco." if bisogno else (
                                 "Il formato di eslogger non è compatibile: aggiorna Paratia." if osservatore.schema_fatale else "Il registro kernel è fermo."))
        scrivi_stato(stato, informazioni)
        sink(R._diagnostico("osservatore-fermato", rc=processo.returncode, needs_fda=bisogno))
    return 0 if fermati[0] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        # Do not emit user data or raw event objects in crash reports.
        print("Registro non avviato (%s)." % type(e).__name__, file=sys.stderr)
        raise SystemExit(1)
