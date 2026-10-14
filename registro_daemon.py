#!/usr/bin/python3
"""Privileged eslogger adapter. Prepared here; installed only with human consent."""
from __future__ import annotations

import argparse
import datetime
import fcntl
import importlib.util
import json
import os
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

SUPPORT = Path("/Library/Application Support/Paratia")
LOGS = Path("/Library/Logs/Paratia")
MAX_RIGA = 1048576
FDA_APP = "/Applications/Paratia.app"
CAMPI_RADICI = ("origine", "bundle", "montaggio", "recupero_temporaneo",
                "montaggio_temporaneo", "backup", "plaintext_residuo")
# Metadata extraction is conservative: unfamiliar/duplicate/escaped headers go
# through the full parser, rather than introducing gaps in loss detection.
_HEADER = re.compile(br'"(schema_version|event_type|global_seq_num|seq_num|time)"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)')
_UNICODE = re.compile(br'\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}')
_ORA_EVENTO = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2})(?:[.,]([0-9]{1,9}))?(Z|z|[+-][0-9]{2}(?::?[0-9]{2})?)")
_FILE_TYPES = (10, 12, 13, 20, 22, 23, 25, 32, 33, 41, 43,
               *("ES_EVENT_TYPE_NOTIFY_" + n for n in ("OPEN", "CLOSE", "CREATE", "MMAP", "MOUNT", "UNMOUNT", "RENAME", "UNLINK", "WRITE", "TRUNCATE", "LOOKUP")))
sys.dont_write_bytecode = True


def _varianti_radice(radice):
    normale = os.path.normpath(radice)
    if normale.startswith("/System/Volumes/Data/"):
        normale = normale[len("/System/Volumes/Data"):]
    if normale in ("/tmp", "/var", "/etc") or any(normale.startswith(p + "/") for p in ("/tmp", "/var", "/etc")):
        normale = "/private" + normale
    varianti = {normale, "/System/Volumes/Data" + normale}
    if normale.startswith(("/private/tmp/", "/private/var/", "/private/etc/")) or normale in ("/private/tmp", "/private/var", "/private/etc"):
        varianti.add(normale[len("/private"):])
    return varianti


def _metadati_grezzi(riga):
    dati = {}
    for m in _HEADER.finditer(riga):
        if m.start() and riga[m.start() - 1] == 92:
            continue  # A quoted key inside a JSON string is not a header.
        chiave = m[1].decode("ascii")
        if chiave in dati:
            return None
        valore = m[2]
        if chiave in ("seq_num", "global_seq_num", "schema_version"):
            if not valore.isdigit() or len(valore) > 20:
                return None
            dati[chiave] = int(valore)
        elif chiave == "event_type":
            if valore.isdigit() and len(valore) <= 20:
                dati[chiave] = int(valore)
            elif valore.startswith(b'"ES_EVENT_TYPE_NOTIFY_') and valore.endswith(b'"') and b"\\" not in valore:
                dati[chiave] = valore[1:-1].decode("ascii", "replace")
            else:
                return None
        elif b"\\" not in valore and valore.startswith(b'"'):
            dati[chiave] = valore[1:-1].decode("ascii", "replace")
        else:
            return None
    if dati.get("schema_version") != 1 or "event_type" not in dati or not ({"seq_num", "global_seq_num"} & dati.keys()):
        return None
    return dati


def _unicode_utf8(m):
    try:
        primo = int(m[0][2:6], 16)
        punto = (0x10000 + ((primo - 0xD800) << 10) + int(m[0][8:12], 16) - 0xDC00) if len(m[0]) == 12 else primo
        return chr(punto).encode("utf8")
    except (ValueError, UnicodeError):
        return m[0]  # The enclosing record will use the full parser on uncertainty.


def _timestamp_evento(value):
    """Accept native ISO nanoseconds/compact offsets on the installed Python 3.9.

    datetime 3.9 accepts only 3/6 fraction digits and colon-delimited offsets.
    Truncate fractions to microseconds; reported lag is rounded to milliseconds.
    A timezone is required: local-wall timestamps cannot establish event lag.
    """
    match = _ORA_EVENTO.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    base, frazione, zona = match.groups()
    base = base.replace("t", "T")
    if frazione:
        base += "." + frazione[:6].ljust(6, "0")
    if zona in ("Z", "z"):
        zona = "+00:00"
    elif len(zona) == 5:
        zona = zona[:3] + ":" + zona[3:]
    elif len(zona) == 3:
        zona += ":00"
    try:
        return datetime.datetime.fromisoformat(base + zona).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


class FlussoEslogger:
    """Filter unrelated raw lines before decoding, while retaining sequence health.

    False positives cost decoding; uncertain encodings/header shapes also decode.
    No event payload, argument, environment, or file contents survive this helper.
    """
    def __init__(self, osservatore, monotonic=time.monotonic, wall_time=time.time):
        self.osservatore = osservatore
        self.monotonic, self.wall_time = monotonic, wall_time
        self.inizio = self.ultimo_campione = monotonic()
        self.contatore_campione = 0
        self.raw_lines = self.filtered_lines = self.parsed_lines = 0
        self.lines_per_second = 0.0
        self.last_event_received_at = None
        self.last_event_time = None
        self.ricompila_radici()

    def ricompila_radici(self):
        radici = set()
        self.codifica_incerta = False
        for voce in self.osservatore.protetti:
            for campo in CAMPI_RADICI:
                p = voce.get(campo)
                if not isinstance(p, str) or not os.path.isabs(p):
                    continue
                self.codifica_incerta |= any(c in p for c in ('"', "\\"))
                for variante in _varianti_radice(p):
                    # create/rename split a newly created watched directory into
                    # its parent and filename. Retain its parent as a candidate.
                    for candidato in (variante, os.path.dirname(variante)):
                        if candidato and candidato != "/":
                            for forma in ("NFC", "NFD"):
                                radici.add(unicodedata.normalize(forma, candidato).encode("utf8"))
        self.radici = tuple(sorted(radici, key=len, reverse=True))

    def _pertinente(self, riga):
        if self.codifica_incerta or any(p in riga for p in self.radici):
            return True
        if b"\\u" in riga or b"\\/" in riga:
            decodificata = _UNICODE.sub(_unicode_utf8, riga).replace(b"\\/", b"/")
            if b"\\u" in decodificata:
                return True
            if any(p in decodificata for p in self.radici):
                return True
            riga = decodificata
        # A filename can mix composed and decomposed characters within a single
        # component. NFC/NFD needles alone would miss that valid spelling.
        if not riga.isascii():
            try:
                canonica = unicodedata.normalize("NFC", riga.decode("utf8")).encode("utf8")
            except UnicodeError:
                return True
            return any(p in canonica for p in self.radici)
        return False

    def ricevi(self, riga):
        self.raw_lines += 1
        metadati = None
        if not self._pertinente(riga):
            metadati = _metadati_grezzi(riga)
        tipo = metadati.get("event_type") if metadati else None
        if metadati is not None and tipo in _FILE_TYPES:
            self.filtered_lines += 1
            self.osservatore.scarta(metadati)
            msg = metadati
        else:
            self.parsed_lines += 1
            msg = json.loads(riga)
            self.osservatore.ricevi(msg)
        self.last_event_received_at = self.wall_time()
        self.last_event_time = msg.get("time") if isinstance(msg, dict) and isinstance(msg.get("time"), str) else None
        return msg

    def metriche(self):
        ora, mono = self.wall_time(), self.monotonic()
        intervallo = mono - self.ultimo_campione
        if intervallo > 0:
            self.lines_per_second = (self.raw_lines - self.contatore_campione) / intervallo
            self.contatore_campione, self.ultimo_campione = self.raw_lines, mono
        lag = None
        if self.last_event_received_at is not None and self.last_event_time:
            data = _timestamp_evento(self.last_event_time)
            if data is not None:
                lag = max(0.0, self.last_event_received_at - data)
        return {"raw_lines": self.raw_lines, "filtered_lines": self.filtered_lines,
                "parsed_lines": self.parsed_lines, "lines_per_second": round(self.lines_per_second, 2),
                "last_event_received_at": self.last_event_received_at,
                "last_event_age_seconds": round(max(0.0, ora - self.last_event_received_at), 3) if self.last_event_received_at is not None else None,
                "event_lag_seconds": round(lag, 3) if lag is not None else None}


def contesto_launcher():
    return {"launch_mode": "app" if os.environ.get("PARATIA_REGISTRY_LAUNCHER") == "app" else "legacy-python",
            "fda_entry": FDA_APP, "fda_regrant_after_build": True}


def messaggio_fda(contesto):
    if contesto["launch_mode"] != "app":
        return ("Il servizio usa il launcher Python precedente. Reinstalla il registro da Paratia; "
                "la voce Accesso completo al disco da verificare è /Applications/Paratia.app.")
    return ("Verifica /Applications/Paratia.app in Accesso completo al disco. "
            "Dopo ogni nuova build con firma ad hoc, rimuovi e aggiungi di nuovo quella voce.")


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
    # The native app parent spawns the installer-verified canonical CLT executable, never the
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
    def protetti():
        return R.leggi_configurazione(Path(utente.pw_dir), args.uid)
    sink = R.ScrittoreDiagnostici(lambda record: R.appendi(catena, record))
    config_illeggibile = False
    try:
        configurazione = protetti()
    except (OSError, ValueError):
        configurazione = {"voci": [], "watch_status": []}
        config_illeggibile = True
        sink(R._diagnostico("registro-cartelle-illeggibile"))
    osservatore = R.Osservatore(configurazione["voci"], sink, R.snapshot_processi())
    flusso = FlussoEslogger(osservatore)
    sink(R._diagnostico("osservatore-avviato", uid=args.uid))
    contesto = contesto_launcher()
    informazioni = {**contesto, "running": False, "healthy": False, "needs_fda": None,
                    "message": "Avvio del registro kernel in corso.", "dropped_events": 0,
                    "drop_detection_available": False, "watched_ids": [v["id"] for v in osservatore.protetti],
                    "watch_status": configurazione["watch_status"], "schema_supported": None,
                    "diagnostic_counts": {}, **flusso.metriche(),
                    "installed_cdhash": R._cdhash_app(SUPPORT / "Paratia.app")}
    informazioni["health_reasons"] = R.motivi_salute(informazioni)
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
                    configurazione = protetti()
                    if osservatore.protetti != configurazione["voci"]:
                        osservatore.protetti = configurazione["voci"]
                        flusso.ricompila_radici()
                    informazioni["watched_ids"] = [v["id"] for v in osservatore.protetti]
                    informazioni["watch_status"] = configurazione["watch_status"]
                    config_illeggibile = False
                except (OSError, ValueError):
                    config_illeggibile = True
                    sink(R._diagnostico("registro-cartelle-illeggibile"))
                    # Keep last valid paths; never silently broaden to all files.
                ultimo_config = ora
            leggibili, _, _ = select.select(list(aperti), [], [], 1)
            for fd in leggibili:
                pezzo = os.read(fd, 262144)
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
                                flusso.ricevi(buffer)
                                visto = True
                                informazioni["needs_fda"] = False
                            except (ValueError, TypeError):
                                osservatore.sano = False
                                sink(R._diagnostico("json-eslogger-non-valido"))
                        buffer, scarta = b"", False
            if osservatore.schema_fatale:
                break
            ora = time.monotonic()
            if ora - ultimo_stato >= 1:
                informazioni.update(running=processo.poll() is None and visto,
                                     healthy=osservatore.sano and visto and not config_illeggibile,
                                     dropped_events=osservatore.persi,
                                     drop_detection_available=osservatore.rileva_perdite,
                                     schema_supported=not osservatore.schema_fatale if visto else None,
                                     diagnostic_counts={k: max(sink.contatori.get(k, 0), osservatore.diagnostici.get(k, 0))
                                                        for k in set(sink.contatori) | set(osservatore.diagnostici)},
                                     message="Registro attivo." if osservatore.sano and visto else "Registro in avvio o con copertura incompleta: consulta i diagnostici.",
                                     **flusso.metriche())
                informazioni["health_reasons"] = R.motivi_salute(informazioni)
                informazioni["healthy"] = informazioni["healthy"] and not informazioni["health_reasons"]
                if informazioni["health_reasons"]:
                    informazioni["message"] = "Registro con copertura incompleta: consulta i motivi e l'elenco cartelle."
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
                             message=messaggio_fda(contesto) if bisogno else (
                                 "Il formato di eslogger non è compatibile: aggiorna Paratia." if osservatore.schema_fatale else "Il registro kernel è fermo."),
                             **flusso.metriche())
        informazioni["health_reasons"] = R.motivi_salute(informazioni)
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
