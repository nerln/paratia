#!/usr/bin/python3
"""Privileged eslogger adapter. Prepared here; installed only with human consent."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import ctypes
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
import threading
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
# File types whose unrelated lines are discarded after reading only the header.
# Close, mount, unmount, mmap and lookup are kept although they are no longer
# subscribed: a stray unrelated line of those types is dropped cheaply, not decoded.
_FILE_TYPES = (10, 12, 13, 20, 22, 23, 25, 32, 33, 41, 43,
               *("ES_EVENT_TYPE_NOTIFY_" + n for n in ("OPEN", "CLOSE", "CREATE", "MMAP", "MOUNT", "UNMOUNT", "RENAME", "UNLINK", "WRITE", "TRUNCATE", "LOOKUP")))
_TIPI_CON_MADRE = (13, 25, "ES_EVENT_TYPE_NOTIFY_CREATE", "ES_EVENT_TYPE_NOTIFY_RENAME")
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
        radici, madri = set(), set()
        self.codifica_incerta = False
        for voce in self.osservatore.protetti:
            for campo in CAMPI_RADICI:
                p = voce.get(campo)
                if not isinstance(p, str) or not os.path.isabs(p):
                    continue
                # JSON can spell controls with short escapes (\t, \n, ...) or
                # Unicode escapes. A parent inherits them from its watched
                # root. Decode every line for these uncommon paths, avoiding a
                # fragile list of raw spellings and preserving create/rename.
                self.codifica_incerta |= any(ord(c) < 32 or c in ('"', "\\") for c in p)
                for variante in _varianti_radice(p):
                    # create/rename split a newly created watched directory into
                    # its parent and filename. Retain its parent as a candidate.
                    # The parent matters only to create and rename: matching it
                    # for every event decoded all the activity of a whole disk
                    # whenever a watched folder sat at its root (27/10/2026).
                    for candidato, insieme in ((variante, radici), (os.path.dirname(variante), madri)):
                        if candidato and candidato != "/":
                            for forma in ("NFC", "NFD"):
                                try:
                                    insieme.add(unicodedata.normalize(forma, candidato).encode("utf8"))
                                except UnicodeError:
                                    # Surrogate-escaped filesystem paths do not
                                    # have a trustworthy UTF-8 needle.
                                    self.codifica_incerta = True
        self.radici = tuple(sorted(radici, key=len, reverse=True))
        self.madri = tuple(sorted(madri - radici, key=len, reverse=True))

    def _pertinente(self, riga, con_madri=True):
        aghi = self.radici + self.madri if con_madri else self.radici
        if self.codifica_incerta or any(p in riga for p in aghi):
            return True
        if b"\\u" in riga or b"\\/" in riga:
            decodificata = _UNICODE.sub(_unicode_utf8, riga).replace(b"\\/", b"/")
            if b"\\u" in decodificata:
                return True
            if any(p in decodificata for p in aghi):
                return True
            riga = decodificata
        # A filename can mix composed and decomposed characters within a single
        # component. NFC/NFD needles alone would miss that valid spelling.
        if not riga.isascii():
            try:
                canonica = unicodedata.normalize("NFC", riga.decode("utf8")).encode("utf8")
            except UnicodeError:
                return True
            return any(p in canonica for p in aghi)
        return False

    def ricevi(self, riga):
        self.raw_lines += 1
        metadati = _metadati_grezzi(riga)
        tipo = metadati.get("event_type") if metadati else None
        # Uncertain headers decode, as before; only create and rename need the parent.
        con_madri = metadati is None or tipo in _TIPI_CON_MADRE
        if metadati is not None and tipo in _FILE_TYPES and not self._pertinente(riga, con_madri):
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


class LettoreTubo:
    """Drain eslogger's pipe at once, so that eslogger never queues in its own memory.

    Measured on 27/10/2026: with the decoder half an hour behind, eslogger held
    32 GB of events it could not hand over. A thread now reads the pipe as soon
    as it has data, and keeps whole lines for the decoder up to ``limite``
    bytes. Beyond that a line is dropped and counted: its gap in eslogger's
    sequence numbers then shows as lost events, which is declared, instead of
    memory growing without bound on either side.
    """
    def __init__(self, fd, limite=64 * 1024 * 1024, massimo_riga=MAX_RIGA):
        self.fd, self.limite, self.massimo_riga = fd, limite, massimo_riga
        self.righe, self.byte = collections.deque(), 0
        self.scartate = self.troppo_grandi = 0
        self.finito = False
        self._condizione = threading.Condition()
        self._thread = threading.Thread(target=self._leggi, name="paratia-eslogger", daemon=True)
        self._thread.start()

    def _leggi(self):
        parziale, scarta = b"", False
        try:
            while True:
                pezzo = os.read(self.fd, 262144)
                if not pezzo:
                    break
                complete = []
                for parte in pezzo.splitlines(keepends=True):
                    if not scarta:
                        parziale += parte
                        if len(parziale) > self.massimo_riga:
                            parziale, scarta = b"", True
                            with self._condizione:
                                self.troppo_grandi += 1
                    if parte.endswith(b"\n"):
                        if not scarta:
                            complete.append(parziale)
                        parziale, scarta = b"", False
                if complete:
                    with self._condizione:
                        for riga in complete:
                            if self.byte + len(riga) > self.limite:
                                self.scartate += 1
                            else:
                                self.righe.append(riga)
                                self.byte += len(riga)
                        self._condizione.notify()
        except OSError:
            pass
        finally:
            with self._condizione:
                self.finito = True
                self.resto = bool(parziale)
                self._condizione.notify()

    def prendi(self, attesa=1.0, quante=20000):
        """Up to ``quante`` lines, waiting at most ``attesa`` seconds for the first."""
        with self._condizione:
            if not self.righe and not self.finito:
                self._condizione.wait(attesa)
            presi = []
            while self.righe and len(presi) < quante:
                riga = self.righe.popleft()
                self.byte -= len(riga)
                presi.append(riga)
            return presi

    @property
    def esaurito(self):
        with self._condizione:
            return self.finito and not self.righe


class _RusageInfoV2(ctypes.Structure):
    # struct rusage_info_v2 from sys/resource.h, up to the footprint we read.
    # Defined once: a class made inside a call stays in ctypes' POINTER cache.
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16), ("ri_user_time", ctypes.c_uint64),
                ("ri_system_time", ctypes.c_uint64), ("ri_pkg_idle_wkups", ctypes.c_uint64),
                ("ri_interrupt_wkups", ctypes.c_uint64), ("ri_pageins", ctypes.c_uint64),
                ("ri_wired_size", ctypes.c_uint64), ("ri_resident_size", ctypes.c_uint64),
                ("ri_phys_footprint", ctypes.c_uint64), ("ri_rest", ctypes.c_uint64 * 32)]


_PROC_PID_RUSAGE = None


def impronta_memoria(pid):
    """Physical footprint in bytes, compressed and swapped pages included; None if unknown.

    This is what Activity Monitor calls Memory. `ps -o rss` leaves out
    compressed pages, and on 27/10/2026 it hid 47 GB.
    """
    global _PROC_PID_RUSAGE
    try:
        if _PROC_PID_RUSAGE is None:
            funzione = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True).proc_pid_rusage
            funzione.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(_RusageInfoV2)]
            funzione.restype = ctypes.c_int
            _PROC_PID_RUSAGE = funzione
        dati = _RusageInfoV2()
        if _PROC_PID_RUSAGE(int(pid), 2, ctypes.byref(dati)):
            return None
        return int(dati.ri_phys_footprint)
    except (AttributeError, OSError, ValueError):
        return None


# Above these the collector writes why, and exits so that launchd restarts it clean.
# eslogger keeps every event it has not yet written: on 27/10/2026, under a
# simulator boot, it grew by 20 MB a second. Checked every 2 s, so it stays
# near 512 MB; a lagging eslogger slows down further once its backlog compresses.
TETTO_MEMORIA_RACCOGLITORE = 512 * 1024 * 1024
TETTO_MEMORIA_ESLOGGER = 512 * 1024 * 1024
CONTROLLO_MEMORIA = 2.0


def oltre_il_tetto(proprio, eslogger):
    """Which process is over its cap, or None. Unknown sizes are not a reason to stop."""
    if proprio is not None and proprio > TETTO_MEMORIA_RACCOGLITORE:
        return "raccoglitore"
    if eslogger is not None and eslogger > TETTO_MEMORIA_ESLOGGER:
        return "eslogger"
    return None


class CaricatoreConfigurazione:
    """Validate owned configuration without pausing the eslogger pipe reader.

    Call these methods from the reader thread. A single worker owns the volume
    cache, and a completed result must be collected before another load starts.
    A failed load preserves the previous successful configuration.
    """
    def __init__(self, load, precedenti=None, cache_volumi=None):
        self._load = load
        self._precedenti = precedenti
        self._cache_volumi = cache_volumi if cache_volumi is not None else {}
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="paratia-configurazione")
        self._future = None
        self._chiuso = False

    def richiedi(self):
        if self._chiuso or self._future is not None:
            return False
        self._future = self._executor.submit(
            self._load, precedenti=self._precedenti, cache_volumi=self._cache_volumi)
        return True

    def raccogli(self):
        if self._chiuso or self._future is None or not self._future.done():
            return None
        risultato, self._future = self._future, None
        configurazione = risultato.result()
        self._precedenti = configurazione
        return configurazione

    def chiudi(self):
        if self._chiuso:
            return
        self._chiuso = True
        if self._future is not None:
            self._future.cancel()
        self._future = None
        self._executor.shutdown(wait=False, cancel_futures=True)


def contesto_launcher(registro):
    # Stessa regola di registro.stato(): con un'identità stabile il permesso resta valido.
    firma = registro._modo_firma_app()
    return {"launch_mode": "app" if os.environ.get("PARATIA_REGISTRY_LAUNCHER") == "app" else "legacy-python",
            "fda_entry": FDA_APP, "fda_regrant_after_build": firma != "stabile", "firma": firma or "non-verificata"}


def messaggio_fda(contesto):
    if contesto["launch_mode"] != "app":
        return ("Il servizio usa il launcher Python precedente. Reinstalla il registro da Paratia; "
                "la voce Accesso completo al disco da verificare è /Applications/Paratia.app.")
    return ("Verifica /Applications/Paratia.app in Accesso completo al disco. "
            "Se la firma è cambiata dopo una nuova build, rimuovi e aggiungi di nuovo quella voce.")


# Stessi file di CODICE in registro_installa.py: il demone carica anche messaggi.py per i testi.
CODICE_DEMONE = ("registro_daemon.py", "registro.py", "catena.py", "messaggi.py")


def codice_affidabile(directory):
    for p in [directory, *directory.parents]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Il percorso del demone deve appartenere a root e non essere scrivibile da altri.")
    for nome in CODICE_DEMONE:
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


def applica_configurazione(registro, osservatore, flusso, informazioni, configurazione, sink):
    """Commit a finished snapshot on the main thread, with fixed diagnostics."""
    if osservatore.protetti != configurazione["voci"]:
        osservatore.protetti = configurazione["voci"]
        flusso.ricompila_radici()
    informazioni["watched_ids"] = [voce["id"] for voce in osservatore.protetti]
    informazioni["watch_status"] = registro._stati_sorveglianza(configurazione["watch_status"])
    motivi = {"folder_absent": "cartella-assente",
              "volume_validation_timeout": "verifica-volume-in-ritardo"}
    diagnostici = [{"id": voce["id"], "code": voce.get("warning_code")}
                  for voce in informazioni["watch_status"]]
    diagnostici += [voce for voce in configurazione.get("diagnostics", []) if isinstance(voce, dict)]
    visti, ids = set(), set(informazioni["watched_ids"])
    for voce in diagnostici:
        code, identifier = voce.get("code"), voce.get("id")
        if not isinstance(code, str) or not isinstance(identifier, str):
            continue
        motivo = motivi.get(code)
        if motivo and identifier in ids and (code, identifier) not in visti:
            visti.add((code, identifier))
            sink(registro._diagnostico(motivo, cartella=identifier))


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
    for p in [SUPPORT, *SUPPORT.parents, *(SUPPORT / n for n in CODICE_DEMONE)]:
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
    cache_volumi = {}
    def protetti(precedenti=None, cache_volumi=cache_volumi):
        return R.leggi_configurazione(Path(utente.pw_dir), args.uid,
                                     precedenti=precedenti, cache_volumi=cache_volumi)
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
    caricatore = CaricatoreConfigurazione(protetti, configurazione, cache_volumi)
    sink(R._diagnostico("osservatore-avviato", uid=args.uid))
    contesto = contesto_launcher(R)
    informazioni = {**contesto, "running": False, "healthy": False, "needs_fda": None,
                    "message": "Avvio del registro kernel in corso.", "dropped_events": 0,
                    "last_dropped_at": None,
                    "drop_detection_available": False, "watched_ids": [v["id"] for v in osservatore.protetti],
                    "watch_status": [], "schema_supported": None,
                    "diagnostic_counts": {}, **flusso.metriche(),
                    "installed_cdhash": R._cdhash_app(SUPPORT / "Paratia.app"),
                    "servizio_impronta": R.impronta_servizio(SUPPORT)}
    try:
        # A restart for memory stays visible to the GUI after the new run begins.
        with open(stato, "rb") as f:
            riavvio = json.loads(f.read(4194304)).get("memory_restart_at")
        if isinstance(riavvio, (int, float)) and time.time() - riavvio < 86400:
            informazioni["memory_restart_at"] = riavvio
    except (OSError, ValueError, AttributeError):
        pass
    applica_configurazione(R, osservatore, flusso, informazioni, configurazione, sink)
    informazioni["health_reasons"] = R.motivi_salute(informazioni)
    scrivi_stato(stato, informazioni)
    processo = subprocess.Popen(["/usr/bin/eslogger", *R.EVENTI], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    fermati = [False]
    for numero in (signal.SIGTERM, signal.SIGINT):
        signal.signal(numero, lambda *_: fermati.__setitem__(0, True))
    ultimo_stato, ultimo_config, visto = 0.0, time.monotonic(), False
    ultimo_controllo_memoria = time.monotonic()
    lettore = LettoreTubo(processo.stdout.fileno())
    # eslogger's stderr: only its last 64 KB, to tell a missing Full Disk Access apart.
    coda_errori = collections.deque(maxlen=64)

    def leggi_errori():
        try:
            while True:
                pezzo = os.read(processo.stderr.fileno(), 1024)
                if not pezzo:
                    break
                coda_errori.append(pezzo)
        except OSError:
            pass
    lettore_errori = threading.Thread(target=leggi_errori, name="paratia-eslogger-stderr", daemon=True)
    lettore_errori.start()
    scartate_viste = troppo_grandi_viste = 0
    try:
        while not fermati[0]:
            ora = time.monotonic()
            if ora - ultimo_config >= 5:
                if caricatore.richiedi():
                    ultimo_config = ora
            try:
                nuova = caricatore.raccogli()
                if nuova is not None:
                    configurazione = nuova
                    applica_configurazione(R, osservatore, flusso, informazioni, configurazione, sink)
                    config_illeggibile = False
            except (OSError, ValueError):
                config_illeggibile = True
                sink(R._diagnostico("registro-cartelle-illeggibile"))
                # Explicitly unhealthy on an unexpected loader failure; owned
                # file/entry refusals are handled independently by the loader.
            for riga in lettore.prendi(attesa=1.0):
                try:
                    flusso.ricevi(riga)
                    visto = True
                    informazioni["needs_fda"] = False
                except (ValueError, TypeError):
                    osservatore.sano = False
                    sink(R._diagnostico("json-eslogger-non-valido"))
                if osservatore.schema_fatale:
                    break
            if lettore.troppo_grandi > troppo_grandi_viste:
                troppo_grandi_viste = lettore.troppo_grandi
                osservatore.sano = False
                sink(R._diagnostico("riga-eslogger-troppo-grande"))
            if lettore.scartate > scartate_viste:
                # The gaps in eslogger's sequence numbers count these as lost events too.
                scartate_viste = lettore.scartate
                sink(R._diagnostico("coda-piena-righe-scartate", scartate=lettore.scartate))
            if osservatore.schema_fatale:
                break
            ora = time.monotonic()
            if ora - ultimo_controllo_memoria >= CONTROLLO_MEMORIA:
                ultimo_controllo_memoria = ora
                proprio, di_eslogger = impronta_memoria(os.getpid()), impronta_memoria(processo.pid)
                informazioni.update(memory_mb=round(proprio / 1048576) if proprio else None,
                                    eslogger_memory_mb=round(di_eslogger / 1048576) if di_eslogger else None)
                chi = oltre_il_tetto(proprio, di_eslogger)
                if chi:
                    # Exit with an error: launchd restarts the collector and a fresh eslogger.
                    sink(R._diagnostico("memoria-oltre-il-tetto", processo=chi,
                                        memoria_mb=informazioni["memory_mb"], eslogger_mb=informazioni["eslogger_memory_mb"]))
                    informazioni.update(running=False, healthy=False, memory_restart_at=time.time(),
                                        message="Registro riavviato: aveva superato il tetto di memoria.")
                    scrivi_stato(stato, informazioni)
                    raise SystemExit(75)
            if ora - ultimo_stato >= 1:
                informazioni.update(running=processo.poll() is None and visto,
                                     healthy=osservatore.sano and visto and not config_illeggibile,
                                     dropped_events=osservatore.persi,
                                     last_dropped_at=osservatore.ultima_perdita,
                                     drop_detection_available=osservatore.rileva_perdite,
                                     schema_supported=not osservatore.schema_fatale if visto else None,
                                     diagnostic_counts={k: max(sink.contatori.get(k, 0), osservatore.diagnostici.get(k, 0))
                                                        for k in set(sink.contatori) | set(osservatore.diagnostici)},
                                     message="Registro attivo." if osservatore.sano and visto else "Registro in avvio o con copertura incompleta: consulta i diagnostici.",
                                     queue_dropped_lines=lettore.scartate,
                                     coalesced_writes=osservatore.scritture_raggruppate,
                                     image_io_skipped=osservatore.io_immagine,
                                     **flusso.metriche())
                informazioni["health_reasons"] = R.motivi_salute(informazioni)
                informazioni["healthy"] = informazioni["healthy"] and not informazioni["health_reasons"]
                if informazioni["health_reasons"]:
                    informazioni["message"] = "Registro con copertura incompleta: consulta i motivi e l'elenco cartelle."
                scrivi_stato(stato, informazioni)
                ultimo_stato = ora
            if processo.poll() is not None and lettore.esaurito:
                break
    finally:
        caricatore.chiudi()
        if processo.poll() is None:
            processo.terminate()
            try:
                processo.wait(timeout=5)
            except subprocess.TimeoutExpired:
                processo.kill()
                processo.wait(timeout=5)
        else:
            processo.wait()
        if getattr(lettore, "resto", False):
            sink(R._diagnostico("riga-eslogger-incompleta"))
        lettore_errori.join(timeout=2)
        errori = b"".join(coda_errori)[-65536:]
        # Retain only the permission category, never the stderr text itself.
        bisogno = any(x in errori.lower() for x in (b"tcc", b"full disk access", b"not permitted", b"not_permitted"))
        informazioni.update(running=False, healthy=False, needs_fda=bisogno,
                             dropped_events=osservatore.persi, last_dropped_at=osservatore.ultima_perdita,
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
