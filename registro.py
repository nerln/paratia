"""Metadata-only access records and a conservative Endpoint Security adapter.

Compatible with the system Python 3.9 used by the privileged daemon. No file
contents, command arguments, environment variables, or transcripts are read.
"""
from __future__ import annotations


def _t(testo, **valori):
    """Testo per la lingua della GUI; senza lingua impostata, quello italiano."""
    import importlib.util
    import os
    import sys
    nome = "paratia_messaggi"
    if nome not in sys.modules:
        percorso = os.path.join(os.path.dirname(os.path.abspath(__file__)), "messaggi.py")
        spec = importlib.util.spec_from_file_location(nome, percorso)
        modulo = importlib.util.module_from_spec(spec)
        sys.modules[nome] = modulo
        spec.loader.exec_module(modulo)
    return sys.modules[nome].t(testo, **valori)

import csv
import datetime
import fcntl
import io
import importlib.util
import json
import math
import os
import pwd
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

_spec = importlib.util.spec_from_file_location("paratia_catena", Path(__file__).resolve().with_name("catena.py"))
_catena = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_catena)
appendi, verifica_catena, acl_scrivibile = _catena.appendi, _catena.verifica, _catena.acl_scrivibile

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
CATENA = CASA / "registro" / "catena.jsonl"
SYSTEM = Path("/Library/Logs/Paratia")
SUPPORT = Path("/Library/Application Support/Paratia")
ETICHETTA = "it.paratia.registro"
EVENTI = ("open", "write", "create", "rename", "unlink", "truncate", "exec", "fork", "exit")
# Historical/imported records remain readable. These notifications are not
# subscribed to by the live collector: close, mount and unmount were dropped on
# 14/10 to reduce eslogger load (lookup and mmap were excluded earlier).
# open says who opened a path; write, create, rename, unlink and truncate say
# who changed it.
TIPI_SUPPORTATI = (*EVENTI, "close", "mount", "unmount", "lookup", "mmap")
# A counted loss stays in the cumulative total, but only reports a health
# reason for this many seconds after it was observed.
PERDITE_RECENTI_SECONDI = 600
# Values are from Apple's ESTypes.h; old values are never renumbered.
NUMERI = {9: "exec", 10: "open", 11: "fork", 12: "close", 13: "create",
          15: "exit", 20: "mmap", 22: "mount", 23: "unmount", 25: "rename",
          32: "unlink", 33: "write", 41: "truncate", 43: "lookup"}
LIMITI = [
    _t("Un'apertura per lettura non prova una lettura dei byte: ES non registra ogni read()."),
    _t("I tentativi falliti, incluso ENOENT, non sono osservabili tutti; gli esiti ES non sono errno."),
    _t("La discendenza può essere sconosciuta, specialmente per processi già avviati."),
    _t("eslogger ha uno schema non stabile e può perdere eventi; i buchi vengono segnalati."),
    _t("La catena rileva modifiche interne; non prova da sola che la coda non sia stata troncata."),
    _t("Il registro locale delle operazioni GUI è modificabile dall'utente; quello kernel è root-owned."),
    _t("Le modifiche solo via mmap non hanno più un evento di chiusura: il registro kernel non le riporta."),
    _t("Montaggi e smontaggi non sono nel registro kernel; apertura e chiusura di una cartella protetta restano nel registro di Paratia."),
]


class ErroreRegistro(ValueError):
    """User-facing resolver errors with fixed codes and no supplied path/data."""

    MESSAGGI = {
        "folder_not_configured": _t("La cartella non è configurata nel registro. Scegli una cartella dall'elenco o aggiungi una sorveglianza."),
        "folder_ambiguous": _t("Il percorso corrisponde a più ID. Scegli l'ID della cartella dall'elenco del registro."),
        "protected_folder_watch": _t("Questo percorso appartiene a una cartella protetta già configurata. Seleziona la cartella nel Registro; non aggiungere una sorveglianza separata."),
    }

    def __init__(self, code):
        self.code = code
        self.message = self.MESSAGGI[code]
        super().__init__(self.message)


def _testo(v):
    if isinstance(v, dict):
        v = v.get("data")
    return v if isinstance(v, str) and len(v) <= 16384 and "\0" not in v else None


def _intero(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _identita(p):
    a = p.get("audit_token", {}) if isinstance(p, dict) else {}
    if not isinstance(a, dict):
        return None
    pid, versione = _intero(a.get("pid")), _intero(a.get("pidversion"))
    return (pid, versione) if pid is not None and versione is not None else None


def _agente(p):
    if not isinstance(p, dict):
        return None
    executable = p.get("executable", {})
    percorso = _testo(executable.get("path")) if isinstance(executable, dict) else None
    firma = (_testo(p.get("signing_id")) or "").lower()
    nome = Path(percorso or "").name.lower()
    if nome in ("claude", "claude-code") or firma in ("com.anthropic.claudecode",):
        return "Claude Code"
    if nome in ("codex", "codex-cli") or "com.openai.codex" in firma:
        return "Codex"
    if nome == "chatgpt" or firma == "com.openai.chat":
        return "ChatGPT"
    if nome == "agentbridge" or "agentbridge" in firma:
        return "agentbridge"
    return None


def _processo(p, nomi_uid=None):
    p = p if isinstance(p, dict) else {}
    a = p.get("audit_token", {})
    a = a if isinstance(a, dict) else {}
    uid = _intero(a.get("euid", a.get("uid")))
    nome = None
    if uid is not None:
        if nomi_uid is not None and uid in nomi_uid:
            nome = nomi_uid[uid]
        else:
            try:
                nome = pwd.getpwuid(uid).pw_name
            except (KeyError, OverflowError):
                pass
            if nomi_uid is not None:
                if len(nomi_uid) >= 256:
                    nomi_uid.clear()
                nomi_uid[uid] = nome
    executable = p.get("executable", {})
    return {"pid": _intero(a.get("pid")), "pidversion": _intero(a.get("pidversion")),
            "uid": uid, "utente": nome,
            "processo": _testo(executable.get("path")) if isinstance(executable, dict) else None,
            "signing_id": _testo(p.get("signing_id")),
            "ppid": _intero(p.get("ppid"))}


def _diagnostico(motivo, **dati):
    return {"source": "eslogger", "sorgente": "eslogger", "evento": "diagnostico", "motivo": motivo,
            "quando": datetime.datetime.now(datetime.timezone.utc).isoformat(), **dati}


class Discendenza:
    def __init__(self, snapshot=None):
        self.processi = {}
        self.snapshot = snapshot or {}
        # Account labels are a bounded session snapshot. Audit-token UID and
        # PID/pidversion remain authoritative and are never inferred from names.
        self.nomi_uid = {}

    def ricorda(self, p):
        identita = _identita(p)
        if identita:
            # Do not keep exec arguments, environment, or the original process object.
            self.processi[identita] = {**_processo(p, self.nomi_uid), "nome_agente": _agente(p),
                                      "parent": _identita({"audit_token": p.get("parent_audit_token")}),
                                      "responsible": _identita({"audit_token": p.get("responsible_audit_token")})}

    def aggiorna(self, tipo, msg, evento):
        p = msg.get("process", {})
        self.ricorda(p)
        if tipo in ("fork", "exec"):
            target = evento.get("child" if tipo == "fork" else "target", {})
            self.ricorda(target)
            if tipo == "fork" and _identita(target) in self.processi:
                self.processi[_identita(target)]["parent"] = _identita(p)

    def classifica(self, p):
        diretto = _agente(p)
        if diretto:
            return {"agente": True, "nome_agente": diretto, "evidenza_agente": "executable/signing_id"}
        responsabile = _identita({"audit_token": p.get("responsible_audit_token")})
        nodo_responsabile = self.processi.get(responsabile, {})
        if nodo_responsabile.get("nome_agente"):
            return {"agente": True, "nome_agente": nodo_responsabile["nome_agente"],
                    "evidenza_agente": "responsible_audit_token"}
        identita = _identita(p)
        visitati = set()
        while identita and identita not in visitati and len(visitati) < 256:
            visitati.add(identita)
            nodo = self.processi.get(identita)
            if not nodo:
                break
            if nodo["nome_agente"]:
                return {"agente": True, "nome_agente": nodo["nome_agente"],
                        "evidenza_agente": "parent_audit_token"}
            if identita[0] == 1:
                return {"agente": False, "nome_agente": None, "evidenza_agente": "linea-fino-a-launchd"}
            identita = nodo["parent"]
        # The fallback needs only a PID, not a second account-name lookup.
        identita = _identita(p)
        candidato, pid = None, identita[0] if identita else None
        visitati = set()
        while pid in self.snapshot and pid not in visitati and len(visitati) < 256:
            visitati.add(pid)
            nodo = self.snapshot[pid]
            candidato = candidato or _agente({"executable": {"path": nodo.get("processo")}})
            pid = nodo.get("ppid")
        return {"agente": None, "nome_agente": None,
                "candidato_agente": candidato,
                "evidenza_agente": "snapshot-pid-non-verificato" if candidato else "discendenza-incompleta"}

    def responsabile(self, p):
        token = p.get("responsible_audit_token", {}) if isinstance(p, dict) else {}
        identita = _identita({"audit_token": token})
        nodo = self.processi.get(identita, {})
        return {"responsabile_pid": identita[0] if identita else None,
                "responsabile_pidversion": identita[1] if identita else None,
                "app_responsabile": nodo.get("processo")}


def snapshot_processi():
    r = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,uid=,comm="],
                       capture_output=True, text=True, timeout=10)
    risultato = {}
    for riga in r.stdout.splitlines():
        parti = riga.strip().split(None, 3)
        if len(parti) == 4 and all(p.isdigit() for p in parti[:3]):
            risultato[int(parti[0])] = {"ppid": int(parti[1]), "uid": int(parti[2]),
                                      "processo": parti[3], "pidversion": None}
    return risultato


def _file(v):
    return _testo(v.get("path")) if isinstance(v, dict) else _testo(v)


def _destinazione(e):
    d = e.get("destination", {})
    if not isinstance(d, dict):
        return None
    if "existing_file" in d:
        return _file(d["existing_file"])
    n = d.get("new_path", {})
    if not isinstance(n, dict):
        return None
    base, nome = _file(n.get("dir")), _testo(n.get("filename"))
    return os.path.normpath(os.path.join(base, nome)) if base and nome and not os.path.isabs(nome) else None


def normalizza(msg, ancestry=None):
    if not isinstance(msg, dict) or type(msg.get("schema_version")) is not int or msg.get("schema_version") != 1:
        return [_diagnostico("schema-eslogger-non-supportato")]
    e = msg.get("event", {})
    if not isinstance(e, dict) or len(e) != 1:
        return [_diagnostico("evento-eslogger-non-valido")]
    tipo = next(iter(e))
    event_type = msg.get("event_type")
    expected = NUMERI.get(event_type) if isinstance(event_type, int) else (
        event_type.removeprefix("ES_EVENT_TYPE_NOTIFY_").lower() if isinstance(event_type, str) else None)
    if tipo not in TIPI_SUPPORTATI or expected != tipo or not isinstance(e[tipo], dict):
        return [_diagnostico("tipo-evento-non-supportato")]
    ancestry = ancestry or Discendenza()
    p, dettaglio = msg.get("process", {}), e[tipo]
    if not isinstance(p, dict) or _identita(p) is None:
        return [_diagnostico("identita-processo-non-valida")]
    ancestry.aggiorna(tipo, msg, dettaglio)
    if tipo in ("exec", "fork", "exit"):
        return []
    percorso, destinazione = None, None
    if tipo == "open":
        percorso = _file(dettaglio.get("file"))
    elif tipo in ("close", "write", "unlink", "truncate"):
        percorso = _file(dettaglio.get("target"))
    elif tipo == "mmap":
        percorso = _file(dettaglio.get("source"))
    elif tipo in ("create", "rename"):
        destinazione = _destinazione(dettaglio)
        percorso = _file(dettaglio.get("source")) if tipo == "rename" else destinazione
    elif tipo in ("mount", "unmount"):
        fs = dettaglio.get("statfs", {})
        percorso = _testo(fs.get("f_mntonname")) if isinstance(fs, dict) else None
    elif tipo == "lookup":
        base, nome = _file(dettaglio.get("source_dir")), _testo(dettaglio.get("relative_target"))
        percorso = os.path.normpath(os.path.join(base, nome)) if base and nome else None
    if not percorso or not os.path.isabs(percorso):
        return [_diagnostico("percorso-evento-non-disponibile", tipo_evento=tipo)]
    quando = _testo(msg.get("time")) or datetime.datetime.now(datetime.timezone.utc).isoformat()
    azione = msg.get("action", {})
    azione = azione if isinstance(azione, dict) else {}
    risultato = azione.get("notify", azione)
    risultato = risultato.get("result", {}) if isinstance(risultato, dict) else {}
    negato = isinstance(risultato, dict) and (risultato.get("auth") in (1, "ES_AUTH_RESULT_DENY")
                                              or risultato.get("flags") == 0)
    r = {"source": "eslogger", "sorgente": "eslogger", "quando": quando, "evento": tipo,
         "percorso": percorso, "destinazione": destinazione,
         "esito": "negato-da-es" if negato else "osservato",
         "schema_version": 1, "message_version": _intero(msg.get("version")),
         **_processo(p, getattr(ancestry, "nomi_uid", None)), **ancestry.classifica(p), **ancestry.responsabile(p)}
    for nome in ("fflag", "protection", "max_protection", "flags"):
        if isinstance(dettaglio.get(nome), int):
            r[nome] = dettaglio[nome]
    for nome in ("modified", "was_mapped_writable"):
        if isinstance(dettaglio.get(nome), bool):
            r[nome] = dettaglio[nome]
    r["apertura_per_lettura"] = bool(r.get("fflag", 0) & 1) if tipo == "open" else None
    r["apertura_per_scrittura"] = bool(r.get("fflag", 0) & 2) if tipo == "open" else None
    for nome in ("seq_num", "global_seq_num"):
        if _intero(msg.get(nome)) is not None:
            r[nome] = msg[nome]
    return [r]


def percorso_normale(p):
    p = unicodedata.normalize("NFC", os.path.normpath(p))
    # APFS firmlinks expose the same user data under both spellings.
    if p == "/System/Volumes/Data":
        p = "/"
    elif p.startswith("/System/Volumes/Data/"):
        p = p[len("/System/Volumes/Data"):]
    for alias in ("/tmp", "/var", "/etc"):
        if p == alias or p.startswith(alias + "/"):
            return "/private" + p
    return p


def corrisponde(record, protetti):
    risultati = []
    percorsi = [percorso_normale(record[k]) for k in ("percorso", "destinazione") if isinstance(record.get(k), str)]
    if any(p == str(base) or p.startswith(str(base) + "/") for p in percorsi for base in (SYSTEM, SUPPORT)):
        return []
    for voce in protetti:
        for campo in ("origine", "bundle", "montaggio", "recupero_temporaneo", "montaggio_temporaneo", "backup", "plaintext_residuo"):
            radice = voce.get(campo)
            if not isinstance(radice, str) or not os.path.isabs(radice):
                continue
            radice = percorso_normale(radice)
            for chiave in ("percorso", "destinazione"):
                p = record.get(chiave)
                if isinstance(p, str):
                    p = percorso_normale(p)
                    if p == radice or p.startswith(radice.rstrip("/") + "/"):
                        risultati.append({"id": voce.get("id"), "nome": voce.get("nome"), "tipo": campo})
                        break
    return risultati


class Osservatore:
    """Sequence tracking and health for one collector run.

    ``sano`` stays False for the run after a diagnostic or a sequence restart.
    Counted losses do not clear or set it: they add to ``persi`` (cumulative)
    and set ``ultima_perdita``, which only drives a time-limited health reason.
    """
    def __init__(self, protetti, sink, snapshot=None, orologio=time.time):
        self.protetti, self.sink = protetti, sink
        self.discendenza = Discendenza(snapshot)
        self.sequenze, self.globale = {}, None
        self.sano, self.persi = True, 0
        self.ultima_perdita = None
        self.orologio = orologio
        self.rileva_perdite = False
        self.diagnostici = {}
        self.schema_fatale = False

    def aggiorna_sequenze(self, msg):
        """Track every subscribed message, including intentionally filtered ones."""
        records = []
        if isinstance(msg, dict):
            tipo, sequenza = msg.get("event_type"), _intero(msg.get("seq_num"))
            if not isinstance(tipo, (int, str)):
                tipo = None
            globale = _intero(msg.get("global_seq_num"))
            self.rileva_perdite = self.rileva_perdite or globale is not None or sequenza is not None
            prima = self.globale if globale is not None else self.sequenze.get(tipo)
            dopo = globale if globale is not None else sequenza
            if prima is not None and dopo is not None and dopo != prima + 1:
                persi = max(0, dopo - prima - 1)
                if persi:
                    self.persi += persi
                    self.ultima_perdita = self.orologio()
                    records.insert(0, _diagnostico("eventi-persi", persi=persi))
                else:
                    records.insert(0, _diagnostico("sequenza-riavviata", persi=0))
                    self.sano = False
            if globale is not None:
                self.globale = globale
            if sequenza is not None and isinstance(tipo, (str, int)):
                self.sequenze[tipo] = sequenza
        return records

    def scarta(self, metadati):
        """Only discard payload work: sequence gaps still reach the diagnostic sink."""
        return self._scrivi(self.aggiorna_sequenze(metadati))

    def ricevi(self, msg):
        records = normalizza(msg, self.discendenza)
        if any(r.get("evento") == "diagnostico" for r in records):
            self.sano = False
        self.schema_fatale = self.schema_fatale or any(r.get("motivo") == "schema-eslogger-non-supportato" for r in records)
        records = self.aggiorna_sequenze(msg) + records
        if len(self.discendenza.processi) > 50000:
            self.discendenza.processi.clear()
            records.insert(0, _diagnostico("cache-discendenza-azzerata"))
            self.sano = False
        return self._scrivi(records)

    def _scrivi(self, records):
        scritti = []
        for r in records:
            cartelle = corrisponde(r, self.protetti)
            if r["evento"] == "diagnostico" or cartelle:
                if r["evento"] == "diagnostico":
                    motivo = r["motivo"]
                    self.diagnostici[motivo] = self.diagnostici.get(motivo, 0) + 1
                    if self.diagnostici[motivo] > 1:
                        continue  # Bound feedback and disk growth on incompatible input.
                if cartelle:
                    r["cartelle"] = cartelle
                    r["cartella"] = cartelle[0]["id"]
                self.sink(r)
                scritti.append(r)
        return scritti


class ScrittoreDiagnostici:
    """Bound all diagnostic paths, including JSON framing/configuration errors."""
    def __init__(self, append):
        self.append = append
        self.contatori = {}

    def __call__(self, record):
        if record.get("evento") == "diagnostico":
            motivo = record.get("motivo", "diagnostico")
            self.contatori[motivo] = self.contatori.get(motivo, 0) + 1
            if self.contatori[motivo] > 1:
                return None
        return self.append(record)


def _leggi_json_posseduto(percorso, uid):
    """Read only a capped, owned registry through a symlink-free directory walk."""
    p = Path(percorso)
    if not p.is_absolute():
        raise ValueError(_t("Il registro richiede un percorso assoluto."))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for parte in p.parts[1:-1]:
            nuovo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = nuovo
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as f:
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != uid or s.st_size > 4194304
                    or s.st_mode & 0o022 or s.st_nlink != 1 or acl_scrivibile(p)):
                raise ValueError(_t("Il registro delle cartelle non ha formato o proprietario validi."))
            dati = f.read(4194305)
            if len(dati) > 4194304:
                raise ValueError(_t("Il registro delle cartelle è troppo grande."))
            r = json.loads(dati)
    except FileNotFoundError:
        return None
    finally:
        os.close(directory)
    return r


MNT_IGNORE_OWNERSHIP = 0x00200000  # Darwin sys/mount.h.
ESITI_CONFIGURAZIONE = {
    "invalid_entry": _t("La voce di configurazione non è valida."),
    "invalid_path": _t("Il percorso configurato non è consentito o non è canonico."),
    "symlink": _t("Il percorso contiene un collegamento simbolico."),
    "owner_mismatch": _t("La cartella non appartiene all'utente della configurazione."),
    "noowners_volume_unverified": _t("Il volume con proprietari ignorati non è stato confermato come disco esterno fisico e non di sistema."),
    "folder_missing": _t("La cartella configurata non è presente. Scegli una cartella esistente da sorvegliare."),
    "volume_validation_timeout": _t("La verifica del volume esterno ha superato il tempo disponibile."),
    "config_unreadable": _t("Il file di configurazione non è leggibile o non ha proprietario e autorizzazioni validi."),
    "duplicate_id": _t("L'ID è usato da più voci di configurazione. Assegna un ID distinto alla sorveglianza."),
}
AVVISI_CONFIGURAZIONE = {
    "folder_absent": _t("Cartella assente: la sorveglianza già confermata resta attiva sul percorso configurato."),
    "volume_validation_timeout": _t("Verifica del volume in ritardo: la cartella già confermata resta attiva sullo stesso volume montato."),
}


class _RifiutoConfigurazione(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(ESITI_CONFIGURAZIONE[code])


def _id_configurazione(identificatore):
    return (isinstance(identificatore, str) and 1 <= len(identificatore) <= 128
            and all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                    for c in identificatore))


def _esito_configurazione(identificatore, code=None):
    return {"id": identificatore if _id_configurazione(identificatore) else None,
            "status": "rejected" if code else "confirmed", "reason_code": code,
            "message": ESITI_CONFIGURAZIONE[code] if code else _t("Cartella confermata dal raccoglitore.")}


def _statfs_configurazione(dove):
    """Read mount flags from the kernel, never infer noowners from an UID."""
    import ctypes
    if sys.platform != "darwin":
        raise _RifiutoConfigurazione("noowners_volume_unverified")

    class Statfs(ctypes.Structure):
        _fields_ = [("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
                    *[(nome, ctypes.c_uint64) for nome in (
                        "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree")],
                    ("f_fsid", ctypes.c_int32 * 2), ("f_owner", ctypes.c_uint32),
                    ("f_type", ctypes.c_uint32), ("f_flags", ctypes.c_uint32),
                    ("f_fssubtype", ctypes.c_uint32), ("f_fstypename", ctypes.c_char * 16),
                    ("f_mntonname", ctypes.c_char * 1024),
                    ("f_mntfromname", ctypes.c_char * 1024),
                    ("f_flags_ext", ctypes.c_uint32), ("f_reserved", ctypes.c_uint32 * 7)]
    try:
        simbolo = "statfs" if os.uname().machine.startswith("arm64") else "statfs$INODE64"
        funzione = getattr(ctypes.CDLL(None, use_errno=True), simbolo)
        funzione.argtypes = [ctypes.c_char_p, ctypes.POINTER(Statfs)]
        funzione.restype = ctypes.c_int
        dati = Statfs()
        if funzione(os.fsencode(dove), ctypes.byref(dati)):
            raise OSError(ctypes.get_errno(), "statfs")
        monte = os.fsdecode(dati.f_mntonname)
        if not monte or not os.path.isabs(monte) or os.path.normpath(monte) != monte:
            raise ValueError()
        return {"flags": int(dati.f_flags), "mount": monte,
                "fsid": tuple(int(v) for v in dati.f_fsid),
                "source": os.fsdecode(dati.f_mntfromname),
                "type": int(dati.f_type)}
    except (AttributeError, OSError, ValueError, UnicodeError) as e:
        raise _RifiutoConfigurazione("noowners_volume_unverified") from e


def _volume_esterno_configurazione(monte):
    """Confirm every APFS physical store, refusing internal and virtual disks."""
    if (not isinstance(monte, str) or not monte.startswith("/Volumes/")
            or len(Path(monte).parts) != 3):
        raise _RifiutoConfigurazione("noowners_volume_unverified")
    cache = {}

    def info(percorso):
        if percorso not in cache:
            if len(cache) >= 16:
                raise ValueError()
            risultato = subprocess.run(["/usr/sbin/diskutil", "info", "-plist", percorso],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       timeout=3.0, check=False,
                                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
            if risultato.returncode or len(risultato.stdout) > 65536:
                raise ValueError()
            dati = plistlib.loads(risultato.stdout)
            if not isinstance(dati, dict):
                raise ValueError()
            cache[percorso] = dati
        return cache[percorso]

    def dispositivo(nome):
        if not isinstance(nome, str) or not re.fullmatch(r"disk[0-9]+(?:s[0-9]+)*", nome):
            raise ValueError()
        return nome

    def fisico(percorso, antenati=()):
        if percorso in antenati or len(antenati) >= 8:
            raise ValueError()
        dati = info(percorso)
        if str(dati.get("BusProtocol", "")).lower().replace(" ", "") == "diskimage":
            raise ValueError()
        stores = dati.get("APFSPhysicalStores")
        if stores is not None:
            if not isinstance(stores, list) or not stores or len(stores) > 16:
                raise ValueError()
            for store in stores:
                if not isinstance(store, dict):
                    raise ValueError()
                fisico(dispositivo(store.get("APFSPhysicalStore")), (*antenati, percorso))
            return
        parent = dati.get("ParentWholeDisk")
        if parent and parent != dati.get("DeviceIdentifier"):
            fisico(dispositivo(parent), (*antenati, percorso))
            return
        intero = dati.get("DeviceIdentifier", percorso)
        if (not isinstance(intero, str) or not re.fullmatch(r"disk[0-9]+", intero)
                or dati.get("VirtualOrPhysical") != "Physical" or dati.get("Internal") is not False):
            raise ValueError()

    try:
        fisico(monte)
    except subprocess.TimeoutExpired as e:
        raise _RifiutoConfigurazione("volume_validation_timeout") from e
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        raise _RifiutoConfigurazione("noowners_volume_unverified") from e


def _firma_volume_configurazione(p, s=None):
    """Cheap kernel identity, re-read before using any session volume proof."""
    s = s if s is not None else p.stat()
    if sys.platform != "darwin":
        return {"flags": 0, "mount": None, "identity": (s.st_dev,)}
    volume = _statfs_configurazione(p)
    monte = Path(volume["mount"])
    radice = monte.stat()
    montato = _statfs_configurazione(monte)
    campi = ("flags", "mount", "fsid", "source", "type")
    if (radice.st_dev != s.st_dev or any(volume.get(k) != montato.get(k) for k in campi)
            or montato["mount"] != str(monte)):
        raise _RifiutoConfigurazione("noowners_volume_unverified")
    # Darwin's fsid and mount source distinguish reused st_dev values. The
    # mount-root inode also prevents reusing a proof after the path is replaced.
    identity = (s.st_dev, tuple(volume.get("fsid", ())), volume["mount"],
                volume.get("source"), volume.get("type"), volume["flags"], radice.st_ino)
    return {**volume, "identity": identity}


def _cartella_posseduta_configurazione(p, uid, configurazione_validata=False, volumi=None):
    """The owned request replaces unreliable st_uid only on external noowners."""
    s = p.stat()
    if not stat.S_ISDIR(s.st_mode):
        raise _RifiutoConfigurazione("invalid_path")
    if sys.platform != "darwin" and s.st_uid == uid:
        return
    # A human CLI request is authenticated by its real UID; root must first
    # read the symlink-free, owned configuration with _leggi_json_posseduto.
    cache = volumi if volumi is not None else {}
    metadati = _firma_volume_configurazione(p, s)
    identity = metadati["identity"]
    persistenti = cache.get("_persistenti", {})
    cache.setdefault("_visti", set()).add(identity)
    if identity not in cache:
        cache[identity] = {**metadati, "confirmed": identity in persistenti}
    volume = cache[identity]
    if "error" in volume:
        if (volume["error"] != "volume_validation_timeout"
                or identity not in cache.get("_timeout_consentiti", set())):
            raise _RifiutoConfigurazione(volume["error"])
    if volume["flags"] & MNT_IGNORE_OWNERSHIP:
        if not configurazione_validata and not (uid > 0 and uid == os.getuid()):
            raise _RifiutoConfigurazione("owner_mismatch")
        if not volume["confirmed"] and "error" not in volume:
            try:
                _volume_esterno_configurazione(volume["mount"])
            except _RifiutoConfigurazione as errore:
                volume["error"] = errore.code
                raise
            volume["confirmed"] = True
            persistenti[identity] = True
        return
    if s.st_uid != uid:
        raise _RifiutoConfigurazione("owner_mismatch")


def _identita_voce_configurazione(identificatore, origine, tipo):
    p = Path(origine)
    genitore = p.parent.stat()
    presente = p.exists()
    volume = _firma_volume_configurazione(p if presente else p.parent)
    return {"id": identificatore, "origine": origine, "tipo": tipo,
            "parent": (genitore.st_dev, genitore.st_ino, genitore.st_uid),
            "volume": volume["identity"]}


def _token_configurazione(identificatore, origine, tipo):
    """Bind a public ID acknowledgement to its path without publishing paths."""
    import hashlib
    dati = json.dumps([identificatore, origine, tipo], ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(dati).hexdigest()


def _conferma_configurazione(validatore, identificatore, origine, tipo, precedenti,
                            volumi, validation, diagnostics):
    """Keep a transient failure only for an unchanged, previously accepted root.

    Owned JSON, symlink checks and ownership validation are still performed by
    the validator on every poll. Previous roots never authorize changed entries.
    """
    precedente = None
    if isinstance(precedenti, dict):
        confermati = {v.get("id") for v in precedenti.get("watch_status", [])
                      if isinstance(v, dict) and v.get("status") == "confirmed"}
        candidato = precedenti.get("validation", {}).get(identificatore)
        if (identificatore in confermati and isinstance(candidato, dict)
                and candidato.get("origine") == origine and candidato.get("tipo") == tipo):
            try:
                attuale = _identita_voce_configurazione(identificatore, origine, tipo)
            except (OSError, ValueError):
                pass
            else:
                if attuale == candidato:
                    precedente = candidato
    richiedi_esistente, avvisi = True, []
    try:
        while True:
            try:
                risultato = validatore(richiedi_esistente)
                break
            except _RifiutoConfigurazione as errore:
                if (errore.code == "folder_missing" and precedente is not None
                        and richiedi_esistente and not Path(origine).exists()):
                    richiedi_esistente = False
                    avvisi.append("folder_absent")
                elif (errore.code == "volume_validation_timeout" and precedente is not None
                      and "volume_validation_timeout" not in avvisi):
                    volumi["_timeout_consentiti"] = {precedente["volume"]}
                    avvisi.append("volume_validation_timeout")
                else:
                    raise
    finally:
        volumi.pop("_timeout_consentiti", None)
    if validation is not None:
        validation[identificatore] = _identita_voce_configurazione(identificatore, origine, tipo)
    esito = _esito_configurazione(identificatore)
    esito["configuration_token"] = _token_configurazione(identificatore, origine, tipo)
    if avvisi:
        esito.update(warning_code=avvisi[0], warning_message=AVVISI_CONFIGURAZIONE[avvisi[0]])
        if diagnostics is not None:
            diagnostics.extend({"id": identificatore, "code": code,
                                "message": AVVISI_CONFIGURAZIONE[code]} for code in avvisi)
    return risultato, esito


def leggi_cartelle(percorso, uid, esiti=None, volumi=None, precedenti=None,
                  validation=None, diagnostics=None):
    r = _leggi_json_posseduto(percorso, uid)
    if r is None:
        return []
    if not isinstance(r, dict) or r.get("versione") != 1 or not isinstance(r.get("cartelle"), dict):
        raise ValueError(_t("Il registro delle cartelle non è valido."))
    risultato = []
    volumi = volumi if volumi is not None else {}
    for identificatore, voce in r["cartelle"].items():
        try:
            if not isinstance(voce, dict) or voce.get("id") != identificatore:
                raise _RifiutoConfigurazione("invalid_entry")
            pulita = {k: _testo(voce.get(k)) for k in (
                "id", "nome", "origine", "bundle", "montaggio", "recupero_temporaneo", "montaggio_temporaneo",
                "backup", "plaintext_residuo")}
            if not pulita["id"] or any(not pulita[k] or not os.path.isabs(pulita[k]) for k in ("origine", "bundle", "montaggio")):
                raise _RifiutoConfigurazione("invalid_path")
            _, esito = _conferma_configurazione(
                lambda _: _valida_radici(pulita, uid, configurazione_validata=True, volumi=volumi),
                identificatore, pulita["origine"], "protetta", precedenti, volumi, validation, diagnostics)
            risultato.append(pulita)
            if esiti is not None:
                esiti.append(esito)
        except (OSError, ValueError) as errore:
            if esiti is None:
                raise
            code = errore.code if isinstance(errore, _RifiutoConfigurazione) else "invalid_path"
            esiti.append(_esito_configurazione(identificatore, code))
    return risultato


def _valida_radici(v, uid, configurazione_validata=False, volumi=None):
    home = Path(pwd.getpwuid(uid).pw_dir)
    identificatore = v["id"]
    if len(identificatore) != 32 or any(c not in "0123456789abcdef" for c in identificatore):
        raise ValueError(_t("L'identificatore della cartella non è valido."))
    fonte = Path(v["origine"])
    if fonte == home or fonte in home.parents or str(fonte) in ("/Users", "/Volumes", "/Library", "/private", "/private/tmp", "/private/var", "/Users/Shared"):
        raise ValueError(_t("Il registro rifiuta percorsi che includono più utenti o tutto il disco."))
    if v["montaggio"] != v["origine"]:
        raise ValueError(_t("Il montaggio deve corrispondere alla cartella protetta."))
    bundle = Path(v["bundle"])
    if bundle.name != "%s-%s.sparsebundle" % (fonte.name, identificatore):
        raise ValueError(_t("Il bundle non corrisponde alla cartella registrata."))
    backup = fonte.with_name("." + fonte.name + ".paratia-" + identificatore)
    if v.get("backup") is not None and Path(v["backup"]) != backup:
        raise ValueError(_t("Il backup non corrisponde alla cartella registrata."))
    if v.get("plaintext_residuo") is not None and v["plaintext_residuo"] not in (
            v["origine"], str(backup), v.get("recupero_temporaneo")):
        raise ValueError(_t("Il residuo plaintext non corrisponde alla cartella registrata."))
    for campo in ("origine", "bundle", "montaggio_temporaneo", "recupero_temporaneo", "backup", "plaintext_residuo"):
        testo = v.get(campo)
        if testo is None:
            continue
        p = Path(testo)
        if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
            raise ValueError(_t("Un percorso protetto non è canonico."))
        for q in [*reversed(p.parents), p]:
            try:
                s = q.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(s.st_mode):
                raise _RifiutoConfigurazione("symlink")
        if campo != "bundle" or p.exists():
            esistente = p if p.exists() else p.parent
            _cartella_posseduta_configurazione(esistente, uid, configurazione_validata, volumi)
        if campo == "montaggio_temporaneo":
            if p.parent != home / ".paratia" / "montaggi" or not (p.name.startswith(identificatore + "-") or p.name.startswith("recupero-")):
                raise ValueError(_t("Il montaggio temporaneo non è nell'area riservata dell'utente."))
        if campo == "recupero_temporaneo":
            if p.parent != fonte.parent or not p.name.startswith("." + fonte.name + ".recupero-"):
                raise ValueError(_t("Il recupero temporaneo non corrisponde alla cartella."))


def _valida_sorveglianza(p, uid, richiedi_esistente=True, configurazione_validata=False, volumi=None):
    if not isinstance(p, (str, Path)):
        raise ValueError(_t("Il percorso di sorveglianza non è valido."))
    p = Path(p)
    home = Path(pwd.getpwuid(uid).pw_dir)
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)) or p == home or p in home.parents:
        raise ValueError(_t("Scegli una singola cartella dell'utente."))
    if str(p) in ("/Users", "/Volumes", "/Library", "/private", "/private/tmp", "/private/var", "/Users/Shared"):
        raise ValueError(_t("Non è possibile sorvegliare una radice di sistema."))
    if any(p == base or base in p.parents or p in base.parents for base in (SYSTEM, SUPPORT)):
        raise ValueError(_t("Il registro non può sorvegliare i propri percorsi."))
    for q in [*reversed(p.parents), p]:
        try:
            s = q.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(s.st_mode):
            raise _RifiutoConfigurazione("symlink")
    if richiedi_esistente and not p.is_dir():
        raise _RifiutoConfigurazione("folder_missing")
    esistente = p if p.exists() else p.parent
    _cartella_posseduta_configurazione(esistente, uid, configurazione_validata, volumi)
    return str(p)


def leggi_sorveglianza(percorso, uid, esiti=None, rifiutate=None, volumi=None, precedenti=None,
                      validation=None, diagnostics=None):
    dati = _leggi_json_posseduto(percorso, uid)
    if dati is None:
        return []
    if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("percorsi"), dict):
        raise ValueError(_t("La sorveglianza non è valida."))
    risultati = []
    volumi = volumi if volumi is not None else {}
    for identificatore, voce in dati["percorsi"].items():
        try:
            if not _id_configurazione(identificatore) or not isinstance(voce, dict):
                raise _RifiutoConfigurazione("invalid_entry")
            if esiti is None:
                # Historical resolvers can still resolve a missing source.
                percorso = _valida_sorveglianza(voce.get("percorso", ""), uid,
                                                richiedi_esistente=False,
                                                configurazione_validata=True, volumi=volumi)
                esito = _esito_configurazione(identificatore)
            else:
                percorso, esito = _conferma_configurazione(
                    lambda esistente: _valida_sorveglianza(
                        voce.get("percorso", ""), uid, richiedi_esistente=esistente,
                        configurazione_validata=True, volumi=volumi),
                    identificatore, voce.get("percorso", ""), "sorveglianza",
                    precedenti, volumi, validation, diagnostics)
            risultati.append({"id": identificatore, "nome": _testo(voce.get("nome")) or Path(percorso).name,
                              "origine": percorso, "tipo": "sorveglianza"})
            if esiti is not None:
                esiti.append(esito)
        except (OSError, ValueError) as errore:
            if esiti is None:
                raise
            code = errore.code if isinstance(errore, _RifiutoConfigurazione) else "invalid_path"
            esiti.append(_esito_configurazione(identificatore, code))
            if rifiutate is not None and _id_configurazione(identificatore):
                raw_path = _testo(voce.get("percorso")) if isinstance(voce, dict) else None
                origine = raw_path if raw_path and os.path.isabs(raw_path) else ""
                nome = (_testo(voce.get("nome")) if isinstance(voce, dict) else None) or Path(origine).name or identificatore
                rifiutate.append({"id": identificatore, "nome": nome, "origine": origine,
                                  "tipo": "sorveglianza"})
    return risultati


def leggi_configurazione(home, uid, precedenti=None, cache_volumi=None):
    """Collector input: accepted roots plus a bounded, content-free ID report.

    Reject each unreadable/unowned file independently and remove its roots.
    Changed or invalid entries are removed. Previously confirmed roots retain
    transient absence/timeouts only with unchanged parent and kernel identity.
    """
    home = Path(home)
    persistenti = cache_volumi if cache_volumi is not None else {}
    voci, esiti, volumi = [], [], {"_persistenti": persistenti}
    validation, diagnostics = {}, []
    for loader, percorso in (
            (leggi_cartelle, home / ".paratia" / "cartelle.json"),
            (leggi_sorveglianza, home / ".paratia" / "registro" / "sorveglianza.json")):
        esiti_file = []
        try:
            valide = loader(percorso, uid, esiti=esiti_file, volumi=volumi,
                            precedenti=precedenti, validation=validation, diagnostics=diagnostics)
        except (OSError, ValueError):
            esiti.append(_esito_configurazione(None, "config_unreadable"))
        else:
            voci.extend(valide)
            esiti.extend(esiti_file)
    conteggi = {}
    for voce in esiti:
        if voce["id"] is not None:
            conteggi[voce["id"]] = conteggi.get(voce["id"], 0) + 1
    duplicati = {identificatore for identificatore, count in conteggi.items() if count > 1}
    if duplicati:
        voci = [voce for voce in voci if voce["id"] not in duplicati]
        esiti = [_esito_configurazione(voce["id"], "duplicate_id")
                 if voce["id"] in duplicati else voce for voce in esiti]
        validation = {k: v for k, v in validation.items() if k not in duplicati}
        diagnostics = [v for v in diagnostics if v["id"] not in duplicati]
    for identity in list(persistenti):
        if identity not in volumi.get("_visti", set()):
            del persistenti[identity]
    return {"voci": voci, "watch_status": esiti, "validation": validation,
            "diagnostics": diagnostics}


def _cambia_sorveglianza(identificatore, percorso=None, nome=""):
    directory = CASA / "registro"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(directory / "sorveglianza.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    p = directory / "sorveglianza.json"
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        dati = _leggi_json_posseduto(p, os.getuid()) or {"versione": 1, "percorsi": {}}
        if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("percorsi"), dict):
            raise ValueError(_t("La sorveglianza non è valida."))
        # Validate identifiers and paths before the atomic registry replacement.
        if not isinstance(identificatore, str) or not 1 <= len(identificatore) <= 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in identificatore):
            raise ValueError(_t("L'identificatore della sorveglianza non è valido."))
        if _testo(nome) is None:
            raise ValueError(_t("Il nome della sorveglianza non è valido."))
        riutilizzata = False
        rinominata = False
        if percorso is None:
            if identificatore not in dati["percorsi"]:
                raise ValueError(_t("L'identificatore non è configurato per la sorveglianza."))
            dati["percorsi"].pop(identificatore)
        else:
            percorso = _valida_sorveglianza(percorso, os.getuid())
            esiti_protette = []
            protette = leggi_cartelle(CASA / "cartelle.json", os.getuid(), esiti=esiti_protette)
            if any(percorso_normale(percorso) == percorso_normale(voce[campo])
                   for voce in protette for campo in ("origine", "montaggio")):
                raise ErroreRegistro("protected_folder_watch")
            voci = leggi_sorveglianza(p, os.getuid(), esiti=[])
            uguali = [v["id"] for v in voci if percorso_normale(v["origine"]) == percorso_normale(percorso)]
            if uguali:
                # Keep the original stable ID. Also repair duplicate legacy
                # watch entries for this exact path while holding the lock.
                identificatore = uguali[0]
                riutilizzata = True
                precedente = dati["percorsi"][identificatore].get("nome", "")
                if nome.strip():
                    nome = nome.strip()
                    rinominata = nome != (_testo(precedente) or Path(percorso).name)
                else:
                    # Callers that reuse a watch without a label, including the
                    # bank, preserve the person's existing name.
                    nome = _testo(precedente) or ""
                for duplicato in uguali[1:]:
                    dati["percorsi"].pop(duplicato)
            elif identificatore in dati["percorsi"]:
                raise ValueError(_t("L'identificatore appartiene a un'altra cartella. Rimuovilo prima di riutilizzarlo."))
            if any(v["id"] == identificatore for v in esiti_protette):
                raise _RifiutoConfigurazione("duplicate_id")
            dati["percorsi"][identificatore] = {"percorso": percorso, "nome": nome}
        fd, temporaneo = tempfile.mkstemp(dir=directory, prefix=".sorveglianza-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(dati, f, ensure_ascii=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporaneo, p)
        finally:
            if os.path.exists(temporaneo):
                os.unlink(temporaneo)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)
    salute = stato()
    attiva = bool(percorso is not None and _raccolta_pronta(salute)
                  and identificatore in _ids_confermati(salute))
    nome_accettato = (_testo(nome) or Path(percorso).name) if percorso is not None else None
    messaggio = (_t("Configurazione rimossa.") if percorso is None else
                 _t("Cartella configurata; il raccoglitore ha confermato la sorveglianza.") if attiva else
                 _t("Cartella configurata; raccolta non attiva o conferma del raccoglitore ancora assente."))
    if riutilizzata:
        messaggio += " " + (_t("Sorveglianza rinominata; ID conservato.") if rinominata else
                            _t("Sorveglianza esistente riutilizzata: ID e nome conservati."))
    raccolta = _raccolta_voce(salute, identificatore) if percorso is not None else {}
    if percorso is not None and raccolta["raccolta"] == "rifiutata":
        attiva = False
        messaggio = _t("Cartella configurata; ") + raccolta["message"]
    return {"id": identificatore, "percorso": percorso, "nome": nome_accettato,
            "configurata": percorso is not None,
            "sorvegliata": attiva, "raccolta_attiva": attiva, "riutilizzata": riutilizzata,
            "rinominata": rinominata,
            "rimossa": percorso is None, "messaggio": messaggio,
            **raccolta}


def sorveglia(identificatore, percorso, nome=""):
    return _cambia_sorveglianza(identificatore, str(percorso), nome)


def _raccolta_voce(salute, identificatore, esito_locale=None, token_locale=None):
    """Use only fixed messages, including when collector status is untrusted."""
    esito = next((v for v in salute.get("watch_status", []) if isinstance(v, dict)
                  and v.get("id") == identificatore), None) if isinstance(salute.get("watch_status", []), list) else None
    if esito and esito.get("status") == "rejected":
        code = esito.get("reason_code")
        code = code if isinstance(code, str) and code in ESITI_CONFIGURAZIONE else "invalid_entry"
        return {"raccolta": "rifiutata", "reason_code": code,
                "message": _t("Rifiutata dal raccoglitore: ") + ESITI_CONFIGURAZIONE[code]}
    if esito_locale and esito_locale.get("status") == "rejected":
        code = esito_locale["reason_code"]
        return {"raccolta": "rifiutata", "reason_code": code,
                "message": _t("Configurazione rifiutata: ") + ESITI_CONFIGURAZIONE[code]}
    if (esito and esito.get("status") == "confirmed") or identificatore in _ids_confermati(salute):
        result = {"raccolta": "confermata", "reason_code": None,
                  "message": _t("Cartella confermata dal raccoglitore.")}
        code = esito.get("warning_code") if esito else None
        if (isinstance(code, str) and code in AVVISI_CONFIGURAZIONE and token_locale is not None
                and esito.get("configuration_token") == token_locale):
            result.update(warning_code=code, warning_message=AVVISI_CONFIGURAZIONE[code],
                          message=AVVISI_CONFIGURAZIONE[code])
        return result
    return {"raccolta": "configurata", "reason_code": None,
            "message": _t("Cartella configurata; conferma del raccoglitore ancora assente.")}


def elenco_sorveglianza():
    """Read validated user watch configuration; never imply kernel coverage."""
    esiti, rifiutate = [], []
    voci = leggi_sorveglianza(CASA / "registro" / "sorveglianza.json", os.getuid(),
                            esiti=esiti, rifiutate=rifiutate)
    salute = stato()
    risultati = []
    esiti_per_id = {v["id"]: v for v in esiti if v["id"] is not None}
    for voce in [*voci, *rifiutate]:
        esito_locale = esiti_per_id.get(voce["id"])
        token = _token_configurazione(voce["id"], voce["origine"], "sorveglianza")
        remoto = next((v for v in salute.get("watch_status", []) if isinstance(v, dict)
                       and v.get("id") == voce["id"]), None) if isinstance(salute.get("watch_status"), list) else None
        if (esito_locale and esito_locale.get("reason_code") == "folder_missing"
                and remoto and remoto.get("status") == "confirmed"
                and remoto.get("warning_code") == "folder_absent"
                and remoto.get("configuration_token") == token):
            try:
                _valida_sorveglianza(voce["origine"], os.getuid(), richiedi_esistente=False,
                                    configurazione_validata=True)
            except (OSError, ValueError):
                pass
            else:
                esito_locale = None
        raccolta = _raccolta_voce(salute, voce["id"], esito_locale, token_locale=token)
        esiste = bool(voce["origine"] and Path(voce["origine"]).is_dir())
        risultati.append({**voce, "percorso": voce["origine"], "esiste": esiste,
                          "configuration_token": token,
                          "configurata": True, "raccolta_attiva": bool(_raccolta_pronta(salute)
                              and raccolta["raccolta"] != "rifiutata"
                              and voce["id"] in _ids_confermati(salute)
                              and (esiste or raccolta.get("warning_code") == "folder_absent")), **raccolta})
    return sorted(risultati, key=lambda voce: (voce["nome"].casefold(), voce["id"]))


def rimuovi_sorveglianza(identificatore):
    return _cambia_sorveglianza(identificatore)


def risolvi_cartella(cartella, solo_sorveglianza=False):
    """Resolve an exact configured folder path to its stable ID for every caller.

    IDs remain usable for historical records after their configuration is gone.
    Paths require a current watch or protected-folder entry; ambiguous legacy
    entries never silently choose an ID.
    """
    if cartella is None:
        return None
    if not isinstance(cartella, (str, Path)):
        raise ValueError(_t("Il filtro cartella richiede un ID o un percorso."))
    cartella = str(cartella)
    if not os.path.isabs(cartella):
        return cartella
    percorso = percorso_normale(cartella)
    voci = []
    loaders = [(leggi_sorveglianza, CASA / "registro" / "sorveglianza.json")]
    if not solo_sorveglianza:
        loaders.append((leggi_cartelle, CASA / "cartelle.json"))
    for loader, configurazione in loaders:
        try:
            voci.extend(loader(configurazione, os.getuid(), esiti=[]))
        except (OSError, ValueError):
            # A rejected configuration cannot authorize a path selector;
            # another independently valid file remains usable for queries.
            continue
    ids = {voce["id"] for voce in voci if any(isinstance(voce.get(k), str)
           and percorso == percorso_normale(voce[k]) for k in ("origine", "montaggio"))}
    if not ids:
        raise ErroreRegistro("folder_not_configured")
    if len(ids) != 1:
        raise ErroreRegistro("folder_ambiguous")
    return ids.pop()


def _raccolta_pronta(salute):
    return (salute.get("running") is True and salute.get("healthy") is True
            and salute.get("needs_fda") is False and salute.get("schema_supported") is not False)


def _ids_confermati(salute):
    valori = salute.get("watched_ids", [])
    return {identifier for identifier in valori if isinstance(identifier, str) and len(identifier) <= 128} if isinstance(valori, list) else set()


def raccolta_kernel(filters=None):
    """Describe collection now; neither health nor an ID ACK proves coverage."""
    folder = risolvi_cartella((filters or {}).get("folder"))
    salute = stato()
    running = salute.get("running") is True
    healthy = salute.get("healthy") is True
    needs_fda = salute.get("needs_fda") if type(salute.get("needs_fda")) is bool else None
    supported = salute.get("schema_supported") if type(salute.get("schema_supported")) is bool else None
    ids = _ids_confermati(salute)
    acknowledged = folder in ids if folder else None
    watched = _stati_sorveglianza(salute.get("watch_status"))
    selected = next((value for value in watched if value["id"] == folder and value["status"] == "rejected"), None)
    if selected:
        acknowledged = False
    active = _raccolta_pronta(salute) and acknowledged is not False
    if selected:
        message = _t("Cartella rifiutata dal raccoglitore: ") + selected["message"]
    elif not running:
        message = _t("Raccolta kernel non attiva. Un elenco vuoto non prova l'assenza di accessi.")
    elif not healthy or supported is False:
        message = _t("Raccolta kernel non sana. I risultati restano consultabili, ma la copertura non è confermata.")
    elif needs_fda is not False:
        message = _t("Raccolta kernel non confermata: Accesso completo al disco non verificato.")
    elif acknowledged is False:
        message = _t("Cartella configurata; il raccoglitore non ha ancora confermato questo ID. Un elenco vuoto non prova l'assenza di accessi.")
    elif not ids:
        message = _t("Raccolta kernel attiva; nessuna cartella confermata. Un elenco vuoto non prova l'assenza di accessi.")
    else:
        message = _t("Raccolta kernel attiva. Gli eventi mancanti non provano l'assenza di accessi.")
    return {"kernel_active": bool(active), "kernel_collection": {
        "running": running, "healthy": healthy, "needs_fda": needs_fda,
        "schema_supported": supported, "folder_id": folder or None,
        "acknowledged": acknowledged, "watched_count": len(ids),
        "drop_detection_available": salute.get("drop_detection_available") is True,
        "dropped_events": _intero(salute.get("dropped_events")),
        "last_dropped_at": _numero_finito(salute.get("last_dropped_at")),
        "watch_status": watched, "health_reasons": salute.get("health_reasons", []),
        "event_lag_seconds": _numero_finito(salute.get("event_lag_seconds")),
        "last_event_received_at": _numero_finito(salute.get("last_event_received_at")),
        "last_event_age_seconds": _numero_finito(salute.get("last_event_age_seconds")),
        "lines_per_second": _numero_finito(salute.get("lines_per_second")),
        "raw_lines": _intero(salute.get("raw_lines")),
        "filtered_lines": _intero(salute.get("filtered_lines")),
        "parsed_lines": _intero(salute.get("parsed_lines")),
        "coverage_guaranteed": False, "message": message}}


def annota(evento, **metadata):
    permessi = {"id", "cartella", "origine", "bundle", "percorso", "file", "byte", "minutes", "minuti",
                "esito", "errno", "rc", "fase", "nome", "processo", "pid", "uid", "agente",
                "nome_agente", "evidenza_agente", "folder", "operazione", "azione", "fonte",
                "app_responsabile", "utente"}
    r = {k: v for k, v in metadata.items() if k in permessi and isinstance(v, (str, int, float, bool, type(None)))}
    r["cartella"] = r.get("cartella", r.get("id"))
    r["percorso"] = r.get("percorso", r.get("origine", r.get("bundle")))
    r.setdefault("processo", sys.executable)
    r.setdefault("utente", pwd.getpwuid(os.getuid()).pw_name)
    if r["percorso"] is None and r["cartella"]:
        try:
            protetti = leggi_cartelle(CASA / "cartelle.json", os.getuid())
            voce = next((v for v in protetti if v["id"] == r["cartella"]), {})
            r["percorso"] = voce.get("montaggio")
        except (OSError, ValueError):
            pass
    return appendi(CATENA, {**r, "source": "paratia", "sorgente": "paratia", "evento": str(evento),
                           "pid": r.get("pid", os.getpid()), "uid": r.get("uid", os.getuid())})


def _catene():
    return [CATENA, SYSTEM / str(os.getuid()) / "catena.jsonl"]


def _data(v):
    if not v:
        return None
    testo = str(v).replace("Z", "+00:00")
    # Python 3.9 accepts colon-separated UTC offsets, unlike the historical
    # strftime %z writer. Preserve old rows without rewriting their hash chain.
    testo = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", testo)
    return datetime.datetime.fromisoformat(testo).timestamp()


def _corrisponde_file(filtro, valore):
    if not isinstance(valore, str):
        return False
    filtro = str(filtro)
    if os.path.isabs(filtro):
        if not os.path.isabs(valore):
            return False
        radice, percorso = percorso_normale(filtro), percorso_normale(valore)
        return percorso == radice or percorso.startswith(radice.rstrip("/") + "/")
    return unicodedata.normalize("NFC", filtro).casefold() in unicodedata.normalize("NFC", valore).casefold()


def query(filters=None):
    filters = filters or {}
    folder = risolvi_cartella(filters.get("folder"))
    risultati = []
    for p in _catene():
        if not p.exists():
            continue
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            fcntl.flock(fd, fcntl.LOCK_SH)
            for riga in f:
                if len(riga) > 1048576:
                    raise ValueError(_t("Una riga del registro è troppo grande."))
                if not riga.strip():
                    continue
                r = json.loads(riga)
                if not isinstance(r, dict):
                    raise ValueError(_t("Il registro contiene una riga non valida."))
                if folder and folder not in (r.get("id"), r.get("cartella")) and not any(folder in (c.get("id"), c.get("nome")) for c in r.get("cartelle", [])):
                    continue
                if filters.get("file") and not any(_corrisponde_file(filters["file"], r.get(k)) for k in ("percorso", "destinazione", "origine")):
                    continue
                if filters.get("process") and str(filters["process"]).lower() not in (str(r.get("processo", "")) + " " + str(r.get("app_responsabile", ""))).lower() and str(filters["process"]) != str(r.get("pid")):
                    continue
                agente = filters.get("agent")
                if agente is not None and agente != "":
                    desiderato = {"true": True, "false": False, "unknown": None, "sconosciuto": None}.get(str(agente).lower(), agente)
                    if desiderato in (True, False, None):
                        if r.get("agente") is not desiderato:
                            continue
                    elif str(agente).lower() not in str(r.get("nome_agente", "")).lower():
                        continue
                timestamp = _data(r.get("quando"))
                if filters.get("since") and (timestamp is None or timestamp < _data(filters["since"])):
                    continue
                if filters.get("until") and (timestamp is None or timestamp > _data(filters["until"])):
                    continue
                risultati.append(r)
    return sorted(risultati, key=lambda r: _data(r.get("quando")) or 0, reverse=True)


def export_csv(filters=None):
    campi = ["quando", "sorgente", "source", "evento", "cartella", "percorso", "destinazione", "processo", "pid", "pidversion",
             "uid", "utente", "app_responsabile", "agente", "nome_agente", "esito", "errno", "rc", "precedente"]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=campi, extrasaction="ignore")
    writer.writeheader()
    for r in query(filters):
        # Spreadsheet programs must not interpret a file name as a formula.
        writer.writerow({k: "'" + v if isinstance(v, str) and (v.startswith(("\t", "\r", "\n")) or v.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))) else v
                         for k, v in r.items() if k in campi})
    return output.getvalue()


def verifica():
    esiti = [{"source": "paratia" if i == 0 else "eslogger", **verifica_catena(p)} for i, p in enumerate(_catene())]
    return {"ok": all(r["ok"] for r in esiti), "catene": esiti, "limite": LIMITI[4]}


def _servizio_installato(uid):
    p = Path("/Library/LaunchDaemons/%s.%d.plist" % (ETICHETTA, uid))
    installed = False
    arguments = []
    try:
        s = p.lstat()
        installed = stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
        if installed:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                s = os.fstat(fd)
                if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or s.st_size > 65536:
                    raise ValueError(_t("Il servizio non ha una configurazione protetta."))
                document = plistlib.loads(stream.read(65537))
                if isinstance(document, dict):
                    arguments = document.get("ProgramArguments", [])
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    launcher = str(SUPPORT / "Paratia.app" / "Contents" / "MacOS" / "Paratia")
    if arguments == [launcher, "--registro", "--uid", str(uid)]:
        mode = "app"
    elif isinstance(arguments, list) and arguments and isinstance(arguments[0], str) and "python" in Path(arguments[0]).name.lower():
        mode = "legacy-python"
    else:
        mode = "unrecognized" if installed else "missing"
    return installed, mode


PASSI_AGGIORNAMENTO = (
    _t("Chiudi Paratia e le eventuali copie di bootstrap aperte."),
    _t("Prepara di nuovo /Library/Application Support/ParatiaBootstrap.noindex/Paratia.app con l'unico comando sudo mostrato dall'app: dopo la verifica della firma elimina il vecchio bootstrap e le cartelle .prepara. Non cambiare i permessi di /Applications."),
    _t("Apri la copia di bootstrap dal Finder e usa Impostazioni → Installa il registro… → Autorizza con macOS."),
    _t("Chiudi la copia di bootstrap dopo l'installazione."),
    _t("In Privacy e Sicurezza → Accesso completo al disco, controlla che /Applications/Paratia.app sia abilitata. Se la firma è cambiata, rimuovi e aggiungi di nuovo la voce. Non autorizzare Python."),
    _t("Riapri /Applications/Paratia.app e premi Aggiorna: controlla servizio attivo, motivi di salute, conferma degli ID e un nuovo evento eslogger."),
)


def _numero_finito(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
        try:
            return value if math.isfinite(value) else None
        except OverflowError:
            pass
    return None


def _cdhash_app(app):
    """Read a fixed bundle identity; never sign or access the keychain."""
    if str(app) not in ("/Applications/Paratia.app", str(SUPPORT / "Paratia.app")):
        return None
    try:
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)],
                                capture_output=True, text=True, timeout=2)
        details = result.stdout + result.stderr
        if result.returncode != 0 or len(details) > 65536:
            return None
        if re.findall(r"^Identifier=(.+)$", details, re.MULTILINE) != ["it.paratia.app"]:
            return None
        hashes = re.findall(r"^CDHash=([0-9a-fA-F]{40,64})$", details, re.MULTILINE)
        return hashes[0].lower() if len(hashes) == 1 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _identita_build(value):
    return value.lower() if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{40,64}", value) else None


def _aggiornamento_build(dati, installed):
    previous = _identita_build(dati.get("installed_cdhash"))
    current = _cdhash_app("/Applications/Paratia.app") if installed else None
    comparison = "different" if previous and current and previous != current else (
        "equal" if previous and current else "unavailable")
    # The older collector has no identity field. Its root-only service bundle
    # cannot be inspected by this user's GUI: request an update honestly rather
    # than pretending to have compared two hashes.
    required = (comparison == "different" or (installed and previous is None))
    message = (_t("Il servizio installato appartiene a una build diversa da /Applications/Paratia.app.")
               if comparison == "different" else
               _t("Identità della build installata non disponibile: aggiorna il registro per verificarla.")
               if required else
               _t("Il servizio e l'app normale appartengono alla stessa build.") if comparison == "equal" else
               _t("Non è possibile confrontare le identità delle build. Verifica la nuova app normale prima di aggiornare."))
    return {"installed_cdhash": previous, "app_cdhash": current,
            "build_comparison": comparison, "needs_update": required if installed else False,
            "update_message": message, "update_steps": list(PASSI_AGGIORNAMENTO)}


def _stati_sorveglianza(values):
    """Only fixed reasons enter the GUI; never reflect strings from a state file."""
    result = []
    if not isinstance(values, list):
        return result
    reasons = globals().get("ESITI_CONFIGURAZIONE", {})
    for value in values:
        if not isinstance(value, dict):
            continue
        status = value.get("status")
        if status not in ("confirmed", "rejected"):
            continue
        identifier = value.get("id")
        if identifier is not None or status != "rejected":
            if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
                continue
        code = value.get("reason_code") if status == "rejected" else None
        if not isinstance(code, str) or code not in reasons:
            code = "invalid_entry" if status == "rejected" else None
        message = reasons.get(code, _t("La cartella non è stata accettata dal raccoglitore.")) if status == "rejected" else _t("Cartella confermata dal raccoglitore.")
        record = {"id": identifier, "status": status, "reason_code": code, "message": message}
        if status == "confirmed":
            warning = value.get("warning_code")
            warnings = globals().get("AVVISI_CONFIGURAZIONE", {})
            if isinstance(warning, str) and warning in warnings:
                record.update(warning_code=warning, warning_message=warnings[warning])
            token = value.get("configuration_token")
            if isinstance(token, str) and re.fullmatch(r"[0-9a-f]{64}", token):
                record["configuration_token"] = token
        result.append(record)
    return result


def _perdita_recente(dati, ora):
    """True only for a loss timestamp inside the reporting window.

    A timestamp more than a minute in the future is invalid, not a permanent
    warning. ``dropped_events`` stays the cumulative count in the state file.
    """
    ultima = _numero_finito(dati.get("last_dropped_at"))
    return ultima is not None and ora - PERDITE_RECENTI_SECONDI < ultima <= ora + 60


def motivi_salute(dati, ora=None):
    """Explain observed problems without treating an idle stream as a delay.

    ``ora`` is the wall-clock time used for the loss window; tests pass it
    explicitly, the daemon and stato() leave it to time.time().
    """
    ora = time.time() if ora is None else ora
    reasons = []
    def add(code, message):
        reasons.append({"code": code, "message": message})
    if dati.get("running") is not True:
        add("not_running", _t("Il raccoglitore non è attivo o non ha ancora ricevuto eventi."))
    if dati.get("needs_fda") is True:
        add("needs_fda", _t("Accesso completo al disco non confermato per /Applications/Paratia.app."))
    lag = _numero_finito(dati.get("event_lag_seconds"))
    if lag is not None and lag > 2:
        add("event_delay", _t("Gli ultimi eventi ricevuti erano in ritardo di oltre 2 secondi."))
    if _perdita_recente(dati, ora):
        add("dropped_events", _t("Endpoint Security ha perso eventi negli ultimi %d minuti: la copertura di quel periodo è incompleta.") % (PERDITE_RECENTI_SECONDI // 60))
    rejected = [value for value in _stati_sorveglianza(dati.get("watch_status")) if value["status"] == "rejected"]
    if rejected:
        add("rejected_watches", _t("Il raccoglitore ha rifiutato una o più cartelle: consulta il motivo per ciascun ID."))
        anonymous = set()
        for value in rejected:
            if value["id"] is None and value["reason_code"] not in anonymous:
                anonymous.add(value["reason_code"])
                add("watch_" + value["reason_code"], value["message"])
    if not _ids_confermati(dati):
        add("no_watched_folders", _t("Nessuna cartella è confermata dal raccoglitore."))
    if dati.get("schema_supported") is False:
        add("schema_unsupported", _t("Il formato di eslogger non è supportato: aggiorna Paratia."))
    if dati.get("healthy") is not True and not reasons:
        add("diagnostics", _t("Il raccoglitore segnala una copertura incompleta: consulta i diagnostici."))
    return reasons


def _modo_firma_app():
    """Solo lettura: 'adhoc' o 'stabile' per /Applications/Paratia.app; None se non verificabile.

    Stessi controlli di _cdhash_app: codice di uscita 0, identificatore it.paratia.app,
    poi una riga Signature=adhoc oppure una catena Authority senza riga adhoc.
    Un errore di lettura o di decodifica (ValueError include UnicodeDecodeError) dà None.
    """
    try:
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", "/Applications/Paratia.app"],
                                capture_output=True, text=True, timeout=2)
        dettagli = result.stdout + result.stderr
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or len(dettagli) > 65536:
        return None
    if re.findall(r"^Identifier=(.+)$", dettagli, re.MULTILINE) != ["it.paratia.app"]:
        return None
    firme = re.findall(r"^Signature=(.+)$", dettagli, re.MULTILINE)
    if firme == ["adhoc"]:
        return "adhoc"
    if not firme and re.findall(r"^Authority=.+$", dettagli, re.MULTILINE):
        return "stabile"
    return None


def stato():
    uid = os.getuid()
    dati = {}
    try:
        p = SYSTEM / str(uid) / "stato.json"
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            fcntl.flock(fd, fcntl.LOCK_SH)
            if os.fstat(fd).st_size <= 4194304:
                dati = json.loads(f.read(4194305))
    except (OSError, ValueError):
        pass
    if not isinstance(dati, dict):
        dati = {}
    installed, mode = _servizio_installato(uid)
    now = time.time()
    heartbeat = _numero_finito(dati.get("heartbeat"))
    fresco = heartbeat is not None and 0 <= now - heartbeat < 20
    locale = verifica_catena(CATENA)
    messaggio_servizio = dati.get("message")
    message = _t(messaggio_servizio) if isinstance(messaggio_servizio, str) else _t("Installa il registro e concedi Accesso completo al disco a /Applications/Paratia.app.")
    if installed and mode != "app":
        message = _t("Il servizio installato usa un avvio precedente. Premi Installa il registro in Paratia per passare al binario dell'app; non concedere Accesso completo al disco a Python.")
    # Con un'identità stabile il permesso resta valido: va rifatto solo con firma ad hoc.
    firma_app = _modo_firma_app()
    regrant = firma_app != "stabile"
    result = {"installed": installed, "running": bool(fresco and dati.get("running") is True),
            "healthy": bool(fresco and dati.get("healthy") is True), "needs_root": not installed,
            "launch_mode": mode, "needs_reinstall": installed and mode != "app",
            "fda_entry": "/Applications/Paratia.app", "fda_regrant_after_build": regrant,
            "firma": firma_app if firma_app in ("adhoc", "stabile") else "non-verificata",
            "fda_message": (_t("Dopo l'installazione abilita /Applications/Paratia.app in Accesso completo al disco. Con firma ad hoc, dopo ogni nuova build rimuovi e aggiungi di nuovo l'app. Python non va autorizzato.") if regrant else _t("Dopo l'installazione abilita /Applications/Paratia.app in Accesso completo al disco. Con firma stabile il permesso resta valido finché l'app viene firmata con lo stesso certificato. Python non va autorizzato.")),
            "needs_fda": dati.get("needs_fda") if fresco and isinstance(dati.get("needs_fda"), bool) else None,
            "dropped_events": _intero(dati.get("dropped_events")),
            "last_dropped_at": _numero_finito(dati.get("last_dropped_at")), "limits": list(LIMITI),
            "drop_detection_available": dati.get("drop_detection_available") is True,
            "watched_ids": sorted(_ids_confermati(dati)) if fresco else [],
            "watch_status": _stati_sorveglianza(dati.get("watch_status")) if fresco else [],
            "diagnostic_counts": dati.get("diagnostic_counts", {}),
            "schema_supported": dati.get("schema_supported"),
            "local_chain_ok": locale["ok"], "local_chain_error": locale["errore"],
            "message": message}
    for field in ("event_lag_seconds", "last_event_received_at", "lines_per_second",
                  "raw_lines", "filtered_lines", "parsed_lines"):
        result[field] = _numero_finito(dati.get(field)) if fresco else None
    received = result["last_event_received_at"]
    result["last_event_age_seconds"] = max(0.0, now - received) if received is not None and received <= now else None
    result.update(_aggiornamento_build(dati, installed))
    reasons = motivi_salute(result, now)
    if not fresco:
        reasons.insert(0, {"code": "stale_state", "message": _t("Lo stato del raccoglitore non è recente o non è leggibile.")})
    if result["needs_update"]:
        reasons.append({"code": "build_outdated", "message": result["update_message"]})
        result["needs_reinstall"] = True
    result["health_reasons"] = reasons
    result["healthy"] = result["healthy"] and not reasons
    return result
