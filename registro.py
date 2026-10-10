"""Metadata-only access records and a conservative Endpoint Security adapter.

Compatible with the system Python 3.9 used by the privileged daemon. No file
contents, command arguments, environment variables, or transcripts are read.
"""
from __future__ import annotations

import csv
import datetime
import fcntl
import io
import importlib.util
import json
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
EVENTI = ("open", "close", "write", "create", "rename", "unlink", "mount",
          "unmount", "mmap", "truncate", "lookup", "exec", "fork", "exit")
# Values are from Apple's ESTypes.h; old values are never renumbered.
NUMERI = {9: "exec", 10: "open", 11: "fork", 12: "close", 13: "create",
          15: "exit", 20: "mmap", 22: "mount", 23: "unmount", 25: "rename",
          32: "unlink", 33: "write", 41: "truncate", 43: "lookup"}
LIMITI = [
    "Un'apertura per lettura non prova una lettura dei byte: ES non registra ogni read().",
    "I tentativi falliti, incluso ENOENT, non sono osservabili tutti; gli esiti ES non sono errno.",
    "La discendenza può essere sconosciuta, specialmente per processi già avviati.",
    "eslogger ha uno schema non stabile e può perdere eventi; i buchi vengono segnalati.",
    "La catena rileva modifiche interne; non prova da sola che la coda non sia stata troncata.",
    "Il registro locale delle operazioni GUI è modificabile dall'utente; quello kernel è root-owned.",
]


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


def _processo(p):
    p = p if isinstance(p, dict) else {}
    a = p.get("audit_token", {})
    a = a if isinstance(a, dict) else {}
    uid = _intero(a.get("euid", a.get("uid")))
    nome = None
    if uid is not None:
        try:
            nome = pwd.getpwuid(uid).pw_name
        except (KeyError, OverflowError):
            pass
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

    def ricorda(self, p):
        identita = _identita(p)
        if identita:
            # Do not keep exec arguments, environment, or the original process object.
            self.processi[identita] = {**_processo(p), "nome_agente": _agente(p),
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
        candidato, pid = None, _processo(p)["pid"]
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
    if tipo not in EVENTI or expected != tipo or not isinstance(e[tipo], dict):
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
         **_processo(p), **ancestry.classifica(p), **ancestry.responsabile(p)}
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
    def __init__(self, protetti, sink, snapshot=None):
        self.protetti, self.sink = protetti, sink
        self.discendenza = Discendenza(snapshot)
        self.sequenze, self.globale = {}, None
        self.sano, self.persi = True, 0
        self.rileva_perdite = False
        self.diagnostici = {}
        self.schema_fatale = False

    def ricevi(self, msg):
        records = normalizza(msg, self.discendenza)
        if any(r.get("evento") == "diagnostico" for r in records):
            self.sano = False
        self.schema_fatale = self.schema_fatale or any(r.get("motivo") == "schema-eslogger-non-supportato" for r in records)
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
                self.persi += persi
                records.insert(0, _diagnostico("eventi-persi" if persi else "sequenza-riavviata", persi=persi))
                self.sano = False
            if globale is not None:
                self.globale = globale
            if sequenza is not None and isinstance(tipo, (str, int)):
                self.sequenze[tipo] = sequenza
        if len(self.discendenza.processi) > 50000:
            self.discendenza.processi.clear()
            records.insert(0, _diagnostico("cache-discendenza-azzerata"))
            self.sano = False
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
        raise ValueError("Il registro richiede un percorso assoluto.")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for parte in p.parts[1:-1]:
            nuovo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = nuovo
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as f:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != uid or s.st_size > 4194304:
                raise ValueError("Il registro delle cartelle non ha formato o proprietario validi.")
            dati = f.read(4194305)
            if len(dati) > 4194304:
                raise ValueError("Il registro delle cartelle è troppo grande.")
            r = json.loads(dati)
    except FileNotFoundError:
        return None
    finally:
        os.close(directory)
    return r


def leggi_cartelle(percorso, uid):
    r = _leggi_json_posseduto(percorso, uid)
    if r is None:
        return []
    if not isinstance(r, dict) or r.get("versione") != 1 or not isinstance(r.get("cartelle"), dict):
        raise ValueError("Il registro delle cartelle non è valido.")
    risultato = []
    for identificatore, voce in r["cartelle"].items():
        if not isinstance(voce, dict) or voce.get("id") != identificatore:
            raise ValueError("Una cartella del registro non è valida.")
        pulita = {k: _testo(voce.get(k)) for k in (
            "id", "nome", "origine", "bundle", "montaggio", "recupero_temporaneo", "montaggio_temporaneo",
            "backup", "plaintext_residuo")}
        if not pulita["id"] or any(not pulita[k] or not os.path.isabs(pulita[k]) for k in ("origine", "bundle", "montaggio")):
            raise ValueError("I percorsi della cartella non sono validi.")
        _valida_radici(pulita, uid)
        risultato.append(pulita)
    return risultato


def _valida_radici(v, uid):
    home = Path(pwd.getpwuid(uid).pw_dir)
    identificatore = v["id"]
    if len(identificatore) != 32 or any(c not in "0123456789abcdef" for c in identificatore):
        raise ValueError("L'identificatore della cartella non è valido.")
    fonte = Path(v["origine"])
    if fonte == home or fonte in home.parents or str(fonte) in ("/Users", "/Volumes", "/Library", "/private", "/private/tmp", "/private/var", "/Users/Shared"):
        raise ValueError("Il registro rifiuta percorsi che includono più utenti o tutto il disco.")
    if v["montaggio"] != v["origine"]:
        raise ValueError("Il montaggio deve corrispondere alla cartella protetta.")
    bundle = Path(v["bundle"])
    if bundle.name != "%s-%s.sparsebundle" % (fonte.name, identificatore):
        raise ValueError("Il bundle non corrisponde alla cartella registrata.")
    backup = fonte.with_name("." + fonte.name + ".paratia-" + identificatore)
    if v.get("backup") is not None and Path(v["backup"]) != backup:
        raise ValueError("Il backup non corrisponde alla cartella registrata.")
    if v.get("plaintext_residuo") is not None and v["plaintext_residuo"] not in (
            v["origine"], str(backup), v.get("recupero_temporaneo")):
        raise ValueError("Il residuo plaintext non corrisponde alla cartella registrata.")
    for campo in ("origine", "bundle", "montaggio_temporaneo", "recupero_temporaneo", "backup", "plaintext_residuo"):
        testo = v.get(campo)
        if testo is None:
            continue
        p = Path(testo)
        if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
            raise ValueError("Un percorso protetto non è canonico.")
        for q in [*reversed(p.parents), p]:
            try:
                s = q.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(s.st_mode):
                raise ValueError("Il registro rifiuta percorsi con collegamenti simbolici.")
        if campo != "bundle" or p.exists():
            esistente = p if p.exists() else p.parent
            if not esistente.is_dir() or esistente.stat().st_uid != uid:
                raise ValueError("La cartella protetta deve appartenere all'utente del registro.")
        if campo == "montaggio_temporaneo":
            if p.parent != home / ".paratia" / "montaggi" or not (p.name.startswith(identificatore + "-") or p.name.startswith("recupero-")):
                raise ValueError("Il montaggio temporaneo non è nell'area riservata dell'utente.")
        if campo == "recupero_temporaneo":
            if p.parent != fonte.parent or not p.name.startswith("." + fonte.name + ".recupero-"):
                raise ValueError("Il recupero temporaneo non corrisponde alla cartella.")


def _valida_sorveglianza(p, uid, richiedi_esistente=True):
    if not isinstance(p, (str, Path)):
        raise ValueError("Il percorso di sorveglianza non è valido.")
    p = Path(p)
    home = Path(pwd.getpwuid(uid).pw_dir)
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)) or p == home or p in home.parents:
        raise ValueError("Scegli una singola cartella dell'utente.")
    if str(p) in ("/Users", "/Volumes", "/Library", "/private", "/private/tmp", "/private/var", "/Users/Shared"):
        raise ValueError("Non è possibile sorvegliare una radice di sistema.")
    if any(p == base or base in p.parents or p in base.parents for base in (SYSTEM, SUPPORT)):
        raise ValueError("Il registro non può sorvegliare i propri percorsi.")
    for q in [*reversed(p.parents), p]:
        try:
            s = q.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(s.st_mode):
            raise ValueError("La sorveglianza rifiuta i collegamenti simbolici.")
    if richiedi_esistente and not p.is_dir():
        raise ValueError("Scegli una cartella esistente da configurare per la sorveglianza.")
    esistente = p if p.exists() else p.parent
    if not esistente.is_dir() or esistente.stat().st_uid != uid:
        raise ValueError("La cartella da sorvegliare deve appartenere all'utente.")
    return str(p)


def leggi_sorveglianza(percorso, uid):
    dati = _leggi_json_posseduto(percorso, uid)
    if dati is None:
        return []
    if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("percorsi"), dict):
        raise ValueError("La sorveglianza non è valida.")
    risultati = []
    for identificatore, voce in dati["percorsi"].items():
        if not isinstance(identificatore, str) or not 1 <= len(identificatore) <= 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in identificatore) or not isinstance(voce, dict):
            raise ValueError("Una sorveglianza non è valida.")
        # A configured source may briefly disappear during migration or later
        # be removed. Reading its metadata is distinct from adding a new watch.
        percorso = _valida_sorveglianza(voce.get("percorso", ""), uid, richiedi_esistente=False)
        risultati.append({"id": identificatore, "nome": _testo(voce.get("nome")) or Path(percorso).name,
                          "origine": percorso, "tipo": "sorveglianza"})
    return risultati


def _cambia_sorveglianza(identificatore, percorso=None, nome=""):
    directory = CASA / "registro"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(directory / "sorveglianza.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    p = directory / "sorveglianza.json"
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        dati = _leggi_json_posseduto(p, os.getuid()) or {"versione": 1, "percorsi": {}}
        if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("percorsi"), dict):
            raise ValueError("La sorveglianza non è valida.")
        # Validate identifiers and paths before the atomic registry replacement.
        if not isinstance(identificatore, str) or not 1 <= len(identificatore) <= 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in identificatore):
            raise ValueError("L'identificatore della sorveglianza non è valido.")
        riutilizzata = False
        if percorso is None:
            if identificatore not in dati["percorsi"]:
                raise ValueError("L'identificatore non è configurato per la sorveglianza.")
            dati["percorsi"].pop(identificatore)
        else:
            percorso = _valida_sorveglianza(percorso, os.getuid())
            voci = leggi_sorveglianza(p, os.getuid())
            uguali = [v["id"] for v in voci if percorso_normale(v["origine"]) == percorso_normale(percorso)]
            if uguali:
                # Keep the original stable ID. Also repair duplicate legacy
                # watch entries for this exact path while holding the lock.
                identificatore = uguali[0]
                riutilizzata = True
                # Reusing a request must preserve the person's label, including
                # when the bank temporarily needs that same watched path.
                nome = dati["percorsi"][identificatore].get("nome", "")
                for duplicato in uguali[1:]:
                    dati["percorsi"].pop(duplicato)
            elif identificatore in dati["percorsi"]:
                raise ValueError("L'identificatore appartiene a un'altra cartella. Rimuovilo prima di riutilizzarlo.")
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
    attiva = bool(percorso is not None and salute["running"] and salute["healthy"]
                  and identificatore in salute.get("watched_ids", []))
    nome_accettato = (_testo(nome) or Path(percorso).name) if percorso is not None else None
    messaggio = ("Configurazione rimossa." if percorso is None else
                 "Cartella configurata; il raccoglitore ha confermato la sorveglianza." if attiva else
                 "Cartella configurata; raccolta non attiva o conferma del raccoglitore ancora assente.")
    if riutilizzata:
        messaggio += " Sorveglianza esistente riutilizzata: ID e nome conservati."
    return {"id": identificatore, "percorso": percorso, "nome": nome_accettato,
            "configurata": percorso is not None,
            "sorvegliata": attiva, "raccolta_attiva": attiva, "riutilizzata": riutilizzata,
            "rimossa": percorso is None, "messaggio": messaggio}


def sorveglia(identificatore, percorso, nome=""):
    return _cambia_sorveglianza(identificatore, str(percorso), nome)


def elenco_sorveglianza():
    """Read validated user watch configuration; never imply kernel coverage."""
    voci = leggi_sorveglianza(CASA / "registro" / "sorveglianza.json", os.getuid())
    salute = stato()
    return sorted(({**voce, "percorso": voce["origine"], "esiste": Path(voce["origine"]).is_dir(),
                    "configurata": True, "raccolta_attiva": bool(salute["running"] and salute["healthy"]
                        and voce["id"] in salute.get("watched_ids", []) and Path(voce["origine"]).is_dir())}
                   for voce in voci), key=lambda voce: (voce["nome"].casefold(), voce["id"]))


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
        raise ValueError("Il filtro cartella richiede un ID o un percorso.")
    cartella = str(cartella)
    if not os.path.isabs(cartella):
        return cartella
    percorso = percorso_normale(cartella)
    voci = leggi_sorveglianza(CASA / "registro" / "sorveglianza.json", os.getuid())
    if not solo_sorveglianza:
        voci += leggi_cartelle(CASA / "cartelle.json", os.getuid())
    ids = {voce["id"] for voce in voci if any(isinstance(voce.get(k), str)
           and percorso == percorso_normale(voce[k]) for k in ("origine", "montaggio"))}
    if not ids:
        raise ValueError("La cartella non è configurata nel registro. Sorvegliala prima o usa il suo ID.")
    if len(ids) != 1:
        raise ValueError("Il percorso corrisponde a più ID. Scegli un ID dall'elenco delle cartelle sorvegliate.")
    return ids.pop()


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
                    raise ValueError("Una riga del registro è troppo grande.")
                if not riga.strip():
                    continue
                r = json.loads(riga)
                if not isinstance(r, dict):
                    raise ValueError("Il registro contiene una riga non valida.")
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
                    raise ValueError("Il servizio non ha una configurazione protetta.")
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


def stato():
    uid = os.getuid()
    dati = {}
    try:
        p = SYSTEM / str(uid) / "stato.json"
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            fcntl.flock(fd, fcntl.LOCK_SH)
            if os.fstat(fd).st_size <= 65536:
                dati = json.loads(f.read(65537))
    except (OSError, ValueError):
        pass
    if not isinstance(dati, dict):
        dati = {}
    installed, mode = _servizio_installato(uid)
    fresco = isinstance(dati, dict) and isinstance(dati.get("heartbeat"), (int, float)) and time.time() - dati.get("heartbeat", 0) < 20
    locale = verifica_catena(CATENA)
    message = dati.get("message", "Installa il registro e concedi Accesso completo al disco a /Applications/Paratia.app.")
    if installed and mode != "app":
        message = "Il servizio installato usa un avvio precedente. Premi Installa il registro in Paratia per passare al binario dell'app; non concedere Accesso completo al disco a Python."
    return {"installed": installed, "running": bool(fresco and dati.get("running")),
            "healthy": bool(fresco and dati.get("healthy")), "needs_root": not installed,
            "launch_mode": mode, "needs_reinstall": installed and mode != "app",
            "fda_entry": "/Applications/Paratia.app", "fda_regrant_after_build": True,
            "fda_message": "Dopo l'installazione abilita /Applications/Paratia.app in Accesso completo al disco. Con firma ad hoc, dopo ogni nuova build rimuovi e aggiungi di nuovo l'app. Python non va autorizzato.",
            "needs_fda": dati.get("needs_fda") if fresco and isinstance(dati.get("needs_fda"), bool) else None,
            "dropped_events": dati.get("dropped_events"), "limits": list(LIMITI),
            "drop_detection_available": dati.get("drop_detection_available", False),
            "watched_ids": dati.get("watched_ids", []),
            "diagnostic_counts": dati.get("diagnostic_counts", {}),
            "schema_supported": dati.get("schema_supported"),
            "local_chain_ok": locale["ok"], "local_chain_error": locale["errore"],
            "message": message}
