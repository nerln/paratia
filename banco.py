"""Repeatable, metadata-only bank, started by a human through the Mac app.

No privileged operation, permission bypass, or credential management belongs
here. A live run requires the already authorized kernel collector.
"""
from __future__ import annotations

import csv
import datetime as dt
import fcntl
import importlib.util
import io
import json
import os
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


def _modulo(nome):
    spec = importlib.util.spec_from_file_location("banco_" + nome, Path(__file__).resolve().with_name(nome + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


C, R = _modulo("cartelle"), _modulo("registro")
CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
ARCHIVIO = CASA / "banco" / "storico.json"
PROBE = Path(__file__).resolve().parent / "strumenti" / "banco-probe.py"
LIMITI = [
    "I file della prova sono sintetici. Il banco non legge i contenuti dei file personali.",
    "La sorgente paratia misura gli esiti dei probe; la sorgente eslogger contiene i riscontri kernel.",
    "mdls può usare metadati in cache. L'assenza di un riscontro kernel non diventa una prova di raccolta.",
    "Le CLI degli agenti usano le loro configurazioni e autorizzazioni. Hook, login o errori possono impedire una prova.",
    "Il banco non concede TCC, non sblocca né modifica il portachiavi e non disattiva hook.",
]


class Rifiuto(ValueError):
    pass


def _ora():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _leggi_storico():
    try:
        fd = os.open(ARCHIVIO, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"versione": 1, "prove": []}
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_size > 16 * 1024**2:
            raise Rifiuto("Lo storico del banco non è un file valido. Conservane una copia prima di riprovare.")
        dati = json.load(f)
    if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("prove"), list):
        raise Rifiuto("Lo storico del banco non è leggibile. Conservane una copia prima di riprovare.")
    return dati


def _salva(prova):
    ARCHIVIO.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = os.open(ARCHIVIO.parent / "storico.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        dati = _leggi_storico()
        dati["prove"] = [p for p in dati["prove"] if p.get("id") != prova["id"]] + [prova]
        fd, nome = tempfile.mkstemp(dir=ARCHIVIO.parent, prefix=".storico-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(dati, f, ensure_ascii=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(nome, ARCHIVIO)
        finally:
            if os.path.exists(nome):
                os.unlink(nome)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def storico():
    dati = _leggi_storico()
    if not dati["prove"]:
        return {"versione": 1, "stato": "non-eseguito", "prove": [], "fasi": [],
                "messaggio": "Il banco non è stato eseguito. Installa e autorizza il registro prima di iniziare.",
                "limiti": LIMITI}
    return {**dati["prove"][-1], "prove": dati["prove"], "limiti": LIMITI}


def _inventario(percorso, escluso=None):
    """Only lstat/scandir: never open a user file or follow its symlink."""
    p = Path(percorso)
    risultati = {}

    def visita(fd, prefisso="", profondita=0):
        if profondita > 100:
            raise Rifiuto("La cartella contiene troppe sottocartelle annidate per il banco.")
        with os.scandir(fd) as entries:
            for e in entries:
                relativo = prefisso + e.name
                if not prefisso and e.name == escluso:
                    continue
                s = e.stat(follow_symlinks=False)
                if not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)):
                    raise Rifiuto("Il banco rifiuta collegamenti e file speciali: conserva i tuoi dati e usa una cartella vuota.")
                risultati[relativo] = {"tipo": "cartella" if stat.S_ISDIR(s.st_mode) else "file",
                                       "byte": s.st_size if stat.S_ISREG(s.st_mode) else 0,
                                       "mtime_ns": s.st_mtime_ns}
                if len(risultati) > 10000:
                    raise Rifiuto("La cartella contiene troppi elementi per il banco. Usa una cartella vuota.")
                if stat.S_ISDIR(s.st_mode):
                    child = os.open(e.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        visita(child, relativo + "/", profondita + 1)
                    finally:
                        os.close(child)
    fd = _directory_fd(p)
    try:
        visita(fd)
    finally:
        os.close(fd)
    return risultati


def _directory_fd(p):
    p = Path(p)
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
        raise Rifiuto("Scegli una cartella esistente senza collegamenti simbolici.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for parte in p.parts[1:]:
            nuovo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nuovo
        return fd
    except BaseException:
        os.close(fd)
        raise


def anteprima(path=None, dove=None):
    p = Path(path or Path.home() / "Desktop" / "folder-test").absolute()
    cartella = next((v for v in C.elenco() if v["origine"] == str(p)), None)
    if cartella:
        return {"stato": cartella["stato"], "percorso": str(p), "file": cartella["file"], "byte": cartella["byte"],
                "richiede_autorizzazione": not R.stato()["healthy"],
                "messaggio": "Cartella già protetta. Il banco riparte solo se lo storico identifica i file sintetici della prova.",
                "cartella_id": cartella["id"]}
    try:
        inventario = _inventario(p)
    except PermissionError:
        return {"stato": "permesso-desktop", "percorso": str(p), "file": None, "byte": None,
                "richiede_autorizzazione": True,
                "messaggio": "macOS protegge il Desktop. Consenti l'accesso a Paratia quando richiesto, poi riprova."}
    file = [v for v in inventario.values() if v["tipo"] == "file"]
    return {"stato": "vuota" if not inventario else "contiene-file", "percorso": str(p),
            "file": len(file), "byte": sum(v["byte"] for v in file),
            "richiede_autorizzazione": not R.stato()["healthy"],
            "messaggio": "Verranno creati file sintetici dichiarati come tali." if not inventario else
                         "Sono presenti dati. Il banco si limita ai metadati e non li migrerà: usa una cartella vuota."}


def _sintetici(p):
    if _inventario(p):
        raise Rifiuto("folder-test contiene già file. Il banco non legge né migra dati personali: spostali tu e riprova.")
    fd = _directory_fd(p)
    identita = os.fstat(fd)

    def scrivi(directory, nome, pezzi):
        file = os.open(nome, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(file, "wb") as f:
            for dati in pezzi:
                f.write(dati)
    try:
        scrivi(fd, "LEGGIMI-SINTETICO.txt", [b"PARATIA: LEGGIMI-SINTETICO.txt, campione.bin, grande.bin e sottocartella/note.txt sono dati sintetici del banco, privi di segreti. I file aggiunti successivamente non appartengono alla prova.\n"])
        scrivi(fd, "campione.bin", [bytes(range(256)) * 32])
        os.mkdir("sottocartella", 0o700, dir_fd=fd)
        child = os.open("sottocartella", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            scrivi(child, "note.txt", [b"Sottocartella sintetica per verificare una migrazione completa.\n"])
        finally:
            os.close(child)
        scrivi(fd, "grande.bin", [bytes(range(256)) * 4096] * 8)
        attuale = p.lstat()
        if (attuale.st_dev, attuale.st_ino) != (identita.st_dev, identita.st_ino):
            raise Rifiuto("La cartella del banco è stata spostata durante la preparazione. Controlla i file sintetici prima di riprovare.")
    finally:
        os.close(fd)
    return _inventario(p)


def _pronto():
    stato = R.stato()
    if not (stato["running"] and stato["healthy"] and stato.get("local_chain_ok", False)):
        raise Rifiuto("Il registro non è pronto. In Registro premi Installa il registro, autorizza /usr/bin/eslogger in Accesso completo al disco e attendi lo stato attivo.")
    return stato


def _attendi_sorveglianza(identificatore):
    fine = time.monotonic() + 20
    while time.monotonic() < fine:
        stato = _pronto()
        if identificatore in stato.get("watched_ids", []):
            return
        time.sleep(0.25)
    raise Rifiuto("Il registro non ha ancora recepito questa cartella. Il banco non è iniziato: riprova fra poco.")


def _cli(nome):
    trovato = shutil.which(nome)
    if trovato:
        return trovato
    candidati = [Path.home() / ".local" / "bin" / nome, Path("/opt/homebrew/bin") / nome]
    if nome == "codex":
        candidati += sorted((Path.home() / ".nvm" / "versions" / "node").glob("*/bin/codex"), reverse=True)
    return next((str(p) for p in candidati if p.is_file() and os.access(p, os.X_OK)), None)


def _comando(argv, cwd, tempo=120, stdin=None):
    env = os.environ.copy()
    if argv and Path(argv[0]).is_absolute():
        env["PATH"] = str(Path(argv[0]).parent) + os.pathsep + env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        p.communicate(input=stdin, timeout=tempo)
    except subprocess.TimeoutExpired:
        return {"rc": None, "pid_launcher": p.pid, "timeout": True}
    finally:
        _termina(p)
    return {"rc": p.returncode, "pid_launcher": p.pid, "timeout": False}


def _termina(processo):
    if processo.poll() is None:
        try:
            os.killpg(processo.pid, signal.SIGTERM)
            try:
                processo.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(processo.pid, signal.SIGKILL)
                processo.wait(timeout=5)
        except ProcessLookupError:
            processo.wait(timeout=5)


def _risultato_probe(p, nonce):
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_size > 16384:
                return None
            r = json.load(f)
        if not isinstance(r, dict) or r.get("nonce") != nonce or type(r.get("riuscito")) is not bool:
            return None
        if type(r.get("pid")) is not int or r["pid"] <= 0 or type(r.get("uid")) is not int or r["uid"] != os.getuid():
            return None
        if type(r.get("ppid")) is not int or r["ppid"] < 0:
            return None
        if not isinstance(r.get("processo"), str) or not os.path.isabs(r["processo"]) or len(r["processo"]) > 16384 or "\0" in r["processo"]:
            return None
        if r["riuscito"] and (r.get("errno") is not None or type(r.get("byte")) is not int or r["byte"] < 0):
            return None
        if not r["riuscito"] and (type(r.get("errno")) is not int or r["errno"] <= 0 or r.get("byte") is not None):
            return None
        return {k: r.get(k) for k in ("pid", "ppid", "uid", "riuscito", "errno", "byte", "processo")}
    except (OSError, ValueError):
        return None


def _mcp_comando(cli, comando, directory):
    """Ask the real Claude Code MCP server for one human-specified Bash call.

    No inference session or authentication workaround is used. A server request
    that needs additional UI consent is refused here and remains an incomplete
    probe. Nothing from its raw responses is persisted.
    """
    processo = subprocess.Popen([cli, "mcp", "serve"], cwd=directory,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
    buffer = b""

    def manda(msg):
        processo.stdin.write((json.dumps(msg) + "\n").encode())
        processo.stdin.flush()

    def risposta(identificatore):
        nonlocal buffer
        fine = time.monotonic() + 45
        while time.monotonic() < fine:
            if b"\n" not in buffer:
                leggibili, _, _ = select.select([processo.stdout], [], [], 0.25)
                if not leggibili:
                    if processo.poll() is not None:
                        raise Rifiuto("Il server Claude Code è terminato senza completare il probe.")
                    continue
                pezzo = os.read(processo.stdout.fileno(), 65536)
                if not pezzo:
                    raise Rifiuto("Il server Claude Code non ha prodotto una risposta.")
                buffer += pezzo
            if len(buffer) > 1048576:
                raise Rifiuto("La risposta del server Claude Code è troppo grande.")
            while b"\n" in buffer:
                linea, buffer = buffer.split(b"\n", 1)
                msg = json.loads(linea)
                if msg.get("id") == identificatore and ("result" in msg or "error" in msg):
                    if "error" in msg or msg.get("result", {}).get("isError"):
                        raise Rifiuto("Claude Code ha rifiutato la prova. Controlla autorizzazioni e hook della CLI.")
                    return msg["result"]
                if "id" in msg and "method" in msg:
                    manda({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "Serve consenso umano; il banco non approva richieste del server."}})
        raise Rifiuto("Claude Code non ha concluso la prova in tempo. Controlla login e autorizzazioni.")

    try:
        os.set_blocking(processo.stdout.fileno(), False)
        manda({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "paratia-banco", "version": "1.0.0"}}})
        risposta(1)
        manda({"jsonrpc": "2.0", "method": "notifications/initialized"})
        manda({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        elenco = risposta(2)
        if not any(t.get("name") == "Bash" for t in elenco.get("tools", [])):
            raise Rifiuto("La CLI Claude Code non espone il tool Bash atteso per il banco.")
        manda({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "Bash", "arguments": {"command": shlex.join(comando), "timeout": 30000,
                                          "description": "Banco sintetico Paratia: open/fstat senza lettura dei byte"}}})
        risposta(3)
        return {"rc": 0, "pid_launcher": processo.pid, "timeout": False, "modo": "Claude Code MCP, comando umano senza modello"}
    except (OSError, ValueError):
        return {"rc": None, "pid_launcher": processo.pid, "timeout": False,
                "modo": "Claude Code MCP, comando umano senza modello"}
    finally:
        try:
            processo.stdin.close()
        except OSError:
            pass
        _termina(processo)


def _probe(attore, target, fase, directory, agenti_reali):
    nonce = uuid.uuid4().hex
    output = directory / (attore + "-" + nonce + ".json")
    comando = [sys.executable, str(PROBE), "--file", str(target), "--result", str(output), "--nonce", nonce]
    r = {"attore": attore, "fase": fase, "quando": _ora(), "percorso": str(target),
         "riuscito": None, "errno": None, "pid": None, "agente": None, "riscontri_kernel": [], "misurato": False}
    if attore == "mdls":
        esito = _comando(["/usr/bin/mdls", "-name", "kMDItemFSSize", str(target)], directory, tempo=30)
        return {**r, **esito, "riuscito": esito["rc"] == 0, "misurato": esito["rc"] is not None,
                "pid": esito["pid_launcher"], "processo": "/usr/bin/mdls"}
    if attore == "shell":
        esito = _comando(["/bin/sh", "-c", 'exec "$@"', "banco-shell", *comando], directory, tempo=30)
    else:
        if not agenti_reali:
            return {**r, "messaggio": "CLI reale non avviata: manca il consenso per questa prova."}
        cli = _cli(attore)
        if not cli:
            return {**r, "messaggio": "La CLI " + attore + " non è disponibile. Nessun processo sostitutivo è stato usato."}
        if attore == "codex":
            # A genuine child of Codex's sandbox command. No model call or hook
            # trust bypass; this is an explicitly requested human CLI operation.
            esito = _comando([cli, "sandbox", "-C", str(directory), "--", *comando], directory, tempo=45)
            esito["modo"] = "Codex sandbox, comando umano senza modello"
        else:
            esito = _mcp_comando(cli, comando, directory)
    misurato = _risultato_probe(output, nonce)
    if misurato is None:
        return {**r, **esito, "messaggio": "Il processo non ha prodotto una misura valida. Controlla login, permessi e hook della CLI."}
    return {**r, **esito, **misurato, "misurato": True}


def _riscontri(probe):
    if probe["pid"] is None:
        return []
    for _ in range(12):
        righe = R.query({"file": probe["percorso"], "since": probe["quando"]})
        trovati = [r for r in righe if r.get("source") == "eslogger" and r.get("pid") == probe["pid"]
                   and probe["percorso"] in (r.get("percorso"), r.get("destinazione"))]
        if trovati:
            return [{k: r.get(k) for k in ("quando", "evento", "pid", "pidversion", "processo", "utente", "app_responsabile",
                                          "agente", "nome_agente", "evidenza_agente", "esito", "precedente")} for r in trovati]
        time.sleep(0.25)
    return []


def _fase(prova, nome, target, cartella_id, chiusa, directory, agenti_reali):
    _pronto()
    voce = next((v for v in C.elenco() if v["id"] == cartella_id), {})
    visibili = _inventario(target.parent, escluso=voce.get("metadir"))
    fase = {"nome": nome, "iniziata": _ora(), "atteso": "rifiuto" if chiusa else "accesso", "prove": [],
            "stato_cartella": "chiusa" if chiusa else "aperta",
            "file_visibili": sum(v["tipo"] == "file" for v in visibili.values()),
            "byte_visibili": sum(v["byte"] for v in visibili.values())}
    prova["fasi"].append(fase)
    _salva(prova)
    for attore in ("shell", "mdls", "codex", "claude"):
        r = _probe(attore, target, nome, directory, agenti_reali)
        r["riscontri_kernel"] = _riscontri(r) if r["misurato"] else []
        if r["riscontri_kernel"]:
            r["agente"] = r["riscontri_kernel"][0].get("agente")
        r["esito_atteso"] = r["misurato"] and r["riuscito"] is (not chiusa)
        r["copertura_verificata"] = bool(r["riscontri_kernel"]) if not chiusa else r["misurato"]
        if attore in ("codex", "claude") and not chiusa:
            nome_agente = "Codex" if attore == "codex" else "Claude Code"
            r["copertura_verificata"] = any(k.get("agente") is True and k.get("nome_agente") == nome_agente for k in r["riscontri_kernel"])
        R.annota("banco-accesso", cartella=cartella_id, percorso=str(target), fase=nome, fonte="banco",
                 processo=r.get("processo"), pid=r.get("pid"), uid=r.get("uid", os.getuid()),
                 esito="riuscito" if r["riuscito"] else "fallito" if r["riuscito"] is False else "non-misurato",
                 errno=r["errno"], rc=r.get("rc"), agente=r["agente"], nome=attore)
        fase["prove"].append(r)
        _salva(prova)
    fase["conclusa"] = _ora()
    fase["ok"] = all(r["esito_atteso"] and r["copertura_verificata"] for r in fase["prove"])
    _salva(prova)


def _operazione(prova, risultato):
    if risultato.get("avviso_registro"):
        prova["avviso_registro"] = risultato["avviso_registro"]
    return risultato


def esegui(dove, passphrase: bytes, minutes=15, agenti_reali=True):
    C._chiave(passphrase)
    C._minuti(minutes)
    _pronto()  # Before Desktop access, fixture creation, or migration.
    fonte = Path.home() / "Desktop" / "folder-test"
    disco = Path(dove).absolute()
    C._esterno(disco)
    esistenti = [v for v in C.elenco() if v["origine"] == str(fonte)]
    vecchia = next((p for p in reversed(_leggi_storico()["prove"]) if p.get("percorso") == str(fonte)
                   and p.get("sintetici") and p.get("inventario")), None)
    if esistenti and (not vecchia or vecchia.get("cartella_id") != esistenti[0]["id"]):
        raise Rifiuto("Questa cartella protetta non appartiene al banco sintetico. Non verrà aperta o migrata dalla prova.")
    identificatore = esistenti[0]["id"] if esistenti else None
    prova = {"versione": 1, "id": uuid.uuid4().hex, "stato": "in-corso", "percorso": str(fonte),
             "iniziata": _ora(), "fasi": [], "sintetici": False, "cartella_id": identificatore, "bundle": None}
    guardia = CASA / "banco"
    guardia.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(guardia / "esecuzione.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise Rifiuto("Un banco è già in corso. Attendi la fine prima di riprovare.")
    watch = None
    try:
        # A fresh ID prevents a previous run from acknowledging stale paths.
        watch = "banco-" + prova["id"]
        R.sorveglia(watch, fonte, "Banco sintetico prima/dopo")
        _attendi_sorveglianza(watch)
        if identificatore:
            if esistenti[0]["stato"] == "chiusa":
                _operazione(prova, C.apri(identificatore, passphrase, minutes))
            attuale = _inventario(fonte, escluso=esistenti[0].get("metadir"))
            if attuale != vecchia["inventario"]:
                raise Rifiuto("I metadati del banco sono cambiati: la prova non tratta questi file come sintetici.")
            prova["inventario"] = attuale
        else:
            attuale = _inventario(fonte)
            if attuale:
                if not vecchia or attuale != vecchia["inventario"]:
                    raise Rifiuto("folder-test contiene file personali o non riconosciuti. Il banco si limita ai metadati: spostali tu e riprova.")
            else:
                attuale = _sintetici(fonte)
            prova["inventario"] = attuale
        prova["sintetici"] = True
        prova["file"] = sum(v["tipo"] == "file" for v in attuale.values())
        prova["byte"] = sum(v["byte"] for v in attuale.values())
        _salva(prova)
        with tempfile.TemporaryDirectory(prefix="paratia-banco-") as area:
            directory = Path(area).resolve()
            target = fonte / "LEGGIMI-SINTETICO.txt"
            _fase(prova, "prima", target, identificatore or watch, False, directory, agenti_reali)
            if not identificatore:
                if _inventario(fonte) != prova["inventario"]:
                    raise Rifiuto("folder-test è cambiata durante la prova: nessun nuovo dato verrà migrato. Chiudi le app che la modificano e riprova.")
                v = _operazione(prova, C.proteggi(fonte, disco, passphrase, minutes))
                identificatore = v["id"]
                prova.update(cartella_id=identificatore, bundle=v["bundle"])
                prova["verifica_migrazione"] = {"file_prima": prova["file"], "byte_prima": prova["byte"],
                                                "file_dopo": v["file"], "byte_dopo": v["byte"],
                                                "verificato": v.get("verificato", False)}
            else:
                _operazione(prova, C.chiudi(identificatore))
            _attendi_sorveglianza(identificatore)
            _fase(prova, "chiusa", target, identificatore, True, directory, agenti_reali)
            _operazione(prova, C.apri(identificatore, passphrase, minutes))
            _fase(prova, "riaperta", target, identificatore, False, directory, agenti_reali)
            _operazione(prova, C.chiudi(identificatore))
            _fase(prova, "richiusa", target, identificatore, True, directory, agenti_reali)
        prova["stato"] = "completo" if all(f["ok"] for f in prova["fasi"]) and not prova.get("avviso_registro") else "incompleto"
        prova["messaggio"] = "Sequenza conclusa e verificata." if prova["stato"] == "completo" else "Sequenza conclusa con prove o riscontri mancanti. Consulta ogni fase; nessun risultato mancante è stato considerato positivo."
    except BaseException as e:
        if not identificatore and isinstance(e, C.Rifiuto):
            # Only the ID created by this exact migration call can be cleaned
            # up. Never guess from a concurrent GUI's new registry entries.
            identificatore = getattr(e, "cartella_id", None)
            prova["cartella_id"] = identificatore
        prova["stato"] = "incompleto"
        prova["messaggio"] = str(e) if isinstance(e, (Rifiuto, C.Rifiuto)) else "Il banco è stato interrotto. Consulta lo stato delle cartelle prima di riprovare."
        prova["tipo_errore"] = type(e).__name__
        raise
    finally:
        if identificatore:
            try:
                finale = C.chiudi(identificatore)
                prova["stato_finale"] = finale["stato"]
                if finale["stato"] != "chiusa":
                    prova["stato"] = "incompleto"
                    prova["avviso_chiusura"] = "La migrazione conserva copie plaintext. Usa Recupera o Annulla migrazione in Cartelle prima di riprovare."
                if finale.get("avviso_registro"):
                    prova["avviso_registro"] = finale["avviso_registro"]
                    prova["stato"] = "incompleto"
            except Exception:
                prova["stato_finale"] = "da-verificare"
                prova["stato"] = "incompleto"
                prova["avviso_chiusura"] = "La cartella non è stata chiusa: chiudi i documenti aperti e premi Chiudi tutte."
        if watch:
            try:
                R.rimuovi_sorveglianza(watch)
            except Exception:
                prova["avviso_sorveglianza"] = "La richiesta di sorveglianza del banco è ancora presente. Riprova quando il registro locale è scrivibile."
        prova["conclusa"] = _ora()
        try:
            _salva(prova)
        finally:
            os.close(fd)
    return prova


def export_csv():
    out = io.StringIO(newline="")
    campi = ["prova", "fase", "quando", "attore", "percorso", "pid", "processo", "riuscito", "errno", "agente", "esito_atteso", "copertura_verificata"]
    writer = csv.DictWriter(out, fieldnames=campi, extrasaction="ignore")
    writer.writeheader()
    for prova in _leggi_storico()["prove"]:
        for fase in prova["fasi"]:
            for r in fase["prove"]:
                row = {**r, "prova": prova["id"], "fase": fase["nome"]}
                writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else v for k, v in row.items() if k in campi})
    return out.getvalue()
