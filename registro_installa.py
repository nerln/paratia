#!/usr/bin/python3
"""Fixed-scope installer invoked only by the human GUI's admin authorization.

Calling piano()/prepara() prepares reviewable argv and a plist without invoking
privilege, changing TCC, or touching any keychain.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import importlib.util
import json
import os
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SUPPORT = Path("/Library/Application Support/Paratia")
LOGS = Path("/Library/Logs/Paratia")
DAEMONS = Path("/Library/LaunchDaemons")
CODICE = ("catena.py", "registro.py", "registro_daemon.py")
MAX_CODICE = 1048576
MAX_BUNDLE = 128 * 1024**2
MAX_ELEMENTI = 10000
FDA_APP = "/Applications/Paratia.app"
LAUNCHER_VERSION = 1
STOP_TIMEOUT = 8.0
STOP_CHECKS = 40
LAUNCHCTL_TIMEOUT = 5.0
BOOTSTRAP_DELAYS = (0.2, 0.5)
MAX_LAUNCHCTL_ERRORS = 12


class ErroreInstallazione(ValueError):
    """Human-readable, JSON-safe installation failure, including recovery state."""

    def __init__(self, error_code, message, launchctl_errors=(), conserva_stage=False, backup=None):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.launchctl_errors = list(launchctl_errors)
        self.conserva_stage = conserva_stage
        self.backup = backup


def _testo_launchctl(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value or "")[:4096]


def _riduci_stderr(value):
    """Keep standard launchctl diagnostics; never reflect arbitrary payloads."""
    testo = _testo_launchctl(value)
    messaggi = []
    descrizioni = {3: "No such process", 5: "Input/output error", 13: "Permission denied",
                   37: "Operation already in progress", 113: "Bad request"}
    for riga in testo.splitlines()[:16]:
        esito = re.fullmatch(r"\s*(Bootstrap failed|Boot-out failed):\s*(\d{1,3})(?::.*)?\s*", riga)
        if esito:
            numero = int(esito.group(2))
            descrizione = descrizioni.get(numero, "Errore launchctl")
            messaggi.append("%s: %d: %s" % (esito.group(1), numero, descrizione))
        elif "Could not find service" in riga:
            messaggi.append("Could not find service in domain for system")
        elif riga.strip() == "Try running the command as root for richer errors.":
            messaggi.append(riga.strip())
    if not messaggi and testo.strip():
        messaggi.append("Diagnostica launchctl non standard omessa.")
    return "\n".join(messaggi)[:512]


def _diagnostica(errors, operation, returncode, stderr):
    if len(errors) < MAX_LAUNCHCTL_ERRORS:
        errors.append({"operation": operation, "returncode": returncode,
                       "stderr": _riduci_stderr(stderr)})


def _launchctl(argv, errors, operation):
    try:
        return subprocess.run(["/bin/launchctl", *argv], capture_output=True,
                              timeout=LAUNCHCTL_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        _diagnostica(errors, operation, None, exc.stderr)
        raise ErroreInstallazione("launchctl_timeout", "launchctl non ha risposto entro il limite di tempo.", errors) from exc
    except OSError as exc:
        _diagnostica(errors, operation, None, "")
        raise ErroreInstallazione("launchctl_unavailable", "Non è stato possibile eseguire launchctl.", errors) from exc


def _servizio_presente(label, errors, operation="print"):
    result = _launchctl(["print", "system/" + label], errors, operation)
    if result.returncode == 0:
        return True
    # launchctl uses ESRCH or its domain-specific bad-request code for absence.
    # Permission, transport and other failures do not prove that a job is gone.
    testo = _testo_launchctl(result.stderr)
    if result.returncode in (3, 113) and (not testo.strip() or "Could not find service" in testo):
        return False
    _diagnostica(errors, operation, result.returncode, result.stderr)
    raise ErroreInstallazione("launchctl_probe_failed", "Non è stato possibile verificare se il servizio è ancora caricato; nessuna sostituzione è autorizzata.", errors)


def _arresta(label, errors, rollback=False):
    prefisso = "rollback_" if rollback else ""
    result = _launchctl(["bootout", "system/" + label], errors, prefisso + "bootout")
    if result.returncode:
        _diagnostica(errors, prefisso + "bootout", result.returncode, result.stderr)
    deadline = time.monotonic() + STOP_TIMEOUT
    for tentativo in range(STOP_CHECKS):
        if not _servizio_presente(label, errors, prefisso + "print"):
            return
        restante = deadline - time.monotonic()
        if restante <= 0:
            break
        time.sleep(min(0.1 + tentativo * 0.05, 0.4, restante))
    codice = "service_stop_failed" if result.returncode else "service_stop_timeout"
    raise ErroreInstallazione(codice, "Il servizio precedente è ancora caricato dopo l'arresto: nessun componente è stato sostituito.", errors)


def _avvia(plist_path, errors, rollback=False):
    operation = "rollback_bootstrap" if rollback else "bootstrap"
    for tentativo in range(len(BOOTSTRAP_DELAYS) + 1):
        result = _launchctl(["bootstrap", "system", str(plist_path)], errors, operation)
        if result.returncode == 0:
            return
        _diagnostica(errors, operation, result.returncode, result.stderr)
        diagnostico = re.search(r"Bootstrap failed:\s*(5|37)(?:\D|$)", _testo_launchctl(result.stderr))
        corsa = result.returncode in (5, 37) or diagnostico is not None
        if not corsa or tentativo == len(BOOTSTRAP_DELAYS):
            break
        time.sleep(BOOTSTRAP_DELAYS[tentativo])
    raise ErroreInstallazione("bootstrap_failed", "launchctl non ha caricato il nuovo servizio dopo i tentativi previsti.", errors)


# Importing the installer must not add unsigned bytecode inside its app bundle.
sys.dont_write_bytecode = True

# The installer is the human-authorized app payload; it imports only its sibling
# ACL inspector. Installed daemon code uses the protected sibling copy instead.
_spec = importlib.util.spec_from_file_location("installer_catena", Path(__file__).resolve().with_name("catena.py"))
_catena = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_catena)


def _rootpath(p):
    p = Path(p).resolve(strict=True)
    for q in [p, *p.parents]:
        s = q.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or _catena.acl_scrivibile(q):
            raise ValueError("Il runtime Python è modificabile senza root. Installa i Command Line Tools Apple in /Library/Developer.")
    return p


def runtime():
    """Use the same protected CLT framework accepted by the native launcher."""
    candidati = [Path("/Library/Developer/CommandLineTools/usr/bin/python3")]
    framework = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/"
    for candidato in candidati:
        try:
            candidato = _rootpath(candidato)
            if not str(candidato).startswith(framework):
                continue
            if candidato.name.startswith("python") and candidato.parent.name == "bin" and candidato.parent.parent.parent.name == "Versions":
                # Validate the framework before executing any of its Python code.
                preliminare = candidato.parent.parent
                for directory, dirs, files in os.walk(preliminare, followlinks=False):
                    _rootpath(directory)
                    for nome in dirs + files:
                        _rootpath(Path(directory) / nome)
            elif os.geteuid() == 0:
                # Never probe an opaque launcher with administrator privilege.
                continue
            r = subprocess.run([str(candidato), "-I", "-S", "-c",
                                "import json,sys; print(json.dumps([sys.executable,sys.prefix,list(sys.version_info[:2])]))"],
                               capture_output=True, text=True, check=True, timeout=10)
            exe, prefix, versione = json.loads(r.stdout)
            exe, prefix = _rootpath(exe), _rootpath(prefix)
            if versione < [3, 9] or not str(exe).startswith(framework) or not str(prefix).startswith(framework):
                continue
            # A protected directory is insufficient if an existing library is writable.
            for directory, dirs, files in os.walk(prefix, followlinks=False):
                _rootpath(directory)
                for nome in dirs + files:
                    _rootpath(Path(directory) / nome)
            return str(exe)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    raise ValueError("Nessun Python Apple protetto da root: installa i Command Line Tools Apple in /Library/Developer, senza cambiare i permessi di Xcode.")


def _utente(uid):
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        raise ValueError("Scegli un utente umano distinto da root.")
    u = pwd.getpwuid(uid)
    if not Path(u.pw_dir).is_absolute() or any(c in u.pw_name for c in ":\n\r"):
        raise ValueError("L'account non ha metadati validi.")
    return u


def plist(uid, executable=None):
    _utente(uid)
    label = "it.paratia.registro.%d" % uid
    return {"Label": label,
            "ProgramArguments": [str(SUPPORT / "Paratia.app" / "Contents" / "MacOS" / "Paratia"),
                                 "--registro", "--uid", str(uid)],
            "UserName": "root", "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False}, "ThrottleInterval": 30,
            "ProcessType": "Background", "Umask": 0o077,
            "WorkingDirectory": str(SUPPORT),
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}


def piano(resource_root=None, uid=None):
    uid = os.getuid() if uid is None else uid
    _utente(uid)
    fonte = Path(resource_root or Path(__file__).resolve().parent).absolute()
    executable = runtime()
    app, identita = _app_sorgente(fonte, uid)
    for nome in (*CODICE, "registro_installa.py"):
        p = fonte / nome
        if not p.is_file() or p.is_symlink():
            raise ValueError("I componenti del registro non sono disponibili nell'app.")
    return {"argv": [executable, "-I", "-S", str(fonte / "registro_installa.py"),
                     "--install", "--uid", str(uid), "--source", str(fonte)],
            "plist": plist(uid, executable), "label": "it.paratia.registro.%d" % uid,
            "needs_root": True, "needs_fda": True,
            "fda_entry": FDA_APP, "fda_regrant_after_build": True,
            "bundle": str(app), "cdhash": identita,
            "launcher_version": LAUNCHER_VERSION,
            "message": "L'autorizzazione amministratore copia il bundle firmato in un percorso protetto e installa il registro. "
                       "Autorizza /Applications/Paratia.app in Accesso completo al disco; dopo ogni nuova build con firma ad hoc rimuovi e aggiungi di nuovo quella voce. "
                       "Il servizio precedente deve essere reinstallato per usare il launcher dell'app."}


prepara = piano


def _directory(p):
    for q in [*reversed(p.parents), p]:
        try:
            s = q.lstat()
        except FileNotFoundError:
            q.mkdir(mode=0o700)
            s = q.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or _catena.acl_scrivibile(q):
            raise ValueError("Un percorso di installazione non è protetto da root.")


def _leggi_codice(fonte, nome, uid):
    # Names are a compile-time allowlist, never supplied as code paths by config.
    for q in [*reversed(fonte.parents), fonte]:
        s = q.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, uid) or s.st_mode & 0o002:
            raise ValueError("La sorgente dell'app non ha autorizzazioni valide.")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for parte in fonte.parts[1:]:
            nuovo = os.open(parte, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = nuovo
        fd = os.open(nome, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0, uid) or s.st_mode & 0o022 or s.st_size > MAX_CODICE:
            raise ValueError("Un componente del registro non è un file attendibile.")
        b = f.read(MAX_CODICE + 1)
        if len(b) > MAX_CODICE:
            raise ValueError("Un componente del registro è troppo grande.")
        compile(b, nome, "exec")
        return b


def _scrivi(p, contenuto, modo):
    if p.exists() or p.is_symlink():
        s = p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Un file installato non è protetto da root.")
    fd, nome = tempfile.mkstemp(dir=p.parent, prefix=".paratia-")
    try:
        os.fchmod(fd, modo)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "wb") as f:
            f.write(contenuto)
            f.flush()
            os.fsync(f.fileno())
        os.replace(nome, p)
    finally:
        if os.path.exists(nome):
            os.unlink(nome)


def _acl(p, account, directory=False):
    # Remove inherited entries first; staff and other users get no metadata access.
    subprocess.run(["/bin/chmod", "-N", str(p)], check=True, capture_output=True)
    permessi = "list,search,readattr,readextattr,readsecurity" if directory else "read,readattr,readextattr,readsecurity"
    subprocess.run(["/bin/chmod", "+a", "user:%s allow %s" % (account, permessi), str(p)],
                   check=True, capture_output=True)


def _apri_directory(p):
    p = Path(p)
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
        raise ValueError("Il percorso dell'app deve essere assoluto e senza alias.")
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


def _identita_file(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def _firma(app):
    """Verify only; never sign, select an identity, or access a keychain."""
    try:
        subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)],
                       check=True, capture_output=True, timeout=30)
        result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)],
                                check=True, capture_output=True, text=True, timeout=30)
        dettagli = result.stdout + result.stderr
        if len(dettagli) > 65536:
            raise ValueError()
        if re.findall(r"^Identifier=(.+)$", dettagli, re.MULTILINE) != ["it.paratia.app"]:
            raise ValueError()
        if re.findall(r"^Signature=(.+)$", dettagli, re.MULTILINE) != ["adhoc"]:
            raise ValueError()
        hashes = re.findall(r"^CDHash=([0-9a-fA-F]{40,64})$", dettagli, re.MULTILINE)
        if len(hashes) != 1:
            raise ValueError()
        return hashes[0].lower()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise ValueError("La firma ad hoc del bundle Paratia non è valida: ricostruisci l'app prima di installare.") from exc


def _info_bundle(app):
    fd = _apri_directory(app / "Contents")
    try:
        file = os.open("Info.plist", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(file, "rb") as source:
        s = os.fstat(file)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_CODICE:
            raise ValueError("I metadati del bundle non sono validi.")
        raw = source.read(MAX_CODICE + 1)
        if len(raw) > MAX_CODICE or _identita_file(s) != _identita_file(os.fstat(file)):
            raise ValueError("I metadati del bundle sono cambiati.")
    info = plistlib.loads(raw)
    if (not isinstance(info, dict) or info.get("CFBundleIdentifier") != "it.paratia.app" or
            info.get("CFBundleExecutable") != "Paratia" or
            type(info.get("ParatiaRegistryLauncherVersion")) is not int or
            info["ParatiaRegistryLauncherVersion"] != LAUNCHER_VERSION):
        raise ValueError("Questo bundle non contiene il launcher del registro supportato. Ricostruisci Paratia.")
    return info


def _albero(app, owners, copia=None):
    """Walk pinned descriptors; reject links/special files and bound the copy."""
    totale, elementi = [0], [0]

    def controlla(s, directory):
        if (s.st_uid not in owners or s.st_mode & 0o022 or s.st_mode & 0o7000 or
                not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) or
                (not directory and s.st_nlink != 1)):
            raise ValueError("Il bundle contiene file, collegamenti o autorizzazioni non attendibili.")

    def visita(fd, destinazione=None, profondita=0):
        if profondita > 64:
            raise ValueError("Il bundle contiene troppe sottocartelle.")
        controlla(os.fstat(fd), True)
        with os.scandir(fd) as entries:
            for entry in entries:
                elementi[0] += 1
                if elementi[0] > MAX_ELEMENTI:
                    raise ValueError("Il bundle contiene troppi elementi.")
                s = entry.stat(follow_symlinks=False)
                isdir = stat.S_ISDIR(s.st_mode)
                controlla(s, isdir)
                if isdir:
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        if destinazione is None:
                            visita(child, None, profondita + 1)
                        else:
                            os.mkdir(entry.name, 0o700, dir_fd=destinazione)
                            target = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                             dir_fd=destinazione)
                            try:
                                visita(child, target, profondita + 1)
                                os.fchmod(target, stat.S_IMODE(s.st_mode))
                                os.fsync(target)
                            finally:
                                os.close(target)
                    finally:
                        os.close(child)
                else:
                    source = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    target = None
                    try:
                        before = os.fstat(source)
                        controlla(before, False)
                        if _identita_file(before) != _identita_file(s):
                            raise ValueError("Il bundle è cambiato durante la copia.")
                        totale[0] += before.st_size
                        if totale[0] > MAX_BUNDLE:
                            raise ValueError("Il bundle supera il limite consentito.")
                        if destinazione is not None:
                            target = os.open(entry.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o600, dir_fd=destinazione)
                            with os.fdopen(os.dup(source), "rb") as reader, os.fdopen(os.dup(target), "wb") as writer:
                                restante = before.st_size
                                while restante:
                                    chunk = reader.read(min(restante, 131072))
                                    if not chunk:
                                        raise ValueError("Il bundle è cambiato durante la copia.")
                                    writer.write(chunk)
                                    restante -= len(chunk)
                                writer.flush()
                            os.fchmod(target, stat.S_IMODE(before.st_mode))
                            os.fsync(target)
                        if _identita_file(before) != _identita_file(os.fstat(source)):
                            raise ValueError("Il bundle è cambiato durante la copia.")
                    finally:
                        os.close(source)
                        if target is not None:
                            os.close(target)

    fd = _apri_directory(app)
    target = None
    try:
        if copia is not None:
            Path(copia).mkdir(mode=0o700)
            target = _apri_directory(copia)
        visita(fd, target)
    finally:
        os.close(fd)
        if target is not None:
            os.close(target)


def _app_sorgente(fonte, uid):
    if fonte.parts[-3:] != ("Contents", "Resources", "python"):
        raise ValueError("Il registro deve essere installato dalle risorse del bundle Paratia.")
    app = fonte.parents[2]
    if app.suffix != ".app":
        raise ValueError("La sorgente non è un bundle app.")
    for p in [*reversed(app.parents), app]:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, uid) or s.st_mode & 0o002:
            raise ValueError("La sorgente dell'app non ha autorizzazioni valide.")
    _albero(app, (0, uid))
    _info_bundle(app)
    executable = app / "Contents" / "MacOS" / "Paratia"
    if not executable.lstat().st_mode & 0o111:
        raise ValueError("Il launcher del bundle non è eseguibile.")
    return app, _firma(app)


def _protetto(p, directory=False):
    s = p.lstat()
    if (s.st_uid != 0 or s.st_mode & 0o022 or s.st_mode & 0o7000 or
            not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) or
            (not directory and s.st_nlink != 1) or _catena.acl_scrivibile(p)):
        raise ValueError("Un componente installato non è protetto da root.")


@contextlib.contextmanager
def _lock_installazione():
    p = SUPPORT / ".installazione.lock"
    try:
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except FileExistsError:
        fd = os.open(p, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _protetto(p)
        fcntl.flock(fd, fcntl.LOCK_EX)
        # The lock cannot be swapped by ordinary users inside protected Support.
        if _identita_file(os.fstat(fd)) != _identita_file(p.lstat()):
            raise ValueError("Il lock di installazione è cambiato.")
        yield
    finally:
        os.close(fd)


def _verifica_copia(app, identita):
    _albero(app, (0,))
    for directory, dirs, files in os.walk(app, followlinks=False):
        for p in [Path(directory), *(Path(directory) / n for n in files)]:
            _protetto(p, directory=p.is_dir())
    _info_bundle(app)
    if _firma(app) != identita:
        raise ValueError("La copia protetta non ha la stessa identità firmata del bundle corrente.")


def _transazione(stage, replacements, uid, identita, prima_avvio=None):
    """Keep old bundle/code/plist until the replacement service bootstraps."""
    label = "it.paratia.registro.%d" % uid
    precedenti, installati = [], []
    launchctl_errors = []
    for _, target in replacements:
        if target.exists() or target.is_symlink():
            _protetto(target, directory=target.is_dir())
            if target.is_dir():
                _albero(target, (0,))
    presente = _servizio_presente(label, launchctl_errors)
    if presente:
        # A successful bootout only schedules removal. Do not replace a loaded
        # job's executable or plist until launchd confirms that the label is gone.
        _arresta(label, launchctl_errors)
    try:
        for index, (candidate, target) in enumerate(replacements):
            backup = stage / ("precedente-%d" % index)
            if target.exists():
                os.replace(target, backup)
                precedenti.append((backup, target))
            os.replace(candidate, target)
            installati.append(target)
        # Both final path and signature are checked after rename, before launchd.
        _verifica_copia(SUPPORT / "Paratia.app", identita)
        if prima_avvio is not None:
            prima_avvio()
        _avvia(DAEMONS / (label + ".plist"), launchctl_errors)
    except BaseException as errore:
        recupero = []
        try:
            _arresta(label, launchctl_errors, rollback=True)
        except BaseException as exc:
            # A possibly loaded candidate must keep its executable. Leave both
            # candidate and protected originals untouched for manual recovery.
            raise ErroreInstallazione(
                "rollback_stop_failed", "Installazione non riuscita. Non è stato possibile confermare l'arresto durante il ripristino: conserva il backup protetto dell'installer; i componenti non sono stati rimossi.",
                launchctl_errors, conserva_stage=True, backup=str(stage)) from exc
        for target in reversed(installati):
            try:
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            except BaseException as exc:
                recupero.append(exc)
        for backup, target in reversed(precedenti):
            try:
                os.replace(backup, target)
            except BaseException as exc:
                recupero.append(exc)
        old_plist = DAEMONS / (label + ".plist")
        if recupero:
            raise ErroreInstallazione(
                "rollback_incomplete", "Il ripristino è incompleto: conserva il backup protetto dell'installer.",
                launchctl_errors, conserva_stage=True, backup=str(stage)) from errore
        if presente and not old_plist.exists():
            raise ErroreInstallazione(
                "rollback_bootstrap_failed", "Installazione non riuscita. I componenti precedenti sono stati ripristinati, ma il plist precedente non è disponibile e il servizio non è stato riavviato. Conserva il backup protetto e riprova l'installazione dall'app.",
                launchctl_errors, conserva_stage=True, backup=str(stage)) from errore
        if presente:
            try:
                _avvia(old_plist, launchctl_errors, rollback=True)
            except BaseException as exc:
                raise ErroreInstallazione(
                    "rollback_bootstrap_failed", "Installazione non riuscita. I componenti precedenti sono stati ripristinati, ma launchctl non ha riavviato il servizio precedente. Conserva il backup protetto e riprova l'installazione dall'app.",
                    launchctl_errors, conserva_stage=True, backup=str(stage)) from exc
        codice = getattr(errore, "error_code", "install_failed")
        dettaglio = str(errore) if isinstance(errore, ErroreInstallazione) else "Non è stato possibile completare la sostituzione dei componenti."
        ripristino = " Il servizio precedente è stato ripristinato e riavviato." if presente else " I componenti precedenti sono stati ripristinati."
        raise ErroreInstallazione(codice, dettaglio + ripristino, launchctl_errors) from errore
    return launchctl_errors


def installa(fonte, uid):
    if os.geteuid() != 0:
        raise PermissionError("L'installazione richiede il dialogo amministratore della GUI.")
    u = _utente(uid)
    fonte = Path(fonte).absolute()
    executable = runtime()
    app, identita = _app_sorgente(fonte, uid)
    for directory in (SUPPORT, LOGS, DAEMONS):
        _directory(directory)
    for directory in (SUPPORT, LOGS):
        subprocess.run(["/bin/chmod", "-N", str(directory)], check=True, capture_output=True)
    with _lock_installazione():
        stage = Path(tempfile.mkdtemp(dir=SUPPORT, prefix=".installazione-"))
        conserva = False
        try:
            _protetto(stage, directory=True)
            staged_app = stage / "Paratia.app"
            _albero(app, (0, uid), copia=staged_app)
            # Newly created objects inherit no ACL from protected Support.
            subprocess.run(["/bin/chmod", "-RN", str(staged_app)], check=True, capture_output=True)
            _verifica_copia(staged_app, identita)
            if _firma(app) != identita:
                raise ValueError("Il bundle corrente è cambiato durante la copia: il servizio precedente è conservato.")
            payload = staged_app / "Contents" / "Resources" / "python"
            contenuti = {nome: _leggi_codice(payload, nome, 0) for nome in CODICE}
            replacements = [(staged_app, SUPPORT / "Paratia.app")]
            for nome, contenuto in contenuti.items():
                candidato = stage / nome
                _scrivi(candidato, contenuto, 0o600)
                replacements.append((candidato, SUPPORT / nome))
            cartella = LOGS / str(uid)
            _directory(cartella)
            label = "it.paratia.registro.%d" % uid
            catena, stato = cartella / "catena.jsonl", cartella / "stato.json"
            for file in (catena, stato):
                if file.exists() or file.is_symlink():
                    _protetto(file)
            if not catena.exists():
                _scrivi(catena, b"", 0o600)
            candidato_stato = stage / "stato.json"
            _scrivi(candidato_stato, json.dumps({"running": False, "healthy": False, "needs_fda": None,
                    "launch_mode": "app", "fda_entry": FDA_APP, "fda_regrant_after_build": True,
                    "installed_cdhash": identita,
                    "message": "Registro installato; attendi la verifica delle autorizzazioni di /Applications/Paratia.app."}).encode(), 0o600)
            replacements.append((candidato_stato, stato))
            candidato_plist = stage / "servizio.plist"
            _scrivi(candidato_plist, plistlib.dumps(plist(uid, executable)), 0o644)
            replacements.append((candidato_plist, DAEMONS / (label + ".plist")))

            def autorizzazioni_log():
                os.chmod(SUPPORT, 0o700)
                os.chmod(LOGS, 0o711)
                os.chmod(cartella, 0o700)
                _acl(cartella, u.pw_name, directory=True)
                os.chmod(catena, 0o600, follow_symlinks=False)
                _acl(catena, u.pw_name)
                _acl(stato, u.pw_name)

            launchctl_errors = _transazione(stage, replacements, uid, identita, autorizzazioni_log)
            return {"installed": True, "error_code": None, "launchctl_errors": launchctl_errors,
                    "needs_fda": None, "label": label,
                    "launch_mode": "app", "fda_entry": FDA_APP,
                    "fda_regrant_after_build": True, "cdhash": identita,
                    "message": "Registro installato dalla copia protetta del bundle. Verifica lo stato; le autorizzazioni di macOS non sono state modificate."}
        except BaseException as exc:
            conserva = bool(getattr(exc, "conserva_stage", False))
            raise
        finally:
            if not conserva:
                shutil.rmtree(stage)


def main(argv=None):
    class ParserJSON(argparse.ArgumentParser):
        def error(self, message):
            raise ErroreInstallazione("invalid_arguments", "Gli argomenti dell'installatore non sono validi.")

    parser = ParserJSON(description="Prepara o installa il registro Paratia.", add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--install", action="store_true")
    codice = 0
    try:
        args = parser.parse_args(argv)
        if args.help:
            result = {"installed": False, "message": "Uso: registro_installa.py [--install] --uid UID --source RISORSE. L'installazione richiede l'autorizzazione amministratore della GUI."}
        else:
            result = installa(args.source, args.uid) if args.install else piano(args.source, args.uid)
        result.setdefault("installed", False)
        result.setdefault("error_code", None)
        result.setdefault("launchctl_errors", [])
    except (Exception, KeyboardInterrupt) as exc:
        codice = 1
        if isinstance(exc, ErroreInstallazione):
            error_code, message = exc.error_code, str(exc)
            errors = exc.launchctl_errors
        elif isinstance(exc, PermissionError):
            error_code = "permission_required"
            message = "L'installazione richiede il dialogo amministratore della GUI."
            errors = []
        elif isinstance(exc, KeyboardInterrupt):
            error_code = "installation_interrupted"
            message = "L'installazione è stata interrotta. Verifica lo stato del servizio e riprova dall'app."
            errors = []
        else:
            error_code = "install_failed"
            message = "Non è stato possibile preparare o installare il registro. Verifica la copia bootstrap protetta e il bundle firmato, quindi riprova dall'app."
            errors = []
        result = {"installed": False, "error_code": error_code, "message": message,
                  "launchctl_errors": errors}
        if getattr(exc, "conserva_stage", False):
            result["backup_retained"] = True
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return codice


if __name__ == "__main__":
    raise SystemExit(main())
