#!/usr/bin/python3
"""Fixed-scope installer invoked only by the human GUI's admin authorization.

Calling piano()/prepara() prepares reviewable argv and a plist without invoking
privilege, changing TCC, or touching any keychain.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import plistlib
import pwd
import stat
import subprocess
import tempfile
from pathlib import Path

SUPPORT = Path("/Library/Application Support/Paratia")
LOGS = Path("/Library/Logs/Paratia")
DAEMONS = Path("/Library/LaunchDaemons")
CODICE = ("catena.py", "registro.py", "registro_daemon.py")
MAX_CODICE = 1048576

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
    """Resolve Apple's launcher: /usr/bin/python3 alone is not a trust boundary."""
    candidati = [Path("/Library/Developer/CommandLineTools/usr/bin/python3"), Path("/usr/bin/python3")]
    for candidato in candidati:
        try:
            candidato = _rootpath(candidato)
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
            if versione < [3, 9]:
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
            "ProgramArguments": [executable or runtime(), "-I", "-S", str(SUPPORT / "registro_daemon.py"), "--uid", str(uid)],
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
    for nome in (*CODICE, "registro_installa.py"):
        p = fonte / nome
        if not p.is_file() or p.is_symlink():
            raise ValueError("I componenti del registro non sono disponibili nell'app.")
    return {"argv": [executable, "-I", "-S", str(fonte / "registro_installa.py"),
                     "--install", "--uid", str(uid), "--source", str(fonte)],
            "plist": plist(uid, executable), "label": "it.paratia.registro.%d" % uid,
            "needs_root": True, "needs_fda": True,
            "message": "L'autorizzazione amministratore installa un LaunchDaemon root. Poi autorizza /usr/bin/eslogger in Accesso completo al disco."}


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


def installa(fonte, uid):
    if os.geteuid() != 0:
        raise PermissionError("L'installazione richiede il dialogo amministratore della GUI.")
    u = _utente(uid)
    fonte = Path(fonte).absolute()
    executable = runtime()
    # Validate and compile every payload before making any privileged change.
    contenuti = {nome: _leggi_codice(fonte, nome, uid) for nome in CODICE}
    for directory in (SUPPORT, LOGS, DAEMONS):
        _directory(directory)
    for directory in (SUPPORT, LOGS):
        subprocess.run(["/bin/chmod", "-N", str(directory)], check=True, capture_output=True)
    cartella = LOGS / str(uid)
    _directory(cartella)
    label = "it.paratia.registro.%d" % uid
    p = DAEMONS / (label + ".plist")
    # Stop the existing service before updating its root-owned code/state.
    subprocess.run(["/bin/launchctl", "bootout", "system/" + label], capture_output=True)
    for nome, contenuto in contenuti.items():
        _scrivi(SUPPORT / nome, contenuto, 0o600)
    os.chmod(SUPPORT, 0o700)
    os.chmod(LOGS, 0o711)  # Traversal only; uid directories remain private.
    os.chmod(cartella, 0o700)
    _acl(cartella, u.pw_name, directory=True)
    catena = cartella / "catena.jsonl"
    if not catena.exists():
        _scrivi(catena, b"", 0o600)
    else:
        s = catena.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0:
            raise ValueError("La catena installata non è protetta da root.")
        os.chmod(catena, 0o600, follow_symlinks=False)
    _acl(catena, u.pw_name)
    stato = cartella / "stato.json"
    _scrivi(stato, json.dumps({"running": False, "healthy": False, "needs_fda": None,
                              "message": "Registro installato; verifica Accesso completo al disco."}).encode(), 0o600)
    _acl(stato, u.pw_name)
    _scrivi(p, plistlib.dumps(plist(uid, executable)), 0o644)
    subprocess.run(["/bin/launchctl", "bootstrap", "system", str(p)], check=True, capture_output=True)
    return {"installed": True, "needs_fda": True, "label": label}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepara o installa il registro Paratia.")
    parser.add_argument("--uid", type=int, default=os.getuid())
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args(argv)
    result = installa(args.source, args.uid) if args.install else piano(args.source, args.uid)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print("Installazione non riuscita (%s). Riapri l'app e riprova il pulsante Installa il registro." % type(e).__name__)
        raise SystemExit(1)
