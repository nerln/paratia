"""Reviewable, reversible user hook configuration for the native Paratia app.

This module remains importable by Apple's Python 3.9. The gate itself runs with
an absolute Python 3.11+ executable. Codex hook trust is always a human action:
this helper neither writes trust state nor changes feature/bypass settings.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

MAX_JSON = 4 * 1024**2
MAX_BACKUP = 8 * 1024**2
DOCS = "https://learn.chatgpt.com/docs/hooks"
TARGETS = {"claude": (".claude", "settings.json"), "codex": (".codex", "hooks.json")}
EVENTS = {"SessionStart": 120, "PreToolUse": 5}
MESSAGE = ("Hook configurati. Riavvia le sessioni. In Codex apri /hooks "
           "(o la gestione hook dell'app) e verifica/approva la definizione: "
           "la fiducia non viene impostata da Paratia.")


class Rifiuto(Exception):
    """A config could not be changed without risking existing user settings."""


def _digest(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rifiuto("Il JSON contiene campi duplicati: correggilo prima di installare gli hook.")
        result[key] = value
    return result


def _json(data):
    try:
        def invalid(_):
            raise ValueError()
        value = json.loads(data, object_pairs_hook=_object, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rifiuto("Una configurazione hook non contiene JSON valido.") from exc
    if not isinstance(value, dict):
        raise Rifiuto("La configurazione hook deve essere un oggetto JSON.")
    return value


def _owned(s):
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1:
        raise Rifiuto("Configurazioni, backup e lock devono essere file ordinari dell'utente, senza collegamenti.")
    if stat.S_IMODE(s.st_mode) & ~0o777:
        raise Rifiuto("I file di configurazione non possono avere bit di autorizzazione speciali.")


def _signature(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode


def _read(directory, name, limit=MAX_JSON):
    if directory is None:
        return None, None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        raise Rifiuto("Impossibile leggere una configurazione senza seguire collegamenti.") from exc
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(fd)
        _owned(before)
        if before.st_size > limit:
            raise Rifiuto("La configurazione o il backup supera il limite consentito.")
        data = source.read(limit + 1)
        if len(data) > limit or _signature(before) != _signature(os.fstat(fd)):
            raise Rifiuto("La configurazione è cambiata durante la lettura.")
        return data, stat.S_IMODE(before.st_mode)


@contextlib.contextmanager
def _home_directory(home):
    p = Path(home if home is not None else Path.home()).expanduser()
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
        raise Rifiuto("La home richiede un percorso assoluto senza alias.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if os.fstat(fd).st_uid != os.getuid():
            raise Rifiuto("La directory di configurazione deve appartenere all'utente corrente.")
        yield p, fd
    except OSError as exc:
        raise Rifiuto("La home non è una directory accessibile senza collegamenti.") from exc
    finally:
        os.close(fd)


@contextlib.contextmanager
def _directories(home, create=False):
    with _home_directory(home) as (path, homefd):
        handles = {}
        lock = None
        locked = False
        try:
            if create:
                try:
                    lock = os.open(".paratia-hooks.lock", os.O_CREAT | os.O_EXCL | os.O_RDWR |
                                   os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=homefd)
                except FileExistsError:
                    lock = os.open(".paratia-hooks.lock", os.O_RDWR | os.O_NOFOLLOW |
                                   os.O_NONBLOCK, dir_fd=homefd)
                _owned(os.fstat(lock))
                fcntl.flock(lock, fcntl.LOCK_EX)
                locked = True
            for harness, (name, _) in TARGETS.items():
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=homefd)
                except FileNotFoundError:
                    if not create:
                        handles[harness] = None
                        continue
                    os.mkdir(name, mode=0o700, dir_fd=homefd)
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=homefd)
                handles[harness] = fd
                if os.fstat(fd).st_uid != os.getuid():
                    raise Rifiuto("Le directory dei due harness devono appartenere all'utente corrente.")
            yield path, handles
        except OSError as exc:
            raise Rifiuto("Una directory hook o il lock non è accessibile senza collegamenti.") from exc
        finally:
            for fd in handles.values():
                if fd is not None:
                    os.close(fd)
            if lock is not None:
                try:
                    if locked:
                        fcntl.flock(lock, fcntl.LOCK_UN)
                finally:
                    os.close(lock)


def _stable_runtime_path(candidate):
    """Retain stable launch aliases instead of freezing Homebrew Cellar versions."""
    path = Path(candidate)
    if "Cellar" not in path.parts:
        return path
    index = path.parts.index("Cellar")
    if len(path.parts) <= index + 2:
        return None
    prefix = Path(*path.parts[:index])
    formula = path.parts[index + 1]
    target = path.resolve(strict=True)
    aliases = [prefix / "bin" / "python3", prefix / "bin" / path.name,
               prefix / "opt" / formula / "bin" / path.name,
               prefix / "opt" / formula / "libexec" / "bin" / "python3"]
    for alias in aliases:
        try:
            if alias.resolve(strict=True) == target:
                return alias
        except OSError:
            continue
    return None


def _runtime(executable=None):
    candidates = [executable] if executable is not None else [
        "/opt/homebrew/bin/python3", "/usr/local/bin/python3", sys.executable,
        *(shutil.which("python3.%d" % minor) for minor in range(14, 10, -1)),
    ]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_absolute():
            continue
        try:
            alias = _stable_runtime_path(candidate)
            if alias is None:
                continue
            p = alias.resolve(strict=True)
            if not p.is_file() or not os.access(p, os.X_OK):
                continue
            if p == Path(sys.executable).resolve() and sys.version_info[:2] >= (3, 11):
                return alias
            check = subprocess.run([str(alias), "-I", "-S", "-c",
                                    "import sys; print('%d.%d' % sys.version_info[:2])"],
                                   capture_output=True, timeout=5, check=False)
            if check.returncode == 0 and len(check.stdout) < 64:
                version = tuple(int(v) for v in check.stdout.decode("ascii").strip().split("."))
                if len(version) == 2 and version >= (3, 11):
                    return alias
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    raise Rifiuto("Gli hook richiedono Python 3.11 o successivo con percorso assoluto e stabile, per esempio /opt/homebrew/bin/python3; non usare una versione sotto Cellar.")


def _parameters(resource_root=None, python_executable=None):
    root = Path(resource_root if resource_root is not None else Path(__file__).resolve().parent)
    if not root.is_absolute() or str(root) != os.path.normpath(str(root)):
        raise Rifiuto("Le risorse dell'app richiedono un percorso assoluto.")
    script = root / "hooks" / "paratia-gate.py"
    for p in [*reversed(script.parents), script]:
        if p.is_symlink():
            raise Rifiuto("Le risorse hook non possono usare collegamenti simbolici.")
    for asset in (script, root / "cartelle.py"):
        try:
            s = asset.lstat()
        except OSError as exc:
            raise Rifiuto("Le risorse della chiusura dei compartimenti non sono disponibili nell'app.") from exc
        if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0, os.getuid()) or s.st_size > MAX_JSON:
            raise Rifiuto("Una risorsa hook non è un file ordinario attendibile.")
    python = _runtime(python_executable)
    command = " ".join(shlex.quote(str(p)) for p in (python, "-I", "-S", script))
    wanted = {}
    for harness in TARGETS:
        call = command + (" --codex" if harness == "codex" else "")
        wanted[harness] = {event: {"matcher": "*", "hooks": [
            {"type": "command", "command": call, "timeout": timeout}
        ]} for event, timeout in EVENTS.items()}
    return wanted


def _build(handles, wanted):
    plans = []
    for harness, (directory, name) in TARGETS.items():
        before, mode = _read(handles[harness], name)
        document = _json(before) if before is not None else {}
        hooks = document.get("hooks", {})
        if not isinstance(hooks, dict):
            raise Rifiuto("Il campo hooks esistente non è un oggetto: correggilo prima dell'installazione.")
        merged = copy.deepcopy(document)
        merged.setdefault("hooks", {})
        events = {}
        for event, group in wanted[harness].items():
            groups = hooks.get(event, [])
            if not isinstance(groups, list) or any(not isinstance(g, dict) for g in groups):
                raise Rifiuto("Un evento hook esistente non contiene gruppi validi.")
            events[event] = group in groups
            if not events[event]:
                merged["hooks"].setdefault(event, []).append(copy.deepcopy(group))
        try:
            after = (json.dumps(merged, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise Rifiuto("La configurazione unita non può essere salvata come JSON.") from exc
        if len(after) > MAX_JSON:
            raise Rifiuto("La configurazione unita supera il limite consentito.")
        # A configured document is left byte-for-byte unchanged, including whitespace.
        changed = not all(events.values())
        plans.append({"harness": harness, "directory": directory, "name": name,
                      "before": before, "after": after if changed else before,
                      "mode": mode, "events": events, "changed": changed,
                      "disabled": document.get("disableAllHooks") is True})
    return plans


def _summary(path, plans):
    harnesses = {p["harness"]: {"configured": all(p["events"].values()), "events": p["events"],
                               "path": str(path / p["directory"] / p["name"]),
                               "disabled_in_settings": p["disabled"],
                               "trust": "unknown" if p["harness"] == "codex" else "not-required",
                               "activation_verified": False} for p in plans}
    configured = all(h["configured"] for h in harnesses.values())
    message = MESSAGE if configured else (
        "Hook da configurare. Dopo l'installazione riavvia le sessioni e approva "
        "la definizione in /hooks o nella gestione hook dell'app Codex.")
    if any(h["disabled_in_settings"] for h in harnesses.values()):
        message += " Le impostazioni esistenti disattivano gli hook: riabilitali nell'harness."
    return {"configured": configured,
            "harnesses": harnesses, "needs_human_trust": True,
            "codex_trust": "unknown", "delegation_provider": "claude-transcript",
            "codex_delegation_verified": False, "docs": DOCS, "message": message}


def piano(resource_root=None, python_executable=None, *, home=None):
    """Read configs and describe only proposed handlers, without exposing foreign values."""
    wanted = _parameters(resource_root, python_executable)
    with _directories(home) as (path, handles):
        plans = _build(handles, wanted)
        result = _summary(path, plans)
        result["changes"] = [{"harness": p["harness"], "path": str(path / p["directory"] / p["name"]),
                              "changed": p["changed"], "hooks": wanted[p["harness"]]} for p in plans]
        return result


def stato(resource_root=None, python_executable=None, *, home=None):
    try:
        result = piano(resource_root, python_executable, home=home)
        result.pop("changes", None)
        return result
    except Rifiuto as exc:
        return {"configured": False, "harnesses": {}, "needs_human_trust": True,
                "codex_trust": "unknown", "codex_delegation_verified": False,
                "docs": DOCS, "error": str(exc), "message": str(exc)}


def _new_file(directory, name, data, mode=0o600):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
    with os.fdopen(fd, "wb") as destination:
        os.fchmod(fd, mode)
        destination.write(data)
        destination.flush()
        os.fsync(fd)


def _backup(directory, plan):
    record = {"versione": 1, "harness": plan["harness"], "file": plan["name"],
              "existed": plan["before"] is not None, "mode": plan["mode"],
              "before_base64": base64.b64encode(plan["before"]).decode("ascii") if plan["before"] is not None else None,
              "before_digest": _digest(plan["before"]), "after_digest": _digest(plan["after"])}
    name = ".%s.paratia-backup-%s-%s.json" % (plan["name"], time.strftime("%Y%m%dT%H%M%S"), uuid.uuid4().hex)
    _new_file(directory, name, json.dumps(record, sort_keys=True).encode())
    os.fsync(directory)
    return name, record


def _write(directory, name, before, after, mode):
    temporary = ".paratia-hooks-%s.tmp" % uuid.uuid4().hex
    try:
        if after is not None:
            _new_file(directory, temporary, after, mode if mode is not None else 0o600)
        current, _ = _read(directory, name)
        if current != before:
            raise Rifiuto("La configurazione è stata modificata da un altro programma: non sarà sovrascritta.")
        if after is None:
            os.unlink(name, dir_fd=directory)
        else:
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass


def installa(resource_root=None, python_executable=None, *, home=None):
    """User-invoked merge; both originals are backed up before either replacement."""
    wanted = _parameters(resource_root, python_executable)
    with _directories(home, create=True) as (path, handles):
        plans = _build(handles, wanted)
        changed = [p for p in plans if p["changed"]]
        backups = []
        try:
            for plan in changed:
                name, _ = _backup(handles[plan["harness"]], plan)
                backups.append(str(path / plan["directory"] / name))
            for plan in changed:
                _write(handles[plan["harness"]], plan["name"], plan["before"], plan["after"], plan["mode"])
        except Exception as exc:
            recovered = True
            # A replace can succeed even if its following directory fsync fails.
            # Inspect every planned target rather than only returned writes.
            for plan in reversed(changed):
                try:
                    current, _ = _read(handles[plan["harness"]], plan["name"])
                    if current == plan["before"]:
                        continue
                    if current != plan["after"]:
                        raise Rifiuto("La configurazione è stata modificata da un altro programma.")
                    _write(handles[plan["harness"]], plan["name"], current, plan["before"], plan["mode"])
                except Exception:
                    recovered = False
            refusal = Rifiuto("Installazione non completata. " + (
                "Le configurazioni già modificate sono state ripristinate." if recovered else
                "Il ripristino è incompleto: conserva i backup e riapri le impostazioni degli hook."))
            refusal.backups = backups
            raise refusal from exc
        result = _summary(path, _build(handles, wanted))
        result.update(changed=bool(changed), backups=backups)
        return result


def ripristina(backup, *, home=None):
    """Restore an installer checkpoint only while the installed bytes still match."""
    p = Path(backup)
    with _directories(home, create=True) as (path, handles):
        harness = next((h for h, (d, _) in TARGETS.items() if p.parent == path / d), None)
        if harness is None or not p.name.startswith("." + TARGETS[harness][1] + ".paratia-backup-"):
            raise Rifiuto("Il backup non appartiene alle configurazioni hook di questo utente.")
        raw, _ = _read(handles[harness], p.name, MAX_BACKUP)
        if raw is None:
            raise Rifiuto("Il backup richiesto non è disponibile.")
        record = _json(raw)
        name = TARGETS[harness][1]
        try:
            if record["versione"] != 1 or record["harness"] != harness or record["file"] != name or not isinstance(record["existed"], bool):
                raise ValueError()
            before = base64.b64decode(record["before_base64"], validate=True) if record["existed"] else None
            mode = record["mode"]
            if _digest(before) != record["before_digest"] or (before is not None and (len(before) > MAX_JSON or isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o777)):
                raise ValueError()
        except (KeyError, TypeError, ValueError) as exc:
            raise Rifiuto("Il backup non contiene un riferimento valido.") from exc
        current, current_mode = _read(handles[harness], name)
        if _digest(current) != record.get("after_digest"):
            raise Rifiuto("La configurazione è cambiata dopo l'installazione: il backup non sovrascriverà le nuove impostazioni.")
        reverse = {"harness": harness, "name": name, "before": current, "after": before, "mode": current_mode}
        checkpoint, _ = _backup(handles[harness], reverse)
        _write(handles[harness], name, current, before, mode)
        return {"restored": True, "harness": harness, "backup": str(path / TARGETS[harness][0] / checkpoint)}
