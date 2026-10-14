"""Reviewable, reversible user hook configuration for the native Paratia app.

This module and the gate run with protected Apple's Python 3.9 or newer,
isolated from user imports. Codex hook trust is always a human action:
this helper neither writes trust state nor changes feature/bypass settings.
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

import base64
import contextlib
import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
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
BOOTSTRAP_ROOT = Path("/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app/Contents/Resources/python")
# Previous signed copies are cleanup identities, never trusted CLI locations.
LEGACY_BOOTSTRAP_ROOT = Path("/Library/Application Support/ParatiaBootstrap/Paratia.app/Contents/Resources/python")
PYTHON_VERSIONS = Path("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions")
BOOTSTRAP_ASSETS = ("paratia.py", "cartelle.py", "registro.py", "catena.py", "hookinstaller.py",
                    "hooks/paratia-gate.py", "hooks/paratia-cli.json")
EVENTS = {"SessionStart": 120, "PreToolUse": 5}
MESSAGE = (_t("Hook configurati. Riavvia le sessioni. In Codex apri /hooks "
           "(o la gestione hook dell'app) e verifica/approva la definizione: "
           "la fiducia non viene impostata da Paratia."))


class Rifiuto(Exception):
    """A config could not be changed without risking existing user settings."""


def _acl_write_safe(path):
    """Darwin's extended ACL, with the same write grants as the native bridge."""
    if sys.platform != "darwin":
        return False
    try:
        library = ctypes.CDLL(None, use_errno=True)
        for name, args, result in (
            ("acl_get_file", [ctypes.c_char_p, ctypes.c_int], ctypes.c_void_p),
            ("acl_get_entry", [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
            ("acl_get_tag_type", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.c_int),
            ("acl_get_permset", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
            ("acl_get_perm_np", [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
            ("acl_valid", [ctypes.c_void_p], ctypes.c_int),
            ("acl_free", [ctypes.c_void_p], ctypes.c_int),
        ):
            function = getattr(library, name)
            function.argtypes, function.restype = args, result
        ctypes.set_errno(0)
        acl = library.acl_get_file(os.fsencode(path), 0x100)  # ACL_TYPE_EXTENDED
        if not acl:
            return ctypes.get_errno() in (errno.ENOENT, errno.ENOTSUP)
        try:
            if library.acl_valid(acl) != 0:
                return False
            position = 0  # ACL_FIRST_ENTRY; ACL_NEXT_ENTRY is -1 on Darwin.
            for _ in range(4096):
                entry = ctypes.c_void_p()
                ctypes.set_errno(0)
                result = library.acl_get_entry(acl, position, ctypes.byref(entry))
                if result != 0:
                    # Darwin documents EINVAL at the end of a valid ACL.
                    # Unexpected read errors are never treated as empty ACLs.
                    return result == -1 and ctypes.get_errno() == errno.EINVAL and library.acl_valid(acl) == 0
                position = -1
                tag, permissions = ctypes.c_int(), ctypes.c_void_p()
                if (library.acl_get_tag_type(entry, ctypes.byref(tag))
                        or library.acl_get_permset(entry, ctypes.byref(permissions))):
                    return False
                if tag.value == 1 and any(library.acl_get_perm_np(permissions, 1 << bit)
                                          for bit in (2, 4, 5, 6, 8, 10, 12, 13)):
                    return False
            return False
        finally:
            library.acl_free(acl)
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _root_path(path, cache=None):
    """lstat every component: no aliases, non-root owners, writes or write ACLs."""
    path = Path(path)
    if (not path.is_absolute() or str(path) != os.path.normpath(str(path))
            or str(path).startswith("//") or any(p in (".", "..") for p in path.parts)):
        return False
    cache = {} if cache is None else cache
    for current in (path, *path.parents):
        name = str(current)
        if name not in cache:
            try:
                metadata = os.lstat(current)
                cache[name] = (metadata.st_uid == 0 and not metadata.st_mode & 0o022
                               and (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))
                               and _acl_write_safe(current))
            except OSError:
                cache[name] = False
        if not cache[name]:
            return False
    return True


def _root_tree(root, cache=None, runtime_version=None):
    """Check all transitive code, including bytecode and extension modules."""
    cache = {} if cache is None else cache
    if not _root_path(root, cache) or not Path(root).is_dir():
        return False
    pending, count = [Path(root)], 0
    try:
        while pending:
            for entry in os.scandir(pending.pop()):
                count += 1
                if count > 20_000:
                    return False
                path = Path(entry.path)
                # Apple ships two build/linker aliases in this non-importable
                # config directory. Their fixed root-owned links must point to
                # the checked framework binary. Application resources have no
                # such exception; every alias there is refused.
                if runtime_version and entry.is_symlink():
                    relative = path.relative_to(root).as_posix()
                    aliases = {f"config-{runtime_version}-darwin/libpython{runtime_version}.a",
                               f"config-{runtime_version}-darwin/libpython{runtime_version}.dylib"}
                    metadata = os.lstat(path)
                    target = Path(root).parent.parent / "Python3"
                    if (relative not in aliases or metadata.st_uid != 0
                            or os.readlink(path) != "../../../Python3"
                            or not _root_path(path.parent, cache) or not _root_path(target, cache)):
                        return False
                    continue
                if not _root_path(path, cache):
                    return False
                if entry.is_dir(follow_symlinks=False):
                    # -S prevents this directory being added to sys.path.
                    if not (runtime_version and path == Path(root) / "site-packages"):
                        pending.append(path)
        return True
    except (OSError, ValueError):
        return False


def _protected_runtime(binary):
    binary = Path(binary)
    version = binary.parent.parent
    if (binary.parent.name != "bin" or version.parent != PYTHON_VERSIONS
            or not re.fullmatch(r"3\.(?:9|[1-9][0-9]+)", version.name)
            or not re.fullmatch(r"python3(?:\.[0-9]+)?", binary.name)):
        return False
    cache = {}
    return (_root_path(binary, cache) and binary.is_file()
            and _root_path(version / "Python3", cache)
            and _root_tree(version / "lib" / ("python" + version.name), cache,
                           runtime_version=version.name))


def _protected_bootstrap(root=None):
    root = BOOTSTRAP_ROOT if root is None else Path(root)
    if root != BOOTSTRAP_ROOT or not _root_tree(root):
        return False
    try:
        if not all((root / relative).is_file() for relative in BOOTSTRAP_ASSETS):
            return False
        manifest = root / "hooks" / "paratia-cli.json"
        if manifest.stat().st_size > 8192:
            return False
        data = json.loads(manifest.read_text())
        if (not isinstance(data, dict) or set(data) != {"versione", "cli", "hook_legacy"}
                or data["versione"] != 2 or data["cli"] != str(root / "paratia.py")):
            return False
        legacy = data["hook_legacy"]
        return (isinstance(legacy, str) and legacy.startswith("/")
                and legacy == os.path.normpath(legacy) and not legacy.startswith("//"))
    except (OSError, ValueError, TypeError):
        return False


def _digest(data):
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rifiuto(_t("Il JSON contiene campi duplicati: correggilo prima di installare gli hook."))
        result[key] = value
    return result


def _json(data):
    try:
        def invalid(_):
            raise ValueError()
        value = json.loads(data, object_pairs_hook=_object, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rifiuto(_t("Una configurazione hook non contiene JSON valido.")) from exc
    if not isinstance(value, dict):
        raise Rifiuto(_t("La configurazione hook deve essere un oggetto JSON."))
    return value


def _owned(s):
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_nlink != 1:
        raise Rifiuto(_t("Configurazioni, backup e lock devono essere file ordinari dell'utente, senza collegamenti."))
    if stat.S_IMODE(s.st_mode) & ~0o777:
        raise Rifiuto(_t("I file di configurazione non possono avere bit di autorizzazione speciali."))


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
        raise Rifiuto(_t("Impossibile leggere una configurazione senza seguire collegamenti.")) from exc
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(fd)
        _owned(before)
        if before.st_size > limit:
            raise Rifiuto(_t("La configurazione o il backup supera il limite consentito."))
        data = source.read(limit + 1)
        if len(data) > limit or _signature(before) != _signature(os.fstat(fd)):
            raise Rifiuto(_t("La configurazione è cambiata durante la lettura."))
        return data, stat.S_IMODE(before.st_mode)


@contextlib.contextmanager
def _home_directory(home):
    p = Path(home if home is not None else Path.home()).expanduser()
    if not p.is_absolute() or str(p) != os.path.normpath(str(p)):
        raise Rifiuto(_t("La home richiede un percorso assoluto senza alias."))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        if os.fstat(fd).st_uid != os.getuid():
            raise Rifiuto(_t("La directory di configurazione deve appartenere all'utente corrente."))
        yield p, fd
    except OSError as exc:
        raise Rifiuto(_t("La home non è una directory accessibile senza collegamenti.")) from exc
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
                    raise Rifiuto(_t("Le directory dei due harness devono appartenere all'utente corrente."))
            yield path, handles
        except OSError as exc:
            raise Rifiuto(_t("Una directory hook o il lock non è accessibile senza collegamenti.")) from exc
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


def _runtime(executable=None):
    candidates = [executable] if executable is not None else sorted(
        PYTHON_VERSIONS.glob("3.*/bin/python3.*"), reverse=True)
    for candidate in candidates:
        if not candidate or not Path(candidate).is_absolute():
            continue
        try:
            p = Path(candidate).resolve(strict=True)
            if os.access(p, os.X_OK) and _protected_runtime(p):
                return p
        except (OSError, ValueError, RuntimeError):
            continue
    raise Rifiuto(_t("Gli hook richiedono il Python Apple 3.9 o successivo dei Command Line Tools, con runtime e libreria standard protetti da root. Ripristina i Command Line Tools prima di configurarli."))


def _parameters(resource_root=None, python_executable=None):
    root = BOOTSTRAP_ROOT if _protected_bootstrap() else Path(
        resource_root if resource_root is not None else Path(__file__).resolve().parent)
    if not root.is_absolute() or str(root) != os.path.normpath(str(root)):
        raise Rifiuto(_t("Le risorse dell'app richiedono un percorso assoluto."))
    script = root / "hooks" / "paratia-gate.py"
    for p in [*reversed(script.parents), script]:
        if p.is_symlink():
            raise Rifiuto(_t("Le risorse hook non possono usare collegamenti simbolici."))
    for asset in (script, root / "cartelle.py"):
        try:
            s = asset.lstat()
        except OSError as exc:
            raise Rifiuto(_t("Le risorse della chiusura dei compartimenti non sono disponibili nell'app.")) from exc
        if not stat.S_ISREG(s.st_mode) or s.st_uid not in (0, os.getuid()) or s.st_size > MAX_JSON:
            raise Rifiuto(_t("Una risorsa hook non è un file ordinario attendibile."))
    python = _runtime(python_executable)
    command = " ".join(shlex.quote(str(p)) for p in (python, "-I", "-S", "-B", script))
    wanted = {}
    for harness in TARGETS:
        call = command + (" --codex" if harness == "codex" else "")
        wanted[harness] = {event: {"matcher": "*", "hooks": [
            {"type": "command", "command": call, "timeout": timeout}
        ]} for event, timeout in EVENTS.items()}
    return wanted


def _legacy_scripts(resource_root=None):
    scripts = {str(Path(__file__).resolve().parent / "hooks" / "paratia-gate.py"),
               "/Applications/Paratia.app/Contents/Resources/python/hooks/paratia-gate.py",
               str(LEGACY_BOOTSTRAP_ROOT / "hooks" / "paratia-gate.py"),
               str(BOOTSTRAP_ROOT / "hooks" / "paratia-gate.py")}
    if resource_root is not None:
        scripts.add(str(Path(resource_root) / "hooks" / "paratia-gate.py"))
    if _protected_bootstrap():
        data = json.loads((BOOTSTRAP_ROOT / "hooks" / "paratia-cli.json").read_text())
        # This field removes a previous exact handler; it never adds a CLI
        # identity or authorizes execution of code at the legacy path.
        scripts.add(data["hook_legacy"])
    return scripts


def _own_legacy_handler(handler, harness, event, scripts):
    if (not isinstance(handler, dict) or set(handler) != {"type", "command", "timeout"}
            or handler["type"] != "command" or handler["timeout"] != EVENTS[event]
            or not isinstance(handler["command"], str)):
        return False
    try:
        argv = shlex.split(handler["command"])
    except ValueError:
        return False
    if (not argv or not os.path.isabs(argv[0])
            or not re.fullmatch(r"python3(?:\.[0-9]+)?", Path(argv[0]).name)):
        return False
    tail = ["--codex"] if harness == "codex" else []
    for flags in (["-I", "-S"], ["-I", "-S", "-B"]):
        if (len(argv) == len(flags) + 2 + len(tail) and argv[1:1 + len(flags)] == flags
                and argv[1 + len(flags)] in scripts and argv[2 + len(flags):] == tail):
            return True
    return False


def _build(handles, wanted, resource_root=None):
    plans = []
    migrate = _protected_bootstrap()
    scripts = _legacy_scripts(resource_root) if migrate else set()
    for harness, (directory, name) in TARGETS.items():
        before, mode = _read(handles[harness], name)
        document = _json(before) if before is not None else {}
        hooks = document.get("hooks", {})
        if not isinstance(hooks, dict):
            raise Rifiuto(_t("Il campo hooks esistente non è un oggetto: correggilo prima dell'installazione."))
        merged = copy.deepcopy(document)
        merged.setdefault("hooks", {})
        events = {}
        migrated = False
        for event, group in wanted[harness].items():
            groups = hooks.get(event, [])
            if not isinstance(groups, list) or any(not isinstance(g, dict) for g in groups):
                raise Rifiuto(_t("Un evento hook esistente non contiene gruppi validi."))
            if migrate:
                kept = []
                for existing in groups:
                    if existing == group:
                        kept.append(existing)
                        continue
                    # Native definitions have a '*' matcher. Keep every
                    # foreign group field and foreign handler byte-for-byte.
                    if existing.get("matcher") == "*" and isinstance(existing.get("hooks"), list):
                        handlers = [h for h in existing["hooks"] if not _own_legacy_handler(h, harness, event, scripts)]
                        if handlers != existing["hooks"]:
                            migrated = True
                            if handlers:
                                kept.append({**existing, "hooks": handlers})
                            continue
                    kept.append(existing)
                groups = kept
                merged["hooks"][event] = copy.deepcopy(groups)
            events[event] = group in groups
            if not events[event]:
                merged["hooks"].setdefault(event, []).append(copy.deepcopy(group))
        try:
            after = (json.dumps(merged, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        except (TypeError, ValueError, RecursionError) as exc:
            raise Rifiuto(_t("La configurazione unita non può essere salvata come JSON.")) from exc
        if len(after) > MAX_JSON:
            raise Rifiuto(_t("La configurazione unita supera il limite consentito."))
        # A configured document is left byte-for-byte unchanged, including whitespace.
        changed = migrated or not all(events.values())
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
        _t("Hook da configurare. Dopo l'installazione riavvia le sessioni e approva "
        "la definizione in /hooks o nella gestione hook dell'app Codex."))
    if any(h["disabled_in_settings"] for h in harnesses.values()):
        message += _t(" Le impostazioni esistenti disattivano gli hook: riabilitali nell'harness.")
    protected = _protected_bootstrap()
    if not protected:
        message += _t(" Copia bootstrap protetta non disponibile: a cartella aperta non è consentita alcuna esenzione CLI. Chiudi le cartelle dall'app Paratia aperta dal Finder.")
    return {"configured": configured,
            "harnesses": harnesses, "needs_human_trust": True,
            "codex_trust": "unknown", "delegation_provider": "claude-transcript",
            "codex_delegation_verified": False, "protected_closure": protected,
            "docs": DOCS, "message": message}


def piano(resource_root=None, python_executable=None, *, home=None):
    """Read configs and describe only proposed handlers, without exposing foreign values."""
    wanted = _parameters(resource_root, python_executable)
    with _directories(home) as (path, handles):
        plans = _build(handles, wanted, resource_root)
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
            raise Rifiuto(_t("La configurazione è stata modificata da un altro programma: non sarà sovrascritta."))
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
        plans = _build(handles, wanted, resource_root)
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
                        raise Rifiuto(_t("La configurazione è stata modificata da un altro programma."))
                    _write(handles[plan["harness"]], plan["name"], current, plan["before"], plan["mode"])
                except Exception:
                    recovered = False
            refusal = Rifiuto(_t("Installazione non completata. ") + (
                _t("Le configurazioni già modificate sono state ripristinate.") if recovered else
                _t("Il ripristino è incompleto: conserva i backup e riapri le impostazioni degli hook.")))
            refusal.backups = backups
            raise refusal from exc
        result = _summary(path, _build(handles, wanted, resource_root))
        result.update(changed=bool(changed), backups=backups)
        return result


def ripristina(backup, *, home=None):
    """Restore an installer checkpoint only while the installed bytes still match."""
    p = Path(backup)
    with _directories(home, create=True) as (path, handles):
        harness = next((h for h, (d, _) in TARGETS.items() if p.parent == path / d), None)
        if harness is None or not p.name.startswith("." + TARGETS[harness][1] + ".paratia-backup-"):
            raise Rifiuto(_t("Il backup non appartiene alle configurazioni hook di questo utente."))
        raw, _ = _read(handles[harness], p.name, MAX_BACKUP)
        if raw is None:
            raise Rifiuto(_t("Il backup richiesto non è disponibile."))
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
            raise Rifiuto(_t("Il backup non contiene un riferimento valido.")) from exc
        current, current_mode = _read(handles[harness], name)
        if _digest(current) != record.get("after_digest"):
            raise Rifiuto(_t("La configurazione è cambiata dopo l'installazione: il backup non sovrascriverà le nuove impostazioni."))
        reverse = {"harness": harness, "name": name, "before": current, "after": before, "mode": current_mode}
        checkpoint, _ = _backup(handles[harness], reverse)
        _write(handles[harness], name, current, before, mode)
        return {"restored": True, "harness": harness, "backup": str(path / TARGETS[harness][0] / checkpoint)}
