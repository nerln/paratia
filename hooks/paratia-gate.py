#!/usr/bin/env python3
"""Two refusals the model does not get a vote on, because the harness runs them.

The first is about the open compartment. `paratia` keeps secrets as ciphertext,
which is airtight while it is locked and worth nothing while it is not: mounted,
it is an ordinary volume and every process running as you can read it. The
obvious guard is a deny list of paths under the mountpoint. That guard is
defeated by `cat "$(printf '/Volumes/pa''ratia/token')"`, and by every other way
of writing a path that is not the way you wrote it down. So this does not look at
paths at all. It asks the kernel whether the volume is mounted, and if it is, it
denies the tool call — any tool call, whatever it says it is doing. There is no
string to disguise because no string is being read.

The second is about delegation, and it is the one that is not a solved problem
anywhere. Claude will not drive computer-use. Codex will. They are wired
together on this machine by AgentBridge, and each vendor enforces its own policy
over its own agent, correctly, in isolation. Nobody enforces anything over the
pair. So the restriction that holds for Claude alone does not hold for Claude
with a phone line: it asks Codex, Codex is not the one under the restriction,
and the composite system does the thing neither was supposed to do on its own.
No rule was broken. The capability was laundered through a second principal.

The fix is that capability has to *intersect* under delegation, not union. An
action inherits the narrowest set of every principal in the chain that asked for
it, and any chain whose most recent human is not the immediate requester loses
the human-only set entirely. So this reads the transcript — written by the
harness, not by the model, which is the whole reason it is worth reading — finds
who actually spoke last, and if the answer is another agent rather than Eugenio,
it takes the human-only tools off the table for that turn.

Both refusals fail closed: if this file cannot make up its mind, it says no.

Input is the PreToolUse payload on stdin. Output is a deny decision, or silence.

With --codex this also handles SessionStart closure and uses Codex's documented
continue=false decision on failure. Its disk guard applies to every tool that
Codex actually sends through PreToolUse. Delegation classification still needs
the Claude transcript provider and is not claimed for the Codex adapter.
"""

from __future__ import annotations

import ctypes
import errno
import fnmatch
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
MONTAGGIO = Path(os.environ.get("PARATIA_MOUNT", "/Volumes/paratia"))
REGOLE = CASA / "dogana.json"
BOOTSTRAP_ROOT = Path("/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app/Contents/Resources/python")
PYTHON_VERSIONS = Path("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions")
BOOTSTRAP_ASSETS = ("paratia.py", "cartelle.py", "registro.py", "catena.py", "hookinstaller.py",
                    "hooks/paratia-gate.py", "hooks/paratia-cli.json")

# Tools that only a human in the chair may ask for. Baked in rather than only
# configured, so deleting the config file loosens nothing — it is the floor, and
# dogana.json can add to it but never take away.
#
# computer-use and the browser are here for the reason in the docstring: they
# are the capabilities a restricted agent would go shopping for. The paratia
# tools are here because a delegated turn asking to open the compartment is the
# same attack one level down.
SOLO_UMANO = (
    "mcp__computer-use__*",
    "mcp__claude-in-chrome__*",
    "mcp__Claude_Browser__computer",
    "mcp__Claude_Code_iOS_Simulator__control",
)

# Shell commands a delegated turn may not run. Same reasoning, different surface:
# the tool is Bash and the capability is in the argv.
ARGV_SOLO_UMANO = ("paratia", "osascript", "cliclick", "security", "sudo")

# While the compartment is open every tool call is denied, with these exact
# invocations excepted so a session is not wedged: they close it or report on
# it, and neither reveals anything. The executable must resolve to this CLI or
# its fixed build-time source identity. A same-named file is never sufficient.
PERMESSI_APERTO = (
    ["lock"],
    ["status"],
    ["status", "--json"],
    ["cartella", "chiudi-tutte"],
    ["cartella", "elenco"],
)


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



def cli_attendibili() -> set[Path]:
    """The running hook and every application module must be root-protected."""
    root = Path(__file__).resolve().parent.parent
    return {BOOTSTRAP_ROOT / "paratia.py"} if _protected_bootstrap(root) else set()


def eseguibile_reale(nome: str) -> Path | None:
    """Resolve a call, never use its basename as evidence of its identity."""
    if nome.startswith("~/"):
        # HOME can be supplied by a tool payload or harness environment. The
        # account database supplies the operator's real home for this alias.
        nome = str(Path(pwd.getpwuid(os.getuid()).pw_dir) / nome[2:])
    if os.path.isabs(nome):
        percorso = nome
    elif nome in ("paratia", "python3"):
        percorso = shutil.which(nome)
    else:
        return None
    if not percorso:
        return None
    try:
        risultato = Path(percorso).resolve(strict=True)
        return risultato if risultato.is_file() else None
    except (OSError, RuntimeError):
        return None


def comando_sicuro_aperto(dati: dict) -> bool:
    """One literal invocation of the real CLI, with a harmless fixed verb."""
    comando = (dati.get("tool_input") or {}).get("command")
    if not isinstance(comando, str) or any(c in comando for c in ("$", "`", "\n", "\r", "\x00")):
        return False
    try:
        parser = shlex.shlex(comando, posix=True, punctuation_chars=";&|<>")
        parser.whitespace_split = True
        parser.commenters = ""
        argv = list(parser)
        if not argv:
            return False
        if any(value.startswith("~/") for value in argv):
            # The gate resolves ~ from passwd; reject a mismatched shell HOME
            # as well, because that shell would otherwise expand another path.
            if os.environ.get("HOME") != pwd.getpwuid(os.getuid()).pw_dir:
                return False
        attendibili = cli_attendibili()
        if not attendibili or any(name.startswith("DYLD_") for name in os.environ):
            return False
        programma = eseguibile_reale(argv[0])
        if programma in attendibili:
            # A direct script needs exactly the trusted isolated shebang. A
            # plain env/python3 shebang could load a user sitecustomize first.
            if not _root_path(Path("/usr/bin/env")):
                return False
            with programma.open("rb") as source:
                shebang = source.readline(1024).decode("ascii").rstrip("\n")
            prefix = "#!/usr/bin/env -S "
            if not shebang.startswith(prefix):
                return False
            runtime_args = shlex.split(shebang[len(prefix):])
            if (len(runtime_args) != 4 or runtime_args[1:] != ["-I", "-S", "-B"]
                    or not os.path.isabs(runtime_args[0])
                    or not _protected_runtime(Path(runtime_args[0]))):
                return False
            argomenti = argv[1:]
        else:
            # Isolation excludes PYTHONPATH, PYTHONHOME, cwd and user/site
            # customization. An otherwise genuine interpreter is insufficient.
            if (programma is None or not _protected_runtime(programma) or len(argv) < 5
                    or argv[1:4] != ["-I", "-S", "-B"]
                    or not (os.path.isabs(argv[4]) or argv[4].startswith("~/"))):
                return False
            script = eseguibile_reale(argv[4])
            if script not in attendibili:
                return False
            argomenti = argv[5:]
        if argomenti in PERMESSI_APERTO:
            return True
        return (len(argomenti) == 3 and argomenti[:2] == ["cartella", "chiudi"]
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", argomenti[2]) is not None)
    except (OSError, ValueError, TypeError, RuntimeError, KeyError, UnicodeError):
        return False


def nega(motivo: str) -> None:
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": motivo,
            }
        },
        sys.stdout,
    )


def montaggi_protetti() -> list[Path]:
    montaggi = [MONTAGGIO]
    registro = CASA / "cartelle.json"
    if registro.exists():
        dati = json.loads(registro.read_text())
        if not isinstance(dati, dict) or dati.get("versione") != 1 or not isinstance(dati.get("cartelle"), dict):
            raise ValueError("registro cartelle non valido")
        for voce in dati["cartelle"].values():
            if not isinstance(voce, dict):
                raise ValueError("voce cartella non valida")
            if voce.get("stato") in ("migrazione", "migrazione-incompleta") or voce.get("plaintext_residuo"):
                raise ValueError("migrazione da completare prima della sessione")
            monte = Path(voce["montaggio"])
            if not monte.is_absolute():
                raise ValueError("mountpoint non assoluto")
            montaggi.append(monte)
            if voce.get("montaggio_temporaneo"):
                montaggi.append(Path(voce["montaggio_temporaneo"]))
    return montaggi


def compartimento_aperto() -> bool:
    try:
        return any(p.is_mount() for p in montaggi_protetti())
    except (OSError, ValueError, KeyError, TypeError):
        # Cannot tell. The whole point of this file is that "cannot tell" is a
        # refusal, so report open and let the caller deny.
        return True


def chiudi_inizio_sessione() -> int:
    """SessionStart closes compartments; ordinary tool calls keep denying open ones."""
    try:
        # Already closed needs no imported disk backend. This also lets an
        # unprotected fallback keep ordinary sessions usable while closed.
        if not compartimento_aperto():
            return 0
        import importlib.util
        if (CASA / "cartelle.json").exists():
            root = Path(__file__).resolve().parent.parent
            if (not _protected_bootstrap(root) or not sys.flags.isolated or not sys.flags.no_site
                    or not _protected_runtime(Path(sys.executable).resolve(strict=True))):
                raise RuntimeError("la chiusura automatica richiede codice e runtime protetti")
            modulo = root / "cartelle.py"
            spec = importlib.util.spec_from_file_location("cartelle_session_start", modulo)
            cartelle = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = cartelle
            spec.loader.exec_module(cartelle)
            risultati = cartelle.chiudi_tutte()
            if any(r.get("errore") for r in risultati):
                raise RuntimeError("una cartella è occupata")
        if MONTAGGIO.is_mount():
            esito = subprocess.run(["/usr/bin/hdiutil", "detach", str(MONTAGGIO)],
                                   capture_output=True)
            if esito.returncode:
                raise RuntimeError("il forziere è occupato")
        if compartimento_aperto():
            raise RuntimeError("un compartimento risulta ancora aperto")
    except Exception:
        print("Paratia: chiusura incompleta. Chiudi i documenti aperti e premi "
              "Chiudi tutte in Paratia; se una migrazione è incompleta, usa "
              "Recupera nell'app prima di avviare l'agente.", file=sys.stderr)
        return 2
    return 0


def solo_umano() -> tuple[str, ...]:
    extra: tuple[str, ...] = ()
    try:
        if REGOLE.is_file():
            dati = json.loads(REGOLE.read_text())
            extra = tuple(dati.get("solo_umano", ()))
    except Exception:  # noqa: BLE001
        pass
    return SOLO_UMANO + extra


def chi_ha_parlato(transcript: str | None) -> str | None:
    """Return the name of the agent whose message opened this turn, or None for
    a human turn.

    Walks the harness-written JSONL backwards for the most recent real user
    turn: not a tool result, not a meta row, not a sidechain. AgentBridge
    delivers Codex's messages into that same slot wrapped in a channel tag, so
    the tag is the evidence, and it is evidence the model cannot forge because
    the model does not write this file.
    """
    if not transcript:
        return None
    p = Path(transcript)
    if not p.is_file():
        return None
    try:
        righe = p.read_text(errors="replace").splitlines()
    except OSError:
        return None

    for riga in reversed(righe[-400:]):
        if not riga.strip():
            continue
        try:
            r = json.loads(riga)
        except json.JSONDecodeError:
            continue
        if r.get("type") != "user" or r.get("isMeta") or r.get("isSidechain"):
            continue
        contenuto = (r.get("message") or {}).get("content")
        if isinstance(contenuto, list):
            # A list of blocks is a tool result unless it holds plain text.
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in contenuto):
                continue
            testo = " ".join(
                b.get("text", "") for b in contenuto if isinstance(b, dict) and b.get("type") == "text"
            )
        elif isinstance(contenuto, str):
            testo = contenuto
        else:
            continue

        # Every bridge that can open a turn here has to be named, because a
        # channel this does not recognise is a channel it treats as the
        # operator. `fanale` carries an origin attribute and it is deliberately
        # NOT consulted: a human typing on the other machine is not the human
        # in front of THIS screen, and the human-only set on this machine is
        # about who can see what computer-use is about to do. A remote human
        # asking through a bridge gets the restricted treatment, same as an
        # agent, and the envelope's origin field does its work on the far side
        # where it governs hop depth.
        for marcatore in ('<channel source="agentbridge"', "<channel source='agentbridge'",
                          '<channel source="fanale"', "<channel source='fanale'"):
            if marcatore in testo:
                fra = testo.split('user="', 1)
                nome = fra[1].split('"', 1)[0] if len(fra) > 1 else "another agent"
                if 'source="fanale"' in testo or "source='fanale'" in testo:
                    nome = f"{nome} over the SSH bridge"
                return nome
        return None  # most recent speaker was the human, at this keyboard
    return None


def argv_di(dati: dict) -> list[str] | None:
    comando = (dati.get("tool_input") or {}).get("command")
    if not isinstance(comando, str):
        return None
    try:
        return shlex.split(comando)
    except ValueError:
        return None


def main(*, codex: bool = False) -> int:
    try:
        dati = json.load(sys.stdin)
        if not isinstance(dati, dict):
            raise ValueError("payload is not an object")
    except Exception as e:  # noqa: BLE001
        nega(f"paratia could not read the tool call ({type(e).__name__}), so it does not run")
        return 0

    if dati.get("hook_event_name") == "SessionStart":
        esito = chiudi_inizio_sessione()
        if esito and codex:
            # Codex documents this SessionStart decision explicitly. The mount
            # guard remains a second check on every supported tool invocation.
            json.dump({"continue": False,
                       "stopReason": "Paratia non ha confermato la chiusura dei compartimenti.",
                       "systemMessage": "Chiudi i documenti e usa Chiudi tutte o Recupera in Paratia."},
                      sys.stdout)
            return 0
        return esito

    strumento = dati.get("tool_name", "")

    # ---- first refusal: the compartment is open
    if compartimento_aperto():
        if strumento == "Bash" and comando_sicuro_aperto(dati):
            return 0
        nega(
            "A paratia compartment is mounted, so its plaintext is "
            f"readable by anything running as this user, including this session. Every "
            "tool call is refused until it is closed. Allowed commands / Comandi consentiti: "
            "`paratia cartella chiudi <id>`, `paratia cartella chiudi-tutte`, `paratia lock`, "
            "`paratia status`, `paratia status --json`, `paratia cartella elenco`. "
            "These exceptions require the root-protected ParatiaBootstrap.noindex CLI, every Python "
            "resource and Apple's protected runtime. Python calls require `PYTHON_APPLE -I -S -B "
            "/Library/Application Support/ParatiaBootstrap.noindex/Paratia.app/Contents/Resources/python/paratia.py ...` "
            "with the script path quoted. Equivalent absolute paths or ~/.local/bin/paratia "
            "must resolve to that protected copy. If this protection is unavailable, no CLI "
            "exception is allowed: open Paratia from Finder and close the folders in the app. "
            "Se la copia protetta non è disponibile, chiudi le cartelle dall'app Paratia aperta dal Finder. "
            "Close protected folders with "
            "chiudi or chiudi-tutte and the main store with lock; use status --json to check. "
            "Usa l'ID indicato da cartella elenco; niente altri comandi, concatenazioni o redirezioni."
        )
        return 0

    # Codex's transcript is not the Claude provider below. Its adapter retains
    # both disk guards and makes no claim about delegation classification.
    if codex:
        return 0

    # ---- second refusal: this turn was opened by another agent
    mittente = chi_ha_parlato(dati.get("transcript_path"))
    if mittente is None:
        return 0

    modelli = solo_umano()
    if any(fnmatch.fnmatch(strumento, m) for m in modelli):
        nega(
            f"This turn was opened by {mittente}, not by Eugenio, and `{strumento}` is "
            f"in the human-only set. Under delegation a capability is the intersection "
            f"of every principal in the chain, not the union, so an agent asking on "
            f"behalf of another agent does not inherit what neither was granted "
            f"directly. Ask Eugenio in his own turn."
        )
        return 0

    if strumento == "Bash":
        argv = argv_di(dati)
        if argv is None:
            nega(
                f"This turn was opened by {mittente}, and the shell command could not be "
                f"parsed, so it is refused rather than guessed at."
            )
            return 0
        if argv and Path(argv[0]).name in ARGV_SOLO_UMANO:
            nega(
                f"This turn was opened by {mittente}, and `{Path(argv[0]).name}` is in the "
                f"human-only set. Delegated turns do not inherit it."
            )
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:] not in ([], ["--codex"]):
            print("Paratia: opzione hook non valida.", file=sys.stderr)
            sys.exit(2)
        sys.exit(main(codex=sys.argv[1:] == ["--codex"]))
    except Exception as e:  # noqa: BLE001
        nega(f"the paratia gate itself failed ({type(e).__name__}), so nothing runs")
        sys.exit(0)
