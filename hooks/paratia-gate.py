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

import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
MONTAGGIO = Path(os.environ.get("PARATIA_MOUNT", "/Volumes/paratia"))
REGOLE = CASA / "dogana.json"

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


def cli_attendibili() -> set[Path]:
    """Fixed code identities; payload, PATH and user settings cannot add one."""
    radice = Path(__file__).resolve().parent.parent
    locale = radice / "paratia.py"
    percorsi = {locale} if locale.is_file() and not locale.is_symlink() else set()
    manifesto = Path(__file__).resolve().with_name("paratia-cli.json")
    if manifesto.exists() or manifesto.is_symlink():
        if manifesto.is_symlink() or not manifesto.is_file() or manifesto.stat().st_size > 8192:
            raise ValueError("manifesto CLI non valido")
        dati = json.loads(manifesto.read_text())
        if (not isinstance(dati, dict) or set(dati) != {"versione", "sorgente"}
                or dati["versione"] != 1 or not isinstance(dati["sorgente"], str)):
            raise ValueError("manifesto CLI non valido")
        sorgente = Path(dati["sorgente"])
        if (not sorgente.is_absolute() or str(sorgente) != dati["sorgente"]
                or str(sorgente) != os.path.normpath(str(sorgente))
                or str(sorgente).startswith("//")):
            raise ValueError("percorso CLI non valido")
        # Do not resolve this stored identity again: replacing it by a symlink
        # must not change which program the manifest authorizes.
        if sorgente.is_file() and not sorgente.is_symlink():
            percorsi.add(sorgente)
    return percorsi


def eseguibile_reale(nome: str) -> Path | None:
    """Resolve a call, never use its basename as evidence of its identity."""
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
        attendibili = cli_attendibili()
        programma = eseguibile_reale(argv[0])
        if programma in attendibili:
            argomenti = argv[1:]
        else:
            # Fixed installed runtimes, plus the interpreter running this hook.
            # Resolving PATH finds the actual call but cannot add a trusted one.
            runtimes = set()
            for nome in (sys.executable, "/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"):
                runtime = eseguibile_reale(nome)
                if runtime is not None:
                    runtimes.add(runtime)
            if programma not in runtimes or len(argv) < 2 or not os.path.isabs(argv[1]):
                return False
            script = eseguibile_reale(argv[1])
            if script not in attendibili:
                return False
            argomenti = argv[2:]
        if argomenti in PERMESSI_APERTO:
            return True
        return (len(argomenti) == 3 and argomenti[:2] == ["cartella", "chiudi"]
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", argomenti[2]) is not None)
    except (OSError, ValueError, TypeError, RuntimeError):
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
        import importlib.util
        modulo = Path(__file__).resolve().parent.parent / "cartelle.py"
        if (CASA / "cartelle.json").exists():
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
            "Equivalent absolute paths and `python3 /absolute/path/paratia.py ...` are allowed "
            "only when they resolve to the real Paratia CLI. Close protected folders with "
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
