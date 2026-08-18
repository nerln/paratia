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
"""

from __future__ import annotations

import fnmatch
import json
import os
import shlex
import sys
from pathlib import Path

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
# it, and neither reveals anything. Matched after shlex.split against the whole
# command, so `paratia lock; cat /Volumes/paratia/x` is not one of them.
PERMESSI_APERTO = (
    ["paratia", "lock"],
    ["paratia", "status"],
    ["paratia", "status", "--json"],
)


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


def compartimento_aperto() -> bool:
    try:
        return MONTAGGIO.is_mount()
    except OSError:
        # Cannot tell. The whole point of this file is that "cannot tell" is a
        # refusal, so report open and let the caller deny.
        return True


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


def main() -> int:
    try:
        dati = json.load(sys.stdin)
        if not isinstance(dati, dict):
            raise ValueError("payload is not an object")
    except Exception as e:  # noqa: BLE001
        nega(f"paratia could not read the tool call ({type(e).__name__}), so it does not run")
        return 0

    strumento = dati.get("tool_name", "")

    # ---- first refusal: the compartment is open
    if compartimento_aperto():
        argv = argv_di(dati)
        if strumento == "Bash" and argv is not None and list(argv) in [list(x) for x in PERMESSI_APERTO]:
            return 0
        nega(
            f"The paratia compartment is mounted at {MONTAGGIO}, so its plaintext is "
            f"readable by anything running as this user, including this session. Every "
            f"tool call is refused until it is closed. Run `paratia lock` — that one is "
            f"allowed — or close it from your own terminal, then carry on."
        )
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
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        nega(f"the paratia gate itself failed ({type(e).__name__}), so nothing runs")
        sys.exit(0)
