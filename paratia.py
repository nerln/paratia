#!/usr/bin/env python3
"""A compartment on this disk that no agent running as you can read.

The usual way to keep a file away from an agent is to write down that the file
is off limits: a line in CLAUDE.md, a path in a deny list, a sentence in a
skill. All three live in the same place the agent's instructions live, and a
model that misreads them, or a web page that carries an instruction of its own
and gets fetched mid-task, gets past all three. Worse, none of them are even
tested by the thing they claim to stop: the agent runs as your user, so it holds
your read bit on every file you own. A deny list is a list of the paths somebody
thought of, and `cat $(echo L1ZvbHVtZXM= | base64 -d)` is never on it.

So this does not hide a path. It removes the plaintext from the disk.

The store is an AES-256 sparsebundle. Locked, the bytes on disk are ciphertext,
and that is true against every process on this machine at every privilege level,
including this one. There is nothing to misread and nothing to talk past. The
passphrase is not stored anywhere: it lives in your head, it is read straight
from the terminal device, and `unlock` refuses to run inside an agent session.

That leaves one window: while the compartment is open, it is a normal mounted
volume and anything running as you can read it. So the window is held shut from
the other side. `paratia gate` is a PreToolUse hook that denies every agent tool
call for as long as the volume is mounted. It does not match paths, it reads
mount state, which is why no amount of quoting, base64 or shell indirection gets
around it: there is no string to disguise.

What an agent gets instead is `paratia broker`. Verbs are declared inside the
compartment, where the agent cannot edit them, and each one is a command line
with the secret filled in by this program. The agent names a verb and reads the
output. It never holds the value and never chooses the command.

Read docs/architettura.md for the layer-by-layer claim, including the two places
where this is tamper-evident rather than tamper-proof, and why on a one-account
Mac it cannot be anything else.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shlex
import subprocess
import sys
import termios
import time
from pathlib import Path

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
FORZIERE = CASA / "forziere.sparsebundle"
MONTAGGIO = Path(os.environ.get("PARATIA_MOUNT", "/Volumes/paratia"))
DIARIO = CASA / "diario.jsonl"

# Inside the compartment, so an agent can neither read the verb list to learn
# what secrets exist nor add a verb that prints one.
VERBI = "verbi.json"
SIGILLI = "sigilli.json"

# Environment set by the harnesses that run agents on this machine. Presence of
# any one of these means `unlock` will not prompt. This is a courtesy rail, not
# the boundary: an agent can unset a variable. The boundary is that the agent
# does not know the passphrase, so a prompt it managed to trigger is a prompt it
# cannot answer.
SPIE_AGENTE = (
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_PLUGIN_ROOT",
    "ANTHROPIC_MODEL",
    "CODEX_SANDBOX",
    "CODEX_HOME",
    "OPENAI_CODEX_SESSION",
    "CURSOR_AGENT",
    "AIDER_MODEL",
)


class Rifiuto(Exception):
    """Something was asked for that this program will not do."""


# ---------------------------------------------------------------- primitives


def _corri(argomenti: list[str], *, dentro: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argomenti, input=dentro, capture_output=True)


def aperto() -> bool:
    """True when the compartment is mounted and its contents are readable."""
    return MONTAGGIO.is_mount()


def dentro_un_agente() -> str | None:
    """Name the harness we appear to be running inside, or None."""
    for spia in SPIE_AGENTE:
        if os.environ.get(spia):
            return spia
    return None


def annota(evento: str, **campi) -> None:
    """Append one line to the log. Kept outside the compartment on purpose: a
    log you can only read when the thing is open tells you nothing about the
    times it was opened. It is append-only by convention only — see `attest`."""
    CASA.mkdir(parents=True, exist_ok=True)
    riga = {"quando": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "evento": evento, **campi}
    with DIARIO.open("a") as f:
        f.write(json.dumps(riga, ensure_ascii=False) + "\n")


def chiedi_passphrase(invito: str) -> bytes:
    """Read the passphrase from the terminal device, with echo off.

    Deliberately not stdin. stdin is whatever the parent handed us, and when the
    parent is an agent that is a pipe the agent is holding. /dev/tty is the
    controlling terminal, so if there is not one — a daemon, a subprocess of a
    subprocess, a hook — this raises instead of quietly reading from somewhere
    an agent chose.
    """
    try:
        tty = open("/dev/tty", "r+b", buffering=0)
    except OSError as e:
        raise Rifiuto(
            "no controlling terminal, so there is nowhere safe to type the "
            f"passphrase ({e.strerror}). Run this from a terminal you opened."
        ) from e
    with tty:
        fd = tty.fileno()
        prima = termios.tcgetattr(fd)
        dopo = termios.tcgetattr(fd)
        dopo[3] &= ~termios.ECHO  # lflag
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, dopo)
            tty.write(invito.encode())
            riga = tty.readline()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, prima)
            tty.write(b"\n")
    return riga.strip()


def percorso(nome: str) -> Path:
    """A path inside the compartment, with no way to point outside it."""
    if not aperto():
        raise Rifiuto("the compartment is locked. `paratia unlock` first.")
    pulito = Path(nome).name
    if not pulito or pulito.startswith("."):
        raise Rifiuto(f"{nome!r} is not a usable name in here")
    return MONTAGGIO / pulito


def leggi_json(nome: str, difetto):
    p = percorso(nome)
    if not p.exists():
        return difetto
    return json.loads(p.read_text())


# ------------------------------------------------------------------ commands


def cmd_init(args) -> int:
    if FORZIERE.exists():
        raise Rifiuto(f"{FORZIERE} already exists. Move it aside if you mean to start over.")
    if (spia := dentro_un_agente()):
        raise Rifiuto(
            f"this looks like an agent session ({spia}). The passphrase would be "
            "typed into a terminal an agent is holding. Open your own terminal."
        )
    CASA.mkdir(parents=True, exist_ok=True)

    print(
        "The passphrase is never written down by this program. It is not in the\n"
        "keychain, not in a file, not in the compartment. If you lose it the\n"
        "contents are gone, and that is the property that makes an agent unable\n"
        "to unlock this: there is nothing on the disk for it to find.\n"
    )
    uno = chiedi_passphrase("passphrase: ")
    due = chiedi_passphrase("again: ")
    if uno != due:
        raise Rifiuto("the two did not match, nothing was created")
    if len(uno) < 12:
        raise Rifiuto("under 12 characters, refused — this is the only lock there is")

    esito = _corri(
        [
            "hdiutil", "create",
            "-size", args.size,
            "-type", "SPARSEBUNDLE",
            "-fs", "APFS",
            "-encryption", "AES-256",
            "-stdinpass",
            "-volname", "paratia",
            str(FORZIERE),
        ],
        dentro=uno + b"\n",
    )
    if esito.returncode != 0:
        raise Rifiuto(f"hdiutil refused: {esito.stderr.decode(errors='replace').strip()}")

    annota("init", forziere=str(FORZIERE), size=args.size)
    print(f"\nMade {FORZIERE} ({args.size}, AES-256, locked).")
    print("Next: `paratia unlock`, then `paratia put <name>` for each secret.")
    return 0


def cmd_unlock(args) -> int:
    if aperto():
        print(f"already open at {MONTAGGIO}")
        return 0
    # Before the existence check on purpose: whether there is a compartment here
    # at all is not something an agent session needs told.
    if (spia := dentro_un_agente()) and not args.force:
        raise Rifiuto(
            f"refusing: {spia} is set, so this is an agent session. Opening here "
            "would put the plaintext where the agent can read it for as long as "
            "it stays open. Open a terminal of your own and unlock there."
        )
    if not FORZIERE.exists():
        raise Rifiuto(f"no compartment at {FORZIERE}. `paratia init` first.")

    parola = chiedi_passphrase("passphrase: ")
    esito = _corri(
        [
            "hdiutil", "attach", str(FORZIERE),
            "-stdinpass", "-nobrowse",
            "-mountpoint", str(MONTAGGIO),
        ],
        dentro=parola + b"\n",
    )
    if esito.returncode != 0:
        annota("unlock-fallito")
        raise Rifiuto(f"did not open: {esito.stderr.decode(errors='replace').strip()}")

    annota("unlock", scadenza=args.minutes)
    print(f"open at {MONTAGGIO}")
    print(
        f"While it is open, `paratia gate` denies every agent tool call in every\n"
        f"session running that hook. Close it with `paratia lock` when you are done."
    )
    if args.minutes:
        subprocess.Popen(
            ["/bin/sh", "-c", f"sleep {int(args.minutes) * 60}; exec {shlex.quote(sys.argv[0])} lock --quiet"],
            start_new_session=True,
        )
        print(f"auto-lock in {args.minutes} min")
    return 0


def cmd_lock(args) -> int:
    if not aperto():
        if not args.quiet:
            print("already locked")
        return 0
    esito = _corri(["hdiutil", "detach", str(MONTAGGIO)])
    if esito.returncode != 0:
        esito = _corri(["hdiutil", "detach", str(MONTAGGIO), "-force"])
    if esito.returncode != 0:
        raise Rifiuto(f"did not close: {esito.stderr.decode(errors='replace').strip()}")
    annota("lock")
    if not args.quiet:
        print("locked — the plaintext is off the disk again")
    return 0


def cmd_put(args) -> int:
    p = percorso(args.name)
    valore = chiedi_passphrase(f"value for {args.name} (not echoed): ")
    p.write_bytes(valore)
    p.chmod(0o600)
    annota("put", nome=args.name)
    print(f"stored {args.name}")
    return 0


def cmd_get(args) -> int:
    if dentro_un_agente() and not args.force:
        raise Rifiuto(
            "refusing to print a secret inside an agent session. This is what "
            "`paratia broker` is for: it uses the value without showing it."
        )
    p = percorso(args.name)
    if not p.exists():
        raise Rifiuto(f"nothing stored under {args.name!r}")
    annota("get", nome=args.name)
    sys.stdout.buffer.write(p.read_bytes())
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    return 0


def cmd_ls(args) -> int:
    for p in sorted(MONTAGGIO.iterdir() if aperto() else []):
        if p.name.startswith(".") or p.name in (VERBI, SIGILLI):
            continue
        print(p.name)
    if not aperto():
        raise Rifiuto("the compartment is locked")
    return 0


def cmd_broker(args) -> int:
    """Run one declared verb with its secrets filled in, and return its output.

    The agent picks a name from a list it cannot read and cannot extend. It does
    not pick the command, so there is no `sh -c 'echo $TOKEN'` to write: the
    template was fixed by you, while the compartment was open and no agent was
    watching.
    """
    verbi = leggi_json(VERBI, {})
    if args.name not in verbi:
        disponibili = ", ".join(sorted(verbi)) or "none declared yet"
        raise Rifiuto(f"no verb called {args.name!r}. Declared: {disponibili}")

    spec = verbi[args.name]
    modello = spec["comando"] if isinstance(spec, dict) else spec
    if not isinstance(modello, list):
        raise Rifiuto(f"verb {args.name!r} must be a list of arguments, not a shell string")

    sostituito = []
    for pezzo in modello:
        if isinstance(pezzo, str) and pezzo.startswith("<") and pezzo.endswith(">"):
            sostituito.append(percorso(pezzo[1:-1]).read_text().strip())
        elif pezzo == "{}":
            sostituito.extend(args.rest)
        else:
            sostituito.append(pezzo)

    annota("broker", verbo=args.name, extra=args.rest)
    esito = subprocess.run(sostituito, capture_output=True)
    sys.stdout.buffer.write(esito.stdout)
    sys.stderr.buffer.write(esito.stderr)
    return esito.returncode


def _impronta(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def cmd_seal(args) -> int:
    """Record what the policy files look like right now, inside the compartment.

    On a Mac with one account there is no file an agent running as you cannot
    rewrite, including the hook that stops it. What there is, is a place it
    cannot write to and cannot read: in here. So the hashes go in here, and
    `attest` compares. That buys detection, not prevention, and the difference
    is written out in docs/architettura.md rather than glossed over.
    """
    sigilli = {}
    for nome in args.files:
        p = Path(nome).expanduser().resolve()
        if not p.is_file():
            raise Rifiuto(f"{p} is not a file")
        sigilli[str(p)] = _impronta(p)
    percorso(SIGILLI).write_text(json.dumps(sigilli, indent=1, sort_keys=True))
    annota("seal", quanti=len(sigilli))
    for k in sigilli:
        print(f"sealed {k}")
    return 0


def cmd_attest(args) -> int:
    sigilli = leggi_json(SIGILLI, {})
    if not sigilli:
        raise Rifiuto("nothing sealed yet — `paratia seal <file>...`")
    guasti = 0
    for nome, atteso in sorted(sigilli.items()):
        p = Path(nome)
        if not p.exists():
            print(f"GONE     {nome}")
            guasti += 1
        elif _impronta(p) != atteso:
            print(f"CHANGED  {nome}")
            guasti += 1
        else:
            print(f"ok       {nome}")
    annota("attest", guasti=guasti)
    if guasti:
        print(f"\n{guasti} file(s) no longer match what you sealed.")
        print("Read them before you trust this session, then re-seal.")
    return 1 if guasti else 0


def cmd_status(args) -> int:
    stato = {
        "forziere": str(FORZIERE),
        "esiste": FORZIERE.exists(),
        "aperto": aperto(),
        "montaggio": str(MONTAGGIO),
        "sessione_agente": dentro_un_agente(),
        "diario": str(DIARIO) if DIARIO.exists() else None,
    }
    if args.json:
        print(json.dumps(stato, indent=1))
        return 0
    print(f"compartment  {FORZIERE}")
    print(f"state        {'OPEN — agent tools are denied right now' if stato['aperto'] else 'locked'}")
    if stato["sessione_agente"]:
        print(f"context      inside an agent session ({stato['sessione_agente']})")
    if aperto():
        verbi = leggi_json(VERBI, {})
        print(f"verbs        {', '.join(sorted(verbi)) or 'none'}")
    return 0


def cmd_doctor(args) -> int:
    ok = True
    def riga(buono: bool, testo: str):
        nonlocal ok
        ok = ok and buono
        print(f"{'ok  ' if buono else 'FAIL'} {testo}")

    riga(sys.version_info >= (3, 11), f"python {sys.version_info.major}.{sys.version_info.minor} (need 3.11+)")
    riga(bool(_corri(["which", "hdiutil"]).stdout.strip()), "hdiutil present")
    riga(FORZIERE.exists(), f"compartment exists at {FORZIERE}")
    try:
        open("/dev/tty").close()
        riga(True, "controlling terminal reachable (unlock can prompt)")
    except OSError:
        riga(False, "no controlling terminal — unlock will refuse from here")
    if (spia := dentro_un_agente()):
        print(f"note  running inside an agent session ({spia}); unlock is disabled here by design")
    return 0 if ok else 1


# --------------------------------------------------------------------- entry


def costruisci() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="paratia",
        description="An encrypted compartment agents running as you cannot read.",
    )
    s = p.add_subparsers(dest="cmd", required=True)

    i = s.add_parser("init", help="create the compartment")
    i.add_argument("--size", default="200m")
    i.set_defaults(fn=cmd_init)

    u = s.add_parser("unlock", help="open it (asks for the passphrase at the terminal)")
    u.add_argument("--minutes", type=int, default=15, help="auto-lock after this many minutes; 0 disables")
    u.add_argument("--force", action="store_true", help="open even inside an agent session")
    u.set_defaults(fn=cmd_unlock)

    l = s.add_parser("lock", help="close it")
    l.add_argument("--quiet", action="store_true")
    l.set_defaults(fn=cmd_lock)

    pu = s.add_parser("put", help="store a secret")
    pu.add_argument("name")
    pu.set_defaults(fn=cmd_put)

    g = s.add_parser("get", help="print a secret (refuses inside an agent session)")
    g.add_argument("name")
    g.add_argument("--force", action="store_true")
    g.set_defaults(fn=cmd_get)

    s.add_parser("ls", help="list what is stored").set_defaults(fn=cmd_ls)

    b = s.add_parser("broker", help="run a declared verb without revealing its secrets")
    b.add_argument("name")
    b.add_argument("rest", nargs="*")
    b.set_defaults(fn=cmd_broker)

    se = s.add_parser("seal", help="record hashes of the policy files inside the compartment")
    se.add_argument("files", nargs="+")
    se.set_defaults(fn=cmd_seal)

    s.add_parser("attest", help="check the sealed files still match").set_defaults(fn=cmd_attest)

    st = s.add_parser("status", help="what state everything is in")
    st.add_argument("--json", action="store_true")
    st.set_defaults(fn=cmd_status)

    s.add_parser("doctor", help="check this machine can run it").set_defaults(fn=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    args = costruisci().parse_args(argv)
    try:
        return args.fn(args)
    except Rifiuto as e:
        print(f"paratia: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
