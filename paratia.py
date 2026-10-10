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
import datetime
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
    riga = {"quando": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "evento": evento, **campi}
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
            "-stdinpass", "-nobrowse", "-owners", "on",
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
    cartelle = []
    cartelle_incerte = False
    if (CASA / "cartelle.json").exists() or (CASA / "cartelle.json").is_symlink():
        import importlib.util
        spec = importlib.util.spec_from_file_location("cartelle_status", Path(__file__).resolve().with_name("cartelle.py"))
        C = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = C
        spec.loader.exec_module(C)
        try:
            for entry in C.elenco():
                mounts = [entry.get("montaggio"), entry.get("montaggio_temporaneo")]
                mounted = [path for path in mounts if path and C._montato(Path(path))]
                incomplete = entry.get("stato") in ("migrazione", "migrazione-incompleta") or bool(entry.get("plaintext_residuo"))
                if mounted or incomplete:
                    cartelle.append({"id": entry["id"], "nome": entry["nome"], "stato": entry["stato"],
                                     "montaggi_aperti": mounted, "da_recuperare": incomplete})
        except (C.Rifiuto, OSError, ValueError, KeyError, TypeError):
            cartelle_incerte = True
    forziere_aperto = aperto()
    stato = {
        "forziere": str(FORZIERE),
        "esiste": FORZIERE.exists(),
        "aperto": forziere_aperto or bool(cartelle),
        "forziere_aperto": forziere_aperto,
        "cartelle_aperte": cartelle,
        "cartelle_non_verificate": cartelle_incerte,
        "montaggio": str(MONTAGGIO),
        "sessione_agente": dentro_un_agente(),
        "diario": str(DIARIO) if DIARIO.exists() else None,
    }
    if args.json:
        print(json.dumps(stato, indent=1))
        return 2 if cartelle_incerte else 0
    print(f"compartment  {FORZIERE}")
    print(f"state        {'UNKNOWN — protected folder registry must be checked' if cartelle_incerte else 'OPEN — agent tools are denied right now' if stato['aperto'] else 'locked'}")
    for entry in cartelle:
        print(f"folder       {entry['nome']} ({entry['id']}): " + ("recovery required" if entry["da_recuperare"] else "open") + " · " + ", ".join(entry["montaggi_aperti"]))
    if cartelle:
        print("close        paratia cartella chiudi-tutte")
    if stato["sessione_agente"]:
        print(f"context      inside an agent session ({stato['sessione_agente']})")
    if forziere_aperto:
        verbi = leggi_json(VERBI, {})
        print(f"verbs        {', '.join(sorted(verbi)) or 'none'}")
    return 2 if cartelle_incerte else 0


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


# ------------------------------------------------------------------- zones
#
# A zone is not a compartment, and conflating the two would be the most
# expensive mistake in this program.
#
# The compartment holds secrets an agent must never read, so the invariant is
# that it is closed while an agent runs, and the gate enforces exactly that. A
# zone holds *work* — a repository, a dataset, a client's files — which the
# agent has to read in order to be useful. There is no arrangement in which the
# agent works on a thing and cannot see it.
#
# So a zone defends against everybody who is not the running session: another
# local account on a volume that ignores ownership, whoever ends up holding the
# SSD, and the copy of your folder that lives on somebody else's server. That is
# a real threat model and it is not the agent's.
#
# Zones therefore mount under their own names, and the gate does not look at
# them. Opening a zone does not stop the session.


def _zone_casa() -> Path:
    return CASA / "zone"


def _zone_registro() -> dict:
    p = _zone_casa() / "registro.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def _zone_scrivi(reg: dict) -> None:
    _zone_casa().mkdir(parents=True, exist_ok=True)
    (_zone_casa() / "registro.json").write_text(json.dumps(reg, indent=1, sort_keys=True))


def _monte_zona(nome: str) -> Path:
    return Path(f"/Volumes/zona-{nome}")


def _volume_di(p: Path) -> str:
    """Which mounted filesystem a path lives on."""
    p = p.resolve()
    while not p.is_mount() and p != p.parent:
        p = p.parent
    return str(p)


def _sincronizzato(p: Path) -> bool:
    """True when the path sits inside a cloud provider's synced tree.

    Putting a sparsebundle inside one is a documented way to lose the whole
    thing: the provider syncs individual band files, a band written while the
    image is mounted arrives out of order or half-copied, and the result is an
    image that will not attach. `zona nuova` refuses these by default.
    """
    s = str(p.resolve())
    return any(
        marchio in s
        for marchio in ("/Library/CloudStorage/", "/Dropbox", "/OneDrive", "/Google Drive", "/iCloud Drive~")
    )


def cmd_zona_nuova(args) -> int:
    if (spia := dentro_un_agente()) and not args.force:
        raise Rifiuto(f"a zone's passphrase gets typed here, and {spia} is set. Your own terminal.")
    dove = Path(args.dove).expanduser().resolve()
    if not dove.is_dir():
        raise Rifiuto(f"{dove} is not a directory")
    if _sincronizzato(dove) and not args.lo_so:
        raise Rifiuto(
            f"{dove} is inside a cloud-synced tree. A sparsebundle there is a known "
            "way to lose everything in it: the provider syncs band files one at a "
            "time, a band written while the image is mounted can arrive torn, and "
            "the image then refuses to attach. If you have a second copy elsewhere "
            "and accept that, pass --lo-so."
        )

    reg = _zone_registro()
    if args.nome in reg:
        raise Rifiuto(f"a zone called {args.nome!r} is already registered")

    bundle = dove / f"{args.nome}.sparsebundle"
    if bundle.exists():
        raise Rifiuto(f"{bundle} already exists")

    print(
        "A zone is encrypted at rest and readable while open. It defends against\n"
        "another account, a stolen disk and a cloud provider. It does NOT hide the\n"
        "work from an agent you are running: an agent that cannot read the repo\n"
        "cannot work on it.\n"
    )
    uno = chiedi_passphrase(f"passphrase for zone {args.nome}: ")
    due = chiedi_passphrase("again: ")
    if uno != due:
        raise Rifiuto("the two did not match, nothing was created")
    if len(uno) < 12:
        raise Rifiuto("under 12 characters, refused")

    esito = _corri(
        [
            "hdiutil", "create",
            "-size", args.size,
            "-type", "SPARSEBUNDLE",
            "-fs", "APFS",
            "-encryption", "AES-256",
            "-stdinpass",
            "-volname", f"zona-{args.nome}",
            str(bundle),
        ],
        dentro=uno + b"\n",
    )
    if esito.returncode != 0:
        raise Rifiuto(f"hdiutil refused: {esito.stderr.decode(errors='replace').strip()}")

    reg[args.nome] = {"bundle": str(bundle), "volume": _volume_di(dove), "creata": time.strftime("%Y-%m-%d")}
    _zone_scrivi(reg)
    annota("zona-nuova", nome=args.nome, dove=str(bundle))
    print(f"\nMade {bundle} ({args.size}, AES-256).")
    print(f"Open it with `paratia zona apri {args.nome}`, then move the work inside.")
    return 0


def cmd_zona_apri(args) -> int:
    reg = _zone_registro()
    if args.nome not in reg:
        raise Rifiuto(f"no zone called {args.nome!r}. Known: {', '.join(sorted(reg)) or 'none'}")
    monte = _monte_zona(args.nome)
    if monte.is_mount():
        print(f"already open at {monte}")
        return 0
    if dentro_un_agente() and not args.force:
        raise Rifiuto(
            f"a zone's passphrase gets typed here. Open it from your own terminal, "
            f"then the session can work inside {monte} normally."
        )
    parola = chiedi_passphrase(f"passphrase for {args.nome}: ")
    esito = _corri(
        # -owners on is not decoration. A freshly created encrypted sparsebundle
        # attaches with ownership IGNORED by default, which means every uid on
        # the machine is treated as the owner of everything inside and the mode
        # bits pass unconditionally. Worse, it is a per-attach flag rather than a
        # property of the image, so whoever runs `hdiutil attach` picks whether
        # the boundary exists at all — and the default is the one without it.
        ["hdiutil", "attach", reg[args.nome]["bundle"], "-stdinpass", "-nobrowse",
         "-owners", "on", "-mountpoint", str(monte)],
        dentro=parola + b"\n",
    )
    if esito.returncode != 0:
        annota("zona-apri-fallito", nome=args.nome)
        raise Rifiuto(f"did not open: {esito.stderr.decode(errors='replace').strip()}")
    annota("zona-apri", nome=args.nome)
    print(f"open at {monte} — agents may work in here, the gate does not block zones")
    return 0


def cmd_zona_chiudi(args) -> int:
    monte = _monte_zona(args.nome)
    if not monte.is_mount():
        print("already closed")
        return 0
    esito = _corri(["hdiutil", "detach", str(monte)])
    if esito.returncode != 0:
        esito = _corri(["hdiutil", "detach", str(monte), "-force"])
    if esito.returncode != 0:
        raise Rifiuto(f"did not close: {esito.stderr.decode(errors='replace').strip()}")
    annota("zona-chiudi", nome=args.nome)
    print("closed")
    return 0


def cmd_zona_elenco(args) -> int:
    reg = _zone_registro()
    if not reg:
        print("no zones")
        return 0
    for nome, z in sorted(reg.items()):
        stato = "open" if _monte_zona(nome).is_mount() else "closed"
        c_e = "" if Path(z["bundle"]).exists() else "  MISSING"
        print(f"{nome:<16} {stato:<7} {z['bundle']}{c_e}")
    return 0


# -------------------------------------------------------------- mirrors


def _specchio_chiave() -> bytes:
    """The HMAC key that makes pseudonyms stable. Lives in the compartment, so
    tokens cannot be recomputed by anything that cannot open it."""
    p = percorso("specchio-chiave")
    if not p.exists():
        p.write_bytes(os.urandom(32))
        p.chmod(0o600)
    return p.read_bytes()


def _specchio_stato(nome: str) -> tuple[Path, dict]:
    p = percorso(f"specchio-{nome}.json")
    if not p.exists():
        raise Rifiuto(f"no mirror called {nome!r}")
    return p, json.loads(p.read_text())


def cmd_specchio_nuovo(args) -> int:
    da = Path(args.da).expanduser().resolve()
    a = Path(args.a).expanduser().resolve()
    if not da.is_dir():
        raise Rifiuto(f"{da} is not a directory")
    p = percorso(f"specchio-{args.nome}.json")
    if p.exists():
        raise Rifiuto(f"a mirror called {args.nome!r} already exists")
    p.write_text(json.dumps({"da": str(da), "a": str(a), "motore": args.motore, "tabella": {}}, indent=1))
    p.chmod(0o600)
    annota("specchio-nuovo", nome=args.nome)
    print(f"registered {args.nome}: {da}  ->  {a}")
    if not args.motore:
        print(
            "\nNo detector engine set. The built-in rules find structured identifiers\n"
            "— email, IBAN, codice fiscale, cards, phones, IPs, API keys — and they do\n"
            "not find names or addresses in prose. If this tree has those, set one:\n"
            "  paratia specchio motore " + args.nome + " 'rizzo-pii --json'"
        )
    return 0


def cmd_specchio_motore(args) -> int:
    p, stato = _specchio_stato(args.nome)
    stato["motore"] = args.comando or None
    p.write_text(json.dumps(stato, indent=1))
    print(f"engine for {args.nome}: {stato['motore'] or 'none (built-in rules only)'}")
    return 0


def cmd_specchio_sincronizza(args) -> int:
    if dentro_un_agente() and not args.force:
        raise Rifiuto(
            "refusing inside an agent session: building the mirror means reading "
            "the originals, and the originals are what the mirror exists to keep "
            "out of a transcript. Run it from your own terminal."
        )
    # Imported by path rather than by name: the command is normally reached
    # through a symlink in ~/.local/bin, and the sibling module has to be found
    # next to the real file rather than next to the link.
    import importlib.util

    _spec = importlib.util.spec_from_file_location("specchio", Path(__file__).resolve().parent / "specchio.py")
    _s = importlib.util.module_from_spec(_spec)
    sys.modules["specchio"] = _s
    _spec.loader.exec_module(_s)

    p, stato = _specchio_stato(args.nome)
    chiave = _specchio_chiave()
    tabella = stato.get("tabella", {})
    esito = _s.rispecchia(
        Path(stato["da"]), Path(stato["a"]), chiave, tabella,
        motore=stato.get("motore"), copia_binari=args.copia_binari,
    )
    stato["tabella"] = tabella
    p.write_text(json.dumps(stato, indent=1))
    annota("specchio-sincronizza", nome=args.nome, file=esito.file_copiati, token=len(tabella))

    print(f"{esito.file_copiati} file written, {esito.file_letti} scanned")
    if esito.conteggio:
        print("replaced: " + ", ".join(f"{t}×{n}" for t, n in sorted(esito.conteggio.items())))
    else:
        print("replaced: nothing — check that the detector fits this material")
    print(f"{len(tabella)} distinct values in the table ({esito.nuovi_token} new), stored in the compartment")

    if esito.binari:
        print(f"\n{len(esito.binari)} file(s) NOT copied because they are not text, so nothing")
        print("in them was scanned. Listing the first few:")
        for b in esito.binari[:8]:
            print(f"  {b}")
        if len(esito.binari) > 8:
            print(f"  ... and {len(esito.binari) - 8} more")

    if not stato.get("motore"):
        print(
            "\nBuilt-in rules only. Names, addresses and anything needing to be\n"
            "understood rather than matched are still in the mirror."
        )
    print(
        "\nThis is pseudonymised, not anonymous. Under GDPR it is still personal\n"
        "data (Recital 26) — the reversal table exists on purpose. It keeps\n"
        "identifiers out of a context window; it is not a certificate."
    )
    return 0


def cmd_specchio_risolvi(args) -> int:
    if dentro_un_agente() and not args.force:
        raise Rifiuto(
            "refusing inside an agent session. Resolving a token is exactly the "
            "step the mirror exists to prevent, and the answer would land in the "
            "transcript."
        )
    _, stato = _specchio_stato(args.nome)
    voce = stato.get("tabella", {}).get(args.token)
    if not voce:
        raise Rifiuto(f"{args.token} is not in this mirror's table")
    annota("specchio-risolvi", nome=args.nome)
    print(f"{voce['tipo']}: {voce['valore']}")
    return 0


def cmd_specchio_elenco(args) -> int:
    if not aperto():
        raise Rifiuto("the compartment is locked")
    trovati = sorted(MONTAGGIO.glob("specchio-*.json"))
    if not trovati:
        print("no mirrors")
        return 0
    for p in trovati:
        s = json.loads(p.read_text())
        nome = p.stem.replace("specchio-", "")
        print(f"{nome:<14} {s['da']} -> {s['a']}")
        print(f"{'':<14} {len(s.get('tabella', {}))} values, engine: {s.get('motore') or 'built-in only'}")
    return 0


# -------------------------------------------------------------- exposure


def _utenti_locali() -> list[str]:
    fuori = _corri(["dscl", ".", "-list", "/Users", "UniqueID"]).stdout.decode(errors="replace")
    utenti = []
    for riga in fuori.splitlines():
        pezzi = riga.split()
        if len(pezzi) == 2 and pezzi[1].isdigit() and int(pezzi[1]) >= 500:
            utenti.append(pezzi[0])
    return utenti


def _monti_senza_proprietari() -> list[str]:
    fuori = _corri(["mount"]).stdout.decode(errors="replace")
    senza = []
    for riga in fuori.splitlines():
        if " on " not in riga or "noowners" not in riga:
            continue
        punto = riga.split(" on ", 1)[1].split(" (", 1)[0]
        senza.append(punto)
    return senza


def cmd_esposizione(args) -> int:
    """What on this machine a second account would and would not protect.

    Written because the answer is machine-specific and the two ways it goes
    wrong are both silent. A home directory readable by group `staff` is
    readable by every local account, since macOS puts every user in staff. And a
    volume mounted `noowners` discards the mode bits entirely, so on that disk a
    second account buys nothing at all — which is the case people discover after
    they have already moved their work there.
    """
    righe: list[tuple[str, str, str]] = []

    casa = Path.home()
    modo = casa.stat().st_mode & 0o777
    utenti = _utenti_locali()
    altri = [u for u in utenti if u != casa.name]
    if modo & 0o007:
        righe.append(("home", "EXPOSED", f"{oct(modo)} — world-readable, every local account reads it"))
    elif modo & 0o070:
        righe.append((
            "home", "EXPOSED" if altri else "WOULD BE",
            f"{oct(modo)} — group-readable, and macOS puts every local account in staff. "
            f"{'Readable now by: ' + ', '.join(altri) if altri else 'No second account yet, but one would read it on day one.'} "
            f"Fix: chmod 750 -> 700 on {casa}",
        ))
    else:
        righe.append(("home", "ok", f"{oct(modo)} — owner only"))

    righe.append(("accounts", "ok" if len(utenti) == 1 else "note",
                  f"{len(utenti)} local account(s): {', '.join(utenti)}"))

    senza = _monti_senza_proprietari()
    for punto in senza:
        righe.append((
            f"volume {punto}", "EXPOSED",
            "mounted noowners — the mode bits are discarded on this volume, so a "
            "second account has full access to everything here regardless of "
            "ownership. Only encryption helps.",
        ))
    if not senza:
        righe.append(("volumes", "ok", "every mounted volume enforces ownership"))

    for radice in args.workspace:
        p = Path(radice).expanduser()
        if not p.exists():
            continue
        vol = _volume_di(p)
        pericolo = vol in senza or any(vol.startswith(s) for s in senza)
        righe.append((
            f"workspace {p}", "EXPOSED" if pericolo else "ok",
            f"on {vol}" + (" — which ignores ownership, so UID separation does nothing here" if pericolo else ""),
        ))

    righe.append(("compartment", "ok" if FORZIERE.exists() else "MISSING",
                  ("locked" if not aperto() else "OPEN — agent tool calls are being denied right now")
                  if FORZIERE.exists() else "no compartment yet, `paratia init`"))

    impostazioni = Path.home() / ".claude" / "settings.json"
    installato = False
    if impostazioni.is_file():
        try:
            installato = "paratia-gate" in impostazioni.read_text()
        except OSError:
            pass
    righe.append(("gate", "ok" if installato else "NOT INSTALLED",
                  "PreToolUse hook found in settings.json" if installato
                  else "the hook is not in ~/.claude/settings.json, so nothing is enforced in sessions"))

    if aperto():
        sigilli = leggi_json(SIGILLI, {})
        rotti = [n for n, h in sigilli.items() if not Path(n).exists() or _impronta(Path(n)) != h]
        righe.append(("seals", "ok" if not rotti else "CHANGED",
                      f"{len(sigilli)} sealed, {len(rotti)} no longer match" if sigilli else "nothing sealed"))
    else:
        righe.append(("seals", "unknown", "compartment closed — `paratia unlock` then `paratia attest`"))

    if args.json:
        print(json.dumps([{"voce": a, "stato": b, "nota": c} for a, b, c in righe], indent=1))
    else:
        largo = max(len(a) for a, _, _ in righe)
        for voce, stato, nota in righe:
            print(f"{stato:<14} {voce:<{largo}}  {nota}")
        brutti = [a for a, b, _ in righe if b in ("EXPOSED", "NOT INSTALLED", "MISSING", "CHANGED")]
        if brutti:
            print(f"\n{len(brutti)} item(s) need attention: {', '.join(brutti)}")
    return 1 if any(b in ("EXPOSED", "CHANGED") for _, b, _ in righe) else 0


# --------------------------------------------------------------------- entry


# ------------------------------------------------------------------ labels
#
# A label is a judgement about content, written down. It is not a boundary and
# this file does not pretend otherwise: `etichette.py` opens with the paragraph
# saying so, and every command below repeats the part that matters — the bytes
# are protected by `applica` moving them somewhere encrypted, never by the label
# naming them. See docs/architettura.md, which now has a row 9 for exactly this.


def _etichette():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "etichette", Path(__file__).resolve().parent / "etichette.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["etichette"] = mod
    spec.loader.exec_module(mod)
    return mod


def cmd_etichetta_segna(args) -> int:
    E = _etichette()
    try:
        r = E.segna(args.percorso, args.come, args.nota or "")
    except E.Rifiuto as e:
        raise Rifiuto(str(e)) from e
    annota("etichetta-segna", percorso=r["percorso"], etichetta=r["etichetta"])
    print(f"{r['etichetta']}  {r['percorso']}")
    print("nothing has moved. `paratia etichetta piano` to see what would.")
    return 0


def cmd_etichetta_togli(args) -> int:
    E = _etichette()
    if E.togli(args.percorso):
        annota("etichetta-togli", percorso=args.percorso)
        print(f"removed the label on {args.percorso}")
        return 0
    print(f"no label on {args.percorso}", file=sys.stderr)
    return 1


def cmd_etichetta_elenco(args) -> int:
    E = _etichette()
    righe = E.elenco()
    if args.json:
        print(json.dumps(righe, ensure_ascii=False, indent=1))
        return 0
    if not righe:
        print("nothing labelled yet.")
        return 0
    largo = max(len(r["etichetta"]) for r in righe)
    for r in righe:
        manca = "" if r["esiste"] else "  (gone)"
        nota = f"  — {r['nota']}" if r.get("nota") else ""
        print(f"{r['etichetta']:<{largo}}  {r['percorso']}{manca}{nota}")
    return 0


def cmd_etichetta_piano(args) -> int:
    E = _etichette()
    p = E.piano(sincronizzato=_sincronizzato)
    if args.json:
        print(json.dumps(p, ensure_ascii=False, indent=1))
        return 0

    if not p["mosse"] and not p["problemi"]:
        print("nothing labelled yet, so there is nothing to move.")
        return 0

    for m in p["mosse"]:
        piu = "+" if m["troncato"] else ""
        print(f"{m['etichetta']:<12} {m['percorso']}")
        print(f"{'':<12}   → {m['destinazione']}, {_umano(m['byte'])} in {m['file']}{piu} files")
        if m.get("avviso"):
            print(f"{'':<12}   ! {m['avviso']}")
    for q in p["problemi"]:
        print(f"{'(problem)':<12} {q['percorso']}: {q['perche']}")
    print(f"\n{_umano(p['byte_totali'])} in total. `paratia etichetta applica` to stage it.")
    return 0


def _umano(b: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or u == "TB":
            return f"{b:.0f}{u}" if u == "B" else f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}TB"


def cmd_etichetta_applica(args) -> int:
    """Copy labelled trees into the place that actually protects them.

    Two deliberate refusals. It does not delete the source — `rsync` and
    `stiva` do verified moves better than a reimplementation here would, and a
    program that both copies and deletes on the same run is one bug away from
    doing only the second. And it will not run while the compartment is closed
    for `riservato` items, because staging them anywhere else first would put
    the plaintext exactly where the label said it should not be.
    """
    E = _etichette()
    p = E.piano(sincronizzato=_sincronizzato)
    if not p["mosse"]:
        print("nothing to apply.")
        return 0

    riservati = [m for m in p["mosse"] if m["etichetta"] == E.RISERVATO]
    if riservati and not aperto():
        raise Rifiuto(
            "there are `riservato` items and the compartment is locked. "
            "`paratia unlock` in your own terminal first — staging them anywhere "
            "else on the way in would defeat the point."
        )

    reg = _zone_registro()
    lavoro = []
    for m in p["mosse"]:
        origine = Path(m["percorso"])
        if m["etichetta"] == E.RISERVATO:
            destinazione = MONTAGGIO / origine.name
        else:
            nome = m["etichetta"][len(E.PREFISSO_ZONA):]
            if nome not in reg.get("zone", reg):
                print(f"skipped {origine}: zone {nome!r} does not exist "
                      f"(`paratia zona nuova {nome} --dove ... --size ...`)", file=sys.stderr)
                continue
            monte = _monte_zona(nome)
            if not monte.is_mount():
                print(f"skipped {origine}: zone {nome!r} is closed "
                      f"(`paratia zona apri {nome}`)", file=sys.stderr)
                continue
            destinazione = monte / origine.name
        lavoro.append((origine, destinazione, m))

    if not lavoro:
        print("nothing could be applied. Open the zones it needs, then run it again.")
        return 1

    for origine, destinazione, m in lavoro:
        print(f"{'copy' if args.esegui else 'would copy'}  {origine}")
        print(f"{'':>4}    → {destinazione}  ({_umano(m['byte'])})")
        for e in m.get("esclusi", ()):
            print(f"{'':>4}    minus {e}  (labelled separately)")

    if not args.esegui:
        print("\nnothing ran. Add --esegui to do it.")
        print("the source is never deleted here: check the copy, then remove it yourself.")
        return 0

    fallite = 0
    for origine, destinazione, m in lavoro:
        if destinazione.is_symlink():
            print(f"symlink, skipped: {destinazione} (the copy must stay on the encrypted volume)",
                  file=sys.stderr)
            fallite += 1
            continue
        if destinazione.exists() and not args.sovrascrivi:
            print(f"exists, skipped: {destinazione}  (--sovrascrivi to replace)", file=sys.stderr)
            fallite += 1
            continue
        # The carve-outs from the plan, as paths relative to the source root and
        # anchored with a leading slash, which is how rsync reads "this exact
        # one" rather than "anything with this name anywhere in the tree".
        esclusioni = []
        for e in m.get("esclusi", ()):
            try:
                relativo = str(Path(e).relative_to(origine))
            except ValueError:
                continue
            # Labels name literal paths; rsync exclusions are glob patterns.
            # Backslashes only need escaping when rsync sees a wildcard.
            if any(c in relativo for c in "*?["):
                relativo = relativo.replace("\\", "\\\\")
                for c in "*?[":
                    relativo = relativo.replace(c, "\\" + c)
            esclusioni += ["--exclude", "/" + relativo]
        esito = _corri(["rsync", "-a", "--checksum", "--partial", *esclusioni,
                        str(origine) + ("/" if origine.is_dir() else ""),
                        str(destinazione)])
        if esito.returncode != 0:
            print(f"rsync failed on {origine}: "
                  f"{esito.stderr.decode(errors='replace').strip()}", file=sys.stderr)
            fallite += 1
            continue
        annota("etichetta-applica", origine=str(origine), destinazione=str(destinazione))
        print(f"copied  {origine} → {destinazione}")

    print("\nthe originals are still where they were. Verify the copies, then delete them "
          "yourself — this command will not.")
    return 1 if fallite else 0


def cmd_finder(args) -> int:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "finder", Path(__file__).resolve().parent / "finder.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["finder"] = mod
    spec.loader.exec_module(mod)
    return mod.servi(args.porta, args.apri, args.forza)


def cmd_registro(args) -> int:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "registro_cli", Path(__file__).resolve().parent / "registro.py")
    registro = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = registro
    spec.loader.exec_module(registro)
    try:
        return _esegui_registro(registro, args)
    except (OSError, ValueError) as e:
        raise Rifiuto("Registro: " + str(e)) from None


def _esegui_registro(registro, args):
    if args.operazione == "stato":
        risultato = registro.stato()
    elif args.operazione == "verifica":
        risultato = registro.verifica()
    elif args.operazione == "sorveglianza":
        risultato = registro.elenco_sorveglianza()
    elif args.operazione == "sorveglia":
        import uuid
        risultato = registro.sorveglia(args.id or uuid.uuid4().hex, args.cartella, args.nome or "")
    elif args.operazione == "smetti":
        identificatore = _registro_id(registro, args.cartella, solo_sorveglianza=True)
        risultato = registro.rimuovi_sorveglianza(identificatore)
    else:
        salute = registro.stato()
        if not (salute["running"] and salute["healthy"]):
            print("Registro: raccolta kernel non attiva. I risultati provengono soltanto dagli eventi già registrati; un elenco vuoto non prova l'assenza di accessi.", file=sys.stderr)
        filtri = {k: v for k, v in {
            "folder": _registro_id(registro, args.cartella), "file": args.file, "process": args.processo,
            "agent": args.agente, "since": args.da, "until": args.a,
        }.items() if v is not None}
        if args.operazione == "esporta":
            print(registro.export_csv(filtri), end="")
            return 0
        risultato = registro.query(filtri)
    print(json.dumps(risultato, ensure_ascii=False, indent=1))
    return 0


def _registro_id(registro, cartella, solo_sorveglianza=False):
    """Use the same exact configured-path lookup as worker query and CSV."""
    try:
        return registro.risolvi_cartella(cartella, solo_sorveglianza=solo_sorveglianza)
    except ValueError as error:
        raise Rifiuto(str(error)) from None


def cmd_cartella(args) -> int:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cartelle", Path(__file__).resolve().parent / "cartelle.py")
    C = importlib.util.module_from_spec(spec)
    sys.modules["cartelle"] = C
    spec.loader.exec_module(C)
    try:
        if args.operazione == "elenco":
            risultato = C.elenco()
        elif args.operazione == "chiudi-tutte":
            risultato = C.chiudi_tutte()
        elif args.operazione == "chiudi":
            risultato = C.chiudi(args.id)
        else:
            if args.operazione == "proteggi":
                C.prepara_protezione(args.origine, args.dove, args.minutes)
            else:
                preparazione = C.prepara_apertura(args.id, args.minutes)
                if preparazione["gia_aperta"]:
                    print(json.dumps({**preparazione["cartella"], "gia_aperta": True,
                                      "messaggio": preparazione["messaggio"],
                                      "timer_invariato": preparazione["timer_invariato"],
                                      "minutes_richiesti": preparazione["minutes_richiesti"],
                                      "minutes_effettivi": preparazione["minutes_effettivi"]},
                                     ensure_ascii=False, indent=1))
                    return 0
            if dentro_un_agente():
                raise Rifiuto("Apri Paratia dal Finder: la chiave va inserita "
                              "nel campo sicuro dell'app, fuori dalla sessione agente.")
            chiave = chiedi_passphrase("Chiave del compartimento: ")
            if args.operazione == "proteggi":
                conferma = chiedi_passphrase("Ripeti la chiave: ")
                if chiave != conferma:
                    raise Rifiuto("Le chiavi non coincidono. Ripeti l'operazione.")
                risultato = C.proteggi(args.origine, args.dove, chiave, args.minutes)
            else:
                risultato = C.apri(args.id, chiave, args.minutes)
        print(json.dumps(risultato, ensure_ascii=False, indent=1))
        return 1 if isinstance(risultato, list) and any(
            isinstance(r, dict) and r.get("errore") for r in risultato) else 0
    except C.ChiaveErrata as exc:
        print(json.dumps({"errore": "chiave_errata", "messaggio": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    except C.VolumeOccupato as exc:
        print(json.dumps({"errore": "volume_occupato", "messaggio": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    except C.DiscoNonDisponibile as exc:
        print(json.dumps({"errore": "disco_non_disponibile", "messaggio": str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        return 2
    except C.Rifiuto as exc:
        raise Rifiuto(str(exc)) from exc


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

    e = s.add_parser("esposizione", help="what a second account would and would not protect here")
    e.add_argument("--json", action="store_true")
    e.add_argument(
        "--workspace", nargs="*",
        default=["~/dev", "/Volumes/AppsAndFiles/dev", "~/Library/CloudStorage"],
        help="workspace roots to locate on their volumes",
    )
    e.set_defaults(fn=cmd_esposizione)

    z = s.add_parser("zona", help="encrypted workspace regions — readable while open, unlike the compartment")
    zs = z.add_subparsers(dest="sub", required=True)

    zn = zs.add_parser("nuova", help="create a zone")
    zn.add_argument("nome")
    zn.add_argument("--dove", required=True, help="directory to hold the image")
    zn.add_argument("--size", default="20g")
    zn.add_argument("--lo-so", dest="lo_so", action="store_true", help="allow creating inside a cloud-synced tree")
    zn.add_argument("--force", action="store_true")
    zn.set_defaults(fn=cmd_zona_nuova)

    za = zs.add_parser("apri", help="open a zone")
    za.add_argument("nome")
    za.add_argument("--force", action="store_true")
    za.set_defaults(fn=cmd_zona_apri)

    zc = zs.add_parser("chiudi", help="close a zone")
    zc.add_argument("nome")
    zc.set_defaults(fn=cmd_zona_chiudi)

    zs.add_parser("elenco", help="list zones").set_defaults(fn=cmd_zona_elenco)

    sp = s.add_parser("specchio", help="a readable copy of a tree with the identifiers taken out")
    sps = sp.add_subparsers(dest="sub", required=True)

    spn = sps.add_parser("nuovo", help="register a mirror")
    spn.add_argument("nome")
    spn.add_argument("--da", required=True)
    spn.add_argument("--a", required=True)
    spn.add_argument("--motore", default=None, help="detector command, e.g. 'rizzo-pii --json'")
    spn.set_defaults(fn=cmd_specchio_nuovo)

    spm = sps.add_parser("motore", help="set or clear the detector engine")
    spm.add_argument("nome")
    spm.add_argument("comando", nargs="?", default=None)
    spm.set_defaults(fn=cmd_specchio_motore)

    sps_ = sps.add_parser("sincronizza", help="build or refresh the mirror")
    sps_.add_argument("nome")
    sps_.add_argument("--copia-binari", dest="copia_binari", action="store_true",
                      help="also copy files that could not be scanned")
    sps_.add_argument("--force", action="store_true")
    sps_.set_defaults(fn=cmd_specchio_sincronizza)

    spr = sps.add_parser("risolvi", help="turn a token back into its value")
    spr.add_argument("nome")
    spr.add_argument("token")
    spr.add_argument("--force", action="store_true")
    spr.set_defaults(fn=cmd_specchio_risolvi)

    sps.add_parser("elenco", help="list mirrors").set_defaults(fn=cmd_specchio_elenco)

    et = s.add_parser(
        "etichetta",
        help="record which paths belong behind a bulkhead — a plan, not a boundary",
    )
    ets = et.add_subparsers(dest="sotto", required=True)

    ete = ets.add_parser("segna", help="label a file or folder")
    ete.add_argument("percorso")
    ete.add_argument("--come", required=True,
                     help="riservato | pubblico | zona:<name>")
    ete.add_argument("--nota", help="why, for the version of you that reads this in a year")
    ete.set_defaults(fn=cmd_etichetta_segna)

    ett = ets.add_parser("togli", help="remove a label")
    ett.add_argument("percorso")
    ett.set_defaults(fn=cmd_etichetta_togli)

    etl = ets.add_parser("elenco", help="every label, and whether its path still exists")
    etl.add_argument("--json", action="store_true")
    etl.set_defaults(fn=cmd_etichetta_elenco)

    etp = ets.add_parser("piano", help="what applying the labels would move, and where")
    etp.add_argument("--json", action="store_true")
    etp.set_defaults(fn=cmd_etichetta_piano)

    eta = ets.add_parser("applica", help="copy labelled trees into the compartment or their zone")
    eta.add_argument("--esegui", action="store_true", help="actually copy; without it, prints only")
    eta.add_argument("--sovrascrivi", action="store_true", help="replace a destination that exists")
    eta.set_defaults(fn=cmd_etichetta_applica)

    fi = s.add_parser("finder", help="browse and label from a browser, on any OS")
    fi.add_argument("--porta", type=int, default=8787)
    fi.add_argument("--non-aprire", dest="apri", action="store_false")
    fi.add_argument("--forza", action="store_true", help="start even inside an agent session")
    fi.set_defaults(fn=cmd_finder)

    ca = s.add_parser("cartella", help="compartimenti per cartelle esistenti")
    cas = ca.add_subparsers(dest="operazione", required=True)
    for nome in ("elenco", "chiudi-tutte"):
        cas.add_parser(nome).set_defaults(fn=cmd_cartella)
    cc = cas.add_parser("chiudi")
    cc.add_argument("id")
    cc.set_defaults(fn=cmd_cartella)
    cap = cas.add_parser("apri")
    cap.add_argument("id")
    cap.add_argument("--minutes", type=int, default=15)
    cap.set_defaults(fn=cmd_cartella)
    cp = cas.add_parser("proteggi")
    cp.add_argument("origine")
    cp.add_argument("--dove", required=True)
    cp.add_argument("--minutes", type=int, default=15)
    cp.set_defaults(fn=cmd_cartella)

    re = s.add_parser("registro", help="eventi osservati e stato delle autorizzazioni")
    res = re.add_subparsers(dest="operazione", required=True)
    for nome in ("stato", "verifica", "sorveglianza"):
        res.add_parser(nome).set_defaults(fn=cmd_registro)
    rw = res.add_parser("sorveglia", help="configura una cartella dell'utente per il registro kernel")
    rw.add_argument("cartella")
    rw.add_argument("--id", help="identificatore stabile; un percorso già configurato conserva il proprio ID")
    rw.add_argument("--nome")
    rw.set_defaults(fn=cmd_registro)
    rd = res.add_parser("smetti", help="rimuovi una sorveglianza per ID o percorso esatto")
    rd.add_argument("cartella")
    rd.set_defaults(fn=cmd_registro)
    for nome in ("elenco", "esporta"):
        r = res.add_parser(nome)
        r.add_argument("--cartella")
        r.add_argument("--file")
        r.add_argument("--processo")
        r.add_argument("--agente", metavar="true|false|unknown|NOME",
                       help="filtra per classificazione oppure nome dell'agente, per esempio Codex")
        r.add_argument("--da")
        r.add_argument("--a")
        r.set_defaults(fn=cmd_registro)

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
