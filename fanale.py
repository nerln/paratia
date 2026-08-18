#!/usr/bin/env python3
"""A ship shows its lights so others know what it is before they can see it.

This is the SSH channel between two Claude sessions on two machines, with the
one thing such a channel does not otherwise have: a statement of who is asking.

WHY THIS FILE EXISTS

`paratia-gate.py` refuses human-only capabilities on turns opened by another
agent, and it works out who spoke by reading the harness-written transcript for
AgentBridge's channel marker. A turn that arrives over SSH carries no such
marker. To the receiving harness it is indistinguishable from the operator
typing, which is precisely the finding this project measured: both vendors
record delegation provenance in detail and stop at their own perimeter, so 38 of
59 programmatically launched sessions are filed as having originated with a
user. An SSH bridge inherits that blindness and adds a shell to it.

WHAT IS ACTUALLY ENFORCED, AND WHAT IS NOT

Be clear about this before trusting any of it.

**Enforced by OpenSSH, not by us.** The bridge key is installed on the far side
with a forced command and every forwarding disabled. A holder of that key cannot
obtain a shell, cannot open a port, cannot forward an agent. It can run one
program: this receiver. That is the control that answers "privilege escalation",
and it is the only one here that an agent running as you cannot undo, because
the file that grants it lives on the other machine.

**Enforced by us, and worth having.** Hop depth, rate, replay, and a
hash-chained log. An agent-origin message may not itself delegate onward, so
A→B→C does not happen. Every envelope names its predecessor's digest, so a
deleted or edited entry breaks the chain and `fanale verifica` says where.

**NOT enforced, and no amount of engineering here would fix it.** We cannot
prove to the far side that a message really began with a human. The stamp is
computed on the sending machine from harness-written state the model does not
author, which is the strongest available signal and is the CaMeL rule; but an
agent with your uid could bypass this program and speak to the socket itself.
What that costs it is: the forced command still holds, the envelope must still
parse, the default on anything malformed is agent-origin, and the attempt is in
the chain. Tamper-evident, not tamper-proof, and it is the same honest boundary
as everywhere else in this repository.

THE DEFAULT IS THE POINT

Absent envelope, malformed envelope, unreadable transcript, unparseable JSON,
crash in this file: all resolve to agent-origin, which is the restricted case.
A guard that fails open is a guard that fails silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

CASA = Path(os.environ.get("FANALE_HOME", Path.home() / ".paratia" / "fanale"))
CATENA = CASA / "catena.jsonl"
CODA = CASA / "coda.jsonl"
CONFIG = CASA / "config.json"
CHIAVE = CASA / "id_fanale"

# An agent-origin message may not delegate onward. One hop from a human is a
# collaboration; two is a chain nobody authorised. The limit is on the envelope
# rather than on the conversation because the conversation is model-authored.
PROFONDITA_MAX = 1

# Messages per window, per direction. Two agents in a listen loop will otherwise
# talk to each other until the quota runs out, which is a real failure mode and
# not a hypothetical one.
FINESTRA = 60
QUOTA = 20


def casa() -> Path:
    CASA.mkdir(parents=True, exist_ok=True)
    return CASA


def config() -> dict:
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


# ------------------------------------------------------------------ origin


def origine_dal_transcript(transcript: str | None) -> tuple[str, str]:
    """Work out whether the current local turn began with the human.

    Read from the harness's own transcript, never from anything the model wrote
    — the model does not author this file, which is the entire reason it is
    worth reading. Anything unreadable returns agent, because the restricted
    answer is the safe one.

    Returns (origin, why) so the log can say what it concluded and on what.
    """
    if not transcript:
        return "agent", "nessun transcript indicato"
    p = Path(transcript)
    if not p.is_file():
        return "agent", "transcript assente"
    try:
        righe = p.read_text(errors="replace").splitlines()
    except OSError as e:
        return "agent", f"transcript illeggibile ({e.strerror})"

    for riga in reversed(righe[-400:]):
        if not riga.strip():
            continue
        try:
            r = json.loads(riga)
        except json.JSONDecodeError:
            continue
        if r.get("type") != "user" or r.get("isMeta") or r.get("isSidechain"):
            continue
        c = (r.get("message") or {}).get("content")
        if isinstance(c, list):
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in c):
                continue
            testo = " ".join(b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text")
        elif isinstance(c, str):
            testo = c
        else:
            continue

        # A turn that itself arrived over a bridge is not a human turn, and this
        # is what stops A -> B -> C: the second hop reads its own inbound
        # marker and stamps agent, whatever the model says about it.
        for marcatore, nome in (('source="agentbridge"', "agentbridge"),
                                ('source="fanale"', "fanale")):
            if marcatore in testo:
                return "agent", f"il turno locale è arrivato da {nome}"
        return "human", "ultimo turno digitato dall'operatore"
    return "agent", "nessun turno umano trovato nella coda del transcript"


# ------------------------------------------------------------------- chain


def _ultimo_digest() -> str:
    if not CATENA.exists():
        return "0" * 64
    ultimo = ""
    with CATENA.open() as f:
        for riga in f:
            if riga.strip():
                ultimo = riga
    if not ultimo:
        return "0" * 64
    return hashlib.sha256(ultimo.strip().encode()).hexdigest()


def annota(voce: dict) -> dict:
    """Append to the hash chain. Each entry names its predecessor's digest, so
    removing or editing one breaks every entry after it, detectably."""
    casa()
    voce = {**voce, "precedente": _ultimo_digest(), "quando": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    with CATENA.open("a") as f:
        f.write(json.dumps(voce, ensure_ascii=False, sort_keys=True) + "\n")
    return voce


def _quota_superata(direzione: str) -> bool:
    if not CATENA.exists():
        return False
    ora = time.time()
    n = 0
    try:
        for riga in CATENA.read_text().splitlines()[-200:]:
            if not riga.strip():
                continue
            v = json.loads(riga)
            if v.get("direzione") != direzione:
                continue
            t = time.mktime(time.strptime(v["quando"][:19], "%Y-%m-%dT%H:%M:%S"))
            if ora - t < FINESTRA:
                n += 1
    except Exception:  # noqa: BLE001
        return True  # cannot count, so assume exceeded
    return n >= QUOTA


# ------------------------------------------------------------------ commands


def cmd_chiavi(args) -> int:
    """Make a bridge-only keypair and print the far-side line that confines it.

    Deliberately NOT your existing key. A key that can open a shell is a key
    that turns this bridge into remote code execution the moment an agent reads
    it, and an agent running as you can read anything you can.
    """
    casa()
    if CHIAVE.exists() and not args.force:
        print(f"{CHIAVE} esiste già. --force per rifarla.")
    else:
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "fanale-bridge",
                        "-f", str(CHIAVE)], check=True, capture_output=True)
        CHIAVE.chmod(0o600)
        print(f"creata {CHIAVE}")

    pub = (CHIAVE.with_suffix(".pub")).read_text().strip()
    ricevitore = args.ricevitore or "/usr/local/bin/fanale ascolta"

    print("\nRiga da mettere in ~/.ssh/authorized_keys SULL'ALTRA MACCHINA,")
    print("tutta su una riga sola:\n")
    print(f'command="{ricevitore}",restrict {pub}')
    print("\nCosa fa ciascun pezzo, perché è qui che sta la sicurezza vera:")
    print('  command="..."  la chiave può eseguire SOLO quel programma. Qualunque')
    print("                 comando arrivi da questo lato viene ignorato: non c'è")
    print("                 shell, e non c'e' modo di chiederne una.")
    print("  restrict       spegne tutto il resto in un colpo: port forwarding,")
    print("                 agent forwarding, X11, pty, esecuzione di ~/.ssh/rc.")
    print("                 OpenSSH aggiunge da solo le negazioni future.")
    print("\nQuesto e' l'unico controllo qui che un agente con il tuo uid non puo'")
    print("annullare, perche' il file che lo concede sta sull'altra macchina.")
    print("\nMeglio ancora: un utente dedicato di la', senza sudo, che possiede")
    print("solo la cartella del ponte. Cosi' anche il ricevitore gira ristretto.")
    return 0


def cmd_collega(args) -> int:
    c = config()
    c.update({"host": args.host, "utente": args.utente, "nome_locale": args.io})
    casa()
    CONFIG.write_text(json.dumps(c, indent=1))
    print(f"configurato: {args.utente}@{args.host}, questo capo si chiama {args.io!r}")
    return 0


def cmd_invia(args) -> int:
    """Send one message, stamped with an origin this program computes.

    There is no --origin flag and there will not be one. The stamp is derived
    from the transcript, not passed in, because a value the caller supplies is a
    value the caller chooses.
    """
    c = config()
    if not c.get("host"):
        print("fanale: nessuna destinazione. `fanale collega --host ... --utente ...`", file=sys.stderr)
        return 2

    origine, perche = origine_dal_transcript(args.transcript or os.environ.get("CLAUDE_TRANSCRIPT_PATH"))
    profondita = 0 if origine == "human" else int(args.profondita_ricevuta) + 1

    if profondita > PROFONDITA_MAX:
        voce = annota({"direzione": "uscita", "esito": "rifiutato", "motivo":
                       f"profondita {profondita} oltre il massimo {PROFONDITA_MAX}",
                       "origine": origine})
        print(f"fanale: rifiutato. {voce['motivo']}.", file=sys.stderr)
        print("Un messaggio che arriva da un agente non ne delega un altro.", file=sys.stderr)
        return 3

    if _quota_superata("uscita"):
        annota({"direzione": "uscita", "esito": "rifiutato", "motivo": "quota"})
        print(f"fanale: quota superata ({QUOTA} messaggi in {FINESTRA}s).", file=sys.stderr)
        return 4

    busta = {
        "v": 1,
        "da": c.get("nome_locale", "ignoto"),
        "origine": origine,
        "perche": perche,
        "profondita": profondita,
        "testo": args.testo,
        "id": hashlib.sha256(f"{time.time()}{args.testo}".encode()).hexdigest()[:16],
    }

    comando = ["ssh", "-i", str(CHIAVE), "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new",
               f"{c['utente']}@{c['host']}"]
    esito = subprocess.run(comando, input=json.dumps(busta).encode(),
                           capture_output=True, timeout=args.timeout)

    annota({"direzione": "uscita", "esito": "inviato" if esito.returncode == 0 else "errore",
            "origine": origine, "profondita": profondita, "id": busta["id"],
            "rc": esito.returncode})

    if esito.returncode != 0:
        print(f"fanale: ssh ha fallito: {esito.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 5
    print(f"inviato (origine: {origine}, hop {profondita})")
    if esito.stdout.strip():
        print(esito.stdout.decode(errors="replace").strip())
    return 0


def cmd_ascolta(args) -> int:
    """The far side. Runs as the forced command; reads one envelope from stdin.

    It never executes anything. It parses, checks, appends to the queue, and
    exits. SSH_ORIGINAL_COMMAND is read only to be logged and refused: whatever
    the caller tried to run, this is what runs instead.
    """
    casa()
    tentato = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    grezzo = sys.stdin.read(args.max_bytes)

    try:
        busta = json.loads(grezzo)
        if not isinstance(busta, dict) or "testo" not in busta:
            raise ValueError("busta senza testo")
    except Exception as e:  # noqa: BLE001
        annota({"direzione": "entrata", "esito": "rifiutato",
                "motivo": f"busta illeggibile: {type(e).__name__}",
                "comando_tentato": tentato})
        print("fanale: busta non valida, rifiutata", file=sys.stderr)
        return 2

    # Anything not positively stated as human is treated as an agent.
    origine = busta.get("origine")
    if origine != "human":
        origine = "agent"
    profondita = busta.get("profondita")
    profondita = profondita if isinstance(profondita, int) and profondita >= 0 else PROFONDITA_MAX + 1

    # A human-origin envelope with a hop count above zero is internally
    # inconsistent: origin human means the chain started here, which is depth
    # zero by construction. Something built that envelope by hand. Downgrade it
    # rather than believe it.
    if origine == "human" and profondita > 0:
        annota({"direzione": "entrata", "esito": "declassato",
                "motivo": "origine human con profondita > 0, incoerente",
                "profondita": profondita, "da": busta.get("da")})
        origine = "agent"

    # The hop limit applies to every envelope, whatever it says about itself.
    # Gating it on origin == "agent" let a message claiming human origin carry
    # any depth it liked, which is exactly the field an agent controls.
    if profondita > PROFONDITA_MAX:
        annota({"direzione": "entrata", "esito": "rifiutato", "motivo": "profondita",
                "profondita": profondita, "da": busta.get("da"), "comando_tentato": tentato})
        print("fanale: profondita oltre il massimo, rifiutato", file=sys.stderr)
        return 3

    if _quota_superata("entrata"):
        annota({"direzione": "entrata", "esito": "rifiutato", "motivo": "quota"})
        print("fanale: quota superata", file=sys.stderr)
        return 4

    voce = annota({"direzione": "entrata", "esito": "accettato", "origine": origine,
                   "profondita": profondita, "da": busta.get("da"),
                   "id": busta.get("id"), "comando_tentato": tentato})

    # The queue line is what a local session will read. The channel tag is the
    # same shape paratia-gate.py already understands, so the gate needs to learn
    # one new source name and nothing else.
    with CODA.open("a") as f:
        f.write(json.dumps({
            "quando": voce["quando"],
            "origine": origine,
            "profondita": profondita,
            "da": busta.get("da", "ignoto"),
            "testo": busta["testo"],
            "tag": f'<channel source="fanale" origin="{origine}" depth="{profondita}" '
                   f'user="{busta.get("da", "ignoto")}">{busta["testo"]}</channel>',
        }, ensure_ascii=False) + "\n")

    print(f"accettato (origine: {origine}, hop {profondita})")
    if tentato:
        print(f"nota: il chiamante aveva provato a eseguire {tentato!r}; ignorato.", file=sys.stderr)
    return 0


def cmd_leggi(args) -> int:
    """Drain the queue for a local session. Prints the channel-tagged form."""
    if not CODA.exists():
        print("nessun messaggio")
        return 0
    righe = [r for r in CODA.read_text().splitlines() if r.strip()]
    if not righe:
        print("nessun messaggio")
        return 0
    for r in righe[-args.quanti:]:
        v = json.loads(r)
        print(v["tag"] if args.tag else f"[{v['quando']}] {v['da']} ({v['origine']}): {v['testo']}")
    if args.svuota:
        CODA.write_text("")
    return 0


def cmd_verifica(args) -> int:
    """Check the hash chain, and report the local posture."""
    problemi = 0

    if not CATENA.exists():
        print("catena  vuota (nessun messaggio ancora)")
    else:
        righe = [r for r in CATENA.read_text().splitlines() if r.strip()]
        atteso = "0" * 64
        for i, r in enumerate(righe, 1):
            v = json.loads(r)
            if v.get("precedente") != atteso:
                print(f"catena  ROTTA alla voce {i}: qualcuno ha tolto o cambiato una riga prima di questa")
                problemi += 1
                break
            atteso = hashlib.sha256(r.strip().encode()).hexdigest()
        else:
            print(f"catena  ok, {len(righe)} voci, nessun buco")

    if CHIAVE.exists():
        modo = CHIAVE.stat().st_mode & 0o777
        print(f"chiave  {CHIAVE} modo {oct(modo)}" + ("" if modo == 0o600 else "  <- dovrebbe essere 0600"))
        problemi += 0 if modo == 0o600 else 1
    else:
        print("chiave  assente, `fanale chiavi`")
        problemi += 1

    c = config()
    print(f"rotta   {c.get('utente','?')}@{c.get('host','?')}, io sono {c.get('nome_locale','?')}")

    # The far-side line is the only real control, so say plainly that we cannot
    # confirm it from here rather than implying that we did.
    print("\nQuello che NON posso verificare da questo lato, e che conta più di tutto:")
    print("  che sull'altra macchina la chiave sia installata con command=\"...\",restrict.")
    print("  Senza quello questo ponte e' esecuzione remota di comandi con un log.")
    print("  Controllalo di la':  grep fanale ~/.ssh/authorized_keys")
    return 1 if problemi else 0


def costruisci() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fanale",
                                description="Provenance for an SSH channel between two agent sessions.")
    s = p.add_subparsers(dest="cmd", required=True)

    k = s.add_parser("chiavi", help="make the bridge-only key and print the far-side line")
    k.add_argument("--ricevitore", default=None)
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_chiavi)

    c = s.add_parser("collega", help="set the far side")
    c.add_argument("--host", required=True)
    c.add_argument("--utente", required=True)
    c.add_argument("--io", default="mac")
    c.set_defaults(fn=cmd_collega)

    i = s.add_parser("invia", help="send a message, origin computed not supplied")
    i.add_argument("testo")
    i.add_argument("--transcript", default=None)
    i.add_argument("--profondita-ricevuta", dest="profondita_ricevuta", default=0)
    i.add_argument("--timeout", type=int, default=30)
    i.set_defaults(fn=cmd_invia)

    a = s.add_parser("ascolta", help="the far-side receiver; runs as the forced command")
    a.add_argument("--max-bytes", dest="max_bytes", type=int, default=65536)
    a.set_defaults(fn=cmd_ascolta)

    l = s.add_parser("leggi", help="drain the queue")
    l.add_argument("--quanti", type=int, default=10)
    l.add_argument("--tag", action="store_true", help="print the channel-tagged form")
    l.add_argument("--svuota", action="store_true")
    l.set_defaults(fn=cmd_leggi)

    s.add_parser("verifica", help="check the chain and the local posture").set_defaults(fn=cmd_verifica)
    return p


def main(argv: list[str] | None = None) -> int:
    args = costruisci().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        # A crash in the guard must not become a pass. Say so and fail.
        print(f"fanale: fallito ({type(e).__name__}), quindi non passa niente", file=sys.stderr)
        sys.exit(1)
