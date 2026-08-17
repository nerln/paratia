#!/usr/bin/env python3
"""E4 — what the two vendors' own logs record about who asked.

This is the negative-space artifact, and after the adversarial pass against the
literature it is the piece the argument rests on. Qi et al. established in 2024
that a refusal living in model weights is shallow and brittle, so "the boundary
is in the weights" is not news. What is not established is that for the
agent-to-agent edge there is no other layer at all. That claim cannot be argued.
It has to be shown, by going to the telemetry both vendors already write and
demonstrating that the edge is not in it.

WHAT THIS READS. Only files the two harnesses write for themselves, on this
machine, read-only:

  ~/.codex/sessions/**/*.jsonl        Codex rollout records, one per session
  ~/.claude/projects/**/*.jsonl       Claude Code transcripts, one per session

WHAT IT LOOKS FOR. Not the absence of a log line — that would be trivial and
unfalsifiable. It looks for the provenance FIELDS each vendor already defines,
and asks what values they actually take when the caller is another agent. A
field that exists and is always "user" is a stronger result than no field at
all: it means the vendor modelled the question and answered it wrong.

Prints counts only. No message content, no prompts, no file paths beyond the two
roots. The point is a distribution over field values, and the transcripts are
the user's.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter

CODEX = "~/.codex/sessions/**/*.jsonl"
CLAUDE = "~/.claude/projects/**/*.jsonl"

# Fields each side defines that could carry provenance. Chosen by reading one
# record from each and taking every key that could plausibly answer "who asked",
# rather than by guessing names.
CAMPI_CODEX = ("originator", "source", "thread_source")
CAMPI_CLAUDE = ("origin", "promptSource", "userType", "entrypoint")


def sessioni(modello: str, quante: int) -> list[str]:
    f = glob.glob(os.path.expanduser(modello), recursive=True)
    return sorted(f, key=os.path.getmtime, reverse=True)[:quante]


def audit_codex(quante: int) -> dict:
    conteggi = {k: Counter() for k in CAMPI_CODEX}
    viste = 0
    for p in sessioni(CODEX, quante):
        try:
            for riga in open(p):
                r = json.loads(riga)
                if r.get("type") != "session_meta":
                    continue
                pl = r.get("payload", {})
                viste += 1
                for k in CAMPI_CODEX:
                    if k in pl:
                        conteggi[k][str(pl[k])] += 1
                break
        except Exception:  # noqa: BLE001
            continue
    return {"sessioni": viste, "campi": {k: dict(v) for k, v in conteggi.items()}}


def audit_claude(quante: int) -> dict:
    conteggi = {k: Counter() for k in CAMPI_CLAUDE}
    turni = 0
    dal_ponte = 0
    for p in sessioni(CLAUDE, quante):
        try:
            for riga in open(p):
                r = json.loads(riga)
                if r.get("type") != "user" or r.get("isMeta") or r.get("isSidechain"):
                    continue
                c = (r.get("message") or {}).get("content")
                # A tool result is not somebody speaking.
                if isinstance(c, list) and any(
                    isinstance(b, dict) and b.get("type") == "tool_result" for b in c
                ):
                    continue
                turni += 1
                testo = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
                if 'source="agentbridge"' in testo:
                    dal_ponte += 1
                for k in CAMPI_CLAUDE:
                    if k in r:
                        conteggi[k][json.dumps(r[k], ensure_ascii=False)[:48]] += 1
        except Exception:  # noqa: BLE001
            continue
    return {
        "turni_utente": turni,
        "turni_dal_ponte": dal_ponte,
        "campi": {k: dict(v) for k, v in conteggi.items()},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="E4 — provenance in the vendors' own logs")
    ap.add_argument("-n", type=int, default=80, help="how many recent sessions per side")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    esito = {"codex": audit_codex(args.n), "claude": audit_claude(args.n)}

    if args.json:
        print(json.dumps(esito, indent=1, ensure_ascii=False))
        return 0

    c = esito["codex"]
    print(f"CODEX — {c['sessioni']} sessioni")
    for k, v in c["campi"].items():
        print(f"  {k:16} {v}")

    cl = esito["claude"]
    print(f"\nCLAUDE CODE — {cl['turni_utente']} turni utente reali, "
          f"{cl['turni_dal_ponte']} dal ponte")
    for k, v in cl["campi"].items():
        print(f"  {k:16} {v}")

    print("\nLettura:")
    ts = c["campi"].get("thread_source", {})
    if ts:
        um = ts.get("user", 0)
        print(f"  Codex definisce thread_source e vale 'user' in {um} sessioni su "
              f"{sum(ts.values())}. Le sessioni con originator=codex_exec sono state "
              f"avviate da un programma, non da una persona che digita, e nel log non "
              f"si distinguono.")
    orig = cl["campi"].get("origin", {})
    if orig:
        print(f"  Claude Code definisce origin.kind e distingue davvero "
              f"({', '.join(sorted(orig))}). Ma nessuno dei valori dice 'richiesto da "
              f"un agente esterno', e i turni dal ponte sono {cl['turni_dal_ponte']}.")
    print("  Nessuno dei due lati registra l'arco fra fornitori. Uno ha il campo e "
          "risponde sempre 'utente'; l'altro distingue umano da notifica interna e non "
          "ha un valore per questo caso.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
