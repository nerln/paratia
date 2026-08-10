#!/usr/bin/env python3
"""The compartment and a zone must not behave alike, and the gate must know it.

Conflating the two is the expensive mistake this file exists to catch. The
compartment holds secrets, so the gate stops the session while it is open. A
zone holds work the agent has to read to be useful, so the gate must ignore it
completely. Getting that backwards either leaks the secrets or makes every
confined workspace unusable, and both failures look fine until they don't.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
GATE = RADICE / "hooks" / "paratia-gate.py"

sys.path.insert(0, str(RADICE))
import importlib.util

spec = importlib.util.spec_from_file_location("paratia", RADICE / "paratia.py")
paratia = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paratia)

esiti: list[tuple[bool, str]] = []


def verifica(nome: str, condizione: bool) -> None:
    esiti.append((condizione, nome))
    print(f"{'ok  ' if condizione else 'FAIL'} {nome}")


def gate(payload: dict, *, mount: str, home: str) -> dict | None:
    p = subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env={**os.environ, "PARATIA_MOUNT": mount, "PARATIA_HOME": home},
    )
    fuori = p.stdout.decode().strip()
    return json.loads(fuori) if fuori else None


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        casa = d / "casa"
        casa.mkdir()
        chiuso = str(d / "non-montato")

        # The gate watches exactly one mountpoint. A zone lives under
        # /Volumes/zona-<name>, so an open zone must be invisible to it. "/" is
        # always a mount, and standing in for a zone here proves the gate is
        # not simply refusing whenever anything is mounted.
        t = d / "t.jsonl"
        t.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": "lavora nel repo"}}))

        verifica(
            "an open zone does not stop the session",
            gate(
                {"tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "transcript_path": str(t)},
                mount=chiuso, home=str(casa),
            ) is None,
        )
        verifica(
            "the compartment still does",
            (gate({"tool_name": "Bash", "tool_input": {"command": "pytest -q"}}, mount="/", home=str(casa)) or {})
            .get("hookSpecificOutput", {}).get("permissionDecision") == "deny",
        )

        # Zone mountpoints must not collide with the compartment's, or an open
        # zone would wedge every session.
        verifica(
            "zone mountpoints are a separate namespace",
            str(paratia._monte_zona("lavoro")) == "/Volumes/zona-lavoro"
            and paratia.MONTAGGIO != paratia._monte_zona("lavoro"),
        )

        # Refusing to build a sparsebundle inside a synced tree.
        for percorso in (
            "/Users/x/Library/CloudStorage/GoogleDrive-a@b.c/Lavoro",
            "/Users/x/Dropbox/roba",
            "/Users/x/OneDrive/roba",
        ):
            verifica(
                f"cloud-synced path refused: {Path(percorso).parts[3]}",
                paratia._sincronizzato(Path(percorso)),
            )
        verifica("an ordinary path is not flagged", not paratia._sincronizzato(d))

        # _volume_di walks up to a real mountpoint rather than guessing.
        verifica("_volume_di finds a mountpoint", Path(paratia._volume_di(d)).is_mount())

        # A name with a slash in it must not escape the compartment.
        aperto_finto = paratia.aperto
        paratia.aperto = lambda: True
        try:
            paratia.MONTAGGIO = d
            verifica(
                "percorso() strips a traversal",
                paratia.percorso("../../etc/passwd") == d / "passwd",
            )
            caduto = False
            try:
                paratia.percorso(".ssh")
            except paratia.Rifiuto:
                caduto = True
            verifica("percorso() refuses a dotfile name", caduto)
        finally:
            paratia.aperto = aperto_finto

        # The exposure report has to notice a group-readable home, because that
        # is the failure that makes a second account pointless without saying so.
        finta_casa = d / "home-aperta"
        finta_casa.mkdir(mode=0o750)
        vecchia = os.environ.get("HOME")
        os.environ["HOME"] = str(finta_casa)
        try:
            import argparse

            args = argparse.Namespace(json=True, workspace=[])
            import io
            import contextlib

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                paratia.cmd_esposizione(args)
            righe = json.loads(buf.getvalue())
            voce = next(r for r in righe if r["voce"] == "home")
            verifica("exposure flags a group-readable home", voce["stato"] in ("EXPOSED", "WOULD BE"))
        finally:
            if vecchia:
                os.environ["HOME"] = vecchia

    caduti = [n for ok, n in esiti if not ok]
    print(f"\n{len(esiti) - len(caduti)}/{len(esiti)} passed")
    for n in caduti:
        print(f"  failed: {n}")
    return 1 if caduti else 0


if __name__ == "__main__":
    sys.exit(main())
