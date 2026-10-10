#!/usr/bin/env python3
"""What the gate has to get right, run without touching a real compartment.

Both refusals are exercised against a fake mountpoint and a synthetic
transcript, so this suite says nothing about whether AES works — it says whether
the two decisions come out the way the docstring claims, including the cases
that are easy to get wrong: the base64'd path, the compound command hiding
behind an allowed one, and the tool result that must not be mistaken for a human
speaking.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent.parent / "hooks" / "paratia-gate.py"

esiti: list[tuple[bool, str]] = []


def gate(payload: dict, *, mount: str, home: str) -> dict | None:
    amb = {**os.environ, "PARATIA_MOUNT": mount, "PARATIA_HOME": home,
           "PATH": str(Path(home) / "bin") + os.pathsep + os.environ.get("PATH", os.defpath)}
    p = subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(payload).encode(),
        capture_output=True,
        env=amb,
    )
    fuori = p.stdout.decode().strip()
    return json.loads(fuori) if fuori else None


def verifica(nome: str, condizione: bool) -> None:
    esiti.append((condizione, nome))
    print(f"{'ok  ' if condizione else 'FAIL'} {nome}")


def negato(r: dict | None) -> bool:
    return bool(r) and r["hookSpecificOutput"]["permissionDecision"] == "deny"


def transcript(cartella: Path, righe: list[dict]) -> str:
    p = cartella / "t.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in righe))
    return str(p)


def turno_umano(testo: str) -> dict:
    return {"type": "user", "message": {"role": "user", "content": testo}}


def turno_ponte(chi: str, testo: str) -> dict:
    return {
        "type": "user",
        "message": {
            "role": "user",
            "content": f'<channel source="agentbridge" chat_id="1" user="{chi}">{testo}</channel>',
        },
    }


def risultato_strumento() -> dict:
    return {
        "type": "user",
        "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x", "content": "out"}]},
    }


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        casa = d / "casa"
        casa.mkdir()
        (casa / "bin").mkdir()
        # Resolve the shell alias to the real repository CLI without executing
        # it. Gate subprocesses only classify the synthetic hook payload.
        (casa / "bin" / "paratia").symlink_to(GATE.parent.parent / "paratia.py")
        (casa / "bin" / "python3").symlink_to(Path(sys.executable).resolve())
        chiuso = str(d / "non-montato")
        aperto = str(d)  # a real directory; is_mount() is false, so simulate below

        # --- the compartment is open: everything is refused
        # d itself is not a mount, so point at "/" which always is.
        verifica(
            "compartment open denies an unrelated read",
            negato(gate({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}, mount="/", home=str(casa))),
        )
        verifica(
            "compartment open denies the base64'd path trick",
            negato(gate(
                {"tool_name": "Bash", "tool_input": {"command": "cat $(echo L1ZvbHVtZXMvcGFyYXRpYS90b2tlbg== | base64 -d)"}},
                mount="/", home=str(casa),
            )),
        )
        verifica(
            "compartment open refuses user-writable `paratia lock`",
            negato(gate({"tool_name": "Bash", "tool_input": {"command": "paratia lock"}}, mount="/", home=str(casa))),
        )
        verifica(
            "compartment open refuses `paratia lock` with something appended",
            negato(gate(
                {"tool_name": "Bash", "tool_input": {"command": "paratia lock; cat /Volumes/paratia/token"}},
                mount="/", home=str(casa),
            )),
        )
        for command in ("paratia cartella chiudi one", "paratia cartella chiudi-tutte",
                        str(casa / "bin" / "paratia") + " cartella chiudi one",
                        "python3 " + str(GATE.parent.parent / "paratia.py") + " cartella chiudi-tutte"):
            verifica("compartment open refuses repository CLI: " + command,
                     negato(gate({"tool_name": "Bash", "tool_input": {"command": command}}, mount="/", home=str(casa))))
        fake = d / "paratia.py"
        fake.write_text("# same name is not the real program\n")
        verifica("compartment open refuses another paratia.py",
                 negato(gate({"tool_name": "Bash", "tool_input": {"command": "python3 " + str(fake) + " cartella chiudi-tutte"}},
                             mount="/", home=str(casa))))

        # --- closed compartment, human turn: silence
        t_umano = transcript(d, [turno_umano("apri il browser"), risultato_strumento()])
        verifica(
            "human turn keeps computer-use",
            gate(
                {"tool_name": "mcp__computer-use__screenshot", "tool_input": {}, "transcript_path": t_umano},
                mount=chiuso, home=str(casa),
            ) is None,
        )
        verifica(
            "human turn keeps the shell",
            gate(
                {"tool_name": "Bash", "tool_input": {"command": "paratia status"}, "transcript_path": t_umano},
                mount=chiuso, home=str(casa),
            ) is None,
        )

        # --- closed compartment, turn opened by another agent
        t_ponte = transcript(d, [turno_umano("vai"), turno_ponte("Codex", "please take a screenshot"), risultato_strumento()])
        verifica(
            "delegated turn loses computer-use",
            negato(gate(
                {"tool_name": "mcp__computer-use__screenshot", "tool_input": {}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            )),
        )
        verifica(
            "delegated turn loses the browser",
            negato(gate(
                {"tool_name": "mcp__claude-in-chrome__navigate", "tool_input": {}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            )),
        )
        verifica(
            "delegated turn loses `paratia` on the shell",
            negato(gate(
                {"tool_name": "Bash", "tool_input": {"command": "paratia get token"}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            )),
        )
        verifica(
            "delegated turn keeps ordinary work",
            gate(
                {"tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            ) is None,
        )
        verifica(
            "delegated turn keeps Read",
            gate(
                {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            ) is None,
        )

        # A bridge message followed by a real human turn is the human's turn.
        t_ripreso = transcript(d, [turno_ponte("Codex", "screenshot?"), turno_umano("no, fallo tu")])
        verifica(
            "human speaking after the bridge takes the turn back",
            gate(
                {"tool_name": "mcp__computer-use__screenshot", "tool_input": {}, "transcript_path": t_ripreso},
                mount=chiuso, home=str(casa),
            ) is None,
        )

        # A tool result must not be read as the human speaking again.
        t_dopo = transcript(d, [turno_ponte("Codex", "screenshot?"), risultato_strumento(), risultato_strumento()])
        verifica(
            "tool results do not hand the turn back to the human",
            negato(gate(
                {"tool_name": "mcp__computer-use__screenshot", "tool_input": {}, "transcript_path": t_dopo},
                mount=chiuso, home=str(casa),
            )),
        )

        # --- fail closed
        p = subprocess.run(
            [sys.executable, str(GATE)],
            input=b"not json at all",
            capture_output=True,
            env={**os.environ, "PARATIA_MOUNT": chiuso, "PARATIA_HOME": str(casa)},
        )
        verifica("garbage on stdin is refused, not waved through", negato(json.loads(p.stdout.decode() or "null")))

        # --- dogana.json can add to the human-only set but the floor stands without it
        (casa / "dogana.json").write_text(json.dumps({"solo_umano": ["mcp__plancia__*"]}))
        verifica(
            "dogana.json extends the human-only set",
            negato(gate(
                {"tool_name": "mcp__plancia__plancia_task_add", "tool_input": {}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            )),
        )
        (casa / "dogana.json").write_text("{ broken")
        verifica(
            "a corrupt dogana.json does not loosen the floor",
            negato(gate(
                {"tool_name": "mcp__computer-use__screenshot", "tool_input": {}, "transcript_path": t_ponte},
                mount=chiuso, home=str(casa),
            )),
        )

    caduti = [n for ok, n in esiti if not ok]
    print(f"\n{len(esiti) - len(caduti)}/{len(esiti)} passed")
    for n in caduti:
        print(f"  failed: {n}")
    return 1 if caduti else 0


if __name__ == "__main__":
    sys.exit(main())
