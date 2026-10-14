"""The bootstrap command has one official copy, and the app shows the same text."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INIZIO = "sudo /bin/sh -c 'set -eu"
FINE = "fi'"
# These documents link to the official copy instead of repeating it.
SENZA_COPIA = ("README.md", "docs/registro-accessi.md")


def _blocco_markdown(testo):
    righe = testo.split("\n")
    inizi = [i for i, riga in enumerate(righe) if riga.startswith(INIZIO)]
    assert len(inizi) == 1, "the Markdown guide must hold exactly one copy of the command"
    fine = next(j for j in range(inizi[0], len(righe)) if righe[j] == FINE)
    return "\n".join(righe[inizi[0]:fine + 1])


def _comando_swift(testo):
    righe = testo.split("\n")
    apertura = righe.index('    static let preparationCommand = """') + 1
    chiusura = righe.index('    """', apertura)
    corpo = righe[apertura:chiusura]
    # Swift removes the indentation of the closing delimiter from every line.
    assert all(riga.startswith("    ") for riga in corpo)
    return "\n".join(riga[4:] for riga in corpo)


def test_copia_ufficiale_uguale_al_comando_mostrato_dall_app():
    ufficiale = _blocco_markdown((ROOT / "docs" / "gui-mac.md").read_text(encoding="utf-8"))
    mostrato = _comando_swift((ROOT / "macos" / "NativeInstall.swift").read_text(encoding="utf-8"))
    assert ufficiale == mostrato


def test_readme_e_registro_rinviano_alla_copia_ufficiale():
    for nome in SENZA_COPIA:
        testo = (ROOT / nome).read_text(encoding="utf-8")
        assert "paratia_bootstrap_stage" not in testo, nome
        assert not any(riga.startswith(INIZIO) for riga in testo.split("\n")), nome
        assert "gui-mac.md#impostazioni" in testo, nome
