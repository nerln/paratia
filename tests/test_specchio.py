#!/usr/bin/env python3
"""What the mirror has to get right before anyone points it at real material.

Three properties carry it. Tokens must be stable, or the same person reads as
two people and the text stops meaning anything. Overlapping matches must resolve
to the outer one, or an IBAN gets shredded into a card and a phone number. And
a file that could not be scanned must not land in the mirror, because a
directory described as safe to read is exactly where an unscanned PDF does the
most damage.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("specchio", RADICE / "specchio.py")
S = importlib.util.module_from_spec(spec)
# Registered before exec because @dataclass resolves annotations through
# sys.modules[cls.__module__], and a module loaded by spec alone is not there.
sys.modules["specchio"] = S
spec.loader.exec_module(S)

esiti: list[tuple[bool, str]] = []
CHIAVE = b"chiave-di-prova-non-segreta-1234"


def verifica(nome: str, condizione: bool) -> None:
    esiti.append((condizione, nome))
    print(f"{'ok  ' if condizione else 'FAIL'} {nome}")


def main() -> int:
    # --- detection
    t = {}
    testo = "Scrivi a mario.rossi@example.com oppure chiama +39 340 1234567."
    fuori, conta = S.pseudonimizza(testo, CHIAVE, t)
    verifica("email found", conta.get("EMAIL") == 1)
    verifica("phone found", conta.get("TEL") == 1)
    verifica("original email is gone", "mario.rossi@example.com" not in fuori)
    verifica("surrounding prose survives", "Scrivi a" in fuori and "oppure chiama" in fuori)

    # --- stability: the same value is the same token, twice and in two files
    t2 = {}
    a, _ = S.pseudonimizza("mario.rossi@example.com", CHIAVE, t2)
    b, _ = S.pseudonimizza("altro testo mario.rossi@example.com qui", CHIAVE, t2)
    verifica("same value gives the same token across files", a.strip() in b)

    t3 = {}
    c, _ = S.pseudonimizza("mario.rossi@example.com", b"un-altra-chiave-diversa-12345", t3)
    verifica("a different key gives a different token", a.strip() != c.strip())

    # --- codice fiscale and IBAN
    t = {}
    fuori, conta = S.pseudonimizza("CF: RSSMRA85M01H501Z e IBAN IT60X0542811101000000123456", CHIAVE, t)
    verifica("codice fiscale found", conta.get("CF") == 1)
    verifica("IBAN found", conta.get("IBAN") == 1)
    verifica("IBAN was not shredded into a card", conta.get("CARTA", 0) == 0)

    # --- Luhn keeps invented numbers out
    t = {}
    _, conta = S.pseudonimizza("carta 4111111111111111 valida", CHIAVE, t)
    verifica("a Luhn-valid card is caught", conta.get("CARTA") == 1)
    t = {}
    _, conta = S.pseudonimizza("codice 1234567890123456 qualsiasi", CHIAVE, t)
    verifica("a Luhn-invalid number is left alone", conta.get("CARTA", 0) == 0)

    # --- partita IVA only when it is labelled
    t = {}
    _, conta = S.pseudonimizza("P.IVA 12345678901", CHIAVE, t)
    verifica("labelled partita IVA is caught", conta.get("PIVA") == 1)
    t = {}
    _, conta = S.pseudonimizza("il numero 12345678901 in mezzo al testo", CHIAVE, t)
    verifica("an unlabelled 11-digit number is left alone", conta.get("PIVA", 0) == 0)

    # --- credentials
    t = {}
    _, conta = S.pseudonimizza("export K=ghp_" + "a" * 36, CHIAVE, t)
    verifica("a github token is caught", conta.get("CHIAVE") == 1)

    # --- the table is the way back
    t = {}
    fuori, _ = S.pseudonimizza("scrivi a anna@example.org", CHIAVE, t)
    gettone = next(iter(t))
    verifica("the table maps the token back to the value", t[gettone]["valore"] == "anna@example.org")
    verifica("the token appears in the output", gettone in fuori)

    # --- external engine
    finto = "python3 -c \"import json,sys; s=sys.stdin.read(); i=s.find('Mario Rossi'); print(json.dumps([{'start':i,'end':i+11,'type':'NOME'}] if i>=0 else []))\""
    t = {}
    fuori, conta = S.pseudonimizza("Il cliente Mario Rossi ha firmato.", CHIAVE, t, motore=finto)
    verifica("an external engine contributes spans", conta.get("NOME") == 1)
    verifica("the name is gone", "Mario Rossi" not in fuori)

    t = {}
    fuori, conta = S.pseudonimizza("testo qualsiasi", CHIAVE, t, motore="exit 1")
    verifica("a broken engine yields nothing instead of crashing", conta == {})

    # --- mirroring a tree
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src, dst = d / "src", d / "dst"
        (src / "sub").mkdir(parents=True)
        (src / "note.md").write_text("contatto: luca@example.com")
        (src / "sub" / "dati.csv").write_text("nome,email\nx,luca@example.com\n")
        (src / "foto.bin").write_bytes(b"\x00\x01\x02binario")
        (src / ".git").mkdir()
        (src / ".git" / "config").write_text("segreto@example.com")

        t = {}
        esito = S.rispecchia(src, dst, CHIAVE, t)

        verifica("text files are mirrored", (dst / "note.md").exists() and (dst / "sub" / "dati.csv").exists())
        verifica("the binary is NOT copied", not (dst / "foto.bin").exists())
        verifica("the binary is reported", any("foto.bin" in b for b in esito.binari))
        verifica("dot directories are skipped", not (dst / ".git").exists())
        verifica("the identifier is gone from the mirror", "luca@example.com" not in (dst / "note.md").read_text())
        verifica(
            "the same value got one table entry across two files",
            len([v for v in t.values() if v["valore"] == "luca@example.com"]) == 1,
        )

        # A second run must not churn: same tokens, same output.
        prima = (dst / "note.md").read_text()
        S.rispecchia(src, dst, CHIAVE, t)
        verifica("re-running is idempotent", (dst / "note.md").read_text() == prima)

        # Binaries only on request.
        S.rispecchia(src, dst, CHIAVE, t, copia_binari=True)
        verifica("--copia-binari copies them", (dst / "foto.bin").exists())

        # The mirror must not be built inside its own source.
        rifiutato = False
        try:
            S.rispecchia(src, src / "dentro", CHIAVE, t)
        except ValueError:
            rifiutato = True
        verifica("a mirror inside its source is refused", rifiutato)

    caduti = [n for ok, n in esiti if not ok]
    print(f"\n{len(esiti) - len(caduti)}/{len(esiti)} passed")
    for n in caduti:
        print(f"  failed: {n}")
    return 1 if caduti else 0


if __name__ == "__main__":
    sys.exit(main())
