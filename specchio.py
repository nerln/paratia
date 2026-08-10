#!/usr/bin/env python3
"""A readable copy of a tree with the identifiers taken out, and the way back
locked in the compartment.

The problem this answers is the one the rest of paratia cannot. A compartment
keeps a secret away from the agent, which works because the agent does not need
it. A zone encrypts work at rest, which does nothing about the agent, because an
agent that cannot read the repository cannot work on the repository. Neither
helps with the case in the middle: a folder the agent genuinely has to read,
which happens to be full of other people's names.

So instead of hiding the tree, this makes a second one. Same structure, same
filenames, same prose — with every identifier it can recognise replaced by a
stable token. The agent reads the mirror. The table that maps tokens back to
values is written inside the compartment, so the thing that would undo the work
is exactly the thing the agent cannot open.

Tokens are an HMAC of the value under a key that also lives in the compartment,
which buys the property that makes a mirror usable at all: the same person is
the same token in every file, so the text still means something, and a mirror
regenerated tomorrow does not churn. Without the key the token is not reversible
by inspection, and without the table it is not reversible at all.

WHAT THIS IS AND IS NOT, because the words are legally load-bearing.

Under GDPR this produces **pseudonymised** data, not **anonymous** data. The
distinction is not pedantic: Recital 26 says pseudonymised data is still
personal data and the Regulation still applies to it in full, while anonymous
data falls outside the Regulation entirely — and the bar for anonymous is that
re-identification is impossible for anyone, by any means reasonably likely. A
reversal table exists here on purpose, so this is pseudonymisation by
definition, and calling it anonymisation would be false in the specific way that
gets people fined.

Pseudonymisation is worth doing on its own terms — Article 32(1)(a) names it as
a security measure, and it is the difference between an identifier reaching a
model's context window and not. It is not a certificate.

The built-in detector recognises structured identifiers: email, IBAN, Italian
codice fiscale and partita IVA, phone numbers, payment cards (Luhn-checked), IP
addresses and a set of API credential shapes. It does **not** recognise names,
addresses or anything else that needs to be understood rather than matched. For
those, plug in an engine that does — `--motore` takes a command, and
`rizzo-pii` (github.com/Rizzo-AI-Academy/rizzo-pii, local, reversible, built for
Italian legal text) or Microsoft Presidio are the obvious ones. A mirror built
without such an engine over prose containing names has not had the names taken
out, and `sincronizza` says so every time rather than letting it be forgotten.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are never mirrored: build output and dependency trees are
# noise, and .git holds the whole history of the original in objects this would
# not scan.
SALTA = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
         ".mypy_cache", ".pytest_cache", ".DS_Store", "dist", "build", ".next"}

LEGGIBILI = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml",
             ".toml", ".ini", ".cfg", ".conf", ".xml", ".html", ".htm", ".py", ".js", ".ts",
             ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".sql", ".rs", ".go", ".java", ".rb",
             ".php", ".c", ".h", ".cpp", ".swift", ".kt", ".log", ".env", ".tex", ".srt", ".vtt"}


def _luhn(numero: str) -> bool:
    cifre = [int(c) for c in numero if c.isdigit()]
    if len(cifre) < 13:
        return False
    somma, doppio = 0, False
    for c in reversed(cifre):
        if doppio:
            c *= 2
            if c > 9:
                c -= 9
        somma += c
        doppio = not doppio
    return somma % 10 == 0


@dataclass(frozen=True)
class Regola:
    tipo: str
    modello: re.Pattern
    convalida: object = None


# Ordered: the first rule to claim a span wins, so the specific ones come first.
# An IBAN that also looks like a long number must be an IBAN, not a card.
REGOLE: tuple[Regola, ...] = (
    Regola("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Regola("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b")),
    # Codice fiscale: six letters, two digits, a month letter, and so on. The
    # shape is distinctive enough that context is not needed.
    Regola("CF", re.compile(r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b")),
    Regola("CARTA", re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn),
    # Partita IVA is eleven bare digits, which collides with too much to match on
    # shape alone, so it is only taken when it is labelled as one.
    Regola("PIVA", re.compile(r"\b(?:P\.?\s?IVA|partita iva|VAT)\W{0,4}(IT)?(\d{11})\b", re.I)),
    # The trailing guard rejects a digit, and a period only when a digit follows
    # it — so a version string or a decimal is left alone while a phone number at
    # the end of a sentence is still caught. Guarding against a bare period
    # instead, which is the obvious way to write it, silently misses every phone
    # number that ends a sentence.
    Regola("TEL", re.compile(r"(?<![\d.])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{3}[ .-]?\d{2,4}(?!\d)(?!\.\d)")),
    Regola("IP", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    Regola("CHIAVE", re.compile(r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b")),
)


@dataclass
class Esito:
    file_letti: int = 0
    file_copiati: int = 0
    file_saltati: list[str] = field(default_factory=list)
    binari: list[str] = field(default_factory=list)
    conteggio: dict = field(default_factory=dict)
    nuovi_token: int = 0


def _e_testo(p: Path) -> bool:
    if p.suffix.lower() in LEGGIBILI:
        return True
    try:
        campione = p.open("rb").read(8192)
    except OSError:
        return False
    if b"\0" in campione:
        return False
    try:
        campione.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _gettone(chiave: bytes, tipo: str, valore: str) -> str:
    """A stable pseudonym. Deterministic under the key, so the same person is
    the same token in every file and a regenerated mirror does not churn."""
    impronta = hmac.new(chiave, f"{tipo}:{valore}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"[[{tipo}_{impronta}]]"


def _motore_esterno(comando: str, testo: str) -> list[tuple[int, int, str]]:
    """Run a pluggable detector. It receives the text on stdin and must print
    JSON: [{"start": int, "end": int, "type": str}, ...].

    Anything it prints is data. A detector that returns garbage produces no
    spans rather than an exception, because the caller has already been told
    that a mirror is only as good as its detector.
    """
    try:
        fuori = subprocess.run(
            comando, shell=True, input=testo.encode(), capture_output=True, timeout=120
        ).stdout.decode(errors="replace")
        dati = json.loads(fuori)
    except Exception:  # noqa: BLE001
        return []
    spans = []
    for d in dati if isinstance(dati, list) else []:
        try:
            spans.append((int(d["start"]), int(d["end"]), str(d.get("type", "PII"))))
        except Exception:  # noqa: BLE001
            continue
    return spans


def pseudonimizza(testo: str, chiave: bytes, tabella: dict, motore: str | None = None) -> tuple[str, dict]:
    """Return the text with identifiers replaced, and a count by type.

    Spans are collected first and applied right to left, so replacing one does
    not move the offsets of the next. Overlaps are resolved by taking the span
    that started earliest and, at equal start, the longest — which is what makes
    an IBAN win over the card-shaped digits inside it.
    """
    trovati: list[tuple[int, int, str, str]] = []

    for regola in REGOLE:
        for m in regola.modello.finditer(testo):
            # A rule with a capture group means the identifier is the group, not
            # the whole labelled match: `P.IVA 12345678901` yields the number.
            if regola.tipo == "PIVA" and m.lastindex:
                inizio, fine = m.span(m.lastindex)
            else:
                inizio, fine = m.span()
            valore = testo[inizio:fine]
            if regola.convalida and not regola.convalida(valore):
                continue
            trovati.append((inizio, fine, regola.tipo, valore))

    if motore:
        for inizio, fine, tipo in _motore_esterno(motore, testo):
            if 0 <= inizio < fine <= len(testo):
                trovati.append((inizio, fine, tipo, testo[inizio:fine]))

    trovati.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    scelti: list[tuple[int, int, str, str]] = []
    ultimo_fine = -1
    for inizio, fine, tipo, valore in trovati:
        if inizio >= ultimo_fine:
            scelti.append((inizio, fine, tipo, valore))
            ultimo_fine = fine

    conteggio: dict = {}
    for inizio, fine, tipo, valore in reversed(scelti):
        g = _gettone(chiave, tipo, valore)
        tabella[g] = {"tipo": tipo, "valore": valore}
        testo = testo[:inizio] + g + testo[fine:]
        conteggio[tipo] = conteggio.get(tipo, 0) + 1

    return testo, conteggio


def rispecchia(
    sorgente: Path,
    destinazione: Path,
    chiave: bytes,
    tabella: dict,
    *,
    motore: str | None = None,
    copia_binari: bool = False,
) -> Esito:
    """Build or refresh the mirror.

    Files that cannot be read as text are NOT copied unless asked for. A PDF, a
    spreadsheet or an image can hold every identifier in the tree and none of it
    would be scanned, so copying one into a directory described as safe to read
    is the failure this refuses to make quietly. They are listed instead.
    """
    esito = Esito()
    sorgente = sorgente.resolve()
    destinazione = destinazione.resolve()
    if destinazione == sorgente or destinazione.is_relative_to(sorgente):
        raise ValueError("the mirror cannot live inside what it mirrors")

    destinazione.mkdir(parents=True, exist_ok=True)

    for radice, cartelle, file in os.walk(sorgente):
        cartelle[:] = [c for c in cartelle if c not in SALTA and not c.startswith(".")]
        rel = Path(radice).relative_to(sorgente)
        (destinazione / rel).mkdir(parents=True, exist_ok=True)

        for nome in file:
            if nome in SALTA or nome.startswith("."):
                continue
            origine = Path(radice) / nome
            arrivo = destinazione / rel / nome
            if origine.is_symlink() or not origine.is_file():
                continue

            if not _e_testo(origine):
                esito.binari.append(str(origine.relative_to(sorgente)))
                if copia_binari:
                    shutil.copy2(origine, arrivo)
                    esito.file_copiati += 1
                continue

            try:
                testo = origine.read_text(errors="replace")
            except OSError:
                esito.file_saltati.append(str(origine.relative_to(sorgente)))
                continue

            esito.file_letti += 1
            prima = len(tabella)
            pulito, conteggio = pseudonimizza(testo, chiave, tabella, motore)
            esito.nuovi_token += len(tabella) - prima
            for tipo, n in conteggio.items():
                esito.conteggio[tipo] = esito.conteggio.get(tipo, 0) + n
            arrivo.write_text(pulito)
            esito.file_copiati += 1

    return esito
