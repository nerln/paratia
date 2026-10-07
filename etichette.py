#!/usr/bin/env python3
"""Labels: a plan for what belongs behind a bulkhead. Not a bulkhead.

Read this paragraph before you rely on anything in this file. A label is a
sentence you wrote down about a path. It lives in `~/.paratia/etichette.json`,
which is a file in your home directory, owned by your uid, which is the uid the
agent runs as. **An agent can read this file and an agent can rewrite it.** It
stops nothing. If it were wired into the gate as a deny rule it would stop
nothing there either, for the reason `docs/architettura.md` spends a section on:
a rule about paths is a rule about spellings, and spellings are infinite.

So what is it for. Two things the rest of paratia does not do.

**It answers the question the compartment poses and does not help with.**
`paratia` gives you a volume whose contents no process can read while it is
locked. It does not tell you what should be in it. On a machine with 300k files
that is the entire difficulty, and it is a human judgement about content, made
once per path, that nothing can infer for you. A label records that judgement
where you can review it, sort it, and change your mind about it.

**It drives `applica`, which is where an actual guarantee shows up.** Labelling
`~/lavoro/contratti` as `riservato` protects nothing. Running `paratia etichetta
applica` moves those bytes into the compartment, and *then* the cipher protects
them — row 1 of the architecture table, not row 6. The label is the plan; the
move is the mechanism. Keeping those two words apart is the whole discipline
here, and the reason this module refuses to describe itself as protection.

Inheritance: a label on a folder applies to everything under it until a nearer
label says otherwise. That is what makes labelling a tree from a root tractable
instead of a per-file chore, and it is resolved at read time, never written down
per child, so moving a folder does not leave orphaned rules behind.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
ARCHIVIO = CASA / "etichette.json"
VERSIONE = 1

# The vocabulary is deliberately four words long. Every label a person invents
# beyond these is a distinction they will not remember in six months, and an
# unremembered distinction is worse than none: it makes `piano` unreadable and
# `applica` unsafe to run without reading every line.
#
#   riservato   bytes that should not be readable by this machine's session at
#               all. Goes into the compartment. Small things: keys, contracts,
#               the passport scan. Not a repository — see `zona`.
#   zona:<nome> work that the session must read to do its job, but that a second
#               local account, a stolen disk, or the cloud provider's copy
#               should not. Goes into the named encrypted zone.
#   pubblico    looked at, deliberately left where it is. Not the same as
#               unlabelled: it records that a human decided, which is what stops
#               the same folder being re-examined every review.
#   (assente)   nobody has looked yet. The default, and the one `piano` counts
#               loudest, because unreviewed is the state that actually hurts.
RISERVATO = "riservato"
PUBBLICO = "pubblico"
PREFISSO_ZONA = "zona:"


class Rifiuto(Exception):
    """Something was asked for that this module will not do."""


def _valida(etichetta: str) -> str:
    e = etichetta.strip()
    if e in (RISERVATO, PUBBLICO):
        return e
    if e.startswith(PREFISSO_ZONA):
        nome = e[len(PREFISSO_ZONA):]
        if not nome or "/" in nome or nome.startswith("."):
            raise Rifiuto(f"{etichetta!r} does not name a zone")
        return e
    raise Rifiuto(
        f"{etichetta!r} is not one of the four. Use {RISERVATO!r}, {PUBBLICO!r}, "
        f"or {PREFISSO_ZONA}<name>. The vocabulary is short on purpose."
    )


def _chiave(p: str | Path) -> str:
    """One spelling per path, so a second label on the same place replaces the
    first instead of sitting next to it and disagreeing with it."""
    return str(Path(p).expanduser().resolve())


# ------------------------------------------------------------------- storage


def carica() -> dict:
    if not ARCHIVIO.is_file():
        return {"versione": VERSIONE, "voci": {}}
    try:
        d = json.loads(ARCHIVIO.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise Rifiuto(f"{ARCHIVIO} is unreadable ({type(e).__name__}). Not guessing at it.") from e
    if not isinstance(d, dict) or "voci" not in d:
        raise Rifiuto(f"{ARCHIVIO} is not a label store")
    return d


def salva(d: dict) -> None:
    CASA.mkdir(parents=True, exist_ok=True)
    tmp = ARCHIVIO.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1, sort_keys=True))
    tmp.replace(ARCHIVIO)


# -------------------------------------------------------------------- verbs


def segna(percorso: str | Path, etichetta: str, nota: str = "") -> dict:
    e = _valida(etichetta)
    k = _chiave(percorso)
    if not Path(k).exists():
        raise Rifiuto(f"{k} does not exist. Labelling a path that is not there hides a typo.")
    d = carica()
    d["voci"][k] = {
        "etichetta": e,
        "quando": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "nota": nota,
    }
    salva(d)
    return {"percorso": k, "etichetta": e}


def togli(percorso: str | Path) -> bool:
    k = _chiave(percorso)
    d = carica()
    if k not in d["voci"]:
        return False
    del d["voci"][k]
    salva(d)
    return True


def elenco() -> list[dict]:
    d = carica()
    fuori = [
        {"percorso": k, **v, "esiste": Path(k).exists()}
        for k, v in d["voci"].items()
    ]
    fuori.sort(key=lambda r: r["percorso"])
    return fuori


def risolvi(percorso: str | Path, voci: dict | None = None) -> tuple[str | None, str | None]:
    """The label in force at a path, and the path it was inherited from.

    Nearest ancestor wins, so a `pubblico` on one subfolder carves an exception
    out of a `riservato` on its parent without needing a rule that says so.
    """
    if voci is None:
        voci = carica()["voci"]
    p = Path(_chiave(percorso))
    for candidato in [p, *p.parents]:
        s = str(candidato)
        if s in voci:
            return voci[s]["etichetta"], s
    return None, None


# --------------------------------------------------------------- the listing


def _peso(p: Path) -> int:
    try:
        if p.is_symlink():
            return 0
        if p.is_file():
            return p.stat().st_size
    except OSError:
        return 0
    return 0


def sfoglia(radice: str | Path, mostra_nascosti: bool = False) -> dict:
    """One directory, with the label in force on each entry.

    Names, sizes and labels only — never file contents. The finder is for
    deciding what goes behind the bulkhead, and a tool that reads your files to
    help you decide which files should be unreadable has argued itself out of
    existence. It also means the local server this feeds cannot be turned into
    a file-reading endpoint by anything that gets hold of its token.
    """
    r = Path(_chiave(radice))
    if not r.is_dir():
        raise Rifiuto(f"{r} is not a directory")

    voci = carica()["voci"]
    proprio, da_proprio = risolvi(r, voci)

    figli = []
    try:
        for e in sorted(r.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            if not mostra_nascosti and e.name.startswith("."):
                continue
            try:
                cartella = e.is_dir() and not e.is_symlink()
            except OSError:
                cartella = False
            etichetta, da = risolvi(e, voci)
            figli.append({
                "nome": e.name,
                "percorso": str(e),
                "cartella": cartella,
                "collegamento": e.is_symlink(),
                "peso": 0 if cartella else _peso(e),
                "etichetta": etichetta,
                "ereditata": bool(etichetta) and da != str(e),
                "da": da,
            })
    except PermissionError as exc:
        raise Rifiuto(f"{r} cannot be listed: {exc.strerror}") from exc

    return {
        "radice": str(r),
        "genitore": str(r.parent) if r.parent != r else None,
        "etichetta": proprio,
        "ereditata": bool(proprio) and da_proprio != str(r),
        "da": da_proprio,
        "figli": figli,
    }


# ----------------------------------------------------------------- the plan


def scavi(percorso: str, voci: dict) -> list[str]:
    """Labelled paths strictly under `percorso`.

    These are carve-outs, and both the size and the copy have to honour them.
    A `pubblico` folder inside a `riservato` one is a human saying *not that
    part*; a plan that quietly counted it, and an `applica` that quietly copied
    it into the compartment, would do the one thing this tool exists to prevent
    — put bytes somewhere the person did not agree to put them. The exclusion
    covers same-label descendants too, because those carry their own move and
    copying them twice is the other way to get this wrong.
    """
    base = percorso.rstrip(os.sep) + os.sep
    return sorted(k for k in voci if k != percorso and k.startswith(base))


def _dimensione(p: Path, limite: int = 20000, esclusi: list[str] | None = None) -> tuple[int, int, bool]:
    """Bytes and file count under a path, skipping carve-outs, giving up after
    `limite` files.

    Giving up loudly beats walking a 400k-file tree to produce a number nobody
    reads. The caller is told it was truncated so the plan can say so.
    """
    esclusi = esclusi or []
    if p.is_file():
        return _peso(p), 1, False

    def tagliato(q: str) -> bool:
        return any(q == e or q.startswith(e.rstrip(os.sep) + os.sep) for e in esclusi)

    byte = n = 0
    troncato = False
    for radice, cartelle, file in os.walk(p, onerror=lambda e: None):
        cartelle[:] = [
            c for c in cartelle
            if not Path(radice, c).is_symlink() and not tagliato(str(Path(radice, c)))
        ]
        for f in file:
            if tagliato(str(Path(radice, f))):
                continue
            n += 1
            if n > limite:
                troncato = True
                return byte, n, troncato
            byte += _peso(Path(radice, f))
    return byte, n, troncato


def piano(sincronizzato=None) -> dict:
    """What `applica` would do, and what it refuses to do.

    `sincronizzato` is injected rather than imported so this module stays
    testable without a cloud mount, and so paratia can pass its own detector.
    """
    voci = carica()["voci"]
    mosse, problemi = [], []

    for k, v in sorted(voci.items()):
        p = Path(k)
        e = v["etichetta"]
        if not p.exists():
            problemi.append({"percorso": k, "etichetta": e, "perche": "the path is gone"})
            continue
        if e == PUBBLICO:
            continue

        esclusi = scavi(k, voci)
        byte, n, troncato = _dimensione(p, esclusi=esclusi)
        voce = {
            "percorso": k,
            "etichetta": e,
            "byte": byte,
            "file": n,
            "troncato": troncato,
            "esclusi": esclusi,
            "destinazione": "compartment" if e == RISERVATO else f"zone {e[len(PREFISSO_ZONA):]}",
        }

        # A compartment is for keys and documents. Someone who labels a 40 GB
        # dataset `riservato` has reached for the wrong word, and finding that
        # out during a copy is worse than finding it out here.
        if e == RISERVATO and byte > 2 * 1024**3:
            voce["avviso"] = (
                "over 2 GB. The compartment is a sparsebundle you unlock by hand; "
                f"a tree this size belongs in a zone. Use {PREFISSO_ZONA}<name>."
            )
        if e == RISERVATO and n > 5000:
            voce["avviso"] = (
                f"{n} files. The compartment is for the handful of things no session "
                "may read, not for a tree. Consider a zone."
            )
        if sincronizzato is not None:
            try:
                if sincronizzato(p):
                    voce["avviso"] = (
                        "this path is inside a cloud-synced folder. Moving it removes "
                        "the local copy; the provider's copies of earlier versions are "
                        "not yours to delete and are not covered by this."
                    )
            except Exception:  # noqa: BLE001
                pass
        mosse.append(voce)

    return {
        "mosse": mosse,
        "problemi": problemi,
        "byte_totali": sum(m["byte"] for m in mosse),
    }


def conta() -> dict:
    voci = carica()["voci"]
    c = {RISERVATO: 0, PUBBLICO: 0, "zone": 0}
    for v in voci.values():
        e = v["etichetta"]
        if e.startswith(PREFISSO_ZONA):
            c["zone"] += 1
        elif e in c:
            c[e] += 1
    return c
