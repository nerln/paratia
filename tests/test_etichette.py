"""What a label does and, more usefully, what it does not.

The last two tests are the ones worth keeping: they pin the claim that this
module is a plan and not a boundary, so that a later change which quietly turns
labels into an enforcement path has to delete a test that says out loud why it
should not.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from argparse import Namespace
from pathlib import Path

import pytest

QUI = Path(__file__).resolve().parent.parent


def carica_modulo(nome: str, casa: Path):
    """Import with PARATIA_HOME already pointed at a tmpdir, since the module
    reads it at import time."""
    import os
    os.environ["PARATIA_HOME"] = str(casa)
    spec = importlib.util.spec_from_file_location(nome, QUI / f"{nome}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[nome] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def E(tmp_path, monkeypatch):
    monkeypatch.setenv("PARATIA_HOME", str(tmp_path / "casa"))
    return carica_modulo("etichette", tmp_path / "casa")


@pytest.fixture()
def P(E, tmp_path, monkeypatch):
    p = carica_modulo("paratia", E.CASA)
    monte = tmp_path / "volume"
    monte.mkdir()
    monkeypatch.setattr(p, "MONTAGGIO", monte)
    monkeypatch.setattr(p, "aperto", lambda: True)
    monkeypatch.setattr(p, "_etichette", lambda: E)
    monkeypatch.setattr(p, "_zone_registro", lambda: {})
    monkeypatch.setattr(p, "_sincronizzato", lambda _p: False)
    return p


@pytest.fixture()
def albero(tmp_path):
    r = tmp_path / "albero"
    (r / "contratti").mkdir(parents=True)
    (r / "contratti" / "affitto.pdf").write_bytes(b"x" * 100)
    (r / "contratti" / "pubblico").mkdir()
    (r / "contratti" / "pubblico" / "nota.md").write_text("ciao")
    (r / "codice").mkdir()
    (r / "codice" / "main.py").write_text("print(1)\n")
    return r


# ------------------------------------------------------------- the basics


def test_segna_e_rilegge(E, albero):
    E.segna(albero / "contratti", "riservato")
    voci = E.elenco()
    assert len(voci) == 1
    assert voci[0]["etichetta"] == "riservato"
    assert voci[0]["esiste"] is True


def test_il_vocabolario_e_chiuso(E, albero):
    for cattiva in ("segreto", "RISERVATO", "zona:", "zona:/x", "", "zona:.x"):
        with pytest.raises(E.Rifiuto):
            E.segna(albero, cattiva)
    E.segna(albero, "zona:lavoro")  # this one is fine


def test_etichettare_un_percorso_assente_e_un_errore(E, tmp_path):
    with pytest.raises(E.Rifiuto):
        E.segna(tmp_path / "non-esiste", "riservato")


def test_una_seconda_etichetta_sostituisce_la_prima(E, albero):
    E.segna(albero, "riservato")
    E.segna(albero, "pubblico")
    assert len(E.elenco()) == 1
    assert E.elenco()[0]["etichetta"] == "pubblico"


def test_togli(E, albero):
    E.segna(albero, "riservato")
    assert E.togli(albero) is True
    assert E.togli(albero) is False
    assert E.elenco() == []


# --------------------------------------------------------- the inheritance


def test_eredita_dal_genitore_piu_vicino(E, albero):
    E.segna(albero / "contratti", "riservato")
    etichetta, da = E.risolvi(albero / "contratti" / "affitto.pdf")
    assert etichetta == "riservato"
    assert da == str((albero / "contratti").resolve())


def test_il_figlio_piu_vicino_vince(E, albero):
    E.segna(albero / "contratti", "riservato")
    E.segna(albero / "contratti" / "pubblico", "pubblico")
    dentro = albero / "contratti" / "pubblico" / "nota.md"
    assert E.risolvi(dentro)[0] == "pubblico"
    assert E.risolvi(albero / "contratti" / "affitto.pdf")[0] == "riservato"


def test_senza_antenati_nessuna_etichetta(E, albero):
    assert E.risolvi(albero / "codice" / "main.py") == (None, None)


# --------------------------------------------------------------- the listing


def test_sfoglia_marca_l_ereditarieta(E, albero):
    E.segna(albero / "contratti", "riservato")
    d = E.sfoglia(albero / "contratti")
    per_nome = {f["nome"]: f for f in d["figli"]}
    assert per_nome["affitto.pdf"]["etichetta"] == "riservato"
    assert per_nome["affitto.pdf"]["ereditata"] is True
    assert d["etichetta"] == "riservato"
    assert d["ereditata"] is False


def test_sfoglia_non_restituisce_mai_il_contenuto(E, albero):
    """The finder shows names, sizes and labels. If a future change starts
    shipping bytes, this fails, and it should: a tool that reads your files to
    help you decide which files should be unreadable has no answer for why."""
    d = E.sfoglia(albero / "codice")
    testo = json.dumps(d)
    assert "print(1)" not in testo
    campi = set(d["figli"][0])
    assert campi == {"nome", "percorso", "cartella", "collegamento",
                     "peso", "etichetta", "ereditata", "da"}


def test_i_nascosti_sono_esclusi_di_default(E, tmp_path):
    r = tmp_path / "d"
    r.mkdir()
    (r / ".env").write_text("K=1")
    (r / "letto.txt").write_text("x")
    assert [f["nome"] for f in E.sfoglia(r)["figli"]] == ["letto.txt"]
    assert len(E.sfoglia(r, mostra_nascosti=True)["figli"]) == 2


# ------------------------------------------------------------------ the plan


def test_il_piano_ignora_pubblico_e_conta_il_resto(E, albero):
    E.segna(albero / "contratti", "riservato")
    E.segna(albero / "codice", "pubblico")
    p = E.piano()
    assert [m["percorso"] for m in p["mosse"]] == [str((albero / "contratti").resolve())]
    assert p["mosse"][0]["destinazione"] == "compartment"
    assert p["byte_totali"] > 0


def test_il_piano_non_conta_il_ritaglio_pubblico(E, albero):
    """The bug this pins: a `pubblico` folder inside a `riservato` one is a
    person saying *not that part*. A plan that counted it, and an `applica` that
    copied it, would move bytes into the compartment that were explicitly
    excluded — the one failure this whole tool exists to avoid."""
    E.segna(albero / "contratti", "riservato")
    E.segna(albero / "contratti" / "pubblico", "pubblico")
    m = [x for x in E.piano()["mosse"] if x["etichetta"] == "riservato"][0]
    assert m["file"] == 1                      # affitto.pdf only, not nota.md
    assert m["byte"] == 100
    assert m["esclusi"] == [str((albero / "contratti" / "pubblico").resolve())]


def test_il_ritaglio_vale_anche_per_una_sottocartella_con_la_stessa_etichetta(E, albero):
    """Same label below is still carved out, because it carries its own move and
    copying it under both would put the bytes down twice."""
    E.segna(albero / "contratti", "riservato")
    E.segna(albero / "contratti" / "pubblico", "riservato")
    mosse = {x["percorso"]: x for x in E.piano()["mosse"]}
    padre = mosse[str((albero / "contratti").resolve())]
    assert padre["file"] == 1
    assert len(mosse) == 2


def test_il_piano_indirizza_alla_zona_giusta(E, albero):
    E.segna(albero / "codice", "zona:lavoro")
    assert E.piano()["mosse"][0]["destinazione"] == "zone lavoro"


def test_il_piano_segnala_i_percorsi_spariti(E, albero, tmp_path):
    d = tmp_path / "sparisce"
    d.mkdir()
    E.segna(d, "riservato")
    d.rmdir()
    p = E.piano()
    assert p["mosse"] == []
    assert p["problemi"][0]["perche"] == "the path is gone"


def test_avvisa_su_un_albero_troppo_grosso_per_il_compartimento(E, tmp_path, monkeypatch):
    d = tmp_path / "grosso"
    d.mkdir()
    (d / "f").write_bytes(b"x")
    E.segna(d, "riservato")
    monkeypatch.setattr(E, "_dimensione", lambda p, limite=20000, esclusi=None: (3 * 1024**3, 1, False))
    assert "belongs in a zone" in E.piano()["mosse"][0]["avviso"]


def test_avvisa_su_una_cartella_sincronizzata(E, albero):
    E.segna(albero / "contratti", "riservato")
    p = E.piano(sincronizzato=lambda _p: True)
    assert "cloud-synced" in p["mosse"][0]["avviso"]


# ------------------------------------------- the two that pin the honest limit


def test_l_archivio_e_un_file_normale_scrivibile(E, albero, tmp_path):
    """Not an accident and not a bug. If this ever fails because the store was
    moved somewhere privileged, the docs claiming labels are only a plan have to
    change in the same commit."""
    E.segna(albero, "riservato")
    assert E.ARCHIVIO.is_file()
    d = json.loads(E.ARCHIVIO.read_text())
    d["voci"] = {}
    E.ARCHIVIO.write_text(json.dumps(d))
    assert E.elenco() == []


def test_etichettare_non_sposta_nulla(E, albero):
    """The label names bytes; it never touches them. `applica` is the only verb
    in this system that moves anything, and it is a separate word on purpose."""
    prima = sorted(p.relative_to(albero).as_posix() for p in albero.rglob("*"))
    E.segna(albero / "contratti", "riservato")
    E.segna(albero / "codice", "zona:lavoro")
    dopo = sorted(p.relative_to(albero).as_posix() for p in albero.rglob("*"))
    assert prima == dopo


def test_un_archivio_illeggibile_e_un_rifiuto_non_un_default(E, albero):
    E.segna(albero, "riservato")
    E.ARCHIVIO.write_text("{ not json")
    with pytest.raises(E.Rifiuto):
        E.elenco()


@pytest.mark.skipif(shutil.which("rsync") is None, reason="rsync is required for applying labels")
@pytest.mark.parametrize("esclusa, vicina", [
    ("public[1]", "public1"),
    ("public*", "public-copy"),
    ("public?", "public1"),
    (r"public\?", r"public\a"),
    (r"public\one", "publicone"),
])
def test_applica_esclude_percorsi_letterali_non_glob(E, P, tmp_path, esclusa, vicina):
    origine = tmp_path / "documenti"
    origine.mkdir()
    (origine / "privato.txt").write_text("privato")
    for nome in (esclusa, vicina):
        (origine / nome).mkdir()
        (origine / nome / "nota.txt").write_text(nome)
    E.segna(origine, "riservato")
    E.segna(origine / esclusa, "pubblico")

    assert P.cmd_etichetta_applica(Namespace(esegui=True, sovrascrivi=False)) == 0
    destinazione = P.MONTAGGIO / origine.name
    assert (destinazione / "privato.txt").read_text() == "privato"
    assert not (destinazione / esclusa).exists()
    assert (destinazione / vicina / "nota.txt").read_text() == vicina
    assert (origine / esclusa / "nota.txt").read_text() == esclusa


@pytest.mark.parametrize("manca", [False, True])
@pytest.mark.parametrize("sovrascrivi", [False, True])
def test_applica_rifiuta_destinazioni_symlink_anche_dangling(
    E, P, tmp_path, monkeypatch, capsys, manca, sovrascrivi,
):
    origine = tmp_path / "documenti"
    origine.mkdir()
    (origine / "privato.txt").write_text("privato")
    E.segna(origine, "riservato")
    fuori = tmp_path / "fuori-dal-volume"
    if not manca:
        fuori.mkdir()
        (fuori / "esistente.txt").write_text("intatto")
    destinazione = P.MONTAGGIO / origine.name
    destinazione.symlink_to(fuori, target_is_directory=True)

    def non_copiare(*_args, **_kwargs):
        pytest.fail("rsync must not run when the destination is a symlink")

    monkeypatch.setattr(P, "_corri", non_copiare)
    assert P.cmd_etichetta_applica(Namespace(esegui=True, sovrascrivi=sovrascrivi)) == 1
    assert "symlink, skipped:" in capsys.readouterr().err
    assert destinazione.is_symlink()
    assert not (fuori / "privato.txt").exists()
    if manca:
        assert not fuori.exists()
    else:
        assert (fuori / "esistente.txt").read_text() == "intatto"
