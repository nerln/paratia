"""paranco's routes are read and never written; --esegui applies only a person's choice."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def ambiente(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    home = base / "casa"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PARATIA_HOME", str(home / "stato"))
    p = load("rotte_paranco_cli", ROOT / "paratia.py")
    r = load("rotte_paranco_registro", ROOT / "registro.py")
    r.SYSTEM = base / "kernel"
    r.SUPPORT = base / "support"
    stato = {"running": False, "healthy": False, "needs_fda": False, "schema_supported": True, "watched_ids": []}
    monkeypatch.setattr(r, "stato", lambda: dict(stato))
    # The test runner may itself run inside an agent session: a human run must not look like one.
    for nome in p.SPIE_AGENTE:
        monkeypatch.delenv(nome, raising=False)
    return SimpleNamespace(base=base, home=home, p=p, r=r)


def run(amb, *argomenti):
    args = amb.p.costruisci().parse_args(["registro", "rotte-paranco", *argomenti])
    return amb.p._esegui_registro(amb.r, args)


def esegui(amb, capsys, *argomenti):
    assert run(amb, *argomenti) == 0
    return json.loads(capsys.readouterr().out)


def file_rotte(amb):
    return amb.home / "Library" / "Application Support" / "paranco" / "routes.json"


def cartella_paranco(amb):
    return amb.home / "Library" / "Application Support" / "paranco"


def scrivi_rotte(amb, dati):
    f = file_rotte(amb)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(dati if isinstance(dati, str) else json.dumps(dati))
    return f


def rotta(nome, cartella, abilitata=True, fonte="memo-in-scriba", **extra):
    return {"id": nome, "name": nome, "sourceID": fonte, "destination": Path(cartella).as_uri(),
            "extensions": [], "enabled": abilitata, **extra}


def per_percorso(out):
    return {riga["percorso"]: riga for riga in out["proposte"]}


def test_file_assente_non_e_un_errore(ambiente, capsys):
    out = esegui(ambiente, capsys)
    assert out["paranco_presente"] is False
    assert out["proposte"] == []


def test_piano_con_rotta_disabilitata_e_cartella_di_paranco(ambiente, capsys):
    memo = ambiente.home / "Memo"
    memo.mkdir()
    spenta = ambiente.home / "Spenta"
    spenta.mkdir()
    f = scrivi_rotte(ambiente, [rotta("memo", memo), rotta("spenta", spenta, abilitata=False)])
    prima = f.read_bytes()
    out = esegui(ambiente, capsys)
    righe = per_percorso(out)
    assert righe[str(memo)]["stato"] == "da-aggiungere" and righe[str(memo)]["nome"] == "memo"
    assert righe[str(spenta)]["stato"] == "disabilitata"
    assert righe[str(cartella_paranco(ambiente))]["stato"] == "da-aggiungere"
    assert righe[str(cartella_paranco(ambiente))]["nome"] == "paranco: rotte e log"
    assert out["riepilogo"]["da-aggiungere"] == 2 and out["riepilogo"]["disabilitata"] == 1
    assert "applicate" not in out
    assert f.read_bytes() == prima


def test_destinazioni_rifiutate_con_motivo_fisso(ambiente, capsys):
    casa = ambiente.home
    fuori = ambiente.base / "fuori"
    fuori.mkdir()
    reale = casa / "reale"
    reale.mkdir()
    collegamento = casa / "collegamento"
    collegamento.symlink_to(reale)
    scrivi_rotte(ambiente, [
        rotta("fuori", fuori),
        rotta("collegamento", collegamento),
        rotta("manca", casa / "manca"),
        rotta("casa", casa),
        {"name": "dotdot", "enabled": True, "destination": casa.as_uri() + "/../x", "sourceID": "s"},
        {"name": "web", "enabled": True, "destination": "https://example.com/x", "sourceID": "s"},
    ])
    out = esegui(ambiente, capsys)
    righe = {riga["nome"]: riga for riga in out["proposte"]}
    assert all(righe[n]["stato"] == "rifiutata" for n in ("fuori", "collegamento", "manca", "casa", "dotdot", "web"))
    assert "fuori dalla tua cartella utente" in righe["fuori"]["motivo"]
    assert "collegamento simbolico" in righe["collegamento"]["motivo"]
    assert "non esiste ancora" in righe["manca"]["motivo"] and "paranco la crea" in righe["manca"]["motivo"]
    assert "cartella utente intera" in righe["casa"]["motivo"]
    assert "destinazione non valida" in righe["dotdot"]["motivo"]
    assert "destinazione non valida" in righe["web"]["motivo"]
    assert righe["web"]["percorso"] is None


def test_nome_ripulito_e_troncato(ambiente, capsys):
    cartella = ambiente.home / "ok"
    cartella.mkdir()
    scrivi_rotte(ambiente, [rotta("memo\n\x1b[31mX\u2028y" + "z" * 100, cartella, fonte="x\u0085y")])
    out = esegui(ambiente, capsys)
    riga = per_percorso(out)[str(cartella)]
    nome = riga["nome"]
    assert len(nome) <= 64
    assert nome.startswith("memo  [31mX y")
    assert not any(ord(c) < 32 or 127 <= ord(c) < 160 or c in "\u2028\u2029" for c in nome)
    assert riga["sorgente"] == "x y"


def test_file_malformato_o_non_lista_non_produce_proposte(ambiente, capsys):
    for contenuto in ("{non json", {"nome": "una mappa"}, "[" * 100000 + "]" * 100000):
        scrivi_rotte(ambiente, contenuto)
        out = esegui(ambiente, capsys)
        assert out["paranco_presente"] is True and out["proposte"] == []
        assert "non è leggibile" in out["messaggio"]


def test_voci_non_dizionario_e_limite_di_sedici(ambiente, capsys):
    cartelle = [ambiente.home / f"c{i:02d}" for i in range(17)]
    for c in cartelle:
        c.mkdir()
    scrivi_rotte(ambiente, ["stringa", 3, *[rotta(f"r{i:02d}", c) for i, c in enumerate(cartelle)]])
    out = esegui(ambiente, capsys)
    rotte = [riga for riga in out["proposte"] if riga["nome"].startswith("r")]
    assert len(rotte) == 16
    assert out["riepilogo"]["voci_ignorate"] == 3  # two non-objects and the seventeenth route


def test_routes_come_collegamento_simbolico_e_rifiutato(ambiente, capsys):
    reale = ambiente.home / "altro.json"
    reale.write_text(json.dumps([rotta("x", ambiente.home)]))
    file_rotte(ambiente).parent.mkdir(parents=True)
    file_rotte(ambiente).symlink_to(reale)
    prima = reale.read_bytes()
    out = esegui(ambiente, capsys)
    assert out["paranco_presente"] is True and out["proposte"] == []
    assert reale.read_bytes() == prima


def test_routes_resta_identico_dopo_ogni_esecuzione(ambiente, capsys):
    cartella = ambiente.home / "Memo"
    cartella.mkdir()
    f = scrivi_rotte(ambiente, [rotta("memo", cartella)])
    prima = f.read_bytes()
    esegui(ambiente, capsys)
    esegui(ambiente, capsys, "--esegui")
    esegui(ambiente, capsys, "--esegui")
    assert f.read_bytes() == prima


def test_esegui_configura_solo_le_da_aggiungere_senza_cambiare_i_nomi(ambiente, capsys):
    memo = ambiente.home / "Memo"
    memo.mkdir()
    spenta = ambiente.home / "Spenta"
    spenta.mkdir()
    f = scrivi_rotte(ambiente, [rotta("memo", memo), rotta("spenta", spenta, abilitata=False)])
    prima = f.read_bytes()
    out1 = esegui(ambiente, capsys, "--esegui")
    esiti = {a["percorso"]: a["esito"] for a in out1["applicate"]}
    assert esiti == {str(memo): "configurata", str(cartella_paranco(ambiente)): "configurata"}
    sorveglianza = ambiente.r.CASA / "registro" / "sorveglianza.json"
    voci = ambiente.r.leggi_sorveglianza(sorveglianza, os.getuid())
    assert {v["origine"]: v["nome"] for v in voci} == {
        str(memo): "memo", str(cartella_paranco(ambiente)): "paranco: rotte e log"}
    dopo_prima = sorveglianza.read_bytes()
    out2 = esegui(ambiente, capsys, "--esegui")
    assert out2["applicate"] == []
    assert per_percorso(out2)[str(memo)]["stato"] == "gia-sorvegliata"
    # A folder already watched is not proposed again.
    assert str(cartella_paranco(ambiente)) not in per_percorso(out2)
    assert sorveglianza.read_bytes() == dopo_prima
    assert f.read_bytes() == prima


def test_cartella_protetta_e_conflitto_anche_da_chiusa(ambiente, capsys):
    casa = ambiente.home
    protetta = casa / "Lavoro"
    protetta.mkdir()
    dentro = protetta / "sotto"
    dentro.mkdir()
    altra = casa / "Altra"
    altra.mkdir()
    libera = casa / "Libera"
    libera.mkdir()
    id_valido = "a" * 32
    cartelle = {"versione": 1, "cartelle": {
        id_valido: {"id": id_valido, "nome": "Lavoro", "origine": str(protetta), "montaggio": str(protetta),
                    "bundle": str(casa / f"Lavoro-{id_valido}.sparsebundle")},
        # Rejected by validation, but still a folder that must not be watched.
        "zz": {"id": "zz", "nome": "Altra", "origine": str(altra), "montaggio": str(altra)},
    }}
    (ambiente.r.CASA).mkdir(parents=True, exist_ok=True)
    (ambiente.r.CASA / "cartelle.json").write_text(json.dumps(cartelle))
    scrivi_rotte(ambiente, [rotta("protetta", protetta), rotta("dentro", dentro),
                            rotta("altra", altra), rotta("libera", libera)])
    out = esegui(ambiente, capsys)
    righe = {riga["nome"]: riga for riga in out["proposte"]}
    assert righe["protetta"]["stato"] == "conflitto" and righe["dentro"]["stato"] == "conflitto"
    assert righe["altra"]["stato"] == "conflitto"
    assert "da chiusa" in righe["protetta"]["motivo"].lower()
    assert righe["libera"]["stato"] == "da-aggiungere"
    out = esegui(ambiente, capsys, "--esegui")
    applicate = {a["percorso"] for a in out["applicate"]}
    assert str(libera) in applicate
    assert not applicate & {str(protetta), str(dentro), str(altra)}


def test_punto_di_montaggio_dentro_casa_e_conflitto(ambiente, capsys, monkeypatch):
    montaggio = ambiente.home / "Volume"
    montaggio.mkdir()
    figlio = montaggio / "dentro"
    figlio.mkdir()
    monkeypatch.setattr(os.path, "ismount", lambda percorso: str(percorso) == str(montaggio))
    scrivi_rotte(ambiente, [rotta("figlio", figlio)])
    out = esegui(ambiente, capsys)
    riga = per_percorso(out)[str(figlio)]
    assert riga["stato"] == "conflitto"
    assert "punto di montaggio" in riga["motivo"]


@pytest.mark.parametrize("ordine", ["abilitata_prima", "disabilitata_prima"])
def test_due_rotte_stessa_destinazione_una_sola_proposta(ambiente, capsys, ordine):
    doppio = ambiente.home / "Doppio"
    doppio.mkdir()
    accesa, spenta = rotta("accesa", doppio), rotta("spenta", doppio, abilitata=False)
    scrivi_rotte(ambiente, [accesa, spenta] if ordine == "abilitata_prima" else [spenta, accesa])
    out = esegui(ambiente, capsys)
    righe = [riga for riga in out["proposte"] if riga["percorso"] == str(doppio)]
    assert len(righe) == 1
    assert righe[0]["stato"] == "da-aggiungere" and righe[0]["nome"] == "accesa"


def test_esegui_in_sessione_agente_e_rifiutato_senza_scrivere(ambiente, capsys, monkeypatch):
    cartella = ambiente.home / "Agente"
    cartella.mkdir()
    scrivi_rotte(ambiente, [rotta("a", cartella)])
    monkeypatch.setenv("CLAUDECODE", "1")
    out = esegui(ambiente, capsys)
    assert per_percorso(out)[str(cartella)]["stato"] == "da-aggiungere"
    with pytest.raises(ambiente.p.Rifiuto):
        run(ambiente, "--esegui")
    assert not (ambiente.r.CASA / "registro" / "sorveglianza.json").exists()


def istantanea(percorsi):
    """Bytes of each file, or None when it is missing: equal before and after means nothing was written."""
    return {str(p): p.read_bytes() if p.exists() else None for p in percorsi}


@pytest.mark.parametrize("controllo", ["\u202e", "\u2066", "\u200f", "\u061c", "\u200b", "\u2028", "\u2029", "\x85"])
def test_controlli_di_formato_nel_nome_e_nella_sorgente_sono_sostituiti(ambiente, capsys, controllo):
    cartella = ambiente.home / "Bidi"
    cartella.mkdir()
    scrivi_rotte(ambiente, [rotta(f"a{controllo}b", cartella, fonte=f"x{controllo}y")])
    riga = per_percorso(esegui(ambiente, capsys))[str(cartella)]
    assert riga["nome"] == "a b"
    assert riga["sorgente"] == "x y"


@pytest.mark.parametrize("danno", ["rotto", "gruppo", "annidato"])
@pytest.mark.parametrize("file_config", ["cartelle", "sorveglianza"])
def test_configurazione_illeggibile_ferma_il_comando_senza_scrivere(ambiente, capsys, file_config, danno):
    stato = ambiente.r.CASA
    if file_config == "cartelle":
        percorso = stato / "cartelle.json"
        valido = {"versione": 1, "cartelle": {}}
    else:
        percorso = stato / "registro" / "sorveglianza.json"
        valido = {"versione": 1, "percorsi": {}}
    percorso.parent.mkdir(parents=True, exist_ok=True)
    if danno == "gruppo":
        percorso.write_text(json.dumps(valido))
        percorso.chmod(0o664)
    else:
        percorso.write_text("{non json" if danno == "rotto" else "[" * 100000 + "]" * 100000)
    memo = ambiente.home / "Memo"
    memo.mkdir()
    scrivi_rotte(ambiente, [rotta("memo", memo)])
    tracciati = [stato / "cartelle.json", stato / "registro" / "sorveglianza.json"]
    prima = istantanea(tracciati)
    with pytest.raises(ambiente.p.Rifiuto):
        run(ambiente)
    with pytest.raises(ambiente.p.Rifiuto):
        run(ambiente, "--esegui")
    assert istantanea(tracciati) == prima
    assert capsys.readouterr().out == ""
    assert ambiente.p.main(["registro", "rotte-paranco"]) == 2
    assert capsys.readouterr().out == ""


def test_surrogati_isolati_non_fermano_il_comando(ambiente, capsys):
    """A lone surrogate from JSON is cleaned in names, and a destination with one is refused."""
    cartella = ambiente.home / "Surrogato"
    cartella.mkdir()
    buono = ambiente.home / "Buono"
    buono.mkdir()
    scrivi_rotte(ambiente, [
        rotta("bad\ud800name", cartella, fonte="src\udfffx"),
        rotta("buona", buono),
        {"id": "d", "name": "dest", "sourceID": "s", "enabled": True, "destination": buono.as_uri() + "\ud800"},
    ])
    assert run(ambiente) == 0
    testo = capsys.readouterr().out
    testo.encode("utf-8")  # the terminal must be able to print the answer
    out = json.loads(testo)
    righe = per_percorso(out)
    assert righe[str(cartella)]["nome"] == "bad name"
    assert righe[str(cartella)]["sorgente"] == "src x"
    assert righe[str(buono)]["stato"] == "da-aggiungere"
    rifiutate = [riga for riga in out["proposte"] if riga["stato"] == "rifiutata"]
    assert len(rifiutate) == 1 and rifiutate[0]["percorso"] is None and rifiutate[0]["nome"] == "dest"


@pytest.mark.skipif(os.geteuid() == 0, reason="root legge anche le cartelle chiuse")
def test_destinazione_sotto_cartella_senza_permessi_e_rifiutata(ambiente, capsys):
    chiusa = ambiente.home / "Chiusa"
    chiusa.mkdir()
    dentro = chiusa / "dentro"
    dentro.mkdir()
    libera = ambiente.home / "Libera"
    libera.mkdir()
    scrivi_rotte(ambiente, [rotta("dentro", dentro), rotta("libera", libera)])
    chiusa.chmod(0o000)
    try:
        out = esegui(ambiente, capsys)
    finally:
        chiusa.chmod(0o755)
    righe = {riga["nome"]: riga for riga in out["proposte"]}
    assert righe["dentro"]["stato"] == "rifiutata"
    assert "permessi insufficienti" in righe["dentro"]["motivo"]
    assert righe["libera"]["stato"] == "da-aggiungere"
    assert out["riepilogo"]["rifiutata"] == 1


def test_nome_di_ripiego_dalla_cartella_e_ripulito_e_il_percorso_si_mostra_escapato(ambiente, capsys):
    cartella = ambiente.home / "Dir\u202ex\u2028y\x1bz"
    cartella.mkdir()
    scrivi_rotte(ambiente, [rotta("", cartella)])
    assert run(ambiente) == 0
    testo = capsys.readouterr().out
    assert "\u202e" not in testo and "\u2028" not in testo and "\x1b" not in testo
    out = json.loads(testo)
    riga = out["proposte"][0]
    assert riga["nome"] == "Dir x y z"
    assert riga["percorso"] == str(ambiente.home) + "/Dir\\u202ex\\u2028y\\u001bz"
    # The configured folder keeps its real name; only the printed path is escaped.
    assert run(ambiente, "--esegui") == 0
    testo = capsys.readouterr().out
    assert "\u202e" not in testo
    sorveglianza = ambiente.r.CASA / "registro" / "sorveglianza.json"
    voci = ambiente.r.leggi_sorveglianza(sorveglianza, os.getuid())
    assert {v["origine"]: v["nome"] for v in voci}[str(cartella)] == "Dir x y z"


def test_conflitto_ha_la_precedenza_sulla_convalida(ambiente, capsys, monkeypatch):
    """With the volume open, validation may refuse a protected folder: the reason stays 'conflitto'."""
    protetta = ambiente.home / "Lavoro"
    protetta.mkdir()
    id_valido = "b" * 32
    cartelle = {"versione": 1, "cartelle": {id_valido: {
        "id": id_valido, "nome": "Lavoro", "origine": str(protetta), "montaggio": str(protetta),
        "bundle": str(ambiente.home / "Lavoro.sparsebundle")}}}
    ambiente.r.CASA.mkdir(parents=True, exist_ok=True)
    (ambiente.r.CASA / "cartelle.json").write_text(json.dumps(cartelle))

    def convalida_rifiuta(*args, **kwargs):
        raise ValueError("convalida rifiutata")

    monkeypatch.setattr(ambiente.r, "_valida_sorveglianza", convalida_rifiuta)
    scrivi_rotte(ambiente, [rotta("protetta", protetta)])
    riga = per_percorso(esegui(ambiente, capsys))[str(protetta)]
    assert riga["stato"] == "conflitto"


def test_maiuscole_diverse_sono_la_stessa_cartella(ambiente, capsys):
    """APFS on the data volume ignores case: `lavoro` is the protected `Lavoro`."""
    casa = ambiente.home
    protetta = casa / "Lavoro"
    (protetta / "sotto").mkdir(parents=True)
    id_valido = "b" * 32
    cartelle = {"versione": 1, "cartelle": {id_valido: {
        "id": id_valido, "nome": "Lavoro", "origine": str(protetta), "montaggio": str(protetta),
        "bundle": str(casa / f"Lavoro-{id_valido}.sparsebundle")}}}
    ambiente.r.CASA.mkdir(parents=True, exist_ok=True)
    (ambiente.r.CASA / "cartelle.json").write_text(json.dumps(cartelle))
    memo = casa / "Memo"
    memo.mkdir()
    scrivi_rotte(ambiente, [rotta("minuscola", casa / "lavoro"), rotta("sotto", casa / "LAVORO" / "sotto"),
                            rotta("memo", memo), rotta("memo-bis", casa / "memo")])
    out = esegui(ambiente, capsys)
    righe = {riga["nome"]: riga for riga in out["proposte"]}
    assert righe["minuscola"]["stato"] == "conflitto" and righe["sotto"]["stato"] == "conflitto"
    # Two routes that differ only by case are one destination, so one proposal.
    assert sum(1 for r in out["proposte"] if (r["percorso"] or "").casefold() == str(memo).casefold()) == 1


def test_destinazione_dentro_library_e_rifiutata_ma_la_cartella_di_paranco_resta_proposta(ambiente, capsys):
    posta = ambiente.home / "Library" / "Mail"
    posta.mkdir(parents=True)
    scrivi_rotte(ambiente, [rotta("posta", posta)])
    out = esegui(ambiente, capsys)
    righe = per_percorso(out)
    assert righe[str(posta)]["stato"] == "rifiutata" and "~/Library" in righe[str(posta)]["motivo"]
    assert righe[str(cartella_paranco(ambiente))]["stato"] == "da-aggiungere"
