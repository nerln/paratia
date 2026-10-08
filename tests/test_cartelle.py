"""Folder migration and recovery with fake disk images and real metadata copies."""

from __future__ import annotations

import importlib.util
import json
import os
import plistlib
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"fixture-only-passphrase-123"


class Dischi:
    def __init__(self, C):
        self.C = C
        self.montati = {}
        self.chiavi = {}
        self.chiamate = []
        self.conta = Counter()
        self.fallisce = None
        self.interno = False
        self.corrompi_al_mount = None
        self.after_copy = None
        self.timer = []
        self.corri_vero = C._corri

    def corri(self, argv, passphrase=None):
        self.chiamate.append((list(argv), passphrase))
        verbo = argv[1] if argv[0] == self.C.HDIUTIL else Path(argv[0]).name
        self.conta[verbo] += 1
        if self.fallisce == (verbo, self.conta[verbo]):
            return subprocess.CompletedProcess(argv, 1, KEY, KEY)
        if argv[0] == self.C.DISKUTIL:
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({
                "Internal": self.interno, "VirtualOrPhysical": "Physical",
            }), b"")
        if argv[0] == self.C.DITTO:
            r = self.corri_vero(argv)
            if self.after_copy:
                self.after_copy()
            return r
        if verbo == "create":
            bundle = Path(argv[-1])
            bundle.mkdir()
            (bundle / "storage").mkdir()
            self.chiavi[str(bundle)] = passphrase
        elif verbo == "attach":
            bundle, monte = Path(argv[2]), Path(argv[argv.index("-mountpoint") + 1])
            if self.chiavi.get(str(bundle)) != passphrase:
                return subprocess.CompletedProcess(argv, 1, KEY, KEY)
            storage = bundle / "storage"
            self.C._copia_metadati(storage, monte)
            for figlio in storage.iterdir():
                figlio.rename(monte / figlio.name)
            (monte / ".fseventsd").mkdir(exist_ok=True)
            self.montati[str(monte)] = bundle
            if self.corrompi_al_mount == self.conta[verbo]:
                (monte / "segreto.txt").write_text("corrotto")
        elif verbo == "detach":
            monte = Path(argv[2])
            storage = self.montati.pop(str(monte)) / "storage"
            self.C._copia_metadati(monte, storage)
            for figlio in monte.iterdir():
                figlio.rename(storage / figlio.name)
        return subprocess.CompletedProcess(argv, 0, b"", b"")


@pytest.fixture()
def C(tmp_path, monkeypatch):
    casa = tmp_path / "casa"
    monkeypatch.setenv("PARATIA_HOME", str(casa))
    spec = importlib.util.spec_from_file_location("cartelle_test", ROOT / "cartelle.py")
    C = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(C)
    return C


@pytest.fixture()
def D(C, monkeypatch):
    if not Path(C.DITTO).is_file():
        pytest.skip("The migration metadata copy uses macOS ditto")
    d = Dischi(C)
    monkeypatch.setattr(C, "_corri", d.corri)
    monkeypatch.setattr(C, "_montato", lambda p: str(p) in d.montati)
    monkeypatch.setattr(C, "_avvia_timer", lambda *a: d.timer.append(a))
    return d


@pytest.fixture()
def albero(tmp_path):
    fonte, disco = tmp_path / "documenti", tmp_path / "SSD"
    fonte.mkdir()
    disco.mkdir()
    (fonte / "segreto.txt").write_text("fixture-private-marker")
    (fonte / ".invisibile").mkdir()
    (fonte / ".invisibile" / "a.txt").write_text("anche questo")
    (fonte / "vuota").mkdir()
    return fonte, disco


def test_proteggi_verifica_rimontaggio_e_lascia_mountpoint_vuoto(C, D, albero):
    fonte, disco = albero
    v = C.proteggi(fonte, disco, KEY)
    assert v["stato"] == "chiusa"
    assert v["verificato"] is True
    assert v["file"] == 2
    assert v["montaggio"] == str(fonte)
    assert fonte.is_dir() and list(fonte.iterdir()) == []
    assert D.conta["attach"] == D.conta["detach"] == 2
    assert not D.montati
    assert C.elenco()[0]["id"] == v["id"]
    registry = C.ARCHIVIO.read_bytes()
    assert KEY not in registry and b"fixture-private-marker" not in registry
    assert b"segreto.txt" not in registry  # Manifest filenames stay in ciphertext.
    assert KEY not in (C.CASA / "registro" / "catena.jsonl").read_bytes()
    for argv, key in D.chiamate:
        assert KEY.decode() not in " ".join(argv)
        if key is not None:
            assert argv[0] == "/usr/bin/hdiutil" and "-stdinpass" in argv
            assert "-encryption" in argv or argv[1] == "attach"
    assert all("-force" not in argv for argv, _ in D.chiamate)


def test_errore_registro_non_invalida_migrazione_conclusa(C, D, albero, monkeypatch):
    def registro_non_scrivibile(*args, **kwargs):
        raise OSError("fixture audit unavailable")
    monkeypatch.setattr(C, "annota", registro_non_scrivibile)
    fonte, disco = albero
    v = C.proteggi(fonte, disco, KEY)
    assert v["stato"] == "chiusa" and v["verificato"]
    assert "avviso_registro" in v
    assert C.elenco()[0]["stato"] == "chiusa"
    assert list(fonte.iterdir()) == []
    assert not D.montati


@pytest.mark.parametrize("fase, numero", [("create", 1), ("attach", 1), ("ditto", 1), ("detach", 1), ("attach", 2), ("detach", 2)])
def test_errori_migrazione_conservano_fonte_e_non_espongono_chiave(C, D, albero, fase, numero):
    fonte, disco = albero
    D.fallisce = (fase, numero)
    with pytest.raises(C.Rifiuto) as errore:
        C.proteggi(fonte, disco, KEY)
    assert KEY.decode() not in str(errore.value)
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"
    assert (fonte / ".invisibile" / "a.txt").read_text() == "anche questo"
    v = C.elenco()[0]
    assert v["stato"] == "migrazione-incompleta"
    assert errore.value.cartella_id == v["id"]
    assert v["plaintext_residuo"] == str(fonte)
    assert C.annulla_migrazione(v["id"])["stato"] == "annullata"
    assert C.elenco() == []


def test_verifica_rimontaggio_rileva_corruzione(C, D, albero):
    fonte, disco = albero
    D.corrompi_al_mount = 2
    with pytest.raises(C.Rifiuto, match="verifica"):
        C.proteggi(fonte, disco, KEY)
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"
    assert C.elenco()[0]["verificato"] is False


def test_modifica_fonte_durante_copia_blocca_cancellazione(C, D, albero):
    fonte, disco = albero
    D.after_copy = lambda: (fonte / "segreto.txt").write_text("cambiato dall'utente")
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    assert (fonte / "segreto.txt").read_text() == "cambiato dall'utente"
    with pytest.raises(C.Rifiuto, match="cambiata"):
        C.annulla_migrazione(C.elenco()[0]["id"])


@pytest.mark.parametrize("tipo", ["symlink", "hardlink", "fifo"])
def test_fonte_con_link_o_file_speciali_rifiutata_prima_create(C, D, albero, tipo):
    fonte, disco = albero
    if tipo == "symlink":
        (fonte / "link").symlink_to(fonte / "segreto.txt")
    elif tipo == "hardlink":
        os.link(fonte / "segreto.txt", fonte / "link")
    else:
        os.mkfifo(fonte / "fifo")
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    assert D.conta["create"] == 0
    assert (fonte / "segreto.txt").exists()


def test_disco_interno_e_destinazione_annidata_rifiutati(C, D, albero):
    fonte, disco = albero
    D.interno = True
    with pytest.raises(C.Rifiuto, match="esterno"):
        C.proteggi(fonte, disco, KEY)
    D.interno = False
    con_figlia = fonte / "destinazione"
    con_figlia.mkdir()
    with pytest.raises(C.Rifiuto, match="annidate"):
        C.proteggi(fonte, con_figlia, KEY)
    assert D.conta["create"] == 0


def test_nomedir_di_sistema_presente_nella_fonte_viene_verificato(C, D, albero):
    fonte, disco = albero
    (fonte / ".Trashes").mkdir()
    (fonte / ".Trashes" / "utente.txt").write_text("da conservare")
    v = C.proteggi(fonte, disco, KEY)
    assert v["file"] == 3
    C.apri(v["id"], KEY)
    assert (fonte / ".Trashes" / "utente.txt").read_text() == "da conservare"
    C.chiudi(v["id"])


def test_apertura_chiave_errata_e_busy_non_forza(C, D, albero):
    fonte, disco = albero
    v = C.proteggi(fonte, disco, KEY)
    with pytest.raises(C.Rifiuto):
        C.apri(v["id"], b"wrong-fixture-key")
    assert not D.montati and list(fonte.iterdir()) == []
    aperta = C.apri(v["id"], KEY, minutes=7)
    assert aperta["stato"] == "aperta" and D.timer[-1][2] == 420
    D.fallisce = ("detach", D.conta["detach"] + 1)
    with pytest.raises(C.Rifiuto):
        C.chiudi(v["id"])
    assert C.elenco()[0]["stato"] == "aperta"
    assert (fonte / "segreto.txt").exists()
    assert all("-force" not in argv for argv, _ in D.chiamate)
    assert C.chiudi(v["id"])["stato"] == "chiusa"


def test_vecchio_timer_non_chiude_riapertura(C, D, albero, monkeypatch):
    fonte, disco = albero
    v = C.proteggi(fonte, disco, KEY)
    vecchia = C.apri(v["id"], KEY)
    C.chiudi(v["id"])
    nuova = C.apri(v["id"], KEY)
    assert nuova["generation"] != vecchia["generation"]
    monkeypatch.setattr(C.time, "sleep", lambda _: pytest.fail("A stale timer should leave immediately"))
    assert C._timer(v["id"], vecchia["generation"], 0) == 0
    assert C.elenco()[0]["stato"] == "aperta"
    C.chiudi(v["id"])


def test_timer_chiude_e_retry_busy(C, D, albero, monkeypatch, capsys):
    _, disco = albero
    v = C.proteggi(albero[0], disco, KEY)
    aperta = C.apri(v["id"], KEY)
    D.fallisce = ("detach", D.conta["detach"] + 1)
    pause = []
    monkeypatch.setattr(C.time, "sleep", lambda secondi: pause.append(secondi))
    assert C._timer(v["id"], aperta["generation"], 0) == 0
    assert pause == [0, 5]
    assert capsys.readouterr().out == "ready\n"
    assert C.elenco()[0]["stato"] == "chiusa"


def test_timer_che_non_parte_richiude_cartella(C, D, albero, monkeypatch):
    v = C.proteggi(*albero, KEY)
    spec = importlib.util.spec_from_file_location("cartelle_handshake", ROOT / "cartelle.py")
    vero = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vero)
    monkeypatch.setattr(C, "_avvia_timer", vero._avvia_timer)
    monkeypatch.setattr(C.sys, "executable", "/usr/bin/false")
    with pytest.raises(C.Rifiuto, match="timer"):
        C.apri(v["id"], KEY)
    assert C.elenco()[0]["stato"] == "chiusa"
    assert not D.montati


def test_cleanup_parziale_rimane_incompleto_e_recuperabile(C, D, albero, monkeypatch):
    fonte, disco = albero
    vero = C.shutil.rmtree

    def cleanup_fallito(p, *args, **kwargs):
        (Path(p) / "segreto.txt").unlink()
        raise OSError("fixture cleanup failure")

    monkeypatch.setattr(C.shutil, "rmtree", cleanup_fallito)
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    v = C.elenco()[0]
    assert v["stato"] == "migrazione-incompleta" and v["verificato"] is True
    assert Path(v["plaintext_residuo"]).is_dir()
    assert list(fonte.iterdir()) == []
    with pytest.raises(C.Rifiuto):
        C.apri(v["id"], KEY)
    monkeypatch.setattr(C.shutil, "rmtree", vero)
    assert C.recupera(v["id"], KEY)["stato"] == "recuperata"
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"
    assert (fonte / ".invisibile" / "a.txt").read_text() == "anche questo"
    assert (fonte / "vuota").is_dir()
    assert C.elenco() == []
    assert Path(v["bundle"]).exists()


def test_recupero_non_sovrascrive_nuovi_dati(C, D, albero, monkeypatch):
    fonte, disco = albero
    monkeypatch.setattr(C.shutil, "rmtree", lambda *_a, **_k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    v = C.elenco()[0]
    (fonte / "nuovo.txt").write_text("cambiamento dell'utente")
    with pytest.raises(C.Rifiuto, match="contiene dati"):
        C.recupera(v["id"], KEY)
    assert (fonte / "nuovo.txt").read_text() == "cambiamento dell'utente"


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS metadata")
def test_xattr_resource_fork_acl_e_modi_conservati(C, D, albero):
    fonte, disco = albero
    file = fonte / "segreto.txt"
    lib = C._libc()
    valore = b"fixture-extended-attribute"
    assert lib.setxattr(os.fsencode(file), b"com.paratia.fixture", valore, len(valore), 0, 1) == 0
    (file / "..namedfork" / "rsrc").write_bytes(b"fixture-resource-fork")
    file.chmod(0o640)
    subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(file)], check=True, capture_output=True)
    try:
        atteso = C._contenuto(C._scansiona(fonte))
        v = C.proteggi(fonte, disco, KEY)
        C.apri(v["id"], KEY)
        trovato = C._contenuto(C._scansiona(fonte, {v["metadir"], ".fseventsd"}))
        assert trovato == atteso
        assert (file / "..namedfork" / "rsrc").read_bytes() == b"fixture-resource-fork"
        C.chiudi(v["id"])
    finally:
        # Only this test's generated fixture tree; no user files are touched.
        subprocess.run(["/bin/chmod", "-RN", str(fonte.parent)], capture_output=True, check=False)


def test_subprocess_chiave_solo_stdin_terminata_nul(C, monkeypatch):
    ricevuto = {}

    def run(argv, **kwargs):
        ricevuto.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(C.subprocess, "run", run)
    C._corri([C.HDIUTIL, "attach", "fixture.sparsebundle", "-stdinpass"], KEY)
    assert ricevuto["input"] == KEY + b"\0"
    assert "env" not in ricevuto and KEY.decode() not in " ".join(ricevuto["argv"])


def test_bundle_pre_esistente_non_sovrascritto(C, D, albero, monkeypatch):
    fonte, disco = albero
    class Identificatore:
        hex = "a" * 32
    monkeypatch.setattr(C.uuid, "uuid4", lambda: Identificatore())
    bundle = disco / (fonte.name + "-" + "a" * 32 + ".sparsebundle")
    bundle.mkdir()
    (bundle / "intatto").write_text("fixture")
    with pytest.raises(C.Rifiuto, match="sovrascritto"):
        C.proteggi(fonte, disco, KEY)
    assert (bundle / "intatto").read_text() == "fixture"
    assert D.conta["create"] == 0


def test_cloud_e_sovrapposizione_registry_rifiutati(C, D, albero, tmp_path):
    fonte, disco = albero
    cloud = tmp_path / "Dropbox"
    cloud.mkdir()
    with pytest.raises(C.Rifiuto, match="cloud"):
        C.proteggi(fonte, cloud, KEY)
    v = C.proteggi(fonte, disco, KEY)
    C.apri(v["id"], KEY)
    with pytest.raises(C.Rifiuto, match="sovrappone"):
        C.proteggi(fonte / ".invisibile", disco, KEY)
    C.chiudi(v["id"])


def test_secondo_recupero_non_dimentica_staging_plaintext(C, D, albero, monkeypatch):
    fonte, disco = albero
    cleanup = C.shutil.rmtree
    monkeypatch.setattr(C.shutil, "rmtree", lambda *_a, **_k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    v = C.elenco()[0]
    monkeypatch.setattr(C.shutil, "rmtree", cleanup)
    stacca = C._stacca
    monte_recovery = []

    def busy(p):
        if Path(p).name.startswith("recupero-"):
            monte_recovery.append(p)
            raise C.Rifiuto("fixture busy recovery")
        stacca(p)

    monkeypatch.setattr(C, "_stacca", busy)
    with pytest.raises(C.Rifiuto):
        C.recupera(v["id"], KEY)
    registrata = C.elenco()[0]
    staging = Path(registrata["recupero_temporaneo"])
    assert (staging / "segreto.txt").read_text() == "fixture-private-marker"
    with pytest.raises(C.Rifiuto, match="precedente"):
        C.recupera(v["id"], KEY)
    assert C.elenco()[0]["recupero_temporaneo"] == str(staging)
    assert staging.exists()
    monkeypatch.setattr(C, "_stacca", stacca)
    C.chiudi_tutte()


@pytest.mark.skipif(os.environ.get("PARATIA_TEST_NATIVE") != "1", reason="real hdiutil is explicitly opt-in")
def test_migrazione_nativa_fixture_temporanea(C, albero, monkeypatch):
    """Opt-in primitive validation; disk selection alone is bypassed for tmpdir."""
    import base64
    import secrets
    fonte, disco = albero
    monkeypatch.setattr(C, "_esterno", lambda _: None)
    monkeypatch.setattr(C, "_avvia_timer", lambda *_: None)
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    try:
        v = C.proteggi(fonte, disco, key)
        if list(fonte.iterdir()) or v["stato"] != "chiusa":
            pytest.fail("Native migration left plaintext at the mountpoint", pytrace=False)
        C.apri(v["id"], key)
        if (fonte / "segreto.txt").read_text() != "fixture-private-marker":
            pytest.fail("Native reopen content mismatch", pytrace=False)
        C.chiudi(v["id"])
        if list(fonte.iterdir()):
            pytest.fail("Native close left plaintext at the mountpoint", pytrace=False)
    except Exception as e:
        pytest.fail("Native migration failed: " + type(e).__name__, pytrace=False)
    finally:
        C.chiudi_tutte()
