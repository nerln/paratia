"""Folder migration and recovery with fake disk images and real metadata copies."""

from __future__ import annotations

import importlib.util
import errno
import json
import os
import plistlib
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"fixture-only-passphrase-123"


def dischi_fixture(interno=False, immagine=False, exfat=False):
    protocollo = "USB"
    volume = {"DeviceIdentifier": "disk12s1", "FilesystemType": "apfs",
              "Internal": interno, "BusProtocol": protocollo, "ParentWholeDisk": "disk12",
              "APFSPhysicalStores": [{"APFSPhysicalStore": "disk10s4"}]}
    if exfat:
        volume = {"DeviceIdentifier": "disk10s3", "FilesystemType": "exfat",
                  "Internal": interno, "BusProtocol": protocollo, "ParentWholeDisk": "disk10"}
    return {"volume": volume,
            "disk12": {"DeviceIdentifier": "disk12", "VirtualOrPhysical": "Virtual",
                       "Internal": interno, "BusProtocol": protocollo,
                       "APFSPhysicalStores": [{"APFSPhysicalStore": "disk10s4"}]},
            "disk10s4": {"DeviceIdentifier": "disk10s4", "Internal": interno,
                         "BusProtocol": protocollo, "ParentWholeDisk": "disk10"},
            "disk10": {"DeviceIdentifier": "disk10", "VirtualOrPhysical": "Virtual" if immagine else "Physical",
                       "Internal": interno, "BusProtocol": "Disk Image" if immagine else protocollo}}


class Dischi:
    def __init__(self, C):
        self.C = C
        self.montati = {}
        self.chiavi = {}
        self.chiamate = []
        self.conta = Counter()
        self.fallisce = None
        self.rc_fallisce = 1
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
            return subprocess.CompletedProcess(argv, self.rc_fallisce, KEY, KEY)
        if argv[0] == self.C.DISKUTIL:
            dischi = dischi_fixture(interno=self.interno)
            return subprocess.CompletedProcess(argv, 0,
                                               plistlib.dumps(dischi.get(argv[-1], dischi["volume"])), b"")
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
                return subprocess.CompletedProcess(argv, 1, KEY, b"Authentication error: " + KEY)
            storage = bundle / "storage"
            self.C._copia_metadati(storage, monte)
            for figlio in storage.iterdir():
                figlio.rename(monte / figlio.name)
            (monte / ".fseventsd").mkdir(exist_ok=True)
            self.montati[str(monte)] = bundle
            if self.corrompi_al_mount == self.conta[verbo]:
                (monte / "segreto.txt").write_text("corrotto")
        elif verbo == "isencrypted":
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"encrypted": True}), b"")
        elif verbo == "imageinfo":
            if self.chiavi.get(argv[2]) != passphrase:
                return subprocess.CompletedProcess(argv, 1, KEY, b"opaque localized error: " + KEY)
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"Properties": {"Encrypted": True}}), b"")
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
            assert "-encryption" in argv or argv[1] in ("attach", "imageinfo")
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
    with pytest.raises(C.ChiaveErrata) as errore:
        C.apri(v["id"], b"wrong-fixture-key")
    assert KEY.decode() not in str(errore.value) and "wrong-fixture-key" not in str(errore.value)
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
    D.rc_fallisce = errno.EBUSY
    pause = []
    monkeypatch.setattr(C, "_attendi_timer", lambda _id, _gen, _token, secondi: pause.append(secondi) or True)
    assert C._timer(v["id"], aperta["generation"], 0) == 0
    assert pause == [0, 5]
    assert capsys.readouterr().out == "ready\n"
    assert C.elenco()[0]["stato"] == "chiusa"
    assert all("-force" not in argv for argv, _ in D.chiamate)


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


@pytest.mark.parametrize("caso", ["sottocartella", "radice", "exfat", "interno", "immagine", "contenitore"])
def test_diskutil_interroga_il_mount_e_rifiuta_interno_e_immagine(C, tmp_path, monkeypatch, caso):
    radice = tmp_path / "SSD"
    figlia = radice / "backup" / "paratia"
    figlia.mkdir(parents=True)
    dove = radice if caso == "radice" else figlia
    chiamate = []
    vero_stat = Path.stat
    dischi = dischi_fixture(interno=caso == "interno", immagine=caso == "immagine", exfat=caso == "exfat")
    if caso == "contenitore":
        del dischi["volume"]["APFSPhysicalStores"]

    def volume_stat(p, *args, **kwargs):
        s = vero_stat(p, *args, **kwargs)
        return SimpleNamespace(st_dev=101 if p == radice or radice in p.parents else 202,
                               st_mode=s.st_mode)

    def diskutil(argv, passphrase=None):
        chiamate.append(argv)
        assert argv[:3] == [C.DISKUTIL, "info", "-plist"]
        assert passphrase is None
        if argv[-1] == str(radice):
            dati = dischi["volume"]
        else:
            dati = dischi[argv[-1]]
        return subprocess.CompletedProcess(argv, 0, plistlib.dumps(dati), b"")

    with monkeypatch.context() as m:
        m.setattr(Path, "stat", volume_stat)
        m.setattr(C.sys, "platform", "fixture")
        m.setattr(C, "_corri", diskutil)
        if caso in ("interno", "immagine"):
            with pytest.raises(C.Rifiuto, match="immagini disco"):
                C._esterno(dove)
        else:
            C._esterno(dove)
    attesi = [str(radice)]
    if caso == "contenitore":
        attesi.append("disk12")
    if caso != "exfat":
        attesi.append("disk10s4")
    attesi.append("disk10")
    assert [argv[-1] for argv in chiamate] == attesi


def test_firmlink_usa_il_mount_statfs_anziche_users(C, tmp_path, monkeypatch):
    alias = tmp_path / "Users"
    dove = alias / "operatore" / "cartella"
    monte = tmp_path / "System" / "Volumes" / "Data"
    dove.mkdir(parents=True)
    monte.mkdir(parents=True)
    vero_stat = Path.stat

    def volume_stat(p, *args, **kwargs):
        s = vero_stat(p, *args, **kwargs)
        stesso_volume = any(p == base or base in p.parents for base in (alias, monte))
        return SimpleNamespace(st_dev=101 if stesso_volume else 202, st_mode=s.st_mode)

    with monkeypatch.context() as m:
        m.setattr(Path, "stat", volume_stat)
        m.setattr(C.sys, "platform", "darwin")
        m.setattr(C, "_monte_statfs", lambda p: monte if p == dove else pytest.fail("unexpected path"))
        assert C._punto_montaggio(dove) == monte


@pytest.mark.skipif(sys.platform != "darwin", reason="native read-only statfs")
def test_statfs_nativo_restituisce_il_volume_effettivo(C, tmp_path):
    monte = C._monte_statfs(tmp_path)
    assert monte.is_dir() and monte.stat().st_dev == tmp_path.stat().st_dev


def test_preflight_protezione_non_chiede_chiave_ne_crea_registro(C, D, albero):
    preparazione = C.prepara_protezione(*albero, minutes=7)
    assert preparazione == {"pronto": True, "origine": str(albero[0]),
                             "dove": str(albero[1]), "minutes": 7}
    assert not C.CASA.exists() and D.conta["create"] == 0
    assert all(key is None for _, key in D.chiamate)
    D.interno = True
    with pytest.raises(C.Rifiuto, match="esterno"):
        C.proteggi(*albero, b"")
    assert not C.CASA.exists() and D.conta["create"] == 0


def test_gia_aperta_precede_chiave_e_non_duplica_timer_o_eventi(C, D, albero):
    v = C.proteggi(*albero, KEY)
    aperta = C.apri(v["id"], KEY)
    registry = C.ARCHIVIO.read_bytes()
    log = (C.CASA / "registro" / "catena.jsonl").read_bytes()
    assert C.prepara_apertura(v["id"])["gia_aperta"] is True
    assert C.apri(v["id"], None)["gia_aperta"] is True
    assert len(D.timer) == 1 and C.ARCHIVIO.read_bytes() == registry
    assert (C.CASA / "registro" / "catena.jsonl").read_bytes() == log
    assert C.elenco()[0]["generation"] == aperta["generation"]
    C.chiudi(v["id"])


def test_gia_chiusa_non_duplica_eventi_ne_riscrive_registro(C, D, albero):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    assert C.chiudi(v["id"])["stato"] == "chiusa"
    registry = C.ARCHIVIO.read_bytes()
    log = (C.CASA / "registro" / "catena.jsonl").read_bytes()
    assert C.chiudi(v["id"])["gia_chiusa"] is True
    assert C.chiudi_tutte()[0]["gia_chiusa"] is True
    assert C.ARCHIVIO.read_bytes() == registry
    assert (C.CASA / "registro" / "catena.jsonl").read_bytes() == log


def test_errore_disco_diverso_da_chiave_errata(C, D, albero):
    v = C.proteggi(*albero, KEY)
    D.fallisce = ("attach", D.conta["attach"] + 1)
    with pytest.raises(C.Rifiuto) as errore:
        C.apri(v["id"], KEY)
    assert not isinstance(errore.value, C.ChiaveErrata)
    assert KEY.decode() not in str(errore.value)


def test_attesa_timer_ricontrolla_token_dopo_025_secondi(C, D, albero, monkeypatch):
    v = C.proteggi(*albero, KEY)
    aperta = C.apri(v["id"], KEY)
    identita = C._identita_timer(C._carica()["cartelle"][v["id"]])
    pause = []
    clock = [0.0]

    def sleep(secondi):
        pause.append(secondi)
        clock[0] += secondi
        C.chiudi(v["id"])

    monkeypatch.setattr(C.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(C.time, "sleep", sleep)
    assert not C._attendi_timer(v["id"], aperta["generation"], identita, 3600)
    assert pause == [0.25]
    assert "timer" not in C._carica()["cartelle"][v["id"]]


@pytest.mark.parametrize("modifica", ["owner", "id"])
def test_timer_non_agisce_con_identita_diversa(C, D, albero, monkeypatch, modifica):
    v = C.proteggi(*albero, KEY)
    aperta = C.apri(v["id"], KEY)
    identita = C._identita_timer(C._carica()["cartelle"][v["id"]])
    with C._registro() as r:
        timer = r["cartelle"][v["id"]]["timer"]
        timer[modifica] = os.getuid() + 1 if modifica == "owner" else "0" * 32
        C._salva(r)
    monkeypatch.setattr(C.time, "sleep", lambda _: pytest.fail("invalidated timer should not sleep"))
    assert not C._attendi_timer(v["id"], aperta["generation"], identita, 3600)
    assert C.elenco()[0]["stato"] == "aperta"
    C.chiudi(v["id"])


def test_chiusura_manuale_termina_figlio_timer_senza_segnali(C, D, albero, tmp_path, monkeypatch):
    v = C.proteggi(*albero, KEY)
    aperta = C.apri(v["id"], KEY)
    driver = tmp_path / "timer_fixture.py"
    driver.write_text("import importlib.util, pathlib, sys\n"
                      "spec = importlib.util.spec_from_file_location('fixture', sys.argv[1])\n"
                      "C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)\n"
                      "C.CASA = pathlib.Path(sys.argv[2]); C.ARCHIVIO = C.CASA / 'cartelle.json'\n"
                      "C._montato = lambda path: True\n"
                      "sys.exit(C._timer(sys.argv[3], sys.argv[4], 3600))\n")
    figlio = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(driver),
                               str(ROOT / "cartelle.py"), str(C.CASA), v["id"], aperta["generation"]],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert C.select.select([figlio.stdout], [], [], 3)[0]
        assert figlio.stdout.readline() == b"ready\n"
        token = C._carica()["cartelle"][v["id"]]["timer"]
        D.fallisce = ("detach", D.conta["detach"] + 1)
        with pytest.raises(C.Rifiuto):
            C.chiudi(v["id"])
        assert figlio.poll() is None and C._carica()["cartelle"][v["id"]]["timer"] == token
        with monkeypatch.context() as m:
            m.setattr(C.os, "kill", lambda *_: pytest.fail("manual closure must not signal a PID"))
            C.chiudi(v["id"])
        stdout, stderr = figlio.communicate(timeout=3)
        assert figlio.returncode == 0 and stdout == stderr == b""
    finally:
        if figlio.poll() is None:
            figlio.kill()
            figlio.wait()
        figlio.stdout.close()
        figlio.stderr.close()


@pytest.fixture()
def CLI(C, monkeypatch):
    originale = importlib.util.spec_from_file_location
    spec = originale("paratia_cartelle_cli", ROOT / "paratia.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    class Loader:
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            module.__dict__.update(C.__dict__)

    def carica(nome, percorso, *args, **kwargs):
        if nome == "cartelle":
            return importlib.util.spec_from_loader(nome, Loader())
        return originale(nome, percorso, *args, **kwargs)

    monkeypatch.setattr(importlib.util, "spec_from_file_location", carica)
    monkeypatch.setattr(cli, "chiedi_passphrase", lambda _: pytest.fail("unexpected passphrase prompt"))
    return cli


def test_cli_valida_il_disco_prima_del_prompt(CLI, D, albero):
    D.interno = True
    args = CLI.costruisci().parse_args(["cartella", "proteggi", str(albero[0]), "--dove", str(albero[1])])
    with pytest.raises(CLI.Rifiuto, match="esterno"):
        CLI.cmd_cartella(args)


def test_cli_gia_aperta_non_chiede_chiave_anche_in_agente(C, D, CLI, albero, monkeypatch, capsys):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    monkeypatch.setattr(CLI, "dentro_un_agente", lambda: "fixture-agent")
    args = CLI.costruisci().parse_args(["cartella", "apri", v["id"]])
    assert CLI.cmd_cartella(args) == 0
    assert json.loads(capsys.readouterr().out)["gia_aperta"] is True
    C.chiudi(v["id"])


def test_cli_chiave_errata_ha_codice_json_distinguibile(C, D, CLI, albero, monkeypatch, capsys):
    v = C.proteggi(*albero, KEY)
    monkeypatch.setattr(CLI, "dentro_un_agente", lambda: None)
    monkeypatch.setattr(CLI, "chiedi_passphrase", lambda _: b"wrong-fixture-passphrase")
    args = CLI.costruisci().parse_args(["cartella", "apri", v["id"]])
    assert CLI.cmd_cartella(args) == 2
    output = capsys.readouterr()
    assert output.out == "" and json.loads(output.err)["errore"] == "chiave_errata"
    assert KEY.decode() not in output.err and "wrong-fixture-passphrase" not in output.err


@pytest.mark.parametrize("messaggio", [b"opaque unfamiliar locale", b"Errore di autenticazione",
                                       b"Authentication error", "Error de autenticación".encode()])
def test_chiave_cifrata_verificata_senza_mount_indipendentemente_dalla_lingua(C, tmp_path, monkeypatch, messaggio):
    bundle, monte = tmp_path / "fixture.sparsebundle", tmp_path / "mount"
    bundle.mkdir()
    monte.mkdir()
    chiamate = []

    def corri(argv, passphrase=None):
        chiamate.append((argv, passphrase))
        if argv[1] == "isencrypted":
            assert passphrase is None
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"encrypted": True}), b"")
        assert argv == [C.HDIUTIL, "imageinfo", str(bundle), "-plist", "-stdinpass"]
        assert passphrase == KEY
        return subprocess.CompletedProcess(argv, 1, KEY, messaggio + b": " + KEY)

    monkeypatch.setattr(C, "_corri", corri)
    with pytest.raises(C.ChiaveErrata) as errore:
        C._attacca(bundle, monte, KEY)
    assert [argv[1] for argv, _ in chiamate] == ["isencrypted", "imageinfo"]
    assert KEY.decode() not in str(errore.value)
    assert all(KEY.decode() not in " ".join(argv) for argv, _ in chiamate)


@pytest.mark.parametrize("messaggio", [b"attach failed - Errore di autenticazione",
                                       b"attach failed - Authentication error",
                                       "attach failed - Error de autenticación".encode()])
def test_errori_localizzati_come_ripiego_senza_metadata_cifratura(C, tmp_path, monkeypatch, messaggio):
    bundle = tmp_path / "fixture.sparsebundle"
    bundle.mkdir()
    def corri(argv, passphrase=None):
        if argv[1] == "isencrypted":
            return subprocess.CompletedProcess(argv, 64, b"", b"provider unsupported")
        return subprocess.CompletedProcess(argv, 1, KEY, messaggio)
    monkeypatch.setattr(C, "_corri", corri)
    with pytest.raises(C.ChiaveErrata):
        C._verifica_chiave(bundle, KEY)
    for verbo in ("attach", "imageinfo"):
        with pytest.raises(C.ChiaveErrata):
            C._comando([C.HDIUTIL, verbo, str(bundle), "-stdinpass"], KEY)


def test_immagine_non_cifrata_rifiutata_senza_chiave_o_mount(C, tmp_path, monkeypatch):
    bundle = tmp_path / "fixture.sparsebundle"
    bundle.mkdir()
    chiamate = []
    def corri(argv, passphrase=None):
        chiamate.append((argv, passphrase))
        return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"encrypted": False}), b"")
    monkeypatch.setattr(C, "_corri", corri)
    with pytest.raises(C.Rifiuto, match="non risulta cifrata"):
        C._verifica_chiave(bundle, KEY)
    assert len(chiamate) == 1 and chiamate[0][1] is None


@pytest.mark.parametrize("rc", [errno.EIO, errno.EACCES, errno.ENODEV, errno.ENXIO,
                               errno.EINVAL, errno.ENOSPC, errno.EROFS, errno.ENOTSUP, errno.EBUSY,
                               errno.EAGAIN, errno.EFBIG])
def test_imageinfo_errore_io_non_diventa_chiave_errata(C, tmp_path, monkeypatch, rc):
    bundle = tmp_path / "fixture.sparsebundle"
    bundle.mkdir()
    def corri(argv, passphrase=None):
        if argv[1] == "isencrypted":
            return subprocess.CompletedProcess(argv, 0, plistlib.dumps({"encrypted": True}), b"")
        return subprocess.CompletedProcess(argv, rc, KEY, KEY)
    monkeypatch.setattr(C, "_corri", corri)
    with pytest.raises(C.Rifiuto) as errore:
        C._verifica_chiave(bundle, KEY)
    assert not isinstance(errore.value, C.ChiaveErrata)
    assert KEY.decode() not in str(errore.value)


def test_volume_occupato_esplicito_e_forza_solo_su_scelta(C, D, albero):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    prima = C._carica()["cartelle"][v["id"]]
    D.fallisce = ("detach", D.conta["detach"] + 1)
    D.rc_fallisce = errno.EBUSY
    with pytest.raises(C.VolumeOccupato, match="app.*terminale") as errore:
        C.chiudi(v["id"])
    assert errore.value.cartella_id == v["id"]
    dopo = C._carica()["cartelle"][v["id"]]
    assert dopo["generation"] == prima["generation"] and dopo["timer"] == prima["timer"]
    assert "-force" not in D.chiamate[-1][0]
    risultato = C.chiudi(v["id"], force=True)
    assert risultato["forzata"] is True and risultato["stato"] == "chiusa"
    assert D.chiamate[-1][0] == [C.HDIUTIL, "detach", str(albero[0]), "-force"]
    eventi = [json.loads(line) for line in (C.CASA / "registro" / "catena.jsonl").read_text().splitlines()]
    assert eventi[-1]["azione"] == "chiusura-forzata"


@pytest.mark.parametrize("force", [1, "true", None])
def test_forza_richiede_bool_esplicito(C, D, albero, force):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    chiamate = len(D.chiamate)
    with pytest.raises(C.Rifiuto, match="scelta esplicita"):
        C.chiudi(v["id"], force=force)
    assert len(D.chiamate) == chiamate and C.elenco()[0]["stato"] == "aperta"
    C.chiudi(v["id"])


def test_chiudi_tutte_busy_non_forza_e_preserva_timer(C, D, albero):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    token = C._carica()["cartelle"][v["id"]]["timer"]
    D.fallisce = ("detach", D.conta["detach"] + 1)
    D.rc_fallisce = errno.EBUSY
    risultato = C.chiudi_tutte()[0]
    assert "in uso" in risultato["errore"] and risultato["stato"] == "aperta"
    assert C._carica()["cartelle"][v["id"]]["timer"] == token
    assert all("-force" not in argv for argv, _ in D.chiamate)
    C.chiudi(v["id"])


def test_disco_scollegato_preflight_tipizzato_prima_della_chiave(C, D, albero):
    v = C.proteggi(*albero, KEY)
    bundle = Path(v["bundle"])
    bundle.rename(bundle.with_name("temporaneamente-non-disponibile"))
    for operazione in (lambda: C.prepara_apertura(v["id"]), lambda: C.apri(v["id"], None)):
        with pytest.raises(C.DiscoNonDisponibile, match="disco esterno non è disponibile") as errore:
            operazione()
        assert "recuper" not in str(errore.value).lower() and "annulla" not in str(errore.value).lower()
    assert D.conta["attach"] == 2


def test_gia_aperta_minuti_richiesti_non_riavviano_timer(C, D, albero):
    v = C.proteggi(*albero, KEY)
    aperta = C.apri(v["id"], KEY, minutes=7)
    prima = C.ARCHIVIO.read_bytes()
    pronto = C.prepara_apertura(v["id"], minutes=30)
    risultato = C.apri(v["id"], None, minutes=30)
    for r in (pronto, risultato):
        assert r["timer_invariato"] is True and r["minutes_richiesti"] == 30
        assert r["minutes_effettivi"] == 7 and "non lo riavviano" in r["messaggio"]
    assert risultato["minutes"] == 7 and risultato["generation"] == aperta["generation"]
    assert risultato["scadenza"] == aperta["scadenza"] and len(D.timer) == 1
    assert C.ARCHIVIO.read_bytes() == prima
    C.chiudi(v["id"])


def test_cli_disco_scollegato_non_chiede_chiave(C, D, CLI, albero, capsys):
    v = C.proteggi(*albero, KEY)
    bundle = Path(v["bundle"])
    bundle.rename(bundle.with_name("temporaneamente-non-disponibile"))
    args = CLI.costruisci().parse_args(["cartella", "apri", v["id"]])
    assert CLI.cmd_cartella(args) == 2
    assert json.loads(capsys.readouterr().err)["errore"] == "disco_non_disponibile"


def test_cli_busy_esplicito(C, D, CLI, albero, capsys):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    D.fallisce = ("detach", D.conta["detach"] + 1)
    D.rc_fallisce = errno.EBUSY
    args = CLI.costruisci().parse_args(["cartella", "chiudi", v["id"]])
    assert CLI.cmd_cartella(args) == 2
    esito = json.loads(capsys.readouterr().err)
    assert esito["errore"] == "volume_occupato" and "terminale" in esito["messaggio"]
    C.chiudi(v["id"])


def test_cli_gia_aperta_minutes_esplicito(C, D, CLI, albero, capsys):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY, minutes=7)
    args = CLI.costruisci().parse_args(["cartella", "apri", v["id"], "--minutes", "30"])
    assert CLI.cmd_cartella(args) == 0
    esito = json.loads(capsys.readouterr().out)
    assert esito["timer_invariato"] and esito["minutes"] == esito["minutes_effettivi"] == 7
    assert esito["minutes_richiesti"] == 30 and "non lo riavviano" in esito["messaggio"]
    C.chiudi(v["id"])
