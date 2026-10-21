"""Folder migration and recovery with fake disk images and real metadata copies."""

from __future__ import annotations

import importlib.util
import errno
import json
import os
import stat
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEY = b"fixture-only-passphrase-123"


def bundle_fixture(bundle):
    """A synthetic encrypted-v2 sparsebundle header; it contains no real keys."""
    bundle.mkdir()
    info = plistlib.dumps({"diskimage-bundle-type": "com.apple.diskimage.sparsebundle",
                          "bundle-backingstore-version": 1, "band-size": 8388608,
                          "size": 268435456})
    (bundle / "Info.plist").write_bytes(info)
    (bundle / "Info.bckup").write_bytes(info)
    (bundle / "bands").mkdir()
    token = bytearray(4096)
    token[:8] = b"encrcdsa"
    struct.pack_into(">I", token, 8, 2)
    struct.pack_into(">I", token, 52, 4096)
    struct.pack_into(">Q", token, 64, len(token))
    struct.pack_into(">I", token, 72, 1)
    struct.pack_into(">IQQ", token, 76, 1, 96, 128)
    (bundle / "token").write_bytes(token)
    return bundle


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
            bundle_fixture(bundle)
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
        elif verbo == "resize" and "-limits" in argv:
            return subprocess.CompletedProcess(argv, 0, b"20480\t614320\t99999999\n", b"")
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
    # Never the person's real Trash: a test image would end up there.
    cestino = tmp_path / "cestino-del-test"
    cestino.mkdir()
    C._cestino_di = lambda p: cestino
    return C


@pytest.fixture()
def D(C, monkeypatch):
    if not Path(C.DITTO).is_file():
        pytest.skip("The migration metadata copy uses macOS ditto")
    d = Dischi(C)
    monkeypatch.setattr(C, "_corri", d.corri)
    monkeypatch.setattr(C, "_montato", lambda p: str(p) in d.montati)
    monkeypatch.setattr(C, "_avvia_timer", lambda *a: d.timer.append(a))
    monkeypatch.setattr(C, "_processi_occupanti", lambda _: [])
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


def test_modifica_fonte_durante_copia_blocca_cancellazione(C, D, albero, tmp_path, monkeypatch):
    fonte, disco = albero
    cestino = tmp_path / "cestino"
    cestino.mkdir()
    monkeypatch.setattr(C, "_cestino_di", lambda p: cestino)
    D.after_copy = lambda: (fonte / "segreto.txt").write_text("cambiato dall'utente")
    with pytest.raises(C.Rifiuto):
        C.proteggi(fonte, disco, KEY)
    assert (fonte / "segreto.txt").read_text() == "cambiato dall'utente"
    v = C.elenco()[0]
    esito = C.annulla_migrazione(v["id"])
    # The folder keeps the person's edit; the older image is recoverable, not deleted.
    assert (fonte / "segreto.txt").read_text() == "cambiato dall'utente"
    assert esito["bundle_eliminato"] is False and esito["bundle_nel_cestino"] == str(cestino / Path(v["bundle"]).name)
    assert (cestino / Path(v["bundle"]).name).is_dir() and not Path(v["bundle"]).exists()


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


def test_disco_interno_accettato_e_destinazione_annidata_rifiutata(C, D, albero):
    fonte, disco = albero
    D.interno = True
    assert C.prepara_protezione(fonte, disco)["pronto"]
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
def test_diskutil_interroga_il_mount_accetta_interno_e_rifiuta_immagine(C, tmp_path, monkeypatch, caso):
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
        if caso == "immagine":
            with pytest.raises(C.Rifiuto, match="immagini disco"):
                C._disco_fisico(dove)
        else:
            C._disco_fisico(dove)
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
                             "dove": str(albero[1]), "minutes": 7, "predefinita": False}
    assert not C.CASA.exists() and D.conta["create"] == 0
    assert all(key is None for _, key in D.chiamate)
    with pytest.raises(C.Rifiuto):
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
    args = CLI.costruisci().parse_args(["cartella", "proteggi", str(albero[0]), "--dove", str(albero[0] / "dentro")])
    (albero[0] / "dentro").mkdir()
    with pytest.raises(CLI.Rifiuto, match="annidate"):
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
    bundle_fixture(bundle)
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
    bundle_fixture(bundle)
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
    bundle_fixture(bundle)
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
    bundle_fixture(bundle)
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
        with pytest.raises(C.DiscoNonDisponibile, match="immagine cifrata non è disponibile") as errore:
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


def _manomette_bundle(bundle, manomissione):
    if manomissione == "info":
        (bundle / "Info.plist").unlink()
        (bundle / "Info.bckup").unlink()
    elif manomissione == "bands":
        (bundle / "bands").rmdir()
    elif manomissione == "token-assente":
        (bundle / "token").unlink()
    elif manomissione == "token-illeggibile":
        (bundle / "token").chmod(0)
    elif manomissione == "token-troncato":
        # Retain the signature, version, table and part of the key blob. The
        # declared data offset still catches a truncation after those headers.
        (bundle / "token").write_bytes((bundle / "token").read_bytes()[:150])


@pytest.mark.parametrize("manomissione", ["info", "bands", "token-assente", "token-illeggibile", "token-troncato"])
def test_immagine_danneggiata_precede_prompt_chiave_e_comandi(C, D, CLI, albero, capsys, manomissione):
    v = C.proteggi(*albero, KEY)
    bundle = Path(v["bundle"])
    _manomette_bundle(bundle, manomissione)
    prima = len(D.chiamate)
    try:
        for operazione in (lambda: C.prepara_apertura(v["id"]), lambda: C.apri(v["id"], None)):
            with pytest.raises(C.ImmagineDanneggiata, match="danneggiata o incompleta") as errore:
                operazione()
            assert not isinstance(errore.value, C.ChiaveErrata)
            assert errore.value.cartella_id == v["id"]
        args = CLI.costruisci().parse_args(["cartella", "apri", v["id"]])
        assert CLI.cmd_cartella(args) == 2
        esito = json.loads(capsys.readouterr().err)
        assert esito["errore"] == "immagine_danneggiata"
        assert "conserva" in esito["messaggio"] and "Reinserisci" not in esito["messaggio"]
        assert len(D.chiamate) == prima  # No passphrase reached hdiutil.
    finally:
        if manomissione == "token-illeggibile":
            (bundle / "token").chmod(0o600)


@pytest.mark.parametrize("dimensione", [0, 8, 12, 75, 95, 150, 4095])
def test_troncamento_token_prima_e_dopo_magic_non_diventa_wrong_key(C, tmp_path, monkeypatch, dimensione):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    token = bundle / "token"
    token.write_bytes(token.read_bytes()[:dimensione])
    monkeypatch.setattr(C, "_corri", lambda *_: pytest.fail("damaged image must not receive a key"))
    with pytest.raises(C.ImmagineDanneggiata):
        C._verifica_chiave(bundle, KEY)


@pytest.mark.parametrize("dimensione", [512, 8192, 122368])
def test_token_dimensione_da_header_non_da_costante(C, tmp_path, dimensione):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    token = bytearray((bundle / "token").read_bytes()[:512])
    token.extend(b"\0" * (dimensione - len(token)))
    struct.pack_into(">Q", token, 64, dimensione)
    (bundle / "token").write_bytes(token)
    C._verifica_struttura_bundle(bundle)


@pytest.mark.parametrize("metadata", ["Info.plist", "Info.bckup"])
def test_metadata_primario_o_backup_sufficiente(C, tmp_path, metadata):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    (bundle / metadata).unlink()
    C._verifica_struttura_bundle(bundle)


def test_metadata_corrotto_con_backup_integro_ammesso(C, tmp_path):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    (bundle / "Info.plist").write_bytes(b"<?xml version='1.0'?><plist><")
    C._verifica_struttura_bundle(bundle)
    (bundle / "Info.bckup").unlink()
    with pytest.raises(C.ImmagineDanneggiata):
        C._verifica_struttura_bundle(bundle)


@pytest.mark.parametrize("elemento", ["Info.plist", "Info.bckup", "bands", "token"])
def test_struttura_bundle_rifiuta_symlink_anche_con_backup(C, tmp_path, elemento):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    percorso = bundle / elemento
    originale = tmp_path / "originale"
    percorso.rename(originale)
    percorso.symlink_to(originale, target_is_directory=originale.is_dir())
    with pytest.raises(C.ImmagineDanneggiata):
        C._verifica_struttura_bundle(bundle)


@pytest.mark.parametrize("tipo", ["directory", "fifo", "hardlink"])
def test_token_deve_essere_file_regolare_indipendente(C, tmp_path, tipo):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    token = bundle / "token"
    if tipo == "hardlink":
        os.link(token, tmp_path / "secondo-token")
    else:
        token.unlink()
        token.mkdir() if tipo == "directory" else os.mkfifo(token)
    with pytest.raises(C.ImmagineDanneggiata):
        C._verifica_struttura_bundle(bundle)


@pytest.mark.parametrize("campo,valore", [("offset", 4097), ("count", 1000), ("blob-offset", 4095), ("blob-size", 9000)])
def test_token_extents_manomessi_rifiutati(C, tmp_path, campo, valore):
    bundle = bundle_fixture(tmp_path / "fixture.sparsebundle")
    token = bytearray((bundle / "token").read_bytes())
    formati = {"offset": (">Q", 64), "count": (">I", 72), "blob-offset": (">Q", 80), "blob-size": (">Q", 88)}
    formato, posizione = formati[campo]
    struct.pack_into(formato, token, posizione, valore)
    (bundle / "token").write_bytes(token)
    with pytest.raises(C.ImmagineDanneggiata):
        C._verifica_struttura_bundle(bundle)


def test_cli_force_vietato_agente_prima_di_import_backend_o_tty(CLI, monkeypatch):
    args = CLI.costruisci().parse_args(["cartella", "chiudi", "fixture-id", "--force"])
    monkeypatch.setattr(CLI, "dentro_un_agente", lambda: "fixture-agent")
    monkeypatch.setattr(CLI, "conferma_chiusura_forzata", lambda: pytest.fail("agent must never reach tty"))
    monkeypatch.setattr(importlib.util, "spec_from_file_location", lambda *_: pytest.fail("agent must not load backend"))
    with pytest.raises(CLI.Rifiuto, match="vietata nelle sessioni agente"):
        CLI.cmd_cartella(args)


@pytest.mark.parametrize("conferma", [True, False])
def test_cli_force_necessita_conferma_esplicita(C, D, CLI, albero, monkeypatch, capsys, conferma):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    monkeypatch.setattr(CLI, "dentro_un_agente", lambda: None)
    monkeypatch.setattr(CLI, "conferma_chiusura_forzata", lambda: conferma)
    args = CLI.costruisci().parse_args(["cartella", "chiudi", v["id"], "--force"])
    prima = len(D.chiamate)
    if conferma:
        assert CLI.cmd_cartella(args) == 0
        assert json.loads(capsys.readouterr().out)["forzata"] is True
        assert D.chiamate[-1][0][-1] == "-force"
    else:
        with pytest.raises(CLI.Rifiuto, match="annullata"):
            CLI.cmd_cartella(args)
        assert len(D.chiamate) == prima and C.elenco()[0]["stato"] == "aperta"
        C.chiudi(v["id"])


@pytest.mark.parametrize("risposta,atteso", [(b"\n", False), (b"", False), (b"si\n", False),
                                            (b"FORZA\n", True), (b"forza\n", False)])
def test_conferma_force_legge_solo_dev_tty_con_default_no(CLI, monkeypatch, risposta, atteso):
    chiamate, scritti = [], []

    class TTY:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def isatty(self):
            return True
        def write(self, data):
            scritti.append(data)
        def readline(self, limite):
            assert limite == 64
            return risposta

    def apri(percorso, modo, **kwargs):
        chiamate.append((percorso, modo, kwargs))
        return TTY()
    monkeypatch.setattr("builtins.open", apri)
    monkeypatch.setattr(CLI.sys, "stdin", SimpleNamespace(readline=lambda *_: pytest.fail("stdin is not consent")))
    assert CLI.conferma_chiusura_forzata() is atteso
    assert chiamate == [("/dev/tty", "r+b", {"buffering": 0})]
    assert "non salvate" in b"".join(scritti).decode()


def test_conferma_force_senza_tty_non_ripiega_su_stdin(CLI, monkeypatch):
    def non_disponibile(*args, **kwargs):
        raise OSError("fixture unavailable")
    monkeypatch.setattr("builtins.open", non_disponibile)
    monkeypatch.setattr(CLI.sys, "stdin", SimpleNamespace(readline=lambda *_: pytest.fail("stdin is not consent")))
    with pytest.raises(CLI.Rifiuto, match="terminale interattivo"):
        CLI.conferma_chiusura_forzata()


class LsofFixture:
    def __init__(self, output, stato=0):
        self.stdout = tempfile.TemporaryFile()
        self.stdout.write(output)
        self.stdout.seek(0)
        self.stato, self.ucciso = stato, False
    def wait(self, timeout=None):
        return self.stato
    def poll(self):
        return self.stato
    def kill(self):
        self.ucciso, self.stato = True, -9


def test_lsof_diagnosi_solo_nome_pid_e_mount_literal(C, tmp_path, monkeypatch):
    mount = tmp_path / "folder;$(echo fixture)"
    output = (b"p123\0cTextEdit\0\nn/private/file-name\0f10\0"
              b"p124\0cTerminal\0\np123\0cduplicate\0"
              b"p125\0cunsafe\nname\0p0\0cInvalid\0p99999999999\0cInvalid\0")
    child = LsofFixture(output)
    chiamate = []
    def crea(argv, **kwargs):
        chiamate.append((argv, kwargs))
        return child
    monkeypatch.setattr(C.subprocess, "Popen", crea)
    assert C._processi_occupanti(mount) == [{"nome": "TextEdit", "pid": 123}, {"nome": "Terminal", "pid": 124}]
    argv, kwargs = chiamate[0]
    assert argv == ["/usr/sbin/lsof", "-nP", "-Fpc0", "+f", "--", str(mount)]
    assert kwargs["stdin"] == kwargs["stderr"] == subprocess.DEVNULL
    assert child.stdout.closed and not child.ucciso


def test_lsof_limita_numero_processi_e_dimensione_nome(C, tmp_path, monkeypatch):
    output = b"p99\0c" + b"x" * 81 + b"\0" + b"".join(
        f"p{i}\0cApp{i}\0".encode() for i in range(1, 40))
    child = LsofFixture(output)
    monkeypatch.setattr(C.subprocess, "Popen", lambda *_args, **_kwargs: child)
    processi = C._processi_occupanti(tmp_path)
    assert len(processi) == 12 and processi[0] == {"nome": "App1", "pid": 1}


@pytest.mark.parametrize("caso", ["timeout", "oversize", "unavailable"])
def test_lsof_errori_e_limiti_non_impediscono_busy(C, tmp_path, monkeypatch, caso):
    child = LsofFixture(b"x" * 65537 if caso == "oversize" else b"", stato=None)
    def crea(*_args, **_kwargs):
        if caso == "unavailable":
            raise OSError("fixture unavailable")
        return child
    monkeypatch.setattr(C.subprocess, "Popen", crea)
    if caso == "timeout":
        monkeypatch.setattr(C.select, "select", lambda *_: ([], [], []))
    try:
        assert C._processi_occupanti(tmp_path) == []
        if caso != "unavailable":
            assert child.ucciso and child.stdout.closed
    finally:
        child.stdout.close()


def test_cli_busy_mostra_nomipids_non_contenuti(C, D, CLI, albero, monkeypatch, capsys):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    D.fallisce = ("detach", D.conta["detach"] + 1)
    D.rc_fallisce = errno.EBUSY
    monkeypatch.setattr(C, "_processi_occupanti", lambda _: [{"nome": "TextEdit", "pid": 123}])
    args = CLI.costruisci().parse_args(["cartella", "chiudi", v["id"]])
    assert CLI.cmd_cartella(args) == 2
    output = capsys.readouterr().err
    esito = json.loads(output)
    assert esito["processi"] == [{"nome": "TextEdit", "pid": 123}]
    assert "TextEdit (PID 123)" in esito["messaggio"]
    assert KEY.decode() not in output and "fixture-private-marker" not in output
    C.chiudi(v["id"])


def test_senza_destinazione_l_immagine_resta_sullo_stesso_disco_nascosta(C, D, albero):
    fonte, _ = albero
    preparazione = C.prepara_protezione(fonte)
    attesa = C.CASA / "compartimenti.noindex"
    assert preparazione["predefinita"] is True and preparazione["dove"] == str(attesa)
    assert not C.CASA.exists()  # The check creates nothing.
    v = C.proteggi(fonte, None, KEY)
    assert Path(v["bundle"]).parent == attesa and (attesa.stat().st_mode & 0o777) == 0o700
    assert v["stato"] == "chiusa" and list(fonte.iterdir()) == []


def test_spazio_insufficiente_rifiutato_prima_di_creare_l_immagine(C, D, albero, monkeypatch):
    monkeypatch.setattr(C.shutil, "disk_usage", lambda p: SimpleNamespace(total=1, used=1, free=1024))
    with pytest.raises(C.Rifiuto, match="Spazio libero insufficiente"):
        C.proteggi(*albero, KEY)
    assert D.conta["create"] == 0 and (albero[0] / "segreto.txt").exists()


def test_togli_protezione_rimette_i_file_e_elimina_l_immagine(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    bundle = Path(v["bundle"])
    with pytest.raises(C.ChiaveErrata):
        C.togli_protezione(v["id"], b"chiave-sbagliata-123")
    assert bundle.is_dir() and C.elenco()[0]["stato"] == "chiusa" and list(fonte.iterdir()) == []
    esito = C.togli_protezione(v["id"], KEY)
    assert esito["stato"] == "non-protetta" and esito["bundle_eliminato"] is True
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"
    assert (fonte / ".invisibile" / "a.txt").read_text() == "anche questo"
    assert not bundle.exists() and C.elenco() == [] and not D.montati
    assert not [p for p in fonte.parent.iterdir() if ".recupero-" in p.name]


def test_togli_protezione_rifiuta_una_cartella_aperta(C, D, albero):
    v = C.proteggi(*albero, KEY)
    C.apri(v["id"], KEY)
    with pytest.raises(C.Rifiuto, match="Chiudi la cartella"):
        C.togli_protezione(v["id"], KEY)
    C.chiudi(v["id"])


def test_togli_protezione_fallita_lascia_l_immagine_e_nessuna_copia_in_chiaro(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    D.fallisce = ("ditto", D.conta["ditto"] + 1)
    with pytest.raises(C.Rifiuto):
        C.togli_protezione(v["id"], KEY)
    assert Path(v["bundle"]).is_dir() and C.elenco()[0]["stato"] == "chiusa"
    assert list(fonte.iterdir()) == [] and not D.montati
    assert not [p for p in fonte.parent.iterdir() if ".recupero-" in p.name]
    D.fallisce = None
    assert C.togli_protezione(v["id"], KEY)["stato"] == "non-protetta"


@pytest.mark.parametrize("interno,accettato", [(True, True), (False, False)])
def test_ssd_interno_apple_silicon_dichiarato_unknown(C, tmp_path, monkeypatch, interno, accettato):
    dove = tmp_path / "Data"
    dove.mkdir()
    dischi = dischi_fixture(interno=interno)
    dischi["disk10"]["VirtualOrPhysical"] = "Unknown"
    monkeypatch.setattr(C.sys, "platform", "fixture")
    monkeypatch.setattr(C, "_corri", lambda argv, passphrase=None: subprocess.CompletedProcess(
        argv, 0, plistlib.dumps(dischi.get(argv[-1], dischi["volume"])), b""))
    if accettato:
        C._disco_fisico(dove)
    else:
        with pytest.raises(C.Rifiuto, match="immagini disco"):
            C._disco_fisico(dove)


def test_attributi_scritti_da_macos_non_fanno_fallire_la_verifica(C, monkeypatch, tmp_path):
    cartella = tmp_path / "x"
    cartella.mkdir()
    monkeypatch.setattr(C, "_tutti_xattr", lambda p: ["com.apple.provenance", "com.apple.macl", "it.paratia.utente"])
    assert C._nomi_xattr(cartella) == ["it.paratia.utente"]


def test_togli_protezione_riporta_anche_le_modifiche_fatte_da_aperta(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    C.apri(v["id"], KEY)
    (fonte / "segreto.txt").write_text("modificato mentre era aperta")
    (fonte / "nuovo.txt").write_text("aggiunto dopo la protezione")
    (fonte / "vuota" / "dentro.txt").write_text("anche in una sottocartella")
    C.chiudi(v["id"])
    esito = C.togli_protezione(v["id"], KEY)
    assert esito["stato"] == "non-protetta" and not Path(v["bundle"]).exists()
    assert (fonte / "segreto.txt").read_text() == "modificato mentre era aperta"
    assert (fonte / "nuovo.txt").read_text() == "aggiunto dopo la protezione"
    assert (fonte / "vuota" / "dentro.txt").read_text() == "anche in una sottocartella"
    assert (fonte / ".invisibile" / "a.txt").read_text() == "anche questo"
    assert not (fonte / v["metadir"]).exists() and not (fonte / ".fseventsd").exists()


def test_togli_protezione_decide_dal_montaggio_non_dallo_stato_salvato(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    with C._registro() as r:
        r["cartelle"][v["id"]]["stato"] = "aperta"  # As after a restart or an eject.
        C._salva(r)
    assert C.togli_protezione(v["id"], KEY)["stato"] == "non-protetta"
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"


def test_una_cartella_chiusa_non_accetta_file_e_si_riapre(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    assert stat.S_IMODE(fonte.stat().st_mode) == C.MODO_CHIUSA
    with pytest.raises(PermissionError):
        (fonte / "lasciato-qui.txt").write_text("non cifrato")
    C.apri(v["id"], KEY)
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"
    C.chiudi(v["id"])
    assert stat.S_IMODE(fonte.stat().st_mode) == C.MODO_CHIUSA and list(fonte.iterdir()) == []


def test_un_file_messo_nella_cartella_chiusa_viene_nominato(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    os.chmod(fonte, 0o700)  # As if the lock had been removed in Finder.
    (fonte / "foto.png").write_bytes(b"x")
    for operazione in (lambda: C.apri(v["id"], KEY), lambda: C.togli_protezione(v["id"], KEY)):
        with pytest.raises(C.Rifiuto, match="foto.png"):
            operazione()
    (fonte / "foto.png").unlink()
    (fonte / ".DS_Store").write_bytes(b"finder")
    assert C.togli_protezione(v["id"], KEY)["stato"] == "non-protetta"


def test_la_verifica_dice_quale_file_e_perche(C, tmp_path):
    a = {".": {"tipo": "cartella"}, "uno.txt": {"tipo": "file", "byte": 1, "hash": "a", "xattr": {}}}
    b = {".": {"tipo": "cartella"}, "uno.txt": {"tipo": "file", "byte": 1, "hash": "b", "xattr": {}}}
    assert "«uno.txt»: il contenuto è diverso" in C._differenza(a, b, tmp_path)
    b["due.txt"] = {"tipo": "file"}
    assert "«due.txt»: manca nella copia" in C._differenza(a, b, tmp_path)
    a["uno.txt"]["hash"] = "b"
    a["due.txt"] = {"tipo": "file", "xattr": {"com.apple.quarantine": "1"}}
    b["due.txt"] = {"tipo": "file", "xattr": {}}
    assert "com.apple.quarantine" in C._differenza(a, b, tmp_path)


def test_la_quarantena_conta_se_c_e_non_byte_per_byte(C, tmp_path):
    a = {"x": {"tipo": "file", "xattr": {"com.apple.quarantine": "presente"}}}
    assert C._differenza(a, {"x": {"tipo": "file", "xattr": {}}}, tmp_path).count("com.apple.quarantine") == 1
    f = tmp_path / "f"
    f.write_text("x")
    if sys.platform == "darwin":
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "0381;00000000;Safari;", str(f)], check=True)
        uno = C._metadati(f)["xattr"]
        subprocess.run(["/usr/bin/xattr", "-w", "com.apple.quarantine", "0181;00000000;;", str(f)], check=True)
        assert C._metadati(f)["xattr"] == uno == {"com.apple.quarantine": "presente"}


def test_ds_store_riscritto_dal_finder_non_fa_fallire_la_protezione(C, D, albero):
    fonte, _ = albero
    (fonte / ".DS_Store").write_bytes(b"prima")
    D.after_copy = lambda: (fonte / ".DS_Store").write_bytes(b"il Finder l'ha riscritto")
    assert C.proteggi(fonte, None, KEY)["stato"] == "chiusa"


def test_dopo_uno_spegnimento_la_cartella_chiusa_torna_in_sola_lettura(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    C.apri(v["id"], KEY)
    C._stacca(fonte)  # The volume goes away without a close.
    os.chmod(fonte, 0o700)
    assert [x["stato"] for x in C.elenco()] == ["chiusa"]
    assert stat.S_IMODE(fonte.stat().st_mode) == C.MODO_CHIUSA


def test_su_un_disco_senza_proprietari_si_apre_nell_area_di_paratia(C, D, albero, monkeypatch):
    fonte, _ = albero
    monkeypatch.setattr(C, "_senza_proprietari", lambda p: True)
    v = C.proteggi(fonte, None, KEY)
    aperta = C.apri(v["id"], KEY)
    punto = C.CASA / "montaggi" / (v["id"] + "-" + v["nome"])
    assert aperta["stato"] == "aperta" and aperta["montaggio_temporaneo"] == str(punto)
    assert (punto / "segreto.txt").read_text() == "fixture-private-marker"
    assert list(fonte.iterdir()) == [] and stat.S_IMODE(fonte.stat().st_mode) == C.MODO_CHIUSA
    assert C.elenco()[0]["stato"] == "aperta"
    with pytest.raises(C.Rifiuto, match="Chiudi la cartella"):
        C.togli_protezione(v["id"], KEY)
    (punto / "nuovo.txt").write_text("scritto da aperta")
    C.chiudi(v["id"])
    assert not punto.exists() and "montaggio_temporaneo" not in C._carica()["cartelle"][v["id"]]
    C.apri(v["id"], KEY)
    C._stacca(punto)  # Unplugged while open.
    assert C.elenco()[0]["stato"] == "chiusa" and not punto.exists()
    esito = C.togli_protezione(v["id"], KEY)
    assert esito["stato"] == "non-protetta" and (fonte / "nuovo.txt").read_text() == "scritto da aperta"


def test_i_nomi_temporanei_di_togli_sono_quelli_che_il_registro_accetta(C, D, albero, monkeypatch):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    visti = []
    vero = C._salva

    def salva(r):
        voce = r["cartelle"].get(v["id"], {})
        if voce.get("montaggio_temporaneo"):
            visti.append((Path(voce["montaggio_temporaneo"]).name, Path(voce["recupero_temporaneo"]).name))
        vero(r)
    monkeypatch.setattr(C, "_salva", salva)
    C.togli_protezione(v["id"], KEY)
    assert visti and all(m.startswith(v["id"] + "-") and r.startswith("." + fonte.name + ".recupero-") for m, r in visti)


def test_annullare_manda_l_immagine_nel_cestino_e_lascia_la_cartella(C, D, albero, tmp_path):
    fonte, _ = albero
    D.fallisce = ("detach", 1)
    with pytest.raises(C.Rifiuto) as errore:
        C.proteggi(fonte, None, KEY)
    v = C._carica()["cartelle"][errore.value.cartella_id]
    D.fallisce = None
    C._stacca(Path(v["montaggio_temporaneo"]))
    esito = C.annulla_migrazione(v["id"])
    nel_cestino = tmp_path / "cestino-del-test" / Path(v["bundle"]).name
    assert esito["bundle_nel_cestino"] == str(nel_cestino) and nel_cestino.is_dir()
    assert not Path(v["bundle"]).exists() and esito["bundle_eliminato"] is False
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"


def test_annullare_dopo_un_confronto_riuscito_cancella_solo_il_doppione(C, D, albero, tmp_path):
    fonte, _ = albero
    D.fallisce = ("detach", 2)
    with pytest.raises(C.Rifiuto) as errore:
        C.proteggi(fonte, None, KEY)
    D.fallisce = None
    with C._registro() as r:
        v = r["cartelle"][errore.value.cartella_id]
        v["verificato"] = True  # Compared, so the image may be deleted only if the folder matches.
        C._salva(r)
    C._stacca(Path(v["montaggio_temporaneo"]))
    esito = C.annulla_migrazione(v["id"])
    assert esito["bundle_eliminato"] is True and not Path(v["bundle"]).exists()
    assert not any((tmp_path / "cestino-del-test").iterdir())
    assert (fonte / "segreto.txt").read_text() == "fixture-private-marker"


def test_annullare_un_tentativo_non_verificato_non_rilegge_la_cartella(C, D, albero, monkeypatch):
    fonte, _ = albero
    D.fallisce = ("ditto", 1)
    with pytest.raises(C.Rifiuto) as errore:
        C.proteggi(fonte, None, KEY)
    v = C._carica()["cartelle"][errore.value.cartella_id]
    assert v["verificato"] is False
    (fonte / "segreto.txt").write_text("cambiato dopo il tentativo")  # The person's folder, in use.
    monkeypatch.setattr(C, "_scansiona", lambda *a, **k: pytest.fail("the folder was read"))
    assert C.annulla_migrazione(v["id"])["stato"] == "annullata" and C.elenco() == []
    assert (fonte / "segreto.txt").read_text() == "cambiato dopo il tentativo"


def test_due_cartelle_con_lo_stesso_nome_si_proteggono_e_si_aprono(C, D, tmp_path, monkeypatch):
    prima, seconda = tmp_path / "uno" / "documenti", tmp_path / "due" / "documenti"
    for cartella, testo in ((prima, "primo"), (seconda, "secondo")):
        cartella.mkdir(parents=True)
        (cartella / "nota.txt").write_text(testo)
    a, b = C.proteggi(prima, None, KEY), C.proteggi(seconda, None, KEY)
    assert a["id"] != b["id"] and a["bundle"] != b["bundle"]
    C.apri(a["id"], KEY)
    C.apri(b["id"], KEY)
    assert (prima / "nota.txt").read_text() == "primo" and (seconda / "nota.txt").read_text() == "secondo"
    C.chiudi_tutte()
    monkeypatch.setattr(C, "_senza_proprietari", lambda p: True)  # Same names on an external SSD.
    pa, pb = C.apri(a["id"], KEY)["montaggio_temporaneo"], C.apri(b["id"], KEY)["montaggio_temporaneo"]
    assert pa != pb and (Path(pa) / "nota.txt").read_text() == "primo" and (Path(pb) / "nota.txt").read_text() == "secondo"
    C.chiudi_tutte()
    for v in (a, b):
        assert C.togli_protezione(v["id"], KEY)["stato"] == "non-protetta"
    assert (prima / "nota.txt").read_text() == "primo" and (seconda / "nota.txt").read_text() == "secondo"


def test_all_apertura_l_immagine_si_compatta_e_cresce_fino_a_lasciare_un_giga(C, D, albero, monkeypatch):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    vero = C.shutil.disk_usage
    monkeypatch.setattr(C.shutil, "disk_usage", lambda p: vero(p)._replace(free=5 * 1024**3))
    aperta = C.apri(v["id"], KEY)
    comandi = [argv for argv, _ in D.chiamate]
    assert any(a[:2] == [C.HDIUTIL, "compact"] and "-batteryallowed" in a for a in comandi)
    ridimensiona = [a for a in comandi if a[:2] == [C.HDIUTIL, "resize"] and "-size" in a]
    attesa = 20480 * 512 + 4 * 1024**3
    attesa -= attesa % 1024**2
    assert ridimensiona[-1][ridimensiona[-1].index("-size") + 1] == "%dm" % (attesa // 1024**2)
    assert aperta["capacita"] == attesa
    assert all(key == KEY for argv, key in D.chiamate if argv[:2] == [C.HDIUTIL, "resize"])


def test_capacita_che_non_si_adatta_non_impedisce_di_aprire(C, D, albero):
    fonte, _ = albero
    v = C.proteggi(fonte, None, KEY)
    D.fallisce = ("compact", D.conta["compact"] + 1)
    assert C.apri(v["id"], KEY)["stato"] == "aperta"


def test_messaggi_precisi_se_un_file_sparisce_o_non_si_puo_leggere(C, tmp_path):
    radice = tmp_path / "r"
    (radice / "chiusa").mkdir(parents=True)
    (radice / "chiusa" / "x.txt").write_text("x")
    os.chmod(radice / "chiusa", 0)
    try:
        with pytest.raises(C.Rifiuto, match="permesso di leggere «chiusa"):
            C._scansiona(radice)
    finally:
        os.chmod(radice / "chiusa", 0o700)
    with pytest.raises(C.Rifiuto, match="«fantasma.txt» è sparito"):
        C._tutti_xattr(radice / "fantasma.txt")
