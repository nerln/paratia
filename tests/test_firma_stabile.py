"""Firma della copia del registro: ad hoc e identità stabile, solo lettura, senza portachiavi."""
import importlib.util
import subprocess
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
HASH = "a" * 40
ADHOC = "Identifier=it.paratia.app\nSignature=adhoc\nCDHash=" + HASH + "\n"
STABILE = ("Identifier=it.paratia.app\nAuthority=Developer ID Application: Test (ABC123)\n"
           "TeamIdentifier=ABC123\nCDHash=" + HASH + "\n")
SENZA_FIRMA = "Identifier=it.paratia.app\nCDHash=" + HASH + "\n"


def carica(nome):
    spec = importlib.util.spec_from_file_location("firma_" + nome.replace(".", "_"), ROOT / nome)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


I = carica("registro_installa.py")
R = carica("registro.py")


def risposta(testo):
    def run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=testo, stderr="")
    return run


@pytest.mark.parametrize("testo, modo", [(ADHOC, "adhoc"), (STABILE, "stabile")])
def test_installer_accepts_both_signing_modes_and_reports_the_mode(testo, modo):
    app = Path("/tmp/paratia-test/Paratia.app")
    with mock.patch.object(I.subprocess, "run", side_effect=risposta(testo)):
        assert I._firma(app) == HASH
        assert I._modo_firma(app) == modo


def test_installer_refuses_a_signature_it_cannot_classify():
    with mock.patch.object(I.subprocess, "run", side_effect=risposta(SENZA_FIRMA)):
        with pytest.raises(ValueError):
            I._firma(Path("/tmp/paratia-test/Paratia.app"))


def test_unverified_app_defaults_to_the_safe_adhoc_answer():
    assert I._modo_firma(Path("/tmp/paratia-test/mai-verificata.app")) == "adhoc"


@pytest.mark.parametrize("testo, atteso", [(ADHOC, "adhoc"), (STABILE, "stabile"), (SENZA_FIRMA, None)])
def test_registry_status_reads_the_installed_signature_only(testo, atteso):
    with mock.patch.object(R.subprocess, "run", side_effect=risposta(testo)):
        assert R._modo_firma_app() == atteso


def _piano_con_modo(tmp_path, modo):
    # Componenti minimi nella cartella sorgente; la firma e' simulata, nessun codesign.
    fonte = tmp_path / "Paratia.app" / "Contents" / "Resources" / "python"
    fonte.mkdir(parents=True)
    for nome in (*I.CODICE, "registro_installa.py"):
        (fonte / nome).write_text("# sintetico\n", encoding="utf-8")
    eseguibile = Path("/Library/Developer/CommandLineTools/usr/bin/python3")
    with mock.patch.object(I, "_utente", lambda uid: None), \
         mock.patch.object(I, "runtime", lambda: eseguibile), \
         mock.patch.object(I, "_app_sorgente", lambda fonte, uid: (fonte.parents[2], HASH)), \
         mock.patch.object(I, "_modo_firma", lambda app: modo):
        return I.piano(resource_root=fonte, uid=501)


@pytest.mark.parametrize("modo, regrant, firma", [("adhoc", True, "adhoc"), ("stabile", False, "stabile")])
def test_install_plan_regrant_follows_the_signature_mode(tmp_path, modo, regrant, firma):
    piano = _piano_con_modo(tmp_path, modo)
    assert piano["fda_regrant_after_build"] is regrant
    assert piano["firma"] == firma
    assert piano["cdhash"] == HASH
    if regrant:
        assert "rimuovi e aggiungi" in piano["message"]
    else:
        assert "rimuovi e aggiungi" not in piano["message"]
        assert "resta valido" in piano["message"]


@pytest.mark.parametrize("modo, regrant", [("stabile", False), ("adhoc", True), (None, True)])
def test_registry_status_regrant_follows_the_installed_signature(modo, regrant, tmp_path):
    with mock.patch.object(R, "SYSTEM", tmp_path), \
         mock.patch.object(R, "_modo_firma_app", lambda: modo), \
         mock.patch.object(R, "_servizio_installato", lambda uid: (True, "app")), \
         mock.patch.object(R, "verifica_catena", lambda percorso: {"ok": True, "errore": None}):
        dati = R.stato()
    assert dati["fda_regrant_after_build"] is regrant
    assert ("stesso certificato" in dati["fda_message"]) is (not regrant)
    assert ("rimuovi e aggiungi" in dati["fda_message"]) is regrant


def test_installer_refuses_when_codesign_verification_fails():
    def fallisce(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv)
    with mock.patch.object(I.subprocess, "run", side_effect=fallisce):
        with pytest.raises(ValueError):
            I._firma(Path("/tmp/paratia-test/Paratia.app"))


def test_installer_refuses_a_stable_signature_with_another_identifier():
    altro = STABILE.replace("it.paratia.app", "it.altro.app")
    with mock.patch.object(I.subprocess, "run", side_effect=risposta(altro)):
        with pytest.raises(ValueError):
            I._firma(Path("/tmp/paratia-test/Paratia.app"))


def test_registry_status_needs_exit_code_zero_and_the_fixed_identifier():
    def fallisce(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=STABILE, stderr="")
    with mock.patch.object(R.subprocess, "run", side_effect=fallisce):
        assert R._modo_firma_app() is None
    altro = STABILE.replace("it.paratia.app", "it.altro.app")
    with mock.patch.object(R.subprocess, "run", side_effect=risposta(altro)):
        assert R._modo_firma_app() is None
    with mock.patch.object(R.subprocess, "run", side_effect=risposta(ADHOC.replace("it.paratia.app", "it.altro.app"))):
        assert R._modo_firma_app() is None


def test_registry_status_treats_undecodable_output_as_unknown():
    def decodifica(argv, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "byte non valido")
    with mock.patch.object(R.subprocess, "run", side_effect=decodifica):
        assert R._modo_firma_app() is None


def test_update_step_for_the_full_disk_access_entry_holds_in_both_modes():
    # Il passo 5 vale con firma ad hoc e con firma stabile: niente «rimuovi sempre».
    passo = R.PASSI_AGGIORNAMENTO[4]
    assert "Se la firma è cambiata, rimuovi e aggiungi di nuovo la voce" in passo
    assert "Non autorizzare Python" in passo
    assert "e abilitala" not in passo
