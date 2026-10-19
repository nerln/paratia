"""Lingua dei messaggi: catalogo it/en/es, segnaposto, worker e frasi non tradotte."""
import ast
import importlib.util
import io
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lessico_italiano import contiene_italiano  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MODULI_PYTHON = ["gui_worker.py", "cartelle.py", "registro.py", "banco.py", "hookinstaller.py",
                 "registro_installa.py", "catena.py"]
# Testi che non arrivano alla persona: confronti con l'output di sistema e
# messaggi verso il server di Claude Code. Restano nella lingua del sorgente.
NON_VISIBILI = {"errore di autenticazione", "password errata", "unreadable regular file required",
                "Serve consenso umano; il banco non approva richieste del server.",
                "Banco sintetico Paratia: open/fstat senza lettura dei byte"}
PAROLE = re.compile(r"\b(il|la|lo|gli|le|di|da|del|della|delle|dei|degli|non|per|che|una|uno|con|sul|nel|nella|sono|alla|questa|questo|dopo|prima|come|senza|dal|se|anche|ancora|solo|ogni|quando|file|cartella|disco|errore|registro|accesso|verifica|servizio|scegli|conserva|riprova)\b", re.IGNORECASE)


def _catalogo():
    spec = importlib.util.spec_from_file_location("messaggi_test", ROOT / "messaggi.py")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_every_key_has_english_and_spanish_with_the_same_placeholders():
    catalogo = _catalogo()
    assert catalogo.LINGUE == ("it", "en", "es")
    for testo, (en, es) in catalogo.TRADUZIONI.items():
        assert en.strip() and es.strip(), testo
        segnaposto = set(re.findall(r"\{(\w+)\}", testo))
        assert set(re.findall(r"\{(\w+)\}", en)) == segnaposto, testo
        assert set(re.findall(r"\{(\w+)\}", es)) == segnaposto, testo
        assert re.findall(r"%[ds]", en) == re.findall(r"%[ds]", testo), testo
        assert re.findall(r"%[ds]", es) == re.findall(r"%[ds]", testo), testo


def test_translations_are_not_copies_of_italian_text():
    catalogo = _catalogo()
    for testo, (en, es) in catalogo.TRADUZIONI.items():
        if len(testo) > 12:
            assert en != testo and es != testo, testo


def test_default_language_is_italian_and_format_placeholders_are_applied(monkeypatch):
    catalogo = _catalogo()
    assert catalogo.imposta("xx") == "it"
    assert catalogo.t("Configurazione rimossa.") == "Configurazione rimossa."
    assert catalogo.imposta("es") == "es"
    assert catalogo.t("Configurazione rimossa.") == "Configuración eliminada."
    chiave = "Una copia plaintext di recupero è ancora presente: {residuo}"
    assert catalogo.t(chiave, residuo="/x") .endswith("/x")
    assert catalogo.imposta("it") == "it"


CHIAVE_AZIONE = "L'operazione richiesta non è disponibile nell'app. Aggiorna Paratia."


@pytest.mark.parametrize("lingua, indice", [("en", 0), ("es", 1), ("it", None)])
def test_worker_speaks_the_language_sent_by_the_app(tmp_path, lingua, indice):
    # La GUI passa la lingua nella variabile PARATIA_LANG del processo worker.
    # Un'azione sconosciuta produce un messaggio fisso, senza toccare dati reali.
    (tmp_path / "gui_worker.py").write_bytes((ROOT / "gui_worker.py").read_bytes())
    (tmp_path / "messaggi.py").write_bytes((ROOT / "messaggi.py").read_bytes())
    env = dict(os.environ, PARATIA_LANG=lingua)
    result = subprocess.run([sys.executable, "-I", "-S", str(tmp_path / "gui_worker.py"), "azione.inesistente"],
                            input=b"", capture_output=True, env=env, timeout=20)
    risposta = json.loads(result.stdout.decode("utf-8"))
    assert risposta["ok"] is False and risposta["code"] == "invalid_action"
    atteso = CHIAVE_AZIONE if indice is None else _catalogo().TRADUZIONI[CHIAVE_AZIONE][indice]
    assert risposta["message"] == atteso


def _stringhe_italiane_non_tradotte(percorso):
    """Frasi italiane nel modulo che non passano da _t() e non sono chiavi del catalogo."""
    albero = ast.parse(percorso.read_text(encoding="utf-8"))
    catalogo = _catalogo().TRADUZIONI
    padri = {}
    for nodo in ast.walk(albero):
        for figlio in ast.iter_child_nodes(nodo):
            padri[figlio] = nodo
    trovate = []
    for nodo in ast.walk(albero):
        if not (isinstance(nodo, ast.Constant) and isinstance(nodo.value, str)):
            continue
        valore, padre = nodo.value, padri.get(nodo)
        if isinstance(padre, ast.Expr):
            continue  # docstring
        if (isinstance(padre, ast.Call) and isinstance(padre.func, ast.Name)
                and padre.func.id in ("_t", "t") and padre.args and padre.args[0] is nodo):
            continue  # già tradotta
        if valore in catalogo or valore in NON_VISIBILI or " " not in valore.strip():
            continue  # chiavi del catalogo, testi non visibili, identificatori e codici
        if contiene_italiano(valore):
            trovate.append((nodo.lineno, valore[:80]))
    return trovate


@pytest.mark.parametrize("nome", MODULI_PYTHON)
def test_no_italian_prose_escapes_the_message_catalog(nome):
    # Le frasi italiane visibili passano da _t(...); un nuovo testo italiano va aggiunto al catalogo.
    assert _stringhe_italiane_non_tradotte(ROOT / nome) == []


def test_daemon_state_messages_are_catalogue_keys_for_the_gui_to_translate():
    # Il demone scrive lo stato in italiano; la GUI lo traduce con t() nella lingua scelta.
    catalogo = _catalogo().TRADUZIONI
    for testo in ("Verifica /Applications/Paratia.app in Accesso completo al disco. "
                  "Se la firma è cambiata dopo una nuova build, rimuovi e aggiungi di nuovo quella voce.",
                  "Il servizio usa il launcher Python precedente. Reinstalla il registro da Paratia; "
                  "la voce Accesso completo al disco da verificare è /Applications/Paratia.app.",
                  "Il registro kernel è fermo.",
                  "Il formato di eslogger non è compatibile: aggiorna Paratia."):
        assert testo in catalogo, testo


def test_a_filled_in_message_is_still_known_but_invented_text_is_not():
    import messaggi as m
    assert m.noto("La verifica non è riuscita su «foto.png»: il contenuto è diverso. Nessun file è stato cancellato.")
    assert m.noto("The check failed on “foto.png”: its content differs. No file was deleted.")
    assert not m.noto("Traceback: something private")
