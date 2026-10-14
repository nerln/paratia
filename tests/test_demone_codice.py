"""Il demone controlla gli stessi file di codice che l'installer copia, e il bootstrap li verifica."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def carica(nome):
    spec = importlib.util.spec_from_file_location("demone_" + nome.replace(".", "_"), ROOT / nome)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def test_daemon_checks_every_file_the_installer_copies_as_code():
    installer = carica("registro_installa.py")
    demone = carica("registro_daemon.py")
    assert set(demone.CODICE_DEMONE) == set(installer.CODICE)
    assert "messaggi.py" in demone.CODICE_DEMONE


def test_bootstrap_verifies_the_message_catalogue_as_root_code():
    swift = (ROOT / "macos" / "NativeInstall.swift").read_text(encoding="utf-8")
    assert '"Contents/Resources/python/messaggi.py"' in swift
