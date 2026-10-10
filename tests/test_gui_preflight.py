"""Secret-free worker preflight and source checks for the unbuilt Swift GUI."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEY = b"synthetic-preflight-only-key-123"


def frame(params, key=b""):
    raw = json.dumps(params).encode()
    return struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(key)) + key


@pytest.fixture()
def W(monkeypatch):
    spec = importlib.util.spec_from_file_location("preflight_worker_test", ROOT / "gui_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_muted_output", contextlib.nullcontext)
    return module


def request(W, action, params, key=b""):
    output = io.StringIO()
    assert W.main(["worker", action], io.BytesIO(frame(params, key)), output) == 0
    return json.loads(output.getvalue())


@pytest.mark.parametrize("action,params", [
    ("cartelle.prepara_protezione", {"origine": "/fixture/source", "dove": "/fixture/external", "minutes": 7}),
    ("cartelle.prepara_apertura", {"id": "fixture", "minutes": 7}),
])
def test_preflight_routes_require_no_key_and_reject_key_before_backend(W, monkeypatch, action, params):
    calls = []
    backend = SimpleNamespace(**{action.split(".")[1]: lambda *args, **kwargs: calls.append((args, kwargs)) or {"pronto": True}})
    monkeypatch.setattr(W, "_load", lambda name: backend)
    result = request(W, action, params)
    assert result["ok"] and result["result"]["pronto"]
    assert len(calls) == 1 and calls[0][1] == {"minutes": 7}
    assert all(not isinstance(arg, bytes) for arg in calls[0][0])
    result = request(W, action, params, KEY)
    assert result["code"] == "unexpected_key" and len(calls) == 1
    assert KEY.decode() not in json.dumps(result)


def test_wrong_key_has_distinct_safe_worker_category(W, monkeypatch):
    class ChiaveErrata(Exception):
        pass

    def fail(*args, **kwargs):
        raise ChiaveErrata("unsafe backend text: " + KEY.decode())

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(apri=fail))
    result = request(W, "cartelle.apri", {"id": "fixture"}, KEY)
    assert result["ok"] is False and result["code"] == "wrong_key"
    assert "chiave" in result["message"] and "Inseriscila" in result["message"]
    assert KEY.decode() not in json.dumps(result) and "unsafe" not in json.dumps(result)


def test_invalid_destination_explains_physical_disk_requirement_without_key(W, monkeypatch):
    class Rifiuto(Exception):
        pass

    def fail(*args, **kwargs):
        raise Rifiuto("unsafe diagnostic: " + KEY.decode())

    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(prepara_protezione=fail))
    result = request(W, "cartelle.prepara_protezione", {"origine": "/fixture/source", "dove": "/fixture/disk-image"})
    assert result["code"] == "refused" and "immagini disco non sono accettati" in result["message"]
    assert KEY.decode() not in json.dumps(result)


def swift_method(name):
    source = (ROOT / "macos" / "AppModel.swift").read_text()
    start = source.index("    func " + name + "(")
    end = source.find("\n    func ", start + 1)
    return source[start:end if end >= 0 else len(source)]


def test_gui_checks_destination_and_open_state_before_creating_key_requests():
    protect = swift_method("protectFolder")
    assert protect.index('worker.request("cartelle.prepara_protezione"') < protect.index("KeyRequest(")
    opening = swift_method("askKey").split('perform("Controllo dello stato della cartella…")', 1)[1]
    assert opening.index('worker.request("cartelle.prepara_apertura"') < opening.index('ready.flag("gia_aperta")')
    assert opening.index('ready.flag("gia_aperta")') < opening.index("return") < opening.index("KeyRequest(")
    assert opening.index('guard ready.flag("pronto")') < opening.index("KeyRequest(")
    bank = swift_method("runBank")
    assert bank.index('worker.request("banco.anteprima"') < bank.index("KeyRequest(")


def test_gui_checks_root_protected_bundle_before_loading_installer_plan():
    install = swift_method("installRegistry")
    assert install.index("NativeInstall.validateBootstrap") < install.index('worker.request("registro.install_plan"')
    assert install.index("NativeInstall.validateBootstrap") < install.index("NSAlert()")
