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
    opening = swift_method("askKey").split('perform(tr("Controllo dello stato della cartella…"))', 1)[1]
    assert opening.index('worker.request("cartelle.prepara_apertura"') < opening.index('ready.flag("gia_aperta")')
    assert opening.index('ready.flag("gia_aperta")') < opening.index("return") < opening.index("KeyRequest(")
    assert opening.index('guard ready.flag("pronto")') < opening.index("KeyRequest(")
    bank = swift_method("runBank")
    assert bank.index('worker.request("banco.anteprima"') < bank.index("KeyRequest(")


def test_gui_checks_root_protected_bundle_before_loading_installer_plan():
    install = swift_method("installRegistry")
    assert install.index("NativeInstall.validateBootstrap") < install.index('worker.request("registro.install_plan"')
    assert install.index("NativeInstall.validateBootstrap") < install.index("NSAlert()")


@pytest.mark.parametrize("exception_name,code,expected", [
    ("VolumeOccupato", "volume_busy", "terminale aperto dentro"),
    ("DiscoNonDisponibile", "disk_unavailable", "Collegalo"),
    ("ImmagineDanneggiata", "damaged_image", "danneggiata o incompleta"),
])
def test_busy_and_unavailable_disks_have_distinct_safe_worker_messages(W, monkeypatch, exception_name, code, expected):
    error = type(exception_name, (Exception,), {})

    def fail(*args, **kwargs):
        raise error("unsafe backend stream: " + KEY.decode())

    action = "cartelle.chiudi" if code == "volume_busy" else "cartelle.prepara_apertura"
    function = "chiudi" if code == "volume_busy" else "prepara_apertura"
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(**{function: fail}))
    result = request(W, action, {"id": "fixture"})
    assert result["ok"] is False and result["code"] == code and expected in result["message"]
    assert "unsafe" not in json.dumps(result) and KEY.decode() not in json.dumps(result)
    if code in ("disk_unavailable", "damaged_image"):
        assert "Recupera" not in result["message"] and "Annulla" not in result["message"]
    if code == "damaged_image":
        assert "reinser" not in result["message"].lower()
        assert "conserva" in result["message"].lower()


@pytest.mark.parametrize("force", [False, True])
def test_worker_force_is_an_explicit_boolean_for_one_folder(W, monkeypatch, force):
    calls = []
    monkeypatch.setattr(W, "_load", lambda name: SimpleNamespace(chiudi=lambda *args, **kwargs: calls.append((args, kwargs)) or {"stato": "chiusa"}))
    result = request(W, "cartelle.chiudi", {"id": "fixture", "force": force})
    assert result["ok"] and calls == [(("fixture",), {"force": force})]
    result = request(W, "cartelle.chiudi_tutte", {"force": True})
    assert result["code"] == "invalid_params" and len(calls) == 1


@pytest.mark.parametrize("force", ["true", 1, None])
def test_worker_refuses_truthy_force_and_keys_before_disk_backend(W, monkeypatch, force):
    monkeypatch.setattr(W, "_load", lambda name: pytest.fail("Invalid force reached backend"))
    result = request(W, "cartelle.chiudi", {"id": "fixture", "force": force})
    assert result["code"] == "invalid_params"
    result = request(W, "cartelle.chiudi", {"id": "fixture", "force": True}, KEY)
    assert result["code"] == "unexpected_key"


def test_gui_force_close_requires_explicit_second_button_confirmation():
    force = swift_method("forceClose")
    assert force.index('alert.addButton(withTitle: tr("Annulla"))') < force.index('alert.addButton(withTitle: tr("Chiudi forzatamente"))')
    assert force.index("guard alert.runModal() == .alertSecondButtonReturn else { return }") < force.index('worker.request("cartelle.chiudi"')
    assert '"force": true' in force and "modifiche non salvate" in force
    assert 'if folder.isIncomplete' in force and "migrazione resta incompleta" in force
    assert force.index("self.captureWarnings(result)") < force.index("self.warning.map")
    assert '?? recoveryNotice' in force
    cards = (ROOT / "macos" / "Views.swift").read_text().split("struct FolderCard", 1)[1]
    incomplete = cards.split("if folder.isIncomplete {", 1)[1].split('} else if folder.state == "aperta"', 1)[0]
    assert 'folder.data.text("montaggio_temporaneo", fallback: "")' in incomplete
    assert "model.close(folder)" in incomplete and "model.forceClose(folder)" in incomplete
    normal = swift_method("close")
    assert '"force"' not in normal
    assert 'ready.text("messaggio"' in swift_method("askKey")


def test_registry_view_distinguishes_zero_events_from_inactive_or_unknown_collection():
    app = (ROOT / "macos" / "AppModel.swift").read_text()
    assert '@Published var eventsKernelActive: Bool?' in app
    query = app.split('private func refreshEvents()', 1)[1].split('\n    func ', 1)[0]
    assert 'eventsKernelActive = result["kernel_active"] as? Bool' in query
    assert 'result["kernel_collection"] as? Record' in query
    export = swift_method("export")
    assert 'action == "registro.export_csv"' in export and 'result["kernel_active"] as? Bool' in export
    view = (ROOT / "macos" / "Views.swift").read_text().split('struct RegistryView', 1)[1]
    counter = view.split('plurale(model.eventTotal', 1)[1].split('Button(tr("Apri dettaglio"))', 1)[0]
    for state in ('"Raccolta kernel attiva"', '"Raccolta kernel inattiva"', '"Raccolta kernel da verificare"'):
        assert state in counter
    assert 'Text(model.eventsKernelMessage)' in view
    watch = swift_method("watchFolder")
    assert 'result.text("messaggio"' in watch and '"nome":' not in watch


def test_gui_keeps_refused_folder_reason_visible_before_global_health_and_missing_path():
    status = swift_method("watchStatus")
    assert 'registry["watch_status"] as? [Record]' in status
    refusal = status.index('return tr("Rifiutata dal raccoglitore: ") + message')
    assert status.index('"rejected"') < refusal < status.index('record["esiste"] as? Bool == false')
    assert refusal < status.index('registry.flag("running")')
    # Acceptance of an ID and health of the entire stream are separate states.
    assert 'registry.flag("healthy")' not in status
    view = (ROOT / "macos" / "Views.swift").read_text()
    assert 'Text(model.watchStatus(folder))' in view
    assert 'Text(tr("Registro: ") + model.watchStatus(folder.data))' in view


def test_confirmed_watch_warning_is_visible_before_missing_path_with_matching_token():
    status = swift_method("watchStatus")
    assert 'let token = record.text("configuration_token", fallback: "")' in status
    assert 'token.isEmpty || $0.text("configuration_token", fallback: "") == token' in status
    warning = status.index('return tr("Confermata dal raccoglitore · ") + warning')
    assert status.index('return tr("Rifiutata dal raccoglitore: ") + message') < warning
    assert warning < status.index('record["esiste"] as? Bool == false')


def test_native_installer_keeps_json_failure_message_and_error_code():
    native = (ROOT / "macos" / "NativeInstall.swift").read_text()
    decode = native.split('static func decodeInstallationResponse(', 1)[1].split('static func execute(', 1)[0]
    assert 'JSONSerialization.jsonObject(with: response)' in decode
    assert 'CFGetTypeID(installed) == CFBooleanGetTypeID()' in decode
    assert 'guard installed.boolValue' in decode
    assert 'result["message"] as? String' in decode and 'result["error_code"] as? String' in decode
    assert 'throw AppError(message: String(message.prefix(2048)) + tr("\\nCodice: ")' in decode
    assert 'return try decodeInstallationResponse(response)' in native
    assert 'Il servizio non ha confermato l\'installazione' not in native


def test_gui_shows_health_reasons_and_separates_event_latency_from_silent_stream_age():
    app = (ROOT / "macos" / "AppModel.swift").read_text()
    query = app.split('private func refreshEvents()', 1)[1].split('\n    func ', 1)[0]
    assert 'eventsKernelCollection = collection' in query
    assert 'self.eventsKernelCollection = collection' in swift_method("export")
    metrics = swift_method("collectionMetrics")
    age = swift_method("lastEventAge")
    assert '"event_lag_seconds"' in metrics and '"lines_per_second"' in metrics
    assert '"last_event_age_seconds"' not in metrics
    assert 'value.isFinite' in metrics and 'value >= 0' in metrics
    assert '"last_event_age_seconds"' in age and 'silenzio non prova un ritardo' in age
    view = (ROOT / "macos" / "Views.swift").read_text()
    assert view.count('RegistryHealthDetails(model: model, record: model.registry)') == 2
    assert 'RegistryHealthDetails(model: model, record: model.eventsKernelCollection)' in view
    details = view.split('struct RegistryHealthDetails:', 1)[1].split('struct RegistryUpdateSteps:', 1)[0]
    assert 'model.healthReasons(record)' in details and 'reason.text("message")' in details
    assert 'prettyJSON' not in details


def test_gui_shows_ordered_update_steps_only_for_a_known_build_mismatch():
    view = (ROOT / "macos" / "Views.swift").read_text()
    steps = view.split('struct RegistryUpdateSteps:', 1)[1].split('struct EventDetail:', 1)[0]
    assert 'if model.registry.flag("needs_update")' in steps
    assert 'model.registry.text("update_message"' in steps
    assert 'Aggiorna il registro e verifica la build installata.' in steps
    assert 'model.registryUpdateSteps.enumerated()' in steps
    assert 'Text("\\(index + 1). \\(step)")' in steps
    settings = view.split('struct SettingsView:', 1)[1]
    assert settings.index('RegistryUpdateSteps(model: model)') < settings.index('GroupBox(tr("Registro kernel"))')
    assert 'Versione del servizio: non ancora verificata.' in settings
    registry = view.split('struct RegistryView:', 1)[1].split('struct RegistryHealthDetails:', 1)[0]
    assert 'Label(model.registry.text("update_message"' in registry
    assert 'Button(tr("Passi per aggiornare…")) { model.section = .settings }' in registry


def test_gui_refresh_invalidates_old_query_health_without_discarding_history_or_requerying():
    refresh = swift_method("refresh")
    state = refresh.index('registry = try await worker.request("registro.stato")')
    for invalidation in ('eventsKernelActive = nil', 'eventsKernelCollection = [:]',
                         'eventsKernelMessage = tr("Stato della ricerca precedente da verificare: ripeti la ricerca.")'):
        assert state < refresh.index(invalidation)
    # Refresh observes current collection status; displayed history survives
    # until the user reruns the filters and gets new query-scoped metadata.
    assert 'events =' not in refresh and 'eventTotal =' not in refresh
    assert 'eventsTruncated =' not in refresh
    assert 'worker.request("registro.query"' not in refresh and 'refreshEvents()' not in refresh
