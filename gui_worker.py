#!/usr/bin/env python3
"""One framed request from the native app; one JSON response, without secrets.

The app supplies an allowlisted action in argv and sends parameters plus a raw
UTF-8 passphrase through stdin. This is a local transport, not an authentication
boundary against other processes running as the same user. Python 3.9 and the
standard library suffice, including under ``-I -S``.
"""
from __future__ import annotations


def _t(testo, **valori):
    """Testo per la lingua della GUI; senza lingua impostata, quello italiano."""
    import importlib.util
    import os
    import sys
    nome = "paratia_messaggi"
    if nome not in sys.modules:
        percorso = os.path.join(os.path.dirname(os.path.abspath(__file__)), "messaggi.py")
        spec = importlib.util.spec_from_file_location(nome, percorso)
        modulo = importlib.util.module_from_spec(spec)
        sys.modules[nome] = modulo
        spec.loader.exec_module(modulo)
    return sys.modules[nome].t(testo, **valori)


def _messaggio_noto(exc):
    """A refusal written for the person is shown as is; anything else stays generic."""
    import sys
    _t("")  # loads the messages module
    testo = str(exc)
    return bool(testo) and sys.modules["paratia_messaggi"].noto(testo)

import contextlib
import csv
import datetime
import importlib.util
import io
import json
import os
import stat
import struct
import sys
from pathlib import Path

# These modules live inside a sealed app bundle. Loading a worker must not
# create __pycache__ there and invalidate the signature used for TCC.
sys.dont_write_bytecode = True

MAX_METADATA = 1024 * 1024
MAX_KEY = 4096
MAX_ROWS = 2500
RESOURCE_ROOT = Path(__file__).resolve().parent

# Required fields, optional fields. No user input selects a module or callable.
SCHEMAS = {
    "cartelle.elenco": (set(), set()),
    "cartelle.prepara_protezione": ({"origine", "dove"}, {"minutes"}),
    "cartelle.prepara_apertura": ({"id"}, {"minutes"}),
    "cartelle.proteggi": ({"origine", "dove"}, {"minutes"}),
    "cartelle.apri": ({"id"}, {"minutes"}),
    "cartelle.chiudi": ({"id"}, {"force"}),
    "cartelle.chiudi_tutte": (set(), set()),
    "cartelle.recupera": ({"id"}, set()),
    "cartelle.annulla": ({"id"}, set()),
    "registro.stato": (set(), set()),
    "registro.elenco_sorveglianza": (set(), set()),
    "registro.sorveglia": ({"id", "percorso"}, {"nome"}),
    "registro.rimuovi_sorveglianza": ({"id"}, set()),
    "registro.query": (set(), {"filters"}),
    "registro.verifica": (set(), set()),
    "registro.export_csv": ({"path"}, {"filters"}),
    "registro.install_plan": (set(), set()),
    "etichette.sfoglia": ({"radice"}, {"mostra_nascosti"}),
    "etichette.segna": ({"percorso", "etichetta"}, {"nota"}),
    "etichette.togli": ({"percorso"}, set()),
    "etichette.elenco": (set(), set()),
    "etichette.piano": (set(), set()),
    "banco.anteprima": (set(), {"path", "dove"}),
    "banco.storico": (set(), set()),
    "banco.run": ({"dove", "agenti_reali"}, {"minutes"}),
    "banco.export_json": ({"path"}, set()),
    "banco.export_csv": ({"path"}, set()),
    "hooks.stato": (set(), set()),
    "hooks.install_plan": (set(), set()),
    "hooks.applica": (set(), set()),
    "hooks.ripristina": ({"path"}, set()),
}
KEY_ACTIONS = {"cartelle.proteggi", "cartelle.apri", "cartelle.recupera", "banco.run"}
FILTERS = {"folder", "file", "process", "agent", "since", "until"}
REGISTRY_ERRORS = {
    "folder_not_configured": _t("La cartella non è configurata nel registro. Scegli una cartella dall'elenco o aggiungi una sorveglianza."),
    "folder_ambiguous": _t("Il percorso corrisponde a più ID. Scegli l'ID della cartella dall'elenco del registro."),
    "protected_folder_watch": _t("Questo percorso appartiene a una cartella protetta già configurata. Seleziona la cartella nel Registro; non aggiungere una sorveglianza separata."),
}
_MODULES = {}


class RequestError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def _request_error():
    return RequestError("invalid_request", _t("La richiesta dell'app è incompleta o non valida. Riprova l'operazione."))


def _read_exact(stream, count):
    pieces = []
    remaining = count
    while remaining:
        part = stream.read(remaining)
        if not isinstance(part, bytes) or not part:
            raise _request_error()
        pieces.append(part)
        remaining -= len(part)
    return b"".join(pieces)


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise _request_error()
        result[name] = value
    return result


def _constant(_):
    raise _request_error()


def read_frame(stream):
    length = struct.unpack(">I", _read_exact(stream, 4))[0]
    if not 1 <= length <= MAX_METADATA:
        raise _request_error()
    raw = _read_exact(stream, length)
    try:
        params = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                            parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise _request_error() from None
    if not isinstance(params, dict):
        raise _request_error()
    key_length = struct.unpack(">I", _read_exact(stream, 4))[0]
    if key_length > MAX_KEY:
        raise _request_error()
    key = _read_exact(stream, key_length)
    if stream.read(1) != b"":
        raise _request_error()
    return params, key


def _invalid_params():
    return RequestError("invalid_params", _t("I dati dell'operazione non sono validi. Controlla i campi e riprova."))


def _text(value, maximum=16384, empty=False):
    if not isinstance(value, str) or len(value) > maximum or "\0" in value or (not empty and not value):
        raise _invalid_params()
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise _invalid_params() from None
    return value


def _absolute(value):
    value = _text(value)
    if not os.path.isabs(value):
        raise RequestError("invalid_params", _t("Scegli un percorso assoluto con il selettore dell'app."))
    return value


def _contains_key(value, key_text):
    if isinstance(value, str):
        return key_text in value
    if isinstance(value, list):
        return any(_contains_key(v, key_text) for v in value)
    if isinstance(value, dict):
        return any(_contains_key(k, key_text) or _contains_key(v, key_text) for k, v in value.items())
    return False


def _validate(action, params, key):
    if action not in SCHEMAS:
        raise RequestError("invalid_action", _t("L'operazione richiesta non è disponibile nell'app. Aggiorna Paratia."))
    required, optional = SCHEMAS[action]
    if not isinstance(params, dict) or not required <= params.keys() or not params.keys() <= required | optional:
        raise _invalid_params()
    if action in KEY_ACTIONS:
        if not key:
            raise RequestError("missing_key", _t("Inserisci la chiave nel campo sicuro dell'app."))
        if not isinstance(key, bytes) or not 12 <= len(key) <= MAX_KEY or any(c in key for c in (b"\0", b"\n", b"\r")):
            raise RequestError("invalid_key", _t("La chiave deve avere almeno 12 byte, senza byte nulli o terminatori di riga."))
        try:
            key_text = key.decode("utf-8")
        except UnicodeError:
            raise RequestError("invalid_key", _t("La chiave deve contenere testo UTF-8 valido. Inseriscila di nuovo.")) from None
        if _contains_key(params, key_text):
            raise RequestError("invalid_params", _t("La chiave deve essere inserita soltanto nel campo sicuro dell'app."))
    elif key:
        raise RequestError("unexpected_key", _t("Questa operazione non richiede una chiave. Riprova dall'app."))
    for name in ("origine", "dove", "path", "radice", "percorso"):
        if name in params:
            _absolute(params[name])
    if "id" in params:
        identifier = _text(params["id"], 128)
        if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in identifier):
            raise _invalid_params()
    if "minutes" in params and (type(params["minutes"]) is not int or not 1 <= params["minutes"] <= 1440):
        raise RequestError("invalid_params", _t("La chiusura automatica deve durare da 1 a 1440 minuti."))
    for name in ("mostra_nascosti", "agenti_reali", "force"):
        if name in params and type(params[name]) is not bool:
            raise _invalid_params()
    for name in ("etichetta", "nota", "nome"):
        if name in params:
            _text(params[name], empty=(name in ("nota", "nome")))
    if "etichetta" in params:
        label = params["etichetta"]
        if label not in ("riservato", "pubblico") and not (label.startswith("zona:") and len(label) > 5 and "/" not in label[5:] and not label[5:].startswith(".")):
            raise RequestError("invalid_params", _t("Scegli riservato, pubblico oppure zona:nome come etichetta."))
    if "filters" in params:
        filters = params["filters"]
        if not isinstance(filters, dict) or not filters.keys() <= FILTERS:
            raise _invalid_params()
        for name, value in filters.items():
            if name == "agent" and (value is None or type(value) is bool):
                continue
            _text(value, empty=True)
            if name in ("since", "until") and value:
                try:
                    timestamp = value.replace("Z", "+00:00")
                    if len(timestamp) >= 5 and timestamp[-5] in "+-" and timestamp[-4:].isdigit():
                        timestamp = timestamp[:-2] + ":" + timestamp[-2:]
                    datetime.datetime.fromisoformat(timestamp)
                except ValueError:
                    raise RequestError("invalid_params", _t("Controlla l'intervallo di tempo: usa date e ore valide.")) from None


def _load(name, optional=False):
    if name in _MODULES:
        return _MODULES[name]
    path = RESOURCE_ROOT / (name + ".py")
    if not path.is_file() or path.is_symlink():
        if optional:
            raise RequestError("pending", _t("Questa funzione non è ancora disponibile in questa versione dell'app. Aggiorna Paratia."))
        raise RequestError("unavailable", _t("Manca un componente dell'app. Ricostruisci o reinstalla Paratia."))
    spec = importlib.util.spec_from_file_location("paratia_gui_" + name, path)
    if spec is None or spec.loader is None:
        raise RequestError("unavailable", _t("Un componente dell'app non può essere caricato. Reinstalla Paratia."))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    _MODULES[name] = module
    return module


def _function(module, name):
    function = getattr(module, name, None)
    if not callable(function):
        raise RequestError("pending", _t("Questa funzione non è ancora disponibile in questa versione dell'app. Aggiorna Paratia."))
    return function


def _parent_fd(path):
    # Walk each component with O_NOFOLLOW, retaining the final directory fd.
    # A later directory rename cannot redirect a write through a symlink.
    if path == "/" or any(p in ("", ".", "..") for p in path[1:].split("/")):
        raise RequestError("invalid_params", _t("Scegli un nome di file valido per l'esportazione."))
    parts = path[1:].split("/")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                # ELOOP and ENOTDIR both occur for symlink directories on macOS.
                try:
                    is_link = stat.S_ISLNK(os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode)
                except OSError:
                    is_link = False
                if is_link:
                    raise RequestError("unsafe_path", _t("L'esportazione rifiuta i collegamenti simbolici. Scegli una cartella reale.")) from None
                raise exc
            os.close(fd)
            fd = next_fd
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def _check_destination(fd, name):
    try:
        mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise RequestError("unsafe_path", _t("L'esportazione rifiuta i collegamenti simbolici. Scegli un file reale."))
    if not stat.S_ISREG(mode):
        raise RequestError("unsafe_path", _t("La destinazione dell'esportazione deve essere un file. Scegli un altro nome."))


def _export(path, contents, count):
    if not isinstance(contents, str):
        raise RequestError("internal_error", _t("L'app non ha prodotto un'esportazione valida. Aggiorna Paratia e riprova."))
    data = contents.encode("utf-8")
    parent, name = _parent_fd(path)
    temporary = ".paratia-export-" + os.urandom(16).hex()
    created = False
    try:
        _check_destination(parent, name)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        created = True
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        _check_destination(parent, name)
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        created = False
        os.fsync(parent)
    finally:
        if created:
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)
    return {"path": path, "count": count, "bytes": len(data)}


def _csv_count(contents):
    if not isinstance(contents, str):
        raise RequestError("internal_error", _t("L'app non ha prodotto un'esportazione valida. Aggiorna Paratia e riprova."))
    return max(0, sum(1 for _ in csv.reader(io.StringIO(contents, newline=""))) - 1)


def dispatch(action, params, key=b""):
    _validate(action, params, key)
    group, verb = action.split(".", 1)
    if group == "cartelle":
        module = _load("cartelle")
        if verb == "prepara_protezione":
            return module.prepara_protezione(params["origine"], params["dove"], minutes=params.get("minutes", 15))
        if verb == "prepara_apertura":
            return module.prepara_apertura(params["id"], minutes=params.get("minutes", 15))
        if verb == "proteggi":
            return module.proteggi(params["origine"], params["dove"], key, minutes=params.get("minutes", 15))
        if verb == "apri":
            return module.apri(params["id"], key, minutes=params.get("minutes", 15))
        if verb == "recupera":
            return module.recupera(params["id"], key)
        if verb == "chiudi":
            return module.chiudi(params["id"], **({"force": params["force"]} if "force" in params else {}))
        if verb == "annulla":
            return module.annulla_migrazione(params["id"])
        return getattr(module, verb)()
    if group == "registro":
        if verb == "install_plan":
            return _load("registro_installa").piano(resource_root=RESOURCE_ROOT)
        module = _load("registro")
        if verb == "sorveglia":
            return module.sorveglia(params["id"], params["percorso"], params.get("nome", ""))
        if verb == "rimuovi_sorveglianza":
            return module.rimuovi_sorveglianza(params["id"])
        filters = params.get("filters", {})
        if verb == "query":
            rows = module.query(filters)
            return {"rows": rows[:MAX_ROWS], "total": len(rows), "truncated": len(rows) > MAX_ROWS,
                    **module.raccolta_kernel(filters)}
        if verb == "export_csv":
            contents = module.export_csv(filters)
            collection = module.raccolta_kernel(filters)
            return {**_export(params["path"], contents, _csv_count(contents)), **collection}
        return getattr(module, verb)()
    if group == "etichette":
        module = _load("etichette")
        if verb == "sfoglia":
            return module.sfoglia(params["radice"], mostra_nascosti=params.get("mostra_nascosti", False))
        if verb == "segna":
            return module.segna(params["percorso"], params["etichetta"], nota=params.get("nota", ""))
        if verb == "togli":
            return module.togli(params["percorso"])
        return getattr(module, verb)()
    if group == "banco":
        module = _load("banco", optional=True)
        if verb == "run":
            return _function(module, "esegui")(params["dove"], key, minutes=params.get("minutes", 15), agenti_reali=params["agenti_reali"])
        if verb == "anteprima":
            return _function(module, "anteprima")(**params)
        if verb == "export_csv":
            contents = _function(module, "export_csv")()
            return _export(params["path"], contents, _csv_count(contents))
        history = _function(module, "storico")()
        if verb == "export_json":
            if not isinstance(history, dict) or not isinstance(history.get("prove", []), list):
                raise RequestError("internal_error", _t("Lo storico del banco non è valido. Verifica il banco e riprova."))
            return _export(params["path"], json.dumps(history, ensure_ascii=False, indent=2, allow_nan=False) + "\n", len(history.get("prove", [])))
        return history
    module = _load("hookinstaller", optional=True)
    if verb == "ripristina":
        return _function(module, "ripristina")(params["path"])
    function = {"stato": "stato", "install_plan": "piano", "applica": "installa"}[verb]
    return _function(module, function)(resource_root=RESOURCE_ROOT, python_executable=None)


class _Discard:
    def write(self, value):
        return len(value)

    def flush(self):
        pass


@contextlib.contextmanager
def _muted_output():
    # Discard Python prints and raw fd writes from imports/backend calls. Never
    # keep backend stderr in a log or forward it to the app, even on failure.
    saved = []
    null_fd = None
    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
        for fd in (1, 2):
            saved.append((fd, os.dup(fd)))
            os.dup2(null_fd, fd)
        with contextlib.redirect_stdout(_Discard()), contextlib.redirect_stderr(_Discard()):
            yield
    finally:
        for fd, original in reversed(saved):
            os.dup2(original, fd)
            os.close(original)
        if null_fd is not None:
            os.close(null_fd)


def _failure(exc, action):
    if isinstance(exc, RequestError):
        code, message = exc.code, exc.message
    elif (action.startswith("registro.") and type(exc).__name__ == "ErroreRegistro"
          and getattr(exc, "code", None) in REGISTRY_ERRORS):
        code = exc.code
        message = REGISTRY_ERRORS[code]
    elif type(exc).__name__ == "ImmagineDanneggiata":
        code, message = "damaged_image", _t("L'immagine è danneggiata o incompleta. Ricollega il disco e ripristina una copia integra del compartimento; conserva l'immagine attuale e non ripetere la migrazione sulla fonte.")
    elif type(exc).__name__ == "ChiaveErrata":
        code, message = "wrong_key", _t("La chiave non apre questa cartella. Inseriscila di nuovo nel campo sicuro; nessun dato è stato modificato.")
    elif type(exc).__name__ == "VolumeOccupato":
        code, message = "volume_busy", _t("La cartella è in uso da un'app o da un terminale aperto dentro: chiudili e riprova. Nell'app puoi scegliere Forza chiusura… e confermare; le modifiche non salvate possono andare perse.")
    elif type(exc).__name__ == "DiscoNonDisponibile":
        code, message = "disk_unavailable", _t("Il disco esterno non è disponibile. Collegalo e riprova prima di inserire la chiave.")
    elif isinstance(exc, PermissionError):
        code, message = "permission_required", _t("macOS ha negato l'accesso. Controlla i permessi della cartella e le autorizzazioni in Privacy e sicurezza, poi riprova.")
    elif isinstance(exc, FileNotFoundError):
        code, message = "not_found", _t("La cartella, il file o il disco richiesto non è disponibile. Controlla il percorso e collega il disco, poi riprova.")
    elif isinstance(exc, OSError):
        code, message = "io_error", _t("Non è stato possibile completare l'operazione sul disco. Controlla lo spazio libero e i permessi, poi riprova.")
    elif type(exc).__name__ == "Rifiuto" and _messaggio_noto(exc):
        code, message = "refused", str(exc)
    elif type(exc).__name__ == "Rifiuto":
        code = "refused"
        if action == "cartelle.prepara_protezione":
            message = _t("La cartella o la destinazione non è pronta. Scegli una fonte valida e una cartella su un disco esterno fisico: i dischi interni e le immagini disco non sono accettati.")
        elif action == "cartelle.prepara_apertura":
            message = _t("La cartella non è pronta per l'apertura. Aggiorna lo stato; se la migrazione è incompleta usa Recupera o Annulla migrazione.")
        elif action.startswith("cartelle."):
            message = _t("L'operazione è stata rifiutata per proteggere i dati. Controlla la chiave, lo stato della cartella e il disco scelto; chiudi i file in uso e riprova.")
        elif action == "banco.anteprima":
            message = _t("La destinazione o il banco non è pronto. Scegli una cartella su un disco esterno fisico: i dischi interni e le immagini disco non sono accettati.")
        elif action.startswith("banco."):
            message = _t("Il banco non può procedere. Verifica il registro, Accesso completo al disco e il disco esterno prima di riprovare.")
        elif action.startswith("hooks."):
            message = _t("Gli hook non possono essere configurati. Verifica il piano, le impostazioni degli agenti e il runtime Apple dei Command Line Tools: Python 3.9 o successivo, protetto da root con la sua libreria standard.")
        else:
            message = _t("L'operazione è stata rifiutata. Controlla il percorso e i dati inseriti, poi riprova.")
    elif isinstance(exc, ValueError) and _messaggio_noto(exc):
        code, message = "invalid_data", str(exc)
    elif isinstance(exc, (ValueError, TypeError)):
        code, message = "invalid_data", _t("I dati richiesti o salvati non sono validi. Controlla i campi e verifica il registro prima di riprovare.")
    else:
        code, message = "internal_error", _t("L'app ha incontrato un errore. Riapri Paratia e riprova; se continua, verifica o reinstalla l'app.")
    # Exception text, subprocess streams and traceback are deliberately absent.
    return {"ok": False, "code": code, "message": message, "action": action}


def main(argv=None, stdin=None, stdout=None):
    argv = sys.argv if argv is None else argv
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    action = argv[1] if len(argv) == 2 and argv[1] in SCHEMAS else ""
    key = b""
    try:
        if not action:
            raise RequestError("invalid_action", _t("L'operazione richiesta non è disponibile nell'app. Aggiorna Paratia."))
        params, key = read_frame(stdin)
        with _muted_output():
            result = dispatch(action, params, key)
        response = {"ok": True, "result": result}
        # Also guard against a future backend returning the raw secret by mistake.
        if key and _contains_key(response, key.decode("utf-8")):
            raise RequestError("internal_error", _t("L'app ha rifiutato una risposta non sicura. Aggiorna Paratia prima di riprovare."))
        serialized = json.dumps(response, ensure_ascii=False, allow_nan=False)
    except BaseException as exc:
        serialized = json.dumps(_failure(exc, action), ensure_ascii=False)
    finally:
        key = b""
    stdout.write(serialized + "\n")
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
