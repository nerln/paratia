#!/usr/bin/env python3
"""Encrypted folders for the operator's GUI, with no stored keys.

Only hdiutil receives a passphrase, through stdin. The registry and timer
processes carry mount metadata only. A migration leaves its source alone until
the image has survived a detach, a fresh attach, and a second content check.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import plistlib
import re
import select
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from xml.parsers.expat import ExpatError

# Timers import sibling registry modules from a sealed app bundle as well.
sys.dont_write_bytecode = True

CASA = Path(os.environ.get("PARATIA_HOME", Path.home() / ".paratia"))
ARCHIVIO = CASA / "cartelle.json"
HDIUTIL = "/usr/bin/hdiutil"
DISKUTIL = "/usr/sbin/diskutil"
DITTO = "/usr/bin/ditto"
LSOF = "/usr/sbin/lsof"
DIR_SISTEMA = {".fseventsd", ".Spotlight-V100", ".Trashes", ".DocumentRevisions-V100", ".TemporaryItems"}


class Rifiuto(Exception):
    """The operation did not meet a condition needed to keep its bytes safe."""

    def __init__(self, message: str, cartella_id: str | None = None):
        super().__init__(message)
        self.cartella_id = cartella_id


class ChiaveErrata(Rifiuto):
    """hdiutil explicitly rejected the supplied passphrase."""


class VolumeOccupato(Rifiuto):
    """A normal detach could not close a volume that is still in use."""

    def __init__(self, message: str, cartella_id: str | None = None, processi: list | None = None):
        super().__init__(message, cartella_id)
        self.processi = processi or []


class DiscoNonDisponibile(Rifiuto):
    """The external image is currently unavailable; no recovery is needed."""


class ImmagineDanneggiata(Rifiuto):
    """The sparsebundle is incomplete or unreadable, before any key is checked."""


MESSAGGIO_IMMAGINE = ("L'immagine è danneggiata o incompleta. Ricollega il disco e ripristina "
                     "una copia integra del compartimento; conserva l'immagine attuale "
                     "e non ripetere la migrazione sulla fonte.")


def annota(evento: str, **metadati) -> None:
    """Append operator operations to the same hash-chain format as kernel events."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "registro_cartelle", Path(__file__).resolve().parent / "registro.py")
    registro = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = registro
    spec.loader.exec_module(registro)
    registro.annota(evento, **metadati)


def _audit(evento: str, **metadati) -> str | None:
    try:
        annota(evento, **metadati)
    except Exception:
        # The disk operation already happened. Report the missing record without
        # turning an audit failure into a misleading migration or mount failure.
        return "L'operazione disco è conclusa, ma non è stata scritta nel registro. Verifica il registro e lo spazio libero."
    return None


def _esito_registrato(voce: dict, evento: str, **metadati) -> dict:
    risultato = _pubblica(voce)
    avviso = _audit(evento, **metadati)
    if avviso:
        risultato["avviso_registro"] = avviso
    return risultato


def _corri(argv: list[str], passphrase: bytes | None = None):
    try:
        return subprocess.run(argv, input=None if passphrase is None else passphrase + b"\0",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as e:
        raise Rifiuto("Il comando di sistema richiesto non è disponibile.") from e


def _autenticazione_fallita(r) -> bool:
    testo = (r.stderr or b"").decode("utf-8", "replace").casefold()
    return any(messaggio in testo for messaggio in (
        "authentication error", "incorrect password", "wrong password", "password incorrect",
        "errore di autenticazione", "password errata", "error de autenticación",
        "error de autenticacion", "contraseña incorrecta", "contrasena incorrecta"))


def _risultato_comando(argv: list[str], r, passphrase: bytes | None = None):
    if r.returncode:
        if (argv[0] == HDIUTIL and argv[1] in ("attach", "imageinfo")
                and passphrase is not None and _autenticazione_fallita(r)):
            raise ChiaveErrata("La chiave del compartimento non è corretta. Reinseriscila.")
        if argv[:2] == [HDIUTIL, "detach"] and r.returncode == errno.EBUSY:
            raise VolumeOccupato("La cartella è in uso da un'app o da un terminale aperto dentro: chiudili e riprova.")
        # Never forward a subprocess stream: even an error must not echo a key.
        raise Rifiuto(f"Operazione disco non riuscita ({Path(argv[0]).name} {argv[1]}, codice {r.returncode}).")
    return r


def _comando(argv: list[str], passphrase: bytes | None = None):
    return _risultato_comando(argv, _corri(argv, passphrase), passphrase)


def _chiave(passphrase: bytes) -> None:
    if not isinstance(passphrase, bytes) or len(passphrase) < 12:
        raise Rifiuto("La passphrase deve contenere almeno 12 byte.")
    if any(c in passphrase for c in (b"\n", b"\r", b"\0")):
        raise Rifiuto("La passphrase non può contenere terminatori di riga o byte nulli.")


def _minuti(minutes: int) -> int:
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 1440:
        raise Rifiuto("Il timer deve durare da 1 a 1440 minuti.")
    return minutes


def _percorso(p: str | Path) -> Path:
    q = Path(p).expanduser()
    if not q.is_absolute():
        raise Rifiuto("Scegli un percorso assoluto.")
    # Reject aliases before resolving, including a symlink in an ancestor.
    q = Path(os.path.abspath(q))
    for antenato in [*reversed(q.parents), q]:
        if antenato.is_symlink():
            raise Rifiuto("I percorsi con collegamenti simbolici non sono ammessi.")
    return q


def _dentro(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def _cloud(p: Path) -> bool:
    s = str(p)
    return any(x in s for x in (
        "/Library/CloudStorage/", "/Library/Mobile Documents/", "/Dropbox",
        "/OneDrive", "/Google Drive", "/iCloud Drive",
    ))


def _monte_statfs(dove: Path) -> Path:
    """Get the kernel's mount name, including APFS Data-volume firmlinks."""
    class Statfs(ctypes.Structure):
        # struct statfs from the macOS SDK's 64-bit sys/mount.h.
        _fields_ = [("f_bsize", ctypes.c_uint32), ("f_iosize", ctypes.c_int32),
                    *[(nome, ctypes.c_uint64) for nome in (
                        "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree")],
                    ("f_fsid", ctypes.c_int32 * 2), ("f_owner", ctypes.c_uint32),
                    ("f_type", ctypes.c_uint32), ("f_flags", ctypes.c_uint32),
                    ("f_fssubtype", ctypes.c_uint32), ("f_fstypename", ctypes.c_char * 16),
                    ("f_mntonname", ctypes.c_char * 1024),
                    ("f_mntfromname", ctypes.c_char * 1024),
                    ("f_flags_ext", ctypes.c_uint32), ("f_reserved", ctypes.c_uint32 * 7)]
    try:
        # arm64 has only the 64-bit inode ABI under the unsuffixed symbol;
        # Intel also exports an older struct layout, so select its INODE64 ABI.
        simbolo = "statfs" if os.uname().machine.startswith("arm64") else "statfs$INODE64"
        funzione = getattr(ctypes.CDLL(None, use_errno=True), simbolo)
        funzione.argtypes = [ctypes.c_char_p, ctypes.POINTER(Statfs)]
        funzione.restype = ctypes.c_int
        dati = Statfs()
        if funzione(os.fsencode(dove), ctypes.byref(dati)):
            raise OSError(ctypes.get_errno(), "statfs")
        return _percorso(os.fsdecode(dati.f_mntonname))
    except (AttributeError, OSError, ValueError) as e:
        raise Rifiuto("Impossibile individuare il volume della destinazione.") from e


def _punto_montaggio(dove: Path) -> Path:
    try:
        dispositivo = dove.stat().st_dev
        monte = dove
        while monte.parent != monte and monte.parent.stat().st_dev == dispositivo:
            monte = monte.parent
        if sys.platform == "darwin":
            # st_dev alone stops at /Users on a firmlink, although diskutil
            # needs the actual /System/Volumes/Data mount name.
            monte = _monte_statfs(dove)
            if not monte.is_dir() or monte.stat().st_dev != dispositivo:
                raise Rifiuto("Il volume della destinazione non è stato confermato.")
        return monte
    except OSError as e:
        raise Rifiuto("Impossibile individuare il volume della destinazione.") from e


def _esterno(dove: Path) -> None:
    rifiuto = "Scegli una cartella su un disco esterno fisico; le immagini disco non sono ammesse."
    cache = {}

    def info(percorso):
        if percorso not in cache:
            if len(cache) >= 16:
                raise Rifiuto("Impossibile verificare il disco scelto.")
            risultato = _comando([DISKUTIL, "info", "-plist", percorso])
            try:
                dati = plistlib.loads(risultato.stdout)
                if not isinstance(dati, dict):
                    raise ValueError()
            except (ValueError, plistlib.InvalidFileException) as e:
                raise Rifiuto("Impossibile verificare il disco scelto.") from e
            cache[percorso] = dati
        return cache[percorso]

    def dispositivo(nome):
        if not isinstance(nome, str) or not re.fullmatch(r"disk[0-9]+(?:s[0-9]+)*", nome):
            raise Rifiuto("Impossibile verificare il disco scelto.")
        return nome

    def fisico(percorso, antenati=()):
        if percorso in antenati or len(antenati) >= 8:
            raise Rifiuto("Impossibile verificare il disco scelto.")
        dati = info(percorso)
        if str(dati.get("BusProtocol", "")).lower().replace(" ", "") == "diskimage":
            raise Rifiuto(rifiuto)
        stores = dati.get("APFSPhysicalStores")
        if stores is not None:
            if not isinstance(stores, list) or not stores or len(stores) > 16:
                raise Rifiuto("Impossibile verificare il disco scelto.")
            for store in stores:
                if not isinstance(store, dict):
                    raise Rifiuto("Impossibile verificare il disco scelto.")
                fisico(dispositivo(store.get("APFSPhysicalStore")), (*antenati, percorso))
            return
        parent = dati.get("ParentWholeDisk")
        if parent and parent != dati.get("DeviceIdentifier"):
            fisico(dispositivo(parent), (*antenati, percorso))
            return
        intero = dati.get("DeviceIdentifier", percorso)
        if (not isinstance(intero, str) or not re.fullmatch(r"disk[0-9]+", intero)
                or dati.get("VirtualOrPhysical") != "Physical" or dati.get("Internal") is not False):
            raise Rifiuto(rifiuto)

    fisico(str(_punto_montaggio(dove)))


def _carica() -> dict:
    if ARCHIVIO.is_symlink():
        raise Rifiuto("Il registro delle cartelle non può essere un collegamento.")
    if not ARCHIVIO.exists():
        return {"versione": 1, "cartelle": {}}
    try:
        r = json.loads(ARCHIVIO.read_text())
    except (OSError, ValueError) as e:
        raise Rifiuto("Il registro delle cartelle è illeggibile.") from e
    if (not isinstance(r, dict) or r.get("versione") != 1
            or not isinstance(r.get("cartelle"), dict)):
        raise Rifiuto("Il registro delle cartelle non è valido.")
    for identificatore, voce in r["cartelle"].items():
        if (not isinstance(identificatore, str) or not isinstance(voce, dict)
                or voce.get("id") != identificatore
                or not all(isinstance(voce.get(k), str)
                           for k in ("nome", "origine", "bundle", "montaggio", "stato", "generation"))):
            raise Rifiuto("Una voce del registro delle cartelle non è valida.")
    return r


def _salva(r: dict) -> None:
    CASA.mkdir(parents=True, exist_ok=True)
    nome = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=CASA, prefix=".cartelle-", delete=False) as f:
            nome = f.name
            json.dump(r, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(nome, ARCHIVIO)
    finally:
        if nome and os.path.exists(nome):
            os.unlink(nome)


@contextlib.contextmanager
def _registro():
    CASA.mkdir(parents=True, exist_ok=True)
    fd = os.open(CASA / "cartelle.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield _carica()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _voce(r: dict, identificatore: str) -> dict:
    try:
        return r["cartelle"][identificatore]
    except (KeyError, TypeError) as e:
        raise Rifiuto("Cartella sconosciuta.") from e


def _montato(p: Path) -> bool:
    return p.is_mount()


def _pubblica(voce: dict) -> dict:
    v = dict(voce)
    v.pop("timer", None)
    if v["stato"] not in ("migrazione", "migrazione-incompleta", "annullata", "recuperata"):
        v["stato"] = "aperta" if _montato(Path(v["montaggio"])) else "chiusa"
    return v


def elenco() -> list[dict]:
    with _registro() as r:
        return sorted((_pubblica(v) for v in r["cartelle"].values()), key=lambda v: v["nome"])


def _firma(s) -> tuple:
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    lib.listxattr.restype = ctypes.c_ssize_t
    lib.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    lib.getxattr.restype = ctypes.c_ssize_t
    lib.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    lib.setxattr.restype = ctypes.c_int
    lib.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.acl_get_file.restype = ctypes.c_void_p
    lib.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    lib.acl_to_text.restype = ctypes.c_void_p
    lib.acl_set_file.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.acl_set_file.restype = ctypes.c_int
    lib.acl_init.argtypes = [ctypes.c_int]
    lib.acl_init.restype = ctypes.c_void_p
    lib.acl_free.argtypes = [ctypes.c_void_p]
    return lib


def _nomi_xattr(p: Path) -> list[str]:
    if sys.platform != "darwin":
        return os.listxattr(p, follow_symlinks=False) if hasattr(os, "listxattr") else []
    lib = _libc()
    n = lib.listxattr(os.fsencode(p), None, 0, 1)
    if n < 0:
        raise Rifiuto("Impossibile leggere gli attributi estesi di un elemento.")
    b = ctypes.create_string_buffer(n)
    if lib.listxattr(os.fsencode(p), b, n, 1) != n:
        raise Rifiuto("Gli attributi estesi sono cambiati durante la verifica.")
    return [os.fsdecode(x) for x in b.raw[:n].split(b"\0") if x]


def _xattr(p: Path, nome: str) -> bytes:
    if sys.platform != "darwin":
        return os.getxattr(p, nome, follow_symlinks=False)
    lib = _libc()
    n = lib.getxattr(os.fsencode(p), os.fsencode(nome), None, 0, 0, 1)
    if n < 0:
        raise Rifiuto("Impossibile leggere un attributo esteso.")
    b = ctypes.create_string_buffer(n)
    if lib.getxattr(os.fsencode(p), os.fsencode(nome), b, n, 0, 1) != n:
        raise Rifiuto("Un attributo esteso è cambiato durante la verifica.")
    return b.raw[:n]


def _acl(p: Path) -> str:
    if sys.platform != "darwin":
        return ""
    lib = _libc()
    acl = lib.acl_get_file(os.fsencode(p), 0x100)  # ACL_TYPE_EXTENDED on macOS.
    if not acl:
        if ctypes.get_errno() == errno.ENOENT and p.exists():
            return ""  # macOS uses ENOENT when an existing file has no ACL.
        raise Rifiuto("Impossibile leggere le autorizzazioni ACL.")
    testo = None
    try:
        lunghezza = ctypes.c_ssize_t()
        testo = lib.acl_to_text(acl, ctypes.byref(lunghezza))
        if not testo:
            raise Rifiuto("Impossibile verificare le autorizzazioni ACL.")
        return hashlib.sha256(ctypes.string_at(testo, lunghezza.value)).hexdigest()
    finally:
        if testo:
            lib.acl_free(testo)
        lib.acl_free(acl)


def _metadati(p: Path) -> dict:
    attributi = {}
    for nome in _nomi_xattr(p):
        if nome == "com.apple.ResourceFork" and p.is_file() and sys.platform == "darwin":
            h = hashlib.sha256()
            with (p / "..namedfork" / "rsrc").open("rb") as f:
                for b in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(b)
            attributi[nome] = h.hexdigest()
        else:
            attributi[nome] = hashlib.sha256(_xattr(p, nome)).hexdigest()
    return {"xattr": attributi, "acl": _acl(p)}


def _copia_metadati(origine: Path, destinazione: Path) -> None:
    shutil.copystat(origine, destinazione, follow_symlinks=False)
    for nome in _nomi_xattr(origine):
        valore = _xattr(origine, nome)
        if sys.platform == "darwin":
            if _libc().setxattr(os.fsencode(destinazione), os.fsencode(nome), valore, len(valore), 0, 1):
                raise Rifiuto("Impossibile ripristinare un attributo della cartella.")
        else:
            os.setxattr(destinazione, nome, valore, follow_symlinks=False)
    if sys.platform == "darwin":
        lib = _libc()
        acl = lib.acl_get_file(os.fsencode(origine), 0x100)
        if not acl and ctypes.get_errno() == errno.ENOENT and origine.exists():
            acl = lib.acl_init(0)
        if not acl:
            raise Rifiuto("Impossibile ripristinare le autorizzazioni della cartella.")
        try:
            if lib.acl_set_file(os.fsencode(destinazione), 0x100, acl):
                raise Rifiuto("Impossibile ripristinare le autorizzazioni della cartella.")
        finally:
            lib.acl_free(acl)


def _leggi(p: Path, attesa=None) -> tuple[int, str]:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        prima = os.fstat(f.fileno())
        if not stat.S_ISREG(prima.st_mode) or prima.st_nlink != 1:
            raise Rifiuto("La fonte contiene file speciali o hard link.")
        if attesa is not None and _firma(prima) != attesa:
            raise Rifiuto("La fonte è cambiata durante la migrazione.")
        h, n = hashlib.sha256(), 0
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
            n += len(b)
        if _firma(prima) != _firma(os.fstat(f.fileno())) or n != prima.st_size:
            raise Rifiuto("Un file è cambiato durante la lettura.")
        return n, h.hexdigest()


def _scansiona(radice: Path, esclusi_root=()) -> dict:
    manifest = {}

    def visita(p: Path):
        s = p.lstat()
        relativo = str(p.relative_to(radice))
        if stat.S_ISDIR(s.st_mode):
            if p != radice and _montato(p):
                raise Rifiuto("La fonte contiene un altro volume montato.")
            manifest[relativo] = {"tipo": "cartella", "modo": stat.S_IMODE(s.st_mode),
                                  "mtime": s.st_mtime_ns, **_metadati(p)}
            for figlio in sorted(p.iterdir(), key=lambda x: x.name):
                if (p == radice and figlio.name in esclusi_root and figlio.is_dir()
                        and not figlio.is_symlink()):
                    continue
                visita(figlio)
        elif stat.S_ISREG(s.st_mode) and s.st_nlink == 1:
            n, h = _leggi(p, _firma(s))
            manifest[relativo] = {"tipo": "file", "byte": n, "hash": h,
                                  "firma": _firma(s), "modo": stat.S_IMODE(s.st_mode),
                                  "mtime": s.st_mtime_ns, **_metadati(p)}
        else:
            raise Rifiuto("La fonte contiene collegamenti, hard link o file speciali.")

    visita(radice)
    return manifest


def _contenuto(manifest: dict) -> dict:
    return {k: {campo: v[campo] for campo in ("tipo", "byte", "hash", "modo", "xattr", "acl") if campo in v}
            for k, v in manifest.items()}


def _totali(manifest: dict) -> tuple[int, int]:
    file = [v for v in manifest.values() if v["tipo"] == "file"]
    return len(file), sum(v["byte"] for v in file)


def _copia(origine: Path, monte: Path, manifest: dict) -> None:
    _comando([DITTO, "--rsrc", "--extattr", "--acl", str(origine), str(monte)])
    # ditto merges into the existing volume root; that root needs an explicit
    # metadata copy even though the children already retain their attributes.
    _copia_metadati(origine, monte)


def _verifica(radice: Path, atteso: dict, metadir: str | None = None) -> None:
    ignorati = {x for x in DIR_SISTEMA if x not in atteso} if metadir else set()
    if metadir:
        ignorati.add(metadir)
    trovato = _scansiona(radice, ignorati)
    if _totali(trovato) != _totali(atteso) or _contenuto(trovato) != _contenuto(atteso):
        raise Rifiuto("La verifica di numero, dimensioni e hash dei file non è riuscita.")


def _impronta(manifest: dict) -> str:
    return hashlib.sha256(json.dumps(_contenuto(manifest), sort_keys=True).encode()).hexdigest()


def _scrivi_manifest(monte: Path, voce: dict, manifest: dict) -> None:
    directory = monte / voce["metadir"]
    directory.mkdir(mode=0o700)
    with (directory / "manifest.json").open("x") as f:
        json.dump({"versione": 1, "id": voce["id"], "manifest": manifest}, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())


def _leggi_manifest(monte: Path, voce: dict) -> dict:
    p = monte / voce["metadir"] / "manifest.json"
    if p.is_symlink():
        raise Rifiuto("Il riferimento di recupero non è valido.")
    try:
        d = json.loads(p.read_text())
        manifest = d["manifest"]
        if d["versione"] != 1 or d["id"] != voce["id"] or _impronta(manifest) != voce["impronta"]:
            raise ValueError()
        for nome in manifest:
            if Path(nome).is_absolute() or ".." in Path(nome).parts:
                raise ValueError()
    except (OSError, KeyError, TypeError, ValueError) as e:
        raise Rifiuto("Il riferimento cifrato di recupero è illeggibile o non corrisponde.") from e
    return manifest


def _file_bundle(directory: int, nome: str) -> int:
    fd = os.open(nome, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        dati = os.fstat(fd)
        if not stat.S_ISREG(dati.st_mode) or dati.st_nlink != 1 or not dati.st_mode & 0o444:
            raise ValueError("unreadable regular file required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _valida_token(fd: int) -> None:
    """Validate the encrypted-v2 header's declared extents, without a key.

    The 76-byte big-endian header carries a data offset at byte 64 and the
    count of 20-byte key-blob descriptors at byte 72. A sparsebundle token
    contains this encryption header up to the data offset; the actual image
    data lives in bands. These extents were checked against an existing
    hdiutil-produced fixture; its total token size is deliberately not fixed.
    """
    dimensione = os.fstat(fd).st_size
    prefisso = os.pread(fd, 12, 0)
    if len(prefisso) != 12:
        raise ValueError("truncated token header")
    if prefisso[:8] != b"encrcdsa":
        raise ValueError("invalid encrypted-token signature")
    if struct.unpack_from(">I", prefisso, 8)[0] != 2:
        raise Rifiuto("Il formato del token cifrato non è supportato. Conserva questa "
                      "copia e verifica il compartimento con assistenza prima di aprirlo.")
    header = os.pread(fd, 76, 0)
    if len(header) != 76:
        raise ValueError("truncated encrypted-v2 header")
    blocco = struct.unpack_from(">I", header, 52)[0]
    fine_header = struct.unpack_from(">Q", header, 64)[0]
    numero = struct.unpack_from(">I", header, 72)[0]
    fine_tabella = 76 + numero * 20
    if (not blocco or blocco & (blocco - 1) or not numero
            or fine_tabella > fine_header or fine_header > dimensione):
        raise ValueError("incomplete encrypted-v2 extents")
    # Bound the descriptor read independently of a tampered count. This is a
    # resource limit, not a claimed fixed length of an encrypted token.
    if numero > 4096:
        raise Rifiuto("Il token cifrato supera i limiti di verifica. Conserva questa "
                      "copia e verifica il compartimento con assistenza prima di aprirlo.")
    tabella = os.pread(fd, numero * 20, 76)
    if len(tabella) != numero * 20:
        raise ValueError("incomplete encrypted-v2 key table")
    for indice in range(numero):
        _tipo, inizio, lunghezza = struct.unpack_from(">IQQ", tabella, indice * 20)
        if not lunghezza or inizio < fine_tabella or inizio + lunghezza > fine_header:
            raise ValueError("incomplete encrypted-v2 key blob")
    # Read the whole declared token without retaining key-blob bytes. A short
    # read or a concurrent truncation must never turn into a wrong-key error.
    posizione = 0
    while posizione < dimensione:
        pezzo = os.pread(fd, min(65536, dimensione - posizione), posizione)
        if not pezzo:
            raise ValueError("token ended before EOF")
        posizione += len(pezzo)
    if os.fstat(fd).st_size != dimensione:
        raise ValueError("token changed during validation")


def _verifica_struttura_bundle(bundle: Path, cartella_id: str | None = None) -> None:
    """Check image metadata, bands and the encryption token before a key prompt."""
    directory = None
    try:
        _percorso(bundle)
        directory = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        valido = False
        for nome in ("Info.plist", "Info.bckup"):
            try:
                metadata = os.stat(nome, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("regular metadata required")
            try:
                fd = _file_bundle(directory, nome)
                try:
                    if os.fstat(fd).st_size > 1048576:
                        raise ValueError("image metadata too large")
                    with os.fdopen(fd, "rb") as file:
                        fd = None
                        info = plistlib.load(file)
                    if (isinstance(info, dict)
                            and info.get("diskimage-bundle-type") == "com.apple.diskimage.sparsebundle"
                            and type(info.get("band-size")) is int and info["band-size"] > 0
                            and type(info.get("size")) is int and info["size"] > 0):
                        valido = True
                finally:
                    if fd is not None:
                        os.close(fd)
            except (OSError, ValueError, ExpatError, plistlib.InvalidFileException):
                # hdiutil can use the backup metadata if the primary plist is
                # absent or corrupt. A symlink/special file is always refused.
                continue
        if not valido:
            raise ValueError("no valid image metadata")
        bands = os.open("bands", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory)
        os.close(bands)
        fd = _file_bundle(directory, "token")
        try:
            _valida_token(fd)
        finally:
            os.close(fd)
    except Rifiuto as errore:
        # Path aliases are damaged metadata too. A recognised but unsupported
        # encryption format keeps its distinct, safe message.
        if directory is not None:
            raise
        raise ImmagineDanneggiata(MESSAGGIO_IMMAGINE, cartella_id) from errore
    except (OSError, ValueError, struct.error) as errore:
        raise ImmagineDanneggiata(MESSAGGIO_IMMAGINE, cartella_id) from errore
    finally:
        if directory is not None:
            os.close(directory)


def _verifica_chiave(bundle: Path, passphrase: bytes) -> None:
    """Check an encrypted image's password without attaching a device."""
    _verifica_struttura_bundle(bundle)
    verifica = _corri([HDIUTIL, "isencrypted", str(bundle), "-plist"])
    cifrata = None
    if verifica.returncode == 0:
        try:
            dati = plistlib.loads(verifica.stdout)
            if isinstance(dati, dict):
                cifrata = dati.get("encrypted", dati.get("Encrypted"))
                if type(cifrata) is not bool:
                    cifrata = None
        except (ValueError, plistlib.InvalidFileException):
            pass  # Older providers can still identify authentication via text.
    if cifrata is False:
        raise Rifiuto("L'immagine non risulta cifrata; non verrà aperta.")
    argv = [HDIUTIL, "imageinfo", str(bundle), "-plist", "-stdinpass"]
    risultato = _corri(argv, passphrase)
    if risultato.returncode:
        if not bundle.is_dir():
            raise DiscoNonDisponibile("Il disco esterno non è disponibile. Collegalo e riprova ad aprire la cartella.")
        _verifica_struttura_bundle(bundle)
        if (cifrata is True and risultato.returncode not in (
                errno.ENOENT, errno.EIO, errno.EACCES, errno.ENODEV, errno.ENXIO,
                errno.EINVAL, errno.ENOSPC, errno.EROFS, errno.ENOTSUP, errno.EBUSY,
                errno.EAGAIN, errno.EFBIG)):
            raise ChiaveErrata("La chiave del compartimento non è corretta. Reinseriscila.")
        _risultato_comando(argv, risultato, passphrase)


def _attacca(bundle: Path, monte: Path, passphrase: bytes) -> None:
    if _montato(monte) or any(monte.iterdir()):
        raise Rifiuto("Il punto di montaggio deve essere vuoto e non montato.")
    _verifica_chiave(bundle, passphrase)
    _comando([HDIUTIL, "attach", str(bundle), "-stdinpass", "-nobrowse", "-noautoopen",
              "-owners", "on", "-mountpoint", str(monte)], passphrase)
    if not _montato(monte):
        raise Rifiuto("Il montaggio del volume non è stato confermato.")


def _processi_occupanti(monte: Path) -> list[dict]:
    """Read only lsof's process names and IDs, never paths or command arguments."""
    processo = None
    try:
        # The local lsof manual documents +f -- for a filesystem and -Fpc0 for
        # process ID and command name. The mount path stays one literal argv.
        processo = subprocess.Popen([LSOF, "-nP", "-Fpc0", "+f", "--", str(monte)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
        limite = time.monotonic() + 2
        dati = bytearray()
        while True:
            rimasto = limite - time.monotonic()
            if rimasto <= 0 or not select.select([processo.stdout], [], [], rimasto)[0]:
                return []
            pezzo = os.read(processo.stdout.fileno(), min(4096, 65537 - len(dati)))
            if not pezzo:
                break
            dati.extend(pezzo)
            if len(dati) > 65536:
                return []
        if processo.wait(timeout=max(0.001, limite - time.monotonic())) not in (0, 1):
            return []
        processi, visti, pid = [], set(), None
        for campo in bytes(dati).split(b"\0"):
            riga = campo.lstrip(b"\n")  # lsof separates its process sets with NL.
            if riga.startswith(b"p"):
                valore = riga[1:]
                pid = int(valore) if valore.isdigit() and 0 < len(valore) <= 10 else None
                if pid is not None and not 0 < pid <= 2147483647:
                    pid = None
            elif riga.startswith(b"c") and pid is not None and pid not in visti:
                nome = riga[1:].decode("utf-8", "replace")
                # Reject multiline/control-character tricks; only the bounded
                # process name supplied by the kernel is allowed into output.
                if not nome or len(nome) > 80 or any(not c.isprintable() for c in nome):
                    continue
                processi.append({"nome": nome, "pid": pid})
                visti.add(pid)
                if len(processi) == 12:
                    break
        return processi
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []
    finally:
        if processo is not None:
            if processo.poll() is None:
                # This is our own short-lived diagnostic child, never a PID
                # found by lsof or stored in the folder/timer registry.
                processo.kill()
            with contextlib.suppress(subprocess.TimeoutExpired):
                processo.wait(timeout=1)
            if processo.stdout is not None:
                processo.stdout.close()


def _stacca(monte: Path, force: bool = False) -> None:
    if type(force) is not bool:
        raise Rifiuto("La chiusura forzata richiede una scelta esplicita.")
    if _montato(monte):
        try:
            _comando([HDIUTIL, "detach", str(monte), *(["-force"] if force else [])])
        except VolumeOccupato as errore:
            processi = _processi_occupanti(monte)
            messaggio = str(errore)
            if processi:
                messaggio += " Processi rilevati: " + ", ".join(
                    f"{p['nome']} (PID {p['pid']})" for p in processi) + "."
            raise VolumeOccupato(messaggio, processi=processi) from None
    if _montato(monte):
        raise Rifiuto("Il volume è ancora montato. Nessuna chiusura forzata eseguita.")


def _origine_libera(origine: Path, r: dict) -> None:
    riservati = [CASA, Path(os.environ.get("PARATIA_MOUNT", "/Volumes/paratia"))]
    riservati += [Path(v[k]) for v in r["cartelle"].values() for k in ("montaggio", "bundle")]
    zona = CASA / "zone" / "registro.json"
    if zona.exists():
        try:
            zone = json.loads(zona.read_text())
            riservati += [Path("/Volumes") / ("zona-" + nome) for nome in zone]
        except (OSError, ValueError, TypeError) as e:
            raise Rifiuto("Il registro delle zone non è leggibile.") from e
    for p in riservati:
        if _dentro(origine, p) or _dentro(p, origine):
            raise Rifiuto("La fonte si sovrappone a una cartella o un compartimento già registrato.")
    if _montato(origine):
        raise Rifiuto("La fonte è già un punto di montaggio.")


def prepara_protezione(origine: str | Path, dove: str | Path, minutes: int = 15) -> dict:
    """Check the operator's choices before any passphrase is requested."""
    minutes = _minuti(minutes)
    fonte, disco = _percorso(origine), _percorso(dove)
    if not fonte.is_dir() or not disco.is_dir():
        raise Rifiuto("Scegli due cartelle esistenti: fonte e destinazione sul disco esterno.")
    if _cloud(fonte) or _cloud(disco):
        raise Rifiuto("Le cartelle sincronizzate con il cloud non sono ammesse.")
    if _dentro(disco, fonte) or _dentro(fonte, disco):
        raise Rifiuto("Fonte e destinazione non possono essere annidate.")
    _esterno(disco)
    _origine_libera(fonte, _carica())
    return {"pronto": True, "origine": str(fonte), "dove": str(disco), "minutes": minutes}


def proteggi(origine: str | Path, dove: str | Path, passphrase: bytes, minutes: int = 15) -> dict:
    preparazione = prepara_protezione(origine, dove, minutes)
    _chiave(passphrase)
    minutes = preparazione["minutes"]
    fonte, disco = Path(preparazione["origine"]), Path(preparazione["dove"])

    with _registro() as r:
        _origine_libera(fonte, r)
        manifest = _scansiona(fonte)
        conta, byte = _totali(manifest)
        identificatore = uuid.uuid4().hex
        bundle = disco / f"{fonte.name}-{identificatore}.sparsebundle"
        if bundle.exists() or bundle.is_symlink():
            raise Rifiuto("Il bundle scelto esiste già; non sarà sovrascritto.")
        area = CASA / "montaggi"
        area.mkdir(mode=0o700, parents=True, exist_ok=True)
        monte = Path(tempfile.mkdtemp(prefix=identificatore + "-", dir=area))
        voce = {"id": identificatore, "nome": fonte.name, "origine": str(fonte),
                "bundle": str(bundle), "montaggio": str(fonte), "stato": "migrazione",
                "minutes": minutes, "generation": uuid.uuid4().hex,
                "file": conta, "byte": byte, "montaggio_temporaneo": str(monte),
                "plaintext_residuo": str(fonte), "verificato": False,
                "metadir": ".paratia-" + identificatore, "impronta": _impronta(manifest),
                "backup": str(fonte.with_name("." + fonte.name + ".paratia-" + identificatore))}
        r["cartelle"][identificatore] = voce
        _salva(r)
        try:
            dimensione = max(256 * 1024**2, byte + byte // 2 + 128 * 1024**2)
            _comando([HDIUTIL, "create", "-size", str((dimensione + 1024**2 - 1) // 1024**2) + "m", "-type", "SPARSEBUNDLE",
                      "-fs", "APFS", "-encryption", "AES-256", "-stdinpass", "-volname",
                      "paratia-" + identificatore, str(bundle)], passphrase)
            _attacca(bundle, monte, passphrase)
            _copia(fonte, monte, manifest)
            _scrivi_manifest(monte, voce, manifest)
            _verifica(monte, manifest, voce["metadir"])
            _verifica(fonte, manifest)
            _stacca(monte)
            _attacca(bundle, monte, passphrase)
            _leggi_manifest(monte, voce)
            _verifica(monte, manifest, voce["metadir"])
            _stacca(monte)
            _verifica(fonte, manifest)
            voce["verificato"] = True
            _salva(r)
            # The registry is already durable before any source deletion.
            backup = Path(voce["backup"])
            if backup.exists() or backup.is_symlink():
                raise Rifiuto("La cartella temporanea di recupero esiste già.")
            fonte.rename(backup)
            voce["plaintext_residuo"] = str(backup)
            _salva(r)
            fonte.mkdir(mode=0o700)
            _verifica(backup, manifest)
            # No encrypted success is reported while a plaintext tree remains.
            shutil.rmtree(backup)
            voce.update(stato="chiusa", plaintext_residuo=None)
            voce.pop("montaggio_temporaneo", None)
            _salva(r)
            return _esito_registrato(voce, "cartella-protetta", id=identificatore,
                                    origine=str(fonte), bundle=str(bundle), file=conta, byte=byte)
        except Exception as e:
            try:
                _stacca(monte)
            except Rifiuto:
                pass
            voce["stato"] = "migrazione-incompleta"
            # Keep the original/backup and the encrypted copy for recovery.
            _salva(r)
            _audit("cartella-migrazione-incompleta", id=identificatore)
            if isinstance(e, Rifiuto):
                e.cartella_id = identificatore
                raise
            raise Rifiuto("Migrazione incompleta: la fonte residua e il bundle sono conservati per il recupero.",
                          cartella_id=identificatore) from e
        finally:
            if not _montato(monte):
                try:
                    monte.rmdir()
                except OSError:
                    pass


def _avvia_timer(identificatore: str, generation: str, secondi: int) -> None:
    processo = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "timer", identificatore,
                                generation, str(secondi)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
    try:
        pronto, _, _ = select.select([processo.stdout], [], [], 5)
        if not pronto or processo.stdout.readline(16) != b"ready\n":
            raise Rifiuto("Il processo timer non ha confermato l'avvio.")
    except Exception:
        processo.terminate()
        try:
            processo.wait(timeout=5)
        except subprocess.TimeoutExpired:
            processo.kill()
            processo.wait()
        raise
    finally:
        processo.stdout.close()


def _prepara_apertura(v: dict, minutes: int) -> dict:
    if v["stato"] in ("migrazione", "migrazione-incompleta") or v.get("plaintext_residuo"):
        raise Rifiuto("La migrazione richiede recupero prima dell'apertura.")
    monte = _percorso(v["montaggio"])
    aperta = _montato(monte)
    if not aperta:
        bundle = Path(v["bundle"])
        if not bundle.is_dir():
            raise DiscoNonDisponibile("Il disco esterno non è disponibile. Collegalo e riprova ad aprire la cartella.")
        _verifica_struttura_bundle(bundle, v["id"])
        if not monte.is_dir():
            raise Rifiuto("Il punto di montaggio non è disponibile. Ripristina il percorso originale e riprova.")
        if any(monte.iterdir()):
            raise Rifiuto("Il punto di montaggio deve essere vuoto e non montato.")
    risultato = {"pronto": not aperta, "gia_aperta": aperta,
                 "cartella": _pubblica(v), "minutes": minutes}
    if aperta:
        risultato["timer_invariato"] = True
        risultato["minutes_richiesti"] = minutes
        risultato["minutes_effettivi"] = v.get("minutes")
        risultato["messaggio"] = ("La cartella è già aperta. Il timer resta invariato: "
                                  "i minuti richiesti non lo riavviano. Chiudi e riapri per cambiarlo.")
    return risultato


def prepara_apertura(identificatore: str, minutes: int = 15) -> dict:
    """Read mount metadata before the UI or CLI asks for a passphrase."""
    return _prepara_apertura(_voce(_carica(), identificatore), _minuti(minutes))


def apri(identificatore: str, passphrase: bytes, minutes: int = 15) -> dict:
    minutes = _minuti(minutes)
    with _registro() as r:
        v = _voce(r, identificatore)
        preparazione = _prepara_apertura(v, minutes)
        if preparazione["gia_aperta"]:
            return {**preparazione["cartella"], "gia_aperta": True,
                    "messaggio": preparazione["messaggio"], "timer_invariato": True,
                    "minutes_richiesti": minutes, "minutes_effettivi": v.get("minutes")}
        _chiave(passphrase)
        monte, bundle = _percorso(v["montaggio"]), _percorso(v["bundle"])
        try:
            _attacca(bundle, monte, passphrase)
        except Rifiuto:
            _audit("tentativo-fallito", azione="apertura", cartella=identificatore,
                   percorso=str(monte))
            raise
        v.update(stato="aperta", minutes=minutes, generation=uuid.uuid4().hex,
                 scadenza=time.time() + minutes * 60,
                 timer={"owner": os.getuid(), "id": uuid.uuid4().hex})
        try:
            _salva(r)
            _avvia_timer(identificatore, v["generation"], minutes * 60)
        except Exception as e:
            try:
                _stacca(monte)
                v.update(stato="chiusa", generation=uuid.uuid4().hex, scadenza=None)
                v.pop("timer", None)
                _salva(r)
            except Rifiuto:
                pass
            raise Rifiuto("Il timer non è stato avviato; controlla lo stato della cartella.") from e
        return _esito_registrato(v, "cartella-aperta", id=identificatore, minutes=minutes)


def _chiudi(r: dict, v: dict, force: bool = False) -> dict:
    stato_precedente = v["stato"]
    montaggi = [Path(v["montaggio"])]
    if v.get("montaggio_temporaneo"):
        montaggi.append(Path(v["montaggio_temporaneo"]))
    era_aperta = any(_montato(p) for p in montaggi)
    try:
        # Include an incomplete migration's temporary mount in the same
        # explicit choice and report the busy folder consistently.
        for monte in montaggi:
            if force:
                _stacca(monte, force=True)
            else:
                _stacca(monte)
    except Rifiuto as e:
        e.cartella_id = v["id"]
        _audit("tentativo-fallito", azione="chiusura", cartella=v["id"],
               percorso=str(monte))
        raise
    if v["stato"] not in ("migrazione", "migrazione-incompleta"):
        v["stato"] = "chiusa"
    # A successful detach invalidates the sleeping child without signals or
    # PIDs. A busy detach returns earlier and retains its retrying timer.
    if (era_aperta or v.get("timer") or v.get("scadenza") is not None
            or v["stato"] != stato_precedente):
        v.update(generation=uuid.uuid4().hex, scadenza=None)
        v.pop("timer", None)
        _salva(r)
    if era_aperta:
        risultato = _esito_registrato(v, "cartella-chiusa", id=v["id"],
                                      azione="chiusura-forzata" if force else "chiusura")
        if force:
            risultato["forzata"] = True
        return risultato
    return {**_pubblica(v), "gia_chiusa": True, "messaggio": "La cartella è già chiusa."}


def chiudi(identificatore: str, force: bool = False) -> dict:
    if type(force) is not bool:
        raise Rifiuto("La chiusura forzata richiede una scelta esplicita.")
    with _registro() as r:
        return _chiudi(r, _voce(r, identificatore), force=force)


def chiudi_tutte() -> list[dict]:
    fuori = []
    with _registro() as r:
        for v in r["cartelle"].values():
            try:
                fuori.append(_chiudi(r, v))
            except Rifiuto as e:
                fuori.append({**_pubblica(v), "errore": str(e)})
    return fuori


def annulla_migrazione(identificatore: str) -> dict:
    """Forget an incomplete attempt only if the complete source still exists."""
    with _registro() as r:
        v = _voce(r, identificatore)
        if v["stato"] not in ("migrazione", "migrazione-incompleta"):
            raise Rifiuto("Questa cartella non ha una migrazione da annullare.")
        if v.get("recupero_temporaneo"):
            residuo = _percorso(v["recupero_temporaneo"])
            if residuo.exists() and (not residuo.is_dir() or any(residuo.iterdir())):
                raise Rifiuto(f"Una copia plaintext di recupero è ancora presente: {residuo}")
        fonte = _percorso(v["origine"])
        if _montato(fonte) or not fonte.is_dir() or _impronta(_scansiona(fonte)) != v["impronta"]:
            raise Rifiuto("La fonte è cambiata o incompleta: non è sicuro annullare la migrazione.")
        if v.get("montaggio_temporaneo"):
            _stacca(Path(v["montaggio_temporaneo"]))
        del r["cartelle"][identificatore]
        _salva(r)
        return _esito_registrato({**v, "stato": "annullata", "bundle_conservato": True},
                                "cartella-migrazione-annullata", id=identificatore, origine=str(fonte))


def recupera(identificatore: str, passphrase: bytes) -> dict:
    """Restore plaintext from a verified image, without replacing user edits."""
    _chiave(passphrase)
    with _registro() as r:
        v = _voce(r, identificatore)
        if v["stato"] not in ("migrazione", "migrazione-incompleta") or not v.get("verificato"):
            raise Rifiuto("Il bundle non è stato verificato: conserva la fonte e annulla il tentativo.")
        if v.get("recupero_temporaneo"):
            residuo = _percorso(v["recupero_temporaneo"])
            if residuo.exists() and (not residuo.is_dir() or any(residuo.iterdir())):
                raise Rifiuto(f"Il recupero precedente conserva una copia plaintext: {residuo}")
        fonte, bundle = _percorso(v["origine"]), _percorso(v["bundle"])
        if _montato(fonte) or (fonte.exists() and (not fonte.is_dir() or any(fonte.iterdir()))):
            raise Rifiuto("L'origine contiene dati: il recupero non li sovrascriverà.")
        if v.get("montaggio_temporaneo"):
            _stacca(Path(v["montaggio_temporaneo"]))
        area = CASA / "montaggi"
        area.mkdir(mode=0o700, parents=True, exist_ok=True)
        monte = Path(tempfile.mkdtemp(prefix="recupero-", dir=area))
        staging = Path(tempfile.mkdtemp(prefix="." + fonte.name + ".recupero-", dir=fonte.parent))
        v["montaggio_temporaneo"] = str(monte)
        v["recupero_temporaneo"] = str(staging)
        _salva(r)
        try:
            _attacca(bundle, monte, passphrase)
            manifest = _leggi_manifest(monte, v)
            _verifica(monte, manifest, v["metadir"])
            backup = _percorso(v["backup"])
            if backup.exists():
                rimasto = _contenuto(_scansiona(backup))
                atteso = _contenuto(manifest)
                if any(k not in atteso or atteso[k] != dati for k, dati in rimasto.items()):
                    raise Rifiuto("La fonte residua è stata modificata: il recupero non la sovrascriverà.")
            for nome in manifest:
                if nome != "." and len(Path(nome).parts) == 1:
                    _comando([DITTO, "--rsrc", "--extattr", "--acl", str(monte / nome), str(staging / nome)])
            _copia_metadati(monte, staging)
            _verifica(staging, manifest)
            _stacca(monte)
            if fonte.exists():
                if any(fonte.iterdir()):
                    raise Rifiuto("L'origine è cambiata durante il recupero.")
                fonte.rmdir()
            staging.rename(fonte)
            v["plaintext_residuo"] = str(fonte)
            _salva(r)
            if backup.exists():
                shutil.rmtree(backup)
            del r["cartelle"][identificatore]
            _salva(r)
            return _esito_registrato({**v, "stato": "recuperata", "bundle_conservato": True},
                                    "cartella-recuperata", id=identificatore, origine=str(fonte))
        except Exception as e:
            try:
                _stacca(monte)
            except Rifiuto:
                pass
            v["stato"] = "migrazione-incompleta"
            _salva(r)
            if isinstance(e, Rifiuto):
                raise
            raise Rifiuto("Recupero incompleto: tutte le copie residue sono conservate.") from e
        finally:
            if not _montato(monte):
                try:
                    monte.rmdir()
                except OSError:
                    pass
            try:
                staging.rmdir()  # Never delete an uninstalled recovered tree.
            except OSError:
                pass


def _identita_timer(v: dict) -> tuple[int, str] | None:
    timer = v.get("timer")
    if (not isinstance(timer, dict) or type(timer.get("owner")) is not int
            or timer["owner"] != os.getuid() or not isinstance(timer.get("id"), str)
            or len(timer["id"]) != 32 or any(c not in "0123456789abcdef" for c in timer["id"])):
        return None
    return timer["owner"], timer["id"]


def _timer_corrente(v: dict | None, generation: str, identita: tuple[int, str]) -> bool:
    return bool(v and v["generation"] == generation and _identita_timer(v) == identita
                and _montato(Path(v["montaggio"])))


def _attendi_timer(identificatore: str, generation: str, identita: tuple[int, str], secondi: int) -> bool:
    """Return false as soon as a manual close invalidates this timer's token."""
    scadenza = time.monotonic() + secondi
    while True:
        if not _timer_corrente(_carica()["cartelle"].get(identificatore), generation, identita):
            return False
        residuo = scadenza - time.monotonic()
        if residuo <= 0:
            return True
        time.sleep(min(0.25, residuo))


def _timer(identificatore: str, generation: str, secondi: int) -> int:
    if secondi < 0 or secondi > 86400:
        return 2
    # The opening process holds the flock while it waits for readiness. The
    # registry uses atomic replacement, so this initial read needs no lock.
    iniziale = _carica()["cartelle"].get(identificatore)
    identita = _identita_timer(iniziale) if iniziale else None
    if identita is None or not _timer_corrente(iniziale, generation, identita):
        return 0
    sys.stdout.write("ready\n")
    sys.stdout.flush()
    if not _attendi_timer(identificatore, generation, identita, secondi):
        return 0
    while True:
        with _registro() as r:
            v = r["cartelle"].get(identificatore)
            if not _timer_corrente(v, generation, identita):
                return 0
            try:
                _chiudi(r, v)
                return 0
            except Rifiuto:
                pass  # A busy image stays open; retry without force-detach.
        if not _attendi_timer(identificatore, generation, identita, 5):
            return 0


def main(argv: list[str] | None = None) -> int:
    a = sys.argv[1:] if argv is None else argv
    if len(a) != 4 or a[0] != "timer":
        return 2
    try:
        return _timer(a[1], a[2], int(a[3]))
    except (Rifiuto, ValueError, OSError):
        return 2


if __name__ == "__main__":
    sys.exit(main())
