"""The existing fanale JSONL hash chain, with serialized, durable appends."""
from __future__ import annotations

import fcntl
import ctypes
import errno
import hashlib
import json
import os
import stat
import time
import sys
from pathlib import Path

ZERO = "0" * 64
_LIBACL = None


def acl_scrivibile(percorso):
    """Inspect macOS ACL metadata; never change permissions or read file bytes."""
    global _LIBACL
    if sys.platform != "darwin":
        return False
    if _LIBACL is None:
        _LIBACL = ctypes.CDLL(None, use_errno=True)
        _LIBACL.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _LIBACL.acl_get_file.restype = ctypes.c_void_p
        _LIBACL.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
        _LIBACL.acl_to_text.restype = ctypes.c_void_p
        _LIBACL.acl_free.argtypes = [ctypes.c_void_p]
        _LIBACL.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = _LIBACL.acl_get_file(os.fsencode(percorso), 0x100)
    if not acl:
        if ctypes.get_errno() in (0, errno.ENOENT):
            return False
        raise OSError(ctypes.get_errno(), "Impossibile verificare le ACL.")
    testo = None
    try:
        lunghezza = ctypes.c_ssize_t()
        testo = _LIBACL.acl_to_text(acl, ctypes.byref(lunghezza))
        if not testo:
            raise OSError("Impossibile interpretare le ACL.")
        righe = ctypes.string_at(testo, lunghezza.value).decode("utf-8", "strict").splitlines()
        mutazioni = {"write", "append", "writeattr", "writeextattr", "writesecurity", "chown",
                     "delete", "delete_child", "add_file", "add_subdirectory"}
        for riga in righe:
            parti = riga.split(":")
            if "allow" in parti and mutazioni.intersection(parti[-1].split(",")):
                return True
        return False
    finally:
        if testo:
            _LIBACL.acl_free(testo)
        _LIBACL.acl_free(acl)


def _coda(f):
    f.seek(0, os.SEEK_END)
    posizione = f.tell()
    if not posizione:
        return ZERO
    f.seek(posizione - 1)
    if f.read(1) != b"\n":
        raise ValueError("La catena termina con una riga incompleta.")
    raccolta = b""
    while posizione:
        n = min(posizione, 8192)
        posizione -= n
        f.seek(posizione)
        raccolta = f.read(n) + raccolta
        righe = raccolta.splitlines()
        complete = righe if posizione == 0 else righe[1:]
        for riga in reversed(complete):
            if riga.strip():
                json.loads(riga)
                return hashlib.sha256(riga.strip()).hexdigest()
        if len(raccolta) > 1048576:
            raise ValueError("Una riga della catena è troppo grande.")
    return ZERO


def appendi(percorso, voce, durevole=True):
    p = Path(percorso)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_CREAT | os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b", buffering=0) as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("La catena deve essere un file ordinario.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            r = {**voce, "precedente": _coda(f),
                 "quando": voce.get("quando", time.strftime("%Y-%m-%dT%H:%M:%S%z"))}
            dati = (json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode()
            if len(dati) > 1048576:
                raise ValueError("Il record della catena è troppo grande.")
            vista = memoryview(dati)
            while vista:
                n = os.write(fd, vista)
                if not n:
                    raise OSError("Scrittura della catena interrotta.")
                vista = vista[n:]
            if durevole:
                os.fsync(fd)
            return r
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


def verifica(percorso):
    p = Path(percorso)
    atteso, n = ZERO, 0
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            fcntl.flock(fd, fcntl.LOCK_SH)
            for riga in f:
                if not riga.strip():
                    continue
                n += 1
                if len(riga) > 1048576 or not riga.endswith(b"\n"):
                    raise ValueError("Riga troppo grande o incompleta.")
                v = json.loads(riga)
                if not isinstance(v, dict) or v.get("precedente") != atteso:
                    raise ValueError("Catena interrotta alla voce %d." % n)
                atteso = hashlib.sha256(riga.strip()).hexdigest()
    except FileNotFoundError:
        return {"ok": True, "voci": 0, "digest": ZERO, "errore": None}
    except (OSError, ValueError, TypeError) as e:
        return {"ok": False, "voci": n, "digest": atteso, "errore": str(e)}
    return {"ok": True, "voci": n, "digest": atteso, "errore": None}
