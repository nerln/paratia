"""Owned configuration, per-entry ACKs and external noowners mount metadata.

All paths are temporary. Disk topology/statfs fixtures replace kernel metadata;
the tests never read an SSD, launch eslogger or change ownership/permissions
outside their own temporary files.
"""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import plistlib
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
VOLUME = "/Volumes/SyntheticExternal"
SECRET = "SYNTHETIC-CONTENT-NEVER-COLLECTED"


@pytest.fixture()
def R(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "home"
    home.mkdir()
    monkeypatch.setenv("PARATIA_HOME", str(home / ".paratia"))
    spec = importlib.util.spec_from_file_location("registro_config_test", ROOT / "registro.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SYSTEM = tmp_path.resolve() / "logs"
    module.SUPPORT = tmp_path.resolve() / "support"
    module._test_home = home
    return module


def write_watch(R, entries):
    p = R.CASA / "registro" / "sorveglianza.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"versione": 1, "percorsi": entries}))
    return p


def write_protected(R, source, identifier="a" * 32, **extra):
    p = R.CASA / "cartelle.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = {"id": identifier, "nome": "Protetta", "origine": str(source), "montaggio": str(source),
             "bundle": str(source.with_name(source.name + "-" + identifier + ".sparsebundle")), **extra}
    p.write_text(json.dumps({"versione": 1, "cartelle": {identifier: entry}}))
    return p


@pytest.fixture()
def ssd(R, tmp_path, monkeypatch):
    """Match root's synthetic UID on a noowners filesystem, not its config."""
    source = tmp_path.resolve() / "ssd" / "documenti"
    source.mkdir(parents=True)
    actual_stat = Path.stat
    calls = []

    def metadata(path, *args, **kwargs):
        s = actual_stat(path, *args, **kwargs)
        if path == source.parent or source.parent in path.parents:
            values = list(s)
            values[2], values[4] = 999999, 0  # dev / apparent UID under root.
            return os.stat_result(values)
        return s

    def flags(path):
        if path == source.parent or source.parent in path.parents:
            return {"flags": R.MNT_IGNORE_OWNERSHIP, "mount": VOLUME}
        return {"flags": 0, "mount": "/System/Volumes/Data"}

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(R, "_statfs_configurazione", flags)
    monkeypatch.setattr(R, "_volume_esterno_configurazione", lambda mount: calls.append(mount))
    monkeypatch.setattr(R.sys, "platform", "darwin")
    return source, calls


@pytest.mark.parametrize("configured", ["watch", "protected", "both"])
def test_root_reads_noowners_requests_from_owned_config_and_probes_once(R, ssd, monkeypatch, configured):
    source, calls = ssd
    uid = os.getuid()
    if configured in ("watch", "both"):
        write_watch(R, {"ssd": {"percorso": str(source), "contents": SECRET}})
    if configured in ("protected", "both"):
        write_protected(R, source)
    monkeypatch.setattr(R.os, "getuid", lambda: 0)
    loaded = R.leggi_configurazione(R._test_home, uid)
    assert len(loaded["voci"]) == (2 if configured == "both" else 1)
    assert all(v["status"] == "confirmed" and v["reason_code"] is None for v in loaded["watch_status"])
    assert calls == [VOLUME]
    assert SECRET not in json.dumps(loaded)


def test_root_cannot_bypass_owned_request_requirement_by_calling_path_validator(R, ssd, monkeypatch):
    source, calls = ssd
    uid = os.getuid()
    monkeypatch.setattr(R.os, "getuid", lambda: 0)
    with pytest.raises(ValueError) as error:
        R._valida_sorveglianza(source, uid)
    assert error.value.code == "owner_mismatch"
    assert calls == []


def test_human_can_configure_noowners_and_atomic_file_retains_real_owner(R, ssd, monkeypatch):
    source, calls = ssd
    monkeypatch.setattr(R, "stato", lambda: {})
    result = R.sorveglia("ssd", source)
    assert result["configurata"] and not result["raccolta_attiva"]
    store = R.CASA / "registro" / "sorveglianza.json"
    assert store.stat().st_uid == os.getuid()
    assert not store.stat().st_mode & 0o077
    assert calls == [VOLUME]


@pytest.mark.parametrize("uid_matches", [False, True])
def test_noowners_always_requires_external_volume_even_when_apparent_uid_matches(R, tmp_path, monkeypatch, uid_matches):
    source = tmp_path.resolve() / "ordinary"
    source.mkdir()
    uid = os.getuid() if uid_matches else os.getuid() + 1
    monkeypatch.setattr(R.pwd, "getpwuid", lambda value: SimpleNamespace(pw_dir=str(R._test_home)))
    monkeypatch.setattr(R.sys, "platform", "darwin")
    monkeypatch.setattr(R, "_statfs_configurazione", lambda p: {"flags": R.MNT_IGNORE_OWNERSHIP,
                                                             "mount": "/System/Volumes/Data"})
    with pytest.raises(ValueError) as error:
        R._valida_sorveglianza(source, uid, configurazione_validata=True)
    assert error.value.code == "noowners_volume_unverified"


@pytest.mark.parametrize("flags", [0, 0x4000])
def test_owner_mismatch_without_noowners_stays_rejected(R, ssd, monkeypatch, flags):
    source, calls = ssd
    write_watch(R, {"ssd": {"percorso": str(source)}})
    monkeypatch.setattr(R, "_statfs_configurazione", lambda p: {"flags": flags, "mount": VOLUME})
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert not loaded["voci"]
    assert loaded["watch_status"][0]["reason_code"] == "owner_mismatch"
    assert calls == []


def test_bad_noowners_volume_is_probed_once_and_does_not_invalidate_internal_watch(R, ssd, tmp_path, monkeypatch):
    source, _ = ssd
    uid = os.getuid()
    sibling = source.parent / "seconda"
    sibling.mkdir()
    internal = tmp_path.resolve() / "internal"
    internal.mkdir()
    write_watch(R, {"ssd": {"percorso": str(source)}, "sibling": {"percorso": str(sibling)},
                    "internal": {"percorso": str(internal)}})
    calls = []

    def denied(mount):
        calls.append(mount)
        raise R._RifiutoConfigurazione("noowners_volume_unverified")

    monkeypatch.setattr(R, "_volume_esterno_configurazione", denied)
    monkeypatch.setattr(R.os, "getuid", lambda: 0)
    loaded = R.leggi_configurazione(R._test_home, uid)
    assert [v["id"] for v in loaded["voci"]] == ["internal"]
    assert [v["status"] for v in loaded["watch_status"]] == ["rejected", "rejected", "confirmed"]
    assert calls == [VOLUME]


@pytest.mark.parametrize("kind", ["watch", "protected"])
def test_noowners_keeps_symlink_rejection(R, ssd, tmp_path, monkeypatch, kind):
    source, calls = ssd
    alias = source.parent / "alias"
    alias.symlink_to(source, target_is_directory=True)
    if kind == "watch":
        write_watch(R, {"alias": {"percorso": str(alias)}})
    else:
        write_protected(R, alias)
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert not loaded["voci"] and loaded["watch_status"][0]["reason_code"] == "symlink"
    assert calls == []


@pytest.mark.parametrize("kind", ["world_write", "group_write", "acl_write", "wrong_owner", "hardlink", "symlink"])
def test_noowners_does_not_weaken_config_file_security(R, ssd, tmp_path, monkeypatch, kind):
    source, calls = ssd
    uid = os.getuid()
    p = write_watch(R, {"ssd": {"percorso": str(source)}})
    if kind == "world_write":
        p.chmod(0o606)
    elif kind == "group_write":
        p.chmod(0o620)
    elif kind == "acl_write":
        monkeypatch.setattr(R, "acl_scrivibile", lambda path: True)
    elif kind == "wrong_owner":
        uid += 1
    elif kind == "hardlink":
        os.link(p, tmp_path.resolve() / "second-hardlink")
    else:
        real = p.with_suffix(".real")
        p.rename(real)
        p.symlink_to(real)
    with pytest.raises((OSError, ValueError)):
        R.leggi_sorveglianza(p, uid)
    loaded = R.leggi_configurazione(R._test_home, uid)
    assert not loaded["voci"]
    assert loaded["watch_status"] == [R._esito_configurazione(None, "config_unreadable")]
    assert calls == []


@pytest.mark.parametrize("bad", [[], {"percorso": "relative"}, {"percorso": "/"}, {"percorso": "/Users"}])
def test_bad_watch_entry_does_not_hide_valid_external_or_protected_roots(R, ssd, bad):
    source, calls = ssd
    write_watch(R, {"bad": bad, "good": {"percorso": str(source)}})
    write_protected(R, source)
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert {v["id"] for v in loaded["voci"]} == {"good", "a" * 32}
    assert next(v for v in loaded["watch_status"] if v["id"] == "bad")["status"] == "rejected"
    assert calls == [VOLUME]


def test_bad_protected_entry_does_not_hide_other_roots(R, ssd):
    source, calls = ssd
    p = write_protected(R, source)
    data = json.loads(p.read_text())
    data["cartelle"]["b" * 32] = {"id": "b" * 32, "origine": "/", "montaggio": "/", "bundle": "/bad"}
    p.write_text(json.dumps(data))
    write_watch(R, {"good": {"percorso": str(source)}})
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert {v["id"] for v in loaded["voci"]} == {"good", "a" * 32}
    assert next(v for v in loaded["watch_status"] if v["id"] == "b" * 32)["status"] == "rejected"
    assert calls == [VOLUME]


def test_invalid_id_is_not_reflected_and_missing_watch_is_not_confirmed(R, tmp_path):
    missing = tmp_path.resolve() / "missing"
    write_watch(R, {SECRET + "\n": {"percorso": SECRET}, "missing": {"percorso": str(missing)}})
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert not loaded["voci"]
    assert loaded["watch_status"][0]["id"] is None
    assert loaded["watch_status"][1]["reason_code"] == "folder_missing"
    assert SECRET not in json.dumps(loaded)


def test_correcting_one_entry_replaces_rejection_without_stale_root(R, tmp_path):
    first, other = tmp_path.resolve() / "first", tmp_path.resolve() / "other"
    first.mkdir()
    other.mkdir()
    write_watch(R, {"first": {"percorso": str(first)}, "other": {"percorso": str(other)}})
    assert len(R.leggi_configurazione(R._test_home, os.getuid())["voci"]) == 2
    first.rmdir()
    middle = R.leggi_configurazione(R._test_home, os.getuid())
    assert [v["id"] for v in middle["voci"]] == ["other"]
    assert middle["watch_status"][0]["status"] == "rejected"
    first.mkdir()
    assert all(v["status"] == "confirmed" for v in R.leggi_configurazione(R._test_home, os.getuid())["watch_status"])


def test_duplicate_id_across_protected_and_plain_watch_is_rejected_without_hiding_other_id(R, tmp_path):
    protected, watched = tmp_path.resolve() / "protected", tmp_path.resolve() / "watched"
    protected.mkdir()
    watched.mkdir()
    identifier = "a" * 32
    write_protected(R, protected, identifier)
    write_watch(R, {identifier: {"percorso": str(watched)}, "other": {"percorso": str(watched)}})
    loaded = R.leggi_configurazione(R._test_home, os.getuid())
    assert [v["id"] for v in loaded["voci"]] == ["other"]
    rejected = [v for v in loaded["watch_status"] if v["id"] == identifier]
    assert len(rejected) == 2 and all(v["reason_code"] == "duplicate_id" and v["status"] == "rejected" for v in rejected)


def test_cli_cannot_configure_watch_with_protected_id_or_mutate_existing_store(R, tmp_path):
    protected, watched = tmp_path.resolve() / "protected", tmp_path.resolve() / "watched"
    protected.mkdir()
    watched.mkdir()
    identifier = "a" * 32
    write_protected(R, protected, identifier)
    p = write_watch(R, {"other": {"percorso": str(protected.parent / "missing")}})
    before = p.read_bytes()
    with pytest.raises(ValueError) as error:
        R.sorveglia(identifier, watched)
    assert error.value.code == "duplicate_id"
    assert p.read_bytes() == before


@pytest.mark.parametrize("bad_file", ["watch", "protected"])
@pytest.mark.parametrize("damage", ["malformed", "unowned"])
def test_one_rejected_configuration_file_revokes_its_roots_and_preserves_the_other(R, tmp_path, monkeypatch, bad_file, damage):
    protected, watched = tmp_path.resolve() / "protected", tmp_path.resolve() / "watched"
    protected.mkdir()
    watched.mkdir()
    protected_id = "a" * 32
    files = {"protected": write_protected(R, protected, protected_id),
             "watch": write_watch(R, {"watch": {"percorso": str(watched)}})}
    first = R.leggi_configurazione(R._test_home, os.getuid())
    assert {v["id"] for v in first["voci"]} == {protected_id, "watch"}
    failed = files[bad_file]
    original = failed.read_bytes()
    with monkeypatch.context() as patch:
        if damage == "malformed":
            failed.write_text("{\"contents\":\"" + SECRET)
        else:
            inode = failed.stat().st_ino
            actual_fstat = os.fstat

            def metadata(fd):
                s = actual_fstat(fd)
                if s.st_ino == inode:
                    values = list(s)
                    values[4] += 1
                    return os.stat_result(values)
                return s
            patch.setattr(R.os, "fstat", metadata)
        after = R.leggi_configurazione(R._test_home, os.getuid())
    good_id = protected_id if bad_file == "watch" else "watch"
    assert [v["id"] for v in after["voci"]] == [good_id]
    rejected = [v for v in after["watch_status"] if v["status"] == "rejected"]
    assert rejected == [R._esito_configurazione(None, "config_unreadable")]
    assert SECRET not in json.dumps(after)
    failed.write_bytes(original)
    restored = R.leggi_configurazione(R._test_home, os.getuid())
    assert {v["id"] for v in restored["voci"]} == {protected_id, "watch"}
    assert all(v["status"] == "confirmed" for v in restored["watch_status"])


def test_path_query_ignores_invalid_neighbor_entry_in_same_watch_file(R, tmp_path):
    source = tmp_path.resolve() / "valid-watch"
    source.mkdir()
    write_watch(R, {"broken": {"percorso": "/"}, "valid": {"percorso": str(source)}})
    R.annota("open", cartella="valid", percorso=str(source / "synthetic.txt"))
    assert R.risolvi_cartella(str(source)) == "valid"
    assert [v["cartella"] for v in R.query({"folder": str(source)})] == ["valid"]
    with pytest.raises(R.ErroreRegistro) as error:
        R.risolvi_cartella("/")
    assert error.value.code == "folder_not_configured"


@pytest.mark.parametrize("bad_file", ["watch", "protected"])
def test_path_query_uses_valid_file_when_the_other_is_unreadable(R, tmp_path, bad_file):
    protected, watched = tmp_path.resolve() / "protected", tmp_path.resolve() / "watched"
    protected.mkdir()
    watched.mkdir()
    identifier = "a" * 32
    files = {"protected": write_protected(R, protected, identifier),
             "watch": write_watch(R, {"watch": {"percorso": str(watched)}})}
    files[bad_file].write_text("{" + SECRET)
    good_path = protected if bad_file == "watch" else watched
    good_id = identifier if bad_file == "watch" else "watch"
    R.annota("open", cartella=good_id, percorso=str(good_path / "synthetic.txt"))
    assert R.risolvi_cartella(str(good_path)) == good_id
    assert [v["cartella"] for v in R.query({"folder": str(good_path)})] == [good_id]
    invalid_path = watched if bad_file == "watch" else protected
    with pytest.raises(R.ErroreRegistro) as error:
        R.risolvi_cartella(str(invalid_path))
    assert error.value.code == "folder_not_configured"
    assert SECRET not in str(error.value)


def disk_result(data, returncode=0):
    return SimpleNamespace(stdout=plistlib.dumps(data), returncode=returncode)


@pytest.mark.parametrize("topology", ["apfs", "partition", "whole"])
def test_external_proof_follows_all_physical_stores_and_parent_whole_disk(R, monkeypatch, topology):
    whole = {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Physical", "Internal": False}
    mapping = {VOLUME: ({"APFSPhysicalStores": [{"APFSPhysicalStore": "disk9s2"}]} if topology == "apfs" else
                       {"DeviceIdentifier": "disk9s2", "ParentWholeDisk": "disk9"} if topology == "partition" else whole),
               "disk9s2": {"DeviceIdentifier": "disk9s2", "ParentWholeDisk": "disk9"}, "disk9": whole}
    calls = []

    def command(args, **kwargs):
        calls.append(args[-1])
        assert args[:3] == ["/usr/sbin/diskutil", "info", "-plist"]
        assert 0 < kwargs["timeout"] <= 1
        assert kwargs["stderr"] is subprocess.DEVNULL
        return disk_result(mapping[args[-1]])

    monkeypatch.setattr(R.subprocess, "run", command)
    R._volume_esterno_configurazione(VOLUME)
    assert calls == ([VOLUME, "disk9s2", "disk9"] if topology == "apfs" else
                     [VOLUME, "disk9"] if topology == "partition" else [VOLUME])


@pytest.mark.parametrize("bad", [
    {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Physical", "Internal": True},
    {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Virtual", "Internal": False},
    {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Physical"},
    {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Physical", "Internal": False, "BusProtocol": "Disk Image"},
    {"APFSPhysicalStores": []}, {"APFSPhysicalStores": [{"APFSPhysicalStore": SECRET}]},
    {"DeviceIdentifier": "disk9s1", "ParentWholeDisk": "disk9s1"},
])
def test_external_proof_refuses_internal_virtual_missing_and_ambiguous_topology(R, monkeypatch, bad):
    monkeypatch.setattr(R.subprocess, "run", lambda *args, **kwargs: disk_result(bad))
    with pytest.raises(ValueError) as error:
        R._volume_esterno_configurazione(VOLUME)
    assert error.value.code == "noowners_volume_unverified"
    assert SECRET not in str(error.value)


def test_external_proof_rejects_mixed_internal_physical_stores_and_cycles(R, monkeypatch):
    mapping = {VOLUME: {"APFSPhysicalStores": [{"APFSPhysicalStore": "disk9"}, {"APFSPhysicalStore": "disk0"}]},
               "disk9": {"DeviceIdentifier": "disk9", "VirtualOrPhysical": "Physical", "Internal": False},
               "disk0": {"DeviceIdentifier": "disk0", "VirtualOrPhysical": "Physical", "Internal": True}}
    monkeypatch.setattr(R.subprocess, "run", lambda args, **kwargs: disk_result(mapping[args[-1]]))
    with pytest.raises(ValueError):
        R._volume_esterno_configurazione(VOLUME)
    mapping[VOLUME] = {"DeviceIdentifier": "disk9s1", "ParentWholeDisk": "disk9"}
    mapping["disk9"] = {"APFSPhysicalStores": [{"APFSPhysicalStore": "disk9"}]}
    with pytest.raises(ValueError):
        R._volume_esterno_configurazione(VOLUME)


@pytest.mark.parametrize("mount", ["/", "/System/Volumes/Data", "/Volumes", "/Volumes/SyntheticExternal/child"])
def test_system_or_nested_mount_is_rejected_before_diskutil(R, monkeypatch, mount):
    def never(*args, **kwargs):
        pytest.fail("A system mount was passed to diskutil")
    monkeypatch.setattr(R.subprocess, "run", never)
    with pytest.raises(ValueError):
        R._volume_esterno_configurazione(mount)


@pytest.mark.parametrize("failure", ["timeout", "bad_plist", "oversized", "exit"])
def test_failed_volume_probe_never_reflects_process_output(R, monkeypatch, failure):
    def command(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], output=SECRET)
        return SimpleNamespace(stdout=(SECRET.encode() if failure == "bad_plist" else b"x" * 65537
                                       if failure == "oversized" else plistlib.dumps({})),
                               returncode=1 if failure == "exit" else 0)
    monkeypatch.setattr(R.subprocess, "run", command)
    with pytest.raises(ValueError) as error:
        R._volume_esterno_configurazione(VOLUME)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_unsupported_statfs_fails_closed_for_owner_exception(R, tmp_path, monkeypatch, platform):
    monkeypatch.setattr(R.sys, "platform", platform)
    with pytest.raises(ValueError) as error:
        R._statfs_configurazione(tmp_path)
    assert error.value.code == "noowners_volume_unverified"


@pytest.mark.parametrize("architecture,symbol", [("arm64", "statfs"), ("x86_64", "statfs$INODE64")])
def test_statfs_reads_real_flag_field_using_matching_darwin_abi(R, tmp_path, monkeypatch, architecture, symbol):
    class Function:
        def __call__(self, path, result):
            assert path == os.fsencode(tmp_path)
            result._obj.f_flags = R.MNT_IGNORE_OWNERSHIP
            result._obj.f_mntonname = VOLUME.encode()
            return 0
    lib = SimpleNamespace(**{symbol: Function()})
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: lib)
    monkeypatch.setattr(R.os, "uname", lambda: SimpleNamespace(machine=architecture))
    monkeypatch.setattr(R.sys, "platform", "darwin")
    assert R._statfs_configurazione(tmp_path) == {"flags": R.MNT_IGNORE_OWNERSHIP, "mount": VOLUME}
