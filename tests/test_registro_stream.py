"""Raw-stream filtering, lineage/loss fidelity and bounded synthetic throughput."""
from __future__ import annotations

import importlib.util
import datetime
import json
import os
import sys
import time
import unicodedata
from pathlib import Path
from unittest import mock

import pytest

import registro as R
import registro_daemon as D

ROOT = "/Users/paratia-synthetic/Desktop/folder-test"


def message(path=ROOT + "/file.txt", sequence=1, kind="open", when="1970-01-01T00:16:40+00:00"):
    p = {"audit_token": {"pid": 20, "pidversion": 1, "euid": os.getuid()},
         "executable": {"path": "/bin/cat"}, "parent_audit_token": {"pid": 1, "pidversion": 1}}
    event = {"open": {"file": {"path": path}, "fflag": 1},
             "exec": {"target": {**p, "executable": {"path": "/usr/local/bin/codex"}}},
             "fork": {"child": {**p, "audit_token": {"pid": 21, "pidversion": 2, "euid": os.getuid()}}},
             "exit": {"stat": 0}}[kind]
    return {"schema_version": 1, "version": 7, "event_type": "ES_EVENT_TYPE_NOTIFY_" + kind.upper(),
            "global_seq_num": sequence, "seq_num": sequence, "time": when,
            "process": p, "event": {kind: event}}


def stream(root=ROOT, **kwargs):
    records = []
    observer = R.Osservatore([{"id": "watch", "origine": root}], records.append)
    return D.FlussoEslogger(observer, **kwargs), observer, records


def raw(msg, **kwargs):
    return json.dumps(msg, separators=(",", ":"), **kwargs).encode()


def test_default_subscription_omits_noisy_events_without_breaking_historical_parser():
    omessi = {"lookup", "mmap", "close", "mount", "unmount"}
    assert not omessi & set(R.EVENTI)
    assert {"exec", "fork", "exit", "open", "write", "create", "rename", "unlink", "truncate"} == set(R.EVENTI)
    assert omessi <= set(R.TIPI_SUPPORTATI)


@pytest.mark.parametrize("root,path", [
    (ROOT, ROOT + "/file"),
    (ROOT, "/System/Volumes/Data" + ROOT + "/file"),
    ("/private/tmp/watch", "/tmp/watch/file"),
    ("/tmp/watch", "/private/tmp/watch/file"),
    ("/private/var/watch", "/var/watch/file"),
    ("/private/etc/watch", "/etc/watch/file"),
    ("/private/tmp/watch", "/System/Volumes/Data/private/tmp/watch/file"),
    ("/Volumes/SSD/watch", "/Volumes/SSD/watch/file"),
])
def test_real_path_aliases_pass_filter_and_match_watch(root, path):
    s, o, records = stream(root)
    s.ricevi(raw(message(path)))
    assert s.parsed_lines == 1 and s.filtered_lines == 0
    assert records[-1]["cartella"] == "watch"
    assert o.persi == 0


@pytest.mark.parametrize("encoding", ["utf8", "ascii", "slash", "all_ascii", "mixed", "upper_unicode", "surrogate"])
def test_unicode_normalization_and_json_path_escapes_never_hide_a_watch(encoding):
    root = ROOT + "/caffè" + ("𝄞" if encoding == "surrogate" else "")
    path = unicodedata.normalize("NFD", "/System/Volumes/Data" + root + "/file")
    r = raw(message(path), ensure_ascii=encoding != "utf8")
    if encoding == "slash":
        r = r.replace(b"/", b"\\/")
    elif encoding == "all_ascii":
        # JSON permits escaping any character, even every ASCII path character.
        encoded = "".join("\\u%04x" % ord(c) for c in path).encode()
        r = r.replace(json.dumps(path)[1:-1].encode(), encoded)
    elif encoding == "mixed":
        r = r.replace(b"/Users", b"\\/\\u0055sers")
    elif encoding == "upper_unicode":
        r = r.replace(b"\\u0301", b"\\u0301").replace(b"\\u00e8", b"\\u00E8")
    s, _, records = stream(root)
    s.ricevi(r)
    assert s.parsed_lines == 1 and records[-1]["cartella"] == "watch"


def escaped_raw(msg, spelling):
    """Use valid JSON spellings without changing the decoded event."""
    line = raw(msg)
    if spelling.startswith("unicode"):
        for control in ("\t", "\n", "\r", "\b", "\f"):
            short = json.dumps(control)[1:-1].encode()
            escaped = ("\\u%04x" % ord(control)).encode()
            if spelling == "unicode_upper":
                escaped = escaped[:-4] + escaped[-4:].upper()
            line = line.replace(short, escaped)
    if spelling == "slash":
        line = line.replace(b"/", b"\\/")
    return line


@pytest.mark.parametrize("control", ["\t", "\n", "\r", "\b", "\f"],
                         ids=["tab", "newline", "carriage-return", "backspace", "form-feed"])
@pytest.mark.parametrize("position", ["parent", "root"])
@pytest.mark.parametrize("spelling", ["short", "unicode_lower", "unicode_upper", "slash"])
def test_control_path_records_match_full_parser_including_lineage_and_loss(control, position, spelling):
    root = ("/Users/paratia-synthetic/parent" + control + "/watch" if position == "parent"
            else "/Users/paratia-synthetic/parent/watch" + control)
    s, filtered, actual = stream(root)
    expected = []
    full = R.Osservatore([{"id": "watch", "origine": root}], expected.append)
    rows = [message("/System/Library/unrelated", 1, "exec"),
            message("/System/Library/unrelated", 2, "fork"),
            message("/System/Library/unrelated", 3),
            message(root + "/file", 4), message(root, 6),
            message("/System/Library/unrelated", 7, "exit"),
            message(root + "/later", 8)]
    # The exec target keeps the same executable for subsequent parent events.
    for parent_event in (rows[1], rows[2], rows[4], rows[5]):
        parent_event["process"]["executable"]["path"] = "/usr/local/bin/codex"
    for access in (rows[3], rows[6]):
        access["process"]["audit_token"].update(pid=21, pidversion=2)
        access["process"]["parent_audit_token"] = {"pid": 20, "pidversion": 1}
    rows[4]["event_type"] = "ES_EVENT_TYPE_NOTIFY_CREATE"
    rows[4]["event"] = {"create": {"destination": {"new_path": {
        "dir": {"path": str(Path(root).parent)}, "filename": Path(root).name}}}}

    class FixedDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 14, 0, 0, tzinfo=datetime.timezone.utc)

    with mock.patch.object(R.datetime, "datetime", FixedDatetime):
        for msg in rows:
            line = escaped_raw(msg, spelling)
            full.ricevi(json.loads(line))
            s.ricevi(line)

    assert actual == expected
    accesses = [r for r in actual if r["evento"] != "diagnostico"]
    assert len(accesses) == 3 and all(r["cartella"] == "watch" for r in accesses)
    assert accesses[0]["nome_agente"] == "Codex" and accesses[0]["agente"] is True
    assert accesses[1]["percorso"] == root
    assert filtered.persi == full.persi == 1 and filtered.sano is full.sano is True
    assert filtered.ultima_perdita is not None and full.ultima_perdita is not None
    assert filtered.globale == full.globale == 8
    assert s.codifica_incerta and s.parsed_lines == len(rows) and s.filtered_lines == 0


@pytest.mark.parametrize("character", [chr(n) for n in range(32)] + ['"', "\\"],
                         ids=["U+%04X" % n for n in range(32)] + ["quote", "backslash"])
def test_json_required_escape_in_any_root_conservatively_disables_filter(character):
    s, _, _ = stream("/Users/parent" + character + "/watch")
    assert s.codifica_incerta
    s.ricevi(raw(message("/System/Library/unrelated")))
    assert s.parsed_lines == 1 and s.filtered_lines == 0


@pytest.mark.parametrize("campo", D.CAMPI_RADICI)
def test_control_characters_disable_filter_for_each_protected_root_field(campo):
    root = "/Users/parent\n/watch"
    actual, expected = [], []
    filtered = R.Osservatore([{"id": "watch", campo: root}], actual.append)
    full = R.Osservatore([{"id": "watch", campo: root}], expected.append)
    s = D.FlussoEslogger(filtered)
    line = raw(message(root + "/file"))
    full.ricevi(json.loads(line))
    s.ricevi(line)
    assert actual == expected and actual[0]["cartella"] == "watch"
    assert s.parsed_lines == 1 and s.filtered_lines == 0


def test_uncertain_utf8_watch_root_falls_back_without_failing_recompile():
    s, _, _ = stream("/Users/parent\udcff/watch")
    assert s.codifica_incerta
    s.ricevi(raw(message("/System/Library/unrelated")))
    assert s.parsed_lines == 1 and s.filtered_lines == 0


def test_refresh_from_control_root_restores_fast_filter_for_ordinary_paths():
    s, o, records = stream("/Users/parent\t/watch")
    s.ricevi(raw(message("/System/Library/unrelated", 1)))
    o.protetti = [{"id": "watch", "origine": ROOT}]
    s.ricompila_radici()
    s.ricevi(raw(message("/System/Library/unrelated", 2)))
    s.ricevi(raw(message(sequence=3)))
    assert not s.codifica_incerta and s.filtered_lines == 1 and s.parsed_lines == 2
    assert records[-1]["cartella"] == "watch" and o.persi == 0


@pytest.mark.parametrize("numeric", [False, True])
def test_intentionally_filtered_lines_do_not_look_like_lost_events(numeric):
    s, o, records = stream()
    with mock.patch.object(D.json, "loads", wraps=json.loads) as loads:
        for i in range(1, 31):
            msg = message(ROOT + "/file" if i in (1, 30) else "/System/Library/unrelated", i)
            if numeric:
                msg["event_type"] = 10
            s.ricevi(raw(msg))
        assert loads.call_count == 2
    assert s.filtered_lines == 28 and s.parsed_lines == 2
    assert o.persi == 0 and o.sano and len(records) == 2


@pytest.mark.parametrize("global_sequence", [True, False])
def test_real_sequence_loss_is_detected_even_between_filtered_lines(global_sequence):
    s, o, records = stream()
    for i in (1, 2, 5, 6):
        msg = message("/System/Library/unrelated", i)
        if not global_sequence:
            del msg["global_seq_num"]
        s.ricevi(raw(msg))
    assert s.filtered_lines == 4 and s.parsed_lines == 0
    assert o.rileva_perdite and o.persi == 2 and o.sano and o.ultima_perdita is not None
    assert len(records) == 1  # Exactly one bounded diagnostic.
    assert records[0]["motivo"] == "eventi-persi" and records[0]["persi"] == 2


def test_sequence_restart_is_not_silently_discarded():
    s, o, records = stream()
    for i in (100, 1):
        s.ricevi(raw(message("/System/Library/unrelated", i)))
    assert not o.sano and o.persi == 0
    assert records[0]["motivo"] == "sequenza-riavviata"


def _salute(o, ora):
    """Same inputs the daemon writes to stato.json; healthy follows the daemon's formula."""
    dati = {"running": True, "healthy": o.sano, "needs_fda": False, "schema_supported": True,
            "watched_ids": ["watch"], "watch_status": [], "event_lag_seconds": 0.1,
            "dropped_events": o.persi, "last_dropped_at": o.ultima_perdita}
    motivi = R.motivi_salute(dati, ora)
    return {m["code"] for m in motivi}, bool(o.sano and not motivi)


def test_loss_total_is_kept_but_health_reason_expires_after_ten_minutes():
    clock = {"now": 1000.0}
    records = []
    o = R.Osservatore([{"id": "watch", "origine": ROOT}], records.append, orologio=lambda: clock["now"])
    s = D.FlussoEslogger(o, wall_time=lambda: clock["now"])
    # Startup: sequence 1 then 4 at t=1000 is a loss of two events.
    for i in (1, 4):
        s.ricevi(raw(message("/System/Library/unrelated", i)))
    assert o.persi == 2 and o.ultima_perdita == 1000.0
    assert _salute(o, 1599.0) == ({"dropped_events"}, False)
    assert _salute(o, 1600.0) == (set(), True)  # Expired exactly at ten minutes.
    assert o.persi == 2 and o.sano  # The cumulative total stays; the session is not stuck.

    # A later loss restarts the window without writing a second diagnostic.
    clock["now"] = 2000.0
    s.ricevi(raw(message("/System/Library/unrelated", 8)))
    assert o.persi == 5 and o.ultima_perdita == 2000.0
    assert _salute(o, 2599.0) == ({"dropped_events"}, False)
    assert _salute(o, 2600.0) == (set(), True)
    assert sum(r["motivo"] == "eventi-persi" for r in records) == 1


@pytest.mark.parametrize("stamp", [None, "ieri", float("nan"), 1000.0 + 61])
def test_invalid_or_far_future_loss_timestamp_never_creates_a_permanent_warning(stamp):
    dati = {"running": True, "healthy": True, "needs_fda": False, "schema_supported": True,
            "watched_ids": ["watch"], "dropped_events": 4, "last_dropped_at": stamp}
    assert "dropped_events" not in {m["code"] for m in R.motivi_salute(dati, 1000.0)}


@pytest.mark.parametrize("kind", ["exec", "fork", "exit"])
def test_ancestry_events_always_decode_even_without_any_watched_root(kind):
    s, o, _ = stream()
    s.ricevi(raw(message("/System/Library/unrelated", kind=kind)))
    assert s.parsed_lines == 1 and s.filtered_lines == 0
    assert (20, 1) in o.discendenza.processi


def test_unrelated_exec_keeps_agent_classification_for_later_watched_access():
    s, _, records = stream()
    s.ricevi(raw(message("/System/Library/unrelated", kind="exec")))
    msg = message(sequence=2)
    msg["process"]["audit_token"]["pid"] = 21
    msg["process"]["parent_audit_token"] = {"pid": 20, "pidversion": 1}
    s.ricevi(raw(msg))
    assert records[-1]["agente"] is True
    assert records[-1]["nome_agente"] == "Codex"


@pytest.mark.parametrize("change", ["schema", "unknown_type", "escaped_header", "duplicate_nested_sequence", "missing_sequences"])
def test_uncertain_headers_use_full_parser(change):
    msg = message("/System/Library/unrelated")
    if change == "schema":
        msg["schema_version"] = 2
    elif change == "unknown_type":
        msg["event_type"] = "ES_EVENT_TYPE_NOTIFY_UNKNOWN"
    elif change == "duplicate_nested_sequence":
        msg["process"]["global_seq_num"] = 1000
    elif change == "missing_sequences":
        del msg["seq_num"], msg["global_seq_num"]
    r = raw(msg)
    if change == "escaped_header":
        r = r.replace(b'"schema_version"', b'"\\u0073chema_version"')
    s, o, _ = stream()
    s.ricevi(r)
    assert s.parsed_lines == 1 and s.filtered_lines == 0
    if change == "schema":
        assert o.schema_fatale


def test_unicode_escaped_unrelated_lines_do_not_invoke_json_decoder():
    s, _, _ = stream()
    r = raw(message("/System/Library/caffè"), ensure_ascii=True).replace(b"/", b"\\/")
    with mock.patch.object(D.json, "loads", side_effect=AssertionError("unrelated JSON decoded")):
        s.ricevi(r)
    assert s.filtered_lines == 1


@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_mixed_unicode_composition_inside_root_component_is_not_lost(ensure_ascii):
    root = "/Users/caffè-é/watch"
    path = "/Users/caffè-e\u0301/watch/file"
    s, _, records = stream(root)
    s.ricevi(raw(message(path), ensure_ascii=ensure_ascii))
    assert s.parsed_lines == 1 and records[-1]["cartella"] == "watch"


def test_new_directory_split_parent_filename_is_retained():
    s, _, records = stream()
    msg = message()
    msg["event_type"] = "ES_EVENT_TYPE_NOTIFY_CREATE"
    msg["event"] = {"create": {"destination": {"new_path": {
        "dir": {"path": str(Path(ROOT).parent)}, "filename": Path(ROOT).name}}}}
    s.ricevi(raw(msg))
    assert records[-1]["percorso"] == ROOT and s.parsed_lines == 1


def test_refresh_watch_roots_changes_filter_without_resetting_sequence_tracking():
    s, o, records = stream()
    s.ricevi(raw(message("/Volumes/SSD/new/file", 1)))
    o.protetti = [{"id": "new", "origine": "/Volumes/SSD/new"}]
    s.ricompila_radici()
    s.ricevi(raw(message("/Volumes/SSD/new/file", 2)))
    assert s.filtered_lines == 1 and s.parsed_lines == 1
    assert records[-1]["cartella"] == "new" and o.persi == 0


def test_lag_and_received_age_distinguish_backlog_from_normal_silence():
    clock = {"wall": 1001.5, "mono": 1.0}
    s, _, _ = stream(wall_time=lambda: clock["wall"], monotonic=lambda: clock["mono"])
    for i in range(1, 11):
        s.ricevi(raw(message("/System/Library/unrelated", i)))
    clock["mono"] = 2.0
    first = s.metriche()
    assert first["event_lag_seconds"] == 1.5
    assert first["lines_per_second"] == 10
    assert first["last_event_received_at"] == 1001.5
    clock.update(wall=1061.5, mono=62.0)
    quiet = s.metriche()
    assert quiet["event_lag_seconds"] == 1.5
    assert quiet["last_event_age_seconds"] == 60
    assert quiet["lines_per_second"] == 0


@pytest.mark.parametrize("when", [None, "invalid", "1970-01-01T00:16:40"])
def test_unknown_or_naive_event_time_does_not_claim_measured_latency(when):
    s, _, _ = stream()
    s.ricevi(raw(message(when=when)))
    assert s.metriche()["event_lag_seconds"] is None


@pytest.mark.parametrize("fraction", ["123", "123456", "123456789"])
@pytest.mark.parametrize("offset", ["Z", "+00:00", "+0000", "+02:00", "+0200", "-02:00", "-0200"])
def test_native_iso_fraction_and_offset_forms_measure_the_same_lag(fraction, offset):
    hour = "02" if offset.startswith("+") and "02" in offset else "22" if offset.startswith("-") else "00"
    day = "1969-12-31" if offset.startswith("-") else "1970-01-01"
    when = f"{day}T{hour}:16:40.{fraction}{offset}"
    s, _, _ = stream(wall_time=lambda: 1001.5)
    s.ricevi(raw(message(when=when)))
    expected = round(1.5 - int(fraction[:6].ljust(6, "0")) / 1000000, 3)
    assert s.metriche()["event_lag_seconds"] == expected


@pytest.mark.parametrize("when", ["1970-01-01T00:16:40.123456789", "1970-01-01T00:16:40.1234567890Z",
                                   "1970-01-01T00:16:40.123+9999", "1970-99-01T00:16:40Z",
                                   "1970-01-01T00:16:40Z trailing", "invalid", None])
def test_native_timestamp_parser_rejects_invalid_or_timezone_free_times(when):
    assert D._timestamp_evento(when) is None


def test_prefilter_retains_all_protected_folder_roots():
    for campo in D.CAMPI_RADICI:
        records = []
        o = R.Osservatore([{"id": "watch", campo: ROOT}], records.append)
        s = D.FlussoEslogger(o)
        s.ricevi(raw(message()))
        assert s.parsed_lines == 1 and records[-1]["cartella"] == "watch"


def test_account_display_name_is_looked_up_once_per_uid_without_changing_identity():
    s, observer, records = stream()
    account = type("Account", (), {"pw_name": "synthetic-account"})()
    with mock.patch.object(R.pwd, "getpwuid", return_value=account) as lookup:
        for sequence in range(1, 31):
            msg = message(sequence=sequence)
            msg["process"]["audit_token"]["pid"] = sequence + 100
            s.ricevi(raw(msg))
        assert lookup.call_count == 1
    assert all(r["uid"] == os.getuid() and r["utente"] == "synthetic-account" for r in records)
    assert [r["pid"] for r in records] == list(range(101, 131))
    assert all(r["pidversion"] == 1 for r in records)
    assert len(observer.discendenza.nomi_uid) == 1


def test_unknown_account_name_is_cached_as_unknown_without_changing_audit_uid():
    s, _, records = stream()
    with mock.patch.object(R.pwd, "getpwuid", side_effect=KeyError("synthetic unknown")) as lookup:
        s.ricevi(raw(message(sequence=1)))
        s.ricevi(raw(message(sequence=2)))
        assert lookup.call_count == 1
    assert all(r["utente"] is None and r["uid"] == os.getuid() for r in records)


def test_account_name_cache_is_bounded_to_256_uids_and_session_local():
    a, b = R.Discendenza(), R.Discendenza()
    account = type("Account", (), {"pw_name": "synthetic-account"})()
    with mock.patch.object(R.pwd, "getpwuid", return_value=account):
        for uid in range(600):
            msg = message()
            msg["process"]["audit_token"]["euid"] = uid
            R.normalizza(msg, a)
            assert len(a.nomi_uid) <= 256
    assert a.nomi_uid and b.nomi_uid == {}


def test_synthetic_mixed_stream_exceeds_conservative_throughput_floor():
    path = Path(__file__).resolve().parents[1] / "strumenti" / "prova-registro-throughput.py"
    spec = importlib.util.spec_from_file_location("paratia_benchmark", path)
    benchmark = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(benchmark)
    rows = benchmark.righe_sintetiche(10000)
    # The benchmark stream may only contain what the collector subscribes to.
    tipi = {next(iter(json.loads(riga)["event"])) for riga in rows}
    assert tipi <= set(R.EVENTI), tipi
    # Deliberately far below the measured fast path, allowing slower CI hardware.
    result = benchmark.misura(rows, True)
    assert result["lines_per_second"] >= 10000, result
    assert result["filtered_lines"] == 9500 and result["parsed_lines"] == 500
    assert result["written_records"] == 400 and result["dropped_events"] == 0


def lifetime(pid, sequence, kind):
    msg = message(sequence=sequence, kind=kind)
    msg["process"] = {**msg["process"], "audit_token": {"pid": pid, "pidversion": 1, "euid": os.getuid()}}
    if kind == "exec":
        msg["event"]["exec"]["target"] = {**msg["process"], "executable": {"path": "/bin/cat"}}
    return msg


def test_a_busy_mac_forgets_exited_processes_instead_of_resetting_the_ancestry(monkeypatch):
    records = []
    observer = R.Osservatore([{"id": "watch", "origine": ROOT}], records.append)
    sequence = 0
    for pid in range(1000, 1000 + 60000):
        for kind in ("exec", "exit"):
            sequence += 1
            observer.ricevi(lifetime(pid, sequence, kind))
    living = lifetime(99999, sequence + 1, "exec")
    observer.ricevi(living)
    assert observer.sano is True
    assert not [r for r in records if r.get("motivo") == "cache-discendenza-azzerata"]
    assert (99999, 1) in observer.discendenza.processi  # A living process keeps its lineage.
    assert len(observer.discendenza.processi) <= 50001


def test_pruning_keeps_the_exited_shell_between_an_agent_and_its_child():
    d = R.Discendenza()
    agent = {"audit_token": {"pid": 10, "pidversion": 1}, "executable": {"path": "/usr/local/bin/codex"},
             "parent_audit_token": {"pid": 1, "pidversion": 1}}
    shell = {"audit_token": {"pid": 11, "pidversion": 1}, "executable": {"path": "/bin/zsh"},
             "parent_audit_token": {"pid": 10, "pidversion": 1}}
    child = {"audit_token": {"pid": 12, "pidversion": 1}, "executable": {"path": "/usr/bin/python3"},
             "parent_audit_token": {"pid": 11, "pidversion": 1}}
    gone = {"audit_token": {"pid": 13, "pidversion": 1}, "executable": {"path": "/bin/ls"},
            "parent_audit_token": {"pid": 11, "pidversion": 1}}
    for p in (agent, shell, child, gone):
        d.ricorda(p)
    d.aggiorna("exit", {"process": shell}, {})
    d.aggiorna("exit", {"process": gone}, {})
    d.pota()
    assert (11, 1) in d.processi and (13, 1) not in d.processi
    assert d.classifica(child)["agente"] is True


def _scrittura(sequence, path, executable="/usr/bin/ditto", pid=4242, kind="write"):
    msg = message(path, sequence, "open")
    msg["event_type"] = "ES_EVENT_TYPE_NOTIFY_" + kind.upper()
    msg["process"] = {**msg["process"], "audit_token": {"pid": pid, "pidversion": 1, "euid": os.getuid()},
                      "executable": {"path": executable}}
    msg["event"] = {kind: {"target": {"path": path}}}
    return msg


def test_repeated_writes_by_one_process_to_one_file_are_one_record():
    records, ora = [], [1000.0]
    observer = R.Osservatore([{"id": "watch", "origine": ROOT}], records.append, orologio=lambda: ora[0])
    for n in range(1, 201):  # ditto copying two files in many chunks
        observer.ricevi(_scrittura(n, ROOT + "/a.bin" if n <= 100 else ROOT + "/b.bin"))
    assert [r["percorso"] for r in records if r["evento"] == "write"] == [ROOT + "/a.bin", ROOT + "/b.bin"]
    assert observer.scritture_raggruppate == 198
    ora[0] += R.FINESTRA_SCRITTURE + 1
    observer.ricevi(_scrittura(201, ROOT + "/a.bin"))
    assert sum(r["evento"] == "write" for r in records) == 3
    observer.ricevi(_scrittura(202, ROOT + "/a.bin", pid=5555))  # another process is always new
    assert sum(r["evento"] == "write" for r in records) == 4


def test_the_systems_image_io_is_not_recorded_but_anyone_else_on_the_image_is():
    bundle = "/Users/paratia-synthetic/.paratia/compartimenti.noindex/x-1.sparsebundle"
    records = []
    observer = R.Osservatore([{"id": "watch", "origine": ROOT, "bundle": bundle}], records.append)
    helper = "/System/Library/PrivateFrameworks/DiskImages2.framework/Versions/A/Resources/diskimages-helper"
    for n in range(1, 51):
        observer.ricevi(_scrittura(n, bundle + "/bands/%x" % n, executable=helper))
    assert not [r for r in records if r["evento"] == "write"] and observer.io_immagine == 50
    observer.ricevi(_scrittura(51, bundle + "/bands/1", executable="/bin/cp", pid=777))
    copiato = [r for r in records if r["evento"] == "write"]
    assert len(copiato) == 1 and copiato[0]["processo"] == "/bin/cp"
    fake = "/tmp/System/Library/PrivateFrameworks/DiskImages2.framework/diskimages-helper"
    observer.ricevi(_scrittura(52, bundle + "/bands/2", executable=fake, pid=778))
    assert len([r for r in records if r["evento"] == "write"]) == 2


def test_the_parent_folder_decodes_only_create_and_rename():
    flow, observer, records = stream(root="/Volumes/Finto/prova")
    for n in range(1, 101):  # the rest of the same disk, busy
        flow.ricevi(raw(message("/Volumes/Finto/build/obj%d.o" % n, n)))
    assert flow.parsed_lines == 0 and flow.filtered_lines == 100
    creato = message("/Volumes/Finto", 101, "open")
    creato["event_type"] = "ES_EVENT_TYPE_NOTIFY_CREATE"
    creato["event"] = {"create": {"destination_type": 1, "destination": {"new_path": {
        "dir": {"path": "/Volumes/Finto"}, "filename": "prova", "mode": 493}}}}
    flow.ricevi(raw(creato))
    assert flow.parsed_lines == 1
    assert [r for r in records if r.get("evento") == "create"]


def test_reader_drains_the_pipe_and_declares_what_it_cannot_keep():
    lettura, scrittura = os.pipe()
    lettore = D.LettoreTubo(lettura, limite=2000)
    riga = b'{"x":"' + b"a" * 90 + b'"}\n'  # 100 bytes
    for _ in range(500):  # 50 KB, the writer is never blocked by a slow decoder
        os.write(scrittura, riga)
    os.close(scrittura)
    while not lettore.finito:
        time.sleep(0.01)
    assert lettore.byte <= 2000 and sum(b.count(b"\n") for b in lettore.blocchi) == 20 and lettore.scartate == 480
    assert b"".join(lettore.prendi(attesa=0)) == riga * 20 and lettore.esaurito
    os.close(lettura)


def test_memory_caps_and_the_footprint_that_counts_compressed_pages():
    assert D.oltre_il_tetto(None, None) is None
    assert D.oltre_il_tetto(D.TETTO_MEMORIA_RACCOGLITORE + 1, 0) == "raccoglitore"
    assert D.oltre_il_tetto(0, D.TETTO_MEMORIA_ESLOGGER + 1) == "eslogger"
    if sys.platform == "darwin":
        assert D.impronta_memoria(os.getpid()) > 1024 * 1024
        assert D.impronta_memoria(999999999) is None


def test_a_memory_restart_is_a_notice_for_a_day():
    now = 10_000_000.0
    stato = {"running": True, "healthy": True, "needs_fda": False, "watched_ids": ["watch"],
             "memory_restart_at": now - 60}
    assert "memory_restart" in {r["code"] for r in R.motivi_salute(stato, now)}
    stato["memory_restart_at"] = now - 90_000
    assert "memory_restart" not in {r["code"] for r in R.motivi_salute(stato, now)}


def test_configuration_reloads_keep_no_memory(tmp_path, monkeypatch):
    import tracemalloc
    casa = tmp_path / "casa"
    (casa / ".paratia").mkdir(parents=True)
    sorvegliata = casa / "sorvegliata"
    sorvegliata.mkdir()
    monkeypatch.setenv("PARATIA_HOME", str(casa / ".paratia"))
    spec = importlib.util.spec_from_file_location("registro_reload", Path(R.__file__))
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    modulo.sorveglia("watch-1", sorvegliata, "prova")
    precedenti, cache = None, {}
    for _ in range(20):
        precedenti = modulo.leggi_configurazione(casa, os.getuid(), precedenti=precedenti, cache_volumi=cache)
    tracemalloc.start()
    prima = tracemalloc.get_traced_memory()[0]
    for _ in range(300):  # 25 minutes of the collector's 5-second reloads
        precedenti = modulo.leggi_configurazione(casa, os.getuid(), precedenti=precedenti, cache_volumi=cache)
    cresciuta = tracemalloc.get_traced_memory()[0] - prima
    tracemalloc.stop()
    # Before the fix each reload kept a ctypes class: about 49 KB, 14 MB here.
    assert cresciuta < 1024 * 1024, cresciuta


def test_blocks_give_the_same_records_losses_and_lineage_as_line_by_line():
    root = "/Users/paratia-synthetic/Kit/folder-test"
    rows, seq = [], 0

    def add(path, kind="open", slash=False):
        nonlocal seq
        seq += 1
        line = raw(message(path, seq, kind))
        rows.append((line.replace(b"/", b"\\/") if slash else line) + b"\n")

    for i in range(20):
        add("/System/Library/unrelated-%d" % i)
    add("/System/Library/unrelated", "exec")
    add("/System/Library/unrelated", "fork")
    for i in range(18):
        add("/Users/other/file-%d" % i, slash=i % 2 == 0)
    add(root + "/inside.txt")
    for i in range(19):
        add("/Users/other/perché-%d" % i)
    creato = message(root, seq + 1, "open")
    creato["event_type"] = "ES_EVENT_TYPE_NOTIFY_CREATE"
    creato["event"] = {"create": {"destination_type": 1, "destination": {"new_path": {
        "dir": {"path": os.path.dirname(root)}, "filename": "folder-test", "mode": 493}}}}
    seq += 1
    rows.append(raw(creato) + b"\n")
    for i in range(19):
        add("/Users/other/after-%d" % i)
    seq += 5  # eslogger lost five events here
    for i in range(25):
        add("/Users/other/gap-%d" % i)
    add(root + "/escaped.txt", slash=True)
    add(root.replace("K", "K") + "/kelvin.txt")  # NFC turns the Kelvin sign into K
    add("/System/Library/unrelated", "exit")
    for i in range(30):
        add("/Users/other/tail-%d" % i)

    def outcome(flow, observer, records):
        senza_ora = [{k: v for k, v in r.items() if k not in ("quando", "registrato_il")} for r in records]
        return (senza_ora, observer.persi, observer.globale, flow.raw_lines, flow.parsed_lines,
                flow.filtered_lines, flow.accettate, sorted(observer.discendenza.processi))

    flow, observer, records = stream(root, wall_time=lambda: 1000.0)
    for line in rows:
        flow.ricevi(line)
    one_by_one = outcome(flow, observer, records)
    assert one_by_one[1] == 5 and len([r for r in records if r.get("evento") == "open"]) == 3

    for size in (len(rows), 50, 13, 7, 3, 2, 1):
        flow, observer, records = stream(root, wall_time=lambda: 1000.0)
        for start in range(0, len(rows), size):
            for line in flow.smista(b"".join(rows[start:start + size])):
                flow.ricevi(line)
        assert outcome(flow, observer, records) == one_by_one, size

    # Unrelated opens only: nothing to decode, the sequence still advances.
    flow, observer, records = stream(root)
    assert list(flow.smista(b"".join(rows[:20]))) == []
    assert flow.raw_lines == flow.filtered_lines == 20 and observer.globale == 20 and not records
    assert flow.bulk_lines == 20 and flow.metriche()["fallback_lines"] == {}
    # A block with a watched path goes line by line, and says why.
    flow, observer, records = stream(root)
    vero = raw(message(root + "/x", 8, "open")) + b"\n"
    assert len(list(flow.smista(b"".join(rows[:7]) + vero))) == 8
    assert flow.fallback_lines == {"relevant": 8} and flow.bulk_lines == 0
    # Two unrelated lines are already a block: a burst arrives a few lines per read.
    flow, observer, records = stream(root)
    assert list(flow.smista(b"".join(rows[:2]))) == [] and flow.bulk_lines == 2
    assert list(flow.smista(rows[2])) == [rows[2]] and flow.fallback_lines == {"short": 1}


def test_reader_joins_consecutive_reads_up_to_a_cap():
    lettura, scrittura = os.pipe()
    lettore = D.LettoreTubo(lettura)
    lettore.blocchi.extend([b"a\n" * 10, b"b\n" * 10, b"c\n" * 10])
    lettore.byte = 60
    assert lettore.prendi(attesa=0, unisci=40) == [b"a\n" * 10 + b"b\n" * 10, b"c\n" * 10]
    assert lettore.byte == 0
    os.close(scrittura)
    os.close(lettura)
