"""Raw-stream filtering, lineage/loss fidelity and bounded synthetic throughput."""
from __future__ import annotations

import importlib.util
import json
import os
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
    assert "lookup" not in R.EVENTI and "mmap" not in R.EVENTI
    assert {"exec", "fork", "exit", "open", "close", "write"} <= set(R.EVENTI)
    assert {"lookup", "mmap"} <= set(R.TIPI_SUPPORTATI)


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
    assert o.rileva_perdite and o.persi == 2 and not o.sano
    assert len(records) == 1  # Exactly one bounded diagnostic.
    assert records[0]["motivo"] == "eventi-persi" and records[0]["persi"] == 2


def test_sequence_restart_is_not_silently_discarded():
    s, o, records = stream()
    for i in (100, 1):
        s.ricevi(raw(message("/System/Library/unrelated", i)))
    assert not o.sano and o.persi == 0
    assert records[0]["motivo"] == "sequenza-riavviata"


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
    # Deliberately far below the measured fast path, allowing slower CI hardware.
    result = benchmark.misura(rows, True)
    assert result["lines_per_second"] >= 10000, result
    assert result["filtered_lines"] == 9500 and result["parsed_lines"] == 500
    assert result["written_records"] == 400 and result["dropped_events"] == 0
