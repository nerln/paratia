"""A slow configuration probe must not block reading the eslogger stream."""
from __future__ import annotations

import concurrent.futures
import json
import os
import threading

import pytest

import registro_daemon as D
import registro as R


def test_slow_load_returns_control_and_never_overlaps_another_load():
    started, release = threading.Event(), threading.Event()
    reader_thread = threading.get_ident()
    result = {"voci": [{"id": "synthetic"}], "watch_status": []}
    calls = []

    def load(*, precedenti, cache_volumi):
        calls.append(threading.get_ident())
        started.set()
        if not release.wait(2):
            raise TimeoutError("Synthetic probe was not released")
        return result

    loader = D.CaricatoreConfigurazione(load)
    try:
        assert loader.richiedi()
        assert started.wait(2)
        assert loader.raccogli() is None
        assert not loader.richiedi()
        assert len(calls) == 1 and calls[0] != reader_thread
        release.set()
        assert loader._future.result(timeout=2) is result
        # Even a completed job cannot overlap its uncollected result.
        assert not loader.richiedi()
        assert loader.raccogli() is result
        assert loader.raccogli() is None
    finally:
        release.set()
        loader.chiudi()


def test_successful_result_becomes_previous_and_volume_cache_survives_polls():
    original = {"voci": [{"id": "first"}], "watch_status": []}
    results = [{"voci": [{"id": "second"}], "watch_status": []},
               {"voci": [{"id": "third"}], "watch_status": []}]
    cache = {}
    calls = []

    def load(*, precedenti, cache_volumi):
        calls.append((precedenti, cache_volumi, dict(cache_volumi)))
        cache_volumi["confirmed-volume"] = True
        return results[len(calls) - 1]

    loader = D.CaricatoreConfigurazione(load, original, cache)
    try:
        for expected in results:
            assert loader.richiedi()
            assert loader._future.result(timeout=2) is expected
            assert loader.raccogli() is expected
        assert calls[0][0] is original
        assert calls[1][0] is results[0]
        assert all(call[1] is cache for call in calls)
        assert calls[0][2] == {}
        assert calls[1][2] == {"confirmed-volume": True}
    finally:
        loader.chiudi()


def test_failed_load_is_reported_without_replacing_previous_and_can_retry():
    previous = {"voci": [{"id": "confirmed"}], "watch_status": []}
    replacement = {"voci": [], "watch_status": []}
    calls = []

    def load(*, precedenti, cache_volumi):
        calls.append(precedenti)
        if len(calls) == 1:
            raise ValueError("Synthetic unreadable configuration")
        return replacement

    loader = D.CaricatoreConfigurazione(load, previous)
    try:
        assert loader.richiedi()
        with pytest.raises(ValueError, match="Synthetic unreadable"):
            loader._future.result(timeout=2)
        with pytest.raises(ValueError, match="Synthetic unreadable"):
            loader.raccogli()
        assert loader.raccogli() is None
        assert loader.richiedi()
        assert loader._future.result(timeout=2) is replacement
        assert loader.raccogli() is replacement
        assert calls == [previous, previous]
    finally:
        loader.chiudi()


def test_close_during_probe_does_not_wait_or_publish_its_late_result():
    started, release, finished = threading.Event(), threading.Event(), threading.Event()

    def load(**kwargs):
        started.set()
        try:
            if not release.wait(2):
                raise TimeoutError("Synthetic probe was not released")
            return {"voci": [{"id": "late"}], "watch_status": []}
        finally:
            finished.set()

    loader = D.CaricatoreConfigurazione(load)
    future = None
    try:
        assert loader.richiedi()
        future = loader._future
        assert started.wait(2)
        loader.chiudi()
        # Closing returned while the running disk probe is still waiting.
        assert not finished.is_set()
        assert loader.raccogli() is None
        assert not loader.richiedi()
        loader.chiudi()
        release.set()
        assert future.result(timeout=2)["voci"][0]["id"] == "late"
        assert loader.raccogli() is None
    finally:
        release.set()
        loader.chiudi()
        if future is not None:
            assert finished.wait(2)


@pytest.mark.parametrize("submitted", [False, True])
def test_close_cancels_an_unstarted_job_and_stops_future_requests(monkeypatch, submitted):
    class PendingExecutor:
        def __init__(self, **kwargs):
            assert kwargs["max_workers"] == 1
            self.future = concurrent.futures.Future()
            self.shutdown_calls = []

        def submit(self, load, **kwargs):
            return self.future

        def shutdown(self, **kwargs):
            self.shutdown_calls.append(kwargs)

    monkeypatch.setattr(D.concurrent.futures, "ThreadPoolExecutor", PendingExecutor)
    loader = D.CaricatoreConfigurazione(lambda **kwargs: pytest.fail("An unstarted job ran"))
    executor = loader._executor
    if submitted:
        assert loader.richiedi()
    loader.chiudi()
    loader.chiudi()
    assert executor.future.cancelled() is submitted
    assert executor.shutdown_calls == [{"wait": False, "cancel_futures": True}]
    assert loader.raccogli() is None
    assert not loader.richiedi()


def test_pending_probe_keeps_reading_confirmed_root_and_commits_only_when_finished():
    root = "/Users/paratia-synthetic/Desktop/project"
    original = {"voci": [{"id": "first", "origine": root}],
                "watch_status": [{"id": "first", "status": "confirmed"}]}
    records = []
    observer = R.Osservatore(original["voci"], records.append)
    stream = D.FlussoEslogger(observer)
    started, release = threading.Event(), threading.Event()

    def load(**kwargs):
        started.set()
        if not release.wait(2):
            raise TimeoutError("Synthetic probe was not released")
        return {"voci": [], "watch_status": [{"id": "first", "status": "rejected",
                                              "reason_code": "owner_mismatch"}]}

    loader = D.CaricatoreConfigurazione(load, original)
    state = {}
    try:
        assert loader.richiedi() and started.wait(2)
        assert loader.raccogli() is None
        for sequence in range(1, 4):
            stream.ricevi(json.dumps({"schema_version": 1, "version": 7, "event_type": 10,
                "global_seq_num": sequence, "seq_num": sequence, "time": "2026-10-14T01:00:00Z",
                "process": {"audit_token": {"pid": 20, "pidversion": 1, "euid": os.getuid()},
                            "executable": {"path": "/bin/cat"}},
                "event": {"open": {"file": {"path": root + "/recreated.txt"}, "fflag": 1}}}).encode())
        assert len(records) == 3 and all(row["cartella"] == "first" for row in records)
        assert observer.persi == 0
        release.set()
        loader._future.result(timeout=2)
        D.applica_configurazione(R, observer, stream, state, loader.raccogli(), records.append)
        assert observer.protetti == [] and stream.radici == ()
        assert state["watched_ids"] == [] and state["watch_status"][0]["status"] == "rejected"
    finally:
        release.set()
        loader.chiudi()


@pytest.mark.parametrize("warning,motivo", [
    ("folder_absent", "cartella-assente"),
    ("volume_validation_timeout", "verifica-volume-in-ritardo"),
])
def test_committed_retained_root_keeps_ack_and_emits_only_fixed_diagnostic(warning, motivo):
    root = "/Users/paratia-synthetic/Desktop/project"
    observer = R.Osservatore([], lambda row: None)
    stream = D.FlussoEslogger(observer)
    state, diagnostics = {}, []
    config = {"voci": [{"id": "first", "origine": root}],
              "watch_status": [{"id": "first", "status": "confirmed", "warning_code": warning,
                                "warning_message": "PRIVATE_KERNEL_FP", "configuration_token": "a" * 64}],
              "diagnostics": [{"id": "first", "code": warning, "message": "PRIVATE_KERNEL_FP"}],
              "validation": {"first": "PRIVATE_KERNEL_FP"}}
    D.applica_configurazione(R, observer, stream, state, config, diagnostics.append)
    assert observer.protetti == config["voci"] and stream.radici
    assert state["watched_ids"] == ["first"]
    assert state["watch_status"][0]["warning_message"] == R.AVVISI_CONFIGURAZIONE[warning]
    assert len(diagnostics) == 1 and diagnostics[0]["motivo"] == motivo
    assert diagnostics[0]["cartella"] == "first"
    assert "PRIVATE_KERNEL_FP" not in json.dumps([state, diagnostics])
