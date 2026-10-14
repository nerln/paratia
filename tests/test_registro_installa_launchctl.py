"""launchd races and recovery, simulated entirely without privilege or services."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

import registro_installa as I
import test_registro_installa_bundle as _bundle


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class Launchctl:
    def __init__(self, loaded=True, slow_checks=0, bootstrap_results=()):
        self.loaded = loaded
        self.slow_checks = slow_checks
        self.removal_left = None
        self.bootstrap_results = list(bootstrap_results)
        self.commands = []
        self.stops = 0
        self.freeze_stop = None
        self.load_on_error = False
        self.before_bootstrap = None

    def run(self, argv, **kwargs):
        self.commands.append(list(argv))
        if argv[0] != "/bin/launchctl":
            assert argv[0] in ("/bin/chmod", "/usr/bin/codesign")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        assert kwargs.get("capture_output") is True
        assert kwargs.get("timeout") == I.LAUNCHCTL_TIMEOUT
        operation = argv[1]
        rc, stderr = 0, b""
        if operation == "print":
            if self.removal_left is not None:
                if self.removal_left == 0:
                    self.loaded = False
                    self.removal_left = None
                else:
                    self.removal_left -= 1
            if not self.loaded:
                rc = 113
                stderr = b'Bad request.\nCould not find service "synthetic" in domain for system'
        elif operation == "bootout":
            self.stops += 1
            if self.stops != self.freeze_stop:
                self.removal_left = self.slow_checks if self.loaded else 0
            if not self.loaded:
                rc, stderr = 3, b"Boot-out failed: 3: No such process"
        elif operation == "bootstrap":
            if self.before_bootstrap is not None:
                self.before_bootstrap(argv)
            assert not self.loaded, "bootstrap before confirmed removal"
            rc, stderr = self.bootstrap_results.pop(0) if self.bootstrap_results else (0, b"")
            self.loaded = rc == 0 or self.load_on_error
        else:
            raise AssertionError(operation)
        return SimpleNamespace(returncode=rc, stdout=b"", stderr=stderr)


@pytest.fixture
def clock(monkeypatch):
    result = Clock()
    monkeypatch.setattr(I.time, "sleep", result.sleep)
    monkeypatch.setattr(I.time, "monotonic", lambda: result.now)
    return result


@pytest.fixture
def bundle():
    fixture = _bundle.BundleInstallerTests(methodName="test_copy_and_success_leave_source_ownership_and_files_unchanged")
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


@pytest.mark.parametrize("failures", [
    [(5, b"Bootstrap failed: 5: Input/output error")],
    [(37, b"Bootstrap failed: 37: Operation already in progress")],
    [(5, b"Bootstrap failed: 5: Input/output error"),
     (37, b"Bootstrap failed: 37: Operation already in progress")],
    [(1, b"Bootstrap failed: 37: Operation already in progress")],
])
def test_bootstrap_retries_race_codes_with_increasing_delay(failures, clock, monkeypatch):
    ctl = Launchctl(loaded=False, bootstrap_results=failures)
    monkeypatch.setattr(I.subprocess, "run", ctl.run)
    errors = []
    I._avvia(Path("/fixed/synthetic.plist"), errors)
    assert ctl.loaded
    assert len(ctl.commands) == len(failures) + 1
    assert clock.sleeps == list(I.BOOTSTRAP_DELAYS[:len(failures)])
    assert [entry["returncode"] for entry in errors] == [item[0] for item in failures]
    assert all(entry["operation"] == "bootstrap" for entry in errors)


def test_slow_bootout_is_observed_before_the_first_bootstrap(bundle, clock):
    bundle.previous()
    ctl = Launchctl(slow_checks=3)
    before = bundle.old_snapshot()

    def start(argv):
        assert (bundle.support / "Paratia.app" / "Contents" / "MacOS" / "Paratia").read_bytes() == b"NEW APP"
        assert [command for command in ctl.commands if command[0] == "/bin/launchctl"][-2][1] == "print"

    ctl.before_bootstrap = start
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        result = I.installa(bundle.source, bundle.uid)
    assert result["installed"] is True
    assert len(clock.sleeps) == 3
    assert before != bundle.old_snapshot()
    assert ctl.loaded


def test_stop_timeout_leaves_all_old_components_untouched(bundle, clock):
    bundle.previous()
    before = bundle.old_snapshot()
    ctl = Launchctl()
    ctl.freeze_stop = 1
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "service_stop_timeout"
    assert bundle.old_snapshot() == before
    assert not any(command[1] == "bootstrap" for command in ctl.commands)
    assert clock.now == pytest.approx(I.STOP_TIMEOUT)
    assert not list(bundle.support.glob(".installazione-*"))


def test_rollback_waits_and_retries_the_old_bootstrap(bundle, clock):
    bundle.previous()
    before = bundle.old_snapshot()
    failures = [(5, b"Bootstrap failed: 5: Input/output error")] * 3
    failures += [(37, b"Bootstrap failed: 37: Operation already in progress")]
    ctl = Launchctl(slow_checks=2, bootstrap_results=failures)
    versions = []
    ctl.before_bootstrap = lambda argv: versions.append(
        (bundle.support / "Paratia.app" / "Contents" / "MacOS" / "Paratia").read_bytes())
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "bootstrap_failed"
    assert "ripristinato e riavviato" in str(caught.value)
    assert versions == [b"NEW APP"] * 3 + [b"OLD APP"] * 2
    assert bundle.old_snapshot() == before
    assert ctl.loaded
    assert any(error["operation"] == "rollback_bootstrap" for error in caught.value.launchctl_errors)
    assert not list(bundle.support.glob(".installazione-*"))


def test_old_bootstrap_failure_is_explicit_and_preserves_recovery_stage(bundle, clock):
    bundle.previous()
    before = bundle.old_snapshot()
    ctl = Launchctl(bootstrap_results=[(5, b"Bootstrap failed: 5: Input/output error")] * 6)
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "rollback_bootstrap_failed"
    assert "non ha riavviato il servizio precedente" in str(caught.value)
    assert caught.value.conserva_stage is True
    assert len(list(bundle.support.glob(".installazione-*"))) == 1
    assert bundle.old_snapshot() == before
    assert not ctl.loaded
    assert [entry["operation"] for entry in caught.value.launchctl_errors].count("rollback_bootstrap") == 3


def test_unconfirmed_rollback_stop_preserves_candidate_and_original_checkpoint(bundle, clock):
    bundle.previous()
    ctl = Launchctl(bootstrap_results=[(1, b"Permission denied")])
    ctl.load_on_error = True
    ctl.freeze_stop = 2
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "rollback_stop_failed"
    stage, = bundle.support.glob(".installazione-*")
    assert (stage / "precedente-0" / "Contents" / "MacOS" / "Paratia").read_bytes() == b"OLD APP"
    assert (bundle.support / "Paratia.app" / "Contents" / "MacOS" / "Paratia").read_bytes() == b"NEW APP"
    assert ctl.loaded


@pytest.mark.parametrize("returncode,stderr", [(5, b"Input/output error"), (13, b"Permission denied"),
                                               (113, b"unrelated diagnostic")])
def test_print_failure_does_not_authorize_replacement(returncode, stderr, monkeypatch):
    monkeypatch.setattr(I.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=returncode, stdout=b"", stderr=stderr))
    with pytest.raises(I.ErroreInstallazione) as caught:
        I._servizio_presente("it.paratia.registro.501", [])
    assert caught.value.error_code == "launchctl_probe_failed"


def test_non_race_bootstrap_failure_is_not_retried(clock, monkeypatch):
    ctl = Launchctl(loaded=False, bootstrap_results=[(13, b"Bootstrap failed: 13: Permission denied")])
    monkeypatch.setattr(I.subprocess, "run", ctl.run)
    with pytest.raises(I.ErroreInstallazione):
        I._avvia(Path("/fixed/synthetic.plist"), [])
    assert len(ctl.commands) == 1
    assert clock.sleeps == []


@pytest.mark.parametrize("exception", [OSError("SECRET /private/path"),
                                        I.subprocess.TimeoutExpired("launchctl", 5, stderr=b"SECRET /private/path")])
def test_launchctl_execution_failures_are_typed_and_redacted(exception, monkeypatch):
    monkeypatch.setattr(I.subprocess, "run", mock.Mock(side_effect=exception))
    errors = []
    with pytest.raises(I.ErroreInstallazione) as caught:
        I._servizio_presente("it.paratia.registro.501", errors)
    assert caught.value.error_code in ("launchctl_timeout", "launchctl_unavailable")
    assert "SECRET" not in str(caught.value)
    assert "SECRET" not in json.dumps(errors)
    assert errors[0]["returncode"] is None


@pytest.mark.parametrize("stderr", [b"SECRET /Users/synthetic\x1b[31m" * 10000,
                                    b"Bootstrap failed: 5: SECRET /Users/synthetic\x00\x1b[31m",
                                    b'Could not find service "SECRET /Users/synthetic" in domain for system'])
def test_reduced_stderr_has_no_paths_control_codes_or_arbitrary_payload(stderr):
    reduced = I._riduci_stderr(stderr)
    assert len(reduced) <= 512
    assert "SECRET" not in reduced
    assert "/Users" not in reduced
    assert "\x1b" not in reduced and "\x00" not in reduced


@pytest.mark.parametrize("error", [
    I.ErroreInstallazione("bootstrap_failed", "Messaggio leggibile", [
        {"operation": "bootstrap", "returncode": 5, "stderr": "Bootstrap failed: 5: Input/output error"}]),
    I.ErroreInstallazione("rollback_bootstrap_failed", "Il precedente non è ripartito", conserva_stage=True),
    PermissionError("SECRET /private/path"), ValueError("SECRET /private/path"),
])
def test_main_always_prints_one_json_failure_with_readable_code(error, monkeypatch):
    monkeypatch.setattr(I, "installa", mock.Mock(side_effect=error))
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = I.main(["--install", "--uid", "501"])
    result = json.loads(output.getvalue())
    assert status == 1
    assert result["installed"] is False
    assert result["error_code"]
    assert result["message"]
    assert isinstance(result["launchctl_errors"], list)
    assert "SECRET" not in output.getvalue()
    if isinstance(error, I.ErroreInstallazione) and error.conserva_stage:
        assert result["backup_retained"] is True


def test_main_reports_bad_arguments_as_json_without_running_install(monkeypatch):
    install = mock.Mock()
    monkeypatch.setattr(I, "installa", install)
    output, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
        status = I.main(["--uid", "not-a-number"])
    assert status == 1
    assert json.loads(output.getvalue())["error_code"] == "invalid_arguments"
    assert not stderr.getvalue()
    install.assert_not_called()


def test_main_success_contains_the_same_result_fields(monkeypatch):
    errors = [{"operation": "bootstrap", "returncode": 5, "stderr": "Bootstrap failed: 5: Input/output error"}]
    monkeypatch.setattr(I, "installa", lambda *args: {"installed": True, "message": "Installato", "launchctl_errors": errors})
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert I.main(["--install", "--uid", "501"]) == 0
    result = json.loads(output.getvalue())
    assert result["installed"] is True
    assert result["error_code"] is None
    assert result["launchctl_errors"] == errors


def test_main_help_is_json_and_does_not_probe_or_install(monkeypatch):
    install, plan = mock.Mock(), mock.Mock()
    monkeypatch.setattr(I, "installa", install)
    monkeypatch.setattr(I, "piano", plan)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert I.main(["--help"]) == 0
    result = json.loads(output.getvalue())
    assert result["installed"] is False
    assert result["error_code"] is None
    assert "Uso:" in result["message"]
    install.assert_not_called()
    plan.assert_not_called()


def test_retry_success_retains_launchctl_diagnostics_in_install_result(bundle, clock):
    bundle.previous()
    ctl = Launchctl(bootstrap_results=[(5, b"Bootstrap failed: 5: Input/output error"),
                                     (37, b"Bootstrap failed: 37: Operation already in progress")])
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run), \
            mock.patch.object(I.time, "sleep", side_effect=clock.sleep):
        result = I.installa(bundle.source, bundle.uid)
    assert result["installed"] is True
    assert [item["returncode"] for item in result["launchctl_errors"]] == [5, 37]
    assert not list(bundle.support.glob(".installazione-*"))


def test_bootout_failure_can_only_proceed_after_confirmed_absence(clock, monkeypatch):
    replies = iter([SimpleNamespace(returncode=3, stdout=b"", stderr=b"Boot-out failed: 3: No such process"),
                    SimpleNamespace(returncode=113, stdout=b"", stderr=b'Could not find service "synthetic" in domain for system')])
    monkeypatch.setattr(I.subprocess, "run", lambda *args, **kwargs: next(replies))
    errors = []
    I._arresta("it.paratia.registro.501", errors)
    assert errors == [{"operation": "bootout", "returncode": 3, "stderr": "Boot-out failed: 3: No such process"}]
    assert clock.sleeps == []


def test_diagnostic_collection_has_a_fixed_limit():
    errors = []
    for _ in range(100):
        I._diagnostica(errors, "bootstrap", 5, "Bootstrap failed: 5: Input/output error")
    assert len(errors) == I.MAX_LAUNCHCTL_ERRORS


def test_print_transport_failure_preserves_old_components_before_any_bootout(bundle, clock):
    bundle.previous()
    before = bundle.old_snapshot()
    commands = []

    def execute(argv, **kwargs):
        commands.append(argv)
        rc = 13 if argv[0] == "/bin/launchctl" else 0
        return SimpleNamespace(returncode=rc, stdout=b"", stderr=b"Permission denied")

    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=execute):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "launchctl_probe_failed"
    assert before == bundle.old_snapshot()
    assert not any(command[:2] == ["/bin/launchctl", "bootout"] for command in commands)
    assert not list(bundle.support.glob(".installazione-*"))


def test_interrupted_rollback_preserves_the_original_checkpoint(bundle, clock):
    bundle.previous()
    ctl = Launchctl(bootstrap_results=[(13, b"Bootstrap failed: 13: Permission denied")])

    def execute(argv, **kwargs):
        if argv[:2] == ["/bin/launchctl", "bootout"] and ctl.stops == 1:
            raise KeyboardInterrupt()
        return ctl.run(argv, **kwargs)

    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=execute):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "rollback_stop_failed"
    assert caught.value.conserva_stage is True
    stage, = bundle.support.glob(".installazione-*")
    assert (stage / "precedente-0" / "Contents" / "MacOS" / "Paratia").read_bytes() == b"OLD APP"


def test_missing_old_plist_is_reported_as_a_service_not_restarted(bundle, clock):
    bundle.previous()
    (bundle.daemons / ("it.paratia.registro.%d.plist" % bundle.uid)).unlink()
    before = bundle.old_snapshot()
    ctl = Launchctl(bootstrap_results=[(13, b"Bootstrap failed: 13: Permission denied")])
    with bundle.installation(), mock.patch.object(I.subprocess, "run", side_effect=ctl.run):
        with pytest.raises(I.ErroreInstallazione) as caught:
            I.installa(bundle.source, bundle.uid)
    assert caught.value.error_code == "rollback_bootstrap_failed"
    assert "plist precedente non è disponibile" in str(caught.value)
    assert caught.value.conserva_stage is True
    assert bundle.old_snapshot() == before
    assert not ctl.loaded
