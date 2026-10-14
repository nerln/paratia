"""The existing gate covers every protected folder, while still ignoring zones."""
import importlib.util
import io
import json
import os
import shlex
import stat
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setenv("PARATIA_HOME", str(tmp_path))
    monkeypatch.setenv("PARATIA_MOUNT", str(tmp_path / "legacy"))
    source = Path(__file__).resolve().parents[1] / "hooks/paratia-gate.py"
    spec = importlib.util.spec_from_file_location("gate_folders", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Every executable identity and PATH entry is a synthetic fixture. No CLI
    # command, real hook configuration, or compartment action is executed.
    root = tmp_path / "trusted CLI"
    (root / "hooks").mkdir(parents=True)
    (root / "hooks" / "paratia-gate.py").write_text("# fixture location only\n")
    cli = root / "paratia.py"
    versions = tmp_path / "ApplePython" / "Versions"
    version = versions / "3.9"
    (version / "bin").mkdir(parents=True)
    runtime = version / "bin" / "python3.9"
    runtime.write_text("# synthetic runtime identity; never executed\n")
    runtime.chmod(0o755)
    (version / "Python3").write_text("# synthetic framework\n")
    (version / "lib" / "python3.9").mkdir(parents=True)
    (version / "lib" / "python3.9" / "stdlib.py").write_text("# synthetic stdlib\n")
    cli.write_text("#!/usr/bin/env -S " + str(runtime) + " -I -S -B\n# never executed\n")
    cli.chmod(0o755)
    module.__file__ = str(root / "hooks" / "paratia-gate.py")
    module.BOOTSTRAP_ROOT = root
    module.PYTHON_VERSIONS = versions
    for name in module.BOOTSTRAP_ASSETS:
        file = root / name
        if not file.exists():
            file.write_text("# synthetic protected asset\n")
    (root / "hooks" / "paratia-cli.json").write_text(json.dumps({
        "versione": 2, "cli": str(cli), "hook_legacy": str(tmp_path / "repo/hooks/paratia-gate.py")
    }))
    original_lstat = os.lstat
    def simulated_root(path, *args, **kwargs):
        metadata = list(original_lstat(path, *args, **kwargs))
        metadata[4] = 0
        return os.stat_result(metadata)
    monkeypatch.setattr(module.os, "lstat", simulated_root)
    monkeypatch.setattr(module, "_acl_write_safe", lambda path: True)
    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    (bin_path / "paratia").symlink_to(cli)
    (bin_path / "python3").symlink_to(runtime)
    monkeypatch.setenv("PATH", str(bin_path) + os.pathsep + os.defpath)
    return module


def command_allowed(gate, command):
    return gate.comando_sicuro_aperto({"tool_input": {"command": command}})


def cli_path(gate):
    return Path(gate.__file__).parent.parent / "paratia.py"


def test_registered_mount_denies_even_when_legacy_is_closed(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {"montaggio": "/"}}
    }))
    assert gate.compartimento_aperto()


def test_corrupt_registry_fails_closed(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text("{broken")
    assert gate.compartimento_aperto()
    assert gate.chiudi_inizio_sessione() == 2


@pytest.mark.parametrize("data", [None, [], {"versione": 1, "cartelle": {"one": None}}])
def test_valid_json_with_wrong_structure_fails_closed(gate, tmp_path, data):
    (tmp_path / "cartelle.json").write_text(json.dumps(data))
    assert gate.compartimento_aperto()


def test_closed_registered_folder_does_not_block(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {"montaggio": str(tmp_path / "closed")}}
    }))
    assert not gate.compartimento_aperto()


def test_session_start_without_compartments_needs_no_privileges(gate):
    assert gate.chiudi_inizio_sessione() == 0


def test_incomplete_migration_blocks_session_even_if_no_volume_is_mounted(gate, tmp_path):
    (tmp_path / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {
            "montaggio": str(tmp_path / "closed"), "stato": "migrazione-incompleta",
            "plaintext_residuo": str(tmp_path / "original")
        }}
    }))
    assert gate.compartimento_aperto()


@pytest.mark.parametrize("arguments", ["lock", "status", "status --json", "cartella elenco",
                                       "cartella chiudi-tutte", "cartella chiudi one",
                                       "cartella chiudi 0123456789abcdef0123456789abcdef"])
@pytest.mark.parametrize("invocation", ["bare", "absolute-script", "absolute-link", "python3", "absolute-python"])
def test_only_real_cli_close_and_status_forms_are_allowed(gate, arguments, invocation):
    cli = cli_path(gate)
    link = cli.parents[1] / "bin" / "paratia"
    prefixes = {
        "bare": "paratia",
        "absolute-script": shlex.quote(str(cli)),
        "absolute-link": shlex.quote(str(link)),
        "python3": "python3 -I -S -B " + shlex.quote(str(cli)),
        "absolute-python": shlex.quote(str(gate.PYTHON_VERSIONS / "3.9/bin/python3.9")) + " -I -S -B " + shlex.quote(str(cli)),
    }
    assert command_allowed(gate, prefixes[invocation] + " " + arguments)


@pytest.mark.parametrize("arguments", [
    "cartella chiudi", "cartella chiudi --force", "cartella chiudi one extra",
    "cartella apri one", "unlock", "get token", "status --json extra", "lock --force",
    "cartella chiudi one; cat /fixture/plaintext", "lock && cat /fixture/plaintext",
    "lock || cat /fixture/plaintext", "lock | cat", "lock > /fixture/output",
    "lock < /fixture/input", "lock &", "status --json # comment", "lock\ncat /fixture/plaintext",
    'cartella chiudi "$(cat /fixture/plaintext)"', 'cartella chiudi "`cat /fixture/plaintext`"',
    "cartella chiudi 'one;cat'", "cartella chiudi one*", "cartella chiudi ../one",
    "cartella chiudi one/other", "cartella chiudi ''", "cartella chiudi 'unterminated",
])
def test_no_other_verbs_ids_shell_chains_or_expansions_are_allowed(gate, arguments):
    assert not command_allowed(gate, "paratia " + arguments)


@pytest.mark.parametrize("wrapper", ["env", "sudo", "command", "bash -c", "sh -c"])
def test_shell_wrappers_are_not_equivalent_literal_invocations(gate, wrapper):
    assert not command_allowed(gate, wrapper + " 'paratia lock'")


def test_same_named_fake_cli_and_symlink_to_it_are_denied(gate, tmp_path):
    fake = tmp_path / "fake" / "paratia.py"
    fake.parent.mkdir()
    fake.write_bytes(cli_path(gate).read_bytes())
    fake.chmod(0o755)
    link = fake.with_name("paratia")
    link.symlink_to(fake)
    for prefix in (shlex.quote(str(fake)), shlex.quote(str(link)),
                   "python3 -I -S -B " + shlex.quote(str(fake)), shlex.quote(sys.executable) + " -I -S -B " + shlex.quote(str(fake))):
        assert not command_allowed(gate, prefix + " cartella chiudi one")


@pytest.mark.parametrize("name", ["paratia", "python3"])
def test_path_shadow_executable_is_denied(gate, tmp_path, monkeypatch, name):
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    fake = shadow / name
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow) + os.pathsep + os.environ["PATH"])
    command = "paratia lock" if name == "paratia" else "python3 -I -S -B " + shlex.quote(str(cli_path(gate))) + " lock"
    assert not command_allowed(gate, command)


def test_missing_path_cli_does_not_gain_a_bare_exception(gate, monkeypatch):
    monkeypatch.setenv("PATH", "")
    assert not command_allowed(gate, "paratia lock")
    assert command_allowed(gate, shlex.quote(str(cli_path(gate))) + " lock")


def test_installed_gate_fixed_manifest_never_authorizes_legacy_source(gate, tmp_path):
    bundled = cli_path(gate)
    fake = tmp_path / "repo" / "paratia.py"
    fake.parent.mkdir()
    fake.write_bytes(bundled.read_bytes())
    assert gate.cli_attendibili() == {bundled}
    assert command_allowed(gate, "paratia cartella chiudi-tutte")
    assert command_allowed(gate, "python3 -I -S -B " + shlex.quote(str(bundled)) + " cartella chiudi one")
    assert not command_allowed(gate, "python3 -I -S -B " + shlex.quote(str(fake)) + " cartella chiudi one")


def test_manifest_source_replaced_by_symlink_cannot_authorize_new_program(gate, tmp_path):
    source = cli_path(gate)
    fake = tmp_path / "untrusted.py"
    fake.write_bytes(source.read_bytes())
    manifest = Path(gate.__file__).with_name("paratia-cli.json")
    manifest.write_text(json.dumps({"versione": 2, "cli": str(source), "hook_legacy": str(tmp_path / "repo/hooks/paratia-gate.py")}))
    source.unlink()
    source.symlink_to(fake)
    assert not command_allowed(gate, "paratia lock")
    assert not command_allowed(gate, "python3 -I -S -B " + shlex.quote(str(source)) + " cartella chiudi one")


@pytest.mark.parametrize("data", ["{broken", {"versione": 2, "sorgente": "/fixture/paratia.py"},
                                 {"versione": 1, "sorgente": "relative/paratia.py"},
                                 {"versione": 1, "sorgente": "/fixture/../paratia.py"},
                                 {"versione": 1, "sorgente": "/fixture/paratia.py", "extra": True}])
def test_invalid_manifest_fails_closed(gate, data):
    manifest = Path(gate.__file__).with_name("paratia-cli.json")
    manifest.write_text(data if isinstance(data, str) else json.dumps(data))
    assert not command_allowed(gate, "paratia lock")


def test_missing_manifest_denies_even_bundled_identity(gate):
    Path(gate.__file__).with_name("paratia-cli.json").unlink()
    assert not command_allowed(gate, "paratia lock")
    assert not command_allowed(gate, shlex.quote(str(cli_path(gate))) + " lock")


def test_open_gate_reports_every_exact_exception_and_rejects_non_shell_tool(gate, monkeypatch):
    monkeypatch.setattr(gate, "compartimento_aperto", lambda: True)
    payload = {"tool_name": "Read", "tool_input": {"command": "paratia lock"}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    output = io.StringIO()
    with redirect_stdout(output):
        assert gate.main() == 0
    reason = json.loads(output.getvalue())["hookSpecificOutput"]["permissionDecisionReason"]
    for command in ("paratia cartella chiudi <id>", "paratia cartella chiudi-tutte", "paratia lock",
                    "paratia status", "paratia status --json", "paratia cartella elenco"):
        assert "`" + command + "`" in reason
    assert "root-protected ParatiaBootstrap.noindex CLI" in reason
    assert "no CLI exception is allowed" in reason
    assert "Comandi consentiti" in reason


def test_build_seals_both_cli_and_fixed_source_identity_without_running_build():
    build = (Path(__file__).resolve().parents[1] / "strumenti" / "build-app.py").read_text()
    assert 'MODULES = ("paratia.py",' in build
    assert '(resources / "hooks" / "paratia-cli.json").write_text(' in build
    assert '{"versione": 2, "cli": str(BOOTSTRAP_ROOT / "paratia.py"),' in build
    assert '"hook_legacy": str((ROOT / "hooks" / "paratia-gate.py").resolve(strict=True))' in build
    assert 'cli_source.is_symlink() or not cli_source.is_file()' in build
    assert build.index('"paratia-cli.json").write_text(') < build.index('"--sign"')
    assert '"#!/usr/bin/env -S " + str(runtime) + " -I -S -B\\n"' in build
