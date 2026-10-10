"""Giro 4 boundaries: synthetic root trees, isolated runtimes and hook migration.

No fixture executable is launched. Root ownership and ACL results are modeled;
filesystem traversal, ancestor checks, manifest parsing and config backups run
against temporary files.
"""
from __future__ import annotations

import base64
import ctypes
import errno
import importlib.util
import json
import os
import shlex
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def protected(tmp_path, monkeypatch):
    monkeypatch.setenv("PARATIA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("PARATIA_MOUNT", str(tmp_path / "unmounted"))
    gate = load_module("gate_protected_test", ROOT / "hooks/paratia-gate.py")
    installer = load_module("installer_protected_test", ROOT / "hookinstaller.py")
    bootstrap = tmp_path / "root resources"
    (bootstrap / "hooks").mkdir(parents=True)
    versions = tmp_path / "ApplePython" / "Versions"
    version = versions / "3.9"
    (version / "bin").mkdir(parents=True)
    runtime = version / "bin/python3.9"
    runtime.write_text("# Fixture interpreter, never executed.\n")
    runtime.chmod(0o755)
    (version / "Python3").write_text("# Fixture framework, never loaded.\n")
    stdlib = version / "lib/python3.9"
    stdlib.mkdir(parents=True)
    (stdlib / "stdlib.py").write_text("# Fixture standard library.\n")
    for asset in gate.BOOTSTRAP_ASSETS:
        (bootstrap / asset).write_text("# Fixture protected asset.\n")
    cli = bootstrap / "paratia.py"
    cli.write_text("#!/usr/bin/env -S " + str(runtime) + " -I -S -B\n# Never executed.\n")
    cli.chmod(0o755)
    repo = tmp_path / "repo"
    (repo / "hooks").mkdir(parents=True)
    legacy = repo / "hooks/paratia-gate.py"
    legacy.write_text("# Fixture legacy hook.\n")
    (repo / "paratia.py").write_text("# Fixture user CLI.\n")
    (repo / "cartelle.py").write_text("raise AssertionError('redirected user module ran')\n")
    (bootstrap / "hooks/paratia-cli.json").write_text(json.dumps({
        "versione": 2, "cli": str(cli), "hook_legacy": str(legacy)
    }))
    for module in (gate, installer):
        monkeypatch.setattr(module, "BOOTSTRAP_ROOT", bootstrap)
        monkeypatch.setattr(module, "PYTHON_VERSIONS", versions)
    gate.__file__ = str(bootstrap / "hooks/paratia-gate.py")
    installer.__file__ = str(bootstrap / "hookinstaller.py")
    real_lstat = os.lstat
    ownership = {}
    writable = set()
    acl_denied = set()

    def modeled_lstat(path, *args, **kwargs):
        values = list(real_lstat(path, *args, **kwargs))
        # Ancestors are modeled root-protected, including the temporary test
        # directory. Preserve the actual file type, so aliases are not hidden.
        key = str(Path(path))
        values[4] = ownership.get(key, 0)
        values[0] &= ~0o022
        if key in writable:
            values[0] |= 0o020
        return os.stat_result(values)

    monkeypatch.setattr(os, "lstat", modeled_lstat)
    for module in (gate, installer):
        monkeypatch.setattr(module, "_acl_write_safe", lambda p: str(Path(p)) not in acl_denied)
    return SimpleNamespace(gate=gate, installer=installer, bootstrap=bootstrap,
                           runtime=runtime, stdlib=stdlib, cli=cli, repo=repo,
                           legacy=legacy, ownership=ownership, writable=writable,
                           acl_denied=acl_denied, base=tmp_path)


def allowed(fixture, executable=None, verb="status"):
    command = shlex.quote(str(executable or fixture.cli)) + " " + verb
    return fixture.gate.comando_sicuro_aperto({"tool_input": {"command": command}})


def test_protected_copy_is_allowed_without_executing_user_module(protected):
    assert protected.gate._protected_bootstrap()
    assert protected.gate._protected_runtime(protected.runtime)
    assert allowed(protected)
    assert allowed(protected, verb="cartella chiudi sample")
    assert not allowed(protected, protected.repo / "paratia.py")


def test_repo_gate_never_exempts_mutated_repository_modules(protected):
    protected.gate.__file__ = str(protected.legacy)
    assert not protected.gate.cli_attendibili()
    assert not allowed(protected)
    assert not allowed(protected, protected.repo / "paratia.py")


@pytest.mark.parametrize("relative", ["paratia.py", "cartelle.py", "registro.py", "catena.py",
                                      "hookinstaller.py", "hooks/paratia-gate.py", "extra.py",
                                      "__pycache__/extra.cpython-39.pyc", "package/extension.so"])
@pytest.mark.parametrize("defect", ["owner", "mode", "acl"])
def test_every_loaded_resource_must_be_root_protected(protected, relative, defect):
    asset = protected.bootstrap / relative
    asset.parent.mkdir(exist_ok=True)
    if not asset.exists():
        asset.write_text("# Synthetic transitive code.\n")
    if defect == "owner":
        protected.ownership[str(asset)] = os.getuid() or 501
    elif defect == "mode":
        protected.writable.add(str(asset))
    else:
        protected.acl_denied.add(str(asset))
    assert not protected.gate._protected_bootstrap()
    assert not protected.installer._protected_bootstrap()
    assert not allowed(protected)


@pytest.mark.parametrize("level", ["resource", "parent", "ancestor"])
@pytest.mark.parametrize("defect", ["owner", "mode", "acl"])
def test_every_resource_ancestor_is_checked(protected, level, defect):
    path = {"resource": protected.bootstrap, "parent": protected.bootstrap.parent,
            "ancestor": protected.bootstrap.parent.parent}[level]
    if defect == "owner":
        protected.ownership[str(path)] = os.getuid() or 501
    elif defect == "mode":
        protected.writable.add(str(path))
    else:
        protected.acl_denied.add(str(path))
    assert not protected.gate._protected_bootstrap()
    assert not protected.installer._protected_bootstrap()
    assert not allowed(protected)


@pytest.mark.parametrize("kind", ["module", "directory"])
def test_aliases_inside_application_resources_are_refused(protected, kind):
    if kind == "module":
        module = protected.bootstrap / "cartelle.py"
        module.unlink()
        module.symlink_to(protected.repo / "cartelle.py")
    else:
        (protected.bootstrap / "package").symlink_to(protected.repo, target_is_directory=True)
    assert not protected.gate._protected_bootstrap()
    assert not protected.installer._protected_bootstrap()
    assert not allowed(protected)


@pytest.mark.parametrize("relative", ["bin/python3.9", "Python3", "lib/python3.9/stdlib.py"])
@pytest.mark.parametrize("defect", ["owner", "mode", "acl"])
def test_runtime_and_standard_library_are_checked(protected, relative, defect):
    asset = protected.runtime.parent.parent / relative
    if defect == "owner":
        protected.ownership[str(asset)] = os.getuid() or 501
    elif defect == "mode":
        protected.writable.add(str(asset))
    else:
        protected.acl_denied.add(str(asset))
    assert not protected.gate._protected_runtime(protected.runtime)
    assert not protected.installer._protected_runtime(protected.runtime)
    assert not allowed(protected)


@pytest.mark.parametrize("flags", ["", "-I", "-I -S", "-S -B", "-I -B", "-I -S -B -c"])
def test_genuine_python_without_exact_isolation_is_not_an_exception(protected, flags):
    command = " ".join([shlex.quote(str(protected.runtime)), flags,
                        shlex.quote(str(protected.cli)), "status"])
    assert not protected.gate.comando_sicuro_aperto({"tool_input": {"command": command}})


def test_isolated_explicit_python_call_is_allowed(protected):
    command = shlex.quote(str(protected.runtime)) + " -I -S -B " + shlex.quote(str(protected.cli)) + " status"
    assert protected.gate.comando_sicuro_aperto({"tool_input": {"command": command}})


@pytest.mark.parametrize("shebang", ["#!/usr/bin/env python3", "#!/usr/bin/python3", "#!/usr/bin/env -S python3 -I -S -B"])
def test_shebang_cannot_use_path_or_user_python_customization(protected, shebang):
    protected.cli.write_text(shebang + "\n# Never executed.\n")
    assert not allowed(protected)


def test_python_environment_cannot_change_isolated_imports(protected, monkeypatch):
    user_code = protected.repo / "sitecustomize.py"
    user_code.write_text("raise AssertionError('user startup hook ran')\n")
    monkeypatch.setenv("PYTHONPATH", str(protected.repo))
    monkeypatch.setenv("PYTHONHOME", str(protected.repo))
    assert allowed(protected)
    protected.cli.write_text("#!/usr/bin/env python3\n# Never executed.\n")
    assert not allowed(protected)


def test_loader_environment_denies_even_a_protected_cli(protected, monkeypatch):
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", str(protected.repo / "bad.dylib"))
    assert not allowed(protected)


def test_tilde_resolves_account_home_and_preserves_same_checks(protected, monkeypatch):
    home = protected.base / "account-home"
    (home / ".local/bin").mkdir(parents=True)
    alias = home / ".local/bin/paratia"
    alias.symlink_to(protected.cli)
    monkeypatch.setattr(protected.gate.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(home)))
    monkeypatch.setenv("HOME", str(home))
    assert protected.gate.eseguibile_reale("~/.local/bin/paratia") == protected.cli
    assert protected.gate.comando_sicuro_aperto({"tool_input": {"command": "~/.local/bin/paratia status"}})
    alias.unlink()
    alias.symlink_to(protected.repo / "paratia.py")
    assert not protected.gate.comando_sicuro_aperto({"tool_input": {"command": "~/.local/bin/paratia status"}})


def test_fake_shell_home_cannot_redirect_tilde_alias(protected, monkeypatch):
    real_home = protected.base / "real-home"
    fake_home = protected.base / "fake-home"
    for home, target in ((real_home, protected.cli), (fake_home, protected.repo / "paratia.py")):
        (home / ".local/bin").mkdir(parents=True)
        (home / ".local/bin/paratia").symlink_to(target)
    monkeypatch.setattr(protected.gate.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=str(real_home)))
    monkeypatch.setenv("HOME", str(fake_home))
    assert protected.gate.eseguibile_reale("~/.local/bin/paratia") == protected.cli
    assert not protected.gate.comando_sicuro_aperto({"tool_input": {"command": "~/.local/bin/paratia status"}})


def forbid_backend_import(monkeypatch):
    attempted = []
    def forbidden(*args, **kwargs):
        attempted.append(args)
        raise AssertionError("SessionStart attempted to load backend code")
    monkeypatch.setattr(importlib.util, "spec_from_file_location", forbidden)
    return attempted


def test_closed_fallback_session_start_needs_no_user_backend(protected, monkeypatch):
    protected.gate.__file__ = str(protected.legacy)
    attempted = forbid_backend_import(monkeypatch)
    assert protected.gate.chiudi_inizio_sessione() == 0
    assert attempted == []


@pytest.mark.parametrize("registry", [
    {"versione": 1, "cartelle": {"one": {"stato": "aperta", "montaggio": "/"}}},
    {"versione": 1, "cartelle": {"one": {"stato": "migrazione-incompleta", "montaggio": "/never-mounted"}}},
    {"versione": 1, "cartelle": {"one": {"stato": "chiusa", "montaggio": "/never-mounted", "plaintext_residuo": True}}},
    "{broken",
    {"versione": 1, "cartelle": []},
])
def test_open_or_unknown_fallback_session_refuses_before_backend_import(protected, monkeypatch, registry):
    protected.gate.__file__ = str(protected.legacy)
    protected.gate.CASA.mkdir()
    (protected.gate.CASA / "cartelle.json").write_text(registry if isinstance(registry, str) else json.dumps(registry))
    attempted = forbid_backend_import(monkeypatch)
    assert protected.gate.chiudi_inizio_sessione() == 2
    assert attempted == []


def test_protected_session_still_requires_isolated_current_runtime(protected, monkeypatch):
    protected.gate.CASA.mkdir()
    (protected.gate.CASA / "cartelle.json").write_text(json.dumps({
        "versione": 1, "cartelle": {"one": {"stato": "aperta", "montaggio": "/"}}
    }))
    monkeypatch.setattr(protected.gate.sys, "flags", SimpleNamespace(isolated=0, no_site=0))
    attempted = forbid_backend_import(monkeypatch)
    assert protected.gate.chiudi_inizio_sessione() == 2
    assert attempted == []


def test_manifest_cannot_authorize_the_legacy_repo(protected):
    manifest = protected.bootstrap / "hooks/paratia-cli.json"
    data = json.loads(manifest.read_text())
    data["cli"] = str(protected.repo / "paratia.py")
    manifest.write_text(json.dumps(data))
    assert not protected.gate._protected_bootstrap()
    assert not protected.installer._protected_bootstrap()
    assert not allowed(protected, protected.repo / "paratia.py")


def test_hook_migration_uses_protected_copy_and_preserves_foreign_handlers(protected):
    installer = protected.installer
    home = protected.base / "config-home"
    home.mkdir()
    originals = {}
    foreign_handlers = {}
    for harness, (directory, filename) in installer.TARGETS.items():
        target = home / directory / filename
        target.parent.mkdir()
        tail = " --codex" if harness == "codex" else ""
        legacy = {"type": "command", "command": "/old/bin/python3 -I -S " + shlex.quote(str(protected.legacy)) + tail,
                  "timeout": installer.EVENTS["PreToolUse"]}
        foreign = [
            {"type": "command", "command": "/vendor/bin/python3 -I -S /foreign/paratia-gate.py" + tail, "timeout": 5},
            {**legacy, "extra": "foreign-handler-metadata"},
            {**legacy, "timeout": 17},
        ]
        foreign_handlers[harness] = foreign
        original = {"env": {"preserve": "value"}, "hooks": {"PreToolUse": [
            {"matcher": "*", "customGroupField": "preserved", "hooks": [legacy, *foreign]},
            {"matcher": "Bash", "hooks": [legacy]},
        ], "Stop": [{"hooks": [{"type": "command", "command": "echo foreign-stop"}]}]}}
        raw = (json.dumps(original, separators=(",", ":")) + "\n").encode()
        target.write_bytes(raw)
        originals[harness] = raw
    result = installer.installa(resource_root=protected.repo, home=home,
                                 python_executable=protected.runtime)
    assert result["changed"] and result["configured"] and result["protected_closure"]
    assert len(result["backups"]) == 2
    for harness, (directory, filename) in installer.TARGETS.items():
        data = json.loads((home / directory / filename).read_bytes())
        groups = data["hooks"]["PreToolUse"]
        assert groups[0] == {"matcher": "*", "customGroupField": "preserved", "hooks": foreign_handlers[harness]}
        assert groups[1]["matcher"] == "Bash" and len(groups[1]["hooks"]) == 1
        for event in installer.EVENTS:
            command = data["hooks"][event][-1]["hooks"][0]["command"]
            argv = shlex.split(command)
            assert argv[:5] == [str(protected.runtime), "-I", "-S", "-B", str(protected.bootstrap / "hooks/paratia-gate.py")]
        assert data["env"] == {"preserve": "value"}
        assert data["hooks"]["Stop"] == json.loads(originals[harness])["hooks"]["Stop"]
    for backup in result["backups"]:
        data = json.loads(Path(backup).read_bytes())
        assert base64.b64decode(data["before_base64"], validate=True) == originals[data["harness"]]
    repeated = installer.installa(resource_root=protected.repo, home=home,
                                   python_executable=protected.runtime)
    assert not repeated["changed"] and repeated["backups"] == []

    for backup in result["backups"]:
        assert installer.ripristina(backup, home=home)["restored"]
    for harness, (directory, filename) in installer.TARGETS.items():
        assert (home / directory / filename).read_bytes() == originals[harness]


class FakeACLFunction:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class FakeACL:
    """ctypes-shaped ACL with explicit EOF/error and allow/deny entries."""
    def __init__(self, *, bits=(), tag=1, entries=True, eof_errno=errno.EINVAL,
                 valid=True, absent_errno=None, entry_error=False):
        self.bits = set(bits)
        self.tag = tag
        self.entries = entries
        self.eof_errno = eof_errno
        self.valid = valid
        self.absent_errno = absent_errno
        self.entry_error = entry_error
        self.calls = 0
        self.freed = 0
        for name, function in {
            "acl_get_file": self.get_file,
            "acl_get_entry": self.get_entry,
            "acl_get_tag_type": self.get_tag,
            "acl_get_permset": self.get_permset,
            "acl_get_perm_np": lambda permissions, mask: int(mask in self.bits),
            "acl_valid": lambda acl: 0 if self.valid else -1,
            "acl_free": self.free,
        }.items():
            setattr(self, name, FakeACLFunction(function))

    def get_file(self, path, acl_type):
        assert acl_type == 0x100
        if self.absent_errno is not None:
            ctypes.set_errno(self.absent_errno)
            return None
        return 123

    def get_entry(self, acl, position, entry):
        assert position == (0 if not self.calls else -1)
        self.calls += 1
        if self.entries and self.calls == 1 and not self.entry_error:
            ctypes.cast(entry, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(456)
            return 0
        ctypes.set_errno(self.eof_errno)
        return -1

    def get_tag(self, entry, tag):
        ctypes.cast(tag, ctypes.POINTER(ctypes.c_int))[0] = self.tag
        return 0

    def get_permset(self, entry, permissions):
        ctypes.cast(permissions, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(789)
        return 0

    def free(self, acl):
        self.freed += 1
        return 0


@pytest.fixture(params=["gate", "installer"])
def acl_guard(request):
    source = ROOT / ("hooks/paratia-gate.py" if request.param == "gate" else "hookinstaller.py")
    return load_module("acl_guard_" + request.param, source)


@pytest.mark.parametrize("bit", [2, 4, 5, 6, 8, 10, 12, 13])
def test_each_native_write_allow_bit_is_refused(acl_guard, monkeypatch, bit):
    library = FakeACL(bits=[1 << bit])
    monkeypatch.setattr(acl_guard.ctypes, "CDLL", lambda *args, **kwargs: library)
    monkeypatch.setattr(acl_guard.sys, "platform", "darwin")
    assert not acl_guard._acl_write_safe(Path("/synthetic/protected"))
    assert library.freed == 1


@pytest.mark.parametrize("case, expected", [
    ({"entries": False}, True),
    ({"bits": [1 << 1, 1 << 3]}, True),
    ({"bits": [1 << 2], "tag": 2}, True),
    ({"eof_errno": errno.EIO}, False),
    ({"eof_errno": 0}, False),
    ({"entries": False, "eof_errno": errno.EIO}, False),
    ({"entry_error": True, "eof_errno": errno.EACCES}, False),
    ({"valid": False}, False),
])
def test_acl_eof_and_errors_are_distinguished(acl_guard, monkeypatch, case, expected):
    library = FakeACL(**case)
    monkeypatch.setattr(acl_guard.ctypes, "CDLL", lambda *args, **kwargs: library)
    monkeypatch.setattr(acl_guard.sys, "platform", "darwin")
    assert acl_guard._acl_write_safe(Path("/synthetic/protected")) is expected
    assert library.freed == 1


@pytest.mark.parametrize("code, expected", [(errno.ENOENT, True), (errno.ENOTSUP, True),
                                           (errno.EACCES, False), (errno.EIO, False), (0, False)])
def test_missing_acl_requires_a_documented_no_acl_errno(acl_guard, monkeypatch, code, expected):
    library = FakeACL(absent_errno=code)
    monkeypatch.setattr(acl_guard.ctypes, "CDLL", lambda *args, **kwargs: library)
    monkeypatch.setattr(acl_guard.sys, "platform", "darwin")
    assert acl_guard._acl_write_safe(Path("/synthetic/protected")) is expected
    assert library.freed == 0


def test_acl_permissions_match_the_native_guard_without_building():
    native = (ROOT / "macos/AuthorizationBridge.c").read_text()
    for name in ("ACL_WRITE_DATA", "ACL_APPEND_DATA", "ACL_DELETE", "ACL_DELETE_CHILD",
                 "ACL_WRITE_ATTRIBUTES", "ACL_WRITE_EXTATTRIBUTES", "ACL_WRITE_SECURITY", "ACL_CHANGE_OWNER"):
        assert "acl_get_perm_np(permissions, " + name + ")" in native
