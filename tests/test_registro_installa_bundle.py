"""Signed bundle transaction fixtures; never invoke root, TCC or a real service."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import registro_installa as I

_spec = importlib.util.spec_from_file_location("daemon_bundle_fixture", Path(I.__file__).with_name("registro_daemon.py"))
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)


class BundleInstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="paratia-install-fixture-", dir="/private/tmp")
        self.base = Path(self.tmp.name).resolve()
        self.app = self.base / "source" / "Paratia.app"
        self.source = self.app / "Contents" / "Resources" / "python"
        self.uid = os.getuid() or 501
        self.identity = "a" * 40
        self.support = self.base / "system" / "Support"
        self.logs = self.base / "system" / "Logs"
        self.daemons = self.base / "system" / "LaunchDaemons"
        self.make_app(self.app, b"NEW APP")
        self.commands = []
        self.bootstrap_fail = False
        self.bootstraps = 0
        self.old_service = False
        self.sleeps = []

    def tearDown(self):
        self.tmp.cleanup()

    def make_app(self, app, binary):
        resources = app / "Contents" / "Resources" / "python"
        resources.mkdir(parents=True)
        for name in (*I.CODICE, "registro_installa.py"):
            (resources / name).write_bytes(b"VALUE = 'synthetic-code-only'\n")
        executable = app / "Contents" / "MacOS" / "Paratia"
        executable.parent.mkdir()
        executable.write_bytes(binary)
        executable.chmod(0o755)
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "it.paratia.app", "CFBundleExecutable": "Paratia",
            "CFBundlePackageType": "APPL", "ParatiaRegistryLauncherVersion": 1}))

    def previous(self):
        self.support.mkdir(parents=True)
        self.daemons.mkdir(parents=True)
        directory = self.logs / str(self.uid)
        directory.mkdir(parents=True)
        self.make_app(self.support / "Paratia.app", b"OLD APP")
        for name in I.CODICE:
            (self.support / name).write_bytes(b"OLD = 1\n")
            (self.support / name).chmod(0o600)
        (directory / "catena.jsonl").write_bytes(b"old-chain-preserved\n")
        (directory / "stato.json").write_bytes(b'{"running":false,"healthy":false,"old":true}')
        for p in directory.iterdir():
            p.chmod(0o600)
        (self.daemons / ("it.paratia.registro.%d.plist" % self.uid)).write_bytes(
            plistlib.dumps({"ProgramArguments": ["/protected/old-python", "old-daemon.py"]}))
        self.old_service = True

    def old_snapshot(self):
        return {str(p.relative_to(self.base)): p.read_bytes()
                for folder in (self.support, self.logs, self.daemons) if folder.exists()
                for p in folder.rglob("*") if p.is_file() and not p.name.startswith(".")}

    def fixture_path(self, p):
        p = Path(p)
        self.assertTrue(p.is_relative_to(self.base), str(p))
        return p

    def protected(self, p, directory=False):
        # Model only root ownership: fixtures retain the ordinary test user's UID.
        p = self.fixture_path(p)
        s = p.lstat()
        self.assertEqual(s.st_uid, os.getuid())
        if (s.st_mode & 0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) or
                (not directory and s.st_nlink != 1)):
            raise ValueError("Unsafe fixture target")

    def command(self, argv, **kwargs):
        self.commands.append(list(argv))
        self.assertIn(argv[0], ("/bin/chmod", "/bin/launchctl", "/usr/bin/codesign"))
        rc = 0
        if argv[:2] == ["/bin/launchctl", "print"]:
            rc = 0 if self.old_service else 3
        if argv[:2] == ["/bin/launchctl", "bootout"]:
            self.old_service = False
        if argv[:2] == ["/bin/launchctl", "bootstrap"]:
            self.bootstraps += 1
            if self.bootstrap_fail and self.bootstraps <= 3:
                rc = 5
            else:
                self.old_service = True
        if kwargs.get("check") and rc:
            raise subprocess.CalledProcessError(rc, argv, stderr=b"RAW_DIAGNOSTIC_NOT_FOR_LOGS")
        return SimpleNamespace(returncode=rc, stdout=b"", stderr=b"")

    @contextlib.contextmanager
    def installation(self):
        original_tree = I._albero

        def source(fonte, uid):
            self.assertEqual(Path(fonte), self.source)
            self.assertEqual(uid, self.uid)
            original_tree(self.app, (os.getuid(),))
            I._info_bundle(self.app)
            return self.app, self.identity

        def directory(p):
            p = self.fixture_path(p)
            p.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.protected(p, directory=True)

        def tree(app, owners, copia=None):
            self.fixture_path(app)
            if copia is not None:
                self.fixture_path(copia)
            return original_tree(app, (os.getuid(),), copia=copia)

        def code(fonte, nome, uid):
            self.fixture_path(fonte)
            self.assertEqual(uid, 0)  # Code is read from the already verified root stage.
            raw = (fonte / nome).read_bytes()
            compile(raw, nome, "exec")
            return raw

        with contextlib.ExitStack() as stack:
            for name, value in (("SUPPORT", self.support), ("LOGS", self.logs), ("DAEMONS", self.daemons)):
                stack.enter_context(mock.patch.object(I, name, value))
            stack.enter_context(mock.patch.object(I.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(I.os, "fchown"))
            stack.enter_context(mock.patch.object(I, "runtime", return_value="/protected/ApplePython"))
            stack.enter_context(mock.patch.object(I, "_app_sorgente", side_effect=source))
            stack.enter_context(mock.patch.object(I, "_directory", side_effect=directory))
            stack.enter_context(mock.patch.object(I, "_protetto", side_effect=self.protected))
            stack.enter_context(mock.patch.object(I, "_albero", side_effect=tree))
            stack.enter_context(mock.patch.object(I, "_firma", return_value=self.identity))
            stack.enter_context(mock.patch.object(I, "_leggi_codice", side_effect=code))
            stack.enter_context(mock.patch.object(I.subprocess, "run", side_effect=self.command))
            stack.enter_context(mock.patch.object(I.time, "sleep", side_effect=self.sleeps.append))
            yield

    def test_new_plist_uses_native_app_parent_and_plan_keeps_nine_authorization_args(self):
        with self.installation(), mock.patch.object(I, "installa") as install:
            plan = I.piano(self.source, self.uid)
            install.assert_not_called()
        self.assertEqual(len(plan["argv"]), 9)
        self.assertEqual(plan["argv"][:3], ["/protected/ApplePython", "-I", "-S"])
        self.assertEqual(plan["plist"]["ProgramArguments"], [
            str(self.support / "Paratia.app" / "Contents" / "MacOS" / "Paratia"), "--registro", "--uid", str(self.uid)])
        self.assertEqual(plan["fda_entry"], "/Applications/Paratia.app")
        self.assertTrue(plan["fda_regrant_after_build"])
        self.assertFalse(self.commands)
        self.assertFalse(self.support.exists())

    def test_copy_and_success_leave_source_ownership_and_files_unchanged(self):
        before = {str(p.relative_to(self.app)): (p.read_bytes(), p.stat().st_uid)
                  for p in self.app.rglob("*") if p.is_file()}
        with self.installation():
            result = I.installa(self.source, self.uid)
        self.assertTrue(result["installed"])
        self.assertIsNone(result["error_code"])
        self.assertEqual(result["launchctl_errors"], [])
        self.assertIsNone(result["needs_fda"])
        self.assertEqual(result["launch_mode"], "app")
        after = {str(p.relative_to(self.app)): (p.read_bytes(), p.stat().st_uid)
                 for p in self.app.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        copied = self.support / "Paratia.app"
        self.assertEqual((copied / "Contents" / "MacOS" / "Paratia").read_bytes(), b"NEW APP")
        for name in I.CODICE:
            self.assertEqual((self.support / name).read_bytes(), (self.source / name).read_bytes())
        state = json.loads((self.logs / str(self.uid) / "stato.json").read_bytes())
        self.assertFalse(state["running"])
        self.assertFalse(state["healthy"])
        self.assertIsNone(state["needs_fda"])
        self.assertEqual(state["fda_entry"], "/Applications/Paratia.app")
        self.assertEqual(state["installed_cdhash"], self.identity)
        self.assertFalse(list(self.support.glob(".installazione-*")))

    def test_bad_copied_signature_preserves_previous_before_bootout(self):
        self.previous()
        before = self.old_snapshot()
        with self.installation(), mock.patch.object(I, "_firma", return_value="b" * 40):
            with self.assertRaises(ValueError):
                I.installa(self.source, self.uid)
        self.assertEqual(self.old_snapshot(), before)
        self.assertFalse(any(c[0] == "/bin/launchctl" for c in self.commands))

    def test_source_resigned_during_copy_is_refused_before_old_service_stops(self):
        self.previous()
        before = self.old_snapshot()
        with self.installation(), mock.patch.object(I, "_firma", side_effect=lambda p: "b" * 40 if p == self.app else self.identity):
            with self.assertRaises(ValueError):
                I.installa(self.source, self.uid)
        self.assertEqual(self.old_snapshot(), before)
        self.assertFalse(any(c[0] == "/bin/launchctl" for c in self.commands))

    def test_bootstrap_failure_restores_app_payload_plist_and_state(self):
        self.previous()
        before = self.old_snapshot()
        self.bootstrap_fail = True
        with self.installation():
            with self.assertRaises(I.ErroreInstallazione) as caught:
                I.installa(self.source, self.uid)
        self.assertEqual(caught.exception.error_code, "bootstrap_failed")
        self.assertIn("ripristinato e riavviato", str(caught.exception))
        self.assertEqual(self.old_snapshot(), before)
        self.assertEqual(self.bootstraps, 4)  # Three retries, then restart only the old service.
        self.assertFalse(list(self.support.glob(".installazione-*")))

    def test_replacement_failure_restores_already_moved_originals(self):
        self.previous()
        before = self.old_snapshot()
        replace = os.replace
        refused = [False]

        def fail_one(source, target, *args, **kwargs):
            if Path(target) == self.support / "registro.py" and not refused[0]:
                refused[0] = True
                raise OSError("synthetic rename failure")
            return replace(source, target, *args, **kwargs)

        with self.installation(), mock.patch.object(I.os, "replace", side_effect=fail_one):
            with self.assertRaises(I.ErroreInstallazione) as caught:
                I.installa(self.source, self.uid)
        self.assertEqual(caught.exception.error_code, "install_failed")
        self.assertEqual(self.old_snapshot(), before)

    def test_failed_rollback_retains_protected_previous_bundle_checkpoint(self):
        self.previous()
        replace = os.replace

        def fail_restore(source, target, *args, **kwargs):
            if Path(target) == self.support / "Paratia.app" and Path(source).name == "precedente-0":
                raise OSError("synthetic recovery failure")
            return replace(source, target, *args, **kwargs)

        self.bootstrap_fail = True
        with self.installation(), mock.patch.object(I.os, "replace", side_effect=fail_restore):
            with self.assertRaises(ValueError) as caught:
                I.installa(self.source, self.uid)
        self.assertTrue(caught.exception.conserva_stage)
        stages = list(self.support.glob(".installazione-*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / "precedente-0" / "Contents" / "MacOS" / "Paratia").read_bytes(), b"OLD APP")

    def test_unsafe_existing_bundle_symlink_never_changes_external_directory(self):
        self.previous()
        old = self.support / "Paratia.app"
        import shutil
        shutil.rmtree(old)
        outside = self.base / "external-fixture"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"KEEP")
        old.symlink_to(outside, target_is_directory=True)
        with self.installation():
            with self.assertRaises(ValueError):
                I.installa(self.source, self.uid)
        self.assertEqual(sentinel.read_bytes(), b"KEEP")
        self.assertTrue(old.is_symlink())
        self.assertFalse(any(c[:2] == ["/bin/launchctl", "bootout"] for c in self.commands))

    def test_source_links_special_files_hardlinks_and_size_caps_are_refused(self):
        external = self.base / "unrelated"
        external.write_bytes(b"KEEP")
        leaf = self.source / "unexpected"
        leaf.symlink_to(external)
        with self.assertRaises(ValueError):
            I._albero(self.app, (os.getuid(),))
        leaf.unlink()
        os.mkfifo(leaf)
        with self.assertRaises(ValueError):
            I._albero(self.app, (os.getuid(),))
        leaf.unlink()
        os.link(external, leaf)
        with self.assertRaises(ValueError):
            I._albero(self.app, (os.getuid(),))
        leaf.unlink()
        with mock.patch.object(I, "MAX_BUNDLE", 1):
            with self.assertRaises(ValueError):
                I._albero(self.app, (os.getuid(),))
        self.assertEqual(external.read_bytes(), b"KEEP")

    def test_launcher_marker_missing_bool_or_newer_version_are_refused(self):
        path = self.app / "Contents" / "Info.plist"
        info = plistlib.loads(path.read_bytes())
        for marker in (None, True, 2):
            with self.subTest(marker=marker):
                changed = dict(info)
                if marker is None:
                    changed.pop("ParatiaRegistryLauncherVersion")
                else:
                    changed["ParatiaRegistryLauncherVersion"] = marker
                path.write_bytes(plistlib.dumps(changed))
                with self.assertRaises(ValueError):
                    I._info_bundle(self.app)

    def test_codesign_verifies_adhoc_identity_and_never_signs_or_uses_keychain(self):
        output = "Identifier=it.paratia.app\nSignature=adhoc\nCDHash=" + self.identity + "\n"
        results = [SimpleNamespace(stdout=b"", stderr=b""), SimpleNamespace(stdout="", stderr=output)]
        with mock.patch.object(I.subprocess, "run", side_effect=results) as run:
            self.assertEqual(I._firma(self.app), self.identity)
        args = [call.args[0] for call in run.call_args_list]
        self.assertEqual(args[0][1:4], ["--verify", "--deep", "--strict"])
        self.assertTrue(all("--sign" not in a and "security" not in a for a in args))
        with mock.patch.object(I.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "codesign", stderr="PRIVATE")):
            with self.assertRaises(ValueError) as caught:
                I._firma(self.app)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_root_owner_is_mandatory_outside_the_fixture_ownership_model(self):
        if os.getuid() == 0:
            self.skipTest("Designed to prove refusal for an ordinary fixture owner")
        with self.assertRaises(ValueError):
            I._protetto(self.app, directory=True)

    def test_daemon_metadata_distinguishes_native_launcher_and_legacy_python(self):
        with mock.patch.dict(os.environ, {"PARATIA_REGISTRY_LAUNCHER": "app"}):
            native = D.contesto_launcher()
        with mock.patch.dict(os.environ, {}, clear=True):
            legacy = D.contesto_launcher()
        self.assertEqual(native["launch_mode"], "app")
        self.assertEqual(legacy["launch_mode"], "legacy-python")
        for value in (native, legacy):
            self.assertEqual(value["fda_entry"], "/Applications/Paratia.app")
            self.assertTrue(value["fda_regrant_after_build"])
            self.assertNotIn("/usr/bin/eslogger", D.messaggio_fda(value))
        self.assertIn("Reinstalla", D.messaggio_fda(legacy))

    def test_runtime_rejects_xcode_before_invoking_any_python(self):
        xcode = Path("/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3")
        with mock.patch.object(I, "_rootpath", return_value=xcode), mock.patch.object(I.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                I.runtime()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
