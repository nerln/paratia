"""Hook merge/rollback, safe filesystem boundaries, and Codex disk decisions.

All config mutations use user-owned temporary homes. Gate tests mock the disk
backend and transcript provider; they never mount volumes or read transcripts.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import hookinstaller as H


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="paratia-hooks-", dir="/private/tmp")
        self.base = Path(self.tmp.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir()
        self.resources = self.base / "resources ' $(literal)"
        (self.resources / "hooks").mkdir(parents=True)
        (self.resources / "hooks" / "paratia-gate.py").write_text("# synthetic gate\n")
        (self.resources / "cartelle.py").write_text("# synthetic disk adapter\n")
        self.kwargs = {"home": self.home, "resource_root": self.resources}

    def tearDown(self):
        self.tmp.cleanup()

    def config(self, harness):
        directory, name = H.TARGETS[harness]
        return self.home / directory / name

    def put(self, harness, data):
        p = self.config(harness)
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        return p

    def test_plan_read_only_and_no_foreign_settings_in_result(self):
        original = b'{"env":{"SECRET_API_KEY":"private-value"}, "hooks":{}}\n'
        p = self.put("claude", original)
        result = H.piano(**self.kwargs)
        self.assertFalse(result["configured"])
        self.assertTrue(all(c["changed"] for c in result["changes"]))
        self.assertEqual(p.read_bytes(), original)
        self.assertFalse((self.home / ".codex").exists())
        self.assertFalse((self.home / ".paratia-hooks.lock").exists())
        self.assertNotIn("private-value", json.dumps(result))
        command = result["changes"][1]["hooks"]["PreToolUse"]["hooks"][0]["command"]
        argv = shlex.split(command)
        self.assertTrue(Path(argv[0]).is_absolute())
        self.assertEqual(argv[1:], ["-I", "-S", "-B", str(self.resources / "hooks" / "paratia-gate.py"), "--codex"])
        self.assertTrue(result["needs_human_trust"])
        self.assertEqual(result["codex_trust"], "unknown")
        self.assertFalse(result["protected_closure"])
        self.assertIn("app Paratia aperta dal Finder", result["message"])

    def test_preserves_foreign_hooks_flags_and_trust_bytes_and_is_idempotent(self):
        foreign_group = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo foreign", "async": True}]}
        original = {"disableAllHooks": True, "env": {"API": "private"}, "hooks": {
            "PreToolUse": [foreign_group], "Stop": [{"hooks": [{"type": "command", "command": "echo stop"}]}]}}
        self.put("claude", json.dumps(original).encode())
        cp = self.put("codex", b'{"description":"Existing", "hooks":{}}\n')
        trust = cp.parent / "hook-trust.json"
        trust.write_bytes(b"UNTOUCHED_TRUST")
        result = H.installa(**self.kwargs)
        self.assertTrue(result["configured"])
        self.assertTrue(result["changed"])
        self.assertEqual(len(result["backups"]), 2)
        merged = json.loads(self.config("claude").read_bytes())
        self.assertEqual(merged["env"], original["env"])
        self.assertTrue(merged["disableAllHooks"])
        self.assertEqual(merged["hooks"]["Stop"], original["hooks"]["Stop"])
        self.assertEqual(merged["hooks"]["PreToolUse"][0], foreign_group)
        self.assertEqual(trust.read_bytes(), b"UNTOUCHED_TRUST")
        self.assertTrue(result["harnesses"]["claude"]["disabled_in_settings"])
        for harness in H.TARGETS:
            body = json.loads(self.config(harness).read_bytes())
            for event in H.EVENTS:
                own = body["hooks"][event][-1]
                self.assertEqual(own["matcher"], "*")
                self.assertNotIn("async", own["hooks"][0])
        before = {h: self.config(h).read_bytes() for h in H.TARGETS}
        again = H.installa(**self.kwargs)
        self.assertFalse(again["changed"])
        self.assertEqual(again["backups"], [])
        self.assertEqual(before, {h: self.config(h).read_bytes() for h in H.TARGETS})
        self.assertEqual(H.stato(**self.kwargs)["codex_trust"], "unknown")

    def test_backups_restore_exact_bytes_and_new_files_can_be_removed(self):
        original = b'{ "other": [1, 2], "hooks": {} }\n'
        p = self.put("claude", original)
        p.chmod(0o640)
        result = H.installa(**self.kwargs)
        for backup in result["backups"]:
            self.assertEqual(Path(backup).stat().st_mode & 0o777, 0o600)
            restored = H.ripristina(backup, home=self.home)
            self.assertTrue(restored["restored"])
        self.assertEqual(p.read_bytes(), original)
        self.assertEqual(p.stat().st_mode & 0o777, 0o640)
        self.assertFalse(self.config("codex").exists())

    def test_restore_refuses_later_foreign_changes(self):
        result = H.installa(**self.kwargs)
        p = self.config("claude")
        p.write_bytes(b'{"new-human-setting":true}\n')
        backup = next(x for x in result["backups"] if Path(x).parent == p.parent)
        with self.assertRaises(H.Rifiuto):
            H.ripristina(backup, home=self.home)
        self.assertEqual(p.read_bytes(), b'{"new-human-setting":true}\n')

    def test_invalid_second_config_is_preflighted_before_first_write(self):
        original = b'{"untouched":true}\n'
        p = self.put("claude", original)
        self.put("codex", b"{invalid")
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)
        self.assertEqual(p.read_bytes(), original)
        self.assertEqual(list(self.home.rglob("*.paratia-backup-*")), [])

    def test_second_failure_restores_first_config(self):
        a = self.put("claude", b'{"a":1}\n')
        b = self.put("codex", b'{"b":2}\n')
        originals = a.read_bytes(), b.read_bytes()
        write = H._write
        failed = [False]
        def fail_second(directory, name, before, after, mode):
            if name == "hooks.json" and not failed[0]:
                failed[0] = True
                raise OSError("synthetic failure")
            return write(directory, name, before, after, mode)
        with mock.patch.object(H, "_write", side_effect=fail_second):
            with self.assertRaises(H.Rifiuto) as caught:
                H.installa(**self.kwargs)
        self.assertEqual((a.read_bytes(), b.read_bytes()), originals)
        self.assertEqual(len(caught.exception.backups), 2)

    def test_failure_after_replace_is_also_rolled_back(self):
        a = self.put("claude", b'{"a":1}\n')
        b = self.put("codex", b'{"b":2}\n')
        originals = a.read_bytes(), b.read_bytes()
        write = H._write
        failed = [False]
        def fail_after_second(directory, name, before, after, mode):
            answer = write(directory, name, before, after, mode)
            if name == "hooks.json" and not failed[0]:
                failed[0] = True
                raise OSError("synthetic directory fsync failure")
            return answer
        with mock.patch.object(H, "_write", side_effect=fail_after_second):
            with self.assertRaises(H.Rifiuto):
                H.installa(**self.kwargs)
        self.assertEqual((a.read_bytes(), b.read_bytes()), originals)

    def test_concurrent_foreign_edit_is_preserved_during_rollback(self):
        a = self.put("claude", b'{"a":1}\n')
        b = self.put("codex", b'{"b":2}\n')
        original_a = a.read_bytes()
        foreign = b'{"new_foreign_setting":true}\n'
        write = H._write
        edited = [False]
        def foreign_edit(directory, name, before, after, mode):
            if name == "hooks.json" and not edited[0]:
                edited[0] = True
                b.write_bytes(foreign)
            return write(directory, name, before, after, mode)
        with mock.patch.object(H, "_write", side_effect=foreign_edit):
            with self.assertRaises(H.Rifiuto) as caught:
                H.installa(**self.kwargs)
        self.assertEqual(a.read_bytes(), original_a)
        self.assertEqual(b.read_bytes(), foreign)
        self.assertEqual(len(caught.exception.backups), 2)

    def test_symlink_ancestor_and_leaf_fifo_and_hardlinks_refused(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.home / ".claude").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)
        self.assertEqual(list(outside.iterdir()), [])
        (self.home / ".claude").unlink()
        (self.home / ".claude").mkdir()
        p = self.config("claude")
        target = outside / "settings.json"
        target.write_bytes(b'{"private":"preserved"}\n')
        p.symlink_to(target)
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)
        self.assertEqual(target.read_bytes(), b'{"private":"preserved"}\n')
        p.unlink()
        os.mkfifo(p)
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)
        p.unlink()
        os.link(target, p)
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)

    def test_json_caps_duplicates_and_other_owner_refused(self):
        self.put("claude", b'{"hooks":{}, "hooks":{}}')
        with self.assertRaises(H.Rifiuto):
            H.installa(**self.kwargs)
        self.config("claude").write_bytes(b'{}' * 100)
        with mock.patch.object(H, "MAX_JSON", 64):
            with self.assertRaises(H.Rifiuto):
                H.installa(**self.kwargs)
        with self.assertRaises(H.Rifiuto):
            H._owned(SimpleNamespace(st_mode=0o100600, st_uid=os.getuid() + 1, st_nlink=1))

    def test_concurrent_installers_keep_one_own_group(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: H.installa(**self.kwargs), range(8)))
        self.assertEqual(sum(r["changed"] for r in results), 1)
        self.assertEqual(sum(len(r["backups"]) for r in results), 2)
        for harness in H.TARGETS:
            body = json.loads(self.config(harness).read_bytes())
            self.assertTrue(all(len(body["hooks"][e]) == 1 for e in H.EVENTS))

    def test_process_lock_serializes_independent_installers(self):
        module_root = str(Path(H.__file__).resolve().parent)
        program = ("import sys,json; sys.path.insert(0,sys.argv[1]); "
                   "import hookinstaller as h; "
                   "print(json.dumps(h.installa(resource_root=sys.argv[2],home=sys.argv[3])))")
        processes = [subprocess.Popen([sys.executable, "-I", "-S", "-c", program,
                                      module_root, str(self.resources), str(self.home)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        results = []
        try:
            for process in processes:
                out, err = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, err.decode(errors="replace"))
                results.append(json.loads(out))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        self.assertEqual(sum(r["changed"] for r in results), 1)
        self.assertEqual(sum(len(r["backups"]) for r in results), 2)
        for harness in H.TARGETS:
            body = json.loads(self.config(harness).read_bytes())
            self.assertTrue(all(len(body["hooks"][e]) == 1 for e in H.EVENTS))

    def test_python_must_be_absolute_and_new_enough(self):
        with self.assertRaises(H.Rifiuto):
            H._runtime("python3")
        with mock.patch.object(H.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"3.9\n")):
            with self.assertRaises(H.Rifiuto):
                H._runtime("/usr/bin/python3")

    def test_user_homebrew_runtime_and_stable_alias_cannot_authorize_protected_hooks(self):
        brew = self.base / "brew"
        version = brew / "Cellar" / "python@3.14" / "3.14.6" / "bin" / "python3.14"
        version.parent.mkdir(parents=True)
        version.write_text("synthetic interpreter; never executed")
        version.chmod(0o700)
        alias = brew / "bin" / "python3"
        alias.parent.mkdir()
        alias.symlink_to(version)
        with mock.patch.object(H.subprocess, "run", side_effect=AssertionError("Untrusted Python executed")):
            for candidate in (version, alias):
                with self.assertRaises(H.Rifiuto):
                    H._runtime(str(candidate))
        next_version = brew / "Cellar" / "python@3.14" / "3.14.7" / "bin" / "python3.14"
        next_version.parent.mkdir(parents=True)
        next_version.write_text("updated synthetic interpreter; never executed")
        next_version.chmod(0o700)
        alias.unlink()
        alias.symlink_to(next_version)
        with mock.patch.object(H.subprocess, "run", side_effect=AssertionError("Untrusted Python executed")):
            with self.assertRaises(H.Rifiuto):
                H._runtime(str(alias))

    def test_cellar_runtime_without_matching_stable_alias_is_refused(self):
        version = self.base / "Cellar" / "python@3.14" / "3.14.6" / "bin" / "python3.14"
        version.parent.mkdir(parents=True)
        version.write_text("synthetic interpreter; never executed")
        version.chmod(0o700)
        with mock.patch.object(H.subprocess, "run", side_effect=AssertionError("Versioned Python was executed")):
            with self.assertRaises(H.Rifiuto):
                H._runtime(str(version))


class CodexGateTests(unittest.TestCase):
    def setUp(self):
        source = Path(__file__).resolve().parents[1] / "hooks" / "paratia-gate.py"
        spec = importlib.util.spec_from_file_location("gate_codex_test", source)
        self.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.gate)

    def run_gate(self, payload, codex=True):
        output = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stdout(output):
            rc = self.gate.main(codex=codex)
        return rc, json.loads(output.getvalue()) if output.getvalue() else None

    def test_codex_mount_guard_denies_every_supported_tool(self):
        with mock.patch.object(self.gate, "compartimento_aperto", return_value=True):
            for tool in ("Bash", "apply_patch", "mcp__files__read", "update_plan", "Agent"):
                rc, result = self.run_gate({"hook_event_name": "PreToolUse", "tool_name": tool,
                                           "tool_input": {"command": "ordinary-command"}})
                self.assertEqual(rc, 0)
                self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_codex_session_start_stops_if_close_fails_claude_keeps_exit_two(self):
        with mock.patch.object(self.gate, "chiudi_inizio_sessione", return_value=2):
            rc, result = self.run_gate({"hook_event_name": "SessionStart"})
            self.assertEqual(rc, 0)
            self.assertFalse(result["continue"])
            self.assertIn("stopReason", result)
            rc, result = self.run_gate({"hook_event_name": "SessionStart"}, codex=False)
            self.assertEqual(rc, 2)
            self.assertIsNone(result)

    def test_codex_does_not_consult_unverified_claude_transcript_provider(self):
        with mock.patch.object(self.gate, "compartimento_aperto", return_value=False), \
                mock.patch.object(self.gate, "chi_ha_parlato", side_effect=AssertionError("must not read transcript")):
            self.assertEqual(self.run_gate({"hook_event_name": "PreToolUse", "tool_name": "mcp__computer-use__screenshot"}), (0, None))


if __name__ == "__main__":
    unittest.main()
