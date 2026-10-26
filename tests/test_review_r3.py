"""R2-N1: binding an operator's SSH enrollment consent to one verified host.

All SSH calls are simulated; only disposable local ED25519 fixtures are created.
"""

import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc


class TTY:
    def isatty(self):
        return True


class EnrollmentAuthorizationTests(unittest.TestCase):
    def create_key(self, root, name):
        key = root / name
        p = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key), "-N", ""],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        return key

    def fixture(self, stack, root):
        etc = root / "etc"
        etc.mkdir()
        state = root / "state.json"
        sc.write_json(state, {"status": "DIRECT"})
        paths = {
            "ETC": etc, "CONF": etc / "config.json",
            "SSH_CONF": etc / "ssh_config", "KNOWN_HOSTS": etc / "known_hosts",
            "STATE": state, "LOCK": root / "manager.lock",
        }
        for name, path in paths.items():
            stack.enter_context(patch.object(sc, name, path))
        for name in ("require_root", "require_client_role", "require_no_teardown"):
            stack.enter_context(patch.object(sc, name))
        stack.enter_context(patch.object(sc, "service_terminated", return_value=True))
        stack.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))

        client = self.create_key(root, "client_key")
        host_a = self.create_key(root, "host_a")
        host_b = self.create_key(root, "host_b")
        data = {}
        for ip, key in (("8.8.8.8", host_a), ("9.9.9.9", host_b)):
            encoded = Path(str(key) + ".pub").read_text().split()[1]
            record = f"[{ip}]:56777 ssh-ed25519 {encoded}\n"
            fingerprint = sc.pinned_host_identity(
                {"remote_ip": ip, "ssh_port": 56777}, record.encode())
            data[ip] = (record, fingerprint)

        def fake_run(args, **kwargs):
            if args[0] == "ssh-keyscan":
                return subprocess.CompletedProcess(args, 0, data[args[-1]][0], "")
            if args[0] == "ssh-keygen" and "-lf" in args:
                line = Path(args[-1]).read_text()
                ip = next(ip for ip, val in data.items() if val[0] == line)
                return subprocess.CompletedProcess(args, 0, f"256 {data[ip][1]} host\n", "")
            if args[0] == "ssh-keygen" and "-y" in args:
                pub = Path(str(args[-1]) + ".pub")
                # The helper validates a staged hard link *before* publishing
                # the frozen public-key snapshot beside it.
                if not pub.exists():
                    pub = Path(str(client) + ".pub")
                return subprocess.CompletedProcess(args, 0, pub.read_text(), "")
            raise AssertionError(f"Unexpected subprocess: {args}")

        stack.enter_context(patch.object(sc, "run", side_effect=fake_run))
        return paths, client, data

    def save_host(self, ip, key, data):
        sc.configure(ip, "root", 56777, str(key), data[ip][1])

    def test_configure_a_then_b_during_enrollment_prompt_cannot_enroll_b(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            consent_args = []
            did_change = []
            def prompt(question):
                if "Trusted remote" in question:
                    return data["8.8.8.8"][1]
                if "Authorize public-key enrollment" in question:
                    consent_args.append(question)
                    self.save_host("9.9.9.9", key, data)
                    did_change.append(True)
                    return "y"
                self.fail(f"Unexpected prompt: {question}")
            with patch.object(sc.sys, "stdin", TTY()), (
                 patch("builtins.input", side_effect=prompt)), (
                 patch.object(sc.subprocess, "run")) as remote:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    with self.assertRaisesRegex(sc.ConnectError, "changed after consent"):
                        sc.configure("8.8.8.8", "root", 56777, str(key), None)
                remote.assert_not_called()
            self.assertEqual(len(did_change), 1)
            self.assertIn("root@8.8.8.8:56777", consent_args[0])
            self.assertNotIn("9.9.9.9", consent_args[0])
            self.assertIn("Public key destination: root@8.8.8.8:56777", output.getvalue())
            self.assertEqual(sc.read_json(paths["CONF"])["remote_ip"], "9.9.9.9")
            self.assertIn("[9.9.9.9]:56777", paths["KNOWN_HOSTS"].read_text())

    def test_standalone_consent_rechecks_changed_host_key_before_remote_action(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            self.save_host("8.8.8.8", key, data)
            alternate_key = self.create_key(Path(d), "alternate_host")
            encoded = Path(str(alternate_key) + ".pub").read_text().split()[1]
            replacement = f"[8.8.8.8]:56777 ssh-ed25519 {encoded}\n"
            old = paths["KNOWN_HOSTS"].read_bytes()
            def authorize(question, **kwargs):
                self.assertIn("root@8.8.8.8:56777", question)
                paths["KNOWN_HOSTS"].write_text(replacement)
                return True
            with patch.object(sc, "yes_no", side_effect=authorize), (
                 patch.object(sc.subprocess, "run")) as remote:
                with self.assertRaisesRegex(sc.ConnectError, "changed after consent"):
                    sc.enroll_public_key()
                remote.assert_not_called()
            self.assertNotEqual(paths["KNOWN_HOSTS"].read_bytes(), old)
            self.assertEqual(sc.read_json(paths["CONF"])["remote_ip"], "8.8.8.8")

    def test_change_during_staging_rejected_before_remote_command(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            self.save_host("8.8.8.8", key, data)
            original = sc.validated_public_key
            def change_when_validating(path):
                paths["KNOWN_HOSTS"].write_text(data["9.9.9.9"][0])
                return original(path)
            with patch.object(sc, "yes_no", return_value=True), (
                 patch.object(sc, "validated_public_key", side_effect=change_when_validating)), (
                 patch.object(sc.subprocess, "run")) as remote:
                with self.assertRaisesRegex(sc.ConnectError, "changed after consent"):
                    sc.enroll_public_key()
                remote.assert_not_called()

    def test_immutable_host_and_public_key_snapshot_survives_later_shared_change(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            self.save_host("8.8.8.8", key, data)
            collected = {}
            def remote(args, **kwargs):
                # This simulates B modifying shared state *after* the final
                # revision check. The already authorized command must use A.
                self.save_host("9.9.9.9", key, data)
                host_arg = next(a for a in args if a.startswith("UserKnownHostsFile="))
                staged_host = Path(host_arg.split("=", 1)[1])
                staged_pub = Path(args[args.index("-i") + 1])
                self.assertEqual(staged_host.read_text(), data["8.8.8.8"][0])
                self.assertEqual(sc.pinned_host_identity(
                    {"remote_ip": "8.8.8.8", "ssh_port": 56777},
                    staged_host.read_bytes()), data["8.8.8.8"][1])
                self.assertEqual(sc.read_public_key_record(staged_pub),
                                 sc.read_public_key_record(Path(str(key) + ".pub")))
                self.assertTrue(Path(str(staged_pub)[:-4]).is_file())
                self.assertEqual(args[-1], "root@8.8.8.8")
                self.assertIn("-F", args)
                self.assertEqual(args[args.index("-F") + 1], "/dev/null")
                self.assertIn("GlobalKnownHostsFile=/dev/null", args)
                self.assertIn("UpdateHostKeys=no", args)
                self.assertIn("HostKeyAlgorithms=ssh-ed25519", args)
                self.assertIn("StrictHostKeyChecking=yes", args)
                collected["paths"] = [staged_pub, staged_host]
                return subprocess.CompletedProcess(args, 0, "", "")
            with patch.object(sc, "yes_no", return_value=True), (
                 patch.object(sc.subprocess, "run", side_effect=remote)) as call:
                sc.enroll_public_key()
                self.assertEqual(call.call_count, 1)
            self.assertEqual(sc.read_json(paths["CONF"])["remote_ip"], "9.9.9.9")
            for path in collected["paths"]:
                self.assertFalse(path.exists(), "temporary enrollment snapshot must be removed")

    def test_declining_explicit_confirmation_never_runs_remote(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            self.save_host("8.8.8.8", key, data)
            display = io.StringIO()
            with patch.object(sc, "yes_no", return_value=False) as consent, (
                 patch.object(sc.subprocess, "run")) as remote, (
                 contextlib.redirect_stdout(display)):
                sc.enroll_public_key()
                consent.assert_called_once()
                remote.assert_not_called()
            self.assertIn("root@8.8.8.8:56777", display.getvalue())
            self.assertIn(data["8.8.8.8"][1], display.getvalue())

    def test_no_manager_lock_during_approval_or_remote_io(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            self.save_host("8.8.8.8", key, data)
            actual_lock = sc.locked
            active = {"value": False, "calls": 0}
            @contextlib.contextmanager
            def traced_lock(*args, **kwargs):
                with actual_lock(*args, **kwargs):
                    self.assertFalse(active["value"])
                    active["value"] = True
                    active["calls"] += 1
                    try:
                        yield
                    finally:
                        active["value"] = False
            def consent(question, **kwargs):
                self.assertFalse(active["value"], "consent must not hold manager lock")
                return True
            def remote(args, **kwargs):
                self.assertFalse(active["value"], "SSH/password I/O must not hold manager lock")
                return subprocess.CompletedProcess(args, 0, "", "")
            with patch.object(sc, "locked", side_effect=traced_lock), (
                 patch.object(sc, "yes_no", side_effect=consent)), (
                 patch.object(sc.subprocess, "run", side_effect=remote)) as call:
                sc.enroll_public_key()
                self.assertEqual(call.call_count, 1)
                self.assertGreaterEqual(active["calls"], 3)

    def test_invalid_host_key_does_not_commit_even_with_supplied_fingerprint(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            paths, key, data = self.fixture(stack, Path(d))
            def inconsistent(args, **kwargs):
                if args[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(args, 0, data["8.8.8.8"][0], "")
                if args[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(args, 0, f"256 {data['9.9.9.9'][1]} host\n", "")
                self.fail("unexpected command")
            with patch.object(sc, "run", side_effect=inconsistent):
                with self.assertRaisesRegex(sc.ConnectError, "does not match the scanned host key"):
                    sc.configure("8.8.8.8", "root", 56777, str(key), data["9.9.9.9"][1])
            self.assertFalse(paths["CONF"].exists())
            self.assertFalse(paths["SSH_CONF"].exists())
            self.assertFalse(paths["KNOWN_HOSTS"].exists())


if __name__ == "__main__":
    unittest.main()
