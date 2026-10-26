"""Hermetic terminal UX and SSH onboarding regressions (no real remote/host mutation)."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc


FP = "SHA256:" + "A" * 43


class TTY:
    def isatty(self):
        return True


class TerminalBuffer(io.StringIO):
    def isatty(self):
        return True


class CliOnboardingTests(unittest.TestCase):
    def make_key(self, directory: Path, name: str = "dedicated") -> Path:
        key = directory / name
        result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                                 "-N", "", "-f", str(key)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return key

    def test_key_directory_permissions_require_operator_consent(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / ".ssh"
            folder.mkdir(mode=0o755)
            folder.chmod(0o755)  # mkdtemp's restrictive umask may mask mkdir mode.
            key = folder / "simple_connect_ed25519"
            with patch.object(sc, "KEY_PATH", key), patch.object(sc, "require_root"), (
                 patch.object(sc.sys, "stdin", TTY())):
                with patch("builtins.input", return_value="n"):
                    with self.assertRaisesRegex(sc.ConnectError, "cancelled"):
                        sc.create_dedicated_key()
                self.assertFalse(key.exists())
                self.assertEqual(folder.stat().st_mode & 0o777, 0o755)
                with patch("builtins.input", return_value="y"):
                    sc.create_dedicated_key()
                self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_managed_key_generation_has_no_overwrite_and_no_remote_action(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / ".ssh" / "simple_connect_ed25519"
            with patch.object(sc, "KEY_PATH", key), patch.object(sc, "require_root"):
                result = sc.create_dedicated_key()
                self.assertEqual(result, key)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                self.assertEqual(key.parent.stat().st_mode & 0o777, 0o700)
                self.assertTrue((key.parent / (key.name + ".pub")).is_file())
                expected = key.read_bytes()
                with self.assertRaisesRegex(sc.ConnectError, "already exists"):
                    sc.create_dedicated_key()
                self.assertEqual(key.read_bytes(), expected)
                self.assertEqual(sc.validated_public_key(key), Path(str(key) + ".pub"))

    def test_unsafe_private_key_permissions_symlinks_and_mismatched_pub(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = self.make_key(root)
            key.chmod(0o644)
            with self.assertRaisesRegex(sc.ConnectError, "permissions"):
                sc.private_key_path(str(key))
            key.chmod(0o600)
            alias = root / "alias"
            alias.symlink_to(key)
            with self.assertRaisesRegex(sc.ConnectError, "symlink"):
                sc.private_key_path(str(alias))
            aliased_parent = root / "linked-dir"
            aliased_parent.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(sc.ConnectError, "symlink"):
                sc.private_key_path(str(aliased_parent / "dedicated"))
            pub = Path(str(key) + ".pub")
            other = self.make_key(root, "different")
            pub.write_bytes(Path(str(other) + ".pub").read_bytes())
            with self.assertRaisesRegex(sc.ConnectError, "does not match"):
                sc.validated_public_key(key)

    def test_select_identity_may_generate_only_on_explicit_interactive_confirmation(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / ".ssh" / "simple_connect_ed25519"
            with patch.object(sc, "KEY_PATH", key), patch.object(sc, "require_root"):
                with patch.object(sc.sys, "stdin", TTY()), patch("builtins.input", side_effect=["", ""]):
                    self.assertEqual(sc.select_identity(None), str(key))
                self.assertTrue(key.is_file())
                with patch.object(sc, "create_dedicated_key") as generator:
                    with self.assertRaisesRegex(sc.ConnectError, "Identity file"):
                        sc.select_identity(str(Path(d) / "missing"))
                    generator.assert_not_called()

    def test_invalid_field_retries_without_kicking_out_of_wizard(self):
        with patch.object(sc.sys, "stdin", TTY()), patch(
            "builtins.input", side_effect=["not-an-ip", "127.0.0.1", "8.8.8.8"]
        ):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                value = sc.checked_field(None, "Remote public IPv4", None,
                                         lambda x: sc.validate_ipv4(x, public=True))
            self.assertEqual(value, "8.8.8.8")
            self.assertIn("[ERROR]", out.getvalue())

    def test_invalid_field_does_not_retry_in_noninteractive_mode(self):
        with patch.object(sc.sys, "stdin", SimpleNamespace(isatty=lambda: False)):
            with self.assertRaises(sc.ConnectError):
                sc.checked_field("invalid", "Remote public IPv4", None,
                                 lambda x: sc.validate_ipv4(x, public=True))

    @contextlib.contextmanager
    def fake_locks(self, active):
        self.assertFalse(active["held"])
        active["held"] = True
        active["count"] += 1
        try:
            yield
        finally:
            active["held"] = False

    def test_configure_prompts_unlocked_and_pins_only_verified_remote(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = self.make_key(root)
            etc = root / "etc"
            etc.mkdir()
            active = {"held": False, "count": 0}
            def mock_run(argv, **kwargs):
                self.assertFalse(active["held"], "I/O performed under manager lock")
                if argv[0] == "ssh-keyscan":
                    self.assertEqual(argv[-1], "8.8.8.8")
                    self.assertIn("22022", argv)
                    return subprocess.CompletedProcess(argv, 0,
                        "[8.8.8.8]:22022 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCK\n", "")
                if argv[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(argv, 0,
                        "256 " + FP + " remote (ED25519)\n", "")
                self.fail(f"unexpected command: {argv}")
            def prompt(_):
                self.assertFalse(active["held"], "input under manager lock")
                return next(values)
            values = iter(["8.8.8.8", "root", "22022", str(key), FP, "n", "n"])
            with patch.object(sc, "ETC", etc), patch.object(sc, "KNOWN_HOSTS", etc / "known_hosts"), (
                 patch.object(sc, "SSH_CONF", etc / "ssh_config")), (
                 patch.object(sc, "CONF", etc / "config.json")), (
                 patch.object(sc, "STATE", root / "state.json")), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc, "read_json", return_value={"status": "DIRECT"})), (
                 patch.object(sc, "locked", side_effect=lambda **_: self.fake_locks(active))), (
                 patch.object(sc, "run", side_effect=mock_run)), (
                 patch.object(sc.sys, "stdin", TTY())), (
                 patch("builtins.input", side_effect=prompt)):
                sc.configure(None, None, None, None, None)
            self.assertEqual(active["count"], 2)
            cfg = json.loads((etc / "config.json").read_text())
            self.assertEqual(cfg["ssh_port"], 22022)
            self.assertEqual(cfg["identity_file"], str(key))
            self.assertIn("StrictHostKeyChecking yes", (etc / "ssh_config").read_text())
            self.assertIn("UserKnownHostsFile", (etc / "ssh_config").read_text())
            self.assertIn("ssh-ed25519", (etc / "known_hosts").read_text())

    def test_fingerprint_mismatch_never_saves_known_hosts_or_config(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = self.make_key(root)
            etc = root / "etc"
            etc.mkdir()
            def mock_run(argv, **kwargs):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, "8.8.8.8 ssh-ed25519 AAAAKEY\n", "")
                return subprocess.CompletedProcess(argv, 0, "256 " + FP + " host\n", "")
            with patch.object(sc, "ETC", etc), patch.object(sc, "KNOWN_HOSTS", etc / "known_hosts"), (
                 patch.object(sc, "SSH_CONF", etc / "ssh_config")), (
                 patch.object(sc, "CONF", etc / "config.json")), (
                 patch.object(sc, "STATE", root / "state.json")), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc, "read_json", return_value={"status": "DIRECT"})), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "run", side_effect=mock_run)):
                with self.assertRaisesRegex(sc.ConnectError, "Fingerprint mismatch"):
                    sc.configure("8.8.8.8", "root", 22022, str(key), "SHA256:" + "B" * 43)
            self.assertEqual(list(etc.iterdir()), [])

    def test_enrollment_rejects_untrusted_remote_before_subprocess(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "no-known-hosts"
            with patch.object(sc, "KNOWN_HOSTS", path), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "read_config", return_value={"identity_file": "/any/key"})), (
                 patch.object(sc.subprocess, "run")) as remote:
                with self.assertRaisesRegex(sc.ConnectError, "Trusted SSH host key missing"):
                    sc.enroll_public_key()
                remote.assert_not_called()

    def test_enrollment_uses_selected_host_port_username_and_strict_host_key(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            known = root / "known_hosts"
            known.write_text("[8.8.8.8]:56777 ssh-ed25519 AAAAKEY\n")
            key = self.make_key(root, "key")
            pub = Path(str(key) + ".pub")
            cfg = {"identity_file": str(key), "ssh_user": "root",
                   "ssh_port": 56777, "remote_ip": "8.8.8.8"}
            with patch.object(sc, "KNOWN_HOSTS", known), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "read_config", return_value=cfg)), (
                 patch.object(sc, "read_json", return_value={"status": "DIRECT"})), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc, "validated_public_key", return_value=pub)), (
                 patch.object(sc.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, "", ""))) as remote:
                sc.enroll_public_key()
            args = remote.call_args.args[0]
            self.assertEqual(args[0], "/usr/bin/ssh-copy-id")
            self.assertEqual(args[-1], "root@8.8.8.8")
            self.assertEqual(args[args.index("-p") + 1], "56777")
            self.assertEqual(args[args.index("-i") + 1], str(pub))
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("UserKnownHostsFile=" + str(known), args)
            self.assertEqual(remote.call_args.kwargs["timeout"], 180)
            self.assertNotIn("sshpass", args)

    def test_enrollment_refuses_active_state_without_remote_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            known = Path(d) / "known_hosts"
            known.write_text("8.8.8.8 ssh-ed25519 AAAKEY\n")
            with patch.object(sc, "KNOWN_HOSTS", known), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "read_config", return_value={"ssh_user": "root",
                     "remote_ip": "8.8.8.8", "ssh_port": 22, "identity_file": "/unused"})), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "read_json", return_value={"status": "ACTIVE"})), (
                 patch.object(sc, "service_terminated", return_value=False)), (
                 patch.object(sc.subprocess, "run")) as remote:
                with self.assertRaisesRegex(sc.ConnectError, "DIRECT/OFF"):
                    sc.enroll_public_key()
                remote.assert_not_called()

    def test_menu_snapshot_displays_real_role_state_ip_and_remote_without_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            etc = Path(d) / "etc"
            etc.mkdir()
            (etc / "role").write_text("client\n")
            key = self.make_key(Path(d))
            state = Path(d) / "state.json"
            sc.write_json(state, {"status": "DIRECT"})
            conf = etc / "config.json"
            sc.write_json(conf, {"remote_ip": "8.8.8.8", "ssh_user": "root",
                                 "ssh_port": 56777, "identity_file": str(key)})
            ip = subprocess.CompletedProcess([], 0,
                json.dumps([{"ifname": "eth0", "addr_info":
                    [{"family": "inet", "local": "198.51.100.15"}]}]), "")
            with patch.object(sc, "ETC", etc), patch.object(sc, "STATE", state), (
                 patch.object(sc, "CONF", conf)), (
                 patch.object(sc, "is_active", side_effect=lambda u: u == sc.GUARD_TIMER)), (
                 patch.object(sc.shutil, "which", return_value=None)), (
                 patch.object(sc.subprocess, "run", return_value=ip)):
                snapshot = sc.menu_snapshot()
            self.assertEqual(snapshot["role"], "CLIENT")
            self.assertEqual(snapshot["state"], "DIRECT")
            self.assertEqual(snapshot["service"], "STOPPED")
            self.assertEqual(snapshot["guard"], "RUNNING")
            self.assertEqual(snapshot["remote"], "root@8.8.8.8:56777")
            self.assertEqual(snapshot["key"], f"PRESENT: {key} (login untested)")
            self.assertIn("198.51.100.15", snapshot["local"])

    def test_direct_state_with_running_service_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            etc = Path(d) / "etc"
            etc.mkdir()
            (etc / "role").write_text("client\n")
            state = Path(d) / "state.json"
            sc.write_json(state, {"status": "DIRECT"})
            with patch.object(sc, "ETC", etc), patch.object(sc, "STATE", state), (
                 patch.object(sc, "is_active", return_value=True)), (
                 patch.object(sc.shutil, "which", return_value=None)), (
                 patch.object(sc.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 1, "", ""))):
                snap = sc.menu_snapshot()
            self.assertIn("State says DIRECT but proxy service runs", snap["note"])

    def test_tty_color_and_clear_respect_no_color_and_redirected_stdout(self):
        with patch.dict(os.environ, {"TERM": "xterm"}, clear=True), (
             patch.object(sc.sys, "stdout", TerminalBuffer())) as tty:
            self.assertIn("\033[", sc.paint("READY", "good"))
            sc.clear_menu()
            self.assertIn("\033[2J", tty.getvalue())
        with patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": "1"}, clear=True), (
             patch.object(sc.sys, "stdout", TerminalBuffer())) as tty:
            self.assertEqual(sc.paint("READY", "good"), "READY")
            sc.clear_menu()
            self.assertIn("\033[2J", tty.getvalue())  # Clearing is independent of NO_COLOR.
        with patch.dict(os.environ, {"TERM": "xterm"}, clear=True), (
             contextlib.redirect_stdout(io.StringIO())) as plain:
            self.assertEqual(sc.paint("READY", "good"), "READY")
            sc.clear_menu()
            self.assertEqual(plain.getvalue(), "")

    def test_menu_bad_option_and_action_error_return_to_menu(self):
        result = io.StringIO()
        with patch.object(sc.sys, "stdin", TTY()), (
             patch("builtins.input", side_effect=["not-a-choice", "", "3", "", "0"])), (
             patch.object(sc, "menu_header")), (
             patch.object(sc, "clear_menu")), (
             patch.object(sc, "configure", side_effect=sc.ConnectError("Identity file missing"))), (
             contextlib.redirect_stdout(result)):
            sc.menu()
        text = result.getvalue()
        self.assertIn("Invalid option", text)
        self.assertIn("Identity file missing", text)
        self.assertIn("Next:", text)

    def test_menu_keyboard_interrupt_keeps_interactive_shell_alive(self):
        result = io.StringIO()
        with patch.object(sc.sys, "stdin", TTY()), (
             patch("builtins.input", side_effect=[KeyboardInterrupt, "", "0"])), (
             patch.object(sc, "menu_header")), (
             patch.object(sc, "clear_menu")), (
             contextlib.redirect_stdout(result)):
            sc.menu()
        self.assertIn("Operation interrupted", result.getvalue())

    def test_bootstrap_uses_persistent_tty_menu_after_setup(self):
        script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        self.assertIn('while [[ -z "$role" ]]', script)
        self.assertIn('printf \'[WARN] Choose 1, 2 or 0.', script)
        self.assertIn('/usr/bin/python3 "$temp/simple_connect.py" setup "$role"', script)
        self.assertIn('/usr/bin/python3 "$temp/simple_connect.py" <&3', script)
        self.assertIn('else\n    /usr/bin/python3 "$temp/simple_connect.py" setup', script)

    def test_public_half_can_be_recovered_without_exposing_private_key(self):
        with tempfile.TemporaryDirectory() as d:
            key = self.make_key(Path(d))
            pub = Path(str(key) + ".pub")
            pub.unlink()
            contents = key.read_bytes()
            recovered = sc.validated_public_key(key)
            self.assertEqual(recovered, pub)
            self.assertTrue(pub.read_text().startswith("ssh-ed25519 "))
            self.assertEqual(pub.stat().st_mode & 0o777, 0o644)
            self.assertEqual(key.read_bytes(), contents)

    def test_header_shows_incomplete_when_config_has_no_usable_key(self):
        snapshot = {"role": "CLIENT", "state": "DIRECT", "service": "STOPPED",
                    "guard": "RUNNING", "remote": "root@8.8.8.8:56777",
                    "key": "MISSING/UNSAFE", "local": "192.0.2.5", "note": ""}
        with patch.object(sc, "menu_snapshot", return_value=snapshot), (
             contextlib.redirect_stdout(io.StringIO())) as out:
            sc.menu_header()
        text = out.getvalue()
        self.assertIn("SSH configured: INCOMPLETE", text)
        self.assertIn("MISSING/UNSAFE", text)
        self.assertNotIn("SSH configured: YES", text)

    def test_active_without_table_fingerprint_never_looks_verified(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            etc = root / "etc"
            etc.mkdir()
            (etc / "role").write_text("client\n")
            key = self.make_key(root)
            sc.write_json(root / "state.json", {"status": "ACTIVE"})
            sc.write_json(etc / "config.json", {
                "remote_ip": "8.8.8.8", "ssh_user": "root",
                "ssh_port": 56777, "identity_file": str(key)})
            with patch.object(sc, "ETC", etc), (
                 patch.object(sc, "STATE", root / "state.json")), (
                 patch.object(sc, "CONF", etc / "config.json")), (
                 patch.object(sc, "is_active", return_value=True)), (
                 patch.object(sc.shutil, "which", return_value="/usr/sbin/nft")), (
                 patch.object(sc, "current_table", return_value={"nftables": []})), (
                 patch.object(sc, "table_is_ours")) as owned, (
                 patch.object(sc.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", ""))):
                result = sc.menu_snapshot()
            self.assertEqual(result["state"], "ACTIVE")
            self.assertIn("ownership/identity not verified", result["note"])
            owned.assert_not_called()

    def test_active_missing_ssh_config_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            etc = root / "etc"
            etc.mkdir()
            (etc / "role").write_text("client\n")
            sc.write_json(root / "state.json", {"status": "ACTIVE"})
            with patch.object(sc, "ETC", etc), (
                 patch.object(sc, "STATE", root / "state.json")), (
                 patch.object(sc, "CONF", etc / "absent_config.json")), (
                 patch.object(sc, "is_active", return_value=True)), (
                 patch.object(sc.shutil, "which", return_value=None)), (
                 patch.object(sc.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 1, "", ""))):
                result = sc.menu_snapshot()
            self.assertIn("SSH configuration missing", result["note"])

    def test_unrecognized_state_is_never_displayed_as_healthy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            etc = root / "etc"
            etc.mkdir()
            (etc / "role").write_text("client\n")
            state = root / "state.json"
            sc.write_json(state, {"status": "\033[2JACTIVE"})
            with patch.object(sc, "ETC", etc), patch.object(sc, "STATE", state), (
                 patch.object(sc, "is_active", return_value=False)), (
                 patch.object(sc.shutil, "which", return_value=None)), (
                 patch.object(sc.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 1, "", ""))):
                result = sc.menu_snapshot()
            self.assertEqual(result["state"], "UNKNOWN")
            self.assertIn("Unrecognized state marker", result["note"])
            self.assertNotIn("\033", result["note"])

    def test_stale_direct_state_at_save_gate_preserves_existing_config(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = self.make_key(root)
            etc = root / "etc"
            etc.mkdir()
            prior = etc / "config.json"
            prior.write_bytes(b"existing content unchanged\n")
            def fake_run(argv, **kwargs):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, "8.8.8.8 ssh-ed25519 AAAAPIN\n", "")
                return subprocess.CompletedProcess(argv, 0, "256 " + FP + " host\n", "")
            with patch.object(sc, "ETC", etc), (
                 patch.object(sc, "KNOWN_HOSTS", etc / "known_hosts")), (
                 patch.object(sc, "SSH_CONF", etc / "ssh_config")), (
                 patch.object(sc, "CONF", prior)), (
                 patch.object(sc, "STATE", root / "state.json")), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc, "read_json",
                              side_effect=[{"status": "DIRECT"}, {"status": "PENDING"}])), (
                 patch.object(sc, "run", side_effect=fake_run)):
                with self.assertRaisesRegex(sc.ConnectError, "Network state changed"):
                    sc.configure("8.8.8.8", "root", 22, str(key), FP)
            self.assertEqual(prior.read_bytes(), b"existing content unchanged\n")
            self.assertFalse((etc / "ssh_config").exists())
            self.assertFalse((etc / "known_hosts").exists())

    def test_ssh_access_menu_errors_return_to_submenu(self):
        output = io.StringIO()
        with patch.object(sc.sys, "stdin", TTY()), (
             patch("builtins.input", side_effect=["99", "", "1", "", "0"])), (
             patch.object(sc, "menu_header")), (
             patch.object(sc, "clear_menu")), (
             patch.object(sc, "enroll_public_key",
                          side_effect=sc.ConnectError("Public key enrollment failed: password authentication refused"))), (
             contextlib.redirect_stdout(output)):
            sc.ssh_access_menu()
        self.assertIn("Invalid choice", output.getvalue())
        self.assertIn("Public key enrollment failed", output.getvalue())
        self.assertIn("Next:", output.getvalue())

    def test_no_terminal_menu_returns_guided_nonzero_error(self):
        with patch.object(sc.sys, "stdin", SimpleNamespace(isatty=lambda: False)), (
             patch.object(sc.sys, "argv", ["simple_connect.py"])), (
             contextlib.redirect_stdout(io.StringIO())) as result:
            self.assertEqual(sc.main(), 1)
        self.assertIn("requires a terminal", result.getvalue())


if __name__ == "__main__":
    unittest.main()
