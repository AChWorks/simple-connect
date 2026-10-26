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

    def host_record(self, key: Path, ip: str, port: int) -> tuple[str, str]:
        fields = Path(str(key) + ".pub").read_text().split()
        label = ip if port == 22 else f"[{ip}]:{port}"
        line = f"{label} {fields[0]} {fields[1]}\n"
        fp = sc.pinned_host_identity({"remote_ip": ip, "ssh_port": port}, line.encode())
        return line, fp

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

    def test_select_identity_never_generates_on_blank_or_negative_consent(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / ".ssh" / "simple_connect_ed25519"
            with (
                patch.object(sc, "KEY_PATH", key),
                patch.object(sc, "require_root"),
                patch.object(sc.sys, "stdin", TTY()),
                patch.object(sc, "create_dedicated_key") as generator,
            ):
                for answer in ("", "n", "no", "back"):
                    with self.subTest(answer=answer):
                        with patch("builtins.input", side_effect=["", answer, "b"]), (
                             contextlib.redirect_stdout(io.StringIO())):
                            with self.assertRaisesRegex(sc.ConnectError, "cancelled"):
                                sc.select_identity(None)
                        generator.assert_not_called()
                        self.assertFalse(key.exists())
                with self.assertRaisesRegex(sc.ConnectError, "Identity file"):
                    sc.select_identity(str(Path(d) / "missing"))
                generator.assert_not_called()

    def test_select_identity_explicit_yes_creates_only_dedicated_key(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / ".ssh" / "simple_connect_ed25519"
            alternate_missing = Path(d) / "another-missing-key"
            with (
                patch.object(sc, "KEY_PATH", key),
                patch.object(sc, "require_root"),
                patch.object(sc.sys, "stdin", TTY()),
                patch("builtins.input", side_effect=[str(alternate_missing), "y"]),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                self.assertEqual(sc.select_identity(None), str(key))
            self.assertTrue(key.is_file())
            self.assertTrue(Path(str(key) + ".pub").is_file())
            self.assertFalse(alternate_missing.exists())
            self.assertIn("will NOT be created", out.getvalue())
            data = key.read_bytes()
            with patch.object(sc, "require_root"), patch.object(sc, "KEY_PATH", key):
                with self.assertRaisesRegex(sc.ConnectError, "already exists"):
                    sc.create_dedicated_key()
            self.assertEqual(key.read_bytes(), data)

    def test_pasted_key_material_and_bad_paths_cannot_offer_generation(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / ".ssh" / "simple_connect_ed25519"
            with (
                patch.object(sc, "KEY_PATH", key),
                patch.object(sc.sys, "stdin", TTY()),
                patch.object(sc, "create_dedicated_key") as generator,
                patch.object(sc, "yes_no", side_effect=AssertionError("Invalid input asked for key generation")),
            ):
                for invalid in (FP, "ssh-ed25519 AAAA forged", "ssh-rsa AAAA",
                                "-----BEGIN OPENSSH PRIVATE KEY-----",
                                "-----BEGIN RSA PRIVATE KEY-----", "./missing",
                                "missing", "../relative", "/tmp/../bad"):
                    with self.subTest(invalid=invalid), (
                         patch("builtins.input", side_effect=[invalid, "b"])), (
                         contextlib.redirect_stdout(io.StringIO())):
                        with self.assertRaisesRegex(sc.ConnectError, "cancelled"):
                            sc.select_identity(None)
                    generator.assert_not_called()
                    self.assertFalse(key.exists())

    def test_invalid_input_retry_selects_existing_key_without_generation(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            existing = self.make_key(folder)
            new = folder / ".ssh" / "simple_connect_ed25519"
            with (
                patch.object(sc, "KEY_PATH", new),
                patch.object(sc.sys, "stdin", TTY()),
                patch("builtins.input", side_effect=["./missing", FP, "ssh-ed25519 AAAA", str(existing)]),
                patch.object(sc, "create_dedicated_key") as generator,
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                self.assertEqual(sc.select_identity(None), str(existing))
                generator.assert_not_called()
            self.assertIn("SERVER fingerprint", out.getvalue())
            self.assertFalse(new.exists())

    def test_server_fingerprint_pasted_as_client_path_is_rejected_and_recoverable(self):
        with self.assertRaisesRegex(sc.ConnectError, "SERVER host fingerprint"):
            sc.checked_key_name(FP)
        with self.assertRaisesRegex(sc.ConnectError, "PUBLIC key text"):
            sc.checked_key_name("ssh-ed25519 AAAA")
        with tempfile.TemporaryDirectory() as d:
            key = self.make_key(Path(d))
            with (
                patch.object(sc, "KEY_PATH", key),
                patch.object(sc.sys, "stdin", TTY()),
                patch("builtins.input", side_effect=[FP, str(key)]),
                patch.object(sc, "create_dedicated_key") as generate,
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                selected = sc.select_identity(None)
            self.assertEqual(selected, str(key))
            generate.assert_not_called()
            self.assertIn("step 5", out.getvalue())
            self.assertIn("CLIENT file path", out.getvalue())
            self.assertIn("SERVER fingerprint", out.getvalue())

    def test_cli_private_path_fingerprint_mistake_fails_without_generation(self):
        with patch.object(sc, "create_dedicated_key") as generate:
            with self.assertRaisesRegex(sc.ConnectError, "SERVER host fingerprint"):
                sc.select_identity(FP)
            generate.assert_not_called()

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
            host_record, host_fp = self.host_record(self.make_key(root, "host_key"), "8.8.8.8", 22022)
            etc = root / "etc"
            etc.mkdir()
            active = {"held": False, "count": 0}
            def mock_run(argv, **kwargs):
                self.assertFalse(active["held"], "I/O performed under manager lock")
                if argv[0] == "ssh-keyscan":
                    self.assertEqual(argv[-1], "8.8.8.8")
                    self.assertIn("22022", argv)
                    return subprocess.CompletedProcess(argv, 0, host_record, "")
                if argv[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(argv, 0,
                        "256 " + host_fp + " remote (ED25519)\n", "")
                self.fail(f"unexpected command: {argv}")
            def prompt(_):
                self.assertFalse(active["held"], "input under manager lock")
                return next(values)
            values = iter(["8.8.8.8", "root", "22022", str(key), host_fp, "n", "n"])
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
            host_record, host_fp = self.host_record(self.make_key(root, "host_key"), "8.8.8.8", 22022)
            etc = root / "etc"
            etc.mkdir()
            def mock_run(argv, **kwargs):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, host_record, "")
                return subprocess.CompletedProcess(argv, 0, "256 " + host_fp + " host\n", "")
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
                 patch.object(sc, "read_json", return_value={"status": "DIRECT"})), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc.subprocess, "run")) as remote:
                with self.assertRaisesRegex(sc.ConnectError, "Trusted SSH host key missing"):
                    sc.enroll_public_key()
                remote.assert_not_called()

    def test_enrollment_uses_selected_host_port_username_and_strict_host_key(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = self.make_key(root, "key")
            record, host_fp = self.host_record(self.make_key(root, "host_key"), "8.8.8.8", 56777)
            known = root / "known_hosts"
            known.write_text(record)
            pub = Path(str(key) + ".pub")
            cfg = {"identity_file": str(key), "ssh_user": "root",
                   "ssh_port": 56777, "remote_ip": "8.8.8.8"}
            observed = {}
            def remote_action(args, **kwargs):
                observed["args"] = list(args)
                stage_pub = Path(args[args.index("-i") + 1])
                host_arg = next(a for a in args if a.startswith("UserKnownHostsFile="))
                stage_hosts = Path(host_arg.partition("=")[2])
                self.assertNotEqual(stage_pub, pub)
                self.assertNotEqual(stage_hosts, known)
                self.assertEqual(sc.read_public_key_record(stage_pub), sc.read_public_key_record(pub))
                self.assertEqual(stage_hosts.read_text(), record)
                self.assertTrue(Path(str(stage_pub)[:-4]).is_file())
                return subprocess.CompletedProcess(args, 0, "", "")
            def mock_run(args, **kwargs):
                self.assertEqual(args[0], "ssh-keygen")
                return subprocess.CompletedProcess(args, 0, pub.read_text(), "")
            with patch.object(sc, "KNOWN_HOSTS", known), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "require_client_role")), (
                 patch.object(sc, "require_no_teardown")), (
                 patch.object(sc, "read_config", return_value=cfg)), (
                 patch.object(sc, "read_json", return_value={"status": "DIRECT"})), (
                 patch.object(sc, "locked", return_value=contextlib.nullcontext())), (
                 patch.object(sc, "service_terminated", return_value=True)), (
                 patch.object(sc, "any_proxy_tables", return_value=False)), (
                 patch.object(sc, "run", side_effect=mock_run)), (
                 patch.object(sc.sys, "stdin", TTY())), (
                 patch("builtins.input", return_value="y")), (
                 patch.object(sc.subprocess, "run", side_effect=remote_action)) as remote:
                sc.enroll_public_key()
            args = observed["args"]
            self.assertEqual(remote.call_count, 1)
            self.assertEqual(args[0], "/usr/bin/ssh-copy-id")
            self.assertEqual(args[-1], "root@8.8.8.8")
            self.assertEqual(args[args.index("-p") + 1], "56777")
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("GlobalKnownHostsFile=/dev/null", args)
            self.assertIn("UpdateHostKeys=no", args)
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
            host_record, host_fp = self.host_record(self.make_key(root, "host_key"), "8.8.8.8", 22)
            etc = root / "etc"
            etc.mkdir()
            prior = etc / "config.json"
            prior.write_bytes(b"existing content unchanged\n")
            def fake_run(argv, **kwargs):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, host_record, "")
                return subprocess.CompletedProcess(argv, 0, "256 " + host_fp + " host\n", "")
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
                    sc.configure("8.8.8.8", "root", 22, str(key), host_fp)
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


    def test_narrow_key_path_prompt_wraps_and_keeps_back_navigation(self):
        with patch.object(sc.shutil, "get_terminal_size",
                          return_value=os.terminal_size((40, 24))), (
             patch.object(sc.sys, "stdin", TTY())), (
             patch("builtins.input", return_value="b")), (
             contextlib.redirect_stdout(io.StringIO())) as output:
            with self.assertRaisesRegex(sc.ConnectError, "Setup cancelled"):
                sc.ask(None, "4/5 CLIENT private key FILE path",
                       "/root/.ssh/simple_connect_ed25519")
        self.assertIn("CLIENT private key FILE path", output.getvalue())
        self.assertTrue(all(len(row) <= 39 for row in output.getvalue().splitlines()))


if __name__ == "__main__":
    unittest.main()
