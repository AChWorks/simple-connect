"""Multi-algorithm SSH host identity and server-side read-only UI tests."""
import contextlib
import io
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc


class HostKeyTests(unittest.TestCase):
    def setUp(self):
        # CI runners need not have openssh-server installed. Only the one
        # canonical daemon's file identity is simulated; all host-key files
        # and ssh-keygen checks are real. Untrusted custom sshd paths remain
        # subject to their actual lstat metadata.
        original = os.lstat
        def controlled_lstat(path, *args, **kwargs):
            if os.fspath(path) == "/usr/sbin/sshd":
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            return original(path, *args, **kwargs)
        mocked = patch.object(sc.os, "lstat", side_effect=controlled_lstat)
        mocked.start()
        self.addCleanup(mocked.stop)

    def key(self, folder, name, kind, bits=None):
        path = folder / name
        args = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", str(path)]
        if bits:
            args.extend(["-b", str(bits)])
        p = subprocess.run(args, text=True, capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return path

    def record(self, key, ip="8.8.8.8", port=56777):
        kind, data = Path(str(key) + ".pub").read_text().split()[:2]
        label = ip if port == 22 else f"[{ip}]:{port}"
        row = f"{label} {kind} {data}\n".encode()
        return row, sc.pinned_host_identity({"remote_ip": ip, "ssh_port": port}, row)

    def test_host_key_wire_types_and_sha2_only_rsa(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            for kind, bits, suffix in (("ed25519", None, "ssh-ed25519"),
                                      ("ecdsa", 256, "ecdsa-sha2-nistp256"),
                                      ("ecdsa", 384, "ecdsa-sha2-nistp384"),
                                      ("ecdsa", 521, "ecdsa-sha2-nistp521"),
                                      ("rsa", 2048, "ssh-rsa")):
                with self.subTest(kind=kind, bits=bits):
                    path = self.key(folder, f"{kind}{bits}", kind, bits)
                    record, fp = self.record(path)
                    self.assertEqual(sc.pinned_host_type(record), suffix)
                    self.assertTrue(fp.startswith("SHA256:"))
                    alg = sc.host_key_signature_algorithms(suffix)
                    self.assertNotIn("ssh-rsa", alg.split(","))
                    if suffix == "ssh-rsa":
                        self.assertEqual(alg, "rsa-sha2-512,rsa-sha2-256")

    def test_wrong_host_type_multiple_records_and_dsa_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            r, _ = self.record(self.key(folder, "rsa", "rsa", 2048))
            for bad in [r + r, r.replace(b"ssh-rsa", b"ssh-dss"),
                        r.replace(b"ssh-rsa", b"ssh-ed25519"),
                        r.replace(b"[8.8.8.8]:56777", b"8.8.8.8")]:
                with self.subTest(bad=bad[:32]):
                    with self.assertRaises(sc.ConnectError):
                        sc.pinned_host_identity(
                            {"remote_ip": "8.8.8.8", "ssh_port": 56777}, bad)

    def test_multiple_secure_scan_options_match_only_trusted_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            rsa = self.key(folder, "rsa", "rsa", 2048)
            ed = self.key(folder, "ed", "ed25519")
            ecdsa = self.key(folder, "ec", "ecdsa", 256)
            rows = [self.record(k)[0].decode() for k in (rsa, ed, ecdsa)]
            original = sc.run
            def mock_run(args, **kw):
                if args[0] == "ssh-keyscan":
                    self.assertEqual(args[args.index("-t") + 1], "ed25519,ecdsa,rsa")
                    return subprocess.CompletedProcess(args, 0, "".join(rows), "")
                return original(args, **kw)
            with patch.object(sc, "run", side_effect=mock_run):
                offered = sc.scanned_host_identities("8.8.8.8", 56777)
            self.assertEqual([r[0] for r in offered],
                             ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"])
            self.assertEqual([r[2] for r in offered],
                             [self.record(k)[1] for k in (ed, ecdsa, rsa)])

    def test_unavailable_and_ambiguous_scans_fail_closed(self):
        with patch.object(sc, "run", return_value=subprocess.CompletedProcess([], 1, "", "connection refused")):
            with self.assertRaisesRegex(sc.ConnectError, "No supported SSH host key"):
                sc.scanned_host_identities("8.8.8.8", 23001)
        with tempfile.TemporaryDirectory() as d:
            host = self.key(Path(d), "ed", "ed25519")
            row = self.record(host)[0].decode()
            actual = sc.run
            def scan_only(argv, **kwargs):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, row + row, "")
                return actual(argv, **kwargs)
            with patch.object(sc, "run", side_effect=scan_only):
                with self.assertRaisesRegex(sc.ConnectError, "Duplicate SSH host key"):
                    sc.scanned_host_identities("8.8.8.8", 56777)

    def test_scan_rejects_short_rsa_even_if_sha2_supported(self):
        with tempfile.TemporaryDirectory() as d:
            key = self.key(Path(d), "rsa1024", "rsa", 1024)
            record, _ = self.record(key)
            original = sc.run
            def fake(argv, **kw):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, record.decode(), "")
                return original(argv, **kw)
            with patch.object(sc, "run", side_effect=fake):
                with self.assertRaisesRegex(sc.ConnectError, "shorter than 2048"):
                    sc.scanned_host_identities("8.8.8.8", 56777)

    def test_configure_rsa_and_ecdsa_pins_one_key_and_safe_signature(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            etc = folder / "etc"
            etc.mkdir()
            client = self.key(folder, "client", "ed25519")
            for kind, bits, text in (("rsa", 2048, "rsa-sha2-512,rsa-sha2-256"),
                                     ("ecdsa", 256, "ecdsa-sha2-nistp256")):
                with self.subTest(kind=kind):
                    host = self.key(folder, f"host-{kind}", kind, bits)
                    row, fp = self.record(host)
                    original = sc.run
                    def fake(argv, **kw):
                        if argv[0] == "ssh-keyscan":
                            return subprocess.CompletedProcess(argv, 0, row.decode(), "")
                        return original(argv, **kw)
                    # File snapshots remain locked even in noninteractive setup.
                    with contextlib.ExitStack() as st:
                        for key, path in (("ETC", etc), ("CONF", etc/"config.json"),
                                          ("SSH_CONF", etc/"ssh_config"),
                                          ("KNOWN_HOSTS", etc/"known_hosts")):
                            st.enter_context(patch.object(sc, key, path))
                        for name in ("require_root", "require_no_teardown", "require_client_role"):
                            st.enter_context(patch.object(sc, name))
                        st.enter_context(patch.object(sc, "locked", return_value=contextlib.nullcontext()))
                        st.enter_context(patch.object(sc, "service_terminated", return_value=True))
                        st.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))
                        st.enter_context(patch.object(sc, "read_json", return_value={"status": "DIRECT"}))
                        st.enter_context(patch.object(sc, "run", side_effect=fake))
                        with contextlib.redirect_stdout(io.StringIO()):
                            sc.configure("8.8.8.8", "root", 56777, str(client), fp)
                        self.assertEqual((etc/"known_hosts").read_bytes(), row)
                        sshcfg = (etc/"ssh_config").read_text()
                        self.assertIn(f"HostKeyAlgorithms {text}", sshcfg)
                        self.assertIn("StrictHostKeyChecking yes", sshcfg)
                        self.assertIn("GlobalKnownHostsFile /dev/null", sshcfg)
                        self.assertIn("UpdateHostKeys no", sshcfg)

    def test_rsa_fingerprint_mismatch_does_not_replace_previous_identity(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            host = self.key(folder, "rsa", "rsa", 2048)
            client = self.key(folder, "client", "ed25519")
            row, fp = self.record(host)
            etc = folder / "etc"
            etc.mkdir()
            prior = etc / "config.json"
            prior.write_text("prior config")
            original = sc.run
            def fake(argv, **kw):
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 0, row.decode(), "")
                return original(argv, **kw)
            with contextlib.ExitStack() as st:
                for name, path in (("ETC", etc), ("CONF", prior), ("SSH_CONF", etc/"ssh_config"),
                                   ("KNOWN_HOSTS", etc/"known_hosts")):
                    st.enter_context(patch.object(sc, name, path))
                for name in ("require_root", "require_no_teardown", "require_client_role"):
                    st.enter_context(patch.object(sc, name))
                st.enter_context(patch.object(sc, "locked", return_value=contextlib.nullcontext()))
                st.enter_context(patch.object(sc, "service_terminated", return_value=True))
                st.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))
                st.enter_context(patch.object(sc, "read_json", return_value={"status": "DIRECT"}))
                st.enter_context(patch.object(sc, "run", side_effect=fake))
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(sc.ConnectError, "Fingerprint mismatch"):
                        sc.configure("8.8.8.8", "root", 56777, str(client),
                                     "SHA256:" + "A" * 43)
            self.assertEqual(prior.read_text(), "prior config")
            self.assertFalse((etc/"known_hosts").exists())

    def test_server_details_are_read_only_and_distinguish_config_from_listener(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            role = folder / "role"
            role.write_text("server\n")
            rsa = self.key(folder, "host", "rsa", 2048)
            pub = Path(str(rsa) + ".pub")
            daemon_config = (f"port 22222\nhostkey {rsa}\n"
                             "hostkeyalgorithms rsa-sha2-512,rsa-sha2-256\n")
            calls = []
            original = sc.run
            def fake(argv, **kw):
                calls.append(argv)
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv, 0, daemon_config, "")
                if argv[0] == "ssh-keygen":
                    return original(argv, **kw)
                raise AssertionError(f"Unexpected command: {argv}")
            with patch.object(sc, "ETC", folder), (
                 patch.object(sc, "SSH_HOST_DIR", folder)), (
                 patch.object(sc.shutil, "which", return_value="/usr/sbin/sshd")), (
                 patch.object(sc, "is_active", return_value=True)), (
                 patch.object(sc, "run", side_effect=fake)):
                report = sc.server_host_report(probe=False)
                self.assertTrue(report["active"])
                self.assertEqual(report["ports"], [22222])
                self.assertEqual(report["keys"][0]["type"], "ssh-rsa")
                self.assertTrue(report["keys"][0]["enabled"])
                self.assertIn("UNVERIFIED", report["keys"][0]["status"])
                self.assertEqual(report["keys"][0]["private"], "PAIR MATCH")
                with patch.object(sc, "require_root"):
                    with contextlib.redirect_stdout(io.StringIO()) as out:
                        sc.show_server_host_fingerprints(probe=False)
                    self.assertIn(report["keys"][0]["fingerprint"], out.getvalue())
            self.assertEqual(len(calls), 6)
            self.assertTrue(pub.is_file())
            self.assertFalse(any(x[0] == "ssh-keyscan" for x in calls))

    def test_server_summary_prefers_copy_ready_ed25519_and_keeps_details_advanced(self):
        import os
        fp_ed = "SHA256:" + "E" * 43
        fp_rsa = "SHA256:" + "R" * 43
        report = {
            "active": True, "ports": [56777], "configured": True,
            "observed": [{"port": 56777, "identities": [
                {"type": "ssh-ed25519", "fingerprint": fp_ed},
                {"type": "ssh-rsa", "fingerprint": fp_rsa},
            ]}],
            "notes": [],
            "keys": [
                {"type": "ssh-rsa", "fingerprint": fp_rsa, "enabled": True,
                 "private": "PAIR MATCH", "path": "/etc/ssh/host_rsa.pub",
                 "status": "configured; listener unverified"},
                {"type": "ssh-ed25519", "fingerprint": fp_ed, "enabled": True,
                 "private": "PAIR MATCH", "path": "/etc/ssh/host_ed.pub",
                 "status": "observed on localhost"},
                {"type": "ssh-dss", "fingerprint": "", "enabled": False,
                 "private": "NOT VERIFIED", "path": "/etc/ssh/host_dsa.pub",
                 "status": "UNSUPPORTED (DSA)"},
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            role = Path(d) / "role"
            role.write_text("server\n")
            with (
                patch.object(sc, "ETC", Path(d)),
                patch.object(sc, "require_root"),
                patch.object(sc, "server_host_report", return_value=report),
                patch.object(sc.shutil, "get_terminal_size",
                             return_value=os.terminal_size((40, 24))),
            ):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    sc.show_server_host_fingerprints(probe=True)
                summary = out.getvalue()
                self.assertIn("ED25519", summary)
                self.assertIn("\n" + fp_ed + "\n", summary)
                self.assertNotIn(fp_rsa, summary)
                self.assertNotIn("host_dsa.pub", summary)
                self.assertIn("localhost port(s): 56777", summary)
                self.assertIn("UNVERIFIED", summary)
                for line in summary.splitlines():
                    if not line.startswith("SHA256:"):
                        self.assertLessEqual(len(line), 39, line)
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    sc.show_server_host_fingerprints(probe=True, advanced=True)
                detail = out.getvalue()
                self.assertIn(fp_rsa, detail)
                self.assertIn("ssh-dss", detail)
                self.assertIn("host_dsa.pub", detail)
                self.assertIn("UNSUPPORTED", detail)

    def test_server_summary_falls_back_to_configured_ecdsa_if_ed25519_is_unready(self):
        fp = "SHA256:" + "C" * 43
        report = {
            "active": True, "ports": [22022], "configured": True,
            "observed": [], "notes": [],
            "keys": [
                {"type": "ssh-ed25519", "fingerprint": "", "enabled": False,
                 "private": "MISSING", "path": "/etc/ssh/host_ed.pub",
                 "status": "HOST KEY NOT READY"},
                {"type": "ecdsa-sha2-nistp256", "fingerprint": fp, "enabled": True,
                 "private": "PAIR MATCH", "path": "/etc/ssh/host_ecdsa.pub",
                 "status": "configured; listener unverified"},
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "role").write_text("server\n")
            with patch.object(sc, "ETC", Path(d)), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "server_host_report", return_value=report)), (
                 contextlib.redirect_stdout(io.StringIO())) as out:
                sc.show_server_host_fingerprints(probe=False)
        self.assertIn("ECDSA (ecdsa-sha2-nistp256)", out.getvalue())
        self.assertIn(fp, out.getvalue())
        self.assertIn("other host key(s)", out.getvalue())
        self.assertNotIn("SSH listener READY", out.getvalue())

    def test_server_summary_with_no_safe_identity_never_suggests_unsupported_key(self):
        report = {
            "active": False, "ports": [], "configured": False,
            "observed": [], "notes": ["sshd config unavailable"],
            "keys": [{"type": "ssh-dss", "fingerprint": "", "enabled": False,
                      "private": "MISSING", "path": "/etc/ssh/host_dsa.pub",
                      "status": "UNSUPPORTED (DSA)"}],
        }
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "role").write_text("server\n")
            with patch.object(sc, "ETC", Path(d)), (
                 patch.object(sc, "require_root")), (
                 patch.object(sc, "server_host_report", return_value=report)), (
                 contextlib.redirect_stdout(io.StringIO())) as out:
                sc.show_server_host_fingerprints(probe=True)
        self.assertIn("NO SAFE SUPPORTED", out.getvalue())
        self.assertIn("NOT VERIFIED ACTIVE", out.getvalue())
        self.assertIn("port is unknown", out.getvalue())
        self.assertNotIn("Recommended SERVER host key:", out.getvalue())

    def test_rsa_enrollment_uses_sha2_only_and_frozen_known_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            etc = folder / "etc"
            etc.mkdir()
            role = etc/"role"
            role.write_text("client\n")
            client = self.key(folder, "client", "ed25519")
            remote = self.key(folder, "rsa", "rsa", 2048)
            record, fp = self.record(remote)
            (etc/"known_hosts").write_bytes(record)
            sc.write_json(etc/"config.json", {
                "remote_ip": "8.8.8.8", "ssh_user": "root",
                "ssh_port": 56777, "identity_file": str(client),
            })
            (etc/"ssh_config").write_text("host sc-remote\n")
            state = folder/"state.json"
            sc.write_json(state, {"status": "DIRECT"})
            snapshot = []
            original = subprocess.run
            def intercept(argv, **kwargs):
                if argv[0] != "/usr/bin/ssh-copy-id":
                    return original(argv, **kwargs)
                snapshot.append(argv)
                self.assertIn("HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256", argv)
                self.assertIn("StrictHostKeyChecking=yes", argv)
                self.assertNotIn("HostKeyAlgorithms=ssh-rsa", argv)
                kh_arg = next(a for a in argv if a.startswith("UserKnownHostsFile="))
                self.assertEqual(Path(kh_arg.split("=", 1)[1]).read_bytes(), record)
                return subprocess.CompletedProcess(argv, 0, "", "")
            with contextlib.ExitStack() as stack:
                for name, value in (
                    ("ETC", etc), ("CONF", etc/"config.json"), ("SSH_CONF", etc/"ssh_config"),
                    ("KNOWN_HOSTS", etc/"known_hosts"), ("STATE", state)):
                    stack.enter_context(patch.object(sc, name, value))
                for method in ("require_root", "require_client_role", "require_no_teardown"):
                    stack.enter_context(patch.object(sc, method))
                stack.enter_context(patch.object(sc, "service_terminated", return_value=True))
                stack.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))
                stack.enter_context(patch.object(sc, "locked", return_value=contextlib.nullcontext()))
                stack.enter_context(patch.object(sc, "yes_no", return_value=True))
                stack.enter_context(patch.object(sc.subprocess, "run", side_effect=intercept))
                with contextlib.redirect_stdout(io.StringIO()):
                    sc.enroll_public_key()
            self.assertEqual(len(snapshot), 1)

    def test_main_menu_is_one_numbered_action_per_line_at_40_columns(self):
        import os
        from types import SimpleNamespace
        class FakeTTY:
            def isatty(self):
                return True
        out = io.StringIO()
        with patch.object(sc.sys, "stdin", FakeTTY()), (
             patch.object(sc, "menu_snapshot", return_value={
                 "role": "SERVER", "state": "SSH SERVER (no tunnel)",
                 "service": "RUNNING", "guard": "n/a", "remote": "n/a",
                 "key": "ssh-rsa (offering unverified)", "note": "",
                 "local": "198.51.100.100 (interface-with-long-name)"})), (
             patch.object(sc.shutil, "get_terminal_size", return_value=os.terminal_size((40, 24)))), (
             patch.object(sc, "clear_menu")), (
             patch("builtins.input", return_value="0")), (
             contextlib.redirect_stdout(out)):
            sc.menu()
        rows = out.getvalue().splitlines()
        choices = [line for line in rows if re.match(r"^\s+\d+\)", line)]
        self.assertEqual(len(choices), 13)
        self.assertEqual({int(re.search(r"\d+", line).group()) for line in choices},
                         set(range(13)))
        self.assertTrue(all(len(line) <= 39 for line in rows), rows)
        self.assertEqual([int(re.search(r"\d+", line).group()) for line in choices],
                         list(range(1, 13)) + [0])

    def test_server_role_refuses_symlinked_role_even_if_contents_server(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            role = folder / "role.actual"
            role.write_text("server\n")
            (folder / "role").symlink_to(role)
            with patch.object(sc, "ETC", folder), patch.object(sc, "require_root"):
                with self.assertRaisesRegex(sc.ConnectError, "SERVER role"):
                    sc.show_server_host_fingerprints(probe=False)

    def test_repeated_server_setup_displays_identity_without_key_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            etc = folder / "etc"
            etc.mkdir()
            key = self.key(folder, "server_host", "ecdsa", 256)
            pub = Path(str(key) + ".pub")
            original_public = pub.read_bytes()
            original_private = key.read_bytes()
            original = sc.run
            calls = []
            config = (f"port 45222\nhostkey {key}\n"
                      "hostkeyalgorithms ecdsa-sha2-nistp256\n")
            def fake(argv, **kw):
                calls.append(argv)
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv, 0, config, "")
                return original(argv, **kw)
            with contextlib.ExitStack() as stack:
                for name, value in (
                    ("ETC", etc), ("CONF", etc/"config.json"),
                    ("STATE", folder/"state.json")):
                    stack.enter_context(patch.object(sc, name, value))
                stack.enter_context(patch.object(sc, "require_root"))
                stack.enter_context(patch.object(sc, "SSH_HOST_DIR", folder))
                stack.enter_context(patch.object(sc, "require_no_teardown"))
                stack.enter_context(patch.object(sc, "install_requirements"))
                stack.enter_context(patch.object(sc, "install_entrypoint"))
                stack.enter_context(patch.object(sc.shutil, "which",
                                                 side_effect=lambda name: "/usr/sbin/sshd" if name == "sshd" else None))
                stack.enter_context(patch.object(sc, "is_active",
                                                 side_effect=lambda unit: unit == "ssh.service"))
                stack.enter_context(patch.object(sc, "run", side_effect=fake))
                with contextlib.redirect_stdout(io.StringIO()) as first:
                    sc.setup("server", "ignored-wheel")
                with contextlib.redirect_stdout(io.StringIO()) as second:
                    sc.setup("server", "ignored-wheel")
            self.assertIn("SHA256:", first.getvalue())
            self.assertIn("SHA256:", second.getvalue())
            self.assertIn("Recommended SERVER host key: ECDSA (ecdsa-sha2-nistp256)", second.getvalue())
            self.assertEqual((etc/"role").read_text(), "server\n")
            self.assertEqual(pub.read_bytes(), original_public)
            self.assertEqual(key.read_bytes(), original_private)
            self.assertFalse(any(command[0] in ("ssh-keyscan", "systemctl") for command in calls))

    def test_missing_ed25519_does_not_invalidate_configured_ecdsa(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            role = folder / "role"
            role.write_text("server\n")
            ecdsa = self.key(folder, "host_ecdsa", "ecdsa", 256)
            missing = folder/"ssh_host_ed25519_key"
            config = (f"port 45456\nhostkey {missing}\n"
                      f"hostkey {ecdsa}\n"
                      "hostkeyalgorithms ecdsa-sha2-nistp256,ssh-ed25519\n")
            original = sc.run
            def fake(argv, **kw):
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv, 0, config, "")
                return original(argv, **kw)
            with patch.object(sc, "ETC", folder), (
                 patch.object(sc, "SSH_HOST_DIR", folder)), (
                 patch.object(sc.shutil, "which", side_effect=lambda name:
                             "/usr/sbin/sshd" if name == "sshd" else None)), (
                 patch.object(sc, "is_active", return_value=True)), (
                 patch.object(sc, "run", side_effect=fake)):
                report = sc.server_host_report(probe=False)
            self.assertEqual([entry["status"] for entry in report["keys"]][0], "PUBLIC KEY MISSING")
            self.assertTrue(report["keys"][1]["enabled"])
            self.assertIn("SHA256:", report["keys"][1]["fingerprint"])
            self.assertNotIn("OBSERVED", report["keys"][1]["status"])

    def test_not_installed_status_never_claims_direct(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(sc, "ETC", Path(d)), (
                 contextlib.redirect_stdout(io.StringIO())) as output:
                sc.status()
            self.assertIn("Role: NOT INSTALLED", output.getvalue())
            self.assertNotIn("State: DIRECT", output.getvalue())

    def test_role_symlink_status_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / "real").write_text("server\n")
            (folder / "role").symlink_to(folder / "real")
            with patch.object(sc, "ETC", folder):
                with self.assertRaisesRegex(sc.ConnectError, "Unsafe role"):
                    sc.status()

    def test_missing_private_host_key_never_claims_ready(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            host=self.key(folder,"unpaired","ed25519")
            host.unlink()
            config=f"port 55555\nhostkey {host}\nhostkeyalgorithms ssh-ed25519\n"
            original=sc.run
            def command(argv, **kwargs):
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv,0,config,"")
                return original(argv, **kwargs)
            with patch.object(sc,"SSH_HOST_DIR",folder), (
                 patch.object(sc.shutil,"which",return_value="/usr/sbin/sshd")), (
                 patch.object(sc,"is_active",return_value=True)), (
                 patch.object(sc,"run",side_effect=command)):
                report=sc.server_host_report(probe=False)
            self.assertEqual(report["keys"][0]["private"],"MISSING")
            self.assertFalse(report["keys"][0]["enabled"])
            self.assertIn("NOT READY", report["keys"][0]["status"])

    def test_mismatched_private_host_key_never_claims_ready(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            first=self.key(folder,"host","ed25519")
            second=self.key(folder,"other","ed25519")
            Path(str(first)+".pub").write_bytes(Path(str(second)+".pub").read_bytes())
            config=f"port 55555\nhostkey {first}\nhostkeyalgorithms ssh-ed25519\n"
            original=sc.run
            def command(argv, **kwargs):
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv,0,config,"")
                return original(argv, **kwargs)
            with patch.object(sc,"SSH_HOST_DIR",folder), (
                 patch.object(sc.shutil,"which",return_value="/usr/sbin/sshd")), (
                 patch.object(sc,"is_active",return_value=True)), (
                 patch.object(sc,"run",side_effect=command)):
                report=sc.server_host_report(probe=False)
            self.assertEqual(report["keys"][0]["private"],"PUBLIC/PRIVATE KEY MISMATCH")
            self.assertFalse(report["keys"][0]["enabled"])
            self.assertIn("NOT READY", report["keys"][0]["status"])

    def test_sshd_diagnostics_do_not_execute_path_hijack(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            (folder/"sshd").write_text("#!/bin/sh\nexit 99\n")
            (folder/"sshd").chmod(0o755)
            calls=[]
            actual=sc.run
            def fake(argv, **kwargs):
                calls.append(argv)
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv,0,
                        "port 23456\nhostkeyalgorithms ssh-ed25519\n","")
                return actual(argv,**kwargs)
            with patch.dict(os.environ,{"PATH":str(folder)+":/usr/bin"},clear=False), (
                 patch.object(sc.shutil,"which",return_value=str(folder/"sshd"))), (
                 patch.object(sc,"SSH_HOST_DIR",folder)), (
                 patch.object(sc,"is_active",return_value=False)), (
                 patch.object(sc,"run",side_effect=fake)):
                result=sc.server_host_report(probe=False)
            self.assertTrue(any(call[0]=="/usr/sbin/sshd" for call in calls))
            self.assertFalse(any(call[0]==str(folder/"sshd") for call in calls))
            self.assertEqual(result["ports"],[23456])

    def test_invalid_daemon_path_is_not_executed(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            file=folder/"sshd"
            file.write_text("#!/bin/sh\nexit 99\n")
            file.chmod(0o777)
            with (
                patch.object(sc, "SSH_DAEMON", file),
                patch.object(sc, "SSH_HOST_DIR", folder),
                patch.object(sc, "is_active", return_value=False),
                patch.object(sc, "run") as execute,
            ):
                report=sc.server_host_report(probe=False)
            execute.assert_not_called()
            self.assertFalse(report["configured"])
            self.assertIn("Unsafe sshd executable", " ".join(report["notes"]))


    def test_server_prefers_observed_supported_identity_when_ed25519_not_offered(self):
        report = {
            "active": True, "ports": [22222], "configured": True, "notes": [],
            "observed": [{"port": 22222, "identities": [
                {"type": "ecdsa-sha2-nistp256", "fingerprint": "SHA256:" + "C" * 43}
            ]}],
            "keys": [
                {"type": "ssh-ed25519", "fingerprint": "SHA256:" + "E" * 43,
                 "enabled": True, "status": "FILE PRESENT",
                 "private": "PAIR MATCH", "path": "/etc/ssh/ed25519.pub"},
                {"type": "ecdsa-sha2-nistp256", "fingerprint": "SHA256:" + "C" * 43,
                 "enabled": True, "status": "OBSERVED on localhost",
                 "private": "PAIR MATCH", "path": "/etc/ssh/ecdsa.pub"},
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "role").write_text("server\n")
            with patch.object(sc, "ETC", Path(d)), patch.object(sc, "require_root"), (
                 patch.object(sc, "server_host_report", return_value=report)), (
                 contextlib.redirect_stdout(io.StringIO())) as output:
                sc.show_server_host_fingerprints(probe=True, advanced=True)
        result = output.getvalue()
        first = result.split("Advanced SERVER host key diagnostics")[0]
        self.assertIn("ECDSA (ecdsa-sha2-nistp256)", first)
        self.assertIn("SHA256:" + "C" * 43, first)
        self.assertNotIn("SHA256:" + "E" * 43, first)
        self.assertIn("SHA256:" + "E" * 43, result)
        self.assertIn("/etc/ssh/ed25519.pub", result)

    def test_duplicate_ed25519_keys_match_only_exact_observed_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / "role").write_text("server\n")
            first = self.key(folder, "first_ed", "ed25519")
            second = self.key(folder, "second_ed", "ed25519")
            keys = [first, second]
            fingerprints = {key: self.record(key)[1] for key in keys}
            observed_key = first
            original = sc.run

            def fake(argv, **kwargs):
                if argv[0] == "/usr/sbin/sshd":
                    config = ("port 24001\n"
                              + "".join(f"hostkey {key}\n" for key in keys)
                              + "hostkeyalgorithms ssh-ed25519\n")
                    return subprocess.CompletedProcess(argv, 0, config, "")
                if argv[0] == "ssh-keyscan":
                    record = Path(str(observed_key) + ".pub").read_text().split()
                    row = f"127.0.0.1 {record[0]} {record[1]}\n"
                    return subprocess.CompletedProcess(argv, 0, row, "")
                return original(argv, **kwargs)

            with (
                patch.object(sc, "ETC", folder),
                patch.object(sc, "SSH_HOST_DIR", folder),
                patch.object(sc, "is_active", return_value=True),
                patch.object(sc, "run", side_effect=fake),
                patch.object(sc, "require_root"),
            ):
                for offered in (second, first):
                    with self.subTest(offered=offered.name):
                        observed_key = offered
                        report = sc.server_host_report(probe=True)
                        self.assertEqual(report["observed"], [{
                            "port": 24001,
                            "identities": [{"type": "ssh-ed25519",
                                            "fingerprint": fingerprints[offered]}],
                        }])
                        for entry in report["keys"]:
                            expected_ports = ([24001] if entry["fingerprint"] == fingerprints[offered]
                                              else [])
                            self.assertEqual(entry["observed_ports"], expected_ports)
                            if not expected_ports:
                                self.assertNotIn("OBSERVED", entry["status"])
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            sc.show_server_host_fingerprints(probe=True, advanced=False)
                        summary = output.getvalue()
                        self.assertIn(fingerprints[offered], summary)
                        self.assertNotIn(fingerprints[first if offered == second else second], summary)
                        self.assertIn("localhost port(s): 24001", summary)
                        self.assertNotIn("AMBIGUOUS", summary)
                        self.assertIn("UNVERIFIED", summary)

    def test_two_observed_ed25519_keys_on_different_ports_are_ambiguous(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / "role").write_text("server\n")
            first = self.key(folder, "port1_ed", "ed25519")
            second = self.key(folder, "port2_ed", "ed25519")
            first_fp, second_fp = self.record(first)[1], self.record(second)[1]
            original = sc.run

            def fake(argv, **kwargs):
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv, 0,
                        f"port 24001\nport 24002\nhostkey {first}\nhostkey {second}\n"
                        "hostkeyalgorithms ssh-ed25519\n", "")
                if argv[0] == "ssh-keyscan":
                    port = int(argv[argv.index("-p") + 1])
                    offered = first if port == 24001 else second
                    fields = Path(str(offered) + ".pub").read_text().split()
                    return subprocess.CompletedProcess(argv, 0,
                        f"127.0.0.1 {fields[0]} {fields[1]}\n", "")
                return original(argv, **kwargs)

            with (
                patch.object(sc, "ETC", folder),
                patch.object(sc, "SSH_HOST_DIR", folder),
                patch.object(sc, "is_active", return_value=True),
                patch.object(sc, "run", side_effect=fake),
                patch.object(sc, "require_root"),
            ):
                report = sc.server_host_report(probe=True)
                self.assertEqual(len(report["observed"]), 2)
                self.assertEqual(report["keys"][0]["observed_ports"], [24001])
                self.assertEqual(report["keys"][1]["observed_ports"], [24002])
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    sc.show_server_host_fingerprints(probe=True, advanced=True)
                display = out.getvalue()
                primary = display.split("Advanced SERVER host key diagnostics")[0]
                self.assertIn("AMBIGUOUS", primary)
                self.assertNotIn("Recommended SERVER host key", primary)
                self.assertNotIn(first_fp, primary)
                self.assertNotIn(second_fp, primary)
                self.assertIn(first_fp, display)
                self.assertIn(second_fp, display)
                self.assertIn("24001", display)
                self.assertIn("24002", display)

    def test_unobserved_same_type_keys_cannot_claim_listener_match(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / "role").write_text("server\n")
            first = self.key(folder, "first_ed", "ed25519")
            second = self.key(folder, "second_ed", "ed25519")
            original = sc.run

            def fake(argv, **kwargs):
                if argv[0] == "/usr/sbin/sshd":
                    return subprocess.CompletedProcess(argv, 0,
                        f"port 24001\nhostkey {first}\nhostkey {second}\n"
                        "hostkeyalgorithms ssh-ed25519\n", "")
                if argv[0] == "ssh-keyscan":
                    return subprocess.CompletedProcess(argv, 1, "", "not listening")
                return original(argv, **kwargs)

            with (
                patch.object(sc, "ETC", folder),
                patch.object(sc, "SSH_HOST_DIR", folder),
                patch.object(sc, "is_active", return_value=True),
                patch.object(sc, "run", side_effect=fake),
                patch.object(sc, "require_root"),
            ):
                report = sc.server_host_report(probe=True)
                self.assertEqual(report["observed"], [])
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    sc.show_server_host_fingerprints(probe=True)
                self.assertIn("AMBIGUOUS", out.getvalue())
                self.assertIn("No matching localhost host key observed", out.getvalue())
                self.assertNotIn("Matched on localhost", out.getvalue())

    def test_server_summary_at_40_and_80_columns_keeps_copy_token(self):
        report = {
            "active": True, "ports": [56777], "configured": True,
            "observed": [{"port": 56777, "identities": [
                {"type": "ssh-ed25519", "fingerprint": "SHA256:" + "E" * 43}
            ]}],
            "notes": [],
            "keys": [{"type": "ssh-ed25519", "fingerprint": "SHA256:" + "E" * 43,
                      "enabled": True, "status": "OBSERVED",
                      "private": "PAIR MATCH", "path": "/etc/ssh/host.pub"}],
        }
        for width in (40, 80):
            with self.subTest(width=width), tempfile.TemporaryDirectory() as d:
                (Path(d) / "role").write_text("server\n")
                with patch.object(sc, "ETC", Path(d)), patch.object(sc, "require_root"), (
                     patch.object(sc, "server_host_report", return_value=report)), (
                     patch.object(sc.shutil, "get_terminal_size",
                                  return_value=os.terminal_size((width, 24)))), (
                     contextlib.redirect_stdout(io.StringIO())) as output:
                    sc.show_server_host_fingerprints(probe=True)
                rows = output.getvalue().splitlines()
                self.assertEqual([line for line in rows if line.startswith("SHA256:")],
                                 ["SHA256:" + "E" * 43])
                self.assertTrue(all(len(row) <= width - 1 or row.startswith("SHA256:")
                                    for row in rows), rows)


if __name__ == "__main__":
    unittest.main()
