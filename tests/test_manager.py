"""Hermetic regression tests. No host-network or production unit mutations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc


class SimpleConnectTests(unittest.TestCase):
    def test_ipv4_validation_and_endpoint_isolation(self):
        self.assertEqual(sc.validate_ipv4("8.8.8.8", public=True), "8.8.8.8")
        for bad in ("127.0.0.1", "192.168.0.1", "224.0.0.1", "::1", "abc"):
            with self.subTest(bad=bad), self.assertRaises(sc.ConnectError):
                sc.validate_ipv4(bad, public=True)

    def test_management_peer_session_has_four_verified_fields(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "203.0.113.10 53255 198.51.100.23 22"}):
            self.assertEqual(sc.initial_ssh_connection(), "203.0.113.10 53255 198.51.100.23 22")
        for broken in ("", "127.0.0.1 x 8.8.8.8 22", "random", "8.8.8.8 0 1.2.3.4 22"):
            with self.subTest(broken=broken), patch.dict(os.environ, {"SSH_CONNECTION": broken}):
                with self.assertRaises(sc.ConnectError):
                    sc.initial_ssh_connection()

    def test_state_atomic_roundtrip_and_schema_reject(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "private.json"
            sc.write_json(p, {"status": "DIRECT"})
            self.assertEqual(sc.read_json(p)["status"], "DIRECT")
            self.assertEqual(sc.read_json(p)["schema"], 1)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            p.write_text(json.dumps({"schema": 99, "status": "ACTIVE"}))
            with self.assertRaises(sc.ConnectError):
                sc.read_json(p)

    def test_expected_nft_snapshot_stable_key_order(self):
        a = {"nftables": [{"table": {"family": "ip", "name": sc.TABLE}}, {"rule": {"chain": "output", "handle": 2}}]}
        b = {"nftables": [{"table": {"name": sc.TABLE, "family": "ip"}}, {"rule": {"handle": 2, "chain": "output"}}]}
        self.assertEqual(sc.table_hash(a), sc.table_hash(b))
        self.assertTrue(sc.table_is_ours(b, sc.table_hash(a)))
        b["nftables"][1]["rule"]["handle"] = 3
        self.assertFalse(sc.table_is_ours(b, sc.table_hash(a)))

    def test_foreign_or_modified_firewall_table_is_not_deleted(self):
        sample = {"nftables": [{"table": {"family": "ip", "name": sc.TABLE}}]}
        with patch.object(sc, "current_table", return_value=sample), patch.object(sc, "run") as command:
            self.assertFalse(sc.owned_cleanup({"table_sha256": "foreign"}))
            self.assertFalse(sc.owned_cleanup({"table_sha256": ""}))
            command.assert_not_called()

    def test_exact_owned_table_is_removed_only_by_its_own_name(self):
        sample = {"nftables": [{"table": {"family": "ip", "name": sc.TABLE}}]}
        with patch.object(sc, "current_table", side_effect=[sample, None]), patch.object(sc, "run") as command:
            self.assertTrue(sc.owned_cleanup({"table_sha256": sc.table_hash(sample)}))
            command.assert_called_once_with(["nft", "delete", "table", "ip", sc.TABLE], timeout=10)

    def test_guard_service_never_enabled_as_tunnel(self):
        units = sc.unit_texts()
        self.assertIn("BindsTo=simple-connect-guard.timer", units[sc.SERVICE])
        self.assertIn("ExecStopPost=", units[sc.SERVICE])
        self.assertIn("OnBootSec=12s", units[sc.GUARD_TIMER])
        self.assertNotIn("WantedBy=multi-user.target", units[sc.SERVICE])

    def test_service_run_requires_pending_state_before_exec(self):
        with patch.object(sc, "require_root"), patch.object(sc, "read_config", return_value={"remote_ip": "8.8.8.8"}):
            with patch.object(sc, "is_active", return_value=True), patch.object(sc, "read_json", return_value={"status": "DIRECT"}):
                with patch.object(sc, "boot_id", return_value="same"), patch.object(os, "execvpe") as execv:
                    with self.assertRaises(sc.ConnectError):
                        sc.service_run()
                    execv.assert_not_called()

    def test_service_command_excludes_private_remote_and_management_peers(self):
        with patch.object(sc, "require_root"), patch.object(sc, "read_config", return_value={"remote_ip": "8.8.8.8"}):
            with patch.object(sc, "is_active", return_value=True), patch.object(sc, "read_json", return_value={
                "status": "PENDING", "boot": "same", "management_ip": "203.0.113.42"
            }):
                with patch.object(sc, "boot_id", return_value="same"), patch.object(os, "execvpe") as execv:
                    sc.service_run()
                    args = execv.call_args.args[1]
                    self.assertEqual(args[-1], "0.0.0.0/0")
                    self.assertIn("--method=nft", args)
                    self.assertIn("--dns", args)
                    self.assertIn("8.8.8.8/32", args)
                    self.assertIn("203.0.113.42/32", args)
                    self.assertIn("192.168.0.0/16", args)

    def test_confirm_refuses_same_ssh_session(self):
        state = {
            "status": "PENDING", "op": "ab12", "boot": "test", "deadline": 9999999999,
            "original_ssh_connection": "203.0.113.10 50000 192.0.2.11 22",
        }
        from contextlib import nullcontext
        with patch.object(sc, "require_root"), patch.object(sc, "locked", return_value=nullcontext()):
            with patch.object(sc, "read_json", return_value=state), patch.object(sc, "boot_id", return_value="test"):
                with patch.object(sc, "initial_ssh_connection", return_value=state["original_ssh_connection"]):
                    with self.assertRaisesRegex(sc.ConnectError, "fresh independent"):
                        sc.confirm("ab12")

    def test_confirm_rejects_wrong_operation(self):
        from contextlib import nullcontext
        with patch.object(sc, "require_root"), patch.object(sc, "locked", return_value=nullcontext()):
            with patch.object(sc, "read_json", return_value={"status": "PENDING", "op": "abc"}):
                with self.assertRaises(sc.ConnectError):
                    sc.confirm("def")

    def test_guard_pending_timeout_requests_stop_and_recovery(self):
        from contextlib import nullcontext
        state = {
            "status": "PENDING", "boot": "b", "deadline": 1, "started": 1,
            "table_sha256": sc.table_hash({"nftables": []}),
        }
        with patch.object(sc, "require_root"), patch.object(sc, "locked", return_value=nullcontext()):
            with patch.object(sc, "read_json", return_value=state), patch.object(sc, "boot_id", return_value="b"):
                with patch.object(sc, "is_active", return_value=True), patch.object(sc, "current_table", return_value={"nftables": []}):
                    with patch.object(sc, "recover") as recovered, patch.object(subprocess, "run") as stop:
                        sc.guard()
                        stop.assert_called_once()
                        self.assertIn("stop", stop.call_args.args[0])
                        recovered.assert_called_once()

    def test_guard_active_missing_table_requests_stop(self):
        from contextlib import nullcontext
        state = {"status": "ACTIVE", "boot": "b", "table_sha256": "a" * 64}
        with patch.object(sc, "require_root"), patch.object(sc, "locked", return_value=nullcontext()):
            with patch.object(sc, "read_json", return_value=state), patch.object(sc, "boot_id", return_value="b"):
                with patch.object(sc, "is_active", return_value=True), patch.object(sc, "current_table", return_value=None):
                    with patch.object(sc, "recover") as recovered, patch.object(subprocess, "run") as stop:
                        sc.guard()
                        stop.assert_called_once()
                        recovered.assert_called_once()

    def test_bootstrap_hash_matches_manager(self):
        repo = Path(__file__).resolve().parents[1]
        boot = (repo / "install.sh").read_text()
        expected = hashlib.sha256((repo / "simple_connect.py").read_bytes()).hexdigest()
        self.assertIn('MANAGER_SHA256="' + expected + '"', boot)
        self.assertIn(sc.WHEEL_SHA256, boot)

    def test_help_is_nonprivileged_and_no_host_effect(self):
        app = Path(__file__).resolve().parents[1] / "simple_connect.py"
        p = subprocess.run([sys.executable, str(app), "--help"], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("configure", p.stdout)


if __name__ == "__main__":
    unittest.main()
