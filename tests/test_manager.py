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

    def test_nft_family_is_inet_in_real_upstream_2_0(self):
        data = {"nftables":[{"metainfo":{"version":"1.1.3"}},
                            {"table":{"family":"inet","name":"sshuttle-ipv4-21001","handle":1}}]}
        proc = subprocess.CompletedProcess([], 0, json.dumps(data), "")
        with patch.object(sc.subprocess, "run", return_value=proc) as call:
            self.assertEqual(sc.current_table({"listen_port":21001}), data)
            self.assertEqual(call.call_args.args[0], ["nft","-j","list","table","inet","sshuttle-ipv4-21001"])

    def test_dynamic_port_avoids_recent_socket_reuse(self):
        with patch.object(sc, "current_table", return_value=None):
            port = sc.choose_port()
        self.assertTrue(20000 <= port < 48000)
        self.assertEqual(sc.proxy_table({"listen_port": port}), f"sshuttle-ipv4-{port}")
        with self.assertRaises(sc.ConnectError):
            sc.proxy_table({"listen_port": "bad"})

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
            command.assert_called_once_with(["nft", "delete", "table", "inet", sc.TABLE], timeout=10)

    def test_guard_service_never_enabled_as_tunnel(self):
        units = sc.unit_texts()
        self.assertIn("BindsTo=simple-connect-guard.timer", units[sc.SERVICE])
        self.assertIn("ExecStopPost=", units[sc.SERVICE])
        self.assertIn("KillSignal=SIGKILL", units[sc.SERVICE])
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

    def test_early_crash_table_shape_rejects_modified_or_foreign_resources(self):
        p = 24567
        name = f"sshuttle-ipv4-{p}"
        state = {"status": "PENDING", "boot": "test-boot", "listen_port": p,
                 "remote_ip": "8.8.8.8", "management_ip": "9.9.9.9", "table_sha256": ""}
        def entry(kind, **fields):
            return {kind: fields}
        common = {"family": "inet", "table": name}
        proto = [{"match": {"op": "!=", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}}, {"return": None}]
        fib = [{"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}}, {"return": None}]
        tcp = [{"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
               {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "0.0.0.0", "len": 0}}}},
               {"redirect": {"port": p}}]
        entries = [
            entry("table", family="inet", name=name, handle=12),
            entry("chain", **common, name="output", handle=1, type="nat", hook="output", prio=-100, policy="accept"),
            entry("chain", **common, name="prerouting", handle=2, type="nat", hook="prerouting", prio=-100, policy="accept"),
            entry("chain", **common, name=name, handle=3),
            entry("rule", **common, chain="output", handle=4, expr=[{"jump": {"target": name}}]),
            entry("rule", **common, chain="prerouting", handle=5, expr=[{"jump": {"target": name}}]),
            entry("rule", **common, chain=name, handle=6, expr=proto),
            entry("rule", **common, chain=name, handle=7, expr=fib),
            entry("rule", **common, chain=name, handle=8, expr=tcp),
        ]
        with patch.object(sc, "boot_id", return_value="test-boot"):
            self.assertTrue(sc.safe_early_sshuttle_table({"nftables": entries}, state))
            import copy
            changed = copy.deepcopy(entries)
            changed[-1]["rule"]["expr"][2]["redirect"]["port"] = p+1
            self.assertFalse(sc.safe_early_sshuttle_table({"nftables": changed}, state))
            changed = copy.deepcopy(entries)
            changed[1]["chain"]["prio"] = -99
            self.assertFalse(sc.safe_early_sshuttle_table({"nftables": changed}, state))
            changed = copy.deepcopy(entries)
            changed.append(entry("rule", **common, chain=name, handle=9, expr=[{"accept": None}]))
            self.assertFalse(sc.safe_early_sshuttle_table({"nftables": changed}, state))
            self.assertFalse(sc.safe_early_sshuttle_table({"nftables": entries}, {**state,"status":"ACTIVE"}))

    def test_server_uninstall_does_not_require_nft_or_client_service(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            etc = root / "etc"
            etc.mkdir()
            (etc / "role").write_text("server\n")
            app = root / "manager.py"
            cmd = root / "simple-connect"
            app.write_text("manager")
            cmd.write_text("wrapper")
            with patch.object(sc, "ETC", etc), patch.object(sc, "APP", app), patch.object(sc, "COMMAND", cmd):
                with patch.object(sc, "require_root"), patch.object(sc, "stop_proxy") as stop:
                    sc.uninstall(True)
                    stop.assert_not_called()
            self.assertFalse(app.exists())
            self.assertFalse(cmd.exists())
            self.assertFalse(etc.exists())

    def test_bootstrap_hash_matches_manager(self):
        repo = Path(__file__).resolve().parents[1]
        boot = (repo / "install.sh").read_text()
        expected = hashlib.sha256((repo / "simple_connect.py").read_bytes()).hexdigest()
        self.assertIn('MANAGER_SHA256="' + expected + '"', boot)
        self.assertIn(sc.WHEEL_SHA256, boot)
        self.assertIn('DEFAULT_MIRROR="https://helpe.ir/simple-connect"', boot)
        self.assertIn('if ( : </dev/tty ) 2>/dev/null; then', boot)

    def test_help_is_nonprivileged_and_no_host_effect(self):
        app = Path(__file__).resolve().parents[1] / "simple_connect.py"
        p = subprocess.run([sys.executable, str(app), "--help"], text=True, capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("configure", p.stdout)


if __name__ == "__main__":
    unittest.main()
