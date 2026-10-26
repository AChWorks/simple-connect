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

    def test_kernel_verified_ssh_session_ignores_forged_environment(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for pid, parent, exe in ((234,123,"/usr/bin/bash"), (123,1,"/usr/sbin/sshd-session")):
                path=root/str(pid)
                path.mkdir()
                (path/"status").write_text(f"Name: bash\nPPid:\t{parent}\n")
                (path/"exe").symlink_to(exe)
                (path/"fd").mkdir()
            (root/"123"/"fd"/"3").symlink_to("socket:[54321]")
            (root/"net").mkdir()
            (root/"net"/"tcp").write_text(
                "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
                "  0: 176433C6:0016 0A7100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 54321 1\n"
            )
            (root/"net"/"tcp6").write_text("sl local_address rem_address st\n")
            expected="203.0.113.10 50000 198.51.100.23 22 54321"
            with patch.dict(os.environ, {"SSH_CONNECTION":"8.8.8.8 12345 9.9.9.9 99"}):
                self.assertEqual(sc.initial_ssh_connection(proc_root=root,pid=234),expected)
            # Fresh TCP kernel inode proves a distinct connection even if
            # SSH_CONNECTION was copied verbatim to the new shell.
            (root/"123"/"fd"/"3").unlink()
            with self.assertRaisesRegex(sc.ConnectError,"socket absent"):
                sc.initial_ssh_connection(proc_root=root,pid=234)

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
        with patch.object(sc, "require_root"), patch.object(sc, "require_client_role"), patch.object(sc, "read_config", return_value={"remote_ip": "8.8.8.8"}):
            with patch.object(sc, "is_active", return_value=True), patch.object(sc, "read_json", return_value={"status": "DIRECT"}):
                with patch.object(sc, "boot_id", return_value="same"), patch.object(os, "execvpe") as execv:
                    with self.assertRaises(sc.ConnectError):
                        sc.service_run()
                    execv.assert_not_called()

    def test_service_command_uses_persisted_ssh_and_onlink_exclusions(self):
        expected=list(sc.EXCLUDED)+["8.8.8.8/32","203.0.113.42/32","11.88.0.0/24"]
        state={"status":"PENDING","boot":"same","remote_ip":"8.8.8.8",
               "management_ip":"203.0.113.42","exclusions":expected}
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"read_config",return_value={"remote_ip":"8.8.8.8"}):
                with patch.object(sc,"is_active",return_value=True),patch.object(sc,"read_json",return_value=state):
                    with patch.object(sc,"boot_id",return_value="same"),patch.object(os,"execvpe") as execv:
                        sc.service_run()
                        args=execv.call_args.args[1]
                        self.assertIn("--method=nft",args)
                        for cidr in expected:
                            self.assertIn(cidr,args)
                        self.assertEqual(args[-1],"0.0.0.0/0")

    def test_confirm_refuses_same_verified_ssh_session(self):
        state={"status":"PENDING","op":"ab12","boot":"test","deadline":9999999999,
               "original_ssh_connection":"203.0.113.10 50000 192.0.2.11 22 8001"}
        from contextlib import nullcontext
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"),patch.object(sc,"locked",return_value=nullcontext()):
            with patch.object(sc,"read_json",return_value=state),patch.object(sc,"boot_id",return_value="test"):
                with patch.object(sc,"initial_ssh_connection",return_value=state["original_ssh_connection"]):
                    with self.assertRaisesRegex(sc.ConnectError,"fresh independent"):
                        sc.confirm("ab12")

    def test_expired_confirmation_never_adopts_a_new_session(self):
        from contextlib import nullcontext
        state={"status":"PENDING","op":"test","boot":"oldboot",
               "deadline":1,"original_ssh_connection":"a"}
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"locked",return_value=nullcontext()):
                with patch.object(sc,"read_json",return_value=state):
                    with patch.object(sc,"boot_id",return_value="oldboot"):
                        with patch.object(sc,"initial_ssh_connection") as session:
                            with self.assertRaisesRegex(sc.ConnectError,"expired"):
                                sc.confirm("test")
                            session.assert_not_called()

    def test_confirm_rejects_wrong_operation(self):
        from contextlib import nullcontext
        with patch.object(sc, "require_root"), patch.object(sc, "locked", return_value=nullcontext()):
            with patch.object(sc, "read_json", return_value={"status": "PENDING", "op": "abc"}):
                with self.assertRaises(sc.ConnectError):
                    sc.confirm("def")

    def test_guard_pending_timeout_requests_safe_stop(self):
        from contextlib import nullcontext
        state={"status":"PENDING","boot":"b","deadline":1,"started":1,
               "table_sha256":sc.table_hash({"nftables":[]})}
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"),patch.object(sc,"locked",return_value=nullcontext()):
            with patch.object(sc,"read_json",return_value=state),patch.object(sc,"boot_id",return_value="b"):
                with patch.object(sc,"is_active",return_value=True),patch.object(sc,"current_table",return_value={"nftables":[]}):
                    with patch.object(sc,"stop_and_recover") as stop:
                        sc.guard()
                        stop.assert_called_once_with("guard")

    def test_guard_active_missing_table_requests_safe_stop(self):
        from contextlib import nullcontext
        state={"status":"ACTIVE","boot":"b","table_sha256":"a"*64}
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"),patch.object(sc,"locked",return_value=nullcontext()):
            with patch.object(sc,"read_json",return_value=state),patch.object(sc,"boot_id",return_value="b"):
                with patch.object(sc,"is_active",return_value=True),patch.object(sc,"current_table",return_value=None):
                    with patch.object(sc,"stop_and_recover") as stop:
                        sc.guard()
                        stop.assert_called_once_with("guard")

    def test_early_crash_never_deletes_unfingerprinted_firewall(self):
        # Even an apparently exact sshuttle footprint cannot establish
        # provenance if the full fingerprint was never recorded.
        name="sshuttle-ipv4-23456"
        data={"nftables":[{"table":{"family":"inet","name":name,"handle":1}},
                          {"rule":{"family":"inet","table":name,"chain":"output",
                                   "handle":2,"expr":[{"redirect":{"port":23456}}]}}]}
        state={"status":"PENDING","listen_port":23456,"table_sha256":""}
        with patch.object(sc,"current_table",return_value=data), patch.object(sc,"run") as execute:
            self.assertFalse(sc.owned_cleanup(state))
            modified={"nftables":data["nftables"]+[{"rule":{"chain":"output","handle":3}}]}
            self.assertFalse(sc.owned_cleanup(state))
            execute.assert_not_called()

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
                with patch.object(sc, "require_root"), patch.object(sc, "service_terminated", return_value=True), patch.object(sc, "stop_proxy") as stop:
                    sc.uninstall(True)
                    stop.assert_not_called()
            self.assertFalse(app.exists())
            self.assertFalse(cmd.exists())
            self.assertFalse(etc.exists())

    def test_systemd_termination_is_verified_not_inferred_from_is_active(self):
        def show(active, main, control):
            return subprocess.CompletedProcess([], 0,
                f"ActiveState={active}\nMainPID={main}\nControlPID={control}\nLoadState=loaded\n", "")
        with patch.object(sc, "run", side_effect=[
                show("active",123,0), show("deactivating",0,9999),
                show("deactivating",0,os.getpid()),show("inactive",0,0)]):
            self.assertFalse(sc.service_terminated())
            self.assertFalse(sc.service_terminated())
            self.assertTrue(sc.service_terminated())
            self.assertTrue(sc.service_terminated())

    def test_manual_recover_refuses_live_proxy_before_firewall_touch(self):
        from contextlib import nullcontext
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"locked",return_value=nullcontext()):
                with patch.object(sc,"service_terminated",return_value=False),patch.object(sc,"owned_cleanup") as nft:
                    with self.assertRaisesRegex(sc.ConnectError,"live/unverified"):
                        sc.recover()
                    nft.assert_not_called()

    def test_systemctl_stop_failure_cannot_write_direct_or_delete_rules(self):
        from contextlib import nullcontext
        current={"status":"ACTIVE","table_sha256":"a"*64}
        with patch.object(sc,"service_terminated",return_value=False):
            with patch.object(sc,"run",return_value=subprocess.CompletedProcess([],1,"","stop failed")):
                with patch.object(sc,"locked",return_value=nullcontext()):
                    with patch.object(sc,"read_json",return_value=current),patch.object(sc,"write_json") as write:
                        with patch.object(sc,"owned_cleanup") as nft:
                            with self.assertRaisesRegex(sc.ConnectError,"UNCERTAIN"):
                                sc.stop_and_recover("failed_stop")
                            self.assertEqual(write.call_args.args[1]["status"],"UNCERTAIN")
                            nft.assert_not_called()

    def test_reconcile_never_persists_direct_when_proxy_may_be_running(self):
        state={"status":"ACTIVE","table_sha256":"a"*64}
        with patch.object(sc,"service_terminated",return_value=False),patch.object(sc,"read_json",return_value=state):
            with patch.object(sc,"write_json") as write,patch.object(sc,"owned_cleanup") as nft:
                with self.assertRaisesRegex(sc.ConnectError,"termination NOT verified"):
                    sc.reconcile("test")
                self.assertEqual(write.call_args.args[1]["status"],"UNCERTAIN")
                nft.assert_not_called()

    def test_reconcile_refuses_direct_with_foreign_orphan_table(self):
        from contextlib import nullcontext
        with patch.object(sc,"service_terminated",return_value=True):
            with patch.object(sc,"read_json",return_value={"status":"STOPPING"}):
                with patch.object(sc,"owned_cleanup",return_value=True):
                    with patch.object(sc,"any_proxy_tables",return_value=True):
                        with patch.object(sc,"write_json") as write:
                            with self.assertRaisesRegex(sc.ConnectError,"untracked"):
                                sc.reconcile("test")
                            self.assertEqual(write.call_args.args[1]["status"],"UNCERTAIN")

    def test_guard_detects_direct_with_unexpected_running_service(self):
        from contextlib import nullcontext
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"),patch.object(sc,"locked",return_value=nullcontext()):
            with patch.object(sc,"read_json",return_value={"status":"DIRECT"}):
                with patch.object(sc,"service_terminated",return_value=False):
                    with patch.object(sc,"mark_uncertain") as mark,patch.object(sc,"stop_and_recover") as stop:
                        sc.guard()
                        mark.assert_called_once_with("direct_with_live_service")
                        stop.assert_called_once_with("guard")

    def test_uninstall_refuses_failed_shutdown_without_erasing_files(self):
        with patch.object(sc,"require_root"),patch.object(sc,"stop_proxy",side_effect=sc.ConnectError("incomplete stop")):
            with patch.object(sc,"unit_action") as action:
                with self.assertRaisesRegex(sc.ConnectError,"incomplete stop"):
                    sc.uninstall(True)
                action.assert_not_called()

    def test_route_discovery_protects_public_onlink_and_gateway(self):
        routes=[
            {"dst":"203.0.113.0/24","dev":"eth0","scope":"link","protocol":"kernel"},
            {"dst":"10.12.0.0/16","dev":"eth1","scope":"link"},
            {"dst":"default","gateway":"203.0.113.1","dev":"eth0"},
            {"dst":"45.45.45.45","gateway":"203.0.113.1","dev":"eth0"},
        ]
        result=subprocess.CompletedProcess([],0,json.dumps(routes),"")
        with patch.object(sc,"run",return_value=result):
            excluded=sc.effective_exclusions("8.8.8.8","198.51.100.10")
        for cidr in ("203.0.113.0/24","203.0.113.1/32",
                     "10.12.0.0/16","198.51.100.10/32","8.8.8.8/32"):
            self.assertIn(cidr,excluded)
        self.assertNotIn("45.45.45.45/32",excluded)
        self.assertEqual(sc.stored_exclusions({"exclusions":excluded,
                                               "remote_ip":"8.8.8.8",
                                               "management_ip":"198.51.100.10"}),excluded)

    def test_route_discovery_rejects_unbounded_onlink_default(self):
        result=subprocess.CompletedProcess([],0,json.dumps([{"dst":"default","dev":"ppp0","scope":"link"}]),"")
        with patch.object(sc,"run",return_value=result):
            with self.assertRaisesRegex(sc.ConnectError,"on-link IPv4 default"):
                sc.effective_exclusions("8.8.8.8","9.9.9.9")

    def test_service_rejects_missing_protected_local_routes(self):
        state={"exclusions":list(sc.EXCLUDED)+["8.8.8.8/32"],
               "remote_ip":"8.8.8.8","management_ip":"203.0.113.15"}
        with self.assertRaisesRegex(sc.ConnectError,"omit"):
            sc.stored_exclusions(state)

    def test_server_rejects_client_configuration_before_any_write(self):
        with tempfile.TemporaryDirectory() as d:
            etc=Path(d)
            (etc/"role").write_text("server\n")
            with patch.object(sc,"ETC",etc),patch.object(sc,"require_root"):
                with patch.object(sc,"atomic_write") as write:
                    with self.assertRaisesRegex(sc.ConnectError,"CLIENT"):
                        sc.configure("8.8.8.8","root",22,"/root/.ssh/id_ed25519","bad")
                    write.assert_not_called()

    def test_server_legacy_config_is_cleanly_uninstalled_without_tunnel(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); etc=root/"etc"; etc.mkdir()
            (etc/"role").write_text("server\n")
            config=etc/"config.json"; config.write_text("{}")
            app=root/"app";app.write_text("installed")
            cmd=root/"bin";cmd.write_text("installed")
            with patch.object(sc,"ETC",etc),patch.object(sc,"CONF",config),patch.object(sc,"STATE",root/"absent_state"):
                with patch.object(sc,"SSH_CONF",etc/"ssh_config"),patch.object(sc,"KNOWN_HOSTS",etc/"known_hosts"):
                    with patch.object(sc,"APP",app),patch.object(sc,"COMMAND",cmd),patch.object(sc,"require_root"):
                        with patch.object(sc,"service_terminated",return_value=True):
                            sc.uninstall(True)
            self.assertFalse(config.exists())
            self.assertFalse(app.exists())
            self.assertFalse(cmd.exists())
            self.assertFalse(etc.exists())

    def test_existing_uncertain_client_setup_cannot_replace_recovery_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            etc=root/"etc";etc.mkdir()
            (etc/"role").write_text("client\n")
            state=root/"state.json";state.write_text('{"schema":1,"status":"UNCERTAIN"}')
            with patch.object(sc,"ETC",etc),patch.object(sc,"STATE",state),patch.object(sc,"require_root"):
                with patch.object(sc,"install_requirements") as installer:
                    with self.assertRaisesRegex(sc.ConnectError,"Recovery unresolved"):
                        sc.setup("client","https://unused.example/x")
                    installer.assert_not_called()

    def test_requires_python310_local_and_remote_contract(self):
        with patch.object(sc.sys,"version_info",(3,9,20)):
            with self.assertRaisesRegex(sc.ConnectError,"3.10"):
                sc.require_supported_python()
        with patch.object(sc.sys,"version_info",(3,13,5)):
            with patch.object(sc.subprocess,"run",return_value=subprocess.CompletedProcess([],0,"","")):
                sc.require_supported_python()
        with patch.object(sc,"run",return_value=subprocess.CompletedProcess([],0,"","")) as remote:
            sc.remote_python_test()
            self.assertIn("(3, 10)",remote.call_args.args[0][-1])

    def test_ssh_session_parse_requires_established_kernel_socket(self):
        line="  0: 176433C6:0016 0A7100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 54321 1"
        self.assertEqual(sc.parse_proc_tcp_line(line),
                         ("203.0.113.10",50000,"198.51.100.23",22,54321))
        self.assertIsNone(sc.parse_proc_tcp_line(line.replace(" 01 "," 0A ")))

    def test_guard_skips_benign_idle_manager_lock_contention(self):
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"guarded_check",side_effect=sc.ConnectError("Another Simple Connect operation is running. Try again shortly.")):
                with patch.object(sc,"service_terminated",return_value=True):
                    sc.guard()
                with patch.object(sc,"service_terminated",return_value=False):
                    with self.assertRaises(sc.ConnectError):
                        sc.guard()

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
