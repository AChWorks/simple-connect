"""Hermetic regression tests. No host-network or production unit mutations."""
from contextlib import ExitStack, nullcontext
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

    def test_confirm_refuses_preexisting_second_ssh_session(self):
        state={"status":"PENDING","op":"ab12","boot":"test","deadline_boot":1100,
               "original_ssh_connection":"203.0.113.10 50000 192.0.2.11 22 8001",
               "ssh_preexisting":["203.0.113.10 50000 192.0.2.11 22 8001",
                                  "203.0.113.11 50001 192.0.2.11 22 8002"]}
        from contextlib import nullcontext
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"locked",return_value=nullcontext()):
                with patch.object(sc,"read_json",return_value=state),patch.object(sc,"boot_id",return_value="test"):
                    with patch.object(sc,"boot_seconds",return_value=1000):
                        with patch.object(sc,"initial_ssh_connection",return_value=state["ssh_preexisting"][1]):
                            with self.assertRaisesRegex(sc.ConnectError,"AFTER activation"):
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
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d)
            etc=root/"etc";etc.mkdir()
            (etc/"role").write_text("client\n")
            patches.enter_context(patch.object(sc,"ETC",etc))
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            reservation=patches.enter_context(patch.object(sc,"reserve_uninstall",return_value="RESERVED"))
            patches.enter_context(patch.object(sc,"stop_proxy",side_effect=sc.ConnectError("incomplete stop")))
            action=patches.enter_context(patch.object(sc,"unit_action"))
            with self.assertRaisesRegex(sc.ConnectError,"incomplete stop"):
                sc.uninstall(True)
            reservation.assert_called_once()
            action.assert_not_called()


    def test_ssh_socket_inventory_captures_all_preexisting_logins(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"net").mkdir()
            header="sl local_address rem_address st tx_queue tr when retr uid timeout inode\n"
            (root/"net"/"tcp").write_text(
                header+
                "0: 176433C6:0016 0A7100CB:C350 01 00000000:00000000 00:00000000 00000000 0 0 54321 1\n"+
                "1: 176433C6:0016 0B7100CB:C351 01 00000000:00000000 00:00000000 00000000 0 0 54322 1\n"
            )
            (root/"net"/"tcp6").write_text(header)
            for pid,inode in ((234,54321),(235,54322)):
                proc=root/str(pid)
                proc.mkdir()
                (proc/"exe").symlink_to("/usr/sbin/sshd-session")
                (proc/"fd").mkdir()
                (proc/"fd"/"3").symlink_to(f"socket:[{inode}]")
            found=sc.ssh_connection_inventory(proc_root=root)
            self.assertEqual(found,["203.0.113.10 50000 198.51.100.23 22 54321",
                                    "203.0.113.11 50001 198.51.100.23 22 54322"])

    def test_confirm_accepts_only_new_kernel_proven_remote_ssh(self):
        from contextlib import nullcontext
        table={"nftables":[{"table":{"family":"inet","name":"sshuttle-ipv4-23000"}}]}
        original="203.0.113.10 50000 192.0.2.11 22 8001"
        second="203.0.113.11 50001 192.0.2.11 22 8002"
        third="203.0.113.12 50002 192.0.2.11 22 8003"
        state={"status":"PENDING","op":"ab12","boot":"boot-one","deadline_boot":2000,
               "table_sha256":sc.table_hash(table),"listen_port":23000,
               "original_ssh_connection":original,"ssh_preexisting":[original,second]}
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"locked",return_value=nullcontext()),patch.object(sc,"read_json",return_value=state):
                with patch.object(sc,"boot_id",return_value="boot-one"),patch.object(sc,"boot_seconds",return_value=1450):
                    with patch.object(sc,"is_active",return_value=True),patch.object(sc,"current_table",return_value=table):
                        with patch.object(sc,"require_external_management_peer") as external,patch.object(sc,"write_json") as saved:
                            with patch.object(sc,"initial_ssh_connection",return_value=second):
                                with self.assertRaisesRegex(sc.ConnectError,"AFTER activation"):
                                    sc.confirm("ab12")
                            with patch.object(sc,"initial_ssh_connection",return_value=third):
                                sc.confirm("ab12")
                            saved.assert_called_once()
                            self.assertEqual(saved.call_args.args[1]["status"],"ACTIVE")
                            external.assert_called_once_with("203.0.113.12")

    def test_self_originated_ssh_is_rejected(self):
        with self.assertRaisesRegex(sc.ConnectError,"Local-only"):
            sc.require_external_management_peer("127.0.0.1")
        out=json.dumps([{"addr_info":[{"family":"inet","local":"203.0.113.5"}]}])
        result=subprocess.CompletedProcess([],0,out,"")
        with patch.object(sc,"run",return_value=result):
            with self.assertRaisesRegex(sc.ConnectError,"Self-originated"):
                sc.require_external_management_peer("203.0.113.5")
            sc.require_external_management_peer("203.0.113.6")

    def test_boottime_deadline_ignores_wallclock_jumps(self):
        state={"deadline_boot":1600,"boot":"boot-one"}
        with patch.object(sc,"boot_seconds",return_value=1599):
            with patch.object(sc.time,"time",return_value=100000000):
                self.assertFalse(sc.pending_expired(state))
        with patch.object(sc,"boot_seconds",return_value=1600):
            with patch.object(sc.time,"time",return_value=1):
                self.assertTrue(sc.pending_expired(state))
        with patch.object(sc,"boot_seconds",return_value=1500):
            with patch.object(sc.time,"time",return_value=9999999999):
                self.assertFalse(sc.pending_expired(state))
        self.assertTrue(sc.pending_expired({"deadline_boot":"broken"}))
        self.assertTrue(sc.pending_expired({"deadline":9999999999}))

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

    def test_first_client_wheel_failure_is_retryable(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d)
            etc=root/"etc"
            state_dir=root/"data"
            patches.enter_context(patch.object(sc,"ETC",etc))
            patches.enter_context(patch.object(sc,"STATE_DIR",state_dir))
            patches.enter_context(patch.object(sc,"STATE",state_dir/"state.json"))
            patches.enter_context(patch.object(sc,"UNIT_DIR",root/"units"))
            patches.enter_context(patch.object(sc,"CONF",etc/"config.json"))
            patches.enter_context(patch.object(sc,"SSH_CONF",etc/"ssh_config"))
            patches.enter_context(patch.object(sc,"KNOWN_HOSTS",etc/"known_hosts"))
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"require_no_teardown"))
            patches.enter_context(patch.object(sc,"install_requirements"))
            patches.enter_context(patch.object(sc,"install_entrypoint"))
            wheel=patches.enter_context(patch.object(sc,"install_wheel",
                side_effect=[sc.ConnectError("mirror failed"),None,None]))
            patches.enter_context(patch.object(sc,"unit_texts",return_value={}))
            patches.enter_context(patch.object(sc,"unit_action"))
            patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
            patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
            patches.enter_context(patch.object(sc,"is_active",return_value=False))
            patches.enter_context(patch.object(sc,"boot_id",return_value="boot-one"))
            with self.assertRaisesRegex(sc.ConnectError,"mirror failed"):
                sc.setup("client","https://mirror.example/wheel")
            self.assertEqual((etc/"role").read_text().strip(),"client")
            self.assertEqual(sc.read_json(sc.STATE)["status"],"INSTALLING")
            sc.setup("client","https://mirror.example/wheel")
            self.assertEqual(sc.read_json(sc.STATE)["status"],"DIRECT")
            sc.setup("client","https://mirror.example/wheel")
            self.assertEqual(sc.read_json(sc.STATE)["status"],"DIRECT")
            self.assertEqual(wheel.call_count,3)

    def test_first_install_recovers_from_interrupted_unit_or_timer(self):
        for failing in ("daemon-reload","enable"):
            with self.subTest(failing=failing):
                with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
                    root=Path(d); etc=root/"etc";state_dir=root/"state"
                    patches.enter_context(patch.object(sc,"ETC",etc))
                    patches.enter_context(patch.object(sc,"STATE_DIR",state_dir))
                    patches.enter_context(patch.object(sc,"STATE",state_dir/"state.json"))
                    patches.enter_context(patch.object(sc,"UNIT_DIR",root/"units"))
                    patches.enter_context(patch.object(sc,"CONF",etc/"config.json"))
                    patches.enter_context(patch.object(sc,"SSH_CONF",etc/"ssh_config"))
                    patches.enter_context(patch.object(sc,"KNOWN_HOSTS",etc/"known_hosts"))
                    for name in ("require_root","require_no_teardown","install_requirements",
                                 "install_entrypoint","install_wheel"):
                        patches.enter_context(patch.object(sc,name))
                    patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
                    patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
                    patches.enter_context(patch.object(sc,"is_active",return_value=False))
                    patches.enter_context(patch.object(sc,"boot_id",return_value="boot-one"))
                    patches.enter_context(patch.object(sc,"unit_texts",return_value={
                        sc.GUARD_TIMER:"# Managed by Simple Connect; do not edit directly.\n[Timer]\n"
                    }))
                    counter={"failed":False}
                    def action(command,*units):
                        if command==failing and not counter["failed"]:
                            counter["failed"]=True
                            raise sc.ConnectError(failing+" failed")
                    patches.enter_context(patch.object(sc,"unit_action",side_effect=action))
                    with self.assertRaises(sc.ConnectError):
                        sc.setup("client","https://mirror.example/wheel")
                    self.assertEqual(sc.read_json(sc.STATE)["status"],"INSTALLING")
                    sc.setup("client","https://mirror.example/wheel")
                    self.assertEqual(sc.read_json(sc.STATE)["status"],"DIRECT")

    def test_legacy_role_without_state_is_retryable_only_when_proven_safe(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d); etc=root/"etc"; etc.mkdir()
            (etc/"role").write_text("client\n")
            state_dir=root/"data"
            for field,value in (("ETC",etc),("STATE_DIR",state_dir),("STATE",state_dir/"state.json"),
                                ("UNIT_DIR",root/"units"),("CONF",etc/"config.json"),
                                ("SSH_CONF",etc/"ssh_config"),("KNOWN_HOSTS",etc/"known_hosts")):
                patches.enter_context(patch.object(sc,field,value))
            for name in ("require_root","require_no_teardown","install_requirements",
                         "install_entrypoint","install_wheel","unit_action"):
                patches.enter_context(patch.object(sc,name))
            patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
            patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
            patches.enter_context(patch.object(sc,"is_active",return_value=False))
            patches.enter_context(patch.object(sc,"boot_id",return_value="boot-one"))
            patches.enter_context(patch.object(sc,"unit_texts",return_value={}))
            sc.setup("client","https://mirror.example/wheel")
            self.assertEqual(sc.read_json(sc.STATE)["status"],"DIRECT")

    def test_teardown_reservation_blocks_on_off_configure_and_setup(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d); etc=root/"etc"; etc.mkdir()
            (etc/"role").write_text("client\n")
            state_dir=root/"state";state_dir.mkdir()
            state=state_dir/"state.json"
            state.write_text('{"schema":1,"status":"DIRECT"}')
            teardown=state_dir/"uninstalling.json"
            teardown.write_text('{"schema":1,"status":"REMOVING"}')
            for field,value in (("ETC",etc),("STATE_DIR",state_dir),("STATE",state),
                                ("TEARDOWN",teardown),("CONF",etc/"config.json"),
                                ("SSH_CONF",etc/"ssh_config"),("KNOWN_HOSTS",etc/"known_hosts")):
                patches.enter_context(patch.object(sc,field,value))
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                sc.start_proxy()
            with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                sc.stop_proxy()
            with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                sc.configure("8.8.8.8","root",22,"/tmp/key","bad")
            with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                sc.setup("client","https://mirror.example/wheel")

    def test_timer_disable_failure_preserves_code_and_uninstall_marker(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d); etc=root/"etc"; etc.mkdir()
            (etc/"role").write_text("client\n")
            state_dir=root/"data";state_dir.mkdir()
            state=state_dir/"state.json"
            state.write_text('{"schema":1,"status":"DIRECT"}')
            app=root/"manager.py";app.write_text("installed")
            teardown=state_dir/"uninstalling.json"
            for field,value in (("ETC",etc),("STATE_DIR",state_dir),("STATE",state),
                                ("TEARDOWN",teardown),("APP",app),("UNIT_DIR",root/"units"),
                                ("CONF",etc/"config.json"),("SSH_CONF",etc/"ssh_config"),
                                ("KNOWN_HOSTS",etc/"known_hosts")):
                patches.enter_context(patch.object(sc,field,value))
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            patches.enter_context(patch.object(sc,"process_birth",return_value="born"))
            patches.enter_context(patch.object(sc,"boot_id",return_value="boot-one"))
            patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
            patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
            patches.enter_context(patch.object(sc,"stop_proxy"))
            patches.enter_context(patch.object(sc,"unit_action",side_effect=sc.ConnectError("timer disable failed")))
            with self.assertRaisesRegex(sc.ConnectError,"timer disable failed"):
                sc.uninstall(True)
            self.assertTrue(teardown.exists())
            self.assertTrue(app.exists())
            self.assertTrue((etc/"role").exists())
            self.assertEqual(sc.read_json(state)["status"],"DIRECT")

    def test_stale_teardown_marker_allows_safe_retry_but_not_concurrent_retry(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d);state_dir=root/"data";state_dir.mkdir()
            teardown=state_dir/"uninstalling.json"
            with patch.object(sc,"TEARDOWN",teardown),patch.object(sc,"STATE",state_dir/"state.json"):
                sc.write_json(sc.STATE,{"status":"DIRECT"})
                sc.write_json(teardown,{"status":"REMOVING","phase":"RESERVED","boot":"boot","pid":1234,"birth":"old"})
                with patch.object(sc,"boot_id",return_value="boot"):
                    with patch.object(sc,"process_birth",side_effect=lambda pid: "old" if pid==1234 else "now"):
                        with self.assertRaisesRegex(sc.ConnectError,"Another uninstall"):
                            sc.reserve_uninstall()
                    with patch.object(sc,"process_birth",side_effect=lambda pid: "now" if pid==os.getpid() else None):
                        sc.reserve_uninstall()
                self.assertEqual(sc.read_json(teardown)["pid"],os.getpid())

    def test_guard_preserves_incomplete_install_state(self):
        with patch.object(sc,"locked",return_value=nullcontext()),patch.object(sc,"read_json",
                          return_value={"status":"INSTALLING","boot":"old-boot"}):
            with patch.object(sc,"service_terminated",return_value=True),patch.object(sc,"any_proxy_tables",return_value=False):
                with patch.object(sc,"write_json") as save,patch.object(sc,"stop_and_recover") as stop:
                    sc.guarded_check()
                    save.assert_not_called()
                    stop.assert_not_called()

    def test_inflight_on_cannot_commit_after_uninstall_reservation(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d);state_dir=root/"state";state_dir.mkdir()
            state=state_dir/"state.json";teardown=state_dir/"uninstalling.json"
            patches.enter_context(patch.object(sc,"STATE",state))
            patches.enter_context(patch.object(sc,"TEARDOWN",teardown))
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"require_client_role"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            patches.enter_context(patch.object(sc,"read_config",return_value={"remote_ip":"8.8.8.8"}))
            patches.enter_context(patch.object(sc,"ensure_stopped"))
            patches.enter_context(patch.object(sc,"is_active",return_value=True))
            patches.enter_context(patch.object(sc,"initial_ssh_connection",
                              return_value="198.51.100.1 12345 203.0.113.2 22 123"))
            patches.enter_context(patch.object(sc,"remote_python_test"))
            patches.enter_context(patch.object(sc,"effective_exclusions",return_value=list(sc.EXCLUDED)))
            patches.enter_context(patch.object(sc,"choose_port",return_value=24567))
            patches.enter_context(patch.object(sc,"boot_id",return_value="b"))
            patches.enter_context(patch.object(sc,"boot_seconds",return_value=1000))
            table={"nftables":[{"table":{"name":"sshuttle-ipv4-24567","family":"inet"}}]}
            patches.enter_context(patch.object(sc,"current_table",return_value=table))
            def concurrent_uninstall(action,*units):
                if action=="start":
                    sc.write_json(teardown,{"status":"REMOVING"})
            patches.enter_context(patch.object(sc,"unit_action",side_effect=concurrent_uninstall))
            stopped=patches.enter_context(patch.object(sc,"stop_and_recover"))
            with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                sc.start_proxy()
            stopped.assert_called_once_with("failed_activation")
            self.assertEqual(sc.read_json(state)["status"],"PENDING")
            self.assertTrue(teardown.exists())

    def test_service_run_refuses_teardown_marker_before_exec(self):
        with patch.object(sc,"require_root"),patch.object(sc,"require_client_role"):
            with patch.object(sc,"require_no_teardown",side_effect=sc.ConnectError("uninstall is pending")):
                with patch.object(os,"execvpe") as execv:
                    with self.assertRaisesRegex(sc.ConnectError,"uninstall is pending"):
                        sc.service_run()
                    execv.assert_not_called()

    def test_guard_expires_pending_by_boottime_even_if_wall_clock_moves(self):
        state={"status":"PENDING","boot":"b","deadline_boot":100,"started_boot":30,
               "table_sha256":"a"*64}
        with patch.object(sc,"locked",return_value=nullcontext()),patch.object(sc,"read_json",return_value=state):
            with patch.object(sc,"boot_id",return_value="b"):
                with patch.object(sc,"boot_seconds",return_value=100):
                    with patch.object(sc.time,"time",return_value=-1000000000):
                        with patch.object(sc,"is_active",return_value=True):
                            with patch.object(sc,"current_table",return_value={"nftables":[]}):
                                with patch.object(sc,"stop_and_recover") as stop:
                                    sc.guarded_check()
                                    stop.assert_called_once_with("guard")

    def test_cli_setup_holds_lock_but_configure_manages_its_own_short_locks(self):
        with patch.object(sys, "argv", ["simple_connect.py", "setup", "server"]), (
             patch.object(sc, "locked", return_value=nullcontext())) as gate, (
             patch.object(sc, "setup")):
            self.assertEqual(sc.main(), 0)
            gate.assert_called_once_with(wait_seconds=6)

        # No lock may be held while interactive SSH/password prompts run.
        with patch.object(sys, "argv", ["simple_connect.py", "configure"]), (
             patch.object(sc, "locked", return_value=nullcontext())) as gate, (
             patch.object(sc, "configure")) as configure:
            self.assertEqual(sc.main(), 0)
            gate.assert_not_called()
            configure.assert_called_once_with(None, None, None, None, None)

    def test_late_uninstall_is_resumable_after_each_crash_window(self):
        # The same verified-manager function is used on the resumed call.
        # Every scenario simulates one process dying AFTER a side effect,
        # then a distinct process acquiring the durable reservation.
        checkpoints = (
            "before_timer_disable", "after_timer_disable",
            "after_first_unit_deletion", "after_all_unit_deletions",
            "after_daemon_reload", "after_manager_removal",
            "after_state_removal", "after_role_removal",
            "after_reservation_removal",
        )
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint):
                with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
                    root = Path(d)
                    etc = root / "etc"
                    data = root / "data"
                    unitdir = root / "units"
                    etc.mkdir()
                    data.mkdir()
                    unitdir.mkdir()
                    files = {
                        "ETC": etc, "STATE_DIR": data,
                        "STATE": data / "state.json",
                        "TEARDOWN": data / "uninstalling.json",
                        "UNIT_DIR": unitdir,
                        "CONF": etc / "config.json",
                        "SSH_CONF": etc / "ssh_config",
                        "KNOWN_HOSTS": etc / "known_hosts",
                        "APP": root / "manager.py",
                        "COMMAND": root / "simple-connect",
                        "PKG": root / "sshuttle",
                    }
                    for field, value in files.items():
                        patches.enter_context(patch.object(sc, field, value))
                    sc.write_json(sc.STATE, {"status": "DIRECT"})
                    (etc / "role").write_text("client\n")
                    sc.APP.write_text("verified manager")
                    sc.COMMAND.write_text("manager entrypoint")
                    sc.CONF.write_text("config")
                    sc.SSH_CONF.write_text("ssh config")
                    sc.KNOWN_HOSTS.write_text("known hosts")
                    sc.PKG.mkdir()
                    (sc.PKG / ".wheel-sha256").write_text(sc.WHEEL_SHA256 + "\n")
                    units = sc.unit_texts()
                    for name, body in units.items():
                        (unitdir / name).write_text(body)
                    foreign = unitdir / "outside.service"
                    foreign.write_text("NOT SIMPLE CONNECT")
                    ssh = root / "system-ssh"
                    ssh.write_text("SSH MUST SURVIVE")
                    patches.enter_context(patch.object(sc, "require_root"))
                    patches.enter_context(patch.object(sc, "locked", return_value=nullcontext()))
                    patches.enter_context(patch.object(sc, "boot_id", return_value="boot"))
                    patches.enter_context(patch.object(sc, "service_terminated", return_value=True))
                    patches.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))
                    patches.enter_context(patch.object(sc, "stop_proxy"))
                    # Old and resumed calls have different process birth IDs.
                    attempt = [0]
                    patches.enter_context(patch.object(sc, "process_birth",
                        side_effect=lambda pid: "birth-" + str(attempt[0])))
                    timer_active = [True]
                    patches.enter_context(patch.object(sc, "is_active",
                        side_effect=lambda name: timer_active[0] if name == sc.GUARD_TIMER else False))
                    def fake_run(argv, **kwargs):
                        if argv[:2] == ["systemctl", "is-enabled"]:
                            enabled = timer_active[0]
                            return subprocess.CompletedProcess(argv, 0 if enabled else 1,
                                "enabled\n" if enabled else
                                ("disabled\n" if (unitdir / sc.GUARD_TIMER).exists()
                                 else "not-found\n"), "")
                        raise AssertionError("Unexpected system command " + repr(argv))
                    patches.enter_context(patch.object(sc, "run", side_effect=fake_run))

                    armed = [True]
                    real_unlink = Path.unlink
                    unit_to_crash = next(iter(units))
                    def interrupted_unlink(path, *args, **kwargs):
                        result = real_unlink(path, *args, **kwargs)
                        trigger = (
                            (checkpoint == "after_first_unit_deletion" and path == unitdir / unit_to_crash)
                            or (checkpoint == "after_manager_removal" and path == sc.APP)
                            or (checkpoint == "after_state_removal" and path == sc.STATE)
                            or (checkpoint == "after_role_removal" and path == etc / "role")
                            or (checkpoint == "after_reservation_removal" and path == sc.TEARDOWN)
                        )
                        if armed[0] and trigger:
                            armed[0] = False
                            raise RuntimeError("simulated process death: " + checkpoint)
                        return result
                    patches.enter_context(patch.object(Path, "unlink", interrupted_unlink))
                    def fake_unit_action(action, *units_):
                        if action == "disable":
                            if checkpoint == "before_timer_disable" and armed[0]:
                                armed[0] = False
                                raise RuntimeError("simulated process death: " + checkpoint)
                            timer_active[0] = False
                            if checkpoint == "after_timer_disable" and armed[0]:
                                armed[0] = False
                                raise RuntimeError("simulated process death: " + checkpoint)
                        elif action == "daemon-reload":
                            if checkpoint in ("after_all_unit_deletions", "after_daemon_reload") and armed[0]:
                                armed[0] = False
                                raise RuntimeError("simulated process death: " + checkpoint)
                    patches.enter_context(patch.object(sc, "unit_action", side_effect=fake_unit_action))
                    with self.assertRaisesRegex(RuntimeError, "simulated process death"):
                        sc.uninstall(True)
                    self.assertFalse(armed[0], "Checkpoint was not reached.")
                    self.assertEqual(foreign.read_text(), "NOT SIMPLE CONNECT")
                    self.assertEqual(ssh.read_text(), "SSH MUST SURVIVE")
                    attempt[0] += 1
                    # The current process is now dead; retry with a distinct
                    # process birth ID, including after role/state/APP deletion.
                    sc.uninstall(True)
                    for name in units:
                        self.assertFalse((unitdir / name).exists())
                    self.assertFalse(etc.exists())
                    self.assertFalse(data.exists())
                    self.assertFalse(sc.APP.exists())
                    self.assertFalse(sc.COMMAND.exists())
                    self.assertFalse(sc.PKG.exists())
                    self.assertTrue(foreign.exists())
                    self.assertEqual(ssh.read_text(), "SSH MUST SURVIVE")
                    sc.uninstall(True)  # idempotent after full completion

    def test_late_uninstall_rejects_unverified_proxy_and_foreign_unit(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root = Path(d)
            etc = root / "etc"
            data = root / "data"
            units = root / "units"
            etc.mkdir()
            data.mkdir()
            units.mkdir()
            for field, value in (
                ("ETC", etc), ("STATE_DIR", data),
                ("STATE", data / "state.json"), ("TEARDOWN", data / "uninstalling.json"),
                ("UNIT_DIR", units), ("CONF", etc / "config.json"),
                ("SSH_CONF", etc / "ssh_config"), ("KNOWN_HOSTS", etc / "known_hosts"),
                ("APP", root / "manager"), ("COMMAND", root / "command"),
                ("PKG", root / "sshuttle"),
            ):
                patches.enter_context(patch.object(sc, field, value))
            sc.write_json(sc.TEARDOWN, {
                "status": "REMOVING", "phase": "UNITS_REMOVED",
                "boot": "old-boot", "pid": 4000, "birth": "old",
            })
            foreign = units / sc.SERVICE
            foreign.write_text("FOREIGN SERVICE: DO NOT DELETE")
            patches.enter_context(patch.object(sc, "require_root"))
            patches.enter_context(patch.object(sc, "locked", return_value=nullcontext()))
            patches.enter_context(patch.object(sc, "boot_id", return_value="new-boot"))
            attempt=[0]
            patches.enter_context(patch.object(sc, "process_birth",
                                               side_effect=lambda pid: "new-birth-" + str(attempt[0])))
            with patch.object(sc, "service_terminated", return_value=False):
                with patch.object(sc, "any_proxy_tables") as nft:
                    with self.assertRaisesRegex(sc.ConnectError, "Proxy or unknown"):
                        sc.uninstall(True)
                    nft.assert_not_called()
            attempt[0]+=1
            self.assertEqual(foreign.read_text(), "FOREIGN SERVICE: DO NOT DELETE")
            with patch.object(sc, "service_terminated", return_value=True):
                with patch.object(sc, "any_proxy_tables", return_value=True):
                    with self.assertRaisesRegex(sc.ConnectError, "Proxy or unknown"):
                        sc.uninstall(True)
            attempt[0]+=1
            with patch.object(sc, "service_terminated", return_value=True):
                with patch.object(sc, "any_proxy_tables", return_value=False):
                    with patch.object(sc, "run", return_value=subprocess.CompletedProcess([], 1, "not-found\n", "")):
                        with patch.object(sc, "is_active", return_value=False):
                            with self.assertRaisesRegex(sc.ConnectError, "Unexpected modified"):
                                sc.uninstall(True)
            self.assertEqual(foreign.read_text(), "FOREIGN SERVICE: DO NOT DELETE")
            self.assertTrue(sc.TEARDOWN.exists())

    def test_missing_role_without_checkpoint_must_not_adopt_cleanup(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d)
            data=root/"data";data.mkdir()
            etc=root/"etc";etc.mkdir()
            for field,value in (("ETC",etc),("STATE_DIR",data),
                                ("STATE",data/"state.json"),("TEARDOWN",data/"uninstalling.json")):
                patches.enter_context(patch.object(sc,field,value))
            sc.write_json(sc.TEARDOWN,{"status":"REMOVING","phase":"RESERVED",
                                     "boot":"old","pid":4000,"birth":"old"})
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            with self.assertRaisesRegex(sc.ConnectError,"CLIENT role missing before"):
                sc.uninstall(True)
            self.assertTrue(sc.TEARDOWN.exists())

    def test_legacy_unphased_late_teardown_can_resume_only_if_proven_safe(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d)
            etc=root/"etc";etc.mkdir()
            data=root/"data";data.mkdir()
            unitdir=root/"units";unitdir.mkdir()
            fields=(("ETC",etc),("STATE_DIR",data),("STATE",data/"state.json"),
                    ("TEARDOWN",data/"uninstalling.json"),("UNIT_DIR",unitdir),
                    ("CONF",etc/"config.json"),("SSH_CONF",etc/"ssh_config"),
                    ("KNOWN_HOSTS",etc/"known_hosts"),("APP",root/"app"),
                    ("COMMAND",root/"command"),("PKG",root/"sshuttle"))
            for name,path in fields:
                patches.enter_context(patch.object(sc,name,path))
            sc.write_json(sc.TEARDOWN,{"status":"REMOVING","boot":"previous",
                                      "pid":4567,"birth":"previous"})
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            patches.enter_context(patch.object(sc,"boot_id",return_value="current"))
            patches.enter_context(patch.object(sc,"process_birth",return_value="new"))
            patches.enter_context(patch.object(sc,"is_active",return_value=False))
            patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
            patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
            patches.enter_context(patch.object(sc,"run",
                return_value=subprocess.CompletedProcess([],1,"not-found\n","")))
            patches.enter_context(patch.object(sc,"unit_action"))
            sc.uninstall(True)
            self.assertFalse(data.exists())
            self.assertFalse(etc.exists())

    def test_legacy_marker_with_missing_state_does_not_hide_unsafe_units(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as patches:
            root=Path(d);etc=root/"etc";etc.mkdir()
            data=root/"data";data.mkdir()
            units=root/"units";units.mkdir()
            for field,value in (("ETC",etc),("STATE_DIR",data),
                                ("STATE",data/"state.json"),("TEARDOWN",data/"uninstalling.json"),
                                ("UNIT_DIR",units)):
                patches.enter_context(patch.object(sc,field,value))
            sc.write_json(sc.TEARDOWN,{"status":"REMOVING","boot":"old",
                                      "pid":3456,"birth":"old"})
            (units/sc.SERVICE).write_text("FOREIGN")
            patches.enter_context(patch.object(sc,"require_root"))
            patches.enter_context(patch.object(sc,"locked",return_value=nullcontext()))
            patches.enter_context(patch.object(sc,"boot_id",return_value="new"))
            patches.enter_context(patch.object(sc,"process_birth",return_value="new"))
            patches.enter_context(patch.object(sc,"service_terminated",return_value=True))
            patches.enter_context(patch.object(sc,"any_proxy_tables",return_value=False))
            patches.enter_context(patch.object(sc,"is_active",return_value=False))
            patches.enter_context(patch.object(sc,"run",
                return_value=subprocess.CompletedProcess([],1,"not-found\n","")))
            with self.assertRaisesRegex(sc.ConnectError,"Unexpected modified"):
                sc.uninstall(True)
            self.assertEqual((units/sc.SERVICE).read_text(),"FOREIGN")
            self.assertTrue(sc.TEARDOWN.exists())

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
