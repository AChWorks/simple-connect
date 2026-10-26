"""R1 findings: hermetic public-key, path, and concurrency regression checks."""

import contextlib
from concurrent.futures import ThreadPoolExecutor
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc

FP = "SHA256:" + "A" * 43


class RemediationTests(unittest.TestCase):
    def make_key(self, root, name="identity"):
        key = root / name
        p = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(key)], capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        return key

    def host_record(self, key, ip, port):
        fields=Path(str(key)+".pub").read_text().split()
        label=ip if port==22 else f"[{ip}]:{port}"
        record=f"{label} {fields[0]} {fields[1]}\n"
        fp=sc.pinned_host_identity({"remote_ip":ip,"ssh_port":port},record.encode())
        return record,fp

    def fixture(self, stack, root, cfg=None):
        etc = root / "etc"
        etc.mkdir()
        state = root / "state.json"
        sc.write_json(state, {"status": "DIRECT"})
        objects = {"ETC": etc, "STATE": state, "LOCK": root / "manager.lock",
                   "CONF": etc / "config.json", "SSH_CONF": etc / "ssh_config",
                   "KNOWN_HOSTS": etc / "known_hosts"}
        for k, value in objects.items():
            stack.enter_context(patch.object(sc, k, value))
        for k in ("require_root", "require_client_role", "require_no_teardown"):
            stack.enter_context(patch.object(sc, k))
        stack.enter_context(patch.object(sc, "service_terminated", return_value=True))
        stack.enter_context(patch.object(sc, "any_proxy_tables", return_value=False))
        if cfg:
            sc.write_json(objects["CONF"], cfg)
        return objects

    def fake_host(self, args, **kw):
        if args[0] == "ssh-keyscan":
            return subprocess.CompletedProcess(args, 0, args[-1] + " ssh-ed25519 AAAAPIN\n", "")
        if args[0] == "ssh-keygen":
            return subprocess.CompletedProcess(args, 0, "256 " + FP + " host\n", "")
        self.fail(f"External command unexpectedly reached: {args}")

    def test_single_public_record_and_extra_record_rejections(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            key=self.make_key(root)
            pub=Path(str(key)+".pub")
            original=pub.read_bytes()
            self.assertEqual(sc.validated_public_key(key),pub)
            bad=(original+original, original+b"# extra\n", original+b"\n",
                 b"from=\"*\" "+original, original+b"\x00", b"not-a-key AAAA\n")
            for content in bad:
                with self.subTest(suffix=content[-30:]):
                    pub.write_bytes(content)
                    with self.assertRaises(sc.ConnectError):
                        sc.validated_public_key(key)
            pub.write_bytes(original)
            self.assertEqual(sc.validated_public_key(key),pub)

    def test_extra_keys_prevent_remote_action(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as st:
            root=Path(d)
            key=self.make_key(root)
            pub=Path(str(key)+".pub")
            original=pub.read_bytes()
            cfg={"remote_ip":"8.8.8.8","ssh_user":"root","ssh_port":56777,"identity_file":str(key)}
            objs=self.fixture(st,root,cfg)
            rec,_=self.host_record(self.make_key(root,"host"),"8.8.8.8",56777)
            objs["KNOWN_HOSTS"].write_text(rec)
            st.enter_context(patch.object(sc,"yes_no",return_value=True))
            st.enter_context(patch.object(sc,"run",return_value=subprocess.CompletedProcess([],0,original.decode(),"")))
            remote=st.enter_context(patch.object(sc.subprocess,"run"))
            for content in (original+original,original+b"# comment record\n",original+b"\n"):
                pub.write_bytes(content)
                with self.assertRaises(sc.ConnectError):
                    sc.enroll_public_key()
                remote.assert_not_called()

    def test_safely_constrained_identity_path_and_owned_ancestors(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            names=["key$(id)","key;touch","key&","key|cat","key#tag",
                   "key space","key[1]","key'quote","key>out","key:colon",
                   "key"+chr(96)+"id"+chr(96)]
            for name in names:
                with self.subTest(name=name),self.assertRaisesRegex(sc.ConnectError,"Unsafe SSH identity path"):
                    sc.checked_key_name(str(root/name))
            folder=root/"writable"
            folder.mkdir()
            key=self.make_key(folder)
            folder.chmod(0o777)
            with self.assertRaisesRegex(sc.ConnectError,"writable by others"):
                sc.private_key_path(str(key))
            folder.chmod(0o700)
            self.assertEqual(sc.private_key_path(str(key)),key)
            alias=root/"alias"
            alias.symlink_to(folder,target_is_directory=True)
            with self.assertRaisesRegex(sc.ConnectError,"symlink|ownership"):
                sc.private_key_path(str(alias/"identity"))

    def test_changed_private_key_during_derivation_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            key=self.make_key(root)
            alternate=self.make_key(root,"other")
            def replacement(args,**kwargs):
                os.replace(alternate,key)
                return subprocess.CompletedProcess([],0,Path(str(key)+".pub").read_text(),"")
            with patch.object(sc,"run",side_effect=replacement):
                with self.assertRaisesRegex(sc.ConnectError,"changed during validation"):
                    sc.validated_public_key(key)

    def test_safe_single_key_enrollment_no_shell_agent_inheritance(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as st:
            root=Path(d)
            key=self.make_key(root)
            cfg={"remote_ip":"8.8.8.8","ssh_user":"root","ssh_port":56777,"identity_file":str(key)}
            objs=self.fixture(st,root,cfg)
            host_line,host_fp=self.host_record(self.make_key(root,"host"),"8.8.8.8",56777)
            objs["KNOWN_HOSTS"].write_text(host_line)
            pub=Path(str(key)+".pub")
            st.enter_context(patch.object(sc,"run",
                return_value=subprocess.CompletedProcess([],0,pub.read_text(),"")))
            st.enter_context(patch.object(sc,"yes_no",return_value=True))
            checked={}
            def remote_cmd(args,**kwargs):
                checked["args"]=list(args)
                staging_pub=Path(args[args.index("-i")+1])
                staging_hosts=Path(next(a.split("=",1)[1] for a in args if a.startswith("UserKnownHostsFile=")))
                self.assertNotEqual(staging_pub,pub)
                self.assertNotEqual(staging_hosts,objs["KNOWN_HOSTS"])
                self.assertEqual(sc.read_public_key_record(staging_pub),sc.read_public_key_record(pub))
                self.assertEqual(staging_hosts.read_text(),host_line)
                self.assertEqual(sc.pinned_host_identity(cfg,staging_hosts.read_bytes()),host_fp)
                return subprocess.CompletedProcess(args,0,"","")
            remote=st.enter_context(patch.object(sc.subprocess,"run",side_effect=remote_cmd))
            sc.enroll_public_key()
            self.assertEqual(remote.call_count,1)
            args=checked["args"]
            self.assertEqual(args[0],"/usr/bin/ssh-copy-id")
            self.assertEqual(args[-1],"root@8.8.8.8")
            self.assertIn("StrictHostKeyChecking=yes",args)
            self.assertIn("GlobalKnownHostsFile=/dev/null",args)
            self.assertIn("UpdateHostKeys=no",args)
            env=remote.call_args.kwargs["env"]
            self.assertEqual(env["HOME"],"/root")
            self.assertEqual(env["PATH"],"/usr/sbin:/usr/bin:/sbin:/bin")
            self.assertNotIn("SSH_AUTH_SOCK",env)


    def test_simultaneous_configure_only_one_wins(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as st:
            root=Path(d)
            key=self.make_key(root)
            server=self.make_key(root,"host")
            _,host_fp=self.host_record(server,"8.8.8.8",56777)
            host_blob=Path(str(server)+".pub").read_text().split()[1]
            objs=self.fixture(st,root)
            barrier=threading.Barrier(2,timeout=6)
            def fake_run(args,**kwargs):
                if args[0]=="ssh-keyscan":
                    barrier.wait()
                    return subprocess.CompletedProcess(args,0,
                        f"[{args[-1]}]:56777 ssh-ed25519 {host_blob}\n","")
                if args[0]=="ssh-keygen":
                    return subprocess.CompletedProcess(args,0,f"256 {host_fp} host\n","")
                self.fail(f"Unexpected command: {args}")
            st.enter_context(patch.object(sc,"run",side_effect=fake_run))
            def configure_one(host):
                try:
                    sc.configure(host,"root",56777,str(key),host_fp)
                    return ("OK",host)
                except sc.ConnectError as e:
                    return ("ERROR",str(e))
            with ThreadPoolExecutor(max_workers=2) as pool:
                future1=pool.submit(configure_one,"8.8.8.8")
                future2=pool.submit(configure_one,"9.9.9.9")
                outcomes=[future1.result(timeout=12),future2.result(timeout=12)]
            self.assertEqual(sum(x=="OK" for x,_ in outcomes),1,outcomes)
            errors=[x for kind,x in outcomes if kind=="ERROR"]
            self.assertEqual(len(errors),1,outcomes)
            self.assertIn("changed during setup",errors[0])
            winner=[x for kind,x in outcomes if kind=="OK"][0]
            self.assertEqual(sc.read_json(objs["CONF"])["remote_ip"],winner)
            self.assertIn(winner,objs["SSH_CONF"].read_text())
            self.assertIn(winner,objs["KNOWN_HOSTS"].read_text())

    def test_concurrent_key_generation_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/".ssh"/"simple_connect_ed25519"
            barrier=threading.Barrier(2,timeout=6)
            def create():
                barrier.wait()
                try:
                    return ("OK",sc.create_dedicated_key())
                except sc.ConnectError as e:
                    return ("ERROR",str(e))
            with patch.object(sc,"KEY_PATH",key),patch.object(sc,"require_root"), (
                 patch("builtins.input",side_effect=AssertionError("Overwrite prompt prohibited"))):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    tasks=[pool.submit(create) for _ in range(2)]
                    results=[t.result(timeout=15) for t in tasks]
            self.assertEqual(sum(k=="OK" for k,_ in results),1,results)
            self.assertIn("already exists",str(results))
            self.assertEqual(sc.validated_public_key(key),Path(str(key)+".pub"))
            self.assertFalse(list(key.parent.glob(".sc-keygen-*")))

    def test_existing_partial_keypair_and_mid_publish_collision(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)/".ssh"
            folder.mkdir(mode=0o700)
            folder.chmod(0o700)  # Independent of the test runner's umask.
            key=folder/"simple_connect_ed25519"
            pub=Path(str(key)+".pub")
            with patch.object(sc,"KEY_PATH",key),patch.object(sc,"require_root"):
                pub.write_bytes(b"preexisting public data\n")
                with self.assertRaisesRegex(sc.ConnectError,"already exists"):
                    sc.create_dedicated_key()
                self.assertFalse(key.exists())
                self.assertEqual(pub.read_bytes(),b"preexisting public data\n")
                pub.unlink()
                original_link=os.link
                def collision(src,dst,**kwargs):
                    if Path(dst)==pub:
                        pub.write_bytes(b"racing public data\n")
                    return original_link(src,dst,**kwargs)
                with patch.object(sc.os,"link",side_effect=collision):
                    with self.assertRaisesRegex(sc.ConnectError,"Another public key appeared"):
                        sc.create_dedicated_key()
                self.assertFalse(key.exists())
                self.assertEqual(pub.read_bytes(),b"racing public data\n")
                self.assertFalse(list(folder.glob(".sc-keygen-*")))
                pub.unlink()
                self.make_key(folder,"simple_connect_ed25519")
                pub.unlink()
                original=key.read_bytes()
                with self.assertRaisesRegex(sc.ConnectError,"already exists"):
                    sc.create_dedicated_key()
                self.assertEqual(key.read_bytes(),original)

    def test_symlinked_public_key_refused_without_remote_action(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as st:
            root=Path(d)
            key=self.make_key(root)
            other=self.make_key(root,"other")
            pub=Path(str(key)+".pub")
            pub.unlink()
            pub.symlink_to(str(other)+".pub")
            objects=self.fixture(st,root,{
                "remote_ip":"8.8.8.8","ssh_user":"root","ssh_port":22,
                "identity_file":str(key)})
            line,_=self.host_record(self.make_key(root,"host"),"8.8.8.8",22)
            objects["KNOWN_HOSTS"].write_text(line)
            st.enter_context(patch.object(sc,"yes_no",return_value=True))
            st.enter_context(patch.object(sc,"run",return_value=subprocess.CompletedProcess([],0,
                Path(str(other)+".pub").read_text(),"")))
            remote=st.enter_context(patch.object(sc.subprocess,"run"))
            with self.assertRaisesRegex(sc.ConnectError,"symlinked public"):
                sc.enroll_public_key()
            remote.assert_not_called()

    def test_untrusted_parent_ownership_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            folder=root/"owned"
            folder.mkdir(mode=0o700)
            key=self.make_key(folder)
            real_lstat=os.lstat
            def fake_lstat(path):
                info=real_lstat(path)
                if Path(path)==folder:
                    class ForeignOwner:
                        st_mode=info.st_mode
                        st_uid=98765432
                    return ForeignOwner()
                return info
            with patch.object(sc.os,"lstat",side_effect=fake_lstat):
                with self.assertRaisesRegex(sc.ConnectError,"untrusted"):
                    sc.private_key_path(str(key))

    def test_staged_generation_failure_does_not_publish_partial_pair(self):
        with tempfile.TemporaryDirectory() as d:
            key=Path(d)/".ssh"/"simple_connect_ed25519"
            with patch.object(sc,"KEY_PATH",key),patch.object(sc,"require_root"), (
                 patch.object(sc,"run",side_effect=sc.ConnectError("Test ssh-keygen failure"))):
                with self.assertRaisesRegex(sc.ConnectError,"Test ssh-keygen failure"):
                    sc.create_dedicated_key()
            self.assertFalse(key.exists())
            self.assertFalse(Path(str(key)+".pub").exists())
            self.assertFalse(list(key.parent.glob(".sc-keygen-*")))

    def test_no_color_keeps_safe_terminal_clear(self):
        class TTY(io.StringIO):
            def isatty(self): return True
        with patch.dict(os.environ,{"NO_COLOR":"1","TERM":"xterm"},clear=True), (
             patch.object(sc.sys,"stdout",TTY())) as output:
            self.assertEqual(sc.paint("READY","good"),"READY")
            sc.clear_menu()
            self.assertIn("\033[2J\033[H",output.getvalue())


if __name__=="__main__":
    unittest.main()
