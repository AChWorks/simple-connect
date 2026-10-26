"""Real 40/80-column PTY acceptance for disposable installed SERVER/CLIENT roles.

The child invokes the real role setup, menu, SSH key selection and configure
flow against isolated filesystem paths. External SSH/systemd/apt/nft operations
are blocked or simulated by role_pty_fixture.py; this is NOT a real-host test.
"""
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "role_pty_fixture.py"
MANAGER = ROOT / "simple_connect.py"


class Session:
    def __init__(self, role: str, variant: str, width: int):
        self.temp = tempfile.TemporaryDirectory(prefix="sc-role-pty-")
        self.root = Path(self.temp.name)
        self.master, slave = pty.openpty()
        self.transcript = b""
        self.cursor = 0
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 35, width, 0, 0))
        self.proc = subprocess.Popen(
            [sys.executable, str(FIXTURE)],
            cwd=ROOT, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True,
            env={**os.environ, "SC_PTY_FIXTURE_ROOT": str(self.root),
                 "SC_PTY_FIXTURE_ROLE": role, "SC_PTY_FIXTURE_VARIANT": variant,
                 "NO_COLOR": "1", "TERM": "dumb", "PYTHONUNBUFFERED": "1"},
        )
        os.close(slave)
        self.width = width

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=4)
        os.close(self.master)
        self.temp.cleanup()

    def send(self, text: str):
        os.write(self.master, text.encode("utf-8"))

    def expect(self, needle: str, timeout: float = 15) -> str:
        pattern = needle.encode("utf-8")
        start = self.cursor
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pos = self.transcript.find(pattern, start)
            if pos != -1:
                end = pos + len(pattern)
                segment = self.transcript[start:end].decode("utf-8", "replace")
                self.cursor = end
                return segment
            ready, _, _ = select.select([self.master], [], [], 0.12)
            if ready:
                try:
                    chunk = os.read(self.master, 32768)
                except OSError:
                    chunk = b""
                self.transcript += chunk
                if not chunk:
                    break
            if self.proc.poll() is not None and not ready:
                break
        raise AssertionError(
            f"Installed {self.width}-col PTY missed {needle!r}, "
            f"process={self.proc.poll()}, recent={self.transcript[-3000:]!r}")

    def choose(self, option: str, until: str = "Press Enter to return to the menu") -> str:
        self.send(option + "\n")
        return self.expect(until)

    def back_to_menu(self):
        self.send("\n")
        return self.expect("Choose:")

    def finish(self):
        self.send("0\n")
        rc = self.proc.wait(timeout=10)
        if rc != 0:
            raise AssertionError(
                f"Role fixture exited {rc}: {self.transcript[-2400:]!r}")

    def metadata(self, intro: str, field: str) -> str:
        match = re.search(r"(?m)^PTY_FIXTURE_" + re.escape(field) + r"=([^\r\n]+)", intro)
        if match is None:
            raise AssertionError(f"Missing role fixture field {field}: {intro[-2000:]!r}")
        return match.group(1)


class InstalledRolePTYTests(unittest.TestCase):
    def test_server_installed_setup_repeat_menu12_and_algorithm_fallback(self):
        for width in (40, 80):
            for variant, expected in (("ed", "ED25519"), ("ec", "ECDSA"),
                                      ("rsa", "RSA"), ("none", "NO SAFE SUPPORTED")):
                with self.subTest(width=width, variant=variant), Session("server", variant, width) as s:
                    intro = s.expect("Choose:", timeout=25)
                    self.assertIn("PTY_FIXTURE_READY", intro)
                    self.assertIn("SERVER role installed", intro)
                    self.assertIn("SERVER fingerprints/Advanced", intro)
                    self.assertIn("Turn ON (CLIENT only)", intro)
                    self.assertNotIn("\x1b[", intro)
                    self.assertIn(expected, intro)

                    repeated = s.choose("1")
                    self.assertIn("SERVER role installed", repeated)
                    self.assertIn(expected, repeated)
                    s.back_to_menu()
                    s.send("12\n")
                    default = s.expect("[y/N]")
                    self.assertIn(expected, default)
                    if variant != "none":
                        self.assertIn("UNVERIFIED", default)
                    else:
                        self.assertIn("NO SAFE SUPPORTED", default)
                    if variant != "none":
                        fp = s.metadata(intro, "FP")
                        self.assertIn(fp, default)
                    s.send("y\n")
                    advanced = s.expect("Press Enter to return to the menu")
                    self.assertIn("Public path:", advanced)
                    self.assertIn("Private pair:", advanced)
                    if variant == "ed":
                        self.assertIn("PAIR MATCH", advanced)
                    else:
                        self.assertIn("HOST KEY NOT READY", advanced)
                    if variant == "none":
                        self.assertIn("NO SAFE SUPPORTED", default)
                    s.back_to_menu()
                    denied = s.choose("3")
                    self.assertIn("CLIENT role", denied)
                    s.back_to_menu()
                    s.finish()

    def test_client_bad_input_mismatch_retry_and_successful_reentry(self):
        for width in (40, 80):
            with self.subTest(width=width), Session("client", "ed", width) as s:
                intro = s.expect("Choose:", timeout=25)
                key = s.metadata(intro, "KEY")
                fp = s.metadata(intro, "FP")
                self.assertIn("Client installed (Direct/OFF)", intro)
                self.assertIn("DIRECT", intro)
                self.assertIn("Configure SSH connection", intro)
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.send("8.8.8.8\n")
                s.expect("2/5 SERVER")
                s.send("root\n")
                s.expect("3/5 SERVER")
                s.send("22022\n")
                s.expect("4/5 CLIENT")
                s.send("SHA256:" + "A" * 43 + "\n")
                mistake = s.expect("4/5 CLIENT")
                self.assertIn("SERVER host fingerprint", mistake)
                s.send("relative-key\n")
                invalid = s.expect("4/5 CLIENT")
                self.assertIn("Unsafe SSH identity path", invalid)
                s.send("ssh-ed25519 AAAA publickey\n")
                public = s.expect("4/5 CLIENT")
                self.assertIn("PUBLIC key text", public)
                s.send(key + "\n")
                s.expect("5/5 Trusted")
                s.send("SHA256:" + "A" * 43 + "\n")
                s.expect("Retry fingerprint entry?")
                s.send("n\n")
                cancelled = s.expect("Press Enter to return to the menu")
                self.assertIn("configuration cancelled", cancelled)
                self.assertFalse((s.root / "etc" / "config.json").exists())
                s.back_to_menu()
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.send("8.8.8.8\n")
                s.expect("2/5 SERVER")
                s.send("root\n")
                s.expect("3/5 SERVER")
                s.send("22022\n")
                s.expect("4/5 CLIENT")
                s.send(key + "\n")
                s.expect("5/5 Trusted")
                s.send(fp + "\n")
                before_enrollment = s.expect("Authorize public-key enrollment")
                self.assertIn("host key pinned", before_enrollment)
                s.send("n\n")
                after_enrollment = s.expect("Test the remote SSH login")
                self.assertIn("enrollment cancelled", after_enrollment)
                s.send("n\n")
                done = s.expect("Press Enter to return to the menu")
                self.assertIn("Test HTTPS", done)
                conf = (s.root / "etc" / "ssh_config").read_text()
                self.assertIn("StrictHostKeyChecking yes", conf)
                self.assertIn("UpdateHostKeys no", conf)
                self.assertTrue((s.root / "etc" / "known_hosts").is_file())
                self.assertFalse((s.root / "enrollment-simulated").exists())
                s.back_to_menu()
                s.finish()

    def test_client_generation_needs_y_and_preserves_cancel_and_enrollment_choice(self):
        for width in (40, 80):
            with self.subTest(width=width), Session("client", "ed", width) as s:
                intro = s.expect("Choose:", timeout=25)
                fp = s.metadata(intro, "FP")
                dedicated = Path(s.metadata(intro, "DEDICATED"))
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.send("8.8.8.8\n")
                s.expect("2/5 SERVER")
                s.send("root\n")
                s.expect("3/5 SERVER")
                s.send("22022\n")
                s.expect("4/5 CLIENT")
                s.send("\n")
                s.expect("[y/N]")
                s.send("\n")
                s.expect("4/5 CLIENT")
                self.assertFalse(dedicated.exists())
                s.send("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                pasted = s.expect("4/5 CLIENT")
                self.assertIn("SSH key CONTENT", pasted)
                self.assertFalse(dedicated.exists())
                s.send("\n")
                s.expect("[y/N]")
                s.send("n\n")
                s.expect("4/5 CLIENT")
                self.assertFalse(dedicated.exists())
                s.send("\n")
                s.expect("[y/N]")
                s.send("y\n")
                new_key = s.expect("5/5 Trusted")
                self.assertIn("New SSH key created", new_key)
                self.assertTrue(dedicated.is_file())
                self.assertEqual(dedicated.stat().st_mode & 0o777, 0o600)
                s.send(fp + "\n")
                s.expect("Authorize public-key enrollment")
                s.send("y\n")
                enrolled = s.expect("Test the remote SSH login")
                self.assertIn("Public-key enrollment finished", enrolled)
                s.send("n\n")
                done = s.expect("Press Enter to return to the menu")
                self.assertIn("Test HTTPS", done)
                self.assertTrue((s.root / "enrollment-simulated").is_file())
                s.back_to_menu()
                s.finish()

    def test_client_cancel_ctrl_c_eof_and_non_tty_refusal(self):
        for width in (40, 80):
            with self.subTest(width=width), Session("client", "ed", width) as s:
                intro = s.expect("Choose:", timeout=25)
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.send("b\n")
                cancelled = s.expect("Press Enter to return to the menu")
                self.assertIn("Setup cancelled", cancelled)
                s.back_to_menu()
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.proc.send_signal(signal.SIGINT)
                interrupted = s.expect("Press Enter to return to the menu")
                self.assertIn("Operation interrupted", interrupted)
                s.back_to_menu()
                self.assertFalse((s.root / "etc" / "config.json").exists())
                s.send("3\n")
                s.expect("1/5 SERVER")
                s.send("\x04")
                response = s.expect("Input ended")
                self.assertIn("Input ended", response)
                self.assertEqual(s.proc.wait(timeout=8), 0)
        with tempfile.TemporaryDirectory() as d:
            out = subprocess.run([sys.executable, str(FIXTURE)], cwd=ROOT,
                 env={**os.environ, "SC_PTY_FIXTURE_ROOT": d,
                      "SC_PTY_FIXTURE_ROLE": "client", "SC_PTY_FIXTURE_VARIANT": "ed",
                      "NO_COLOR": "1", "TERM": "dumb"},
                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=25)
            self.assertEqual(out.returncode, 1, out.stderr[-1200:])
            self.assertIn("requires a terminal", out.stdout)


if __name__ == "__main__":
    unittest.main()
