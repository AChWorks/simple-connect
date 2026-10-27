"""Actual pseudo-terminal interaction regressions, without root/network mutation.

Unlike patched input() tests, this executes the real manager and terminal
output with a bounded tty. It intentionally does NOT install/activate networking.
"""
import fcntl
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import termios
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / "simple_connect.py"


class InteractivePTYTests(unittest.TestCase):
    def test_narrow_dumb_terminal_full_menu_and_navigation(self):
        master, slave = pty.openpty()
        settings = termios.tcgetattr(slave)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, settings)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 35, 40, 0, 0))
        proc = None
        transcript = b""
        try:
            proc = subprocess.Popen(
                [sys.executable, str(MANAGER)],
                cwd=ROOT,
                stdin=slave, stdout=slave, stderr=slave,
                start_new_session=True,
                env={**os.environ, "NO_COLOR": "1", "TERM": "dumb",
                     "PYTHONUNBUFFERED": "1"},
            )
            os.close(slave)
            slave = -1

            def read_until(pattern: bytes, timeout=8):
                nonlocal transcript
                start = len(transcript)
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if pattern in transcript[start:]:
                        return transcript[start:].decode("utf-8", "replace")
                    ready, _, _ = select.select([master], [], [], 0.1)
                    if ready:
                        try:
                            transcript += os.read(master, 16384)
                        except OSError:
                            break
                    if proc.poll() is not None:
                        break
                self.fail(f"PTY did not render {pattern!r} before timeout: "
                          f"{transcript[-1200:]!r}")

            def enter(value: bytes, needle: bytes):
                os.write(master, value)
                return read_until(needle)

            main = read_until(b"Choose:")
            self.assertIn("SIMPLE CONNECT", main)
            self.assertIn("Show SERVER SSH fingerprints", main)
            self.assertIn("SETUP", main)
            self.assertNotIn("\x1b[", main)
            self.assertIn("   1) Setup remote SERVER", main)
            self.assertIn("   2) Setup Iran CLIENT", main)
            options = [line for line in main.splitlines() if line.strip()
                       and line.lstrip()[:1].isdigit()
                       and ")" in line[:8]]
            self.assertEqual(len(options), 13)
            numbers = [int(line.strip().split(")", 1)[0]) for line in options]
            self.assertEqual(numbers, list(range(1, 13)) + [0],
                             "Menu shortcuts must appear in natural ascending order.")
            self.assertTrue(all(len(line) <= 39 for line in main.splitlines()))

            invalid = enter(b"abc\n", b"Press Enter to return to the menu")
            self.assertIn("Invalid option", invalid)
            enter(b"\n", b"Choose:")

            access = enter(b"11\n", b"Choose:")
            self.assertIn("SSH ACCESS", access)
            self.assertIn("Enroll selected PUBLIC key", access)
            back = enter(b"0\n", b"Choose:")
            self.assertIn("MAIN MENU", back)

            # Do not invoke a real setup or network operation here.
            os.write(master, b"0\n")
            self.assertEqual(proc.wait(timeout=8), 0)
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            if slave != -1:
                os.close(slave)
            os.close(master)


if __name__ == "__main__":
    unittest.main()
