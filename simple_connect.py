#!/usr/bin/env python3
"""Simple Connect: a small, guarded sshuttle manager for Debian Linux hosts.

This file is also the installed management entry point. It never chooses a
remote endpoint or enables traffic during setup. Operator-requested SSH key
creation/enrollment is an explicit, separate interactive step.
"""
from __future__ import annotations

import argparse
import base64
import errno
import contextlib
from dataclasses import dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import textwrap
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

VERSION = "0.1.5"
SCHEMA_VERSION = 1
SSHUTTLE_VERSION = "2.0.0"
# Retain upstream latency control while allowing a full high-RTT bandwidth window.
SSHUTTLE_LATENCY_BUFFER_SIZE = 1_048_576
WHEEL_SHA256 = "506a8cad2f047ca42f0d784654cb3459e2193bfad79d0a03734e0e07473f2bbb"
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/25/1d/"
    "c409e26b9d5d26e6f07466c3d4662abb1c3ca4810424f66f38e1b5e54f33/"
    "sshuttle-2.0.0-py3-none-any.whl"
)
ETC = Path("/etc/simple-connect")
STATE_DIR = Path("/var/lib/simple-connect")
APP = Path("/usr/local/lib/simple-connect/simple_connect.py")
COMMAND = Path("/usr/local/sbin/simple-connect")
PKG = Path("/opt/simple-connect/sshuttle")
CONF = ETC / "config.json"
SSH_CONF = ETC / "ssh_config"
KNOWN_HOSTS = ETC / "known_hosts"
STATE = STATE_DIR / "state.json"
TEARDOWN = STATE_DIR / "uninstalling.json"
LOCK = Path("/run/lock/simple-connect.lock")
TABLE = "sshuttle-ipv4-13080"
PORT = 13080
GUARD_TIMER = "simple-connect-guard.timer"
SERVICE = "simple-connect.service"
GUARD_UNIT = "simple-connect-guard.service"
STOP_UNIT = "simple-connect-stop.service"
UNIT_DIR = Path("/etc/systemd/system")
EXCLUDED = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4",
)


KEY_PATH = Path("/root/.ssh/simple_connect_ed25519")
# RSA host public keys are encoded as ssh-rsa even when the SSH host-key
# SIGNATURE is rsa-sha2-512/256. Never permit the legacy ssh-rsa SHA-1
# signature algorithm in any connection.
HOST_KEY_ALGORITHMS = {
    "ssh-ed25519": "ssh-ed25519",
    "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384": "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521": "ecdsa-sha2-nistp521",
    "ssh-rsa": "rsa-sha2-512,rsa-sha2-256",
}
HOST_KEY_ORDER = tuple(HOST_KEY_ALGORITHMS)
SSH_HOST_DIR = Path("/etc/ssh")
# Never execute an sshd discovered through a potentially user-controlled PATH
# while displaying root-only server diagnostics.
SSH_DAEMON = Path("/usr/sbin/sshd")
COLORS = {
    "title": "\033[1;34m", "heading": "\033[1;36m",
    "good": "\033[1;32m", "warn": "\033[1;33m",
    "error": "\033[1;31m", "muted": "\033[2m",
    "accent": "\033[1;35m",
}


class ConnectError(Exception):
    pass


def color_enabled() -> bool:
    """ANSI only on a real, capable terminal; plain output remains parseable."""
    return (sys.stdout.isatty() and "NO_COLOR" not in os.environ
            and os.environ.get("TERM", "").lower() not in ("", "dumb"))


def terminal_width() -> int:
    """Leave one column for a safe PTY margin; cap long desktop lines."""
    return max(24, min(88, shutil.get_terminal_size(fallback=(80, 24)).columns - 1))


def paint(value: str, tone: str) -> str:
    if not color_enabled():
        return value
    return f"{COLORS[tone]}{value}\033[0m"


def say(message: str, kind: str = "INFO") -> None:
    """Semantic text labels work without color; wrap long notices on real PTYs."""
    tone = {"OK": "good", "WARN": "warn", "ERROR": "error", "INFO": "heading"}
    prefix = f"[{kind}]"
    rows = ([message] if not sys.stdout.isatty()
            else textwrap.wrap(message, width=max(18, terminal_width() - len(prefix) - 1),
                               break_long_words=False, break_on_hyphens=False) or [""])
    print(f"{paint(prefix, tone.get(kind, 'heading'))} {rows[0]}", flush=True)
    for row in rows[1:]:
        print(" " * (len(prefix) + 1) + row, flush=True)


def guidance(message: str) -> str:
    """Human action to take, without hiding original error/provider detail."""
    lower = message.lower()
    if "identity file" in lower or "private key" in lower or "permission" in lower and "key" in lower:
        return "Open Configure SSH to select or create a dedicated SSH key. Never paste a private key into a prompt."
    if "fingerprint" in lower or "host key" in lower:
        return "Use the SERVER fingerprint action on its trusted console; verify the exact selected host key out of band."
    if "permission denied" in lower or "publickey" in lower or "password" in lower and "ssh" in lower:
        return "Use SSH key access in the menu to enroll the public key; remote SSH policy may disallow passwords."
    if "timed out" in lower or "connection refused" in lower or "no route to host" in lower:
        return "Check the remote IP, SSH port, server sshd listener and firewall; retry Test SSH before ON."
    if "uncertain" in lower or "firewall" in lower or "ownership" in lower:
        return "Do not bypass recovery. Keep SSH access; inspect Status and Logs before attempting ON."
    if "not configured" in lower or "configuration missing" in lower or "client role" in lower:
        return "Install the correct role, then use Configure SSH and Test connection from the menu."
    if "uninstall" in lower:
        return "Use the guarded Uninstall option and preserve recovery state when cleanup is incomplete."
    return "Use Status and Logs for details. Resolve the reported problem before trying the action again."


def show_error(exc: BaseException) -> None:
    message = str(exc).strip() or type(exc).__name__
    say(message, "ERROR")
    terminal_note("Next: " + guidance(message), tone="heading")


def fail(message: str) -> None:
    raise ConnectError(message)


def run(argv: list[str], *, check: bool = True, timeout: int = 30, capture: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv, check=check, timeout=timeout, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env={**os.environ, "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except subprocess.TimeoutExpired:
        fail(f"Command timed out after {timeout}s: {argv[0]}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()[-600:]
        fail(f"{argv[0]} failed (exit {exc.returncode}): {detail}")


def require_root() -> None:
    if os.geteuid() != 0:
        fail("Root required. Run: sudo simple-connect <command>")


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        dir_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_json(path: Path, data: dict) -> None:
    atomic_write(path, (json.dumps({"schema": SCHEMA_VERSION, **data}, sort_keys=True, indent=2) + "\n").encode())


def read_json(path: Path, default: dict | None = None) -> dict:
    if path.is_symlink():
        fail(f"Refusing symlinked state file: {path}")
    if not path.exists():
        if default is not None:
            return default.copy()
        fail(f"Configuration missing: {path}. Run setup/configure first.")
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            fail(f"Unsafe state or configuration file: {path}")
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            fail(f"Invalid JSON object: {path}")
        if data.get("schema", SCHEMA_VERSION) != SCHEMA_VERSION:
            fail(f"Unsupported state schema in {path}; upgrade explicitly.")
        return data
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        fail(f"Invalid JSON in {path}: {exc}")


@contextlib.contextmanager
def locked(wait_seconds: float = 0):
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        until = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    fail("Another Simple Connect operation is running. Try again shortly.")
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def is_active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=8).returncode == 0


def unit_action(action: str, *units: str) -> None:
    run(["systemctl", action, *units], timeout=75)


def validate_ipv4(ip: str, *, public: bool = False) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4 or addr.is_unspecified or addr.is_multicast or addr.is_loopback:
            fail(f"Expected a usable IPv4 address: {ip}")
        if public and not addr.is_global:
            fail(f"Remote must use a public IPv4 address: {ip}")
        return str(addr)
    except ValueError:
        fail(f"Invalid IPv4 address: {ip}")


def validate_config(cfg: dict) -> dict:
    if set(cfg) - {"schema"} != {"remote_ip", "ssh_user", "ssh_port", "identity_file"}:
        fail("Unsupported config fields; run 'configure' again.")
    cfg["remote_ip"] = validate_ipv4(str(cfg["remote_ip"]), public=True)
    name = str(cfg["ssh_user"])
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}\$?", name, re.IGNORECASE):
        fail("Invalid SSH username.")
    cfg["ssh_user"] = name
    try:
        port = int(cfg["ssh_port"])
        if not (1 <= port <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        fail("SSH port must be 1..65535.")
    cfg["ssh_port"] = port
    cfg["identity_file"] = str(private_key_path(str(cfg["identity_file"])))
    return cfg


def banner() -> None:
    print(f"\n{paint('SIMPLE CONNECT', 'title')} v{VERSION}")
    print("SSH-based outbound IPv4 TCP / DNS | defaults to DIRECT/OFF\n")


def require_supported_python() -> None:
    if not ((3, 10) <= sys.version_info[:2] < (4, 0)):
        fail("Python >=3.10 and <4.0 is required by official sshuttle 2.0.0.")
    proc = subprocess.run(
        ["/usr/bin/python3", "-c",
         "import sys; assert (3, 10) <= sys.version_info[:2] < (4, 0)"],
        capture_output=True, text=True, timeout=10,
    )
    if proc.returncode != 0:
        fail("System /usr/bin/python3 must be >=3.10 and <4.0.")


def require_client_role() -> None:
    role = ETC / "role"
    if not role.is_file() or role.is_symlink() or role.read_text().strip() != "client":
        fail("This action requires a configured CLIENT role; SERVER role is SSH-only.")



def teardown_pending() -> bool:
    return TEARDOWN.exists() or TEARDOWN.is_symlink()


def require_no_teardown() -> None:
    if teardown_pending():
        fail("Client uninstall is pending; retry 'uninstall --yes' before configuring or activating.")


def process_birth(pid: int) -> str | None:
    """Kernel process start-time identity, not just a reusable PID."""
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text()
        return stat.rsplit(") ", 1)[1].split()[19]
    except (OSError, IndexError, ValueError):
        return None


UNINSTALL_PHASES = ("RESERVED", "STOPPED", "TIMER_DISABLED", "UNITS_REMOVED", "PAYLOAD_REMOVED")


def uninstall_phase(marker: dict) -> str:
    if marker.get("status") != "REMOVING":
        fail("Invalid uninstall reservation; preserve resources for inspection.")
    phase = marker.get("phase", "RESERVED")  # older incomplete reservations
    if phase not in UNINSTALL_PHASES:
        fail("Unknown uninstall phase; refusing unsafe recovery.")
    return phase


def reserve_uninstall() -> str:
    """Reserve or resume teardown with a durable monotonic phase.

    Called under the manager lock. Incomplete teardown is never adopted as
    a fresh client installation, nor is progress reset during resume.
    """
    phase = "RESERVED"
    started = int(time.time())
    if teardown_pending():
        old = read_json(TEARDOWN)
        phase = uninstall_phase(old)
        started = old.get("started", started)
        previous_pid = old.get("pid")
        if (old.get("boot") == boot_id() and type(previous_pid) is int
                and process_birth(previous_pid) is not None
                and process_birth(previous_pid) == old.get("birth")):
            fail("Another uninstall operation remains active; refusing overlap.")
        if "phase" not in old and (
                not (ETC / "role").exists() or not STATE.exists()):
            # A partially removed R3-era installation lacked phase
            # checkpoints. Adopt ONLY a demonstrably post-unit-removal
            # state; never infer safety merely from missing role/state.
            verify_uninstall_network("UNITS_REMOVED")
            verify_uninstall_timer()
            verify_uninstall_units()
            if is_active(GUARD_UNIT) or is_active(STOP_UNIT):
                fail("Legacy teardown has active helper units; manual inspection required.")
            if any((UNIT_DIR / name).exists() or (UNIT_DIR / name).is_symlink()
                   for name in unit_texts()):
                fail("Legacy teardown missing role/state but still has unit files.")
            verify_uninstall_role("UNITS_REMOVED")
            phase = "UNITS_REMOVED"
        say(f"Resuming interrupted client uninstall at {phase}.", "WARN")
    else:
        state = read_json(STATE, {"status": "DIRECT"})
        if state.get("status") == "STOPPING":
            fail("OFF/recovery is already in progress. Retry uninstall after it completes.")
    birth = process_birth(os.getpid())
    if birth is None:
        fail("Cannot prove current uninstall process identity.")
    write_json(TEARDOWN, {
        "status": "REMOVING", "phase": phase, "boot": boot_id(),
        "pid": os.getpid(), "birth": birth, "started": started,
    })
    return phase


def advance_uninstall_phase(phase: str) -> None:
    """Checkpoint completed teardown stage before entering the next stage."""
    marker = read_json(TEARDOWN)
    previous = uninstall_phase(marker)
    if UNINSTALL_PHASES.index(phase) != UNINSTALL_PHASES.index(previous) + 1:
        fail("Unexpected uninstall phase transition; preserving resources.")
    write_json(TEARDOWN, {**marker, "phase": phase})



def install_requirements(role: str) -> None:
    if not Path("/etc/os-release").exists():
        fail("Only apt-based Linux hosts are supported at present.")
    needed = {"python3": "python3", "ssh-keygen": "openssh-client", "ssh-keyscan": "openssh-client"}
    if role == "server":
        needed["sshd"] = "openssh-server"
    else:
        needed.update({"ssh": "openssh-client", "ssh-copy-id": "openssh-client",
                       "nft": "nftables", "curl": "curl", "ip": "iproute2"})
    missing = sorted({pkg for exe, pkg in needed.items() if shutil.which(exe) is None})
    if missing:
        if shutil.which("apt-get") is None:
            fail(f"Missing dependencies: {', '.join(missing)}; apt-get not available.")
        say(f"Installing missing packages ONLY: {', '.join(missing)}")
        run(["apt-get", "update"], timeout=150, capture=False)
        run(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=240, capture=False)
    require_supported_python()
    say("Prerequisites already present or installed. No system-wide upgrade.", "OK")


def install_entrypoint() -> None:
    APP.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    src = Path(__file__).resolve()
    if src != APP:
        atomic_write(APP, src.read_bytes(), 0o755)
    script = f"#!/bin/sh\nexec /usr/bin/python3 {shlex.quote(str(APP))} \"$@\"\n"
    if not COMMAND.exists() or COMMAND.read_text() != script:
        atomic_write(COMMAND, script.encode(), 0o755)


def install_wheel(url: str) -> None:
    if PKG.joinpath(".wheel-sha256").exists():
        if PKG.joinpath(".wheel-sha256").read_text().strip() == WHEEL_SHA256:
            version = subprocess.run(
                ["/usr/bin/python3", "-m", "sshuttle", "--version"], capture_output=True,
                text=True, env={**os.environ, "PYTHONPATH": str(PKG)}, timeout=10,
            )
            if version.returncode == 0 and SSHUTTLE_VERSION in version.stdout:
                say(f"sshuttle {SSHUTTLE_VERSION} already correct; no reinstall.", "OK")
                return
    if not url.startswith("https://"):
        fail("Wheel source must be HTTPS (or supply an already downloaded local wheel).")
    PKG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sc-stage-", dir=PKG.parent) as d:
        stage = Path(d)
        wheel = stage / "sshuttle.whl"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "SimpleConnect/0.1"})
            with urllib.request.urlopen(request, timeout=25) as response, wheel.open("wb") as out:
                digest = hashlib.sha256()
                size = 0
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > 12 * 1024 * 1024:
                        fail("Wheel exceeds 12 MiB safety bound.")
                    digest.update(chunk)
                    out.write(chunk)
        except Exception as exc:
            fail(f"Wheel download failed. Choose an approved mirror or local package. {type(exc).__name__}: {exc}")
        if digest.hexdigest() != WHEEL_SHA256:
            fail("Wheel SHA-256 mismatch: rejected. Do not use this mirror.")
        unpacked = stage / "payload"
        unpacked.mkdir()
        try:
            with zipfile.ZipFile(wheel) as z:
                for member in z.infolist():
                    name = Path(member.filename)
                    if name.is_absolute() or ".." in name.parts or member.file_size > 5 * 1024 * 1024:
                        fail("Invalid wheel archive entry.")
                    # This wheel is a pinned, verified pure-Python artifact.
                    if member.filename.endswith("/"):
                        continue
                    outpath = unpacked / member.filename
                    outpath.parent.mkdir(parents=True, exist_ok=True)
                    outpath.write_bytes(z.read(member))
        except (zipfile.BadZipFile, RuntimeError) as exc:
            fail(f"Invalid wheel: {exc}")
        result = subprocess.run(
            ["/usr/bin/python3", "-m", "sshuttle", "--version"], capture_output=True,
            text=True, env={**os.environ, "PYTHONPATH": str(unpacked)}, timeout=10,
        )
        if result.returncode != 0 or SSHUTTLE_VERSION not in result.stdout:
            fail("Downloaded sshuttle failed exact-version validation.")
        atomic_write(unpacked / ".wheel-sha256", (WHEEL_SHA256 + "\n").encode())
        backup = PKG.with_name("sshuttle.previous")
        if backup.exists():
            fail(f"Unexpected old backup {backup}; resolve before install.")
        if PKG.exists():
            PKG.rename(backup)
        try:
            unpacked.rename(PKG)
        except Exception:
            if backup.exists():
                backup.rename(PKG)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    say(f"Installed verified upstream sshuttle {SSHUTTLE_VERSION}.", "OK")


def unit_texts() -> dict[str, str]:
    cmd = f"/usr/bin/python3 {APP}"
    return {
        SERVICE: f"""# Managed by Simple Connect; do not edit directly.
[Unit]
Description=Simple Connect guarded sshuttle (IPv4 TCP / DNS)
Wants=network-online.target
After=network-online.target {GUARD_TIMER}
Requires={GUARD_TIMER}
BindsTo={GUARD_TIMER}

[Service]
Type=notify
ExecStart={cmd} internal-run
ExecStopPost=-{cmd} recover
Restart=no
TimeoutStartSec=50
TimeoutStopSec=15
# Stop upstream without its unconditional "delete entire table" destructor.
# Our independent recovery removes ONLY an identity-verified owned table.
KillSignal=SIGKILL
KillMode=control-group

[Install]
# Deliberately not enabled: reboot defaults to Direct.
""",
        GUARD_UNIT: f"""# Managed by Simple Connect; do not edit directly.
[Unit]
Description=Simple Connect independent safety guard
OnFailure={STOP_UNIT}

[Service]
Type=oneshot
ExecStart={cmd} guard
TimeoutStartSec=20
""",
        STOP_UNIT: f"""# Managed by Simple Connect; do not edit directly.
[Unit]
Description=Simple Connect emergency stop when independent guard fails

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl --no-block stop {SERVICE}
""",
        GUARD_TIMER: f"""# Managed by Simple Connect; do not edit directly.
[Unit]
Description=Periodic Simple Connect safety guard

[Timer]
OnBootSec=12s
OnUnitInactiveSec=12s
AccuracySec=2s
Unit={GUARD_UNIT}

[Install]
WantedBy=timers.target
""",
    }



def validate_existing_client_units() -> None:
    """Refuse to overwrite unrelated systemd units during incomplete setup."""
    for name in unit_texts():
        path = UNIT_DIR / name
        if path.is_symlink():
            fail(f"Unexpected symlinked systemd unit: {path}")
        if path.exists() and (not path.is_file() or
                              not path.read_text().startswith("# Managed by Simple Connect;")):
            fail(f"Refusing to replace non-owned systemd unit: {path}")


def first_install_retry_is_safe() -> None:
    """Proof for a never-activated, interrupted initial client setup."""
    if CONF.exists() or CONF.is_symlink() or SSH_CONF.exists() or KNOWN_HOSTS.exists():
        fail("Missing/incomplete CLIENT state with SSH configuration: manual recovery required.")
    if not service_terminated() or any_proxy_tables():
        fail("Incomplete CLIENT install with live proxy/firewall: refuse retry.")
    validate_existing_client_units()



def setup(role: str, wheel_url: str) -> None:
    require_root()
    require_no_teardown()
    role_path = ETC / "role"
    previous = role_path.exists() or role_path.is_symlink()
    state_exists = STATE.exists() or STATE.is_symlink()
    initial_client = role == "client" and (not state_exists or
                      read_json(STATE).get("status") == "INSTALLING")

    if previous:
        if role_path.is_symlink() or not role_path.is_file():
            fail("Unsafe role file; refusing setup.")
        current_role = role_path.read_text().strip()
        if current_role != role:
            fail(f"Host already configured as {current_role}; switch roles only after cleanup.")
        if role == "client":
            if STATE.is_symlink() or (state_exists and not STATE.is_file()):
                fail("Unsafe CLIENT state file; refuse setup.")
            if initial_client:
                first_install_retry_is_safe()
            else:
                old = read_json(STATE)
                if old.get("status") != "DIRECT" or not service_terminated() or any_proxy_tables():
                    fail("Recovery unresolved, service may be running or nft table remains: refuse setup/update.")
                validate_existing_client_units()
        elif CONF.exists() or STATE.exists() or is_active(SERVICE):
            fail("Unexpected CLIENT resources on SERVER role; use documented recovery before setup.")
    elif state_exists:
        if role == "client" and not STATE.is_symlink() and STATE.is_file() and initial_client:
            first_install_retry_is_safe()
        else:
            fail("Orphan CLIENT state/service exists; refuse to replace recovery assets.")
    elif CONF.exists() or CONF.is_symlink() or is_active(SERVICE):
        fail("Orphan CLIENT resources or service detected; refuse setup.")

    install_requirements(role)
    # INSTALLING is a durable, never-activated marker. It is written before
    # both the role and the wheel to make failed first installs retryable.
    # Existing activated clients NEVER have their recovery state overwritten.
    if initial_client:
        STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json(STATE, {"status": "INSTALLING", "boot": boot_id()})
    install_entrypoint()
    ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write(role_path, (role + "\n").encode())
    if role == "server":
        show_server_host_fingerprints(probe=False)
        say("SERVER role installed; SSH readiness is separately verified. No proxy, account or firewall created.", "OK")
        return
    install_wheel(wheel_url)
    ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, text in unit_texts().items():
        path = UNIT_DIR / name
        if path.exists() and not path.read_text().startswith("# Managed by Simple Connect;"):
            fail(f"Refusing to overwrite non-owned systemd unit: {path}")
        if not path.exists() or path.read_text() != text:
            atomic_write(path, text.encode(), 0o644)
    unit_action("daemon-reload")
    unit_action("enable", "--now", GUARD_TIMER)
    if initial_client:
        write_json(STATE, {"status": "DIRECT"})
    say("Client installed (Direct/OFF). Network interception is NOT enabled.", "OK")
    if not CONF.exists():
        say("Next step: Configure SSH from the menu to select/create a key and verify the remote host.", "INFO")


def ask(value: str | None, label: str, default: str | None = None) -> str:
    if value is not None:
        return value.strip()
    if not sys.stdin.isatty():
        fail(f"Missing {label}. Supply explicit configuration flags.")
    suffix = f" [{default}]" if default is not None else ""
    prompt = f"{label}{suffix} (b=back)"
    width = max(24, min(88, shutil.get_terminal_size(fallback=(80, 24)).columns - 1))
    if len(prompt) + 2 > width:
        terminal_note(prompt, indent="")
        entered = input(f"{paint('> ', 'heading')}").strip()
    else:
        entered = input(f"{paint(prompt, 'heading')}: ").strip()
    if entered.lower() in ("b", "back"):
        fail("Setup cancelled. Previously saved configuration was not changed; any generated SSH key is retained.")
    return entered or (default or "")


def yes_no(question: str, *, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        fail("Interactive confirmation requires a terminal.")
    suffix = "[Y/n]" if default else "[y/N]"
    prompt = f"{question} {suffix}"
    width = max(24, min(88, shutil.get_terminal_size(fallback=(80, 24)).columns - 1))
    while True:
        if len(prompt) + 2 > width:
            terminal_note(prompt, indent="")
            answer = input(f"{paint('> ', 'heading')}").strip().lower()
        else:
            answer = input(f"{paint(prompt, 'heading')}: ").strip().lower()
        if not answer:
            return default
        if answer in ("yes", "y"):
            return True
        if answer in ("no", "n", "b", "back"):
            return False
        say("Please enter Y or N. No action taken.", "WARN")


def checked_field(value: str | None, label: str, default: str | None, validator):
    """Retry one bad interactive field; explicit CLI flags still fail nonzero."""
    while True:
        raw = ask(value, label, default)
        try:
            return validator(raw)
        except (ConnectError, ValueError) as exc:
            if value is not None or not sys.stdin.isatty():
                raise ConnectError(str(exc)) from exc
            show_error(exc)


def valid_user(value: str) -> str:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}\$?", value, re.IGNORECASE):
        fail("Invalid SSH username. Use letters, digits, underscore or hyphen.")
    return value


def valid_port(value: str) -> int:
    try:
        number = int(value)
        if 1 <= number <= 65535:
            return number
    except ValueError:
        pass
    fail("SSH port must be an integer in the range 1..65535.")


# ssh-copy-id uses shell evaluation around its -i filename. We must never
# interpolate a user-selected pathname containing shell syntax into that helper.
SAFE_KEY_PATH = re.compile(r"/[A-Za-z0-9_./-]+")


def checked_key_name(value: str) -> Path:
    stripped = value.strip()
    if stripped.upper().startswith("SHA256:"):
        fail("SERVER host fingerprint pasted into the CLIENT private-key FILE "
             "path. Step 4 needs an absolute filename on this CLIENT "
             "(for example /root/.ssh/simple_connect_ed25519). "
             "Use the SHA256 value separately in step 5.")
    if stripped.lower().startswith(("ssh-", "ecdsa-sha2-", "sk-")):
        fail("That is SSH PUBLIC key text, not a CLIENT private-key file path. "
             "Enter the path to your existing local private key.")
    if stripped.upper().startswith(("-----BEGIN ", "-----END ")):
        fail("That is SSH key CONTENT, not a CLIENT private-key file path. "
             "Never paste a private key here; enter only its absolute filename.")
    path = Path(value)
    if (not path.is_absolute() or not SAFE_KEY_PATH.fullmatch(value)
            or any(part in (".", "..") for part in value.split("/"))):
        fail("Unsafe SSH identity path. Use an absolute path with only letters, digits, /, ., _ or -.")
    return path


def trusted_key_parents(folder: Path) -> None:
    """Reject replaceable parents; /tmp is accepted only as root-owned + sticky."""
    trusted_owners = {0, os.geteuid()}
    for parent in reversed((folder, *folder.parents)):
        try:
            info = os.lstat(parent)
        except FileNotFoundError:
            fail(f"SSH key directory missing: {parent}. Select a valid key or generate a dedicated one.")
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in trusted_owners:
            fail(f"Unsafe/untrusted SSH key directory ownership or symlink: {parent}")
        if info.st_mode & 0o022:
            sticky_root = (info.st_uid == 0 and
                           info.st_mode & stat.S_ISVTX and
                           stat.S_ISDIR(info.st_mode))
            if not sticky_root:
                fail(f"SSH key parent directory is writable by others: {parent}")


def private_key_path(value: str) -> Path:
    key = checked_key_name(value)
    trusted_key_parents(key.parent)
    try:
        meta = os.lstat(key)
    except FileNotFoundError:
        fail(f"Identity file missing or unsafe: {key}")
    if not stat.S_ISREG(meta.st_mode):
        fail(f"Identity file missing or unsafe (symlinks are not accepted): {key}")
    if meta.st_mode & 0o077 or (os.geteuid() == 0 and meta.st_uid != 0):
        fail(f"Private key permissions/ownership unsafe: {key}; expected root-owned mode 0600.")
    if meta.st_uid not in {0, os.geteuid()}:
        fail(f"Untrusted owner of private SSH key: {key}")
    return key


@contextlib.contextmanager
def locked_key_directory(folder: Path):
    """Advisory lock on the *directory inode*, not the networking-state lock."""
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        limit = time.monotonic() + 12
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= limit:
                    fail("Another SSH key creation is running. Try again shortly.")
                time.sleep(0.05)
        trusted_key_parents(folder)
        yield
    finally:
        os.close(fd)


def create_dedicated_key() -> Path:
    """Generate in a private staging dir and publish via no-replace hard links."""
    require_root()
    key = checked_key_name(str(KEY_PATH))
    pub = Path(str(key) + ".pub")
    folder = key.parent
    # Parent must already exist and be trusted. Never create arbitrary
    # ancestors from user-controlled path components.
    trusted_key_parents(folder.parent)
    # Two concurrent creators may both see an absent .ssh directory. Create
    # idempotently, then verify ownership/mode before using or locking it.
    folder.mkdir(mode=0o700, exist_ok=True)
    trusted_key_parents(folder)
    info = os.lstat(folder)
    if info.st_mode & 0o077:
        if not yes_no(f"Secure SSH key directory {folder} to mode 0700 before generating?", default=False):
            fail("SSH key creation cancelled; the existing directory was not changed.")
        folder.chmod(0o700)
    with locked_key_directory(folder):
        if folder.stat().st_mode & 0o077:
            fail(f"SSH key directory remains unsafe: {folder}")
        if any(p.exists() or p.is_symlink() for p in (key, pub)):
            fail(f"Dedicated key already exists or is partially created: {key}. No overwrite attempted.")
        say(f"Creating a dedicated ED25519 SSH identity at {key} (no passphrase for unattended tunnel).")
        with tempfile.TemporaryDirectory(prefix=".sc-keygen-", dir=folder) as stage:
            staged = Path(stage) / "identity"
            staged_pub = Path(str(staged) + ".pub")
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(staged),
                 "-C", "simple-connect"], timeout=30)
            private_key_path(str(staged))
            if not staged_pub.is_file() or staged_pub.is_symlink():
                fail("SSH key generation did not produce a valid public key.")
            staged_pub.chmod(0o644)
            try:
                # Hard links fail with EEXIST even if another writer races:
                # never use rename/replace for security-sensitive key paths.
                os.link(staged, key, follow_symlinks=False)
            except FileExistsError:
                fail(f"Dedicated private key appeared during creation: {key}. No overwrite performed.")
            try:
                os.link(staged_pub, pub, follow_symlinks=False)
            except BaseException as exc:
                # Roll back only the inode linked by *this* process.
                try:
                    own = os.lstat(key)
                    stage_inode = os.lstat(staged)
                    if (own.st_dev, own.st_ino) == (stage_inode.st_dev, stage_inode.st_ino):
                        key.unlink()
                except FileNotFoundError:
                    pass
                if isinstance(exc, FileExistsError):
                    fail(f"Another public key appeared during generation: {pub}. Nothing was overwritten; inspect the existing keypair.")
                raise
        private_key_path(str(key))
        say(f"New SSH key created. Private key stays ONLY on this CLIENT: {key}", "OK")
        return key


def select_identity(explicit: str | None) -> str:
    """Guide interactive selection and safe creation; noninteractive never auto-generates."""
    if explicit is not None:
        return str(private_key_path(explicit))
    default = str(KEY_PATH)
    for candidate in (KEY_PATH, Path("/root/.ssh/id_ed25519")):
        try:
            private_key_path(str(candidate))
        except (ConnectError, OSError):
            continue
        default = str(candidate)
        break
    terminal_section("STEP 4/5 - CLIENT authentication key (PRIVATE file).")
    terminal_note("Select an existing key file on THIS CLIENT, or explicitly generate one.")
    terminal_note("Do NOT paste a SHA256 fingerprint or the contents of a key here.",
                  tone="warn")
    while True:
        chosen = ask(explicit, "4/5 CLIENT private key FILE path", default)
        try:
            return str(private_key_path(chosen))
        except ConnectError as exc:
            if explicit is not None or not sys.stdin.isatty():
                raise
            show_error(exc)
            if chosen.strip().upper().startswith("SHA256:"):
                say("Keep that SERVER fingerprint for step 5. Step 4 needs a CLIENT file path.", "INFO")
                continue
            # Only a syntactically valid absolute filename may lead to an
            # *optional* dedicated-key offer. A fingerprint, pasted key,
            # relative/unsafe pathname or an existing unsafe file must never
            # become implicit consent to create a new credential.
            try:
                candidate = checked_key_name(chosen)
            except ConnectError:
                say("Enter a valid CLIENT private-key FILE path, or b to cancel.", "INFO")
                continue
            if not candidate.exists() and not candidate.is_symlink():
                if candidate != KEY_PATH:
                    terminal_note(f"The missing path {candidate} will NOT be created. "
                                  f"Key generation uses only {KEY_PATH}.")
                if yes_no(f"Generate a NEW dedicated CLIENT key at {KEY_PATH}?", default=False):
                    return str(create_dedicated_key())
            say("Enter another existing CLIENT key path, or b to cancel.", "INFO")


def single_public_record(data: bytes) -> tuple[str, str]:
    """A single plain OpenSSH public-key line, not an authorized_keys bundle."""
    if len(data) > 8192:
        fail("Public key file is too large; expected exactly one SSH key record.")
    try:
        raw = data.decode("ascii")
    except UnicodeDecodeError:
        fail("Public key must contain exactly one printable ASCII SSH key record.")
    if raw.count("\n") > 1 or "\r" in raw:
        fail("Public key must contain exactly one line; additional keys/records are not allowed.")
    line = raw[:-1] if raw.endswith("\n") else raw
    if not line or any(ord(c) < 32 or ord(c) > 126 for c in line):
        fail("Public key contains unexpected control/extra content.")
    fields = line.split(maxsplit=2)
    if len(fields) < 2 or not (fields[0] in ("ssh-ed25519", "ssh-rsa")
                              or fields[0].startswith("ecdsa-sha2-")
                              or fields[0].startswith("sk-")):
        fail("Public key must be a plain OpenSSH public-key record.")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", fields[1]):
        fail("Public key data has unexpected characters.")
    try:
        if len(base64.b64decode(fields[1], validate=True)) < 16:
            fail("Public key data is unexpectedly short.")
    except (ValueError, base64.binascii.Error):
        fail("Public key data is not valid base64.")
    return fields[0], fields[1]


def read_public_key_record(path: Path) -> tuple[str, str]:
    """Read one trusted public-key record from an open NOFOLLOW descriptor."""
    trusted_key_parents(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # Symlink blocked by O_NOFOLLOW.
            fail(f"Unsafe symlinked public SSH key: {path}")
        raise
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o022):
            fail(f"Unsafe public key owner/permissions: {path}")
        if info.st_size > 8192:
            fail(f"Public key file is too large: {path}")
        content = os.read(fd, 8193)
        return single_public_record(content)
    finally:
        os.close(fd)


def validated_public_key(key: Path) -> Path:
    """Verify the sole public key against a stable, passphrase-free private key."""
    private_key_path(str(key))
    pub = Path(str(key) + ".pub")
    before = os.lstat(key)
    response = run(["ssh-keygen", "-y", "-P", "", "-f", str(key)], timeout=12)
    after = os.lstat(key)
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if fingerprint(before) != fingerprint(after):
        fail("Private SSH key changed during validation; public-key enrollment cancelled.")
    expected = single_public_record(response.stdout.encode("utf-8"))
    try:
        actual = read_public_key_record(pub)
    except FileNotFoundError:
        # No atomic_write here: it could overwrite a public key published
        # by another process between the existence check and final save.
        try:
            fd = os.open(pub, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        except FileExistsError:
            fail(f"Public SSH key appeared during validation: {pub}; retry without overwriting.")
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o644)
                handle.write((" ".join(expected) + "\n").encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            # Remove only the inode we exclusively created. Never unlink a
            # key that another operator replaced in the meantime.
            try:
                current = os.lstat(pub)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    pub.unlink()
            except FileNotFoundError:
                pass
            raise
        actual = read_public_key_record(pub)
        say(f"Recovered matching public key: {pub}", "OK")
    if actual != expected:
        fail(f"Public key does not match selected private key: {pub}")
    if fingerprint(os.lstat(key)) != fingerprint(after):
        fail("Private SSH key changed during public-key validation; retry safely.")
    return pub


@dataclass(frozen=True)
class EnrollmentIntent:
    """The exact destination and SSH host identity for one operator consent."""
    remote_ip: str
    ssh_user: str
    ssh_port: int
    identity_file: str
    host_record: bytes
    host_fingerprint: str
    config_revision: tuple[bytes | None, ...]


def host_key_signature_algorithms(key_type: str) -> str:
    try:
        return HOST_KEY_ALGORITHMS[key_type]
    except KeyError:
        fail(f"Unsupported or obsolete SSH host key type: {key_type}. DSA and RSA-SHA1 are refused.")


def host_key_fingerprint(key_type: str, encoded: str) -> str:
    """Check key blob's SSH wire type, not merely the untrusted text label."""
    host_key_signature_algorithms(key_type)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded):
        fail("SSH host key contains invalid base64.")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) < 32 or len(raw) > 8192:
            fail("SSH host key has an invalid length.")
        (length,) = struct.unpack(">I", raw[:4])
        if not 1 <= length <= 64 or len(raw) <= 4 + length:
            fail("SSH host key wire format is invalid.")
        if raw[4:4 + length].decode("ascii") != key_type:
            fail("SSH host key type differs from the encoded key material.")
        return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    except (UnicodeDecodeError, ValueError, struct.error, base64.binascii.Error):
        fail("SSH host key wire encoding is invalid.")


def pinned_host_type(record: bytes) -> str:
    if not record or len(record) > 8192 or record.count(b"\n") != 1 or not record.endswith(b"\n"):
        fail("Pinned SSH host key must contain exactly one record; run Configure SSH.")
    try:
        parts = record[:-1].decode("ascii").split()
    except UnicodeDecodeError:
        fail("Pinned SSH host key must use ASCII.")
    if len(parts) != 3:
        fail("Pinned SSH host key is not a single plain record.")
    host_key_fingerprint(parts[1], parts[2])
    return parts[1]


def pinned_host_identity(cfg: dict, record: bytes) -> str:
    """Validate the single exact endpoint and supported host identity."""
    key_type = pinned_host_type(record)
    parts = record[:-1].decode("ascii").split()
    expected_host = (cfg["remote_ip"] if cfg["ssh_port"] == 22
                     else f"[{cfg['remote_ip']}]:{cfg['ssh_port']}")
    if parts[0] != expected_host:
        fail("Pinned SSH host key does not match the configured IP and port; run Configure SSH.")
    return host_key_fingerprint(key_type, parts[2])


def scanned_host_identities(ip: str, port: int) -> list[tuple[str, bytes, str]]:
    """Collect only explicit, unique supported SSH identities; no TOFU."""
    response = run(["ssh-keyscan", "-4", "-T", "7", "-t", "ed25519,ecdsa,rsa",
                    "-p", str(port), ip], timeout=25, check=False)
    rows = [row.strip() for row in response.stdout.splitlines()
            if row.strip() and not row.lstrip().startswith("#")]
    if not rows:
        fail("No supported SSH host key received. Check SSH port, listener, firewall and "
             f"ED25519/ECDSA/RSA-SHA2 policy. ssh-keyscan: {response.stderr.strip()[-300:]}")
    keys: dict[str, tuple[str, bytes, str]] = {}
    for row in rows:
        try:
            record = (row + "\n").encode("ascii")
            parts = row.split()
            if len(parts) != 3:
                fail("Unexpected extra fields in SSH host-key scan; nothing trusted.")
            key_type = parts[1]
            if key_type in keys:
                fail("Duplicate SSH host key type in scan; refusing ambiguous response.")
            fp = pinned_host_identity({"remote_ip": ip, "ssh_port": port}, record)
            with tempfile.TemporaryDirectory(prefix="sc-hostscan-") as folder:
                path = Path(folder) / "host"
                path.write_bytes(record)
                check = run(["ssh-keygen", "-lf", str(path)], timeout=10).stdout.split()
            if len(check) < 2 or check[1] != fp:
                fail("Observed SSH host fingerprint does not match the scanned host key or failed ssh-keygen validation.")
            if key_type == "ssh-rsa" and (not check[0].isdigit() or int(check[0]) < 2048):
                fail("RSA host key shorter than 2048 bits is not accepted.")
            keys[key_type] = key_type, record, fp
        except UnicodeEncodeError:
            fail("SSH host-key scan contained non-ASCII data.")
    return [keys[key] for key in HOST_KEY_ORDER if key in keys]

def read_pinned_host_record() -> bytes:
    """Fail closed on mutable aliases, excessive content, or unsafe ownership."""
    try:
        fd = os.open(KNOWN_HOSTS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        fail("Trusted SSH host key missing; run Configure SSH and verify the fingerprint first.")
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 8192
                or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022):
            fail("Pinned SSH host key file is unsafe; reconfigure the SSH endpoint.")
        return os.read(fd, 8193)
    finally:
        os.close(fd)


def current_enrollment_intent_unlocked() -> EnrollmentIntent:
    """Caller holds manager lock; check consistent configuration and host pin."""
    before = ssh_configuration_snapshot()
    cfg = read_config()
    host = read_pinned_host_record()
    fingerprint = pinned_host_identity(cfg, host)
    after = ssh_configuration_snapshot()
    if before != after:
        fail("SSH configuration changed while preparing enrollment; retry.")
    return EnrollmentIntent(
        remote_ip=cfg["remote_ip"], ssh_user=cfg["ssh_user"],
        ssh_port=cfg["ssh_port"], identity_file=cfg["identity_file"],
        host_record=host, host_fingerprint=fingerprint,
        config_revision=after,
    )


def require_enrollment_intent_unlocked(intent: EnrollmentIntent) -> None:
    """Never apply consent to another revision, destination, or host key."""
    require_no_teardown()
    if (read_json(STATE).get("status") != "DIRECT"
            or not service_terminated() or any_proxy_tables()):
        fail("Public-key enrollment requires verified DIRECT/OFF; inspect recovery.")
    if (ssh_configuration_snapshot() != intent.config_revision
            or current_enrollment_intent_unlocked() != intent):
        fail("SSH destination, key or host identity changed after consent was prepared. "
             "Nothing enrolled; reopen SSH Access and approve the current destination.")


def enroll_public_key(intent: EnrollmentIntent | None = None) -> None:
    """Opt-in enrollment bound to an immutable, independently pinned host key."""
    require_root()
    require_client_role()
    require_no_teardown()
    if intent is not None and not isinstance(intent, EnrollmentIntent):
        fail("Invalid enrollment context; restart SSH setup.")
    if intent is None:
        with locked(wait_seconds=6):
            require_no_teardown()
            if (read_json(STATE).get("status") != "DIRECT"
                    or not service_terminated() or any_proxy_tables()):
                fail("Public-key enrollment requires verified DIRECT/OFF; inspect recovery.")
            intent = current_enrollment_intent_unlocked()

    helper = Path("/usr/bin/ssh-copy-id")
    if not helper.is_file() or helper.is_symlink():
        fail("ssh-copy-id unavailable. Install Debian openssh-client before enrolling.")
    if "$" in intent.ssh_user:
        fail("Public-key enrollment cannot safely use '$' in SSH usernames; "
             "use a different remote account or the trusted console.")

    say(f"Public key destination: {intent.ssh_user}@{intent.remote_ip}:{intent.ssh_port}", "INFO")
    say(f"SSH private identity: {intent.identity_file}", "INFO")
    host_type = pinned_host_type(intent.host_record)
    say(f"Independently pinned remote {host_type}: {intent.host_fingerprint}", "INFO")
    say("Only the corresponding PUBLIC key will be installed; no network interception.", "WARN")
    if not yes_no(f"Authorize public-key enrollment on {intent.ssh_user}@{intent.remote_ip}:{intent.ssh_port}?"):
        say("Public-key enrollment cancelled. No remote action taken.", "INFO")
        return

    # The consent prompt and all remote/password I/O occur without the lock.
    with locked(wait_seconds=6):
        require_enrollment_intent_unlocked(intent)

    key = private_key_path(intent.identity_file)
    pub = validated_public_key(key)
    expected_record = read_public_key_record(pub)

    # ssh-copy-id is a shell helper and reads files by pathname. Publish a
    # temporary operator-private snapshot: its -i input, matching private
    # identity, and verified known_hosts cannot be retargeted by a concurrent
    # Configure SSH session after the manager lock is released.
    with tempfile.TemporaryDirectory(prefix="sc-enroll-", dir=key.parent) as directory:
        staged_dir = Path(directory)
        trusted_key_parents(staged_dir)
        staged_key = staged_dir / "identity"
        staged_pub = staged_dir / "identity.pub"
        staged_hosts = staged_dir / "known_hosts"
        os.link(key, staged_key, follow_symlinks=False)
        private_key_path(str(staged_key))
        derived = run(["ssh-keygen", "-y", "-P", "", "-f", str(staged_key)], timeout=12)
        if single_public_record(derived.stdout.encode("utf-8")) != expected_record:
            fail("SSH private key changed before enrollment; no remote action taken.")
        atomic_write(staged_pub, (" ".join(expected_record) + "\n").encode("ascii"), 0o644)
        atomic_write(staged_hosts, intent.host_record, 0o600)
        if read_public_key_record(staged_pub) != expected_record:
            fail("Enrollment public key changed during preparation; refusing remote access.")
        if pinned_host_identity({
            "remote_ip": intent.remote_ip, "ssh_port": intent.ssh_port,
        }, staged_hosts.read_bytes()) != intent.host_fingerprint:
            fail("Pinned SSH host key changed during preparation; refusing remote access.")

        # Final revision check immediately before the subprocess. If another
        # configure commits after this check, command arguments still refer
        # exclusively to this explicitly approved, immutable snapshot.
        with locked(wait_seconds=6):
            require_enrollment_intent_unlocked(intent)

        say("Remote SSH may request the account password here; it is not stored.", "WARN")
        cmd = [
            str(helper), "-F", "/dev/null", "-i", str(staged_pub),
            "-p", str(intent.ssh_port),
            "-o", f"UserKnownHostsFile={staged_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"HostKeyAlgorithms={host_key_signature_algorithms(host_type)}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            f"{intent.ssh_user}@{intent.remote_ip}",
        ]
        try:
            result = subprocess.run(
                cmd, timeout=180, check=False,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                     "HOME": "/root", "TERM": os.environ.get("TERM", "dumb")},
            )
        except subprocess.TimeoutExpired:
            fail("Public-key enrollment timed out. Confirm SSH port, credentials and policy.")
        if result.returncode:
            fail(f"Public-key enrollment failed (ssh-copy-id exit {result.returncode}). "
                 "Remote password login may be disabled; authorize the public key via its trusted console.")
    say("Public-key enrollment finished. Run Test SSH to verify it.", "OK")



def display_public_key() -> None:
    require_root()
    require_client_role()
    cfg = read_config()
    pub = validated_public_key(Path(cfg["identity_file"]))
    say("PUBLIC key only (safe to paste into the remote account's authorized_keys):", "INFO")
    print(pub.read_text().strip())


def ssh_configuration_snapshot() -> tuple[bytes | None, ...]:
    """Stable contents of all three owned SSH configuration files under lock."""
    fingerprints = []
    for path in (CONF, SSH_CONF, KNOWN_HOSTS):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            fingerprints.append(None)
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                fail(f"Unsafe SSH configuration file: {path}")
            raw = os.read(fd, 65537)
            fingerprints.append(hashlib.sha256(raw).digest())
        finally:
            os.close(fd)
    return tuple(fingerprints)


def configure(remote_ip: str | None, ssh_user: str | None, ssh_port: int | None,
              identity_file: str | None, fingerprint: str | None) -> None:
    require_root()
    require_no_teardown()
    require_client_role()
    with locked(wait_seconds=6):
        if not service_terminated() or read_json(STATE).get("status") != "DIRECT" or any_proxy_tables():
            fail("Switch OFF and complete recovery before changing the SSH endpoint.")
        prior_ssh = ssh_configuration_snapshot()
    interactive = (sys.stdin.isatty() and
                   any(x is None for x in (remote_ip, ssh_user, ssh_port, identity_file, fingerprint)))
    if interactive:
        terminal_section("CONFIGURE SSH / 5 STEPS")
        terminal_note("Configure SSH - traffic interception stays OFF. Enter b to cancel.",
                      tone="warn")
        terminal_note("Steps 1-3: remote SERVER. Step 4: CLIENT private key file.")
        terminal_note("Step 5: independently trusted SERVER host SHA256 fingerprint.")
    remote_ip = checked_field(remote_ip, "1/5 SERVER public IPv4", None,
                              lambda value: validate_ipv4(value, public=True))
    ssh_user = checked_field(ssh_user, "2/5 SERVER SSH username", "root", valid_user)
    ssh_port = checked_field(str(ssh_port) if ssh_port is not None else None,
                             "3/5 SERVER SSH port", "22", valid_port)
    if interactive:
        terminal_field("SSH destination", f"{ssh_user}@{remote_ip}:{ssh_port}")
        terminal_note("Next: select the private SSH identity kept only on this CLIENT.",
                      tone="heading")
    identity_file = select_identity(identity_file)
    cfg = validate_config({
        "remote_ip": remote_ip, "ssh_user": ssh_user, "ssh_port": ssh_port,
        "identity_file": identity_file,
    })
    candidates = scanned_host_identities(cfg["remote_ip"], cfg["ssh_port"])
    if interactive:
        terminal_section("STEP 5/5 - SERVER host identity (PUBLIC fingerprint, not a file).")
        terminal_note("On the trusted SERVER console, open option 12 and copy the "
                      "recommended SHA256 fingerprint. Verify it out of band.")
        terminal_note("Do not enter your CLIENT key path or paste SSH key contents here.",
                      tone="warn")
    for key_type, _, fp in candidates:
        say(f"Observed (UNTRUSTED) remote {key_type}: {fp}", "WARN")
    if not interactive:
        print("  Verify the SERVER host fingerprint independently (SERVER menu option 12).")
    while True:
        expected = ask(fingerprint, "5/5 Trusted SERVER HOST SHA256 fingerprint")
        chosen = [(key_type, record, fp) for key_type, record, fp in candidates
                  if re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected) and expected == fp]
        if len(chosen) == 1:
            host_type, verified_host_record, actual = chosen[0]
            break
        if fingerprint is not None or not sys.stdin.isatty():
            fail("Fingerprint mismatch or unsupported host identity; nothing saved.")
        say("Fingerprint does not match any supported observed host key. Nothing saved.", "ERROR")
        if not yes_no("Retry fingerprint entry?", default=True):
            fail("SSH fingerprint not approved; configuration cancelled.")
    signatures = host_key_signature_algorithms(host_type)
    host = cfg["remote_ip"]
    port = cfg["ssh_port"]
    sshcfg = (
        "Host sc-remote\n"
        f"  HostName {host}\n  User {cfg['ssh_user']}\n  Port {port}\n"
        f"  IdentityFile {cfg['identity_file']}\n"
        f"  UserKnownHostsFile {KNOWN_HOSTS}\n"
        f"  HostKeyAlgorithms {signatures}\n"
        "  GlobalKnownHostsFile /dev/null\n  UpdateHostKeys no\n"
        "  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n"
        "  BatchMode yes\n  AddressFamily inet\n"
        "  ConnectTimeout 10\n  ConnectionAttempts 1\n"
        "  ServerAliveInterval 10\n  ServerAliveCountMax 3\n"
        "  ClearAllForwardings yes\n"
    )
    # Do not hold the manager lock across user input, ssh-keyscan or password
    # prompts. Recheck the network state under the lock immediately before
    # changing owned SSH configuration, then release it before enrollment.
    with locked(wait_seconds=6):
        require_no_teardown()
        if not service_terminated() or read_json(STATE).get("status") != "DIRECT" or any_proxy_tables():
            fail("Network state changed during SSH setup; no configuration saved.")
        if ssh_configuration_snapshot() != prior_ssh:
            fail("SSH configuration changed during setup by another session. No changes saved; restart Configure SSH.")
        ETC.mkdir(parents=True, exist_ok=True)
        atomic_write(KNOWN_HOSTS, verified_host_record)
        atomic_write(SSH_CONF, sshcfg.encode())
        write_json(CONF, cfg)
        # Capture A while holding the commit lock, before another operator
        # can configure B. Consent must never be rebound to current globals.
        enrollment_intent = EnrollmentIntent(
            remote_ip=cfg["remote_ip"], ssh_user=cfg["ssh_user"],
            ssh_port=cfg["ssh_port"], identity_file=cfg["identity_file"],
            host_record=verified_host_record, host_fingerprint=actual,
            config_revision=ssh_configuration_snapshot(),
        )
    say(f"Remote {host_type} host key pinned ({actual}); network remains DIRECT/OFF.", "OK")
    if interactive:
        enroll_public_key(enrollment_intent)
        if yes_no("Test the remote SSH login and Python prerequisites now?", default=True):
            remote_python_test()
        say("Use Test HTTPS for full traffic checks before considering ON.", "INFO")


def read_config() -> dict:
    return validate_config(read_json(CONF))


def remote_python_test() -> None:
    p = run(["ssh", "-F", str(SSH_CONF), "sc-remote",
             'python3 -c "import sys; assert (3, 10) <= sys.version_info[:2] < (4, 0)"'],
            timeout=25)
    say("Authenticated SSH and remote Python >=3.10,<4.0 verified.", "OK")


def parse_proc_tcp_line(line: str, *, ipv6: bool = False) -> tuple[str, int, str, int, int] | None:
    """Linux /proc/net/tcp{,6} ESTABLISHED socket tuple and kernel inode."""
    parts = line.split()
    if len(parts) < 10 or parts[3] != "01":
        return None
    try:
        local_hex, local_port = parts[1].split(":")
        remote_hex, remote_port = parts[2].split(":")
        def decode(raw: str) -> str:
            if ipv6:
                packed = b"".join(bytes.fromhex(raw[i:i + 8])[::-1] for i in range(0, 32, 8))
                addr = ipaddress.IPv6Address(packed)
                if addr.ipv4_mapped is None:
                    raise ValueError("IPv6 SSH management is not yet supported")
                return str(addr.ipv4_mapped)
            return str(ipaddress.IPv4Address(bytes.fromhex(raw)[::-1]))
        local = decode(local_hex)
        remote = decode(remote_hex)
        return (remote, int(remote_port, 16), local, int(local_port, 16), int(parts[9]))
    except (ValueError, IndexError, TypeError):
        return None


def initial_ssh_connection(*, proc_root: Path = Path('/proc'), pid: int | None = None) -> str:
    """Prove the caller descends from a real sshd TCP session.

    NEVER trust SSH_CONNECTION (which can be edited by any local process).
    Only the kernel socket inode of an ancestor sshd/sshd-session process
    paired with an established kernel TCP connection is accepted.
    The TCP inode additionally differentiates repeated logins with a
    reused 4-tuple and cannot be forged by environment-only changes.
    """
    pid = os.getpid() if pid is None else pid
    ssh_sockets: set[int] = set()
    seen: set[int] = set()
    for _ in range(64):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        proc = proc_root / str(pid)
        try:
            status = (proc / "status").read_text()
            m = re.search(r"(?m)^PPid:\s*(\d+)$", status)
            if m is None:
                fail("Cannot verify the invoking process ancestry.")
            parent = int(m.group(1))
            executable = Path(os.readlink(proc / "exe")).name
            if executable in ("sshd", "sshd-session"):
                for f in (proc / "fd").iterdir():
                    try:
                        target = os.readlink(f)
                    except (OSError, PermissionError):
                        continue
                    match = re.fullmatch(r"socket:\[(\d+)\]", target)
                    if match:
                        ssh_sockets.add(int(match.group(1)))
            pid = parent
        except (OSError, PermissionError) as exc:
            fail(f"Cannot verify authenticated SSH parent process: {exc}")
    if not ssh_sockets:
        fail("Authenticated SSH process ancestry/socket absent; run from a real SSH login.")

    matches: set[tuple[str, int, str, int, int]] = set()
    for filename, is_v6 in (("tcp", False), ("tcp6", True)):
        try:
            lines = (proc_root / "net" / filename).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parsed = parse_proc_tcp_line(line, ipv6=is_v6)
            if parsed and parsed[4] in ssh_sockets:
                matches.add(parsed)
    if len(matches) != 1:
        fail("Could not uniquely verify an ESTABLISHED authenticated SSH TCP socket.")
    peer_ip, peer_port, host_ip, host_port, inode = matches.pop()
    if peer_port == 0 or host_port == 0:
        fail("SSH socket has invalid endpoint ports.")
    return f"{peer_ip} {peer_port} {host_ip} {host_port} {inode}"




def ssh_connection_inventory(proc_root: Path = Path("/proc")) -> list[str]:
    """Post-activation baseline of established SSH TCP sockets on this host.

    Scan the kernel's established sockets and SSH daemon processes, not
    SSH_CONNECTION or user-supplied session data. The baseline is taken
    AFTER sshuttle is running, so a pre-existing second login cannot
    confirm that new administration remains possible.
    """
    established: dict[int, str] = {}
    for filename, is_v6 in (("tcp", False), ("tcp6", True)):
        try:
            lines = (proc_root / "net" / filename).read_text().splitlines()[1:]
        except OSError as exc:
            fail(f"Cannot inventory kernel TCP connections: {exc}")
        for line in lines:
            parsed = parse_proc_tcp_line(line, ipv6=is_v6)
            if parsed:
                established[parsed[4]] = " ".join(str(x) for x in parsed)
    found: set[str] = set()
    try:
        processes = list(proc_root.iterdir())
    except OSError as exc:
        fail(f"Cannot inventory SSH processes: {exc}")
    for proc in processes:
        if not proc.name.isdigit():
            continue
        try:
            exe = Path(os.readlink(proc / "exe")).name
        except (OSError, PermissionError):
            continue
        if exe not in ("sshd", "sshd-session"):
            continue
        try:
            fds = list((proc / "fd").iterdir())
        except (OSError, PermissionError) as exc:
            fail(f"Cannot inspect an SSH daemon's TCP sockets: {exc}")
        for fd in fds:
            try:
                target = os.readlink(fd)
            except (OSError, PermissionError):
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match and int(match.group(1)) in established:
                found.add(established[int(match.group(1))])
    return sorted(found)


def require_external_management_peer(peer_ip: str) -> None:
    """Reject localhost/self-originated SSH confirmations.

    Private remote peers are valid: don't restrict users to public SSH.
    """
    try:
        peer = ipaddress.IPv4Address(peer_ip)
    except ipaddress.AddressValueError:
        fail("Non-IPv4 SSH management connection; cannot confirm remote access.")
    if peer.is_loopback or peer.is_unspecified or peer.is_link_local or peer.is_multicast:
        fail("Local-only SSH connection cannot confirm external management access.")
    res = run(["ip", "-j", "-4", "address", "show"], timeout=10)
    try:
        interfaces = json.loads(res.stdout)
        if not isinstance(interfaces, list):
            raise ValueError()
        local_ips = {
            str(ipaddress.IPv4Address(info["local"]))
            for iface in interfaces
            for info in iface["addr_info"]
            if info.get("family") == "inet"
        }
    except (ValueError, TypeError, KeyError, ipaddress.AddressValueError):
        fail("Cannot identify local IPv4 addresses to verify SSH session origin.")
    if str(peer) in local_ips:
        fail("Self-originated SSH connection cannot confirm external management access.")


def boot_seconds() -> float:
    """Linux CLOCK_BOOTTIME: elapsed time incl. suspension; wall-clock independent."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def pending_expired(state: dict) -> bool:
    deadline = state.get("deadline_boot")
    if type(deadline) not in (int, float) or not (0 < deadline < float("inf")):
        return True  # legacy/corrupt PENDING must never extend the safety window
    return boot_seconds() >= deadline


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def proxy_port(state: dict | None = None) -> int:
    if state is None:
        state = read_json(STATE, {"status": "DIRECT"})
    port = state.get("listen_port", PORT)
    if type(port) is not int or not (13000 <= port <= 61000):
        fail("Invalid stored proxy listener port; refusing to touch firewall.")
    return port


def proxy_table(state: dict | None = None) -> str:
    return f"sshuttle-ipv4-{proxy_port(state)}"


def choose_port() -> int:
    # sshuttle 2.0.0 does not set SO_REUSEADDR. Reusing a recent fixed
    # listening port fails with EADDRINUSE while its accepted TCP sockets
    # remain in TIME_WAIT. A new distinct port fixes fast ON/OFF cycles.
    for _ in range(32):
        port = 20000 + secrets.randbelow(28000)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
        if current_table({"listen_port": port}) is None:
            return port
    fail("Could not allocate an available proxy port; no network changes made.")


def current_table(state: dict | None = None) -> dict | None:
    name = proxy_table(state)
    proc = subprocess.run(
        ["nft", "-j", "list", "table", "inet", name],
        text=True, capture_output=True, timeout=8,
    )
    if proc.returncode != 0:
        if "No such file or directory" in proc.stderr or "does not exist" in proc.stderr:
            return None
        fail(f"Cannot inspect nftables safely: {proc.stderr.strip()[-300:]}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        fail("Could not parse current nftables table; refusing cleanup.")
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        fail("Unexpected nftables table format.")
    return data


def table_hash(table: dict) -> str:
    return hashlib.sha256(json.dumps(table, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def table_is_ours(table: dict, expected: str) -> bool:
    return bool(expected) and table_hash(table) == expected


def any_proxy_tables() -> bool:
    """Never adopt an untracked prior sshuttle table with a different port."""
    if shutil.which("nft") is None:
        fail("nft command missing; unable to establish firewall safety.")
    proc = run(["nft", "-j", "list", "tables"], timeout=10)
    try:
        items = json.loads(proc.stdout)["nftables"]
        if not isinstance(items, list):
            raise ValueError()
        for entry in items:
            t = entry.get("table", {}) if isinstance(entry, dict) else {}
            if t.get("family") == "inet" and re.fullmatch(r"sshuttle-ipv4-[0-9]+", str(t.get("name", ""))):
                return True
        return False
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        fail("Cannot enumerate nftables safely; refuse operation.")


def ensure_stopped() -> None:
    require_client_role()
    if not service_terminated():
        fail("Cannot proceed while the proxy is still active or stopping.")
    state = read_json(STATE)
    if state.get("status") != "DIRECT":
        fail(f"State is {state.get('status', 'UNKNOWN')}. Run off/recover before ON.")
    if any_proxy_tables():
        fail("Existing/untracked sshuttle nftables table detected; refuse activation.")



def owned_cleanup(state: dict) -> bool:
    table = current_table(state)
    if table is None:
        return True
    expected = state.get("table_sha256", "")
    # A table cannot be claimed by its name or plausible shape. During the
    # activation gap BEFORE a full fingerprint has been durably recorded,
    # report UNCERTAIN instead of deleting a possibly foreign-modified table.
    if not isinstance(expected, str) or not table_is_ours(table, expected):
        say(f"UNCERTAIN: nftables table {proxy_table(state)} differs from recorded owned state. Manual inspection needed.", "ERROR")
        return False
    run(["nft", "delete", "table", "inet", proxy_table(state)], timeout=10)
    return current_table(state) is None


def service_terminated() -> bool:
    """Conservative systemd proof; inactive alone is insufficient.

    ExecStopPost runs while the unit is 'deactivating' and the control PID
    is the recovery process itself. Only allow that special systemd state
    when the main PID is already zero and our own PID is the control PID.
    """
    proc = run(
        ["systemctl", "show", SERVICE, "--no-pager",
         "--property=ActiveState,MainPID,ControlPID,LoadState"],
        timeout=10,
    )
    data = dict(
        line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
    )
    try:
        main_pid = int(data["MainPID"])
        control_pid = int(data["ControlPID"])
        active = data["ActiveState"]
    except (KeyError, ValueError):
        fail("Cannot verify proxy process termination through systemd.")
    if main_pid != 0:
        return False
    if active in ("inactive", "failed"):
        return control_pid == 0
    return active == "deactivating" and control_pid == os.getpid()


def mark_uncertain(reason: str) -> None:
    state = read_json(STATE, {"status": "DIRECT"})
    write_json(STATE, {**state, "status": "UNCERTAIN", "last_recovery": reason})


def reconcile(reason: str) -> None:
    # Do NOT delete any nftables table, or claim DIRECT, while a live
    # sshuttle process may be manipulating/recreating the redirection.
    if not service_terminated():
        mark_uncertain("proxy_not_confirmed_stopped:" + reason)
        fail("Proxy process termination NOT verified; state UNCERTAIN, firewall untouched.")
    state = read_json(STATE, {"status": "DIRECT"})
    if not owned_cleanup(state):
        mark_uncertain("firewall_ownership_uncertain:" + reason)
        fail("Partial rollback: unknown or changed nftables table preserved; provider-console recovery required.")
    # A stale table from a different listener port is still capable of
    # redirecting host traffic. Do not claim DIRECT merely because the
    # last recorded listener's table is absent.
    if any_proxy_tables() or not service_terminated():
        mark_uncertain("untracked_table_or_live_proxy:" + reason)
        fail("Cannot prove DIRECT: untracked sshuttle table or running proxy; UNCERTAIN.")
    write_json(STATE, {"status": "DIRECT", "last_recovery": reason})
    say(f"Direct networking restored/verified for owned nftables table ({reason}).", "OK")


def stop_and_recover(reason: str) -> None:
    # Do not hold the manager lock over systemctl stop: ExecStopPost takes it.
    if not service_terminated():
        try:
            stop = run(["systemctl", "stop", SERVICE], check=False, timeout=40)
        except (ConnectError, OSError, subprocess.TimeoutExpired) as exc:
            with locked():
                mark_uncertain("systemd_stop_error:" + reason)
            fail(f"Unable to stop proxy safely: {exc}. State UNCERTAIN.")
        if stop.returncode != 0 or not service_terminated():
            with locked():
                mark_uncertain("systemd_stop_unverified:" + reason)
            fail("Proxy stop did not complete successfully; state UNCERTAIN, no firewall deletion.")
    # ExecStopPost may have already completed recovery. Reconcile remains
    # idempotent but strictly checks service termination again.
    recover(reason)


def effective_exclusions(remote_ip: str, management_ip: str) -> list[str]:
    """Keep directly connected PUBLIC subnets and on-link gateways direct.

    Local address-only nft FIB checks do NOT exclude neighboring public-IP
    hosts in the same L2 subnet. Never infer on-link routes from RFC1918.
    """
    routes = run(["ip", "-j", "-4", "route", "show", "table", "all"], timeout=12)
    try:
        entries = json.loads(routes.stdout)
    except json.JSONDecodeError:
        fail("Cannot read IPv4 routing configuration; refusing proxy activation.")
    if not isinstance(entries, list) or not entries:
        fail("No parsable IPv4 routes; cannot protect on-link network paths.")

    exclusions = {str(ipaddress.IPv4Network(x)) for x in EXCLUDED}
    exclusions.add(str(ipaddress.IPv4Network(remote_ip + "/32")))
    exclusions.add(str(ipaddress.IPv4Network(management_ip + "/32")))
    for entry in entries:
        if not isinstance(entry, dict):
            fail("Malformed IPv4 route; refusing activation.")
        gateway = entry.get("gateway")
        if gateway is not None:
            try:
                exclusions.add(str(ipaddress.IPv4Network(validate_ipv4(str(gateway)) + "/32")))
            except (ValueError, TypeError):
                fail("Invalid route gateway; refusing activation.")
        scope = entry.get("scope")
        if scope != "link" or not entry.get("dev"):
            continue
        dst = str(entry.get("dst", "default"))
        if dst == "default" or dst == "0.0.0.0/0":
            fail("An un-gatewayed on-link IPv4 default route cannot be safely intercepted.")
        try:
            network = ipaddress.IPv4Network(dst, strict=False)
        except ValueError:
            fail("Malformed directly connected subnet; refusing activation.")
        exclusions.add(str(network))
    if len(exclusions) > 128:
        fail("Unusually many local routes; refusing unchecked firewall rules.")
    return sorted(exclusions, key=lambda x: (int(ipaddress.IPv4Network(x).network_address),
                                            ipaddress.IPv4Network(x).prefixlen))


def stored_exclusions(state: dict) -> list[str]:
    items = state.get("exclusions")
    if not isinstance(items, list) or len(items) > 128 or len(items) < len(EXCLUDED) + 1:
        fail("Missing/invalid pinned network exclusions; refusing activation.")
    if any(not isinstance(x, str) for x in items) or len(items) != len(set(items)):
        fail("Duplicate/invalid pinned network exclusions.")
    try:
        canonical = {str(ipaddress.IPv4Network(x, strict=True)) for x in items}
    except ValueError:
        fail("Malformed pinned network exclusion.")
    required = {str(ipaddress.IPv4Network(x)) for x in EXCLUDED}
    for ip in (state.get("remote_ip"), state.get("management_ip")):
        try:
            required.add(str(ipaddress.IPv4Network(str(ip) + "/32")))
        except ValueError:
            fail("Invalid management/remote IP in pinned exclusions.")
    if not required.issubset(canonical):
        fail("Pinned exclusions omit remote SSH endpoint or management networks.")
    return items


def start_proxy() -> None:
    require_root()
    require_client_role()
    with locked():
        require_no_teardown()
        cfg = read_config()
        if not is_active(GUARD_TIMER):
            fail("Independent guard timer inactive. Run setup-client; do not bypass the guard.")
        ensure_stopped()
        ssh_conn = initial_ssh_connection()
        remote_python_test()
        excludes = effective_exclusions(cfg["remote_ip"], ssh_conn.split()[0])
        op = secrets.token_hex(8)
        port = choose_port()
        started = boot_seconds()
        state = {
            "status": "PENDING", "op": op, "boot": boot_id(),
            "started": int(time.time()), "deadline": int(time.time()) + 600,
            "started_boot": started, "deadline_boot": started + 600,
            "original_ssh_connection": ssh_conn, "management_ip": ssh_conn.split()[0],
            "remote_ip": cfg["remote_ip"], "listen_port": port,
            "exclusions": excludes, "table_sha256": "",
        }
        write_json(STATE, state)
    # Never hold the manager lock during systemd's start/stop transactions.
    # ExecStopPost and the independent guard need that same lock to recover.
    try:
        require_no_teardown()
        unit_action("start", SERVICE)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and current_table(state) is None and is_active(SERVICE):
            time.sleep(0.2)
        with locked():
            require_no_teardown()
            observed = read_json(STATE)
            if observed.get("op") != op or observed.get("status") != "PENDING":
                fail("Activation changed concurrently; refusing to commit firewall identity.")
            if not is_active(SERVICE):
                fail("sshuttle service did not enter ACTIVE state.")
            table = current_table(observed)
            if table is None:
                fail("No expected nftables table after sshuttle startup.")
            # Snapshot *all* pre-existing established SSH connections only
            # AFTER the proxy firewall is active. Confirmation must use a
            # new authenticated TCP connection not in this durable baseline.
            previous = ssh_connection_inventory()
            if ssh_conn not in previous:
                fail("Initiating SSH connection not found in server-side socket baseline.")
            observed["ssh_preexisting"] = previous
            observed["table_sha256"] = table_hash(table)
            write_json(STATE, observed)
    except Exception:
        # Preserve the actual stop/recovery error rather than silently
        # overriding it with the earlier activation failure.
        stop_and_recover("failed_activation")
        raise
    say(f"Proxy started in PENDING state; automatic rollback deadline ~10 minutes. Operation: {op}", "WARN")
    say("From a NEW authenticated SSH session, run the following command:", "INFO")
    print(f"sudo simple-connect confirm {op}")  # One intact, copy-ready command.


def confirm(op: str) -> None:
    require_root()
    require_client_role()
    with locked():
        require_no_teardown()
        state = read_json(STATE)
        if state.get("status") != "PENDING" or not secrets.compare_digest(str(state.get("op", "")), op):
            fail("No matching pending activation operation.")
        if state.get("boot") != boot_id() or pending_expired(state):
            fail("Confirmation deadline expired or server rebooted. Recovery required.")
        fresh = initial_ssh_connection()
        prior = state.get("ssh_preexisting")
        if not isinstance(prior, list) or not prior or fresh in prior:
            fail("Confirmation MUST use a new SSH TCP connection established AFTER activation.")
        require_external_management_peer(fresh.split()[0])
        if not is_active(SERVICE):
            fail("Proxy process is not active.")
        table = current_table(state)
        if table is None or not table_is_ours(table, str(state.get("table_sha256", ""))):
            fail("Firewall state changed or is missing; confirmation refused.")
        state["status"] = "ACTIVE"
        state["confirmed_at"] = int(time.time())
        state.pop("deadline", None)
        state.pop("deadline_boot", None)
        state.pop("ssh_preexisting", None)
        write_json(STATE, state)
    say("ACTIVE: authenticated fresh SSH session confirmed; ongoing guard remains armed.", "OK")


def recover(reason: str = "service_exit_or_manual_recovery") -> None:
    require_root()
    require_client_role()
    with locked():
        if not service_terminated():
            fail("Cannot recover with a live/unverified proxy process. Use 'off' first.")
        reconcile(reason)


def stop_proxy(*, for_uninstall: bool = False) -> None:
    require_root()
    require_client_role()
    with locked():
        if not for_uninstall:
            require_no_teardown()
        state = read_json(STATE, {"status": "DIRECT"})
        if state.get("status") in ("PENDING", "ACTIVE"):
            write_json(STATE, {**state, "status": "STOPPING"})
    stop_and_recover("manual_off")


def guard() -> None:
    require_root()
    require_client_role()
    try:
        return guarded_check()
    except ConnectError as exc:
        if str(exc).startswith("Another Simple Connect operation is running.") and service_terminated():
            # The manager is doing preflight/setup, but no proxy process
            # exists. No firewall state could be intercepted. The periodic
            # timer will check again; do not trigger OnFailure unnecessarily.
            say("Guard deferred during non-networking manager operation.", "WARN")
            return
        raise


def guarded_check() -> None:
    with locked(wait_seconds=6):
        state = read_json(STATE, {"status": "DIRECT"})
        status = state.get("status")
        # DIRECT is inconsistent if a service still has a live main PID.
        if status == "DIRECT":
            if not service_terminated():
                mark_uncertain("direct_with_live_service")
            elif any_proxy_tables():
                mark_uncertain("direct_with_firewall_table")
                fail("DIRECT with an untracked sshuttle nftables table: UNCERTAIN.")
            else:
                return
        elif status == "UNCERTAIN":
            if service_terminated():
                fail("Recovery UNCERTAIN: firewall requires manual verification.")
        elif status == "INSTALLING":
            # Retain the interrupted first-install transaction until setup
            # finishes. A guard tick must not turn it into completed DIRECT.
            if service_terminated() and not any_proxy_tables():
                return
            mark_uncertain("unexpected_proxy_during_install")
            fail("Proxy resources discovered during initial install: UNCERTAIN.")
        else:
            stale_boot = state.get("boot") != boot_id()
            expired = status == "PENDING" and pending_expired(state)
            process_lost = status in ("ACTIVE", "PENDING") and not is_active(SERVICE)
            started_boot = state.get("started_boot")
            startup_grace = (status == "PENDING" and type(started_boot) in (int, float)
                             and 0 <= boot_seconds() - started_boot < 45)
            observed_table = current_table(state)
            changed = observed_table is not None and bool(state.get("table_sha256")) and not table_is_ours(
                observed_table, str(state["table_sha256"])
            )
            missing = observed_table is None and status in ("ACTIVE", "PENDING") and not startup_grace
            if not (stale_boot or expired or (process_lost and not startup_grace)
                    or changed or missing or status == "STOPPING"):
                return
        # Stop outside the lock; ExecStopPost may need it.
    stop_and_recover("guard")


def service_run() -> None:
    require_root()
    require_client_role()
    require_no_teardown()
    cfg = read_config()
    if not is_active(GUARD_TIMER):
        fail("Guard not armed; refusing to start.")
    state = read_json(STATE)
    if state.get("status") != "PENDING" or state.get("boot") != boot_id():
        fail("Refusing unguarded service start.")
    if str(state.get("remote_ip")) != cfg["remote_ip"]:
        fail("Remote endpoint changed during activation; refusing service start.")
    excluded = stored_exclusions(state)
    argv = [
        "/usr/bin/python3", "-m", "sshuttle", "--method=nft", "--dns",
        "--latency-buffer-size", str(SSHUTTLE_LATENCY_BUFFER_SIZE),
        "--listen", f"127.0.0.1:{proxy_port(state)}", "--remote", "sc-remote",
        "--ssh-cmd", f"ssh -F {SSH_CONF} -o BatchMode=yes",
    ]
    for cidr in excluded:
        argv.extend(["--exclude", cidr])
    argv.append("0.0.0.0/0")
    os.environ["PYTHONPATH"] = str(PKG)
    os.execvpe(argv[0], argv, os.environ)



def server_host_report(*, probe: bool = False) -> dict:
    """Read-only evidence: effective sshd config, local files and optional loopback scan.

    Local public-key files and sshd -T are NOT proof of a listening SSH
    daemon. A loopback scan may miss a listener bound only to an external IP.
    """
    report = {"active": False, "ports": [], "keys": [],
              "notes": [], "observed": [], "configured": False}
    try:
        report["active"] = is_active("ssh.service") or is_active("sshd.service")
    except (ConnectError, OSError, subprocess.TimeoutExpired) as exc:
        report["notes"].append(f"SSH service state unknown: {exc}")
    daemon = None
    try:
        daemon_stat = os.lstat(SSH_DAEMON)
        if (stat.S_ISREG(daemon_stat.st_mode) and daemon_stat.st_uid == 0
                and not daemon_stat.st_mode & 0o022):
            daemon = str(SSH_DAEMON)
        else:
            report["notes"].append(f"Unsafe sshd executable identity or permissions: {SSH_DAEMON}")
    except FileNotFoundError:
        pass
    except OSError as exc:
        report["notes"].append(f"Could not inspect sshd executable: {exc}")
    config = {}
    if daemon:
        try:
            detail = run([daemon, "-T"], check=False, timeout=8)
            if detail.returncode:
                report["notes"].append(f"sshd -T failed: {detail.stderr.strip()[-240:]}")
            else:
                for row in detail.stdout.splitlines():
                    name, _, value = row.partition(" ")
                    if value:
                        config.setdefault(name, []).append(value.strip())
                report["configured"] = True
        except (ConnectError, OSError) as exc:
            report["notes"].append(f"Unable to inspect effective sshd settings: {exc}")
    else:
        report["notes"].append("Trusted /usr/sbin/sshd unavailable: effective SSH configuration cannot be inspected.")

    ports = []
    for item in config.get("port", []):
        if item.isdecimal() and 1 <= int(item) <= 65535:
            ports.append(int(item))
    report["ports"] = list(dict.fromkeys(ports))
    accepted = set(",".join(config.get("hostkeyalgorithms", [])).split(","))
    configured_paths = config.get("hostkey", [])
    standard_paths = [str(SSH_HOST_DIR / f"ssh_host_{k}_key")
                      for k in ("ed25519", "ecdsa", "rsa", "dsa")]
    # Show configured missing keys AND extra local host keys not configured
    # in sshd, including obsolete DSA. Never present extra files as enabled.
    paths = list(dict.fromkeys(
        configured_paths + [item for item in standard_paths
                            if not report["configured"] or Path(item + ".pub").exists()
                            or Path(item + ".pub").is_symlink()]
    ))
    for item in paths:
        path = Path(item + ".pub")
        entry = {"path": str(path), "type": "UNKNOWN", "fingerprint": "",
                 "status": "PUBLIC KEY MISSING", "private": "NOT VERIFIED",
                 "enabled": False, "observed_ports": []}
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_size > 8192
                        or st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022):
                    fail(f"Unsafe host public key file: {path}")
                data = os.read(fd, 8193)
            finally:
                os.close(fd)
            try:
                public = data.decode("ascii").strip().split()
            except UnicodeDecodeError:
                fail("Host public key is not ASCII.")
            if not public:
                fail("Host public key file is empty.")
            kind = public[0]
            entry["type"] = kind
            if kind not in HOST_KEY_ALGORITHMS:
                entry["status"] = "UNSUPPORTED (DSA/other)"
            else:
                _, blob = single_public_record(data)
                entry["fingerprint"] = host_key_fingerprint(kind, blob)
                with tempfile.TemporaryDirectory(prefix="sc-hostkey-") as folder:
                    snapshot = Path(folder) / "host.pub"
                    snapshot.write_bytes(data)
                    detail = run(["ssh-keygen", "-lf", str(snapshot)], timeout=10).stdout.split()
                if len(detail) < 2 or detail[1] != entry["fingerprint"]:
                    fail("Local host public key failed ssh-keygen validation.")
                if kind == "ssh-rsa" and (not detail[0].isdigit() or int(detail[0]) < 2048):
                    fail("Weak RSA host key (under 2048 bits).")
                # A .pub file alone is not evidence sshd can use its matching
                # private host key. Verify regular owner-only private material,
                # then compare only derived PUBLIC halves, never print secrets.
                private = Path(item)
                try:
                    private_stat = os.lstat(private)
                except FileNotFoundError:
                    entry["private"] = "MISSING"
                except OSError as exc:
                    entry["private"] = f"UNREADABLE ({exc})"
                else:
                    if (not stat.S_ISREG(private_stat.st_mode)
                            or private_stat.st_uid not in (0, os.geteuid())
                            or private_stat.st_mode & 0o077):
                        entry["private"] = "UNSAFE TYPE, OWNER OR PERMISSIONS"
                    else:
                        try:
                            derived = run(["ssh-keygen", "-y", "-P", "",
                                           "-f", str(private)], timeout=12)
                            derived_type, derived_blob = single_public_record(
                                derived.stdout.encode("utf-8"))
                            entry["private"] = ("PAIR MATCH" if (derived_type, derived_blob) == (kind, blob)
                                                else "PUBLIC/PRIVATE KEY MISMATCH")
                        except (ConnectError, OSError) as exc:
                            entry["private"] = f"PAIR UNVERIFIED ({exc})"
                allowed = host_key_signature_algorithms(kind).split(",")
                entry["enabled"] = (entry["private"] == "PAIR MATCH"
                                    and report["configured"]
                                    and bool(accepted.intersection(allowed)))
                if entry["private"] != "PAIR MATCH":
                    entry["status"] = f"HOST KEY NOT READY: private {entry['private']}"
                elif not report["configured"]:
                    entry["status"] = "FILE PRESENT; effective config unknown"
                elif item not in configured_paths:
                    entry["enabled"] = False
                    entry["status"] = "FILE PRESENT; NOT configured by sshd"
                elif entry["enabled"]:
                    entry["status"] = "FILE PRESENT; matched pair, configured/algorithm enabled; listener UNVERIFIED"
                else:
                    entry["status"] = "FILE PRESENT; host-key algorithm disabled"
        except FileNotFoundError:
            pass
        except (ConnectError, OSError) as exc:
            entry["status"] = f"INVALID/UNREADABLE: {exc}"
        report["keys"].append(entry)

    if not report["active"]:
        report["notes"].append("SSH systemd service not confirmed active; inspect socket activation/listeners.")
    if not report["ports"]:
        report["notes"].append("No verified effective SSH port; do not assume 22.")
    if not any(item["enabled"] for item in report["keys"]):
        report["notes"].append("No verified configured supported host identity; check sshd config and keys.")
    if probe and report["ports"]:
        # This read-only loopback observation is exact (port, algorithm,
        # fingerprint). A type-only dictionary silently loses a key when
        # sshd config has multiple HostKey entries of the same algorithm.
        if len(report["ports"]) > 4:
            report["notes"].append("Only the first four configured SSH ports were probed.")
        for port in report["ports"][:4]:
            try:
                result = run(["ssh-keyscan", "-4", "-T", "3",
                              "-t", "ed25519,ecdsa,rsa", "-p", str(port),
                              "127.0.0.1"], check=False, timeout=12)
                seen: set[tuple[str, str]] = set()
                for row in result.stdout.splitlines():
                    fields = row.split()
                    if not row or row.startswith("#") or len(fields) != 3:
                        continue
                    kind = fields[1]
                    if kind not in HOST_KEY_ALGORITHMS:
                        continue
                    try:
                        fingerprint = host_key_fingerprint(kind, fields[2])
                    except ConnectError as exc:
                        report["notes"].append(f"Invalid local SSH host-key scan at port {port}: {exc}")
                        continue
                    matched = [entry for entry in report["keys"]
                               if entry["enabled"] and entry["type"] == kind
                               and entry["fingerprint"] == fingerprint]
                    if not matched:
                        report["notes"].append(
                            f"Unmatched localhost:{port} {kind} identity; do not trust by type alone.")
                        continue
                    for entry in matched:
                        entry["observed_ports"].append(port)
                        observed_at = ", ".join(map(str, entry["observed_ports"]))
                        entry["status"] = (f"OBSERVED exact fingerprint on localhost port(s): "
                                           f"{observed_at}; signature negotiation not yet tested")
                    seen.add((kind, fingerprint))
                if seen:
                    report["observed"].append({
                        "port": port,
                        "identities": [{"type": kind, "fingerprint": fingerprint}
                                       for kind, fingerprint in sorted(seen)],
                    })
                else:
                    report["notes"].append(f"No matching key observed on localhost:{port}; external-only listeners may differ.")
            except (ConnectError, OSError) as exc:
                report["notes"].append(f"Local SSH probe on port {port} failed: {exc}")
        report["notes"].append("RSA host-key scans do not prove RSA-SHA2 negotiation; test with strict SSH client.")
    return report


def terminal_note(message: str, *, indent: str = "  ",
                  tone: str | None = None) -> None:
    """Wrap guidance but never split long technical tokens or fingerprints."""
    for row in textwrap.wrap(message, width=max(18, terminal_width() - len(indent)),
                             break_long_words=False, break_on_hyphens=False) or [""]:
        print(indent + (paint(row, tone) if tone else row))


def terminal_section(label: str) -> None:
    """Quiet grouping shared by the menu, diagnostics and onboarding."""
    print()
    terminal_note(label, tone="heading")


def terminal_field(label: str, value: str, *, tone: str | None = None) -> None:
    """Readable key/value groups; never include ANSI bytes in width calculation."""
    head = f"{label}: "
    width = terminal_width()
    if len(head) > (width - 2) // 2:
        # A long label and value compete at 40 columns. Stack them instead
        # of leaving a confusing bare continuation without a visible label.
        terminal_note(label + ":", indent="  ", tone="muted")
        terminal_note(value, indent="    ", tone=tone)
        return
    rows = textwrap.wrap(head + value, width=max(18, width - 2),
                         break_long_words=False, break_on_hyphens=False) or [head]
    for row in rows:
        if row.startswith(head):
            print("  " + paint(label + ":", "muted") + " "
                  + (paint(row[len(head):], tone) if tone else row[len(head):]))
        else:
            print("  " + (paint(row, tone) if tone else row))


def terminal_warning(message: str) -> None:
    terminal_note("WARNING: " + message, tone="warn")


def show_advanced_server_host_fingerprints(info: dict) -> None:
    """All identities stay available, but do not crowd the primary choice."""
    terminal_section("Advanced SERVER host key diagnostics (PUBLIC keys only):")
    for entry in info["keys"]:
        print()
        terminal_note(f"{entry['type']}: {entry['fingerprint'] or 'no valid fingerprint'}",
                      tone="heading" if entry["enabled"] else "warn")
        terminal_field("Status", entry["status"],
                       tone="warn" if not entry["enabled"] else None)
        terminal_field("Public path", entry["path"])
        terminal_field("Private pair", entry["private"],
                       tone="warn" if entry["private"] != "PAIR MATCH" else None)
    if info["notes"]:
        terminal_section("ADDITIONAL SSH DIAGNOSTICS")
        for note in info["notes"]:
            terminal_warning(note)


def show_server_host_fingerprints(*, probe: bool = True, advanced: bool = False) -> dict:
    require_root()
    if (ETC / "role").is_symlink() or not (ETC / "role").is_file() or (
            ETC / "role").read_text().strip() != "server":
        fail("SERVER fingerprint action requires SERVER role; no client key is shown.")
    info = server_host_report(probe=probe)
    terminal_section("SERVER SSH / PUBLIC HOST IDENTITY")
    terminal_field("SSH service",
                   "ACTIVE (systemd)" if info["active"] else "NOT VERIFIED ACTIVE",
                   tone="good" if info["active"] else "warn")
    terminal_field("Effective configured SSH port(s)",
                   ", ".join(map(str, info["ports"])) or "UNKNOWN",
                   tone=None if info["ports"] else "warn")

    ready = [entry for entry in info["keys"]
             if entry["enabled"] and entry["fingerprint"]]
    observed_ports: dict[tuple[str, str], set[int]] = {}
    for scan in info["observed"]:
        for identity in scan["identities"]:
            pair = (identity["type"], identity["fingerprint"])
            observed_ports.setdefault(pair, set()).add(scan["port"])
    # Prefer the exact identity locally offered, never merely its algorithm.
    if probe and any((entry["type"], entry["fingerprint"]) in observed_ports for entry in ready):
        ready = [entry for entry in ready
                 if (entry["type"], entry["fingerprint"]) in observed_ports]
    ranking = {kind: index for index, kind in enumerate(HOST_KEY_ORDER)}
    ready.sort(key=lambda entry: (ranking.get(entry["type"], len(ranking)),
                                  entry["fingerprint"], entry["path"]))
    best = ([entry for entry in ready
             if ranking.get(entry["type"], len(ranking)) ==
                ranking.get(ready[0]["type"], len(ranking))] if ready else [])
    # Multiple different keys of the preferred algorithm, even on separate
    # ports, have no unambiguous default CLIENT fingerprint. A caller must
    # choose the exact verified identity for the intended listener.
    ambiguous = len({(entry["type"], entry["fingerprint"]) for entry in best}) > 1
    if ambiguous:
        terminal_section("MANUAL SELECTION REQUIRED")
        terminal_warning("AMBIGUOUS SERVER identity: multiple distinct "
                         "keys of the preferred algorithm. No single fingerprint "
                         "can be recommended for all listeners.")
        terminal_note("Inspect Advanced for exact fingerprints and observed "
                      "localhost ports. Verify the intended SERVER port and "
                      "its specific identity before configuring the CLIENT.")
    elif ready:
        selected = ready[0]
        kind = selected["type"]
        friendly = ("ED25519 (ssh-ed25519)" if kind == "ssh-ed25519" else
                    "RSA (SHA-2 signatures only)" if kind == "ssh-rsa" else
                    "ECDSA (" + kind + ")")
        terminal_section("RECOMMENDED SERVER HOST KEY")
        terminal_field("Recommended SERVER host key", friendly, tone="heading")
        terminal_note("Copy this PUBLIC SHA256 fingerprint to the CLIENT:", tone="heading")
        print(selected["fingerprint"])  # One complete, directly copyable token.
        ports = sorted(observed_ports.get((kind, selected["fingerprint"]), set()))
        if probe and ports:
            terminal_note("Exact fingerprint matched on localhost port(s): "
                          + ", ".join(map(str, ports)) + ". External SSH reachability "
                          "and authenticated signature negotiation are UNVERIFIED.")
        else:
            terminal_note("Verified configured local key pair only. The SSH "
                          "listener and remote authentication are UNVERIFIED.")
        terminal_section("NEXT STEP ON CLIENT")
        terminal_note("On the CLIENT: option 3 (Configure SSH), enter the "
                      "SERVER IP/user/port, choose a CLIENT private key FILE, "
                      "then paste this SHA256 value at step 5.", tone="heading")
    else:
        terminal_section("NO RECOMMENDATION AVAILABLE")
        terminal_warning("NO SAFE SUPPORTED SERVER host identity verified; "
                         "do not pin an arbitrary key. Inspect Advanced diagnostics.")

    warnings = []
    unready = [entry for entry in info["keys"] if not entry["enabled"]]
    if unready:
        warnings.append(f"{len(unready)} other host key(s) are missing, "
                        "disabled, unsupported or unsafe; see Advanced diagnostics.")
    if not info["active"]:
        warnings.append("SSH service not confirmed active.")
    if not info["ports"]:
        warnings.append("SSH port is unknown; inspect effective sshd configuration.")
    if len(info["ports"]) > 1:
        warnings.append("Multiple configured ports; verify which listener "
                        "your CLIENT can actually reach.")
    if probe and not info["observed"]:
        warnings.append("No matching localhost host key observed. "
                        "An external-only listener may behave differently.")
    if not probe:
        warnings.append("Local files and sshd configuration are not proof of an "
                        "actual listening SSH connection.")
    if warnings:
        terminal_section("WARNINGS / LIMITATIONS")
        for warning in warnings:
            terminal_warning(warning)
    terminal_note("Advanced diagnostics show all algorithms, paths and readiness; "
                  "no sshd or key changes were made.", tone="muted")
    if advanced:
        show_advanced_server_host_fingerprints(info)
    return info


def status() -> None:
    """Read-only state report: colors describe local observations, not field acceptance."""
    role_path = ETC / "role"
    if role_path.is_symlink():
        fail("Unsafe role path (symlink); status cannot be trusted.")
    if not role_path.is_file():
        print(f"Simple Connect: {VERSION}")
        terminal_field("Role", "NOT INSTALLED", tone="warn")
        terminal_field("State", "NOT INSTALLED (no Simple Connect network state verified)",
                       tone="warn")
        return
    role = role_path.read_text().strip()
    if role == "server":
        print(f"Simple Connect: {VERSION} | SERVER (no proxy/tunnel)")
        show_server_host_fingerprints(probe=False)
        return
    if role != "client":
        fail("Unknown Simple Connect role; inspect role file, no network state inferred.")
    state = read_json(STATE, {"status": "UNKNOWN"})
    label = str(state.get("status", "UNKNOWN"))
    active = is_active(SERVICE)
    guard_active = is_active(GUARD_TIMER)
    nft_available = shutil.which("nft") is not None
    table = current_table(state) if nft_available and label != "DIRECT" else None
    untracked = any_proxy_tables() if label == "DIRECT" and nft_available else False
    expected_sha = state.get("table_sha256")
    # table_hash() persists hashlib.hexdigest(): exactly 64 lowercase hex
    # characters. Noncanonical/malformed values cannot establish ownership,
    # and must not be reported as a valid but changed recorded fingerprint.
    valid_sha = (isinstance(expected_sha, str)
                 and re.fullmatch(r"[0-9a-f]{64}", expected_sha) is not None)
    verified_table = (table is not None and valid_sha
                      and table_is_ours(table, expected_sha))
    # ACTIVE is a persisted state label, not proof of safe firewall ownership.
    # Do not give that overall label a green health cue while the observation
    # is unverifiable, changed, missing, or the service/guard is unhealthy.
    if label == "ACTIVE":
        if not active or not guard_active or (nft_available and table is None):
            tone = "error"
        elif not nft_available or not valid_sha:
            tone = "warn"
        else:
            tone = "good" if verified_table else "error"
    elif label == "DIRECT":
        tone = ("error" if untracked or active else
                "good" if nft_available and guard_active else "warn")
    else:
        tone = "warn" if label == "PENDING" else "error"
    print(f"Simple Connect: {VERSION}")
    terminal_section("CONNECTION")
    terminal_field("Role", "CLIENT")
    terminal_field("State", label, tone=tone)
    service_tone = ("good" if active == (label in ("PENDING", "ACTIVE"))
                    else "error")
    terminal_field("Proxy service", "running" if active else "stopped",
                   tone=service_tone)
    if label != "DIRECT":
        terminal_field("Proxy listener port", str(proxy_port(state)))
    terminal_section("RECOVERY / OWNED FIREWALL")
    terminal_field("Independent guard", "running" if guard_active else "not active",
                   tone="good" if guard_active else "warn")
    if label == "DIRECT":
        # Absence is only a healthy observation after an actual nft inspection.
        if not nft_available:
            terminal_field("Owned nftables table", "UNVERIFIED (nft unavailable)", tone="warn")
        else:
            terminal_field("Owned nftables table",
                           "untracked table(s) present" if untracked else "absent",
                           tone="error" if untracked else "good")
            if untracked:
                terminal_warning("Untracked sshuttle nftables table(s) present; inspect manually.")
    elif not nft_available:
        terminal_field("Owned nftables table", "UNVERIFIED (nft unavailable)", tone="warn")
        terminal_field("Table identity", "UNVERIFIED (cannot inspect)", tone="warn")
    elif table is None:
        terminal_field("Owned nftables table", "absent", tone="error")
        terminal_field("Table identity", "ABSENT", tone="error")
    else:
        # A matching table name proves presence only, never ownership. Do not
        # show green unless the *full* persisted snapshot hash verifies.
        if not valid_sha:
            missing = expected_sha is None or expected_sha == ""
            identity = ("UNVERIFIED (no saved SHA256)" if missing
                        else "UNVERIFIED (invalid SHA256)")
            table_tone = "warn"
        elif verified_table:
            identity, table_tone = "MATCH", "good"
        else:
            identity, table_tone = "CHANGED", "error"
        terminal_field("Owned nftables table", "present", tone=table_tone)
        terminal_field("Table identity", identity, tone=table_tone)
        if identity.startswith("UNVERIFIED"):
            terminal_warning("Table ownership cannot be verified without a valid saved SHA256; "
                             "do not adopt or delete it.")
        elif identity == "CHANGED":
            terminal_warning("Table differs from recorded ownership SHA256; "
                             "do not adopt or delete it.")
    if label == "PENDING":
        terminal_field("Confirmation operation", str(state.get("op")))
        terminal_field("Confirmation expires at UTC timestamp", str(state.get("deadline")))
    if state.get("last_recovery"):
        terminal_field("Last recovery reason", str(state["last_recovery"]))
    terminal_note("These are local checks; external egress, DNS leaks and application "
                  "reachability require separate field verification.", tone="muted")


def test_path(url: str) -> None:
    require_client_role()
    read_config()
    if not url.startswith("https://") or " " in url or len(url) > 500:
        fail("Test URL must be a short HTTPS URL.")
    remote_python_test()
    with tempfile.TemporaryDirectory(prefix="sc-probe-") as tmp:
        dest = str(Path(tmp) / "download")
        p = subprocess.run(
            ["curl", "--noproxy", "*", "--ipv4", "--fail", "--location", "--silent",
             "--show-error", "--connect-timeout", "10", "--max-time", "35",
             "--max-filesize", "15000000", "--output", dest, url],
            text=True, capture_output=True, timeout=40,
        )
        if p.returncode != 0:
            fail(f"Download failed (curl {p.returncode}): {p.stderr[-500:]}")
        size = os.path.getsize(dest)
        if size < 1:
            fail("Download returned an empty file.")
        say(f"Full HTTPS GET succeeded: {size} bytes (no content-hash assertion).", "OK")
    say("Traffic-path attribution and DNS leak checks require separate field verification.", "WARN")


def logs() -> None:
    terminal_section("RECENT PROXY / GUARD JOURNAL (100 LINES)")
    run(["journalctl", "--no-pager", "-n", "100", "-u", SERVICE,
         "-u", GUARD_UNIT], timeout=12, capture=False)


def verify_uninstall_role(phase: str) -> None:
    """Role may disappear only after the units-removal checkpoint."""
    role = ETC / "role"
    if role.is_symlink() or (role.exists() and not role.is_file()):
        fail("Unexpected role file during uninstall; preserving resources.")
    if role.exists():
        if role.read_text().strip() != "client":
            fail("Uninstall reservation conflicts with the current host role.")
    elif UNINSTALL_PHASES.index(phase) < UNINSTALL_PHASES.index("UNITS_REMOVED"):
        fail("CLIENT role missing before verified unit removal; refuse recovery.")


def verify_uninstall_network(phase: str) -> None:
    """Never infer safe teardown from missing state or from a marker alone."""
    if not service_terminated() or any_proxy_tables():
        fail("Proxy or unknown firewall table remains: uninstall cannot advance.")
    if STATE.is_symlink() or (STATE.exists() and not STATE.is_file()):
        fail("Unsafe client state path during uninstall.")
    if STATE.exists():
        if read_json(STATE).get("status") != "DIRECT":
            fail("Recovery not DIRECT; preserve teardown marker and recovery files.")
    elif UNINSTALL_PHASES.index(phase) < UNINSTALL_PHASES.index("UNITS_REMOVED"):
        fail("Client state missing before verified unit removal; refuse teardown.")


def verify_uninstall_units() -> None:
    """Allow missing already-removed units, but never adopt foreign unit files."""
    for name, expected in unit_texts().items():
        path = UNIT_DIR / name
        if path.is_symlink() or (path.exists() and
             (not path.is_file() or path.read_text() != expected)):
            fail(f"Unexpected modified systemd unit {path}; refuse removal.")


def verify_uninstall_timer() -> None:
    if is_active(GUARD_TIMER):
        fail("Independent guard timer is still active; keep manager installed.")
    enabled = run(["systemctl", "is-enabled", GUARD_TIMER], check=False, timeout=10)
    if enabled.returncode == 0 or enabled.stdout.strip() not in (
            "disabled", "not-found", "masked"):
        fail("Cannot prove guard timer disabled; keep recovery executable.")


def verify_uninstall_payload_paths() -> None:
    for path in (CONF, SSH_CONF, KNOWN_HOSTS, STATE, ETC / "role", APP, COMMAND):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            fail(f"Unexpected non-file/symlink at {path}; no destructive cleanup.")
    if PKG.is_symlink() or (PKG.exists() and not PKG.is_dir()):
        fail("Unexpected package path; preserving it.")
    if PKG.exists():
        marker = PKG / ".wheel-sha256"
        if marker.is_symlink() or not marker.is_file() or marker.read_text().strip() != WHEEL_SHA256:
            fail("Unrecognized sshuttle package; refusing to delete foreign content.")


def finish_uninstalled_directories() -> None:
    """Resume the final narrow gap after the durable reservation was removed.

    Only empty, private Simple Connect directories may be removed here.
    This never adopts missing state as evidence that a proxy was safely
    stopped: systemd and nftables are checked again independently.
    """
    if teardown_pending():
        fail("Uninstall reservation still present; complete teardown first.")
    if not service_terminated() or any_proxy_tables():
        fail("Cannot finish uninstall: live proxy or firewall interception.")
    if is_active(GUARD_UNIT) or is_active(STOP_UNIT):
        fail("Cannot finish uninstall with an active Simple Connect helper.")
    verify_uninstall_timer()
    verify_uninstall_units()
    if any((UNIT_DIR / name).exists() or (UNIT_DIR / name).is_symlink()
           for name in unit_texts()):
        fail("Cannot finish uninstall while Simple Connect unit files remain.")
    verify_uninstall_payload_paths()
    if any(path.exists() or path.is_symlink()
           for path in (CONF, SSH_CONF, KNOWN_HOSTS, STATE, ETC / "role", APP, COMMAND, PKG)):
        fail("Cannot finish uninstall: installed payload still exists.")
    for directory in (ETC, STATE_DIR):
        if directory.is_symlink():
            fail(f"Unexpected symlinked directory {directory}.")
        if directory.exists():
            if not directory.is_dir() or any(directory.iterdir()):
                fail(f"Unexpected content in {directory}: no deletion performed.")
            directory.rmdir()


def uninstall(yes: bool) -> None:
    require_root()
    if not yes:
        fail("Uninstall destroys Simple Connect's private configuration. Use 'uninstall --yes'.")
    if ETC.is_symlink() or STATE_DIR.is_symlink():
        fail("Symlinked Simple Connect private directory: refuse uninstall.")
    role_path = ETC / "role"
    if role_path.is_symlink():
        fail("Symlinked role file: refusing uninstall.")
    if role_path.is_file() and role_path.read_text().strip() == "server":
        # Remote endpoint never installed any traffic interception.
        with locked():
            require_no_teardown()
            if STATE.exists() or not service_terminated():
                fail("Unexpected active CLIENT state on SERVER role; refusing ambiguous cleanup.")
            for path in (CONF, SSH_CONF, KNOWN_HOSTS, APP, COMMAND, role_path):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            if ETC.is_dir() and not any(ETC.iterdir()):
                ETC.rmdir()
        say("Server-side Simple Connect manager removed; existing SSH remains unchanged.", "OK")
        return

    with locked():
        if teardown_pending():
            # The verified reservation survives role/state/manager deletion.
            # reserve_uninstall also validates any legacy unphased marker.
            phase = reserve_uninstall()
            verify_uninstall_role(phase)
        elif role_path.is_file():
            require_client_role()
            phase = reserve_uninstall()
        elif not role_path.exists():
            finish_uninstalled_directories()
            say("Already uninstalled; any empty private directories cleaned.", "OK")
            return
        else:
            fail("Unexpected role path; refusing ambiguous uninstall.")

    # No manager lock across systemctl stop: ExecStopPost must take it.
    # Every stage is repeatable from its durable checkpoint. A crash
    # *within* a stage leaves the previous phase and is safe to retry.
    if phase == "RESERVED":
        stop_proxy(for_uninstall=True)
        with locked():
            verify_uninstall_role(phase)
            verify_uninstall_network(phase)
            advance_uninstall_phase("STOPPED")
        phase = "STOPPED"

    if phase == "STOPPED":
        with locked():
            verify_uninstall_role(phase)
            verify_uninstall_network(phase)
            verify_uninstall_units()
        # If a previous interrupted removal left the timer file absent,
        # use systemd's independent inactive/disabled proof to skip
        # the now-impossible unit file disable operation.
        if (UNIT_DIR / GUARD_TIMER).exists():
            unit_action("disable", "--now", GUARD_TIMER)
        elif is_active(GUARD_TIMER):
            unit_action("stop", GUARD_TIMER)
        verify_uninstall_timer()
        if is_active(GUARD_UNIT):
            unit_action("stop", GUARD_UNIT)
        if is_active(GUARD_UNIT):
            fail("Guard service still active; preserving recovery files.")
        with locked():
            verify_uninstall_network(phase)
            advance_uninstall_phase("TIMER_DISABLED")
        phase = "TIMER_DISABLED"

    if phase == "TIMER_DISABLED":
        verify_uninstall_network(phase)
        verify_uninstall_timer()
        verify_uninstall_units()
        if is_active(GUARD_UNIT):
            unit_action("stop", GUARD_UNIT)
        if is_active(GUARD_UNIT):
            fail("Guard service did not stop; retain recovery executables.")
        with locked():
            verify_uninstall_network(phase)
            for name in unit_texts():
                path = UNIT_DIR / name
                if path.exists():
                    path.unlink()
        unit_action("daemon-reload")
        verify_uninstall_timer()
        if is_active(GUARD_UNIT) or is_active(STOP_UNIT):
            fail("Simple Connect helper is active after unit removal.")
        with locked():
            verify_uninstall_network(phase)
            advance_uninstall_phase("UNITS_REMOVED")
        phase = "UNITS_REMOVED"

    if phase == "UNITS_REMOVED":
        with locked():
            verify_uninstall_role(phase)
            verify_uninstall_network(phase)
            verify_uninstall_timer()
            verify_uninstall_units()
            if any((UNIT_DIR / name).exists() or (UNIT_DIR / name).is_symlink()
                   for name in unit_texts()):
                fail("Unit files unexpectedly reappeared; preserving recovery assets.")
            if is_active(GUARD_UNIT) or is_active(STOP_UNIT):
                fail("A Simple Connect helper is still active.")
            # Validate every owned payload path BEFORE deleting any file.
            # A partial payload deletion is safe to resume: absent files
            # are accepted but foreign/symlinked paths are not.
            verify_uninstall_payload_paths()
            for path in (CONF, SSH_CONF, KNOWN_HOSTS):
                if path.is_file():
                    path.unlink()
            if PKG.exists():
                shutil.rmtree(PKG)
            # Keep the installed entrypoint until the last payload stage,
            # maximizing the chance that normal CLI retry stays available.
            for path in (STATE, role_path, COMMAND, APP):
                if path.is_file():
                    path.unlink()
            advance_uninstall_phase("PAYLOAD_REMOVED")
        phase = "PAYLOAD_REMOVED"

    if phase == "PAYLOAD_REMOVED":
        with locked():
            verify_uninstall_role(phase)
            verify_uninstall_network(phase)
            verify_uninstall_timer()
            verify_uninstall_units()
            if is_active(GUARD_UNIT) or is_active(STOP_UNIT):
                fail("Simple Connect helper is active; refusing to finalize uninstall.")
            verify_uninstall_payload_paths()
            if any(path.exists() or path.is_symlink()
                   for path in (CONF, SSH_CONF, KNOWN_HOSTS, STATE,
                                role_path, APP, COMMAND, PKG)):
                fail("Payload remains after teardown; reservation retained.")
            if any((UNIT_DIR / name).exists() or (UNIT_DIR / name).is_symlink()
                   for name in unit_texts()):
                fail("Unit files remain after teardown; reservation retained.")
            if ETC.is_symlink() or STATE_DIR.is_symlink():
                fail("Unexpected symlink in private directories; refusing cleanup.")
            if ETC.exists():
                if not ETC.is_dir() or any(ETC.iterdir()):
                    fail("Unexpected remaining configuration; retaining reservation.")
                ETC.rmdir()
            if not STATE_DIR.is_dir() or any(p != TEARDOWN for p in STATE_DIR.iterdir()):
                fail("Unexpected state-directory content; retaining reservation.")
            # Reservation is the final owned file to remove. If interrupted
            # between this unlink and rmdir, verified-manager uninstall
            # will finish the now-empty private directories safely.
            TEARDOWN.unlink()
            STATE_DIR.rmdir()

    say("Owned resources removed; SSH, foreign firewall rules and routes unchanged.", "OK")


def clear_menu() -> None:
    # Screen clearing is a terminal control, not a color; NO_COLOR does not disable it.
    if (sys.stdout.isatty()
            and os.environ.get("TERM", "") not in ("", "dumb")):
        print("\033[2J\033[H", end="", flush=True)


def menu_snapshot() -> dict[str, str]:
    """A read-only, fail-explanatory snapshot; no route or firewall changes."""
    result = {"role": "NOT INSTALLED", "state": "NOT INSTALLED",
              "service": "n/a", "guard": "n/a", "remote": "NOT CONFIGURED",
              "key": "NOT CONFIGURED", "note": "", "local": "UNKNOWN"}
    role_path = ETC / "role"
    try:
        if role_path.is_symlink():
            raise ConnectError("Unsafe role path (symlink).")
        if role_path.is_file():
            result["role"] = role_path.read_text().strip().upper()
            if result["role"] not in ("CLIENT", "SERVER"):
                raise ConnectError("Unrecognized role; do not change host networking.")
    except (OSError, ConnectError) as exc:
        result["role"] = "UNKNOWN"
        result["note"] = str(exc)

    if result["role"] == "SERVER":
        result["state"] = "SSH SERVER (no tunnel)"
        result["remote"] = "n/a (SSH endpoint)"
        info = server_host_report(probe=False)
        eligible = [item for item in info["keys"] if item["enabled"]]
        result["key"] = (f"{', '.join(item['type'] for item in eligible)} (key pairs checked; listener unverified)"
                         if eligible else "NO VERIFIED SUPPORTED HOST KEY")
        if not eligible or not info["active"]:
            result["note"] = "SSH host key or service readiness unverified; see SERVER fingerprints."
        try:
            result["service"] = "RUNNING" if is_active("ssh.service") or is_active("sshd.service") else "NOT ACTIVE"
        except (OSError, subprocess.TimeoutExpired):
            result["service"] = "UNKNOWN"
        result["guard"] = "n/a"
    if result["role"] == "CLIENT":
        try:
            state = read_json(STATE)
            result["state"] = str(state.get("status", "UNKNOWN"))
            if result["state"] not in ("DIRECT", "INSTALLING", "PENDING", "ACTIVE", "STOPPING", "UNCERTAIN"):
                raise ConnectError("Unrecognized state marker; inspect state and recovery before ON.")
            if result["state"] == "PENDING":
                result["note"] = "New, independently authenticated SSH connection needed to Confirm."
            if result["state"] == "UNCERTAIN":
                result["note"] = "Manual recovery required; do NOT start another tunnel."
        except (ConnectError, OSError) as exc:
            result["state"] = "UNKNOWN"
            result["note"] = str(exc)
        for field, unit in (("service", SERVICE), ("guard", GUARD_TIMER)):
            try:
                result[field] = "RUNNING" if is_active(unit) else "STOPPED"
            except (OSError, subprocess.TimeoutExpired) as exc:
                result[field] = "UNKNOWN"
                result["note"] = str(exc)
        if result["state"] == "DIRECT" and result["service"] == "RUNNING":
            result["note"] = "State says DIRECT but proxy service runs: investigate before ON."
        if result["state"] in ("ACTIVE", "PENDING") and result["service"] != "RUNNING":
            result["note"] = "Proxy state and systemd service disagree; inspect recovery before ON."
        if result["state"] in ("ACTIVE", "PENDING") and result["guard"] != "RUNNING":
            result["note"] = "Independent guard unavailable. Investigate before ON."
        try:
            if not shutil.which("nft"):
                if result["state"] in ("ACTIVE", "PENDING", "DIRECT") and not result["note"]:
                    result["note"] = "nftables command unavailable; firewall state not verified."
            else:
                state_detail = read_json(STATE, {"status": "UNKNOWN"})
                if result["state"] == "DIRECT" and any_proxy_tables():
                    result["note"] = "Intercepting nftables rules exist despite DIRECT state; inspect recovery."
                elif result["state"] in ("ACTIVE", "PENDING"):
                    table = current_table(state_detail)
                    fingerprint = state_detail.get("table_sha256")
                    if table is None or not fingerprint or not table_is_ours(table, fingerprint):
                        result["note"] = "Tunnel nftables ownership/identity not verified; inspect recovery."
        except (ConnectError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
            result["note"] = f"Unable to verify firewall state: {exc}"
        try:
            if result["state"] in ("ACTIVE", "PENDING") and not (CONF.exists() or CONF.is_symlink()):
                result["note"] = "Tunnel state present but SSH configuration missing; inspect recovery."
            if CONF.exists() or CONF.is_symlink():
                cfg = read_json(CONF)
                user = valid_user(str(cfg.get("ssh_user", "")))
                ip = validate_ipv4(str(cfg.get("remote_ip", "")), public=True)
                port = valid_port(str(cfg.get("ssh_port", "")))
                result["remote"] = f"{user}@{ip}:{port}"
                path = cfg.get("identity_file")
                if isinstance(path, str):
                    try:
                        private_key_path(path)
                        result["key"] = f"PRESENT: {path} (login untested)"
                    except (ConnectError, OSError):
                        result["key"] = "MISSING/UNSAFE"
                else:
                    result["key"] = "MISSING/UNSAFE"
        except (ConnectError, OSError, ValueError) as exc:
            result["remote"] = "INVALID CONFIG"
            result["key"] = "UNKNOWN"
            result["note"] = str(exc)

    try:
        p = subprocess.run(["ip", "-j", "-4", "address", "show", "scope", "global"],
                           text=True, capture_output=True, timeout=2)
        if p.returncode == 0:
            for nic in json.loads(p.stdout):
                for item in nic.get("addr_info", []):
                    if item.get("family") == "inet" and item.get("local"):
                        result["local"] = f"{item['local']} ({nic.get('ifname', '?')})"
                        return result
    except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
        pass
    return result


def menu_header(section: str = "MAIN MENU") -> dict:
    width = terminal_width()
    info = menu_snapshot()
    state = info["state"]
    state_tone = ("good" if state in ("DIRECT", "ACTIVE") and not info["note"]
                  else "warn" if state in ("PENDING", "NOT INSTALLED", "SSH SERVER (no tunnel)")
                  and not info["note"] else "error")
    print(paint("=" * width, "title"))
    print(f"  {paint('SIMPLE CONNECT', 'title')} v{VERSION}")
    print(f"  {paint(section, 'heading')}")
    print(paint("-" * width, "muted"))
    terminal_field("Role", info["role"])
    terminal_field("Link", state, tone=state_tone)
    terminal_field("Local IPv4", info["local"])
    if info["role"] == "SERVER":
        terminal_field("SSH service", info["service"],
                       tone="good" if info["service"] == "RUNNING" else "warn")
        terminal_field("SSH readiness", "Host keys and external login must be verified",
                       tone="warn")
    else:
        terminal_field("Proxy service", info["service"],
                       tone="good" if info["service"] == "RUNNING" and state in ("ACTIVE", "PENDING")
                       or info["service"] == "STOPPED" and state == "DIRECT" else "warn")
        terminal_field("Guard", info["guard"],
                       tone="good" if info["guard"] == "RUNNING" else "warn")
        has_remote = info["role"] == "CLIENT" and info["remote"] not in ("NOT CONFIGURED", "INVALID CONFIG")
        key_ready = info["key"].startswith("PRESENT: ")
        configured = "KEY PRESENT (SSH untested)" if has_remote and key_ready else (
            "INCOMPLETE" if has_remote else "NO")
        terminal_field("SSH configured", configured,
                       tone="heading" if has_remote and key_ready else "warn")
        if has_remote:
            terminal_field("Remote SSH", info["remote"])
        if info["role"] == "CLIENT":
            terminal_field("Client key", "PRESENT (login untested)" if key_ready else info["key"],
                           tone="heading" if key_ready else "warn")
    if info["note"]:
        terminal_warning("ATTENTION: " + info["note"])
    print(paint("-" * width, "muted"))
    return info


def menu_option(number: int, label: str, *, tone: str | None = None) -> None:
    """Stable numeric shortcuts, with color reserved for action consequences."""
    print(f"  {number:>2}) " + (paint(label, tone) if tone else label))


def menu_group(title: str) -> None:
    print()
    print(f"  {paint(title, 'heading')}")


def pause_menu() -> None:
    try:
        input(f"\n{paint('Press Enter to return to the menu...', 'muted')}")
    except (KeyboardInterrupt, EOFError):
        pass


def ssh_access_menu() -> None:
    while True:
        clear_menu()
        menu_header("SSH ACCESS")
        menu_group("CLIENT SSH / PUBLIC KEY ACCESS")
        menu_option(1, "Enroll selected PUBLIC key", tone="warn")
        menu_option(2, "Show PUBLIC key")
        menu_option(3, "Test authenticated SSH / Python")
        menu_option(4, "Configure SSH / choose key")
        menu_option(0, "Back to main menu")
        print()
        try:
            choice = input(f"{paint('Choose', 'heading')}: ").strip()
            if choice == "0":
                return
            if choice == "1":
                enroll_public_key()
            elif choice == "2":
                display_public_key()
            elif choice == "3":
                remote_python_test()
            elif choice == "4":
                configure(None, None, None, None, None)
            else:
                say("Invalid choice. Select 0..4.", "WARN")
        except (ConnectError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
            show_error(exc)
        except (KeyboardInterrupt, EOFError):
            say("SSH access operation cancelled; returning to main menu.", "WARN")
            return
        pause_menu()


def menu() -> None:
    if not sys.stdin.isatty():
        fail("Interactive menu requires a terminal (TTY). Use documented CLI subcommands for automation.")
    while True:
        clear_menu()
        info = menu_header()
        role = info.get("role", "") if isinstance(info, dict) else ""
        menu_group("SETUP")
        menu_option(1, "Setup remote SERVER" + (" (other role)" if role == "CLIENT" else ""))
        menu_option(2, "Setup Iran CLIENT" + (" (other role)" if role == "SERVER" else ""))
        menu_option(3, "Configure SSH (CLIENT only)" if role == "SERVER"
                    else "Configure SSH connection")
        menu_group("CONNECTION")
        menu_option(4, "Turn ON (CLIENT only)" if role == "SERVER"
                    else "Turn ON (field approval)", tone=None if role == "SERVER" else "warn")
        menu_option(5, "Confirm ON (CLIENT only)" if role == "SERVER"
                    else "Confirm ON (fresh SSH)")
        menu_option(6, "Turn OFF (CLIENT only)" if role == "SERVER"
                    else "Turn OFF", tone=None if role == "SERVER" else "good")
        menu_group("DIAGNOSTICS")
        menu_option(7, "Status")
        menu_option(8, "Test SSH (CLIENT only)" if role == "SERVER"
                    else "Test SSH + HTTPS")
        menu_option(9, "Logs (CLIENT only)" if role == "SERVER" else "Logs")
        menu_group("OTHER TOOLS / MAINTENANCE")
        menu_option(10, "Uninstall (destructive)", tone="error")
        menu_option(11, "SSH keys/access (CLIENT only)" if role == "SERVER"
                    else "SSH keys / access")
        menu_option(12, "SERVER fingerprints/Advanced" if role == "SERVER"
                    else "Show SERVER SSH fingerprints" if role != "CLIENT"
                    else "SERVER keys (SERVER only)")
        menu_option(0, "Exit")
        print()
        try:
            choice = input(f"{paint('Choose', 'heading')}: ").strip()
            if choice == "0":
                return
            if choice == "1":
                with locked(wait_seconds=6):
                    setup("server", WHEEL_URL)
            elif choice == "2":
                with locked(wait_seconds=6):
                    setup("client", WHEEL_URL)
                if not CONF.exists():
                    say("Client is DIRECT/OFF. Choose Configure SSH (3) for guided onboarding.", "INFO")
            elif choice == "3":
                configure(None, None, None, None, None)
            elif choice == "4":
                start_proxy()
            elif choice == "5":
                confirm(input("Operation ID from PENDING state: ").strip())
            elif choice == "6":
                stop_proxy()
            elif choice == "7":
                status()
            elif choice == "8":
                test_path("https://www.debian.org/")
            elif choice == "9":
                logs()
            elif choice == "10":
                uninstall(input(paint("Type YES to uninstall: ", "error")).strip() == "YES")
            elif choice == "11":
                if role == "SERVER":
                    say("SSH keys/access is CLIENT-only. On this SERVER, use option 12 "
                        "for the public host fingerprint.", "WARN")
                else:
                    ssh_access_menu()
                    continue
            elif choice == "12":
                report = show_server_host_fingerprints()
                if yes_no("Show Advanced host key diagnostics?", default=False):
                    show_advanced_server_host_fingerprints(report)
            else:
                say("Invalid option. Choose one of the numbered menu entries.", "WARN")
        except (ConnectError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
            show_error(exc)
        except KeyboardInterrupt:
            say("Operation interrupted. If networking had begun changing, inspect Status before retrying.", "WARN")
        except EOFError:
            say("Input ended; leaving the interactive menu.", "WARN")
            return
        pause_menu()


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple Connect sshuttle manager (no auto-on after reboot)")
    sub = parser.add_subparsers(dest="action")
    setup_cmd = sub.add_parser("setup")
    setup_cmd.add_argument("role", choices=["client", "server"])
    setup_cmd.add_argument("--wheel-url", default=WHEEL_URL, help="HTTPS mirror of pinned wheel")
    c = sub.add_parser("configure")
    c.add_argument("--remote-ip")
    c.add_argument("--ssh-user")
    c.add_argument("--ssh-port", type=int)
    c.add_argument("--identity-file")
    c.add_argument("--fingerprint", help="SHA256 of independently verified ED25519/ECDSA/RSA host key")
    for action in ("on", "off", "status", "logs", "guard", "recover", "internal-run"):
        sub.add_parser(action)
    h = sub.add_parser("host-fingerprints", help="Recommended SERVER fingerprint (read-only)")
    h.add_argument("--advanced", action="store_true", help="Show all host identities and diagnostics")
    cf = sub.add_parser("confirm")
    cf.add_argument("operation_id")
    t = sub.add_parser("test")
    t.add_argument("--url", default="https://www.debian.org/")
    u = sub.add_parser("uninstall")
    u.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    try:
        if args.action is None:
            menu()
        elif args.action == "setup":
            # Installation does not launch an error-prone wizard: the bootstrap
            # opens the persistent menu on the same TTY after setup succeeds.
            with locked(wait_seconds=6):
                setup(args.role, args.wheel_url)
        elif args.action == "configure":
            configure(args.remote_ip, args.ssh_user, args.ssh_port, args.identity_file, args.fingerprint)
        elif args.action == "on":
            start_proxy()
        elif args.action == "off":
            stop_proxy()
        elif args.action == "confirm":
            confirm(args.operation_id)
        elif args.action == "status":
            status()
        elif args.action == "host-fingerprints":
            show_server_host_fingerprints(advanced=args.advanced)
        elif args.action == "test":
            test_path(args.url)
        elif args.action == "logs":
            logs()
        elif args.action == "uninstall":
            uninstall(args.yes)
        elif args.action == "guard":
            guard()
        elif args.action == "recover":
            recover()
        elif args.action == "internal-run":
            service_run()
        return 0
    except ConnectError as exc:
        show_error(exc)
        return 1
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        show_error(exc)
        return 1
    except KeyboardInterrupt:
        say("Interrupted. Inspect Status before retrying any in-progress networking action.", "WARN")
        return 130
    except EOFError:
        say("Interactive input ended. Use explicit CLI flags for automation.", "WARN")
        return 1


if __name__ == "__main__":
    sys.exit(main())
