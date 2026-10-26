#!/usr/bin/env python3
"""Simple Connect: a small, guarded sshuttle manager for Debian Linux hosts.

This file is also the installed management entry point. It never chooses a
remote endpoint, creates SSH credentials, or enables traffic during setup.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

VERSION = "0.1.0-dev"
SCHEMA_VERSION = 1
SSHUTTLE_VERSION = "2.0.0"
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


class ConnectError(Exception):
    pass


def say(message: str, kind: str = "INFO") -> None:
    colors = {"INFO": "\033[36m", "OK": "\033[32m", "WARN": "\033[33m", "ERROR": "\033[31m"}
    prefix = f"[{kind}]"
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        prefix = f"{colors.get(kind, '')}{prefix}\033[0m"
    print(prefix, message, flush=True)


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
def locked():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another Simple Connect operation is running. Try again shortly.")
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
    key = Path(str(cfg["identity_file"]))
    if not key.is_absolute() or re.search(r"[\n\r\x00]", str(key)):
        fail("Identity file must be an absolute path.")
    if not key.is_file() or key.is_symlink():
        fail(f"Identity file missing or unsafe: {key}")
    cfg["identity_file"] = str(key)
    return cfg


def banner() -> None:
    print("\n" + "\033[1;34m" + "  SIMPLE CONNECT  " + "\033[0m" + f"v{VERSION}")
    print("  SSH-based outbound IPv4 TCP / DNS  |  default DIRECT\n")


def install_requirements(role: str) -> None:
    if not Path("/etc/os-release").exists():
        fail("Only apt-based Linux hosts are supported at present.")
    needed = {"python3": "python3", "ssh-keygen": "openssh-client", "ssh-keyscan": "openssh-client"}
    if role == "server":
        needed["sshd"] = "openssh-server"
    else:
        needed.update({"ssh": "openssh-client", "nft": "nftables", "curl": "curl"})
    missing = sorted({pkg for exe, pkg in needed.items() if shutil.which(exe) is None})
    if missing:
        if shutil.which("apt-get") is None:
            fail(f"Missing dependencies: {', '.join(missing)}; apt-get not available.")
        say(f"Installing missing packages ONLY: {', '.join(missing)}")
        run(["apt-get", "update"], timeout=150, capture=False)
        run(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=240, capture=False)
    if sys.version_info < (3, 9):
        fail("Python >=3.9 is required; the system Python is too old.")
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


def setup(role: str, wheel_url: str) -> None:
    require_root()
    if is_active(SERVICE):
        fail("Stop and recover the active proxy before running setup or updating files.")
    install_requirements(role)
    role_path = ETC / "role"
    if role_path.is_file() and role_path.read_text().strip() != role:
        fail(f"Host already configured as {role_path.read_text().strip()}; switch roles only after cleanup.")
    install_entrypoint()
    ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write(role_path, (role + "\n").encode())
    if role == "server":
        host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub")
        if host_key.is_file():
            fingerprint = run(["ssh-keygen", "-lf", str(host_key)]).stdout.strip()
            say(f"Remote SSH ED25519 host identity (verify using trusted console): {fingerprint}", "OK")
        if not is_active("ssh.service") and not is_active("sshd.service"):
            say("SSH server is not confirmed active. Configure SSH service and credentials before connecting.", "WARN")
        say("Server role ready. No public proxy, tunnel, account or firewall rule created.", "OK")
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
    if not STATE.exists():
        write_json(STATE, {"status": "DIRECT"})
    say("Client installed (Direct/OFF). Network interception is NOT enabled.", "OK")
    if not CONF.exists() and sys.stdin.isatty():
        answer = input("Configure remote SSH endpoint now? [Y/n] ").strip().lower()
        if answer in ("", "y", "yes"):
            configure(None, None, None, None, None)


def ask(value: str | None, label: str, default: str | None = None) -> str:
    if value is not None:
        return value.strip()
    if not sys.stdin.isatty():
        fail(f"Missing {label}. Supply explicit configuration flags.")
    suffix = f" [{default}]" if default is not None else ""
    entered = input(f"{label}{suffix}: ").strip()
    return entered or (default or "")


def configure(remote_ip: str | None, ssh_user: str | None, ssh_port: int | None,
              identity_file: str | None, fingerprint: str | None) -> None:
    require_root()
    if is_active(SERVICE):
        fail("Switch OFF before changing the SSH endpoint.")
    remote_ip = ask(remote_ip, "Remote public IPv4")
    ssh_user = ask(ssh_user, "SSH username", "root")
    try:
        ssh_port = int(ask(str(ssh_port) if ssh_port else None, "SSH port", "22"))
    except ValueError:
        fail("SSH port must be an integer from 1 to 65535.")
    identity_file = ask(identity_file, "Private key path", "/root/.ssh/id_ed25519")
    cfg = validate_config({
        "remote_ip": remote_ip, "ssh_user": ssh_user, "ssh_port": ssh_port,
        "identity_file": identity_file,
    })
    ETC.mkdir(parents=True, exist_ok=True)
    response = run(["ssh-keyscan", "-4", "-T", "7", "-t", "ed25519",
                    "-p", str(cfg["ssh_port"]), cfg["remote_ip"]], timeout=15)
    keys = [line for line in response.stdout.splitlines()
            if line and not line.startswith("#") and len(line.split()) == 3
            and line.split()[1] == "ssh-ed25519"]
    if len(keys) != 1:
        fail("Expected exactly one ED25519 host key; refusing ambiguous trust.")
    with tempfile.TemporaryDirectory() as d:
        keyfile = Path(d) / "key"
        keyfile.write_text(keys[0] + "\n")
        observed = run(["ssh-keygen", "-lf", str(keyfile)]).stdout.split()
    if len(observed) < 2:
        fail("Could not read SSH host fingerprint.")
    actual = observed[1]
    expected = ask(fingerprint, "Trusted remote ED25519 fingerprint (SHA256:...)")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected) or expected != actual:
        fail(f"Fingerprint mismatch. Observed {actual}. Verify via provider console; nothing saved.")
    host = cfg["remote_ip"]
    port = cfg["ssh_port"]
    sshcfg = (
        "Host sc-remote\n"
        f"  HostName {host}\n  User {cfg['ssh_user']}\n  Port {port}\n"
        f"  IdentityFile {cfg['identity_file']}\n"
        f"  UserKnownHostsFile {KNOWN_HOSTS}\n"
        "  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n"
        "  BatchMode yes\n  AddressFamily inet\n"
        "  ConnectTimeout 10\n  ConnectionAttempts 1\n"
        "  ServerAliveInterval 10\n  ServerAliveCountMax 3\n"
        "  ClearAllForwardings yes\n"
    )
    atomic_write(KNOWN_HOSTS, (keys[0] + "\n").encode())
    atomic_write(SSH_CONF, sshcfg.encode())
    write_json(CONF, cfg)
    say("SSH identity pinned; configuration saved. Try 'simple-connect test' before ON.", "OK")


def read_config() -> dict:
    return validate_config(read_json(CONF))


def remote_python_test() -> None:
    p = run(["ssh", "-F", str(SSH_CONF), "sc-remote",
             'python3 -c "import sys; assert sys.version_info >= (3, 9)"'],
            timeout=25)
    say("Authenticated SSH and remote Python >=3.9 verified.", "OK")


def initial_ssh_connection() -> str:
    value = os.getenv("SSH_CONNECTION", "").strip()
    parts = value.split()
    if len(parts) != 4:
        fail("Run ON from an authenticated SSH terminal (SSH_CONNECTION missing).")
    validate_ipv4(parts[0])
    if not all(p.isdigit() and 0 < int(p) <= 65535 for p in (parts[1], parts[3])):
        fail("SSH_CONNECTION contains invalid ports.")
    validate_ipv4(parts[2])
    return " ".join(parts)


def boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def current_table() -> dict | None:
    proc = subprocess.run(
        ["nft", "-j", "list", "table", "ip", TABLE],
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


def ensure_stopped() -> None:
    if is_active(SERVICE):
        fail("Cannot proceed while the proxy is already running.")
    if current_table() is not None:
        fail(f"Existing nftables table '{TABLE}' detected: refuse to adopt/overwrite it.")
    state = read_json(STATE, {"status": "DIRECT"})
    if state.get("status") != "DIRECT":
        fail(f"State is {state.get('status', 'UNKNOWN')}. Run off/recover before ON.")


def owned_cleanup(state: dict) -> bool:
    table = current_table()
    if table is None:
        return True
    expected = state.get("table_sha256", "")
    if not isinstance(expected, str) or not table_is_ours(table, expected):
        say(f"UNCERTAIN: nftables table {TABLE} differs from recorded owned state. Manual inspection needed.", "ERROR")
        return False
    run(["nft", "delete", "table", "ip", TABLE], timeout=10)
    return current_table() is None


def reconcile(reason: str) -> None:
    state = read_json(STATE, {"status": "DIRECT"})
    if owned_cleanup(state):
        write_json(STATE, {"status": "DIRECT", "last_recovery": reason})
        say(f"Direct networking restored/verified for owned nftables table ({reason}).", "OK")
    else:
        write_json(STATE, {**state, "status": "UNCERTAIN", "last_recovery": reason})
        fail("Partial rollback: non-owned or changed rules may exist. Use provider console; no blind flush.")


def start_proxy() -> None:
    require_root()
    with locked():
        cfg = read_config()
        if not is_active(GUARD_TIMER):
            fail("Independent guard timer inactive. Run setup-client; do not bypass the guard.")
        ensure_stopped()
        ssh_conn = initial_ssh_connection()
        remote_python_test()
        op = secrets.token_hex(8)
        state = {
            "status": "PENDING", "op": op, "boot": boot_id(),
            "started": int(time.time()), "deadline": int(time.time()) + 600,
            "original_ssh_connection": ssh_conn, "management_ip": ssh_conn.split()[0],
            "remote_ip": cfg["remote_ip"], "table_sha256": "",
        }
        write_json(STATE, state)
        try:
            unit_action("start", SERVICE)
            if not is_active(SERVICE):
                fail("sshuttle service did not enter ACTIVE state.")
            table = current_table()
            if table is None:
                fail("No expected nftables table after sshuttle startup.")
            state["table_sha256"] = table_hash(table)
            write_json(STATE, state)
        except Exception:
            subprocess.run(["systemctl", "stop", SERVICE], timeout=30)
            try:
                reconcile("failed_activation")
            except ConnectError:
                pass
            raise
    say(f"Proxy started in PENDING state; automatic rollback deadline ~10 minutes. Operation: {op}", "WARN")
    say(f"From a NEW authenticated SSH session, run: sudo simple-connect confirm {op}")


def confirm(op: str) -> None:
    require_root()
    with locked():
        state = read_json(STATE)
        if state.get("status") != "PENDING" or not secrets.compare_digest(str(state.get("op", "")), op):
            fail("No matching pending activation operation.")
        if state.get("boot") != boot_id() or int(time.time()) >= int(state.get("deadline", 0)):
            fail("Confirmation deadline expired or server rebooted. Recovery required.")
        fresh = initial_ssh_connection()
        if fresh == state.get("original_ssh_connection"):
            fail("Confirmation MUST come from a fresh independent SSH session.")
        if not is_active(SERVICE):
            fail("Proxy process is not active.")
        table = current_table()
        if table is None or not table_is_ours(table, str(state.get("table_sha256", ""))):
            fail("Firewall state changed or is missing; confirmation refused.")
        state["status"] = "ACTIVE"
        state["confirmed_at"] = int(time.time())
        state.pop("deadline", None)
        write_json(STATE, state)
    say("ACTIVE: authenticated fresh SSH session confirmed; ongoing guard remains armed.", "OK")


def recover() -> None:
    require_root()
    with locked():
        reconcile("service_exit_or_manual_recovery")


def stop_proxy() -> None:
    require_root()
    with locked():
        state = read_json(STATE, {"status": "DIRECT"})
        if state.get("status") in ("PENDING", "ACTIVE"):
            state["status"] = "STOPPING"
            write_json(STATE, state)
        # Do not hold the lock across systemctl stop: ExecStopPost calls recover.
    if is_active(SERVICE):
        subprocess.run(["systemctl", "stop", SERVICE], timeout=30, check=False)
    recover()


def guard() -> None:
    require_root()
    with locked():
        state = read_json(STATE, {"status": "DIRECT"})
        status = state.get("status")
        if status == "DIRECT":
            if current_table() is not None:
                fail("Unexpected nftables table while Direct: manual inspection required.")
            return
        if status == "UNCERTAIN":
            # Ask systemd to stop without blocking on ExecStopPost and our lock.
            if is_active(SERVICE):
                subprocess.run(["systemctl", "--no-block", "stop", SERVICE], timeout=10, check=False)
            fail("Previous recovery UNCERTAIN: proxy stop requested; operator inspection required.")
        stale_boot = state.get("boot") != boot_id()
        expired = status == "PENDING" and int(time.time()) >= int(state.get("deadline", 0))
        process_lost = status in ("ACTIVE", "PENDING") and not is_active(SERVICE)
        startup_grace = status == "PENDING" and int(time.time()) - int(state.get("started", 0)) < 45
        observed_table = current_table()
        changed = observed_table is not None and bool(state.get("table_sha256")) and not table_is_ours(
            observed_table, str(state["table_sha256"])
        )
        missing = observed_table is None and status in ("ACTIVE", "PENDING") and not startup_grace
        if not (stale_boot or expired or (process_lost and not startup_grace) or changed or missing or status == "STOPPING"):
            return
        # Dropping the lock is necessary: systemd ExecStopPost may call recover.
    if is_active(SERVICE):
        subprocess.run(["systemctl", "stop", SERVICE], timeout=30, check=False)
    recover()


def service_run() -> None:
    require_root()
    cfg = read_config()
    if not is_active(GUARD_TIMER):
        fail("Guard not armed; refusing to start.")
    state = read_json(STATE)
    if state.get("status") != "PENDING" or state.get("boot") != boot_id():
        fail("Refusing unguarded service start.")
    excluded = list(EXCLUDED) + [cfg["remote_ip"] + "/32", str(state["management_ip"]) + "/32"]
    argv = [
        "/usr/bin/python3", "-m", "sshuttle", "--method=nft", "--dns",
        "--listen", f"127.0.0.1:{PORT}", "--remote", "sc-remote",
        "--ssh-cmd", f"ssh -F {SSH_CONF} -o BatchMode=yes",
    ]
    for cidr in excluded:
        argv.extend(["--exclude", cidr])
    argv.append("0.0.0.0/0")
    os.environ["PYTHONPATH"] = str(PKG)
    os.execvpe(argv[0], argv, os.environ)


def status() -> None:
    state = read_json(STATE, {"status": "DIRECT"})
    print(f"Simple Connect: {VERSION}")
    role = (ETC / "role").read_text().strip().upper() if (ETC / "role").is_file() else "NOT SET UP"
    print(f"Role: {role}")
    print(f"State: {state.get('status', 'UNKNOWN')}")
    print(f"Proxy service: {'running' if is_active(SERVICE) else 'stopped'}")
    print(f"Independent guard: {'running' if is_active(GUARD_TIMER) else 'not active'}")
    table = current_table() if shutil.which("nft") else None
    print(f"Owned nftables table: {'present' if table else 'absent'}")
    if table and state.get("table_sha256"):
        print(f"Table identity: {'MATCH' if table_is_ours(table, state['table_sha256']) else 'CHANGED'}")
    if state.get("status") == "PENDING":
        print(f"Confirmation operation: {state.get('op')}")
        print(f"Confirmation expires at UTC timestamp: {state.get('deadline')}")
    if state.get("last_recovery"):
        print(f"Last recovery reason: {state['last_recovery']}")


def test_path(url: str) -> None:
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
    run(["journalctl", "--no-pager", "-n", "100", "-u", SERVICE,
         "-u", GUARD_UNIT], timeout=12, capture=False)


def uninstall(yes: bool) -> None:
    require_root()
    if not yes:
        fail("Uninstall destroys Simple Connect's private configuration. Use 'uninstall --yes'.")
    stop_proxy()
    if read_json(STATE, {"status": "DIRECT"}).get("status") != "DIRECT":
        fail("Recovery uncertain; refusing to uninstall with active or unknown firewall resources.")
    subprocess.run(["systemctl", "disable", "--now", GUARD_TIMER], timeout=20, check=False)
    for name, expected in unit_texts().items():
        path = UNIT_DIR / name
        if path.is_file() and path.read_text().startswith("# Managed by Simple Connect;"):
            path.unlink()
    unit_action("daemon-reload")
    for path in (CONF, SSH_CONF, KNOWN_HOSTS, STATE, ETC / "role"):
        if path.is_file():
            path.unlink()
    for path in (ETC, STATE_DIR):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    if PKG.exists() and PKG.joinpath(".wheel-sha256").is_file():
        shutil.rmtree(PKG)
    for path in (APP, COMMAND):
        if path.is_file():
            path.unlink()
    say("Owned resources removed; no global firewall, route, SSH or credentials were changed.", "OK")


def menu() -> None:
    while True:
        banner()
        print("  1) Setup remote SERVER      2) Setup Iran CLIENT")
        print("  3) Configure SSH endpoint   4) Turn ON")
        print("  5) Confirm ON (new SSH)     6) Turn OFF")
        print("  7) Status                   8) Test HTTPS")
        print("  9) Logs                    10) Uninstall")
        print("  0) Exit\n")
        choice = input("Choose: ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                setup("server", WHEEL_URL)
            elif choice == "2":
                setup("client", WHEEL_URL)
            elif choice == "3":
                configure(None, None, None, None, None)
            elif choice == "4":
                start_proxy()
            elif choice == "5":
                confirm(input("Operation ID: ").strip())
            elif choice == "6":
                stop_proxy()
            elif choice == "7":
                status()
            elif choice == "8":
                test_path("https://www.debian.org/")
            elif choice == "9":
                logs()
            elif choice == "10":
                uninstall(input("Type YES to uninstall: ").strip() == "YES")
            else:
                say("Unknown menu option.", "WARN")
        except ConnectError as exc:
            say(str(exc), "ERROR")
        input("\nPress Enter to continue...")


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
    c.add_argument("--fingerprint", help="ED25519 SHA256 host key fingerprint verified out of band")
    for action in ("on", "off", "status", "logs", "guard", "recover", "internal-run"):
        sub.add_parser(action)
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
            with locked():
                setup(args.role, args.wheel_url)
        elif args.action == "configure":
            with locked():
                configure(args.remote_ip, args.ssh_user, args.ssh_port, args.identity_file, args.fingerprint)
        elif args.action == "on":
            start_proxy()
        elif args.action == "off":
            stop_proxy()
        elif args.action == "confirm":
            confirm(args.operation_id)
        elif args.action == "status":
            status()
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
        say(str(exc), "ERROR")
        return 1
    except (OSError, subprocess.TimeoutExpired) as exc:
        say(f"System operation failed: {type(exc).__name__}: {exc}", "ERROR")
        return 1


if __name__ == "__main__":
    sys.exit(main())
