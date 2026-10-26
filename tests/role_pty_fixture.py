#!/usr/bin/env python3
"""Disposable installed-role PTY fixture; NO privileged host or network changes.

The real manager performs setup, role-dependent menus, prompts, key generation,
host-key validation, and locked SSH configuration saves against private paths
inside SC_PTY_FIXTURE_ROOT. Only OS/package operations, remote calls and systemd
are substituted; no SSH daemon/network/firewall state is ever altered.
"""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import simple_connect as sc


def create_key(path: Path, kind: str, bits: int | None = None) -> None:
    argv = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", str(path)]
    if bits:
        argv += ["-b", str(bits)]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise RuntimeError(proc.stderr)


def main() -> int:
    root = Path(os.environ["SC_PTY_FIXTURE_ROOT"]).resolve()
    role = os.environ["SC_PTY_FIXTURE_ROLE"]
    variant = os.environ.get("SC_PTY_FIXTURE_VARIANT", "ed")
    if role not in ("server", "client") or variant not in ("ed", "ec", "rsa", "none"):
        raise RuntimeError("Unrecognized disposable fixture scenario")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    hosts = root / "hosts"
    hosts.mkdir(mode=0o700)
    client = root / "client"
    client.mkdir(mode=0o700)
    hostpaths = {}
    for kind, bits in (("ed", None), ("ec", 256), ("rsa", 2048)):
        path = hosts / f"ssh_host_{kind}_key"
        create_key(path, {"ed": "ed25519", "ec": "ecdsa", "rsa": "rsa"}[kind], bits)
        hostpaths[kind] = path
    client_key = client / "existing"
    create_key(client_key, "ed25519")
    dedicated = client / ".ssh" / "simple_connect_ed25519"
    # Simulate an unsafe or absent preferred host key without touching sshd.
    if variant in ("ec", "rsa", "none"):
        hostpaths["ed"].chmod(0o644)
    if variant in ("rsa", "none"):
        hostpaths["ec"].chmod(0o644)
    if variant == "none":
        hostpaths["rsa"].unlink()  # Public half deliberately remains.

    selected = {"ed": "ed", "ec": "ec", "rsa": "rsa"}.get(variant)
    def key_identity(path: Path) -> tuple[str, str, str]:
        kind, blob, *_ = Path(str(path) + ".pub").read_text().split()
        return kind, blob, sc.host_key_fingerprint(kind, blob)
    identities = {kind: key_identity(path) for kind, path in hostpaths.items()}

    original_run = sc.run
    original_subprocess = subprocess.run
    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/sbin/sshd":
            config = ("port 22022\n"
                      + "".join(f"hostkey {path}\n" for path in hostpaths.values())
                      + "hostkeyalgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256\n")
            return subprocess.CompletedProcess(argv, 0, config, "")
        if argv[0] == "ssh-keyscan":
            if selected is None:
                return subprocess.CompletedProcess(argv, 1, "", "No supported host key")
            kind, blob, _ = identities[selected]
            port = int(argv[argv.index("-p") + 1])
            target = argv[-1]
            label = target if port == 22 else f"[{target}]:{port}"
            row = f"{label} {kind} {blob}\n"
            return subprocess.CompletedProcess(argv, 0, row, "")
        if argv[0] == "ip":
            return subprocess.CompletedProcess(argv, 0,
                json.dumps([{"ifname": "eth0", "addr_info": [
                    {"family": "inet", "local": "198.51.100.100"}]}]), "")
        if argv[0] == "ssh":
            return subprocess.CompletedProcess(argv, 0, "Python available (simulated)\n", "")
        if argv[0] == "ssh-keygen":
            return original_run(argv, **kwargs)
        raise AssertionError(f"Blocked unexpected external fixture command: {argv[0]}")

    def safe_subprocess(argv, *args, **kwargs):
        if isinstance(argv, (list, tuple)) and argv and argv[0] == "/usr/bin/ssh-copy-id":
            if "StrictHostKeyChecking=yes" not in argv or "GlobalKnownHostsFile=/dev/null" not in argv:
                raise AssertionError("Unsafe enrollment parameters")
            (root / "enrollment-simulated").write_text("PUBLIC key only (no remote call)\n")
            return subprocess.CompletedProcess(argv, 0, "", "")
        # Allow only the actual local cryptographic tool or the manager's
        # read-only interface query. A future source change must NOT silently
        # cause a live network, systemd or firewall operation in this fixture.
        if isinstance(argv, (list, tuple)) and argv and argv[0] == "ssh-keygen":
            return original_subprocess(argv, *args, **kwargs)
        if list(argv) == ["ip", "-j", "-4", "address", "show", "scope", "global"]:
            addresses = [{"ifname": "eth0", "addr_info": [
                {"family": "inet", "local": "198.51.100.100"}]}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(addresses), "")
        raise AssertionError(f"Blocked unexpected direct subprocess in PTY fixture: {argv}")

    patches = [
        patch.object(sc, "ETC", root / "etc"),
        patch.object(sc, "CONF", root / "etc" / "config.json"),
        patch.object(sc, "KNOWN_HOSTS", root / "etc" / "known_hosts"),
        patch.object(sc, "SSH_CONF", root / "etc" / "ssh_config"),
        patch.object(sc, "STATE_DIR", root / "state"),
        patch.object(sc, "STATE", root / "state" / "state.json"),
        patch.object(sc, "LOCK", root / "state" / "lock"),
        patch.object(sc, "TEARDOWN", root / "state" / "uninstalling.json"),
        patch.object(sc, "UNIT_DIR", root / "units"),
        patch.object(sc, "SSH_HOST_DIR", hosts),
        patch.object(sc, "KEY_PATH", dedicated),
        patch.object(sc, "APP", root / "bin" / "simple_connect.py"),
        patch.object(sc, "COMMAND", root / "bin" / "simple-connect"),
        patch.object(sc, "require_root"),
        patch.object(sc, "install_requirements"),
        patch.object(sc, "install_entrypoint"),
        patch.object(sc, "install_wheel"),
        patch.object(sc, "unit_action"),
        patch.object(sc, "service_terminated", return_value=True),
        patch.object(sc, "any_proxy_tables", return_value=False),
        patch.object(sc, "is_active",
                     side_effect=lambda unit: unit in ("ssh.service", sc.GUARD_TIMER)),
        patch.object(sc, "run", side_effect=fake_run),
        patch.object(sc.subprocess, "run", side_effect=safe_subprocess),
    ]
    with contextlib.ExitStack() as stack:
        for change in patches:
            stack.enter_context(change)
        (root / "units").mkdir()
        sc.setup(role, "https://example.invalid/never-fetched")
        print("PTY_FIXTURE_READY")
        print(f"PTY_FIXTURE_KEY={client_key}")
        print(f"PTY_FIXTURE_DEDICATED={dedicated}")
        print("PTY_FIXTURE_FP=" + (identities[selected][2] if selected else "NONE"))
        sys.stdout.flush()
        return sc.main()


if __name__ == "__main__":
    raise SystemExit(main())
