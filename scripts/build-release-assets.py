#!/usr/bin/env python3
"""Create reproducible, separately checksummed release files from the four-file mirror."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_STORED

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
MIRROR = DIST / "simple-connect-mirror"
ARCHIVE = DIST / "simple-connect-mirror.zip"
SIDECAR = DIST / "simple-connect-mirror.zip.sha256"
CONTENTS = (
    "install.sh",
    "simple_connect.py",
    "sshuttle-2.0.0-py3-none-any.whl",
    "SHA256SUMS",
)
HASHED = CONTENTS[:-1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"[ERROR] {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned(source: str, name: str) -> str:
    value = re.search(rf'^{re.escape(name)}\s*=\s*"([a-f0-9]{{64}})"$', source, re.M)
    require(value is not None, f"Missing or invalid {name} pin.")
    return value.group(1)


def verify_inputs() -> dict[str, bytes]:
    require(MIRROR.is_dir() and not MIRROR.is_symlink(), "Mirror directory is missing or unsafe.")
    require(
        {p.name for p in MIRROR.iterdir()} == set(CONTENTS),
        "Mirror must contain exactly the four approved flat files.",
    )
    files = {}
    for name in CONTENTS:
        path = MIRROR / name
        require(path.is_file() and not path.is_symlink(), f"Unsafe mirror entry: {name}")
        files[name] = path.read_bytes()

    lines = files["SHA256SUMS"].decode("ascii").splitlines()
    require(len(lines) == len(HASHED), "SHA256SUMS must list exactly three payloads.")
    checksums = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([a-zA-Z0-9._-]+)", line)
        require(match is not None, "Malformed SHA256SUMS entry.")
        digest, name = match.groups()
        require(name not in checksums, "Duplicate checksum entry.")
        checksums[name] = digest
    require(set(checksums) == set(HASHED), "SHA256SUMS payload list mismatch.")
    for name in HASHED:
        require(checksums[name] == sha256(files[name]), f"Checksum mismatch: {name}")

    manager = files["simple_connect.py"].decode("utf-8")
    bootstrap = files["install.sh"].decode("utf-8")
    version = re.search(r'^VERSION = "([^"\n]+)"$', manager, re.M)
    require(version is not None, "Missing manager version.")
    require(not version.group(1).endswith("-dev"), "Development version cannot be a release asset.")
    require(
        pinned(bootstrap, "readonly MANAGER_SHA256") == checksums["simple_connect.py"],
        "Bootstrap manager pin mismatch.",
    )
    require(
        pinned(bootstrap, "readonly WHEEL_SHA256") == checksums["sshuttle-2.0.0-py3-none-any.whl"],
        "Bootstrap wheel pin mismatch.",
    )
    require(
        pinned(manager, "WHEEL_SHA256") == checksums["sshuttle-2.0.0-py3-none-any.whl"],
        "Manager wheel pin mismatch.",
    )

    with ZipFile(MIRROR / "sshuttle-2.0.0-py3-none-any.whl") as wheel:
        require(
            "sshuttle-2.0.0.dist-info/licenses/LICENSE" in wheel.namelist(),
            "Upstream wheel license is missing.",
        )
    return files


def temporary_file() -> Path:
    fd, path = tempfile.mkstemp(prefix=".simple-connect-release-", dir=DIST)
    os.close(fd)
    return Path(path)


def build(files: dict[str, bytes]) -> str:
    for dest in (ARCHIVE, SIDECAR):
        require(
            not dest.is_symlink() and (not dest.exists() or dest.is_file()),
            f"Unsafe release output path: {dest}",
        )
    tmp_zip = temporary_file()
    tmp_hash = temporary_file()
    try:
        # ZIP_STORED and fixed metadata produce the same bytes independent of zlib.
        with ZipFile(tmp_zip, mode="w", compression=ZIP_STORED) as archive:
            for name in CONTENTS:
                info = ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100755 if name in ("install.sh", "simple_connect.py") else 0o100644) << 16
                info.compress_type = ZIP_STORED
                archive.writestr(info, files[name])

        with ZipFile(tmp_zip) as archive:
            require(archive.namelist() == list(CONTENTS), "Release archive entry mismatch.")
            require(archive.testzip() is None, "Corrupt ZIP payload.")
            for name in CONTENTS:
                require(archive.read(name) == files[name], f"ZIP content mismatch: {name}")

        digest = sha256(tmp_zip.read_bytes())
        with tmp_hash.open("wb") as handle:
            handle.write(f"{digest}  {ARCHIVE.name}\n".encode("ascii"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_zip, ARCHIVE)
        os.replace(tmp_hash, SIDECAR)
        return digest
    finally:
        tmp_zip.unlink(missing_ok=True)
        tmp_hash.unlink(missing_ok=True)


if __name__ == "__main__":
    files = verify_inputs()
    digest = build(files)
    print(f"[OK] {ARCHIVE.name} SHA256={digest}")
    print(f"[OK] {SIDECAR.name}")
