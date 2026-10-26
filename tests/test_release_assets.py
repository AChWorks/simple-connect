"""Hermetic release packaging checks; never touches host services or networking."""
from __future__ import annotations

from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-release-assets.py"
SPEC = spec_from_file_location("simple_connect_release_assets", SCRIPT)
RELEASE = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(RELEASE)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


class ReleaseAssetsTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dist = Path(temporary.name)
        self.mirror = self.dist / "simple-connect-mirror"
        self.mirror.mkdir()
        self.archive = self.dist / "simple-connect-mirror.zip"
        self.sidecar = self.dist / "simple-connect-mirror.zip.sha256"
        for name, value in (
            ("DIST", self.dist),
            ("MIRROR", self.mirror),
            ("ARCHIVE", self.archive),
            ("SIDECAR", self.sidecar),
        ):
            override = patch.object(RELEASE, name, value)
            override.start()
            self.addCleanup(override.stop)
        self.stage()

    def stage(self, *, version="0.1.0", license_present=True, manager_pin=None):
        wheel_buffer = BytesIO()
        with ZipFile(wheel_buffer, "w") as wheel:
            wheel.writestr(
                "sshuttle-2.0.0.dist-info/licenses/LICENSE"
                if license_present else "sshuttle-2.0.0.dist-info/DUMMY",
                b"LGPL-2.1 test fixture" if license_present else b"missing license",
            )
        wheel_data = wheel_buffer.getvalue()
        wheel_hash = digest(wheel_data)
        manager = (
            f'VERSION = "{version}"\n'
            f'WHEEL_SHA256 = "{wheel_hash}"\n'
        ).encode()
        manager_hash = digest(manager)
        bootstrap = (
            f'readonly MANAGER_SHA256="{manager_pin or manager_hash}"\n'
            f'readonly WHEEL_SHA256="{wheel_hash}"\n'
        ).encode()
        payloads = {
            "install.sh": bootstrap,
            "simple_connect.py": manager,
            "sshuttle-2.0.0-py3-none-any.whl": wheel_data,
        }
        for name, content in payloads.items():
            (self.mirror / name).write_bytes(content)
        (self.mirror / "SHA256SUMS").write_text(
            "".join(f"{digest(content)}  {name}\n" for name, content in payloads.items())
        )

    def test_valid_bundle_is_reproducible_and_flat(self):
        files = RELEASE.verify_inputs()
        checksum = RELEASE.build(files)
        before = self.archive.read_bytes()
        self.assertEqual(checksum, digest(before))
        self.assertEqual(
            self.sidecar.read_text(),
            f"{checksum}  simple-connect-mirror.zip\n",
        )
        self.assertEqual(RELEASE.build(files), checksum)
        self.assertEqual(self.archive.read_bytes(), before)
        with ZipFile(self.archive) as archive:
            self.assertEqual(archive.namelist(), list(RELEASE.CONTENTS))
            for name in RELEASE.CONTENTS:
                self.assertEqual(archive.read(name), files[name])
                expected_mode = 0o755 if name in ("install.sh", "simple_connect.py") else 0o644
                self.assertEqual((archive.getinfo(name).external_attr >> 16) & 0o777, expected_mode)

    def test_rejects_dev_version(self):
        self.stage(version="0.1.0-dev")
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()

    def test_rejects_wrong_manager_pin_even_with_valid_manifest(self):
        self.stage(manager_pin="0" * 64)
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()

    def test_rejects_tampered_payload(self):
        with (self.mirror / "simple_connect.py").open("ab") as handle:
            handle.write(b"unverified")
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()

    def test_rejects_foreign_entry(self):
        (self.mirror / "foreign.txt").write_text("operator-owned")
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()
        self.assertTrue((self.mirror / "foreign.txt").exists())

    def test_rejects_symlink_entry(self):
        target = self.dist / "outside.txt"
        target.write_text("do not read")
        path = self.mirror / "install.sh"
        path.unlink()
        path.symlink_to(target)
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()

    def test_rejects_wheel_without_license(self):
        self.stage(license_present=False)
        with self.assertRaises(SystemExit):
            RELEASE.verify_inputs()

    def test_refuses_symlink_output_without_altering_target(self):
        files = RELEASE.verify_inputs()
        foreign = self.dist / "foreign-artifact"
        foreign.write_bytes(b"untouched")
        self.archive.symlink_to(foreign)
        with self.assertRaises(SystemExit):
            RELEASE.build(files)
        self.assertEqual(foreign.read_bytes(), b"untouched")
        self.assertFalse(self.sidecar.exists())


if __name__ == "__main__":
    unittest.main()
