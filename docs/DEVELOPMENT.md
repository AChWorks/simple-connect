# Simple Connect — Development and release verification

For end-user setup, use the [README](../README.md). This document is for maintainers preparing source changes and releases. See the repository's [AGENTS.md](../AGENTS.md) for authoritative engineering, approval and host-safety rules.

## Components

- `simple_connect.py`: single standard-library Python manager; CLI/TTY menu, SSH configuration, systemd unit templates, guard, nftables ownership, setup/uninstall and the sshuttle argv.
- `install.sh`: minimal HTTPS bootstrap with an exact `MANAGER_SHA256` pin and the official `WHEEL_SHA256`.
- `scripts/build-mirror-bundle.sh`: creates the exact four-file mirror staging directory.
- `scripts/build-release-assets.py`: validates and generates a deterministic ZIP and SHA256 sidecar.
- `tests/`: hermetic test suite and disposable role-PTY fixtures. They do not simulate production Internet access.

Upstream sshuttle is **v2.0.0**, installed privately, with its original LGPL-2.1 license preserved in the wheel. The CLIENT supports Debian 13 amd64 and Python >=3.10, <4.0 on both sides of its SSH link. Changes to networking lifecycle require the repository's independent HIGH_ASSURANCE review before merge.

## Verify source and installer

When `simple_connect.py` changes, update `readonly MANAGER_SHA256` in `install.sh` in the **same candidate**. The pinned wheel digest must match the actual official distribution; never silently swap or repack it.

```bash
python3 -m py_compile simple_connect.py
bash -n install.sh scripts/build-mirror-bundle.sh
python3 -m unittest discover -s tests -v
git diff --check
sha256sum simple_connect.py
```

The required GitHub Actions `source-and-mirror` check validates the exact PR HEAD under protected `main`. Documentation-only updates do not change the executable review envelope, but they still need normal branch-policy/CI integration.

## Build a candidate distribution

```bash
bash scripts/build-mirror-bundle.sh
python3 scripts/build-release-assets.py
(cd dist && sha256sum -c simple-connect-mirror.zip.sha256)
```

Expect an exact, flat four-file directory `dist/simple-connect-mirror/`, plus `dist/simple-connect-mirror.zip` and `dist/simple-connect-mirror.zip.sha256`. The builder checks the manager/installer pins, original wheel license, contents, ZIP consistency and reproducibility. The `dist/` output directory is ignored by Git and must remain inside the checkout, never a symlink to an active web root. CI artifacts are **temporary**, not publicly available release downloads.

To publish, verify the final Git commit and version, compare the release tag to that exact commit, upload the two verified release assets and check a fresh public download plus its checksum. Use a descriptive GitHub release title such as `Simple Connect v0.1.5 — Stable`; do not call a tag/release Stable merely because source tests passed. Owner production/release approval and applicable real-host acceptance are separate gates. Set `prerelease=false` only for an approved Stable release.

The owner HTTPS mirror is a **separate** delivery target: it requires the website administrator's authenticated upload of the exact four files and public HTTPS verification. Never pretend that publishing GitHub assets also updates `helpe.ir`.

## Release and field evidence

Use canonical GitHub objects rather than maintaining historical test narratives in the README:

- [Issue #2 — field/release acceptance and unresolved work](https://github.com/AChWorks/simple-connect/issues/2)
- [PR #18 — increased sshuttle latency buffer](https://github.com/AChWorks/simple-connect/pull/18)
- [GitHub Releases](https://github.com/AChWorks/simple-connect/releases)
- [GitHub Actions](https://github.com/AChWorks/simple-connect/actions)

The source review establishes code-level assurance; a field test proves only the installed bytes, environment and actions actually observed. Do not treat a namespace test as a full guest reboot or a software version label as proof of deployment.
