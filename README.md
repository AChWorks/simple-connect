# Simple Connect

A small, standalone SSH-based outbound connectivity manager for Linux hosting servers. The same installer supports two roles:

- **SERVER (remote SSH endpoint):** check or install missing Python/SSH prerequisites and display the SSH ED25519 host fingerprint. It does not create a public proxy, user or credentials.
- **CLIENT (Iran-side host):** install the verified official sshuttle **2.0.0** wheel without changing system Python packages; configure pinned SSH identity; manage transparent outbound IPv4 TCP and conventional UDP/53 DNS.

**Status: [v0.1.0 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.0) is the latest publicly published package; SSH onboarding/menu improvements for v0.1.1 are a separate unreleased source candidate. Neither release nor source candidate is production-field-accepted. The default HTTPS mirror has not been deployed. Do NOT run ON on a live hosting/production server without separately authorized host-specific field acceptance.**

Simple Connect is intentionally separate from [Server Connect](https://github.com/AChWorks/server-connect). It does not use sing-box, alter the default route, provide general UDP/QUIC, or open foreign inbound access to websites.

## Distribution and installer (live-host acceptance still required)

The [v0.1.0 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.0) publishes a verified four-file archive and detached ZIP checksum. These installer entry points exist, but no host-specific production activation has been accepted. The GitHub raw `main` installer is mutable; for an immutable distribution, use the tagged Release assets and verify their authenticity and checksum before use.

Primary GitHub installer (both roles, interactive role selection):

~~~bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash
~~~

For unattended setup, append argument flags after the last pipe, such as:

~~~bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash -s -- --role client
~~~

**Independent HTTPS mirror:** The configured mirror is
https://helpe.ir/simple-connect/. Upload the **exact four files**
install.sh, simple_connect.py, sshuttle-2.0.0-py3-none-any.whl,
and SHA256SUMS directly into the website's public /simple-connect/ directory
(no additional nested folder). Ensure the deployed directory is traversable
by the HTTPS server and the four public distribution files are readable;
do not expose any credentials or unrelated web-root contents. When that
HTTPS path serves the files correctly:

~~~bash
curl -fsSL https://helpe.ir/simple-connect/install.sh | sudo bash -s -- --mirror
~~~

For a different future mirror base URL, use --mirror https://other.example/path.
The --mirror flag without a value selects the configured helpe.ir URL.
Until the owner uploads these files, the site returns HTTP 404 and the
mirror one-liner is not functional.

The bootstrap verifies the manager's embedded pinned SHA-256. The manager independently verifies the official upstream wheel SHA-256 even when downloaded from the mirror. A malicious replacement of the **bootstrap itself** could also replace its checksum: trust the mirror or verify the bootstrap checksum against an authenticated independent source *before running it as root*. The build script below emits SHA256SUMS for independent comparison. Do not treat HTTPS or a self-supplied checksum alone as publisher authentication.

The [v0.1.0 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.0) provides the permanent `simple-connect-mirror.zip` archive and separate `simple-connect-mirror.zip.sha256` checksum. Verify the downloaded pair:

~~~bash
sha256sum -c simple-connect-mirror.zip.sha256
~~~

The reviewed v0.1.0 ZIP SHA256 is `b0e6c276d13bdf7d8b3b63bb00560d2f744933c20d4859bb00435306c65a533c` and its tag points to commit `d1d905f9eb1c732314234485c7526c6c71f40965`. The archive contains the same **four flat files** used by any trusted, operator-hosted HTTPS mirror (`--mirror https://their.example/path`). An independently trusted source is still needed to authenticate the bootstrap: a checksum retrieved solely from the same untrusted server is not proof of publisher identity.

Prepare an independent mirror folder using:

~~~bash
bash scripts/build-mirror-bundle.sh
# Upload the contents of dist/simple-connect-mirror/ over your authenticated deployment path.
~~~

After the release version and embedded manager SHA256 are aligned, prepare
**reproducible release upload assets** from the same verified four-file
mirror directory:

~~~bash
python3 scripts/build-release-assets.py
(cd dist && sha256sum -c simple-connect-mirror.zip.sha256)
# Output: dist/simple-connect-mirror.zip and dist/simple-connect-mirror.zip.sha256
~~~

The release archive contains exactly the same four flat files, including
the official wheel's upstream license. Both builders reject a symlinked
`dist/` parent to avoid redirecting output outside this checkout; the
release builder also requires staged manager and installer files to match
the checked-out sources. It rejects a `-dev` version, mismatched checksums,
missing licensing and unexpected mirror entries. It uses fixed ZIP metadata
and no compression for stable byte-for-byte archives. CI checks repeatability
and uploads the pair as **temporary** artifacts; the separate GitHub pre-release
above hosts the permanent assets. Future tags and public Release publication
still require explicit Owner authorization and relevant review/CI gates.
Extraction and hosting the four files on a trusted custom HTTPS mirror
remain operator-controlled and have not been performed on helpe.ir.

The mirror hostname is owner-selected; its web-root storage and actual file deployment remain owner-managed. Even with the mirror, operating-system apt prerequisites must be obtainable from a configured Debian/local mirror. The setup process only installs **missing** apt packages and never performs a blanket apt upgrade.

## Configure and use

An existing SSH account on the remote server and an independently verified remote ED25519 host fingerprint are required. **The interactive CLIENT menu now manages SSH key onboarding:** choose an existing secure key, or explicitly generate a dedicated passphrase-free ED25519 key pair on the CLIENT, then optionally enroll **only the public key** on the selected remote SSH account using its existing login credentials. This operation never creates remote users, changes their SSH server policy, copies a private key, or enables interception. If password enrollment is unavailable, the menu displays the verified public key for adding via a trusted remote console. The remote IPv4 address, SSH account and port are always operator-selected; verify the host fingerprint out-of-band before saving configuration. Generated private keys remain on the CLIENT even if Simple Connect is uninstalled, so key rotation/deletion is a separate operator decision.

In SERVER role the installer displays its host-key fingerprint. Verify it via a trusted console, not via an unverified network message. In the unreleased v0.1.1 source candidate, an interactive installation opens the persistent, screen-clearing manager menu after setup; the published v0.1.0 asset still uses the earlier onboarding flow. **A failed configuration, bad field, SSH error, missing key or cancelled step returns to a guided menu** rather than exiting into a shell; headless installation still needs explicit flags. The menu header shows role, local IPv4, genuine proxy state, systemd guard/service state, remote SSH target and key readiness. ON remains OFF until explicitly requested and separately accepted on real hosts. From the CLIENT shell you may also use:

~~~bash
sudo simple-connect                    # guided menu
sudo simple-connect configure          # remote IPv4/user/port/key/trusted fingerprint
sudo simple-connect test               # authenticated SSH + complete HTTPS GET
sudo simple-connect on                 # enters PENDING and prints OPERATION_ID
~~~

After ON reports PENDING, open a **genuinely new, remote authenticated SSH TCP connection**. An SSH session already open before ON, a localhost/self-originated SSH connection, or an edited SSH_CONNECTION environment variable cannot confirm. Then:

~~~bash
sudo simple-connect confirm OPERATION_ID
sudo simple-connect status
sudo simple-connect off
sudo simple-connect logs
sudo simple-connect uninstall --yes
~~~

A first CLIENT installation interrupted by a wheel download, unit-installation, or timer-activation failure stays in a non-active INSTALLING state and may be retried with the same installer after correcting the original problem. An already activated or uncertain installation does not become a new install on retry. Uninstall keeps a durable uninstalling.json reservation with monotonic phase checkpoints (stopped, timer disabled, systemd units removed, payload removed). Concurrent ON/OFF/configure/setup operations are refused; an interrupted removal can be resumed safely without requiring an already deleted role/state file or rerunning systemd disable against a missing unit. If an uninstall is interrupted, retry sudo simple-connect uninstall --yes. If the manager executable was already removed, use sudo python3 /path/to/verified/simple_connect.py uninstall --yes from the matching release ZIP, **not setup**. The same fallback can finish empty private directories if interrupted after the reservation itself was deleted. Never delete state files or systemd units manually to bypass an UNCERTAIN firewall: failed stop, foreign unit edits or unknown nftables ownership require investigation before retry.

The client stores its trusted SSH host key separately under /etc/simple-connect/known_hosts. SSH uses strict host-key verification, a single configured private key and connection keepalives. Existing global SSH settings and credentials are never rewritten.

ON preflights the endpoint, discovers and excludes the host's actual directly connected/on-link IPv4 networks (including publicly numbered subnets and gateway IPs), requires an independent active systemd guard timer, refuses existing/untracked sshuttle nftables tables, starts sshuttle, and requires a **new remote SSH TCP connection created after the tunnel was active** for confirmation. The manager captures a kernel-backed inventory of pre-existing SSH connections after activation; a confirming socket must have a new identity and a non-local origin. The 600-second deadline uses Linux CLOCK_BOOTTIME elapsed time (including suspend), is tied to the current boot ID and cannot be extended by moving the system clock backward. SSH_CONNECTION is never trusted for confirmation. The guard subsequently checks that the service and owned nftables table are still present and unchanged. A service stop uses systemd SIGKILL for sshuttle to suppress upstream's unconditional firewall-table destructor; the separate recovery operation instead checks the recorded table identity before deleting **only proven owned resources**. On unknown provenance it reports UNCERTAIN and stops redirector processing without flushing somebody else's rules. If activation is interrupted BEFORE an exact table fingerprint is persisted, table ownership is **not provable**: the manager deliberately preserves any remaining table and reports UNCERTAIN for manual provider-console recovery, rather than deleting something it may not own. Manual recover refuses while the proxy process is still live; stop failures never produce a false DIRECT result.

OFF restores Direct routing (which may still have blocked international downloads). The main proxy service is **not enabled at boot**; after reboot it defaults OFF and the independent timer checks an interrupted previous operation. Duplicate activation is rejected.

## Coverage and safety boundaries

- Intended: IPv4 outbound TCP on the ordinary host network namespace, including typical curl/wget/apt/aaPanel download traffic; ordinary plaintext DNS to known resolvers on UDP/53, via the sshuttle --dns method.
- Not included: general UDP, QUIC/HTTP3, full IPv6 interception, container network namespaces, all custom DNS/DoH configurations, or inbound connectivity to hosted sites. IPv6 can stay direct, and is not globally disabled.
- Management SSH and remote SSH endpoint IPs are excluded from capture; reserved/private and **observed public on-link IPv4 networks and gateway addresses** are excluded. For safety, operator ON/confirmation currently require an identifiable **IPv4 SSH TCP session** in the Linux process ancestry. Existing inbound SSH/HTTP replies, conntrack, aaPanel and third-party firewall interactions still need **real network testing on the actual host topology** before activation.
- No automatic proxy reconnection loop, no generic whole-host killswitch, no default-route changes, no global firewall flush. By default failure recovers the original Direct state, not necessarily foreign connectivity.
- Initial target: Debian 13 amd64 with systemd, nftables, iproute2, **Python >=3.10 and <4.0** on both local and SSH remote, and working remote SSH. Other systems have not been accepted.
- Pinned official sshuttle 2.0.0 is installed in /opt/simple-connect/sshuttle. It is not installed into global pip. Repeated setup skips a correct, verified installation.
- IMPORTANT: Author-operated isolated Debian 13 systemd/SSH guest tests exercised basic ON/OFF, new SSH confirmation, a simulated unconfirmed deadline, SIGKILL, guard shutdown, foreign-rule preservation, and nine interrupted-uninstall recovery checkpoints. Independent high-assurance reviewers approved the exact source and release-preparation candidates, but did **not** independently reproduce the guest or physical host tests. Neither CI nor isolated guest evidence establishes physical reboot behavior, live hosting SSH recovery, aaPanel/website response safety, mixed production firewall/conntrack acceptance, or all partial failure timings. Separately authorized, host-specific field acceptance is still required **before executing ON on real hosting**.

## Development checks

~~~bash
python3 -m unittest discover -s tests -v
python3 -m py_compile simple_connect.py
bash -n install.sh scripts/build-mirror-bundle.sh
~~~

These are hermetic source-level tests, NOT proof of live SSH/website/aaPanel/IPv6/rollback safety. Do not execute root networking tests on shared Dev or production hosts. The contract separates Python standard-library control logic, sshuttle's upstream data plane, systemd units and a minimal Bash bootstrap; state/config have a versioned JSON schema for deliberate future migration without an unnecessary framework.

Upstream: [sshuttle](https://github.com/sshuttle/sshuttle) (2.0.0, LGPL-2.1).
