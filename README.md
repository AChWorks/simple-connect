# Simple Connect

A small, standalone SSH-based outbound connectivity manager for Linux hosting servers. The same installer supports two roles:

- **SERVER (remote SSH endpoint):** check or install missing Python/SSH prerequisites and display available ED25519, ECDSA and RSA-SHA2 host-key fingerprints from the trusted console. Local key files, effective sshd configuration, and actual listener observations are distinguished; the tool never creates host keys or SSH accounts.
- **CLIENT (Iran-side host):** install the verified official sshuttle **2.0.0** wheel without changing system Python packages; configure pinned SSH identity; manage transparent outbound IPv4 TCP and conventional UDP/53 DNS.

**New in v0.1.2:** a strictly single-column interactive menu, discoverable SERVER SSH host fingerprints and readiness diagnostics, and secure ED25519/ECDSA/RSA-SHA2 host-key pinning with independent SHA256 confirmation. Existing guarded networking and OFF-by-default behavior remain unchanged.

**Unreleased v0.1.3 source candidate:** the SERVER menu prioritizes one verified-local, supported SSH host identity and its copy-ready SHA256 fingerprint, with other keys and file diagnostics in Advanced. The CLIENT wizard separates the local private-key *file path* (step 4) from the independently verified SERVER *host fingerprint* (step 5), detects pasted fingerprints in path fields, wraps narrow-terminal prompts, and marks role-only actions. These interface changes do not activate the tunnel or modify SSH server policy.

**Status: [v0.1.2 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.2) is the current verified package. Its Debian 13.7 isolated KVM/QEMU SERVER/CLIENT installation, root-menu, SSH, systemd, nftables, ON/OFF, reboot recovery and uninstall acceptance passed; first-time password-based key enrollment remains NOT_RUN. Physical Debian 13/aaPanel production field acceptance and the owner HTTPS mirror remain pending in [Issue #2](https://github.com/AChWorks/simple-connect/issues/2). Do NOT activate ON on a live hosting server without separately approved host-specific acceptance.**

Simple Connect is intentionally separate from [Server Connect](https://github.com/AChWorks/server-connect). It does not use sing-box, alter the default route, provide general UDP/QUIC, or open foreign inbound access to websites.

## Distribution and installer (live-host acceptance still required)

The [v0.1.2 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.2) publishes a verified four-file archive and detached ZIP checksum. These installer entry points exist, but no host-specific production activation has been accepted. The GitHub raw `main` installer is mutable; for an immutable distribution, use the tagged Release assets and verify their authenticity and checksum before use.

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

The [v0.1.2 GitHub pre-release](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.2) provides the permanent `simple-connect-mirror.zip` archive and separate `simple-connect-mirror.zip.sha256` checksum. Verify the downloaded pair:

~~~bash
sha256sum -c simple-connect-mirror.zip.sha256
~~~

The verified v0.1.2 ZIP SHA256 is `3b20f089ae1fa3f7f709a54fe38593e727ae2f6b385b9d6b16c4a523a4e0f1c5`; the [v0.1.2 tag](https://github.com/AChWorks/simple-connect/releases/tag/v0.1.2) identifies its immutable source. Historical checksums: v0.1.1 `993a04a12d57f2d7590fd6f9b571493e8865b9b3d1eff0afedd524f83aa32896` and v0.1.0 `b0e6c276d13bdf7d8b3b63bb00560d2f744933c20d4859bb00435306c65a533c`. The archive contains the same **four flat files** used by any trusted, operator-hosted HTTPS mirror (`--mirror https://their.example/path`). An independently trusted source is still needed to authenticate the bootstrap: a checksum retrieved solely from the same untrusted server is not proof of publisher identity.

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

### Operator quick start (v0.1.3 candidate)

1. On the **SERVER**, use **12) SERVER fingerprints/Advanced** or `sudo simple-connect host-fingerprints`. Check the actual configured SSH port and copy the **one recommended SHA256 host fingerprint**; if no safe supported host identity is verified, diagnose before proceeding. The display is local evidence, **not** proof that external SSH login works. Use `sudo simple-connect host-fingerprints --advanced` for alternate algorithms, public-key paths, key-pair status and warnings.
2. On the **CLIENT**, use **3) Configure SSH connection** and enter the SERVER IPv4 address, SSH user and port. At **step 4**, select an existing safe **CLIENT private-key file path** (such as `/root/.ssh/simple_connect_ed25519`), or explicitly approve generating a dedicated key. Never paste SSH key contents or a SHA256 fingerprint into this field.
3. At **step 5**, enter the SERVER's SHA256 fingerprint obtained separately from the trusted SERVER console. The CLIENT network scan is **untrusted** until it matches the independently confirmed host identity. The CLIENT's private key never leaves that machine.
4. Public-key enrollment is a **separate opt-in** for the exact verified SERVER destination. Afterward, use the authenticated SSH and HTTPS tests; any tunnel activation on a real production host still needs its own authorized acceptance.

An existing SSH account on the remote server and an independently verified **SHA256 fingerprint for the exact selected SSH host key** are required. Supported host public-key types are ED25519 (preferred), ECDSA (nistp256/384/521), and RSA at least 2048 bits with **RSA-SHA2 signatures only**. DSA and legacy RSA-SHA1 negotiation are rejected. The CLIENT scans all supported identities and pins exactly one independently confirmed identity; matching a network-observed fingerprint is not, by itself, trust. **The interactive CLIENT menu now manages SSH key onboarding:** choose an existing secure key, or explicitly generate a dedicated passphrase-free ED25519 key pair on the CLIENT, then optionally enroll **only the public key** on the selected remote SSH account using its existing login credentials. This operation never creates remote users, changes their SSH server policy, copies a private key, or enables interception. If password enrollment is unavailable, the menu displays the verified public key for adding via a trusted remote console. The remote IPv4 address, SSH account and port are always operator-selected; verify the host fingerprint out-of-band before saving configuration. Existing SSH identity paths must be absolute and use only ASCII letters, digits, '/', '.', '_' and '-' (no shell syntax), with trusted non-writable parent directories and no symlinks. The matching public-key file must contain **exactly one** plain OpenSSH key record; appended records are refused rather than silently copied. A concurrent SSH configuration change aborts a stale wizard instead of overwriting the other operator's verified host identity. **Public-key enrollment is a separate, explicit authorization bound to the exact selected username, remote IP, port, private-key identity and independently pinned selected server host-key fingerprint.** The confirmation screen displays all of these before consent. If a second operator changes any saved SSH configuration or host key before the enrollment command starts, the original consent is rejected without remote changes. The SSH helper uses a temporary, private copy of the approved *public key and pinned host-key record* (and an exclusive hard-link to the chosen local private-key inode), not the mutable shared `known_hosts` or another operator's current settings; these temporary files are removed after enrollment. SSH/password prompts never hold the manager lifecycle lock. Generated private keys remain on the CLIENT even if Simple Connect is uninstalled, so key rotation/deletion is a separate operator decision.

In SERVER role, initial **and repeated** setup display currently available SSH host-key fingerprints from the trusted console; neither creates missing keys nor modifies/restarts sshd. Menu action **12) Show SERVER SSH fingerprints**, or `sudo simple-connect host-fingerprints`, also inspects effective sshd ports/key paths and optionally scans **localhost only**. The display also checks the existence, restrictive permissions and public/private correspondence of each configured host key; a missing or mismatched private half is NOT READY. A local file or a configured HostKey path does **not** prove sshd is serving that key, and a loopback scan can miss an external-only listener. RSA keyscan proves the public key, **not** RSA-SHA2 negotiation; use a strict, authenticated SSH client test before declaring readiness. If the port or daemon is not working, diagnose the actual listener—do not assume port 22 or silently generate keys. Verify the selected fingerprint via a trusted console, not via an unverified network message. Starting with published v0.1.1, interactive installation opens the persistent, screen-clearing manager menu after setup; v0.1.0 used the earlier onboarding flow. **A failed configuration, bad field, SSH error, missing key or cancelled step returns to a guided menu** rather than exiting into a shell; headless installation still needs explicit flags. The menu header shows role, local IPv4, genuine proxy state, systemd guard/service state, remote SSH target and key readiness. ON remains OFF until explicitly requested and separately accepted on real hosts. From the CLIENT shell you may also use:

~~~bash
sudo simple-connect                    # guided menu
sudo simple-connect configure          # remote IPv4/user/port/key/trusted fingerprint
sudo simple-connect test               # authenticated SSH + complete HTTPS GET
sudo simple-connect host-fingerprints  # SERVER role: read-only host key details
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

The client stores its single exact trusted SSH host-key record separately under /etc/simple-connect/known_hosts. SSH uses strict host-key checking, a type-specific HostKeyAlgorithms allowlist (RSA-SHA2 rather than RSA-SHA1), disabled global known_hosts and host-key auto-update, one selected private key and connection keepalives. SSH key enrollment uses the **same immutable host-key pin and negotiated algorithm policy**, never Trust On First Use. Existing global SSH settings and credentials are never rewritten.

ON preflights the endpoint, discovers and excludes the host's actual directly connected/on-link IPv4 networks (including publicly numbered subnets and gateway IPs), requires an independent active systemd guard timer, refuses existing/untracked sshuttle nftables tables, starts sshuttle, and requires a **new remote SSH TCP connection created after the tunnel was active** for confirmation. The manager captures a kernel-backed inventory of pre-existing SSH connections after activation; a confirming socket must have a new identity and a non-local origin. The 600-second deadline uses Linux CLOCK_BOOTTIME elapsed time (including suspend), is tied to the current boot ID and cannot be extended by moving the system clock backward. SSH_CONNECTION is never trusted for confirmation. The guard subsequently checks that the service and owned nftables table are still present and unchanged. A service stop uses systemd SIGKILL for sshuttle to suppress upstream's unconditional firewall-table destructor; the separate recovery operation instead checks the recorded table identity before deleting **only proven owned resources**. On unknown provenance it reports UNCERTAIN and stops redirector processing without flushing somebody else's rules. If activation is interrupted BEFORE an exact table fingerprint is persisted, table ownership is **not provable**: the manager deliberately preserves any remaining table and reports UNCERTAIN for manual provider-console recovery, rather than deleting something it may not own. Manual recover refuses while the proxy process is still live; stop failures never produce a false DIRECT result.

OFF restores Direct routing (which may still have blocked international downloads). The main proxy service is **not enabled at boot**; after reboot it defaults OFF and the independent timer checks an interrupted previous operation. Duplicate activation is rejected.

## Coverage and safety boundaries

- Intended: IPv4 outbound TCP on the ordinary host network namespace, including typical curl/wget/apt/aaPanel download traffic; ordinary plaintext DNS to known resolvers on UDP/53, via the sshuttle --dns method.
- Not included: general UDP, QUIC/HTTP3, full IPv6 interception, container network namespaces, all custom DNS/DoH configurations, or inbound connectivity to hosted sites. IPv6 can stay direct, and is not globally disabled.
- Management SSH and remote SSH endpoint IPs are excluded from capture; reserved/private and **observed public on-link IPv4 networks and gateway addresses** are excluded. For safety, operator ON/confirmation currently require an identifiable **IPv4 SSH TCP session** in the Linux process ancestry. Existing inbound SSH/HTTP replies, conntrack, aaPanel and third-party firewall interactions still need **real network testing on the actual host topology** before activation.
- No automatic proxy reconnection loop, no generic whole-host killswitch, no default-route changes, no global firewall flush. By default failure recovers the original Direct state, not necessarily foreign connectivity.
- Initial target: Debian 13 amd64 with systemd, nftables, iproute2, **Python >=3.10 and <4.0** on both local and SSH remote, and working remote SSH. Other systems have not been accepted.
- Pinned official sshuttle 2.0.0 is installed in /opt/simple-connect/sshuttle. It is not installed into global pip. Repeated setup skips a correct, verified installation.
- IMPORTANT: Owner-authorized independent Debian 13.7 KVM/QEMU SERVER and CLIENT guests executed real root installation, 40-column menu operations, actual SSH and HTTPS, fresh SSH confirmation, ON/PENDING/ACTIVE/OFF, nftables/service guard checks, service-stop/SIGKILL recovery, reboot **of the isolated CLIENT guest from ACTIVE**, and uninstall with SSH preserved. Ten complete root PTY suites totalled 63/63 PASS; 131 automated source tests passed. A separate initial interactive configuration **test harness** timed out at an unhandled enrollment consent prompt (6/7 checks passed), with the saved configuration and subsequent cancellation/SSH paths separately verified. First-time password-based key enrollment is **NOT_RUN**. An author-separated independent reviewer verified the preserved evidence and approved Issue #8; the reviewer did not independently rerun these privileged tests. **None** of this proves physical production reboot, aaPanel/website coexistence, external HTTPS mirror availability, mixed host firewall/conntrack behavior or Iran-to-remote connectivity. Host-specific field acceptance under [Issue #2](https://github.com/AChWorks/simple-connect/issues/2) is still required before ON on real hosting.

## Development checks

~~~bash
python3 -m unittest discover -s tests -v
python3 -m py_compile simple_connect.py
bash -n install.sh scripts/build-mirror-bundle.sh
~~~

These commands run the hermetic source-level checks; the separately recorded disposable-root QEMU acceptance above does not prove live hosting/aaPanel/IPv6 safety. Do not execute root networking tests on shared Dev or production hosts. The contract separates Python standard-library control logic, sshuttle's upstream data plane, systemd units and a minimal Bash bootstrap; state/config have a versioned JSON schema for deliberate future migration without an unnecessary framework.

Upstream: [sshuttle](https://github.com/sshuttle/sshuttle) (2.0.0, LGPL-2.1).
