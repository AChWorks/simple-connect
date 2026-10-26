# Simple Connect

A small, standalone SSH-based outbound connectivity manager for Linux hosting servers. The same installer supports two roles:

- **SERVER (remote SSH endpoint):** check or install missing Python/SSH prerequisites and display the SSH ED25519 host fingerprint. It does not create a public proxy, user or credentials.
- **CLIENT (Iran-side host):** install the verified official sshuttle **2.0.0** wheel without changing system Python packages; configure pinned SSH identity; manage transparent outbound IPv4 TCP and conventional UDP/53 DNS.

**Status: DEVELOPMENT CANDIDATE. No live-host acceptance, stable release, or deployed mirror. Do NOT run ON on a hosting/production server yet.**

Simple Connect is intentionally separate from [Server Connect](https://github.com/AChWorks/server-connect). It does not use sing-box, alter the default route, provide general UDP/QUIC, or open foreign inbound access to websites.

## One-line install (after review, merge, release and field acceptance)

Primary GitHub installer (both roles, interactive role selection):

~~~bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash
~~~

For unattended setup, append argument flags after the last pipe, such as:

~~~bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash -s -- --role client
~~~

**Independent HTTPS mirror:** Upload the *identical bytes* of install.sh, simple_connect.py and sshuttle-2.0.0-py3-none-any.whl to a trusted non-GitHub HTTPS location. Example (placeholder, not a real deployed host):

~~~bash
curl -fsSL https://YOUR-TRUSTED-MIRROR.example/simple-connect/install.sh | sudo bash -s -- --mirror https://YOUR-TRUSTED-MIRROR.example/simple-connect
~~~

The bootstrap verifies the manager's embedded pinned SHA-256. The manager independently verifies the official upstream wheel SHA-256 even when downloaded from the mirror. A malicious replacement of the **bootstrap itself** could also replace its checksum: trust the mirror or verify the bootstrap checksum against an authenticated independent source *before running it as root*. The build script below emits SHA256SUMS for independent comparison. Do not treat HTTPS or a self-supplied checksum alone as publisher authentication.

Prepare an independent mirror folder using:

~~~bash
bash scripts/build-mirror-bundle.sh
# Upload the contents of dist/simple-connect-mirror/ over your authenticated deployment path.
~~~

The mirror domain and storage are a later owner choice. The example URL above is not runnable. Even with the mirror, operating-system apt prerequisites must be obtainable from a configured Debian/local mirror. The setup process only installs **missing** apt packages and never performs a blanket apt upgrade.

## Configure and use

A pre-existing SSH account, working private key and a verified remote ED25519 fingerprint are necessary. Simple Connect does not create SSH users or keys. The remote IPv4 endpoint is selected later by the operator.

In the SERVER role the installer displays a host-key fingerprint. Verify it via a trusted console, not via an unverified network message. On the CLIENT:

~~~bash
sudo simple-connect                    # guided menu
sudo simple-connect configure          # remote IPv4/user/port/key/trusted fingerprint
sudo simple-connect test               # authenticated SSH + complete HTTPS GET
sudo simple-connect on                 # enters PENDING and prints OPERATION_ID
~~~

Open a **new authenticated SSH session** to the client host, then:

~~~bash
sudo simple-connect confirm OPERATION_ID
sudo simple-connect status
sudo simple-connect off
sudo simple-connect logs
sudo simple-connect uninstall --yes
~~~

The client stores its trusted SSH host key separately under /etc/simple-connect/known_hosts. SSH uses strict host-key verification, a single configured private key and connection keepalives. Existing global SSH settings and credentials are never rewritten.

ON preflights the endpoint, requires an independent active systemd guard timer, refuses existing/foreign nftables tables with the intended name, starts sshuttle, and requires fresh-SSH confirmation within 600 seconds. The guard subsequently checks that the service and owned nftables table are still present and unchanged. Failure requests shutdown and cleanup of **only the recorded owned table**. On unknown provenance it reports UNCERTAIN rather than flushing somebody else's firewall.

OFF restores Direct routing (which may still have blocked international downloads). The main proxy service is **not enabled at boot**; after reboot it defaults OFF and the independent timer checks an interrupted previous operation. Duplicate activation is rejected.

## Coverage and safety boundaries

- Intended: IPv4 outbound TCP on the ordinary host network namespace, including typical curl/wget/apt/aaPanel download traffic; ordinary plaintext DNS to known resolvers on UDP/53, via the sshuttle --dns method.
- Not included: general UDP, QUIC/HTTP3, full IPv6 interception, container network namespaces, all custom DNS/DoH configurations, or inbound connectivity to hosted sites. IPv6 can stay direct, and is not globally disabled.
- Management SSH and remote SSH endpoint IPs are excluded from capture; private and local networks are excluded. Existing inbound SSH/HTTP replies, conntrack, aaPanel and third-party firewall interactions still need **real network testing on the actual host topology** before activation.
- No automatic proxy reconnection loop, no generic whole-host killswitch, no default-route changes, no global firewall flush. By default failure recovers the original Direct state, not necessarily foreign connectivity.
- Initial target: Debian 13 amd64 with systemd, nftables, Python >=3.9 and working remote SSH. Other systems have not been accepted.
- Pinned official sshuttle 2.0.0 is installed in /opt/simple-connect/sshuttle. It is not installed into global pip. Repeated setup skips a correct, verified installation.
- IMPORTANT: The current fingerprint-based firewall cleanup cannot prove safe recovery for every crash timing, concurrent foreign rule edit, or reboot. More isolated guest/field verification and a fresh high-assurance independent review are required **before shipping or executing ON on real hosting**.

## Development checks

~~~bash
python3 -m unittest discover -s tests -v
python3 -m py_compile simple_connect.py
bash -n install.sh scripts/build-mirror-bundle.sh
~~~

These are hermetic source-level tests, NOT proof of live SSH/website/aaPanel/IPv6/rollback safety. Do not execute root networking tests on shared Dev or production hosts. The contract separates Python standard-library control logic, sshuttle's upstream data plane, systemd units and a minimal Bash bootstrap; state/config have a versioned JSON schema for deliberate future migration without an unnecessary framework.

Upstream: [sshuttle](https://github.com/sshuttle/sshuttle) (2.0.0, LGPL-2.1).
