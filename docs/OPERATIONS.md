# Simple Connect — Operations guide

This guide supplements the [user-facing README](../README.md). Use it when configuring SSH identities, diagnosing an uncertain state or installing from a trusted mirror. **Do not use these commands to override unknown firewall ownership.**

## What each role does

**SERVER** relies on an existing SSH daemon and account. The manager inspects local SSH host keys, effective SSH configuration and listener observations. It does not create SSH accounts, generate/rewrite server host keys, alter sshd policy or enable the tunnel on the SERVER.

**CLIENT** manages a pinned SSH connection to that SERVER, a private sshuttle 2.0.0 installation, its own nftables table, a systemd service and a separate guard timer. Activation is explicitly requested and initially **PENDING**. Inbound SSH, the remote endpoint, reserved networks and discovered directly connected IPv4 networks are excluded from forwarding.

The selected supported CLIENT platform is Debian 13 amd64 with systemd, nftables and Python >=3.10, <4.0. Other OS/network configurations need their own verification. General UDP, QUIC, IPv6 interception, container network namespaces and encrypted DNS clients are outside the forwarding contract.

## Installation and release files

The online installer is:

```bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash
```

It downloads a SHA256-pinned manager; that manager independently checks the pinned upstream sshuttle wheel. It installs missing prerequisites, not a blanket system update, and never enables the CLIENT tunnel merely by installing.

[GitHub Releases](https://github.com/AChWorks/simple-connect/releases) also distribute **`simple-connect-mirror.zip`** and **`simple-connect-mirror.zip.sha256`**, containing four flat files:

- `install.sh`
- `simple_connect.py`
- `sshuttle-2.0.0-py3-none-any.whl`
- `SHA256SUMS`

After downloading the ZIP and checksum from the **same trusted, authenticated release**, verify:

```bash
sha256sum -c simple-connect-mirror.zip.sha256
unzip -l simple-connect-mirror.zip
```

The archive is a portable **distribution/mirror payload**, not an automatically offline installer: OS prerequisites may still require `apt`, and the bootstrap uses configured HTTPS sources unless you provide a functioning trusted HTTPS mirror. Do not assume that extracting the ZIP switches the network installer to local files.

The owner-selected mirror address is `https://helpe.ir/simple-connect/`. This endpoint is usable only after its administrator uploads the four verified files **directly** beneath `/simple-connect/` and confirms public HTTPS reads. Until then, use GitHub. Once that mirror is independently verified:

```bash
curl -fsSL https://helpe.ir/simple-connect/install.sh | sudo bash -s -- --mirror
```

A different HTTPS base URL may be supplied after `--mirror`; it must serve the matching manager/wheel bytes. A checksum obtained only from an untrusted bootstrap or mirror cannot establish publisher authenticity.

## Verify SERVER SSH identity

On the trusted SERVER console:

```bash
sudo simple-connect host-fingerprints
sudo simple-connect host-fingerprints --advanced
```

A recommended **SHA256 host fingerprint** is shown only when a supported identity can be selected unambiguously. Match the actual SSH port and key offered by the intended listener. A valid key file on disk is not evidence that the listening daemon serves it; a local loopback probe may miss external-only listeners. For multiple host keys, use Advanced and confirm the correct identity through an independent trusted channel.

Supported types: ED25519 (preferred), ECDSA and RSA >=2048 with RSA-SHA2 negotiation. Legacy DSA and RSA-SHA1 signatures are not supported.

## Configure CLIENT SSH access safely

On the CLIENT open the menu and select **3**. The wizard asks for:

1. Remote public IPv4 address, existing SSH username and port.
2. An **absolute path to a CLIENT private-key file**. Choose a trusted existing file or explicitly answer Y/YES to create a new dedicated CLIENT key; Enter/N creates nothing.
3. The SERVER's **independently verified SHA256 host fingerprint** (not an SSH key path and not the private key).
4. Optional public-key enrollment into the approved existing remote SSH account. Enrollment prompts for exact destination/identity consent and may require the remote user's existing password. Only the public key is sent.

Global SSH settings are not rewritten. The pinned host key is stored separately, and neither `ssh-copy-id` nor the manager transmits the local private key. If automated enrollment is unavailable, install the displayed **public** key through the SERVER's trusted administration interface.

Test via menu **8** or:

```bash
sudo simple-connect test
```

## Safe connection lifecycle

```bash
sudo simple-connect status
sudo simple-connect on
# Open a NEW remote SSH session to the CLIENT after ON becomes PENDING.
sudo simple-connect confirm OPERATION_ID
sudo simple-connect status
sudo simple-connect off
```

Confirmation is bound to a genuinely new authenticated remote SSH TCP connection observed at kernel level, the same boot ID and a monotonic approximately 600-second activation deadline. An old or local session cannot confirm activation; changing `SSH_CONNECTION` does not bypass it. The guard monitors service and owned nftables identity.

A stopped sshuttle subprocess is not enough to conclude that the firewall is safe: the manager verifies the recorded table hash and removes only its own proven table. If the state says **UNCERTAIN** or a foreign/modified table is present, use the hosting provider's console and investigate. **Never flush nftables or delete ambiguous tables by hand just to make a status indicator green.**

After reboot, the CLIENT proxy service is deliberately not enabled; the default is DIRECT/OFF, and the independent guard handles interrupted state. Re-activate explicitly.

## aaPanel and website coexistence

Simple Connect intercepts supported outbound IPv4 traffic only, not inbound connections to a hosted website. Nevertheless, routing/firewall differences can affect established connections: before enabling on a busy hosting server, record working SSH, the host panel and existing site traffic, then check incoming HTTP(S), DNS and connection reply behavior after activation. Ensure that you have independent console recovery for any destructive field experiment.

Do not interpret an open TCP listener or an unauthenticated HTTP status as proof that aaPanel login or a hosted application works. Perform real authenticated application tests only with authorized credentials.

## Troubleshooting

| Symptom | Recommended check |
|---|---|
| SSH fingerprint mismatch | Confirm the exact SERVER port and selected host key through its console; do not accept an unverified new key |
| CLIENT private-key path rejected | Enter a secure absolute existing key path, not raw key contents or a fingerprint; use explicit key generation if appropriate |
| ON remains PENDING | Open a new authenticated remote SSH session after ON, then enter the displayed operation ID |
| Proxy is DIRECT after reboot | Expected: manually activate it again |
| Status reports UNCERTAIN / nft identity mismatch | Stop and inspect with an independent provider console; do not manually delete unknown nftables state |
| Foreign downloads still fail | Confirm SERVER Internet access, strict SSH authentication, supported traffic type, DNS resolver and client status |
| General UDP or QUIC fails | Not supported by this IPv4 TCP/UDP-53 DNS design |
| Speed varies by route | Compare an identical workload in DIRECT vs tunneled mode; throughput is not a guaranteed rate |

The current manager sets sshuttle 2.0.0's latency buffer to **1 MiB** (upstream latency control remains enabled) to improve throughput across high-RTT links. This is not a claim of universal speed.

## Uninstall and interrupted cleanup

Use menu **10** (type YES) or:

```bash
sudo simple-connect uninstall --yes
```

Uninstall has durable monotonic checkpoints and does not erase your independently managed SSH identities. If interrupted, retry the same command. If the installed manager executable was already removed, recover the manager from the **matching, independently verified release**:

```bash
sudo python3 /path/to/verified/simple_connect.py uninstall --yes
```

Never run `setup` as a substitute for resuming a partially completed uninstall. An uncertain firewall ownership state needs manual investigation instead of forced cleanup.

For technical build/release procedures, see [DEVELOPMENT.md](DEVELOPMENT.md). Current real-host limitations and acceptance status are tracked in [Issue #2](https://github.com/AChWorks/simple-connect/issues/2).
