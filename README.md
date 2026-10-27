# Simple Connect

**Connect a Linux server to the internet through a trusted remote SSH server — with a guided menu and safeguards for existing SSH and hosting services.**

Simple Connect is a lightweight, open-source manager built on [sshuttle](https://github.com/sshuttle/sshuttle). It is useful when a Linux server can reach a remote SSH endpoint but some outbound websites or downloads are difficult to access directly. You configure **two machines**:

```text
CLIENT (your Linux server)  -- authenticated SSH -->  SERVER (remote SSH host)
    Outbound IPv4 TCP + supported DNS                 Access to the internet
```

The **SERVER** uses its existing SSH service; it does not run a second VPN server. The **CLIENT** sends supported outbound traffic through SSH only when you explicitly turn Simple Connect on. It does not replace your SSH server or change the system's default route.

## Features

- **Guided terminal menu:** install, configure SSH, test, connect, disconnect, view status and logs, and uninstall.
- **Trusted SSH identity:** independently verify the SERVER's host-key fingerprint; use an existing CLIENT SSH key or explicitly create one. Public-key enrollment is optional.
- **Protection for server management:** exclude SSH endpoints and directly connected networks; manage only the tool's own nftables table.
- **Recovery by default:** an independent guard checks the connection; a stopped proxy returns to direct networking when its owned firewall state can be verified. The tunnel is **OFF after a reboot**.
- **Improved throughput:** current source uses a larger 1 MiB sshuttle latency buffer while keeping latency control enabled. Actual speed depends on your link.

## Requirements

- **CLIENT:** Debian 13 (amd64), systemd, nftables and Python >=3.10 and <4.0.
- **SERVER:** a reachable Linux SSH server, an existing SSH user and Python >=3.10 and <4.0. Other distributions are not yet broadly certified.
- SSH access from the CLIENT to the SERVER, plus a way to verify the SERVER host-key fingerprint **independently** (for example, its provider console).
- Root or `sudo` for setup on each machine.

Simple Connect handles **outbound IPv4 TCP** and conventional **UDP/53 DNS** with sshuttle. It does **not** provide general UDP forwarding, QUIC/HTTP3 tunneling, full IPv6 tunneling, or a traditional whole-device VPN. Incoming website traffic is not routed *into* the tunnel.

## Install

Run the same command on **each** machine:

```bash
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash
```

Choose **SERVER** on the remote host and **CLIENT** on the machine that needs outbound access. Installation checks the required software, verifies SHA256-pinned components and opens the menu when a terminal is available. **Installation alone does not turn the CLIENT tunnel on.**

For unattended role selection:

```bash
# On the remote SSH host:
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash -s -- --role server

# On your Linux client:
curl -fsSL https://raw.githubusercontent.com/AChWorks/simple-connect/main/install.sh | sudo bash -s -- --role client
```

The one-line installer follows the current `main` branch. For a versioned archive and checksum file, use [GitHub Releases](https://github.com/AChWorks/simple-connect/releases). Inspect trusted scripts before running them as root. If GitHub cannot be reached directly, see [installation and mirror guidance](docs/OPERATIONS.md#installation-and-release-files).

## First-time setup

1. **On the SERVER:** run `sudo simple-connect`. Use **12) SERVER fingerprints / Advanced** to find the recommended public SSH host-key fingerprint. Verify the intended SSH port. The program does not create an SSH account or change your SSH server settings.
2. **On the CLIENT:** run `sudo simple-connect`, then **3) Configure SSH connection**. Enter the SERVER's IPv4 address, SSH username and port.
3. **Select a CLIENT private key:** choose the path to an existing private-key file. If you need a dedicated key, explicitly approve its creation when prompted. The **file path** is not the key contents and not the SERVER fingerprint.
4. **Verify the SERVER:** paste the SHA256 fingerprint you obtained from its trusted console. If necessary, use **11) SSH keys / access** to opt into enrolling only your CLIENT **public key** on the remote account. Never copy the CLIENT private key to the SERVER.
5. **Check connectivity:** select **8) Test SSH + HTTPS**. Resolve any reported errors before enabling the tunnel.

### Turn the connection on

Select **4) Turn ON** on the CLIENT. Simple Connect starts in a guarded **PENDING** state and shows an operation ID.

**Important:** open a *new* SSH session to the CLIENT **after** enabling the tunnel. In that new session, run:

```bash
sudo simple-connect confirm OPERATION_ID
sudo simple-connect status
```

Replace `OPERATION_ID` with the value shown by the program. A session that was already open cannot confirm activation. If confirmation is not completed within the guarded window (about 10 minutes), the activation is rolled back.

To stop forwarding and return to the direct connection, use **6) Turn OFF** or:

```bash
sudo simple-connect off
```

## Everyday commands

| Command | Purpose |
|---|---|
| `sudo simple-connect` | Open the interactive menu |
| `sudo simple-connect status` | Check role, connection state, guard and firewall ownership |
| `sudo simple-connect test` | Test configured SSH and an external HTTPS request |
| `sudo simple-connect on` | Request guarded activation on the CLIENT |
| `sudo simple-connect off` | Stop forwarding and restore the direct state |
| `sudo simple-connect logs` | View diagnostics |
| `sudo simple-connect host-fingerprints` | See available SERVER SSH host fingerprints |
| `sudo simple-connect uninstall --yes` | Remove Simple Connect using its managed cleanup |

## Common questions

**Why does it say DIRECT or OFF after reboot?** This is intentional. Simple Connect does not automatically re-enable network interception after restarting. Open the menu and activate it again when needed.

**Why can I SSH into the SERVER but the connection is not ACTIVE?** A working SSH login does not automatically activate the CLIENT tunnel. Run the connection test, turn it on and confirm from a *new* SSH session.

**Will this route my hosted websites or all UDP applications?** No. The tool targets supported *outbound* IPv4 traffic. Keep an independent management/recovery path and test any active aaPanel/website services in your environment.

**Where do I get the SERVER fingerprint?** From the SERVER's trusted console using menu option 12, or `sudo simple-connect host-fingerprints`. Do not trust a fingerprint obtained only from an unverified CLIENT network scan.

## More information

- [Operations, SSH trust, troubleshooting and release files](docs/OPERATIONS.md)
- [Development, testing and release verification](docs/DEVELOPMENT.md)
- [Downloads and release notes](https://github.com/AChWorks/simple-connect/releases)
- [Known limitations and field-acceptance tracking](https://github.com/AChWorks/simple-connect/issues/2)

Simple Connect is independent of [Server Connect](https://github.com/AChWorks/server-connect). Upstream sshuttle 2.0.0 is licensed under LGPL-2.1; its verified wheel and license are included in the release bundle.
