# Simple Connect — engineering and safety boundaries

- Single repo owner: AChWorks/simple-connect. Do not modify Server Connect or SSH/host networks from this project without exact separate authorization.
- Keep this utility intentionally small: one Python standard-library manager, one verified Bash bootstrap, one mirror packaging script, direct upstream sshuttle. No speculative core/provider framework.
- The selected target is Debian 13 amd64, systemd and nftables; do not silently claim other Linux/IPv6/container support.
- Never select a remote endpoint or create SSH users, passwords or private keys without operator authorization. Pin SSH host key identity out-of-band.
- SSH tunnel service defaults OFF after reboot. Preserve existing SSH, aaPanel and website reply paths; support only owned nftables cleanup and independent recovery. Ambiguous ownership must be surfaced, never flush/firewall-reset.
- Updating simple_connect.py requires updating the exact pinned MANAGER_SHA256 in install.sh in the **same candidate**. The wheel's immutable upstream digest must be validated for original and independent mirror.
- Run hermetic tests, real disposable isolated-host regression and a fresh author-separated HIGH_ASSURANCE independent review before merging privileged network code. Real hosting installation/activation needs a separate explicit rollout and recovery approval.
- Source/PR/CI are truth for candidate state; README documents stable usage and truthful limitations. No chat-dependent state or speculative release claims.
