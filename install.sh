#!/usr/bin/env bash
# Simple Connect bootstrap: same SHA-pinned manager from GitHub or a mirror.
set -Eeuo pipefail
umask 077
readonly OFFICIAL_MANAGER="https://raw.githubusercontent.com/AChWorks/simple-connect/main/simple_connect.py"
readonly OFFICIAL_WHEEL="https://files.pythonhosted.org/packages/25/1d/c409e26b9d5d26e6f07466c3d4662abb1c3ca4810424f66f38e1b5e54f33/sshuttle-2.0.0-py3-none-any.whl"
readonly MANAGER_SHA256="e45a21f7ab69b4fb45ae8c383471cf694da085a699017a24674e3ec790d02b49"
readonly WHEEL_SHA256="506a8cad2f047ca42f0d784654cb3459e2193bfad79d0a03734e0e07473f2bbb"
readonly DEFAULT_MIRROR="https://helpe.ir/simple-connect"

die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
info() { printf '[INFO] %s\n' "$*"; }

[[ $(id -u) -eq 0 ]] || die "Run with sudo/root; e.g. curl -fsSL URL/install.sh | sudo bash"
role=""
mirror=""
wheel_url=""
while (($#)); do
    case "$1" in
        --role) (($# >= 2)) || die "Missing --role value"; role="$2"; shift 2 ;;
        --mirror)
            if (($# >= 2)) && [[ "$2" == https://* ]]; then
                mirror="$(printf '%s' "$2" | sed 's,/$,,')"; shift 2
            else
                mirror="$DEFAULT_MIRROR"; shift
            fi ;;
        --wheel-url) (($# >= 2)) || die "Missing --wheel-url"; wheel_url="$2"; shift 2 ;;
        --help|-h)
            printf 'Usage: install.sh [--role server|client] [--mirror [HTTPS_BASE_URL]] [--wheel-url HTTPS_URL]\n'
            exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

if [[ -n "$mirror" ]]; then
    [[ "$mirror" == https://* ]] || die "Mirror must use HTTPS."
    manager_url="$mirror/simple_connect.py"
    [[ -n "$wheel_url" ]] || wheel_url="$mirror/sshuttle-2.0.0-py3-none-any.whl"
else
    manager_url="$OFFICIAL_MANAGER"
    [[ -n "$wheel_url" ]] || wheel_url="$OFFICIAL_WHEEL"
fi
[[ "$wheel_url" == https://* ]] || die "Wheel URL must be HTTPS."

if ! command -v python3 >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || die "Python3 missing; apt-get not found."
    info "Python3 missing: installing required package only."
    apt-get update
    apt-get install -y --no-install-recommends python3
fi
/usr/bin/python3 -c 'import sys; assert (3,10) <= sys.version_info[:2] < (4,0)' ||
    die "System Python >=3.10 and <4.0 is required by sshuttle 2.0.0."

if [[ -z "$role" ]]; then
    [[ -e /dev/tty ]] || die "Specify --role server|client in noninteractive mode."
    while [[ -z "$role" ]]; do
        printf '\nSimple Connect - select this machine role:\n  1) SERVER (remote SSH endpoint)\n  2) CLIENT (Iran-side outbound connectivity)\n  0) Cancel\n'
        read -r -p 'Choose 1 or 2: ' choice < /dev/tty || die "Cannot read terminal choice; installer cancelled."
        case "$choice" in
            1) role="server" ;;
            2) role="client" ;;
            0) info "Cancelled without installing."; exit 0 ;;
            *) printf '[WARN] Choose 1, 2 or 0. No changes were made.\n' >&2 ;;
        esac
    done
fi
[[ "$role" == client || "$role" == server ]] || die "Role must be client or server."

temp="$(mktemp -d -t simple-connect-bootstrap.XXXXXXXX)"
trap 'rm -rf -- "$temp"' EXIT
info "Fetching pinned manager (source: $([[ -n "$mirror" ]] && echo mirror || echo GitHub))."
curl --fail --location --silent --show-error --retry 2 --connect-timeout 10 --max-time 70 \
    --proto '=https' --proto-redir '=https' --output "$temp/simple_connect.py" "$manager_url" ||
    die "Manager download failed. Try a trusted mirror; no installation performed."
printf '%s  %s\n' "$MANAGER_SHA256" "$temp/simple_connect.py" | sha256sum --check --status ||
    die "Manager SHA-256 MISMATCH. Rejecting source; no installation performed."
info "Manager SHA-256 verified."

# A piped shell script needs /dev/tty for interactive setup.
# /dev/tty can exist but have no controlling terminal (cron, Docker, CI).
# A read-permission check alone is insufficient; probe a real open first.
if ( : </dev/tty ) 2>/dev/null; then
    exec 3< /dev/tty
    /usr/bin/python3 "$temp/simple_connect.py" setup "$role" --wheel-url "$wheel_url" <&3
    # Keep the user in the manager after installation. Wizard errors are
    # handled by its resilient menu rather than terminating the bootstrap.
    /usr/bin/python3 "$temp/simple_connect.py" <&3
    exec 3<&-
else
    /usr/bin/python3 "$temp/simple_connect.py" setup "$role" --wheel-url "$wheel_url" </dev/null
fi
if [[ -x /usr/local/sbin/simple-connect ]]; then
    printf '\n[OK] Simple Connect installed. Manage with: sudo simple-connect\n'
else
    info "Menu session finished; Simple Connect is no longer installed."
fi
