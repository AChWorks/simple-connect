#!/usr/bin/env bash
# Build a self-contained, static HTTPS mirror folder without deploying it.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
umask 077
wheel="sshuttle-2.0.0-py3-none-any.whl"
expected_wheel="506a8cad2f047ca42f0d784654cb3459e2193bfad79d0a03734e0e07473f2bbb"
wheel_url="https://files.pythonhosted.org/packages/25/1d/c409e26b9d5d26e6f07466c3d4662abb1c3ca4810424f66f38e1b5e54f33/sshuttle-2.0.0-py3-none-any.whl"

expected_manager="$(sed -n 's/^readonly MANAGER_SHA256="\([a-f0-9]*\)"$/\1/p' install.sh)"
actual_manager="$(sha256sum simple_connect.py | awk '{print $1}')"
if [[ "$expected_manager" != "$actual_manager" ]]; then
    printf '[ERROR] Bootstrap manager hash is stale; refusing to package.\n' >&2
    exit 1
fi
out="dist/simple-connect-mirror"
mkdir -p "$out"
cp -- install.sh simple_connect.py "$out/"
if [[ -e "$out/$wheel" ]] && printf '%s  %s\n' "$expected_wheel" "$out/$wheel" | sha256sum --check --status; then
    echo "[OK] Verified upstream wheel already in mirror; skipped download."
else
    tmp="$(mktemp "$out/.wheel.XXXXXXXX")"
    trap 'rm -f -- "$tmp"' EXIT
    curl --fail --location --silent --show-error --connect-timeout 10 --max-time 90 \
        --proto '=https' --proto-redir '=https' --output "$tmp" "$wheel_url"
    printf '%s  %s\n' "$expected_wheel" "$tmp" | sha256sum --check --status || {
        echo '[ERROR] Upstream wheel SHA-256 mismatch.' >&2; exit 1;
    }
    mv -f -- "$tmp" "$out/$wheel"
fi
(
    cd "$out"
    sha256sum install.sh simple_connect.py "$wheel" > SHA256SUMS
)
printf '[OK] Mirror folder: %s\n' "$out"
printf '[INFO] Upload these EXACT files to your independent HTTPS base and keep the original SHA256SUMS.\n'
