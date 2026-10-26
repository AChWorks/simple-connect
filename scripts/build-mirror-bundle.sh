#!/usr/bin/env bash
# Build exact four-file standalone mirror payload; never delete foreign files.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
umask 077
# Never stage or publish through a dist/ symlink (e.g. into a live webroot).
[[ ! -L dist ]] || { echo '[ERROR] Unsafe dist output directory: symlink.' >&2; exit 1; }
mkdir -p dist
[[ -d dist && ! -L dist && "$(realpath -e -- dist)" == "$(pwd -P)/dist" ]] || {
  echo '[ERROR] Unsafe dist output directory: must be checkout-local.' >&2
  exit 1
}
wheel="sshuttle-2.0.0-py3-none-any.whl"
expected_wheel="506a8cad2f047ca42f0d784654cb3459e2193bfad79d0a03734e0e07473f2bbb"
wheel_url="https://files.pythonhosted.org/packages/25/1d/c409e26b9d5d26e6f07466c3d4662abb1c3ca4810424f66f38e1b5e54f33/sshuttle-2.0.0-py3-none-any.whl"
expected_manager="$(sed -n 's/^readonly MANAGER_SHA256="\([a-f0-9]*\)"$/\1/p' install.sh)"
actual_manager="$(sha256sum simple_connect.py | awk '{print $1}')"
[[ -n "$expected_manager" && "$expected_manager" == "$actual_manager" ]] || {
  echo '[ERROR] Bootstrap manager SHA-256 mismatch.' >&2
  exit 1
}
out="dist/simple-connect-mirror"
allowed=(install.sh simple_connect.py "$wheel" SHA256SUMS)
if [[ -e "$out" || -L "$out" ]]; then
  [[ -d "$out" && ! -L "$out" ]] || { echo '[ERROR] Unsafe output path.' >&2; exit 1; }
  while IFS= read -r -d '' item; do
    name="${item##*/}"
    found=0
    for file in "${allowed[@]}"; do
      [[ "$name" != "$file" ]] || found=1
    done
    if [[ "$found" != 1 || ! -f "$item" || -L "$item" ]]; then
      echo "[ERROR] Unexpected mirror file: $item (left untouched)." >&2
      exit 1
    fi
  done < <(find "$out" -mindepth 1 -maxdepth 1 -print0)
fi
stage="$(mktemp -d dist/.simple-connect-stage.XXXXXXXX)"
trap 'rm -rf -- "$stage"' EXIT
cp -- install.sh simple_connect.py "$stage/"
if [[ -f "$out/$wheel" && ! -L "$out/$wheel" ]] &&
  printf '%s  %s\n' "$expected_wheel" "$out/$wheel" | sha256sum --check --status; then
  cp -- "$out/$wheel" "$stage/$wheel"
  echo '[OK] Cached wheel verified; no repeat download.'
else
  curl --fail --location --silent --show-error --connect-timeout 10 --max-time 90 \
    --proto '=https' --proto-redir '=https' --output "$stage/$wheel" "$wheel_url"
fi
printf '%s  %s\n' "$expected_wheel" "$stage/$wheel" | sha256sum --check --status || {
  echo '[ERROR] Upstream wheel hash mismatch.' >&2; exit 1;
}
(cd "$stage" && sha256sum install.sh simple_connect.py "$wheel" > SHA256SUMS &&
  sha256sum -c SHA256SUMS)
[[ "$(find "$stage" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 4 ]] || exit 1
mkdir -p "$out"
for file in "${allowed[@]}"; do
  mv -f -- "$stage/$file" "$out/$file"
done
# This directory is the intentionally public HTTPS mirror payload. Staging
# stays private; only verified final output receives public-readable modes.
chmod 0755 "$out" "$out/install.sh" "$out/simple_connect.py"
chmod 0644 "$out/$wheel" "$out/SHA256SUMS"
(cd "$out" && sha256sum -c SHA256SUMS)
[[ "$(find "$out" -mindepth 1 -maxdepth 1 | wc -l)" -eq 4 ]] || {
  echo '[ERROR] Mirror output does not have exactly four entries.' >&2; exit 1;
}
printf '[OK] Four-file mirror directory: %s\n' "$out"
