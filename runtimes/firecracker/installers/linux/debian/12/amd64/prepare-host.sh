#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Firecracker host preparation: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'Usage: %s --check|--apply\n' "$0"
  printf 'Prepare Debian 12 AMD64 host packages and devices for the Firecracker backend.\n'
  printf '%s\n' '--check makes no changes. --apply needs root and can change host packages and services.'
  printf '%s\n' 'Host package and service changes are not rolled back after a failure.'
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
case "$1" in
  --check|--apply) mode="$1" ;;
  --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

[[ -r /etc/os-release ]] || fail 'cannot read /etc/os-release'
# shellcheck source=/dev/null
source /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 12 ]] ||
  fail "requires Debian 12; found ${ID:-unknown} ${VERSION_ID:-unknown}"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  fail "requires Linux AMD64; found $(uname -s)/$(uname -m)"
[[ "$(</proc/1/comm)" == systemd ]] || fail 'requires systemd as PID 1'
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || fail 'requires cgroup v2'
grep -Eq '(^|[[:space:]])(vmx|svm)([[:space:]]|$)' /proc/cpuinfo ||
  fail 'CPU virtualization is unavailable; enable it in firmware or the outer VM'

missing_packages=()
command -v ip >/dev/null 2>&1 && command -v tc >/dev/null 2>&1 || missing_packages+=(iproute2)
command -v curl >/dev/null 2>&1 || missing_packages+=(curl)
command -v tar >/dev/null 2>&1 || missing_packages+=(tar)
command -v modprobe >/dev/null 2>&1 || missing_packages+=(kmod)
command -v nft >/dev/null 2>&1 || missing_packages+=(nftables)
command -v docker >/dev/null 2>&1 || missing_packages+=(docker.io)

if [[ "$mode" == --apply ]]; then
  [[ "$(id -u)" -eq 0 ]] || fail '--apply requires root'
  if ((${#missing_packages[@]})); then
    printf 'Installing Debian packages: %s\n' "${missing_packages[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_packages[@]}"
  fi
  if [[ ! -e /dev/kvm ]]; then
    modprobe kvm
    if grep -Eq '(^|[[:space:]])vmx([[:space:]]|$)' /proc/cpuinfo; then
      modprobe kvm_intel
    else
      modprobe kvm_amd
    fi
  fi
  [[ -e /dev/net/tun ]] || modprobe tun
  if ! systemctl is-active --quiet docker; then
    systemctl start docker
  fi
fi

if ((${#missing_packages[@]})) && [[ "$mode" == --check ]]; then
  fail "missing packages: ${missing_packages[*]}; run sudo $0 --apply"
fi
for command_name in ip tc curl tar modprobe nft docker; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing command: $command_name"
done
[[ -r /dev/kvm && -w /dev/kvm ]] || fail '/dev/kvm is not readable and writable; check KVM and device access'
[[ -r /dev/net/tun && -w /dev/net/tun ]] || fail '/dev/net/tun is not readable and writable; check TUN and device access'
systemctl is-active --quiet docker || fail 'Docker service is not active'
docker info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -qv rootless ||
  fail 'rootful Docker Engine is required'

printf 'Firecracker host preparation: package and device checks passed for Debian 12 AMD64.\n'
printf 'Next: run the install preflight with the exact accepted inputs.\n'
