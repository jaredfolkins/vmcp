#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Firecracker host preparation: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'Usage: %s --check|--apply\n' "$0"
  printf 'Prepare a Ubuntu 24.04 AMD64 host for the vmcp Compose install.\n'
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
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] ||
  fail "requires Ubuntu 24.04; found ${ID:-unknown} ${VERSION_ID:-unknown}"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  fail "requires Linux AMD64; found $(uname -s)/$(uname -m)"
[[ "$(</proc/1/comm)" == systemd ]] || fail 'requires systemd as PID 1'
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || fail 'requires cgroup v2'
grep -Eq '(^|[[:space:]])(vmx|svm)([[:space:]]|$)' /proc/cpuinfo ||
  fail 'CPU virtualization is unavailable; enable it in firmware or the outer VM'
[[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] ||
  fail 'AppArmor is not enabled; install the apparmor package and boot the kernel with apparmor=1 security=apparmor'

have_docker() { command -v docker >/dev/null 2>&1; }
have_compose() { docker compose version >/dev/null 2>&1; }

if [[ "$mode" == --apply ]]; then
  [[ "$(id -u)" -eq 0 ]] || fail '--apply requires root'
  if ! have_docker; then
    # Docker Engine and the Compose plugin from the Docker apt repository.
    printf 'Installing Docker Engine and the Compose plugin from download.docker.com\n'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
      "$VERSION_CODENAME" >/etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
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
    systemctl enable --now docker
  fi
fi

have_docker || fail "Docker is missing; run sudo $0 --apply"
have_compose || fail 'the Docker Compose plugin is missing; install docker-compose-plugin (or docker-compose-v2 with docker.io)'
[[ -e /dev/kvm ]] || fail "/dev/kvm is missing; run sudo $0 --apply"
[[ -e /dev/net/tun ]] || fail "/dev/net/tun is missing; run sudo $0 --apply"
systemctl is-active --quiet docker || fail 'Docker service is not active'
if [[ "$(id -u)" -eq 0 ]]; then
  docker info --format '{{json .SecurityOptions}}' | grep -q apparmor ||
    fail 'Docker does not use AppArmor'
  docker info --format '{{json .SecurityOptions}}' | grep -qv rootless ||
    fail 'rootful Docker Engine is required'
fi

printf 'Firecracker host preparation: checks passed for Ubuntu 24.04 AMD64. Next: docker compose up -d\n'
