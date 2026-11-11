#!/usr/bin/env bash
# Proves the Compose install on every supported host distribution.
#
#   scripts/host-matrix.sh [debian/12 debian/13 ubuntu/24.04 ubuntu/26.04]
#
# For each host it boots a fresh cloud image as a QEMU guest with nested
# KVM, runs prepare-host.sh --apply, loads the vmcp image built from this
# tree, runs one `docker compose up -d`, the self-test, a second `up`, a
# guest reboot, and the self-test again. It needs qemu-system-x86_64,
# qemu-img, xorriso, curl, ssh, docker, and nested virtualization. It
# changes nothing on this host outside VMCP_MATRIX_DIR.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=${VMCP_MATRIX_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/vmcp-host-matrix}
image=vmcp:host-matrix

declare -A url=(
  [debian/12]=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
  [debian/13]=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
  [ubuntu/24.04]=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
  [ubuntu/26.04]=https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img
)
hosts=("$@")
((${#hosts[@]})) || hosts=(debian/12 debian/13 ubuntu/24.04 ubuntu/26.04)
for h in "${hosts[@]}"; do
  [[ -n "${url[$h]:-}" ]] || { printf 'unknown host %s\n' "$h" >&2; exit 2; }
  [[ -x "$repo/runtimes/firecracker/installers/linux/$h/amd64/prepare-host.sh" ]] ||
    { printf 'no installer folder for %s\n' "$h" >&2; exit 2; }
done

mkdir -p "$work/img"
[[ -f "$work/key" ]] || ssh-keygen -q -t ed25519 -N '' -f "$work/key" -C vmcp-host-matrix
docker build -q -t "$image" "$repo" >/dev/null
docker save "$image" -o "$work/vmcp.tar"

ssh_opts=(-q -i "$work/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)

# The guest half: prints one line per proof and fails on the first miss.
# shellcheck disable=SC2016
guest_probe='
set -euo pipefail
for _ in $(seq 90); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ready || true)
  [ "$code" = 204 ] && break
  sleep 2
done
[ "$code" = 204 ] || { echo "ready=$code"; exit 1; }
cred=$(sudo docker run --rm -u 0 -v vmcp_vmcp-credential:/c --entrypoint cat '"$image"' /c/vmcp-credential)
curl -s -m 300 -X POST -H "Authorization: Bearer $cred" http://127.0.0.1:18080/v1/selftest | grep -q "\"passed\":true" ||
  { echo "self-test failed"; exit 1; }
denials=$(sudo dmesg | grep -c "apparmor=\"DENIED\".*vmcp" || true)
[ "$denials" = 0 ] || { echo "apparmor denials=$denials"; exit 1; }
echo "ready, self-test passed, 0 denials"
'

run_host() {
  local h=$1 port=$2 dir base s out
  dir="$work/vm/${h//\//-}"
  base="$work/img/$(basename "${url[$h]}")"
  [[ -f "$base" ]] || curl -fsSL -o "$base" "${url[$h]}"
  mkdir -p "$dir"
  if [[ -f "$dir/pid" ]]; then kill "$(cat "$dir/pid")" 2>/dev/null || true; sleep 1; fi
  rm -f "$dir"/{disk.qcow2,seed.iso,pid}
  qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$dir/disk.qcow2" 24G
  printf 'instance-id: %s\nlocal-hostname: vmcp-matrix\n' "${h//\//-}" >"$dir/meta-data"
  printf '#cloud-config\nusers:\n  - name: t\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - %s\n' \
    "$(cat "$work/key.pub")" >"$dir/user-data"
  xorriso -as mkisofs -quiet -o "$dir/seed.iso" -V cidata -J -r "$dir/user-data" "$dir/meta-data" 2>/dev/null
  qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 6144 -display none -daemonize -pidfile "$dir/pid" \
    -drive "file=$dir/disk.qcow2,if=virtio" -drive "file=$dir/seed.iso,if=virtio,media=cdrom" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$port-:22"
  s=(ssh "${ssh_opts[@]}" -p "$port" t@127.0.0.1)
  wait_ssh() { for _ in $(seq 120); do "${s[@]}" true 2>/dev/null && return 0; sleep 3; done; echo 'no ssh'; return 1; }
  wait_ssh
  "${s[@]}" 'sudo cloud-init status --wait >/dev/null 2>&1 || true; mkdir -p vmcp/runtimes/firecracker/deploy'
  # shellcheck disable=SC2016
  out=$("${s[@]}" '. /etc/os-release; echo "$ID $VERSION_ID, kernel $(uname -r)"')
  echo "os: $out"
  scp "${ssh_opts[@]}" -P "$port" "$repo/runtimes/firecracker/installers/linux/$h/amd64/prepare-host.sh" \
    "$repo/compose.yaml" t@127.0.0.1:vmcp/
  scp "${ssh_opts[@]}" -P "$port" "$repo/runtimes/firecracker/deploy/seccomp.json" t@127.0.0.1:vmcp/runtimes/firecracker/deploy/
  "${s[@]}" 'cd vmcp && sudo ./prepare-host.sh --apply >prepare.log 2>&1 && ./prepare-host.sh --check'
  "${s[@]}" 'sudo docker load -q' <"$work/vmcp.tar" >/dev/null
  "${s[@]}" "cd vmcp && sudo VMCP_IMAGE=$image docker compose up -d >up.log 2>&1 &&
    sudo docker logs vmcp-vmcp-host-1 2>/dev/null | grep -E '\"(host_os|installed)\"' | tr -s ' ' | tr '\n' ' '; echo"
  out=$("${s[@]}" "$guest_probe")
  echo "first up: $out"
  "${s[@]}" "cd vmcp && sudo VMCP_IMAGE=$image docker compose up -d >up2.log 2>&1 &&
    sudo docker logs vmcp-vmcp-host-1 2>/dev/null | tr -d ' \n' | grep -o '\"written\":\[[^]]*\]' | tail -1 | grep -qx '\"written\":\[\]'"
  echo 'second up: 0 writes'
  "${s[@]}" 'sudo systemctl reboot' || true
  sleep 15
  wait_ssh
  out=$("${s[@]}" "$guest_probe")
  echo "after reboot: $out"
  echo PASS
}

port=22200
failed=0
for h in "${hosts[@]}"; do
  port=$((port + 1))
  log="$work/${h//\//-}.log"
  # A subshell of its own keeps errexit on inside run_host.
  (run_host "$h" "$port" >"$log" 2>&1) &
done
wait || true
for h in "${hosts[@]}"; do
  log="$work/${h//\//-}.log"
  printf '== %s\n' "$h"
  cat "$log"
  [[ "$(tail -1 "$log")" == PASS ]] || { echo FAIL; failed=1; }
  pid="$work/vm/${h//\//-}/pid"
  if [[ -f "$pid" ]]; then kill "$(cat "$pid")" 2>/dev/null || true; fi
done
exit "$failed"
