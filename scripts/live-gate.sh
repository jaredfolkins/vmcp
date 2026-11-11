#!/usr/bin/env bash
# Runs the Firecracker live gate of AGENTS.md (Container settings proven by
# the live gate), steps 1, 2, 3, 5, and 6, on this KVM host.
#
# Usage: scripts/live-gate.sh [--keep] [-test.run pattern]
#
# It builds vmcp:dev and the gate image, installs the host resources of
# install "live-gate", runs TestLiveFirecracker in the vmcp image as UID
# 65532, counts the AppArmor denials of the gate, and tears the install
# down. --keep leaves the install for another run. It needs Docker, sudo,
# journalctl, /dev/kvm, and /dev/net/tun. The log is in $GATE_DIR/gate.log.
set -euo pipefail

install_id=live-gate
keep=false
run_pattern='^TestLiveFirecracker$'
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) keep=true ;;
    -test.run) run_pattern="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate_dir=${GATE_DIR:-$(mktemp -d)}
mkdir -p "$gate_dir"

host_command() {
  docker run --rm --user 0:0 --cgroupns=host --network host --pid=host \
    --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
    --cap-add MAC_ADMIN --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
    --cap-add SYS_ADMIN --cap-add SYS_MODULE --cap-add SYS_PTRACE \
    --security-opt apparmor=unconfined \
    -v /etc:/host/etc -v /usr/lib/os-release:/host/usr/lib/os-release:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /sys/fs/cgroup:/sys/fs/cgroup \
    -v /sys/kernel/security:/sys/kernel/security \
    vmcp:dev host "$1" --install-id "$install_id"
}

echo "step 1: build vmcp:dev and install the host resources of $install_id"
docker build -q -t vmcp:dev "$repo" >/dev/null
host_command install >"$gate_dir/install.json"

echo "step 3: build the gate image"
(cd "$repo" && CGO_ENABLED=0 go test -c -trimpath -o "$gate_dir/firecracker.test" ./runtimes/firecracker)
cp "$repo/runtimes/firecracker/testdata/live.hujson" "$gate_dir/live.hujson"
cat >"$gate_dir/Dockerfile" <<'EOF'
FROM vmcp:dev
USER 0:0
COPY --chown=0:0 --chmod=0555 firecracker.test /usr/local/bin/vmcp
RUN setcap cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_net_admin,cap_net_bind_service=eip /usr/local/bin/vmcp
COPY --chown=0:0 --chmod=0444 live.hujson /usr/share/vmcp/live.hujson
USER 65532:65532
EOF
docker build -q -t vmcp:gate "$gate_dir" >/dev/null

echo "step 2: run the gate in the vmcp image as UID 65532"
start=$(date -u '+%Y-%m-%d %H:%M:%S')
status=0
docker run --rm --user 65532:65532 \
  --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --security-opt "apparmor=vmcp-$install_id" \
  --security-opt "seccomp=/etc/vmcp/$install_id/seccomp.json" \
  --device /dev/kvm --device /dev/net/tun \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
  --cap-add MKNOD --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --cap-add SETGID --cap-add SETUID --cap-add SYS_ADMIN \
  --no-healthcheck \
  vmcp:gate -test.run "$run_pattern" -test.v -vmcp-live-config /usr/share/vmcp/live.hujson \
  >"$gate_dir/gate.log" 2>&1 || status=$?
grep -E '^\s*--- (PASS|FAIL)' "$gate_dir/gate.log" || true

echo "step 5: count the AppArmor denials of the gate"
kernel_log=$(sudo journalctl -k --since "$start UTC")
denials=$(grep 'apparmor="DENIED"' <<<"$kernel_log" | grep -c "profile=\"vmcp-$install_id\"" || true)
suppressed=$(grep -c 'callbacks suppressed' <<<"$kernel_log" || true)
echo "apparmor denials: $denials; suppressed audit lines: $suppressed"

if [[ "$keep" == false ]]; then
  echo "step 6: tear down $install_id"
  host_command teardown >"$gate_dir/teardown.json"
fi

echo "gate log: $gate_dir/gate.log"
if [[ $status -ne 0 || $denials -ne 0 || $suppressed -ne 0 ]]; then
  echo "live gate FAILED" >&2
  exit 1
fi
echo "live gate passed"
