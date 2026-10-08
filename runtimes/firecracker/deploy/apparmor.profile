# vmcp-owner: @INSTALL_ID@
# AppArmor profile vmcp-@INSTALL_ID@ of the vmcp service container.
# vmcp host install renders this template, writes it to
# /etc/apparmor.d/vmcp-@INSTALL_ID@, and loads it in enforce mode.
# vmcp host teardown unloads and removes each file that has the
# vmcp-owner line of its install. Do not edit the rendered file.
#
# One profile confines tini, vmcp, its tools, the jailer, and Firecracker.
# Paths that start at / without /var/lib/vmcp are inside a jail, after the
# jailer moved its root there with pivot_root.

abi <abi/3.0>,

#include <tunables/global>

profile vmcp-@INSTALL_ID@ flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # The union of the file capabilities of vmcp and of the jailer.
  capability chown,
  capability dac_override,
  capability fowner,
  capability fsetid,
  capability mknod,
  capability net_admin,
  capability net_bind_service,
  capability setgid,
  capability setuid,
  capability sys_admin,

  # The API, the brokers, image registries, and DNS.
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  # ip, nft, and the enforcer watches.
  network netlink raw,
  # Guest vsock and the Firecracker API are Unix sockets on the host:
  # Firecracker serves guest vsock on v.sock and v.sock_<port> in the jail.
  # So no process opens an AF_VSOCK socket, and the profile allows no
  # vsock family.
  network unix stream,
  network unix dgram,

  # The jailer: a private mount namespace, a bind mount of the jail root,
  # pivot_root into it, and the unmount of the old root.
  mount options=(rw, rslave) -> /,
  mount options=(rw, rbind) /var/lib/vmcp/jail/firecracker/*/root/ -> /var/lib/vmcp/jail/firecracker/*/root/,
  pivot_root oldroot=/var/lib/vmcp/jail/firecracker/*/root/old_root/ /var/lib/vmcp/jail/firecracker/*/root/,
  umount /old_root/,

  # Signals and ptrace only inside this profile, and from the container
  # runtime.
  signal (send, receive) peer=vmcp-@INSTALL_ID@,
  signal (receive) peer=unconfined,
  signal (receive) peer=runc,
  signal (receive) peer=crun,
  ptrace (read, readby) peer=vmcp-@INSTALL_ID@,

  # Programs.
  /usr/bin/tini ix,
  /usr/local/bin/vmcp rix,
  /usr/libexec/vmcp/jailer rix,
  /usr/bin/ip rix,
  /usr/sbin/nft rix,
  /usr/sbin/mke2fs rix,
  /firecracker rix,

  # vmcp inputs.
  /usr/libexec/vmcp/vmcp-agent r,
  /usr/share/vmcp/ r,
  /usr/share/vmcp/** r,
  /run/secrets/vmcp-credential r,
  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/nsswitch.conf r,
  /etc/ssl/certs/ r,
  /etc/ssl/certs/** r,
  /usr/share/ca-certificates/** r,
  /etc/iproute2/ r,
  /etc/iproute2/** r,
  /etc/mke2fs.conf r,

  # The state root: binaries, images, machines, and jails.
  /var/lib/vmcp/ rw,
  /var/lib/vmcp/** rwlk,

  # The parent cgroup of this install, and the host checks. The jailer
  # writes +cpu, +memory, and +pids into cgroup.subtree_control of every
  # ancestor of its cgroup, also of the root, where they are on already.
  # The Go runtime reads cpu.max of its own cgroup and its ancestors.
  /sys/fs/cgroup/ r,
  /sys/fs/cgroup/cgroup.controllers r,
  /sys/fs/cgroup/cgroup.subtree_control rw,
  /sys/fs/cgroup/**/cpu.max r,
  # vmcp holds the lock of the parent cgroup while it runs; vmcp host
  # teardown refuses to start while it is held.
  /sys/fs/cgroup/vmcp-@INSTALL_ID@/ rwk,
  /sys/fs/cgroup/vmcp-@INSTALL_ID@/** rw,

  @{PROC}/ r,
  @{PROC}/** r,
  # The Go runtime reads it at start.
  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size r,

  /dev/kvm rw,
  /dev/net/tun rw,
  /dev/null rw,
  /dev/urandom rw,

  # Inside a jail. The jailer gives the jail root, /run, and the device
  # nodes that it creates to the machine user.
  / w,
  /run/ w,
  /dev/ rw,
  /dev/net/ rw,
  /dev/userfaultfd rw,
  /vmlinux r,
  /rootfs.ext4 r,
  /config.bin r,
  /config.json r,
  /upper.ext4 rw,
  /drive-*.ext4 rw,
  /fc.sock rw,
  /v.sock rw,
  /v.sock_* rw,
  /firecracker.pid rw,
  /old_root/ rw,
}
