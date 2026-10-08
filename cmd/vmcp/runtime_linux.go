//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker"
)

// runtimeFlags configure the Firecracker runtime.
type runtimeFlags struct {
	stateRoot, jailBase, kernel, agent, jailer, cgroupParent, installID, pool, dns, deny string
	uidBase                                                                              int
}

func (f *runtimeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.stateRoot, "state-root", "/var/lib/vmcp", "state root; mount it nosuid and nodev")
	fs.StringVar(&f.jailBase, "jail-base", "/var/lib/vmcp/jail", "jailer chroot base on the state-root file system; keep it short")
	fs.StringVar(&f.kernel, "kernel", "/usr/share/vmcp/vmlinux", "guest kernel")
	fs.StringVar(&f.agent, "agent", "/usr/libexec/vmcp/vmcp-agent", "static guest agent")
	fs.StringVar(&f.jailer, "jailer", "/usr/libexec/vmcp/jailer", "baked jailer with its file capabilities")
	fs.StringVar(&f.cgroupParent, "cgroup-parent", "", "parent cgroup name; empty is vmcp-<install-id>, as vmcp host install creates it")
	fs.StringVar(&f.installID, "install-id", "vmcp", "install identity that tags every owned host resource")
	fs.StringVar(&f.pool, "pool", "100.80.0.0/16", "IPv4 pool for machine networks")
	fs.StringVar(&f.dns, "dns-upstreams", "1.1.1.1:53,8.8.8.8:53", "comma-separated DNS upstreams for guests")
	fs.StringVar(&f.deny, "deny", "", "comma-separated extra prefixes that guests never reach")
	fs.IntVar(&f.uidBase, "uid-base", 400000, "first machine UID and GID")
}

// attrs returns the runtime configuration for the startup log line.
func (f *runtimeFlags) attrs() []any {
	return []any{"state_root", f.stateRoot, "jail_base", f.jailBase, "cgroup_parent", f.parent(),
		"install_id", f.installID, "pool", f.pool, "dns_upstreams", f.dns, "extra_deny", f.deny, "uid_base", f.uidBase}
}

// parent is the parent cgroup name.
func (f *runtimeFlags) parent() string {
	if f.cgroupParent != "" {
		return f.cgroupParent
	}
	return firecracker.CgroupParentName(f.installID)
}

// checkProcess refuses to serve without the capabilities of the runtime.
func checkProcess() error { return firecracker.CheckProcessCapabilities() }

func newRuntime(ctx context.Context, f runtimeFlags, log *slog.Logger) (machine.Runtime, string, error) {
	pool, err := netip.ParsePrefix(f.pool)
	if err != nil {
		return nil, "", fmt.Errorf("pool: %w", err)
	}
	var deny []netip.Prefix
	for _, d := range splitList(f.deny) {
		p, err := netip.ParsePrefix(d)
		if err != nil {
			return nil, "", fmt.Errorf("deny: %w", err)
		}
		deny = append(deny, p)
	}
	rt, err := firecracker.New(ctx, firecracker.Config{
		StateRoot: f.stateRoot, JailBase: f.jailBase, KernelPath: f.kernel, AgentPath: f.agent, JailerPath: f.jailer,
		CgroupRoot: "/sys/fs/cgroup", CgroupParent: f.parent(), InstallID: f.installID,
		UIDBase: f.uidBase, Pool: pool, DNSUpstreams: splitList(f.dns), Deny: deny, Logger: log,
	})
	if err != nil {
		return nil, "", err
	}
	return rt, f.stateRoot, nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
