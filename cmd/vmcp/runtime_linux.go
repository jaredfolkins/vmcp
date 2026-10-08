//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
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

// hostCommand runs vmcp host check, install, teardown, or status. It
// prints one JSON result and fails when the result is not OK. Run it as
// root in a one-shot privileged container; AGENTS.md lists the flags.
func hostCommand(ctx context.Context, args []string, out io.Writer, log *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: vmcp host check|install|teardown|status --install-id ID [flags]")
	}
	command := args[0]
	switch command {
	case "check", "install", "teardown", "status":
	default:
		return fmt.Errorf("unknown host command %q", command)
	}
	fs := flag.NewFlagSet("host "+command, flag.ContinueOnError)
	installID := fs.String("install-id", "", "install identity that tags every host resource (required)")
	hostRoot := fs.String("host-root", "/host", "directory that holds the host /etc as <host-root>/etc")
	uid, gid := 65532, 65532
	if command == "install" {
		fs.IntVar(&uid, "service-uid", uid, "UID of the vmcp service; the parent cgroup is delegated to it")
		fs.IntVar(&gid, "service-gid", gid, "GID of the vmcp service")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch {
	case fs.NArg() > 0:
		return fmt.Errorf("host %s takes no arguments, got %q", command, fs.Args())
	case *installID == "":
		return errors.New("--install-id is required")
	case !filepath.IsAbs(*hostRoot):
		return fmt.Errorf("--host-root %q must be an absolute path", *hostRoot)
	case uid < 0 || gid < 0:
		return errors.New("--service-uid and --service-gid must not be negative")
	}
	res := firecracker.RunHostCommand(ctx, command, firecracker.HostConfig{
		InstallID: *installID, HostRoot: filepath.Clean(*hostRoot), CgroupRoot: "/sys/fs/cgroup",
		SecurityFS: "/sys/kernel/security", CPUInfo: "/proc/cpuinfo", ServiceUID: uid, ServiceGID: gid,
		Version: version, Commit: commit, Logger: log,
	})
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("write host result: %w", err)
	}
	if !res.OK {
		return errReported
	}
	return nil
}
