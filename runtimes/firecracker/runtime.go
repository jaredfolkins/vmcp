//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/image"
)

// Config is the host configuration of the Firecracker runtime.
type Config struct {
	// StateRoot holds binaries, images, and machine work directories.
	StateRoot string
	// JailBase is the jailer chroot base. Keep it short: jail socket paths
	// must stay under 108 bytes.
	JailBase string
	// KernelPath is the guest kernel.
	KernelPath string
	// AgentPath is the static guest agent binary.
	AgentPath string
	// JailerPath is the baked jailer in the image, with the file
	// capabilities in jailerCaps. vmcp uses it only after its size and
	// SHA-256 match the release lock.
	JailerPath string
	// CgroupRoot is the cgroup v2 mount, normally /sys/fs/cgroup.
	CgroupRoot string
	// CgroupParent is the parent cgroup name for every machine. vmcp host
	// install creates it and delegates it to the vmcp user.
	CgroupParent string
	// InstallID tags every host resource that this install owns.
	InstallID string
	// UIDBase is the first machine UID and GID. Slot n uses UIDBase+n.
	UIDBase int
	// Pool is the IPv4 prefix for machine /30 networks.
	Pool netip.Prefix
	// DNSUpstreams are host:port resolvers for the DNS broker and egress.
	DNSUpstreams []string
	// Deny adds destinations that public egress never reaches.
	Deny   []netip.Prefix
	Logger *slog.Logger
	// HTTP fetches images. Nil uses http.DefaultClient.
	HTTP *http.Client
}

// Runtime runs Firecracker machines on one host.
type Runtime struct {
	cfg         Config
	host        Host
	firecracker string
	jailer      string
	release     string
	compat      string
	enf         *enforcer
}

// New prepares the runtime: it checks the process capabilities, the baked
// jailer, and the parent cgroup that vmcp host install delegated, installs
// Firecracker, and replaces the vmcp nftables table. It starts the
// enforcer, which runs until ctx ends.
func New(ctx context.Context, cfg Config) (*Runtime, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.HTTP == nil {
		cfg.HTTP = http.DefaultClient
	}
	if err := ValidInstallID(cfg.InstallID); err != nil {
		return nil, err
	}
	if err := checkProcessCapabilities("/proc/self/status"); err != nil {
		return nil, err
	}
	rel, err := BakedRelease()
	if err != nil {
		return nil, err
	}
	r := &Runtime{cfg: cfg, host: DefaultHost, release: rel.Version}
	r.host.CgroupControls = filepath.Join(cfg.CgroupRoot, "cgroup.controllers")
	for _, d := range []string{cfg.StateRoot, r.binDir(), r.imagesDir(), r.machinesDir(), cfg.JailBase} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	if err := writeMarker(cfg.StateRoot, cfg.InstallID); err != nil {
		return nil, err
	}
	if r.firecracker, err = r.installBinary("firecracker"); err != nil {
		return nil, err
	}
	if err := checkJailer(cfg.JailerPath); err != nil {
		return nil, err
	}
	r.jailer = cfg.JailerPath
	if err := r.installKernel(); err != nil {
		return nil, err
	}
	if r.compat, err = image.AgentCompatibility(cfg.AgentPath); err != nil {
		return nil, fmt.Errorf("hash guest agent: %w", err)
	}
	if err := r.checkCgroupParent(); err != nil {
		return nil, err
	}
	if err := setupTable(ctx); err != nil {
		return nil, fmt.Errorf("set up nftables table: %w", err)
	}
	r.enf = newEnforcer(r)
	r.enf.sweep(ctx)
	go r.enf.run(ctx)
	return r, nil
}

func (r *Runtime) binDir() string      { return filepath.Join(r.cfg.StateRoot, "bin") }
func (r *Runtime) imagesDir() string   { return filepath.Join(r.cfg.StateRoot, "images") }
func (r *Runtime) machinesDir() string { return filepath.Join(r.cfg.StateRoot, "machines") }
func (r *Runtime) cgroupParent() string {
	return filepath.Join(r.cfg.CgroupRoot, r.cfg.CgroupParent)
}

// Name is the runtime name.
func (r *Runtime) Name() string { return Name }

// Release is the baked Firecracker release.
func (r *Runtime) Release() string { return r.release }

// installBinary writes a verified baked binary into the bin directory.
func (r *Runtime) installBinary(name string) (string, error) {
	var buf bytes.Buffer
	if err := WriteArtifact(&buf, name); err != nil {
		return "", err
	}
	p := filepath.Join(r.binDir(), name)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o755); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", fmt.Errorf("install %s: %w", name, err)
	}
	return p, nil
}

// checkCgroupParent verifies the parent cgroup. vmcp host install creates
// it, tags it, enables the controllers that the jailer limits, and
// delegates it to the vmcp user. vmcp does not create it.
func (r *Runtime) checkCgroupParent() error {
	p := r.cgroupParent()
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("parent cgroup %s is missing; run vmcp host install: %w", p, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("parent cgroup %s is not delegated to UID %d; run vmcp host install", p, os.Geteuid())
	}
	b, err := os.ReadFile(filepath.Join(p, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read parent cgroup controllers: %w", err)
	}
	enabled := strings.Fields(string(b))
	for _, c := range cgroupControllers {
		if !slices.Contains(enabled, c) {
			return fmt.Errorf("parent cgroup %s does not enable the %s controller; run vmcp host install", p, c)
		}
	}
	return nil
}

func writeMarker(dir, installID string) error {
	p := filepath.Join(dir, ".vmcp-owner")
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != installID {
		return fmt.Errorf("state root %s belongs to another install", dir)
	}
	return os.WriteFile(p, []byte(installID+"\n"), 0o600)
}

// Status reports the release, host checks, enforcer health, and capacity.
func (r *Runtime) Status() api.Status {
	st := r.host.Status()
	if r.enf.healthy() {
		st.Checks = append(st.Checks, api.Check{Name: "enforcer", OK: true})
	} else {
		st.Checks = append(st.Checks, api.Check{Name: "enforcer", Detail: "enforcer sweeps stopped"})
		st.Ready = false
	}
	for _, p := range []struct{ name, path string }{{"kernel", r.cfg.KernelPath}, {"agent", r.cfg.AgentPath}} {
		if fi, err := os.Stat(p.path); err != nil || !fi.Mode().IsRegular() {
			st.Checks = append(st.Checks, api.Check{Name: p.name, Detail: "file is missing"})
			st.Ready = false
		} else {
			st.Checks = append(st.Checks, api.Check{Name: p.name, OK: true})
		}
	}
	return st
}

// PrepareImage builds a prepared image in its own directory under the state
// root.
func (r *Runtime) PrepareImage(ctx context.Context, id string, req api.ImageRequest) (machine.ImageInfo, error) {
	plat := image.Platform{OS: "linux", Architecture: "amd64"}
	if req.Platform != "" && req.Platform != "linux/amd64" {
		return machine.ImageInfo{}, fmt.Errorf("platform %q is not supported", req.Platform)
	}
	meta, err := image.Prepare(ctx, r.cfg.HTTP, filepath.Join(r.imagesDir(), id), image.Request{
		Ref:           req.Ref,
		Registry:      req.Registry.URL,
		RegistryToken: req.Registry.Token,
		Platform:      plat,
		AgentPath:     r.cfg.AgentPath,
		MaxBytes:      4 << 30,
	})
	if err != nil {
		return machine.ImageInfo{}, err
	}
	p := meta.Process
	return machine.ImageInfo{
		ImageDigest:   meta.ImageDigest,
		Compatibility: meta.Compatibility,
		SizeBytes:     meta.SizeBytes,
		Process: machine.ProcessConfig{
			Entrypoint: p.Entrypoint, Cmd: p.Cmd, Env: p.Env, WorkingDir: p.WorkingDir, User: p.User,
		},
	}, nil
}

// ImageCompatibility is the compatibility key of images prepared with the
// installed guest agent.
func (r *Runtime) ImageCompatibility() string { return r.compat }

// PrepareSelfTestImage builds the built-in self-test image under id.
func (r *Runtime) PrepareSelfTestImage(ctx context.Context, id string) (machine.ImageInfo, error) {
	dir := r.ImageDir(id)
	_ = os.RemoveAll(dir)
	meta, err := image.PrepareSelfTest(ctx, dir, r.cfg.AgentPath)
	if err != nil {
		return machine.ImageInfo{}, err
	}
	return machine.ImageInfo{ImageDigest: meta.ImageDigest, Compatibility: meta.Compatibility, SizeBytes: meta.SizeBytes,
		Process: machine.ProcessConfig{Cmd: meta.Process.Cmd}}, nil
}

// ImageDir is the directory of a prepared image.
func (r *Runtime) ImageDir(id string) string { return filepath.Join(r.imagesDir(), id) }

// DeleteImage removes a prepared image.
func (r *Runtime) DeleteImage(id string) error { return os.RemoveAll(r.ImageDir(id)) }

// Recover kills and removes every machine cgroup, jail, and tap that this
// install left. It touches only resources under the vmcp parent cgroup, the
// vmcp jail base, and taps that carry this install tag.
func (r *Runtime) Recover(ctx context.Context) error {
	var errs []error
	entries, err := os.ReadDir(r.cgroupParent())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "vmcp-") {
			continue
		}
		p := filepath.Join(r.cgroupParent(), e.Name())
		errs = append(errs, killCgroup(p), removeCgroup(p))
	}
	jails := filepath.Join(r.cfg.JailBase, "firecracker")
	if entries, err = os.ReadDir(jails); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "vmcp-") {
				errs = append(errs, os.RemoveAll(filepath.Join(jails, e.Name())))
			}
		}
	}
	taps, err := ownedTaps(ctx, r.cfg.InstallID)
	errs = append(errs, err)
	for _, t := range taps {
		errs = append(errs, run(ctx, nil, "ip", "link", "del", "dev", t))
	}
	return errors.Join(errs...)
}
