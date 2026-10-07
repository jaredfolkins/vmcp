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
	"strings"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/image"
)

// ownerXattr tags every cgroup that vmcp owns with its install identity.
const ownerXattr = "trusted.vmcp.owner"

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
	// CgroupRoot is the cgroup v2 mount, normally /sys/fs/cgroup.
	CgroupRoot string
	// CgroupParent is the parent cgroup name for every machine.
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
}

// New prepares the host: it installs the baked binaries, creates and tags
// the parent cgroup, and replaces the vmcp nftables table.
func New(ctx context.Context, cfg Config) (*Runtime, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.HTTP == nil {
		cfg.HTTP = http.DefaultClient
	}
	if cfg.InstallID == "" || strings.ContainsAny(cfg.InstallID, " \t\n\"") {
		return nil, errors.New("install ID is required and must not contain spaces or quotes")
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
	if r.jailer, err = r.installBinary("jailer"); err != nil {
		return nil, err
	}
	if err := r.installKernel(); err != nil {
		return nil, err
	}
	if err := r.prepareCgroup(); err != nil {
		return nil, err
	}
	if err := setupTable(ctx); err != nil {
		return nil, fmt.Errorf("set up nftables table: %w", err)
	}
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

// prepareCgroup creates the parent cgroup, enables the controllers that the
// jailer limits, and tags it. It refuses an existing parent that another
// owner tagged.
func (r *Runtime) prepareCgroup() error {
	p := r.cgroupParent()
	if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create parent cgroup: %w", err)
	}
	owner := make([]byte, 256)
	if n, err := unix.Getxattr(p, ownerXattr, owner); err == nil && string(owner[:n]) != r.cfg.InstallID {
		return fmt.Errorf("parent cgroup %s belongs to another owner", p)
	}
	if err := unix.Setxattr(p, ownerXattr, []byte(r.cfg.InstallID), 0); err != nil {
		return fmt.Errorf("tag parent cgroup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(p, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644); err != nil {
		return fmt.Errorf("enable cgroup controllers: %w", err)
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

// Status reports the release, host checks, and capacity.
func (r *Runtime) Status() api.Status {
	st := r.host.Status()
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

// ImageMeta is a prepared image.
type ImageMeta = image.Meta

// PrepareImage builds a prepared image in its own directory under the state
// root.
func (r *Runtime) PrepareImage(ctx context.Context, id string, req api.ImageRequest) (ImageMeta, error) {
	plat := image.Platform{OS: "linux", Architecture: "amd64"}
	if req.Platform != "" && req.Platform != "linux/amd64" {
		return ImageMeta{}, fmt.Errorf("platform %q is not supported", req.Platform)
	}
	return image.Prepare(ctx, r.cfg.HTTP, filepath.Join(r.imagesDir(), id), image.Request{
		Ref:           req.Ref,
		Registry:      req.Registry.URL,
		RegistryToken: req.Registry.Token,
		Platform:      plat,
		AgentPath:     r.cfg.AgentPath,
		MaxBytes:      4 << 30,
	})
}

// ImageDir is the directory of a prepared image.
func (r *Runtime) ImageDir(id string) string { return filepath.Join(r.imagesDir(), id) }

// DeleteImage removes a prepared image.
func (r *Runtime) DeleteImage(id string) error { return os.RemoveAll(r.ImageDir(id)) }
