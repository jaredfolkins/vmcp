//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

// The seccomp profile and the AppArmor profile template of the vmcp
// service container. vmcp host install writes them to the host.
var (
	//go:embed deploy/seccomp.json
	seccompProfile []byte
	//go:embed deploy/apparmor.profile
	apparmorTemplate string
)

const (
	// ownerXattr tags every cgroup that vmcp owns with its install
	// identity. A cgroup inside a tagged cgroup belongs to the same
	// install unless it has another tag.
	ownerXattr = "trusted.vmcp.owner"
	// ownerLine starts the first line of every host text file that vmcp
	// writes. The install identity follows it.
	ownerLine = "# vmcp-owner: "
	// ownerMarker is the marker file of a vmcp configuration directory.
	// Its first line is an owner line. Each other line names one file of
	// the directory that vmcp wrote.
	ownerMarker = ".vmcp-owner"
	// installIDToken is replaced with the install identity in templates.
	installIDToken = "@INSTALL_ID@"
	receiptSchema  = "vmcp/host-receipt/v1"
	receiptName    = "receipt.json"
	seccompName    = "seccomp.json"
)

// delegatedFiles are the parent cgroup directory and the files that a
// delegatee writes, as the cgroup v2 documentation lists them.
var delegatedFiles = []string{"", "cgroup.procs", "cgroup.subtree_control", "cgroup.threads"}

// Kinds of host resources.
const (
	kindCgroup          = "cgroup"
	kindAppArmorFile    = "apparmor-file"
	kindAppArmorProfile = "apparmor-profile"
	kindModulesLoad     = "modules-load"
	kindConfigDir       = "config-dir"
	kindConfigFile      = "config-file"
	kindLink            = "link"
)

// HostConfig selects the host and the identity of one install. The host
// commands run as root in a privileged container. The host /etc is under
// HostRoot; the cgroup root, securityfs, and the network namespace are the
// host ones.
type HostConfig struct {
	InstallID string
	// HostRoot holds the host /etc at HostRoot/etc.
	HostRoot   string
	CgroupRoot string
	SecurityFS string
	CPUInfo    string
	// ServiceUID and ServiceGID run the vmcp service. Install delegates the
	// parent cgroup to them.
	ServiceUID int
	ServiceGID int
	// Version and Commit identify this vmcp build in the receipt.
	Version string
	Commit  string
	Logger  *slog.Logger
	// Now and sys are replaced by tests.
	Now func() time.Time
	sys hostSystem
}

// HostResource is one host resource that a host command found, removed,
// wrote, or refused to touch.
type HostResource struct {
	Kind string `json:"kind"`
	// Path is the host path, or the name of a profile or link.
	Path   string `json:"path"`
	Owner  string `json:"owner,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// HostReceipt records a committed host install.
type HostReceipt struct {
	Schema      string    `json:"schema"`
	InstallID   string    `json:"install_id"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	Release     string    `json:"release"`
	ServiceUID  int       `json:"service_uid"`
	ServiceGID  int       `json:"service_gid"`
	InstalledAt time.Time `json:"installed_at"`
}

// HostResult is the one JSON result of a host command.
type HostResult struct {
	Command   string `json:"command"`
	InstallID string `json:"install_id"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	// Installed is true when every resource of a complete install exists.
	Installed bool        `json:"installed"`
	Checks    []api.Check `json:"checks,omitempty"`
	// KilledProcesses counts the processes that teardown found in owned
	// cgroups and killed.
	KilledProcesses int            `json:"killed_processes"`
	Removed         []HostResource `json:"removed"`
	Written         []HostResource `json:"written"`
	// Owned is a fresh inventory of the resources of this install, taken
	// at the end of the command.
	Owned []HostResource `json:"owned"`
	// Conflicts are untagged resources that look like vmcp resources, and
	// resources that block this install. vmcp never touches them.
	Conflicts []HostResource `json:"conflicts"`
	// OtherInstalls are resources that another install identity tagged.
	OtherInstalls []HostResource `json:"other_installs"`
	Receipt       *HostReceipt   `json:"receipt,omitempty"`
}

// hostRun is one host command.
type hostRun struct {
	cfg HostConfig
	sys hostSystem
	log *slog.Logger
	res *HostResult
}

// RunHostCommand runs check, install, teardown, or status for one install
// identity and returns its result. The result is complete also when the
// command fails; OK is false then.
func RunHostCommand(ctx context.Context, command string, cfg HostConfig) HostResult {
	res := HostResult{Command: command, InstallID: cfg.InstallID, Removed: []HostResource{},
		Written: []HostResource{}, Owned: []HostResource{}, Conflicts: []HostResource{}, OtherInstalls: []HostResource{}}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger.With("install_op", command, "install_id", cfg.InstallID)
	ctx, span := trace.Start(ctx, log, "host."+command)
	h := &hostRun{cfg: cfg, sys: cfg.sys, log: log, res: &res}
	if h.sys == nil {
		h.sys = kernelHost{ctx: ctx, securityFS: cfg.SecurityFS}
	}
	log.InfoContext(ctx, "host command started", "host_root", cfg.HostRoot)
	err := ValidInstallID(cfg.InstallID)
	if err == nil {
		switch command {
		case "check":
			err = h.check(ctx)
		case "install":
			err = h.install(ctx)
		case "teardown":
			err = h.teardown(ctx)
		case "status":
			err = h.status(ctx)
		default:
			err = fmt.Errorf("unknown host command %q", command)
		}
	}
	res.OK = err == nil
	if err != nil && command == "install" {
		// A failed install leaves only tagged resources. Report them; the
		// next install or teardown removes them.
		if inv, ierr := h.inventory(ctx); ierr == nil {
			h.report(inv)
		}
	}
	if err != nil {
		res.Error = err.Error()
		log.ErrorContext(ctx, "host command failed", "code", "host_"+command+"_failed", "error", trace.BoundedError(err))
	}
	d := span.End(err)
	log.InfoContext(ctx, "host command finished", "ok", res.OK, "installed", res.Installed,
		"removed", len(res.Removed), "written", len(res.Written), "conflicts", len(res.Conflicts),
		"killed_processes", res.KilledProcesses, "duration_ms", trace.Millis(d))
	return res
}

// etc returns a path under the host /etc.
func (h *hostRun) etc(elem ...string) string {
	return filepath.Join(append([]string{h.cfg.HostRoot, "etc"}, elem...)...)
}

// hostPath is the host path of a path under HostRoot.
func (h *hostRun) hostPath(p string) string {
	rel, err := filepath.Rel(h.cfg.HostRoot, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return "/" + rel
}

func (h *hostRun) profileName() string { return "vmcp-" + h.cfg.InstallID }
func (h *hostRun) parentCgroup() string {
	return filepath.Join(h.cfg.CgroupRoot, CgroupParentName(h.cfg.InstallID))
}
func (h *hostRun) profileFile() string { return h.etc("apparmor.d", h.profileName()) }
func (h *hostRun) modulesFile() string {
	return h.etc("modules-load.d", "vmcp-"+h.cfg.InstallID+".conf")
}
func (h *hostRun) configDir() string { return h.etc("vmcp", h.cfg.InstallID) }

// check verifies the host prerequisites. It makes no change.
func (h *hostRun) check(ctx context.Context) error {
	_, span := trace.Start(ctx, h.log, "host.check")
	add := func(name string, err error) {
		c := api.Check{Name: name, OK: err == nil}
		if err != nil {
			c.Detail = err.Error()
		}
		h.res.Checks = append(h.res.Checks, c)
	}
	add("root", func() error {
		if h.sys.euid() != 0 {
			return errors.New("host commands run as root; use --user 0:0")
		}
		return nil
	}())
	add("host-etc", func() error {
		fi, err := os.Stat(h.etc())
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("host /etc is not mounted at %s", h.etc())
		}
		return nil
	}())
	add("cgroup2", func() error {
		for _, f := range []string{"cgroup.controllers", "cgroup.subtree_control"} {
			b, err := os.ReadFile(filepath.Join(h.cfg.CgroupRoot, f))
			if err != nil {
				return fmt.Errorf("cgroup v2 root is not mounted at %s", h.cfg.CgroupRoot)
			}
			have := strings.Fields(string(b))
			for _, c := range cgroupControllers {
				if !slices.Contains(have, c) {
					return fmt.Errorf("the cgroup root %s does not enable the %s controller", f, c)
				}
			}
		}
		return nil
	}())
	add("apparmor", func() error {
		_, err := h.sys.loadedProfiles()
		return err
	}())
	add("cpu-virtualization", func() error {
		_, err := h.kvmModule()
		return err
	}())
	var failed []string
	for _, c := range h.res.Checks {
		if !c.OK {
			failed = append(failed, c.Name)
			h.log.WarnContext(ctx, "host check failed", "code", "host_check_failed", "check", c.Name, "detail", c.Detail)
		}
	}
	var err error
	if len(failed) > 0 {
		err = fmt.Errorf("host checks failed: %s", strings.Join(failed, ", "))
	}
	span.End(err, "checks", len(h.res.Checks))
	return err
}

// kvmModule returns the KVM module for the host CPU.
func (h *hostRun) kvmModule() (string, error) {
	b, err := os.ReadFile(h.cfg.CPUInfo)
	if err != nil {
		return "", fmt.Errorf("read CPU flags: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(k) != "flags" {
			continue
		}
		flags := strings.Fields(v)
		switch {
		case slices.Contains(flags, "vmx"):
			return "kvm_intel", nil
		case slices.Contains(flags, "svm"):
			return "kvm_amd", nil
		}
		break
	}
	return "", errors.New("the CPU has no vmx or svm flag; enable virtualization")
}

// status reports the inventory and the receipt. It makes no change.
func (h *hostRun) status(ctx context.Context) error {
	inv, err := h.inventory(ctx)
	if err != nil {
		return err
	}
	h.report(inv)
	h.res.Installed = h.complete(inv) == nil
	h.res.Receipt = h.readReceipt(inv)
	return nil
}

// report copies an inventory into the result. The inventory already
// added its conflicts.
func (h *hostRun) report(inv *inventory) {
	h.res.Owned = inv.ownedResources()
	h.res.OtherInstalls = inv.others
}

func (h *hostRun) readReceipt(inv *inventory) *HostReceipt {
	for _, d := range inv.configDirs {
		b, err := os.ReadFile(filepath.Join(d.full, receiptName))
		if err != nil {
			continue
		}
		var r HostReceipt
		if json.Unmarshal(b, &r) == nil {
			return &r
		}
	}
	return nil
}

// install runs check, then teardown, then writes every host resource of
// the install, verifies them from a fresh inventory, and commits the
// receipt.
func (h *hostRun) install(ctx context.Context) error {
	if err := h.check(ctx); err != nil {
		return err
	}
	if err := h.teardown(ctx); err != nil {
		return fmt.Errorf("teardown before install: %w", err)
	}
	if err := h.blockers(ctx); err != nil {
		return err
	}
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"host.write.config", h.writeConfig},
		{"host.write.apparmor", h.writeAppArmor},
		{"host.write.cgroup", h.writeCgroup},
		{"host.write.modules", h.writeModules},
	}
	for _, s := range steps {
		sctx, span := trace.Start(ctx, h.log, s.name)
		err := s.run(sctx)
		span.End(err)
		if err != nil {
			return fmt.Errorf("%s: %w", strings.TrimPrefix(s.name, "host."), err)
		}
	}
	vctx, span := trace.Start(ctx, h.log, "host.verify")
	inv, err := h.inventory(vctx)
	if err == nil {
		err = h.complete(inv)
	}
	span.End(err)
	if err != nil {
		return fmt.Errorf("verify install: %w", err)
	}
	if err := h.writeReceipt(ctx); err != nil {
		return err
	}
	if inv, err = h.inventory(ctx); err != nil {
		return err
	}
	h.report(inv)
	h.res.Installed = h.complete(inv) == nil
	h.res.Receipt = h.readReceipt(inv)
	return nil
}

// blockers refuses an install when an untagged or foreign resource holds a
// name that the install writes.
func (h *hostRun) blockers(ctx context.Context) error {
	var blocked []string
	for _, b := range []struct{ kind, path, show string }{
		{kindCgroup, h.parentCgroup(), h.parentCgroup()},
		{kindAppArmorFile, h.profileFile(), h.hostPath(h.profileFile())},
		{kindModulesLoad, h.modulesFile(), h.hostPath(h.modulesFile())},
		{kindConfigDir, h.configDir(), h.hostPath(h.configDir())},
	} {
		if _, err := os.Lstat(b.path); err == nil {
			blocked = append(blocked, b.show)
			h.conflict(ctx, HostResource{Kind: b.kind, Path: b.show, Detail: "blocks the install"})
		}
	}
	loaded, err := h.sys.loadedProfiles()
	if err != nil {
		return err
	}
	if _, ok := loaded[h.profileName()]; ok {
		blocked = append(blocked, h.profileName())
		h.conflict(ctx, HostResource{Kind: kindAppArmorProfile, Path: h.profileName(),
			Detail: "blocks the install: loaded from a file that this install does not own"})
	}
	if len(blocked) > 0 {
		return fmt.Errorf("resources that this install does not own block it: %s", strings.Join(blocked, ", "))
	}
	return nil
}

// conflict records a resource that vmcp does not touch. A resource is
// listed once; a second reason extends its detail.
func (h *hostRun) conflict(ctx context.Context, r HostResource) {
	i := slices.IndexFunc(h.res.Conflicts, func(c HostResource) bool { return c.Kind == r.Kind && c.Path == r.Path })
	switch {
	case i < 0:
		h.res.Conflicts = append(h.res.Conflicts, r)
	case strings.Contains(h.res.Conflicts[i].Detail, r.Detail):
		return
	default:
		h.res.Conflicts[i].Detail += "; " + r.Detail
	}
	h.log.WarnContext(ctx, "host conflict", "code", "host_conflict", "kind", r.Kind, "path", r.Path, "detail", r.Detail)
}

func (h *hostRun) written(ctx context.Context, kind, path string) {
	r := HostResource{Kind: kind, Path: path, Owner: h.cfg.InstallID}
	h.res.Written = append(h.res.Written, r)
	h.log.InfoContext(ctx, "host resource written", "kind", kind, "path", path)
}

// ownerHeader is the first line of a host text file of this install.
func (h *hostRun) ownerHeader() string { return ownerLine + h.cfg.InstallID + "\n" }

// writeConfig writes the configuration directory: the marker first, then
// the seccomp profile. The receipt comes last, after verification.
func (h *hostRun) writeConfig(ctx context.Context) error {
	if err := os.MkdirAll(h.etc("vmcp"), 0o755); err != nil {
		return err
	}
	dir := h.configDir()
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	h.written(ctx, kindConfigDir, h.hostPath(dir))
	marker := h.ownerHeader() + seccompName + "\n" + receiptName + "\n"
	if err := writeFileExcl(filepath.Join(dir, ownerMarker), []byte(marker)); err != nil {
		return err
	}
	if err := writeFileExcl(filepath.Join(dir, seccompName), seccompProfile); err != nil {
		return err
	}
	h.written(ctx, kindConfigFile, h.hostPath(filepath.Join(dir, seccompName)))
	return nil
}

// writeAppArmor renders, writes, and loads the AppArmor profile.
func (h *hostRun) writeAppArmor(ctx context.Context) error {
	if err := os.MkdirAll(h.etc("apparmor.d"), 0o755); err != nil {
		return err
	}
	f := h.profileFile()
	body := strings.ReplaceAll(apparmorTemplate, installIDToken, h.cfg.InstallID)
	if !strings.HasPrefix(body, h.ownerHeader()) {
		return errors.New("the AppArmor template does not start with its owner line")
	}
	if err := writeFileExcl(f, []byte(body)); err != nil {
		return err
	}
	h.written(ctx, kindAppArmorFile, h.hostPath(f))
	if err := h.sys.loadProfile(f); err != nil {
		return err
	}
	h.written(ctx, kindAppArmorProfile, h.profileName())
	return nil
}

// writeCgroup creates, tags, and delegates the parent cgroup.
func (h *hostRun) writeCgroup(ctx context.Context) error {
	p := h.parentCgroup()
	if err := h.sys.makeCgroup(p); err != nil {
		return fmt.Errorf("create parent cgroup: %w", err)
	}
	if err := h.sys.tagCgroup(p, h.cfg.InstallID); err != nil {
		return err
	}
	h.written(ctx, kindCgroup, p)
	if err := h.sys.enableControllers(p, cgroupControllers); err != nil {
		return fmt.Errorf("enable controllers: %w", err)
	}
	for _, f := range delegatedFiles {
		if err := h.sys.chown(filepath.Join(p, f), h.cfg.ServiceUID, h.cfg.ServiceGID); err != nil {
			return fmt.Errorf("delegate parent cgroup: %w", err)
		}
	}
	return nil
}

// writeModules loads the KVM and TUN modules and keeps them across a host
// boot.
func (h *hostRun) writeModules(ctx context.Context) error {
	kvm, err := h.kvmModule()
	if err != nil {
		return err
	}
	mods := []string{"kvm", kvm, "tun"}
	for _, m := range mods {
		if err := h.sys.loadModule(m); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(h.etc("modules-load.d"), 0o755); err != nil {
		return err
	}
	f := h.modulesFile()
	if err := writeFileExcl(f, []byte(h.ownerHeader()+strings.Join(mods, "\n")+"\n")); err != nil {
		return err
	}
	h.written(ctx, kindModulesLoad, h.hostPath(f))
	return nil
}

func (h *hostRun) writeReceipt(ctx context.Context) error {
	rel, err := BakedRelease()
	if err != nil {
		return err
	}
	r := HostReceipt{Schema: receiptSchema, InstallID: h.cfg.InstallID, Version: h.cfg.Version, Commit: h.cfg.Commit,
		Release: rel.Version, ServiceUID: h.cfg.ServiceUID, ServiceGID: h.cfg.ServiceGID,
		InstalledAt: h.cfg.Now().UTC().Truncate(time.Second)}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(h.configDir(), receiptName)
	if err := writeFileExcl(p, append(b, '\n')); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	h.written(ctx, kindConfigFile, h.hostPath(p))
	return nil
}

// complete returns nil when the inventory holds every resource of a
// complete install in its expected state.
func (h *hostRun) complete(inv *inventory) error {
	var missing []string
	if !slices.ContainsFunc(inv.cgroups, func(c ownedCgroup) bool { return c.full == h.parentCgroup() }) {
		missing = append(missing, "parent cgroup")
	} else if err := h.checkParent(); err != nil {
		missing = append(missing, err.Error())
	}
	if !slices.ContainsFunc(inv.profileFiles, func(f ownedFile) bool { return f.full == h.profileFile() }) {
		missing = append(missing, "AppArmor profile file")
	}
	if mode, ok := inv.loaded[h.profileName()]; !ok || mode != "enforce" {
		missing = append(missing, "AppArmor profile in enforce mode")
	}
	if !slices.ContainsFunc(inv.moduleFiles, func(f ownedFile) bool { return f.full == h.modulesFile() }) {
		missing = append(missing, "kernel module file")
	}
	if !slices.ContainsFunc(inv.configDirs, func(d ownedConfigDir) bool {
		return d.full == h.configDir() && slices.Contains(d.present, seccompName)
	}) {
		missing = append(missing, "seccomp profile")
	}
	if len(missing) > 0 {
		return fmt.Errorf("install is incomplete: %s", strings.Join(missing, ", "))
	}
	return nil
}

// checkParent checks the delegation and the controllers of the parent
// cgroup.
func (h *hostRun) checkParent() error {
	p := h.parentCgroup()
	for _, f := range delegatedFiles {
		uid, gid, err := h.sys.fileOwner(filepath.Join(p, f))
		if err != nil {
			return fmt.Errorf("parent cgroup: %w", err)
		}
		if uid != h.cfg.ServiceUID || gid != h.cfg.ServiceGID {
			return fmt.Errorf("parent cgroup %s is not delegated to %d:%d", filepath.Join(p, f), h.cfg.ServiceUID, h.cfg.ServiceGID)
		}
	}
	b, err := os.ReadFile(filepath.Join(p, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	for _, c := range cgroupControllers {
		if !slices.Contains(strings.Fields(string(b)), c) {
			return fmt.Errorf("parent cgroup does not enable %s", c)
		}
	}
	return nil
}

// writeFileExcl creates a new host file with mode 0644.
func writeFileExcl(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// readOwnerLine returns the install identity of the owner line that starts
// a file, and false when the file has none.
func readOwnerLine(p string) (string, bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, 256)).ReadString('\n')
	if err != nil {
		return "", false
	}
	owner, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), ownerLine)
	if !ok || ValidInstallID(owner) != nil {
		return "", false
	}
	return owner, true
}

// regularFiles lists the regular files of a directory. A missing
// directory has none.
func regularFiles(dir string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, e)
		}
	}
	return out, nil
}
