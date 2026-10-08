//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jaredfolkins/vmcp/internal/trace"
)

var hostConfig = flag.String("vmcp-host-config", "testdata/host.hujson", "HuJSON file with host command cases")

type hostCase struct {
	Cgroups []struct {
		Path  string `json:"path"`
		Owner string `json:"owner"`
		Procs string `json:"procs"`
		// Locked means that a vmcp process holds the lock of the cgroup.
		Locked bool `json:"locked"`
	} `json:"cgroups"`
	Files               map[string]string `json:"files"`
	LoadedProfiles      map[string]string `json:"loaded_profiles"`
	Links               []hostLink        `json:"links"`
	NftTables           []hostTable       `json:"nft_tables"`
	WantRemoved         []string          `json:"want_removed"`
	WantKilledProcesses int               `json:"want_killed_processes"`
	WantConflicts       []string          `json:"want_conflicts"`
	WantOtherInstalls   []string          `json:"want_other_installs"`
	WantKeptProfiles    []string          `json:"want_kept_profiles"`
}

type logLine struct {
	Msg   string `json:"msg"`
	Level string `json:"level"`
	Code  string `json:"code"`
	Span  string `json:"span"`
}

type hostInput struct {
	InstallID          string   `json:"install_id"`
	Teardown           hostCase `json:"teardown"`
	UntaggedConfigFile hostCase `json:"untagged_config_file"`
	BlockedInstall     hostCase `json:"blocked_install"`
	ServiceRunning     hostCase `json:"service_running"`
	NftRuleset         struct {
		Ruleset string      `json:"ruleset"`
		Want    []hostTable `json:"want"`
	} `json:"nft_ruleset"`
	InstallLog []logLine `json:"install_log"`
	BlockedLog []logLine `json:"blocked_log"`
	// WantTmpfiles are the lines of the tmpfiles.d file of an install, with
	// the token cgroupRootToken for the cgroup root.
	WantTmpfiles      []string `json:"want_tmpfiles"`
	UnsafeCgroupRoots []string `json:"unsafe_cgroup_roots"`
}

// cgroupRootToken stands for the fake cgroup root in want_tmpfiles.
const cgroupRootToken = "@CGROUP_ROOT@"

// fakeHost is a host in temporary directories. Cgroups are directories
// with the files that the kernel creates; tags, profiles, modules, and
// links are in memory.
type fakeHost struct {
	t        *testing.T
	cgroups  string
	tags     map[string]string
	owners   map[string][2]int
	profiles map[string]string
	modules  []string
	linkList []hostLink
	tables   []hostTable
	locked   map[string]bool
	kills    []string
}

var cgroupFiles = []string{"cgroup.procs", "cgroup.subtree_control", "cgroup.threads", "cgroup.controllers"}

func (f *fakeHost) euid() int { return 0 }

func (f *fakeHost) fileOwner(path string) (int, int, error) {
	if o, ok := f.owners[path]; ok {
		return o[0], o[1], nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid), nil
}

func (f *fakeHost) cgroupOwner(path string) (string, bool, error) {
	o, ok := f.tags[path]
	return o, ok, nil
}

func (f *fakeHost) tagCgroup(path, owner string) error {
	f.tags[path] = owner
	return nil
}

func (f *fakeHost) makeCgroup(path string) error {
	if err := os.Mkdir(path, 0o755); err != nil {
		return err
	}
	for _, n := range cgroupFiles {
		if err := os.WriteFile(filepath.Join(path, n), nil, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeHost) enableControllers(path string, controllers []string) error {
	return os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte(strings.Join(controllers, " ")+"\n"), 0o644)
}

func (f *fakeHost) chown(path string, uid, gid int) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	f.owners[path] = [2]int{uid, gid}
	return nil
}

func (f *fakeHost) cgroupProcs(path string) ([]int, error) { return cgroupPIDs(path) }

func (f *fakeHost) killCgroup(path string) error {
	f.kills = append(f.kills, path)
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return os.WriteFile(filepath.Join(p, "cgroup.procs"), nil, 0o644)
	})
}

// removeCgroup fails like rmdir on cgroupfs: with processes or children.
func (f *fakeHost) removeCgroup(path string) error {
	if pids, _ := cgroupPIDs(path); len(pids) > 0 {
		return syscall.EBUSY
	}
	for _, n := range cgroupFiles {
		_ = os.Remove(filepath.Join(path, n))
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	delete(f.tags, path)
	return nil
}

func (f *fakeHost) loadedProfiles() (map[string]string, error) { return maps(f.profiles), nil }

var profileRE = regexp.MustCompile(`(?m)^\s*profile\s+(\S+)`)

func (f *fakeHost) profileNames(file string) ([]string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, m := range profileRE.FindAllStringSubmatch(string(b), -1) {
		names = append(names, m[1])
	}
	return names, nil
}

func (f *fakeHost) loadProfile(file string) error {
	names, err := f.profileNames(file)
	for _, n := range names {
		f.profiles[n] = "enforce"
	}
	return err
}

func (f *fakeHost) unloadProfile(file string) error {
	names, err := f.profileNames(file)
	for _, n := range names {
		if _, ok := f.profiles[n]; !ok {
			return errors.New("profile is not loaded")
		}
		delete(f.profiles, n)
	}
	return err
}

func (f *fakeHost) removeLoadedProfile(name string) error {
	for p := range f.profiles {
		if p == name || strings.HasPrefix(p, name+"//") {
			delete(f.profiles, p)
		}
	}
	return nil
}

func (f *fakeHost) loadModule(name string) error {
	f.modules = append(f.modules, name)
	return nil
}

func (f *fakeHost) links() ([]hostLink, error) { return slices.Clone(f.linkList), nil }

func (f *fakeHost) deleteLink(name string) error {
	f.linkList = slices.DeleteFunc(f.linkList, func(l hostLink) bool { return l.Name == name })
	return nil
}

func (f *fakeHost) lockCgroup(path string) (func(), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	if f.locked[path] {
		return nil, errCgroupLocked
	}
	return func() {}, nil
}

func (f *fakeHost) nftTables() ([]hostTable, error) { return slices.Clone(f.tables), nil }

func (f *fakeHost) deleteNftTable(family, name string) error {
	f.tables = slices.DeleteFunc(f.tables, func(t hostTable) bool { return t.Family == family && t.Name == name })
	return nil
}

func maps(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// newFakeHost builds a host with the cgroup root, a CPU with vmx, and the
// resources of tc. It returns the host and a config for install id.
func newFakeHost(t *testing.T, id string, tc hostCase, log *slog.Logger) (*fakeHost, HostConfig) {
	t.Helper()
	dir := t.TempDir()
	f := &fakeHost{t: t, cgroups: filepath.Join(dir, "cgroup"), tags: map[string]string{}, owners: map[string][2]int{},
		profiles: maps(tc.LoadedProfiles), linkList: slices.Clone(tc.Links), tables: slices.Clone(tc.NftTables),
		locked: map[string]bool{}}
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(f.cgroups, "cgroup.controllers"), "cpuset cpu io memory pids\n")
	write(filepath.Join(f.cgroups, "cgroup.subtree_control"), "cpu io memory pids\n")
	write(filepath.Join(dir, "cpuinfo"), "processor\t: 0\nflags\t\t: fpu vme vmx sse\n")
	if err := os.MkdirAll(filepath.Join(dir, "host", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range tc.Cgroups {
		p := filepath.Join(f.cgroups, c.Path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := f.makeCgroup(p); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(p, "cgroup.procs"), c.Procs)
		if c.Owner != "" {
			f.tags[p] = c.Owner
		}
		f.locked[p] = c.Locked
	}
	for name, body := range tc.Files {
		write(filepath.Join(dir, "host", name), body)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return f, HostConfig{
		InstallID: id, HostRoot: filepath.Join(dir, "host"), CgroupRoot: f.cgroups, SecurityFS: filepath.Join(dir, "securityfs"),
		CPUInfo: filepath.Join(dir, "cpuinfo"), ServiceUID: 65532, ServiceGID: 65532, Version: "test", Commit: "0123abc",
		Logger: log, Now: func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }, sys: f,
	}
}

// keys turns resources into "kind path" strings, with cgroup paths
// relative to the fake cgroup root.
func keys(cfg HostConfig, rs []HostResource) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		p := r.Path
		if r.Kind == kindCgroup {
			p = strings.TrimPrefix(p, cfg.CgroupRoot+"/")
		}
		out = append(out, r.Kind+" "+p)
	}
	slices.Sort(out)
	return out
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	if s == nil {
		s = []string{}
	}
	return s
}

func readHostInput(t *testing.T) hostInput {
	t.Helper()
	var in hostInput
	readHuJSON(t, *hostConfig, &in)
	if in.InstallID == "" || len(in.Teardown.WantRemoved) == 0 {
		t.Fatal("host input has no teardown case")
	}
	return in
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// TestHostTeardownRemovesOnlyTaggedResources proves that teardown finds the
// resources of an install by their tags, so it also removes what older
// versions wrote under other names and depths, and that it never touches
// an untagged look-alike or a resource of another install. It detects a
// teardown that computes today's names, or that deletes by name prefix.
func TestHostTeardownRemovesOnlyTaggedResources(t *testing.T) {
	in := readHostInput(t)
	tc := in.Teardown
	f, cfg := newFakeHost(t, in.InstallID, tc, nil)
	before := map[string]string{}
	for name, body := range tc.Files {
		before[name] = body
	}

	res := RunHostCommand(context.Background(), "teardown", cfg)
	if !res.OK {
		t.Fatalf("teardown failed: %s", res.Error)
	}
	if got, want := keys(cfg, res.Removed), sorted(tc.WantRemoved); !slices.Equal(got, want) {
		t.Errorf("removed:\n got %q\nwant %q", got, want)
	}
	if res.KilledProcesses != tc.WantKilledProcesses {
		t.Errorf("killed_processes = %d, want %d", res.KilledProcesses, tc.WantKilledProcesses)
	}
	if got, want := keys(cfg, res.Conflicts), sorted(tc.WantConflicts); !slices.Equal(got, want) {
		t.Errorf("conflicts:\n got %q\nwant %q", got, want)
	}
	if got, want := keys(cfg, res.OtherInstalls), sorted(tc.WantOtherInstalls); !slices.Equal(got, want) {
		t.Errorf("other_installs:\n got %q\nwant %q", got, want)
	}
	if len(res.Owned) != 0 {
		t.Errorf("owned after teardown = %+v, want none", res.Owned)
	}
	for name, body := range before {
		removed := false
		for _, r := range tc.WantRemoved {
			kind, path, _ := strings.Cut(r, " ")
			if kind != kindCgroup && kind != kindLink && kind != kindNftTable && strings.HasPrefix("/"+name, path) {
				removed = true
			}
		}
		got, err := os.ReadFile(filepath.Join(cfg.HostRoot, name))
		switch {
		case removed && err == nil:
			t.Errorf("tagged file /%s remains", name)
		case !removed && (err != nil || string(got) != body):
			t.Errorf("untouched file /%s changed or is gone: %v", name, err)
		}
	}
	for _, c := range tc.Cgroups {
		owned := false
		for _, r := range tc.WantRemoved {
			if kind, path, _ := strings.Cut(r, " "); kind == kindCgroup && (c.Path == path || strings.HasPrefix(c.Path, path+"/")) {
				owned = true
			}
		}
		if p := filepath.Join(cfg.CgroupRoot, c.Path); exists(p) == owned {
			t.Errorf("cgroup %s exists = %t, want %t", c.Path, exists(p), !owned)
		}
	}
	for _, p := range tc.WantKeptProfiles {
		if _, ok := f.profiles[p]; !ok {
			t.Errorf("profile %s was unloaded; it is not owned", p)
		}
	}
	if len(f.profiles) != len(tc.WantKeptProfiles) {
		t.Errorf("loaded profiles after teardown = %v, want only %v", f.profiles, tc.WantKeptProfiles)
	}
	for _, l := range tc.Links {
		gone := !slices.ContainsFunc(f.linkList, func(h hostLink) bool { return h.Name == l.Name })
		if want := slices.Contains(tc.WantRemoved, "link "+l.Name); gone != want {
			t.Errorf("link %s removed = %t, want %t", l.Name, gone, want)
		}
	}
	for _, tb := range tc.NftTables {
		gone := !slices.Contains(f.tables, tb)
		if want := slices.Contains(tc.WantRemoved, kindNftTable+" "+tb.Family+" "+tb.Name); gone != want {
			t.Errorf("nft table %s %s removed = %t, want %t", tb.Family, tb.Name, gone, want)
		}
	}
	if exists(filepath.Join(cfg.HostRoot, "etc", "vmcp", in.InstallID)) {
		t.Error("the configuration directory of the install remains")
	}
}

// TestHostTeardownRefusesUntaggedConfigFile proves that teardown refuses
// an owned configuration directory that holds a file that vmcp did not
// write, leaves the whole directory unchanged, and reports the file.
func TestHostTeardownRefusesUntaggedConfigFile(t *testing.T) {
	in := readHostInput(t)
	tc := in.UntaggedConfigFile
	_, cfg := newFakeHost(t, in.InstallID, tc, nil)
	res := RunHostCommand(context.Background(), "teardown", cfg)
	if res.OK {
		t.Fatal("teardown OK with an untagged file in an owned directory, want a refusal")
	}
	if got, want := keys(cfg, res.Conflicts), sorted(tc.WantConflicts); !slices.Equal(got, want) {
		t.Errorf("conflicts:\n got %q\nwant %q", got, want)
	}
	for name, body := range tc.Files {
		if got, err := os.ReadFile(filepath.Join(cfg.HostRoot, name)); err != nil || string(got) != body {
			t.Errorf("file /%s changed or is gone: %v", name, err)
		}
	}
}

// TestHostInstallIsIdempotent proves that install writes every tagged
// resource, that a second install tears the first one down and writes it
// again, and that teardown then leaves nothing of the install.
func TestHostInstallIsIdempotent(t *testing.T) {
	in := readHostInput(t)
	f, cfg := newFakeHost(t, in.InstallID, hostCase{}, nil)
	ctx := context.Background()
	first := RunHostCommand(ctx, "install", cfg)
	if !first.OK || !first.Installed {
		t.Fatalf("install: ok %t installed %t error %q", first.OK, first.Installed, first.Error)
	}
	checkInstalled(t, f, cfg)
	checkTmpfiles(t, cfg, in.WantTmpfiles)

	second := RunHostCommand(ctx, "install", cfg)
	if !second.OK || !second.Installed {
		t.Fatalf("second install: ok %t installed %t error %q", second.OK, second.Installed, second.Error)
	}
	if got, want := keys(cfg, second.Removed), keys(cfg, first.Owned); !slices.Equal(withoutLoaded(got), withoutLoaded(want)) {
		t.Errorf("second install removed %q, want the first install %q", got, want)
	}
	if got, want := keys(cfg, second.Owned), keys(cfg, first.Owned); !slices.Equal(got, want) {
		t.Errorf("second install owns %q, want %q", got, want)
	}
	checkInstalled(t, f, cfg)

	status := RunHostCommand(ctx, "status", cfg)
	if !status.OK || !status.Installed || status.Receipt == nil || status.Receipt.InstallID != in.InstallID {
		t.Errorf("status = ok %t installed %t receipt %+v, want an installed receipt", status.OK, status.Installed, status.Receipt)
	}

	down := RunHostCommand(ctx, "teardown", cfg)
	if !down.OK || len(down.Owned) != 0 {
		t.Fatalf("teardown: ok %t error %q owned %+v", down.OK, down.Error, down.Owned)
	}
	for _, p := range []string{filepath.Join(cfg.HostRoot, "etc", "vmcp"), filepath.Join(cfg.CgroupRoot, "vmcp-"+in.InstallID),
		filepath.Join(cfg.HostRoot, "etc", "apparmor.d", "vmcp-"+in.InstallID),
		filepath.Join(cfg.HostRoot, "etc", "modules-load.d", "vmcp-"+in.InstallID+".conf"),
		filepath.Join(cfg.HostRoot, "etc", "tmpfiles.d", "vmcp-"+in.InstallID+".conf")} {
		if exists(p) {
			t.Errorf("%s remains after teardown", p)
		}
	}
	if len(f.profiles) != 0 {
		t.Errorf("profiles loaded after teardown: %v", f.profiles)
	}
}

// withoutLoaded drops the loaded profile entry. An install lists the
// profile as owned; teardown reports its unload as a removal too.
func withoutLoaded(s []string) []string {
	return slices.DeleteFunc(slices.Clone(s), func(v string) bool { return strings.HasPrefix(v, kindAppArmorProfile+" ") })
}

// checkInstalled checks every resource of an install on the fake host.
func checkInstalled(t *testing.T, f *fakeHost, cfg HostConfig) {
	t.Helper()
	id := cfg.InstallID
	etc := filepath.Join(cfg.HostRoot, "etc")
	header := ownerLine + id + "\n"
	for _, p := range []string{filepath.Join(etc, "apparmor.d", "vmcp-"+id), filepath.Join(etc, "modules-load.d", "vmcp-"+id+".conf"),
		filepath.Join(etc, "tmpfiles.d", "vmcp-"+id+".conf"), filepath.Join(etc, "vmcp", id, ownerMarker)} {
		b, err := os.ReadFile(p)
		if err != nil || !strings.HasPrefix(string(b), header) {
			t.Errorf("%s does not start with the owner line %q: %v", p, header, err)
		}
	}
	profile, _ := os.ReadFile(filepath.Join(etc, "apparmor.d", "vmcp-"+id))
	if strings.Contains(string(profile), installIDToken) || !strings.Contains(string(profile), "profile vmcp-"+id+" ") {
		t.Errorf("AppArmor profile is not rendered for %s", id)
	}
	if mode := f.profiles["vmcp-"+id]; mode != "enforce" {
		t.Errorf("profile vmcp-%s mode %q, want enforce", id, mode)
	}
	if b, _ := os.ReadFile(filepath.Join(etc, "vmcp", id, seccompName)); !bytes.Equal(b, seccompProfile) {
		t.Error("seccomp.json is not the baked seccomp profile")
	}
	var r HostReceipt
	if b, err := os.ReadFile(filepath.Join(etc, "vmcp", id, receiptName)); err != nil || json.Unmarshal(b, &r) != nil {
		t.Errorf("read receipt: %v", err)
	}
	if r.Schema != receiptSchema || r.InstallID != id || r.Commit != cfg.Commit || r.ServiceUID != cfg.ServiceUID || r.Release == "" {
		t.Errorf("receipt = %+v", r)
	}
	parent := filepath.Join(cfg.CgroupRoot, "vmcp-"+id)
	if f.tags[parent] != id {
		t.Errorf("parent cgroup tag = %q, want %q", f.tags[parent], id)
	}
	for _, n := range delegatedFiles {
		if o := f.owners[filepath.Join(parent, n)]; o != [2]int{cfg.ServiceUID, cfg.ServiceGID} {
			t.Errorf("parent cgroup %q owner = %v, want %d:%d", n, o, cfg.ServiceUID, cfg.ServiceGID)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control")); strings.Join(strings.Fields(string(b)), " ") != "cpu memory pids" {
		t.Errorf("parent controllers = %q, want cpu memory pids", b)
	}
	if mods := f.modules[len(f.modules)-3:]; !slices.Equal(mods, []string{"kvm", "kvm_intel", "tun"}) {
		t.Errorf("loaded modules = %q, want kvm, kvm_intel, tun", mods)
	}
}

// checkTmpfiles compares the tmpfiles.d file of an install with the
// wanted lines. A difference means that the host would not create the
// parent cgroup at boot as install creates it.
func checkTmpfiles(t *testing.T, cfg HostConfig, want []string) {
	t.Helper()
	if len(want) == 0 {
		t.Fatal("host input has no want_tmpfiles")
	}
	b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "etc", "tmpfiles.d", "vmcp-"+cfg.InstallID+".conf"))
	if err != nil {
		t.Fatalf("read tmpfiles.d file: %v", err)
	}
	wantBody := strings.ReplaceAll(strings.Join(want, "\n")+"\n", cgroupRootToken, cfg.CgroupRoot)
	if got := string(b); got != wantBody {
		t.Errorf("tmpfiles.d file:\n got %q\nwant %q", got, wantBody)
	}
}

// TestHostStatusNeedsTmpfiles proves that an install without its
// tmpfiles.d file is not complete, because the parent cgroup would be gone
// after the next host boot.
func TestHostStatusNeedsTmpfiles(t *testing.T) {
	in := readHostInput(t)
	_, cfg := newFakeHost(t, in.InstallID, hostCase{}, nil)
	ctx := context.Background()
	if res := RunHostCommand(ctx, "install", cfg); !res.OK {
		t.Fatalf("install: %s", res.Error)
	}
	if err := os.Remove(filepath.Join(cfg.HostRoot, "etc", "tmpfiles.d", "vmcp-"+in.InstallID+".conf")); err != nil {
		t.Fatal(err)
	}
	status := RunHostCommand(ctx, "status", cfg)
	if !status.OK || status.Installed {
		t.Errorf("status without the tmpfiles.d file = ok %t installed %t, want ok and not installed", status.OK, status.Installed)
	}
}

// TestHostTmpfilesRefusesUnsafePath proves that install does not write a
// tmpfiles.d line for a cgroup path with whitespace, an escape, a
// specifier, or a glob. systemd-tmpfiles would read such a line as another
// path, or as a glob that changes the owner of other cgroups at boot.
func TestHostTmpfilesRefusesUnsafePath(t *testing.T) {
	in := readHostInput(t)
	if len(in.UnsafeCgroupRoots) == 0 {
		t.Fatal("host input has no unsafe_cgroup_roots")
	}
	for _, root := range in.UnsafeCgroupRoots {
		h := &hostRun{cfg: HostConfig{InstallID: in.InstallID, CgroupRoot: root, ServiceUID: 65532, ServiceGID: 65532}}
		if body, err := h.tmpfilesBody(); err == nil {
			t.Errorf("tmpfilesBody with cgroup root %q = %q, want an error", root, body)
		}
	}
}

// TestHostInstallRefusesUntaggedNames proves that install refuses to start
// when an untagged resource holds a name that it writes, writes nothing,
// and reports each one.
func TestHostInstallRefusesUntaggedNames(t *testing.T) {
	in := readHostInput(t)
	tc := in.BlockedInstall
	_, cfg := newFakeHost(t, in.InstallID, tc, nil)
	res := RunHostCommand(context.Background(), "install", cfg)
	if res.OK || len(res.Written) != 0 || len(res.Removed) != 0 {
		t.Fatalf("install: ok %t written %+v removed %+v, want a refusal with no change", res.OK, res.Written, res.Removed)
	}
	if got, want := keys(cfg, res.Conflicts), sorted(tc.WantConflicts); !slices.Equal(got, want) {
		t.Errorf("conflicts:\n got %q\nwant %q", got, want)
	}
	if exists(filepath.Join(cfg.HostRoot, "etc", "vmcp")) {
		t.Error("install wrote /etc/vmcp after a refusal")
	}
}

// TestHostCommandLog proves the log of the install flow and of its main
// failure: the levels, the codes, the install_op attribute, and one trace
// for every line of a command.
func TestHostCommandLog(t *testing.T) {
	in := readHostInput(t)
	for _, tc := range []struct {
		name string
		host hostCase
		want []logLine
	}{
		{"install", hostCase{}, in.InstallLog},
		{"blocked install", in.BlockedInstall, in.BlockedLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(traceHandler(&buf))
			_, cfg := newFakeHost(t, in.InstallID, tc.host, log)
			RunHostCommand(context.Background(), "install", cfg)
			var lines []map[string]any
			sc := bufio.NewScanner(&buf)
			for sc.Scan() {
				var m map[string]any
				if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
					t.Fatalf("log line is not JSON: %s", sc.Text())
				}
				lines = append(lines, m)
			}
			traceID, _ := lines[0]["trace_id"].(string)
			for _, l := range lines {
				if l["install_op"] != "install" || l["trace_id"] != traceID || traceID == "" {
					t.Errorf("line %v lacks install_op install or the command trace %s", l, traceID)
				}
				if lvl := l["level"]; (lvl == "WARN" || lvl == "ERROR") && l["code"] == nil {
					t.Errorf("%s line without code: %v", lvl, l)
				}
			}
			for _, w := range tc.want {
				if !slices.ContainsFunc(lines, func(l map[string]any) bool {
					return l["msg"] == w.Msg && l["level"] == w.Level && (w.Code == "" || l["code"] == w.Code) &&
						(w.Span == "" || l["span"] == w.Span)
				}) {
					t.Errorf("no log line %+v", w)
				}
			}
		})
	}
}

// traceHandler is the vmcp log handler at DEBUG.
func traceHandler(w io.Writer) slog.Handler {
	return trace.NewHandler(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestHostRefusesWhileServiceRuns proves that teardown and install refuse
// to start while a vmcp process holds the lock of an owned cgroup, change
// nothing, and report the running service. Without the lock, teardown
// removed the parent cgroup and the profile of a running service whose
// machine cgroups were empty.
func TestHostRefusesWhileServiceRuns(t *testing.T) {
	in := readHostInput(t)
	tc := in.ServiceRunning
	if len(tc.Cgroups) == 0 {
		t.Fatal("host input has no service_running case")
	}
	for _, command := range []string{"teardown", "install"} {
		f, cfg := newFakeHost(t, in.InstallID, tc, nil)
		res := RunHostCommand(context.Background(), command, cfg)
		if res.OK || !res.ServiceRunning || len(res.Removed) != 0 || len(res.Written) != 0 || len(res.Owned) == 0 {
			t.Errorf("%s: ok %t service_running %t removed %d written %d owned %d, want a refusal with no change that reports the owned resources",
				command, res.OK, res.ServiceRunning, len(res.Removed), len(res.Written), len(res.Owned))
		}
		for name, body := range tc.Files {
			if got, err := os.ReadFile(filepath.Join(cfg.HostRoot, name)); err != nil || string(got) != body {
				t.Errorf("%s: file /%s changed or is gone: %v", command, name, err)
			}
		}
		for _, c := range tc.Cgroups {
			if !exists(filepath.Join(cfg.CgroupRoot, c.Path)) {
				t.Errorf("%s: cgroup %s is gone", command, c.Path)
			}
		}
		if len(f.profiles) != len(tc.LoadedProfiles) {
			t.Errorf("%s: loaded profiles = %v, want %v", command, f.profiles, tc.LoadedProfiles)
		}
	}
	_, cfg := newFakeHost(t, in.InstallID, tc, nil)
	if st := RunHostCommand(context.Background(), "status", cfg); !st.OK || !st.ServiceRunning {
		t.Errorf("status: ok %t service_running %t, want ok and a running service", st.OK, st.ServiceRunning)
	}
}

// TestParseNftTables proves that the table comment comes from the table
// block and not from a set, chain, or rule in it. A wrong parse would tag
// or miss the vmcp table of an install.
func TestParseNftTables(t *testing.T) {
	in := readHostInput(t)
	if in.NftRuleset.Ruleset == "" {
		t.Fatal("host input has no nft_ruleset")
	}
	if got := parseNftTables([]byte(in.NftRuleset.Ruleset)); !slices.Equal(got, in.NftRuleset.Want) {
		t.Errorf("parseNftTables() = %+v, want %+v", got, in.NftRuleset.Want)
	}
}
