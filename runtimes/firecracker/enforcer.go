//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

const (
	sweepEvery = time.Second
	// staleAfter makes status not ready when sweeps stop.
	staleAfter = 5 * time.Second
	// nfnlgrpNFTables is the netfilter netlink group for nftables events.
	nfnlgrpNFTables = 7
)

// jailFiles are the regular files and sockets that a jail root may hold.
var jailFiles = map[string]bool{
	"firecracker": true, "firecracker.pid": true, "vmlinux": true, "rootfs.ext4": true,
	"config.bin": true, "config.json": true, "upper.ext4": true, ".vmcp-owner": true,
	"v.sock": true, "v.sock_1024": true, "v.sock_1025": true, "fc.sock": true,
}

// jailDevices are the device nodes that the jailer creates.
var jailDevices = map[string]bool{
	"dev/kvm": true, "dev/net/tun": true, "dev/urandom": true, "dev/userfaultfd": true,
}

// enforcer audits every owned asset and contains violations.
type enforcer struct {
	r       *Runtime
	trigger chan struct{}

	mu       sync.Mutex
	machines map[string]*Machine
	last     time.Time
	inotify  int
	watches  map[int]string
}

func newEnforcer(r *Runtime) *enforcer {
	return &enforcer{r: r, trigger: make(chan struct{}, 1), machines: map[string]*Machine{}, inotify: -1, watches: map[int]string{}}
}

// run sweeps every second and after each owned-asset event.
func (e *enforcer) run(ctx context.Context) {
	for _, start := range []func(context.Context){e.watchNetlink, e.watchNFTables, e.watchFiles} {
		go start(ctx)
	}
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		e.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.trigger:
		}
	}
}

func (e *enforcer) poke() {
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

// healthy reports whether a sweep finished recently.
func (e *enforcer) healthy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.last) < staleAfter
}

func (e *enforcer) add(m *Machine) {
	e.mu.Lock()
	e.machines[m.jailID] = m
	e.mu.Unlock()
	e.watch(m.jailRoot)
	e.watch(filepath.Join(m.jailRoot, "dev"))
}

func (e *enforcer) remove(m *Machine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.machines, m.jailID)
}

func (e *enforcer) known(jailID string) *Machine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.machines[jailID]
}

// sweep checks every owned asset once.
func (e *enforcer) sweep(ctx context.Context) {
	e.sweepCgroups()
	e.sweepJails()
	e.sweepTaps(ctx)
	e.sweepTable(ctx)
	e.mu.Lock()
	e.last = time.Now()
	e.mu.Unlock()
}

func (e *enforcer) violation(m *Machine, what string) {
	m.mu.Lock()
	logCtx := m.traceCtx
	m.mu.Unlock()
	m.log.ErrorContext(logCtx, "enforcer violation", "code", "enforcer_violation", "violation", what)
	m.event(api.Event{Kind: api.EventStep, Step: "enforcer", Status: "failed", Data: []byte(what)})
	m.Kill("enforcer")
}

// stray removes an asset that no live machine owns. A sweep lists assets
// before it reads the live machines, so a machine teardown can remove the
// asset first. stray acts only while the asset exists, and it reports only
// a real removal or a real failure.
func (e *enforcer) stray(kind, name string, exists func() bool, remove func() error) {
	if !exists() {
		return
	}
	err := remove()
	switch {
	case err == nil:
		e.r.cfg.Logger.Warn("enforcer removed stray asset", "code", "enforcer_stray_removed", "kind", kind, "name", name)
	case !exists():
		e.r.cfg.Logger.Debug("stray asset removed by its owner first", "kind", kind, "name", name)
	default:
		e.r.cfg.Logger.Error("enforcer could not remove stray asset", "code", "enforcer_cleanup_failed", "kind", kind,
			"name", name, "error", trace.BoundedError(err))
	}
}

func pathExists(p string) func() bool {
	return func() bool {
		_, err := os.Lstat(p)
		return err == nil
	}
}

// sweepCgroups kills unknown machine cgroups and checks the posture of
// every booted machine.
func (e *enforcer) sweepCgroups() {
	entries, _ := os.ReadDir(e.r.cgroupParent())
	for _, d := range entries {
		if !d.IsDir() {
			continue
		}
		p := filepath.Join(e.r.cgroupParent(), d.Name())
		m := e.known(d.Name())
		if m == nil {
			e.stray("cgroup", d.Name(), pathExists(p), func() error { return errorsJoin(killCgroup(p), removeCgroup(p)) })
			continue
		}
		if !m.postureChecked() {
			continue
		}
		pids, err := cgroupPIDs(p)
		if err != nil {
			continue
		}
		if len(pids) > 1 {
			e.violation(m, fmt.Sprintf("machine cgroup has %d processes, want 1", len(pids)))
			continue
		}
		if _, v, err := postureViolations(p, m.uid); err == nil && len(v) > 0 {
			e.violation(m, v[0])
		}
	}
}

// sweepJails removes unknown jails and checks the files of known ones.
func (e *enforcer) sweepJails() {
	base := filepath.Join(e.r.cfg.JailBase, "firecracker")
	entries, _ := os.ReadDir(base)
	for _, d := range entries {
		m := e.known(d.Name())
		if m == nil {
			jail := filepath.Join(base, d.Name())
			e.stray("jail", d.Name(), pathExists(jail), func() error { return os.RemoveAll(jail) })
			continue
		}
		if what := jailViolation(m.jailRoot, len(m.spec.Spec.Drives)); what != "" {
			e.violation(m, what)
		}
	}
}

// jailViolation returns the first file in a jail root that the jail may not
// hold, or "".
func jailViolation(root string, drives int) string {
	allowed := func(rel string) bool {
		if jailFiles[rel] {
			return true
		}
		for i := range drives {
			if rel == fmt.Sprintf("drive-%d.ext4", i) {
				return true
			}
		}
		return false
	}
	found := ""
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		mode := fi.Mode()
		switch {
		case mode&(fs.ModeSetuid|fs.ModeSetgid) != 0:
			found = "setuid or setgid file " + rel
		case mode&fs.ModeDevice != 0:
			if !jailDevices[rel] {
				found = "unexpected device node " + rel
			}
		case mode.IsDir():
			if rel == "old_root" {
				// The jailer's pivot_root mount point. It briefly holds the
				// old root; never walk into it.
				return filepath.SkipDir
			}
			if rel != "dev" && rel != "dev/net" && rel != "run" {
				found = "unexpected directory " + rel
			}
		case mode.IsRegular(), mode&fs.ModeSocket != 0:
			if !allowed(rel) && !strings.HasPrefix(rel, "run/") {
				found = "unexpected file " + rel
			}
		default:
			found = "unexpected entry " + rel
		}
		return nil
	})
	return found
}

// sweepTaps removes vmcp taps that no live machine owns, and taps that
// gained a master device.
func (e *enforcer) sweepTaps(ctx context.Context) {
	links, err := listLinks(ctx)
	if err != nil {
		return
	}
	e.mu.Lock()
	owned := map[string]*Machine{}
	for _, m := range e.machines {
		if n := m.netInfo(); n != nil {
			owned[n.Tap] = m
		}
	}
	e.mu.Unlock()
	for _, l := range links {
		if !strings.HasPrefix(l.Name, TapPrefix) {
			continue
		}
		m := owned[l.Name]
		if m == nil {
			name := l.Name
			e.stray("tap", name, func() bool { return run(ctx, nil, "ip", "link", "show", "dev", name) == nil },
				func() error { return run(ctx, nil, "ip", "link", "del", "dev", name) })
			continue
		}
		if l.Master != "" {
			e.violation(m, "tap joined master device "+l.Master)
		}
	}
}

type link struct {
	Name   string `json:"ifname"`
	Master string `json:"master"`
}

func listLinks(ctx context.Context) ([]link, error) {
	cmd := exec.CommandContext(ctx, "ip", "-j", "link", "show")
	cmd.Env = []string{toolPath, "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var links []link
	return links, json.Unmarshal(out, &links)
}

// sweepTable restores the vmcp table when its chains changed, and removes
// set elements that no live machine owns.
func (e *enforcer) sweepTable(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", nftTable)
	cmd.Env = []string{toolPath, "LC_ALL=C"}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		// vmcp is stopping. A failed listing is not a changed table.
		return
	}
	if err != nil || chainRuleCount(out) != expectedChainRules {
		attrs := []any{"code", "enforcer_table_restored", "chain_rules", chainRuleCount(out)}
		if err != nil {
			attrs = append(attrs, "error", trace.BoundedError(err))
		}
		e.r.cfg.Logger.Error("enforcer restored the vmcp table", attrs...)
		e.restoreTable(ctx)
		return
	}
	want := map[string]bool{}
	e.mu.Lock()
	for _, m := range e.machines {
		if n := m.netInfo(); n != nil {
			for _, a := range n.Allowed {
				want[fmt.Sprintf("%s|%s|%d", n.Tap, a.Proto, a.Port)] = true
			}
		}
	}
	e.mu.Unlock()
	for _, el := range setElements(out) {
		if !want[el.key()] {
			e.stray("nft element", el.Tap, func() bool { return elementExists(ctx, el) },
				func() error {
					return run(ctx, nil, "nft", "delete", "element", "inet", nftTable, "guest_allow", el.expr())
				})
		}
	}
}

// elementExists reports whether the guest_allow set holds el now.
func elementExists(ctx context.Context, el element) bool {
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", nftTable)
	cmd.Env = []string{toolPath, "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return true
	}
	for _, cur := range setElements(out) {
		if cur.key() == el.key() {
			return true
		}
	}
	return false
}

// expectedChainRules is the rule count of the input and forward chains.
const expectedChainRules = 4

func chainRuleCount(listing []byte) int {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(listing, &doc) != nil {
		return -1
	}
	n := 0
	for _, item := range doc.Nftables {
		if _, ok := item["rule"]; ok {
			n++
		}
	}
	return n
}

type element struct {
	Tap, Guest, Host, Proto string
	Port                    int
}

func (el element) key() string { return fmt.Sprintf("%s|%s|%d", el.Tap, el.Proto, el.Port) }
func (el element) expr() string {
	return fmt.Sprintf(`{ "%s" . %s . %s . %s . %d }`, el.Tap, el.Guest, el.Host, el.Proto, el.Port)
}

// setElements reads the guest_allow elements from a JSON listing.
func setElements(listing []byte) []element {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Name string `json:"name"`
				Elem []any  `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(listing, &doc) != nil {
		return nil
	}
	var out []element
	for _, item := range doc.Nftables {
		if item.Set == nil || item.Set.Name != "guest_allow" {
			continue
		}
		for _, raw := range item.Set.Elem {
			if el, ok := parseElement(raw); ok {
				out = append(out, el)
			}
		}
	}
	return out
}

func parseElement(raw any) (element, bool) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return element{}, false
	}
	if inner, ok := obj["elem"].(map[string]any); ok {
		obj = inner
	}
	concat, ok := obj["concat"].([]any)
	if !ok {
		if v, ok := obj["val"].(map[string]any); ok {
			concat, ok = v["concat"].([]any)
			if !ok {
				return element{}, false
			}
		} else {
			return element{}, false
		}
	}
	if len(concat) != 5 {
		return element{}, false
	}
	s := func(i int) string { v, _ := concat[i].(string); return v }
	port, _ := concat[4].(float64)
	return element{Tap: s(0), Guest: s(1), Host: s(2), Proto: s(3), Port: int(port)}, true
}

// restoreTable recreates the vmcp table and the elements of live machines.
func (e *enforcer) restoreTable(ctx context.Context) {
	if err := setupTable(ctx); err != nil {
		return
	}
	e.mu.Lock()
	ms := make([]*Machine, 0, len(e.machines))
	for _, m := range e.machines {
		ms = append(ms, m)
	}
	e.mu.Unlock()
	for _, m := range ms {
		if n := m.netInfo(); n != nil && len(n.Allowed) > 0 {
			_ = run(ctx, nil, "nft", "add", "element", "inet", nftTable, "guest_allow", n.elements(m.tag))
		}
	}
}

// watchNetlink pokes the enforcer on link, address, and route changes.
func (e *enforcer) watchNetlink(ctx context.Context) {
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE)
	e.watchSocket(ctx, unix.NETLINK_ROUTE, groups)
}

// watchNFTables pokes the enforcer on nftables changes.
func (e *enforcer) watchNFTables(ctx context.Context) {
	e.watchSocket(ctx, unix.NETLINK_NETFILTER, 1<<(nfnlgrpNFTables-1))
}

func (e *enforcer) watchSocket(ctx context.Context, proto int, groups uint32) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return
	}
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		return
	}
	buf := make([]byte, 64<<10)
	for {
		if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil && err != unix.ENOBUFS {
			return
		}
		e.poke()
	}
}

// watchFiles pokes the enforcer on changes in the cgroup parent, the jail
// base, and each jail root.
func (e *enforcer) watchFiles(ctx context.Context) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return
	}
	e.mu.Lock()
	e.inotify = fd
	e.mu.Unlock()
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	_ = os.MkdirAll(filepath.Join(e.r.cfg.JailBase, "firecracker"), 0o700)
	e.watch(e.r.cgroupParent())
	e.watch(filepath.Join(e.r.cfg.JailBase, "firecracker"))
	buf := make([]byte, 64<<10)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
		e.poke()
	}
}

func (e *enforcer) watch(dir string) {
	e.mu.Lock()
	fd := e.inotify
	e.mu.Unlock()
	if fd < 0 {
		return
	}
	mask := uint32(unix.IN_CREATE | unix.IN_ATTRIB | unix.IN_MOVED_TO | unix.IN_DELETE)
	if wd, err := unix.InotifyAddWatch(fd, dir, mask); err == nil {
		e.mu.Lock()
		e.watches[wd] = dir
		e.mu.Unlock()
	}
}

func errorsJoin(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
