//go:build linux

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jaredfolkins/vmcp/internal/trace"
)

// teardown removes every host resource that carries the install tag, from
// any vmcp version, and verifies from a fresh inventory that none is left.
// It never touches an untagged resource or a resource of another install;
// it reports them. It refuses to start while the vmcp service of the
// install runs, and it holds the lock of every owned cgroup until it ends,
// so that the service cannot start meanwhile. It kills every process that
// it finds in an owned cgroup.
func (h *hostRun) teardown(ctx context.Context) error {
	inv, err := h.inventory(ctx)
	if err != nil {
		return err
	}
	// A refused teardown reports what it found.
	h.report(inv)
	tctx, span := trace.Start(ctx, h.log, "host.teardown")
	release, err := h.lockOwned(tctx, inv)
	if err != nil {
		span.End(err)
		return err
	}
	defer release()
	var errs []error
	for _, l := range inv.links {
		if err := h.sys.deleteLink(l); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindLink, l)
	}
	for _, t := range inv.nftTables {
		if err := h.sys.deleteNftTable(t.Family, t.Name); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindNftTable, t.Family+" "+t.Name)
	}
	for _, c := range inv.cgroups {
		if c.blocked {
			errs = append(errs, fmt.Errorf("cgroup %s holds a cgroup of another install", c.full))
			continue
		}
		if err := h.removeCgroupTree(tctx, c); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindCgroup, c.full)
	}
	for _, f := range inv.profileFiles {
		if err := h.removeProfileFile(tctx, inv, f); err != nil {
			errs = append(errs, err)
		}
	}
	for _, p := range inv.orphanProfiles {
		if parent, _, child := strings.Cut(p, "//"); child && slices.Contains(inv.orphanProfiles, parent) {
			continue // A child profile goes with its parent.
		}
		if err := h.sys.removeLoadedProfile(p); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindAppArmorProfile, p)
	}
	for _, f := range inv.moduleFiles {
		if err := os.Remove(f.full); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindModulesLoad, f.show)
	}
	for _, f := range inv.tmpfilesFiles {
		if err := os.Remove(f.full); err != nil {
			errs = append(errs, err)
			continue
		}
		h.removed(tctx, kindTmpfiles, f.show)
	}
	for _, d := range inv.configDirs {
		if err := h.removeConfigDir(tctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	// /etc/vmcp is shared by every install. Remove it only when it is an
	// empty directory.
	if fi, err := os.Lstat(h.etc("vmcp")); err == nil && fi.IsDir() {
		if entries, err := os.ReadDir(h.etc("vmcp")); err == nil && len(entries) == 0 {
			if err := os.Remove(h.etc("vmcp")); err != nil {
				errs = append(errs, err)
			}
		}
	}
	after, err := h.inventory(tctx)
	switch {
	case err != nil:
		errs = append(errs, err)
	default:
		h.report(after)
		if left := after.ownedResources(); len(left) > 0 {
			h.log.ErrorContext(tctx, "host teardown left resources", "code", "host_teardown_incomplete",
				"remaining", len(left), "first_remaining", left[0].Kind+" "+left[0].Path)
			errs = append(errs, fmt.Errorf("teardown left %d resources of install %s", len(left), h.cfg.InstallID))
		}
	}
	err = errors.Join(errs...)
	span.End(err, "removed", len(h.res.Removed), "killed_processes", h.res.KilledProcesses)
	return err
}

// lockOwned takes the lock of every owned cgroup. When a vmcp process holds
// one, it releases the others and refuses: the service of the install
// runs.
func (h *hostRun) lockOwned(ctx context.Context, inv *inventory) (func(), error) {
	var releases []func()
	release := func() {
		for _, r := range releases {
			r()
		}
	}
	var busy []string
	for _, c := range inv.cgroups {
		r, err := h.sys.lockCgroup(c.full)
		switch {
		case errors.Is(err, errCgroupLocked):
			busy = append(busy, c.full)
			h.log.WarnContext(ctx, "host vmcp service runs", "code", "host_service_running", "cgroup", c.full)
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			release()
			return nil, err
		default:
			releases = append(releases, r)
		}
	}
	if len(busy) > 0 {
		release()
		h.res.ServiceRunning = true
		return nil, fmt.Errorf("the vmcp service of install %s runs: a process holds the lock of %s; stop the service first",
			h.cfg.InstallID, strings.Join(busy, ", "))
	}
	// A vmcp version without the lock still watches its parent cgroup.
	// Look again with the locks held, so that no new service starts.
	paths := make([]string, 0, len(inv.cgroups))
	for _, c := range inv.cgroups {
		paths = append(paths, c.full)
	}
	var watchers []cgroupWatcher
	if len(paths) > 0 {
		var err error
		if err = h.sys.hostProcesses(); err == nil {
			watchers, err = h.sys.cgroupWatchers(paths)
		}
		if err != nil {
			release()
			return nil, fmt.Errorf("cannot check for a running vmcp service: %w", err)
		}
	}
	if len(watchers) > 0 {
		release()
		h.res.ServiceRunning = true
		h.res.ServiceProcesses = watcherList(watchers)
		for _, w := range watchers {
			h.log.WarnContext(ctx, "host vmcp service runs", "code", "host_service_running", "cgroup", w.Cgroup,
				"pid", w.PID, "comm", w.Comm)
		}
		return nil, fmt.Errorf("the vmcp service of install %s runs: %s; stop the service first",
			h.cfg.InstallID, strings.Join(h.res.ServiceProcesses, ", "))
	}
	return release, nil
}

func (h *hostRun) removed(ctx context.Context, kind, path string) {
	h.res.Removed = append(h.res.Removed, HostResource{Kind: kind, Path: path, Owner: h.cfg.InstallID})
	h.log.InfoContext(ctx, "host resource removed", "kind", kind, "path", path)
}

// removeCgroupTree kills the processes of an owned cgroup subtree and
// removes its cgroups, children first.
func (h *hostRun) removeCgroupTree(ctx context.Context, c ownedCgroup) error {
	procs := 0
	for _, p := range c.subtree {
		pids, err := h.sys.cgroupProcs(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("list processes of cgroup %s: %w", p, err)
		}
		procs += len(pids)
	}
	if procs > 0 {
		h.log.WarnContext(ctx, "host teardown killed processes", "code", "host_processes_killed",
			"cgroup", c.full, "processes", procs)
		if err := h.sys.killCgroup(c.full); err != nil {
			return err
		}
		h.res.KilledProcesses += procs
	}
	for i := len(c.subtree) - 1; i >= 0; i-- {
		if err := h.sys.removeCgroup(c.subtree[i]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove cgroup %s: %w", c.subtree[i], err)
		}
	}
	return nil
}

// removeProfileFile unloads the loaded profiles of an owned file and
// removes the file.
func (h *hostRun) removeProfileFile(ctx context.Context, inv *inventory, f ownedFile) error {
	var loaded []string
	for _, p := range f.profiles {
		if _, ok := inv.loaded[p]; ok {
			loaded = append(loaded, p)
		}
	}
	if len(loaded) > 0 {
		if err := h.sys.unloadProfile(f.full); err != nil {
			return err
		}
		for _, p := range loaded {
			h.removed(ctx, kindAppArmorProfile, p)
		}
	}
	if err := os.Remove(f.full); err != nil {
		return err
	}
	h.removed(ctx, kindAppArmorFile, f.show)
	return nil
}

// removeConfigDir removes the listed files, the marker, and the directory.
// It refuses a directory that holds an untagged entry and leaves it
// unchanged.
func (h *hostRun) removeConfigDir(ctx context.Context, d ownedConfigDir) error {
	if d.blocked {
		return fmt.Errorf("%s holds files that this install does not own", d.show)
	}
	for _, f := range d.present {
		if err := os.Remove(filepath.Join(d.full, f)); err != nil {
			return err
		}
		h.removed(ctx, kindConfigFile, filepath.Join(d.show, f))
	}
	if err := os.Remove(filepath.Join(d.full, ownerMarker)); err != nil {
		return err
	}
	if err := os.Remove(d.full); err != nil {
		return err
	}
	h.removed(ctx, kindConfigDir, d.show)
	return nil
}
