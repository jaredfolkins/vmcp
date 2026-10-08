//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
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

// inventory is what one scan of the host found. It finds owned resources
// by their tags, never by the names that this version writes, so it also
// finds what older versions wrote.
type inventory struct {
	// cgroups are the owned cgroups that are not inside another owned
	// cgroup. Each one owns its subtree.
	cgroups      []ownedCgroup
	profileFiles []ownedFile
	// orphanProfiles are loaded profiles with the install profile name and
	// no owned file.
	orphanProfiles []string
	moduleFiles    []ownedFile
	configDirs     []ownedConfigDir
	links          []string
	loaded         map[string]string
	conflicts      []HostResource
	others         []HostResource
}

type ownedCgroup struct {
	full string
	// subtree lists the cgroup and every cgroup below it, parents first.
	subtree []string
	// blocked is true when a cgroup in the subtree has another tag.
	blocked bool
}

type ownedFile struct {
	full, show string
	// profiles are the profiles that an AppArmor file defines.
	profiles []string
}

type ownedConfigDir struct {
	full, show string
	// listed are the files that the marker names. present are the listed
	// files that exist.
	listed, present []string
	// blocked is true when the directory holds an unlisted entry.
	blocked bool
}

// ownedResources lists the owned resources for a result.
func (inv *inventory) ownedResources() []HostResource {
	out := []HostResource{}
	for _, c := range inv.cgroups {
		d := ""
		if n := len(c.subtree) - 1; n > 0 {
			d = fmt.Sprintf("%d child cgroups", n)
		}
		out = append(out, HostResource{Kind: kindCgroup, Path: c.full, Detail: d})
	}
	for _, f := range inv.profileFiles {
		out = append(out, HostResource{Kind: kindAppArmorFile, Path: f.show})
		for _, p := range f.profiles {
			if mode, ok := inv.loaded[p]; ok {
				out = append(out, HostResource{Kind: kindAppArmorProfile, Path: p, Detail: mode})
			}
		}
	}
	for _, p := range inv.orphanProfiles {
		out = append(out, HostResource{Kind: kindAppArmorProfile, Path: p, Detail: inv.loaded[p] + ", no file"})
	}
	for _, f := range inv.moduleFiles {
		out = append(out, HostResource{Kind: kindModulesLoad, Path: f.show})
	}
	for _, d := range inv.configDirs {
		out = append(out, HostResource{Kind: kindConfigDir, Path: d.show})
		for _, f := range d.present {
			out = append(out, HostResource{Kind: kindConfigFile, Path: filepath.Join(d.show, f)})
		}
	}
	for _, l := range inv.links {
		out = append(out, HostResource{Kind: kindLink, Path: l})
	}
	return out
}

func (inv *inventory) conflict(r HostResource) {
	if !slices.Contains(inv.conflicts, r) {
		inv.conflicts = append(inv.conflicts, r)
	}
}

// inventory scans every place where vmcp writes host resources.
func (h *hostRun) inventory(ctx context.Context) (*inventory, error) {
	_, span := trace.Start(ctx, h.log, "host.inventory")
	inv := &inventory{conflicts: []HostResource{}, others: []HostResource{}}
	var err error
	if inv.loaded, err = h.sys.loadedProfiles(); err != nil {
		span.End(err)
		return nil, err
	}
	for _, scan := range []func(*inventory) error{h.scanCgroups, h.scanAppArmor, h.scanModules, h.scanConfig, h.scanLinks} {
		if err := scan(inv); err != nil {
			span.End(err)
			return nil, err
		}
	}
	for _, c := range inv.conflicts {
		h.conflict(ctx, c)
	}
	span.End(nil, "owned", len(inv.ownedResources()), "conflicts", len(inv.conflicts), "other_installs", len(inv.others))
	return inv, nil
}

// scanCgroups walks the whole cgroup tree. A cgroup with this install tag
// is owned with its subtree. A cgroup with another tag belongs to another
// install with its subtree. An untagged cgroup named like vmcp outside
// every tagged subtree is a conflict.
func (h *hostRun) scanCgroups(inv *inventory) error {
	// tagged is a tagged cgroup. owned is its index in inv.cgroups, or -1
	// for another install.
	type tagged struct {
		path  string
		owned int
	}
	var roots []tagged
	inside := func(p string) (tagged, bool) {
		for i := len(roots) - 1; i >= 0; i-- {
			if strings.HasPrefix(p, roots[i].path+"/") {
				return roots[i], true
			}
		}
		return tagged{}, false
	}
	err := filepath.WalkDir(h.cfg.CgroupRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() || p == h.cfg.CgroupRoot {
			return nil
		}
		owner, isTagged, err := h.sys.cgroupOwner(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		parent, in := inside(p)
		switch {
		case in && parent.owned >= 0:
			c := &inv.cgroups[parent.owned]
			c.subtree = append(c.subtree, p)
			if isTagged && owner != h.cfg.InstallID {
				c.blocked = true
				inv.conflict(HostResource{Kind: kindCgroup, Path: p, Owner: owner,
					Detail: "has another tag inside a cgroup of this install"})
			}
		case isTagged && owner == h.cfg.InstallID:
			roots = append(roots, tagged{p, len(inv.cgroups)})
			inv.cgroups = append(inv.cgroups, ownedCgroup{full: p, subtree: []string{p}})
		case in:
			// A cgroup of another install.
		case isTagged:
			roots = append(roots, tagged{p, -1})
			inv.others = append(inv.others, HostResource{Kind: kindCgroup, Path: p, Owner: owner})
		case strings.HasPrefix(d.Name(), "vmcp"):
			inv.conflict(HostResource{Kind: kindCgroup, Path: p, Detail: "untagged"})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("scan cgroups: %w", err)
	}
	return nil
}

// scanAppArmor finds profile files by their owner line, and a loaded
// profile with the install profile name that no file defines.
func (h *hostRun) scanAppArmor(inv *inventory) error {
	dir := h.etc("apparmor.d")
	files, err := regularFiles(dir)
	if err != nil {
		return fmt.Errorf("scan AppArmor profiles: %w", err)
	}
	defined := map[string]bool{}
	for _, e := range files {
		full := filepath.Join(dir, e.Name())
		show := h.hostPath(full)
		owner, ok := readOwnerLine(full)
		switch {
		case ok && owner == h.cfg.InstallID:
			names, err := h.sys.profileNames(full)
			if err != nil {
				return err
			}
			for _, n := range names {
				defined[n] = true
			}
			inv.profileFiles = append(inv.profileFiles, ownedFile{full: full, show: show, profiles: names})
		case ok:
			inv.others = append(inv.others, HostResource{Kind: kindAppArmorFile, Path: show, Owner: owner})
		case strings.HasPrefix(e.Name(), "vmcp"):
			inv.conflict(HostResource{Kind: kindAppArmorFile, Path: show, Detail: "untagged"})
			// A profile that an untagged file defines is not owned, even
			// with the install profile name.
			names, err := h.sys.profileNames(full)
			if err != nil {
				return err
			}
			for _, n := range names {
				defined[n] = true
			}
		}
	}
	name := h.profileName()
	for p := range inv.loaded {
		if (p == name || strings.HasPrefix(p, name+"//")) && !defined[p] && !defined[strings.Split(p, "//")[0]] {
			inv.orphanProfiles = append(inv.orphanProfiles, p)
		}
	}
	slices.Sort(inv.orphanProfiles)
	return nil
}

// scanModules finds module load files by their owner line.
func (h *hostRun) scanModules(inv *inventory) error {
	dir := h.etc("modules-load.d")
	files, err := regularFiles(dir)
	if err != nil {
		return fmt.Errorf("scan kernel module files: %w", err)
	}
	for _, e := range files {
		full := filepath.Join(dir, e.Name())
		show := h.hostPath(full)
		owner, ok := readOwnerLine(full)
		switch {
		case ok && owner == h.cfg.InstallID:
			inv.moduleFiles = append(inv.moduleFiles, ownedFile{full: full, show: show})
		case ok:
			inv.others = append(inv.others, HostResource{Kind: kindModulesLoad, Path: show, Owner: owner})
		case strings.HasPrefix(e.Name(), "vmcp"):
			inv.conflict(HostResource{Kind: kindModulesLoad, Path: show, Detail: "untagged"})
		}
	}
	return nil
}

// scanConfig finds configuration directories under /etc/vmcp by their
// marker. Every entry of an owned directory must be the marker or a file
// that the marker names.
func (h *hostRun) scanConfig(inv *inventory) error {
	base := h.etc("vmcp")
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan configuration: %w", err)
	}
	for _, e := range entries {
		full := filepath.Join(base, e.Name())
		show := h.hostPath(full)
		if !e.IsDir() {
			inv.conflict(HostResource{Kind: kindConfigFile, Path: show, Detail: "untagged"})
			continue
		}
		owner, listed, ok := readMarker(filepath.Join(full, ownerMarker))
		switch {
		case !ok:
			inv.conflict(HostResource{Kind: kindConfigDir, Path: show, Detail: "untagged: no owner marker"})
			continue
		case owner != h.cfg.InstallID:
			inv.others = append(inv.others, HostResource{Kind: kindConfigDir, Path: show, Owner: owner})
			continue
		}
		d := ownedConfigDir{full: full, show: show, listed: listed}
		files, err := os.ReadDir(full)
		if err != nil {
			return fmt.Errorf("scan configuration: %w", err)
		}
		for _, f := range files {
			switch {
			case f.Name() == ownerMarker:
			case f.Type().IsRegular() && slices.Contains(listed, f.Name()):
				d.present = append(d.present, f.Name())
			default:
				d.blocked = true
				inv.conflict(HostResource{Kind: kindConfigFile, Path: filepath.Join(show, f.Name()),
					Detail: "untagged file in a directory of this install"})
			}
		}
		inv.configDirs = append(inv.configDirs, d)
	}
	return nil
}

// readMarker reads a configuration directory marker.
func readMarker(p string) (owner string, files []string, ok bool) {
	owner, ok = readOwnerLine(p)
	if !ok {
		return "", nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", nil, false
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan()
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name != "" && name == filepath.Base(name) && name != ownerMarker && !strings.HasPrefix(name, ".") {
			files = append(files, name)
		}
	}
	return owner, files, true
}

// scanLinks finds host links by their ifalias tag.
func (h *hostRun) scanLinks(inv *inventory) error {
	links, err := h.sys.links()
	if err != nil {
		return err
	}
	own := "vmcp:" + h.cfg.InstallID + ":"
	for _, l := range links {
		switch {
		case strings.HasPrefix(l.Alias, own):
			inv.links = append(inv.links, l.Name)
		case strings.HasPrefix(l.Alias, "vmcp:"):
			owner, _, _ := strings.Cut(strings.TrimPrefix(l.Alias, "vmcp:"), ":")
			inv.others = append(inv.others, HostResource{Kind: kindLink, Path: l.Name, Owner: owner})
		case strings.HasPrefix(l.Name, TapPrefix):
			inv.conflict(HostResource{Kind: kindLink, Path: l.Name, Detail: "untagged"})
		}
	}
	return nil
}
