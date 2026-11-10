//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jaredfolkins/vmcp/internal/trace"
)

// ensure brings the host resources of the install to the state that this
// vmcp version writes. It writes only what is missing or differs, and it
// removes nothing. A second run on an unchanged host changes nothing. It
// does not need the vmcp service to stop, so a one-shot container can run
// it before every start of the service. It refuses a name that an untagged
// resource or another install holds.
func (h *hostRun) ensure(ctx context.Context) error {
	if err := h.check(ctx); err != nil {
		return err
	}
	if err := h.foreign(ctx); err != nil {
		return err
	}
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"host.ensure.config", h.ensureConfig},
		{"host.ensure.apparmor", h.ensureAppArmor},
		{"host.ensure.cgroup", h.ensureCgroup},
		{"host.ensure.tmpfiles", h.ensureTmpfiles},
		{"host.ensure.modules", h.ensureModules},
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
	if err := h.ensureReceipt(ctx); err != nil {
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

// foreign refuses an ensure when a resource that this install does not own
// holds a name that the install writes. Resources of this install pass.
func (h *hostRun) foreign(ctx context.Context) error {
	var blocked []string
	block := func(kind, show string) {
		blocked = append(blocked, show)
		h.conflict(ctx, HostResource{Kind: kind, Path: show, Detail: "blocks the install"})
	}
	if _, err := os.Lstat(h.parentCgroup()); err == nil {
		owner, ok, err := h.sys.cgroupOwner(h.parentCgroup())
		if err != nil {
			return err
		}
		if !ok || owner != h.cfg.InstallID {
			block(kindCgroup, h.parentCgroup())
		}
	}
	for _, f := range []struct{ kind, path string }{
		{kindAppArmorFile, h.profileFile()},
		{kindModulesLoad, h.modulesFile()},
		{kindTmpfiles, h.tmpfilesFile()},
		{kindConfigDir, filepath.Join(h.configDir(), ownerMarker)},
	} {
		target := f.path
		if f.kind == kindConfigDir {
			target = h.configDir()
		}
		if _, err := os.Lstat(target); err != nil {
			continue
		}
		if owner, ok := readOwnerLine(f.path); !ok || owner != h.cfg.InstallID {
			block(f.kind, h.hostPath(target))
		}
	}
	if _, err := os.Lstat(h.profileFile()); err != nil {
		loaded, err := h.sys.loadedProfiles()
		if err != nil {
			return err
		}
		if _, ok := loaded[h.profileName()]; ok {
			blocked = append(blocked, h.profileName())
			h.conflict(ctx, HostResource{Kind: kindAppArmorProfile, Path: h.profileName(),
				Detail: "blocks the install: loaded from a file that this install does not own"})
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("resources that this install does not own block it: %s", strings.Join(blocked, ", "))
	}
	return nil
}

// ensureFile gives a host file its body. It returns true when it wrote
// the file. It replaces a file with another body in one rename.
func (h *hostRun) ensureFile(ctx context.Context, kind, path string, body []byte) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, body) {
		return false, nil
	}
	// A dot file: the AppArmor and systemd loaders skip it.
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".vmcp-new")
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	h.written(ctx, kind, h.hostPath(path))
	return true, nil
}

func (h *hostRun) ensureConfig(ctx context.Context) error {
	dir := h.configDir()
	if err := os.MkdirAll(h.etc("vmcp"), 0o755); err != nil {
		return err
	}
	marker := []byte(h.ownerHeader() + seccompName + "\n" + receiptName + "\n")
	if err := os.Mkdir(dir, 0o755); err == nil {
		h.written(ctx, kindConfigDir, h.hostPath(dir))
		// The marker makes the directory a resource of this install. Do
		// not leave the directory without it.
		if err := writeFileExcl(filepath.Join(dir, ownerMarker), marker); err != nil {
			_ = os.Remove(dir)
			return err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	if _, err := h.ensureFile(ctx, kindConfigFile, filepath.Join(dir, ownerMarker), marker); err != nil {
		return err
	}
	_, err := h.ensureFile(ctx, kindConfigFile, filepath.Join(dir, seccompName), seccompProfile)
	return err
}

func (h *hostRun) ensureAppArmor(ctx context.Context) error {
	if err := os.MkdirAll(h.etc("apparmor.d"), 0o755); err != nil {
		return err
	}
	body := strings.ReplaceAll(apparmorTemplate, installIDToken, h.cfg.InstallID)
	if !strings.HasPrefix(body, h.ownerHeader()) {
		return errors.New("the AppArmor template does not start with its owner line")
	}
	changed, err := h.ensureFile(ctx, kindAppArmorFile, h.profileFile(), []byte(body))
	if err != nil {
		return err
	}
	loaded, err := h.sys.loadedProfiles()
	if err != nil {
		return err
	}
	if !changed && loaded[h.profileName()] == "enforce" {
		return nil
	}
	// The load replaces a loaded profile of the same name in place.
	if err := h.sys.loadProfile(h.profileFile()); err != nil {
		return err
	}
	h.written(ctx, kindAppArmorProfile, h.profileName())
	return nil
}

func (h *hostRun) ensureCgroup(ctx context.Context) error {
	p := h.parentCgroup()
	if _, err := os.Lstat(p); err != nil {
		return h.writeCgroup(ctx)
	}
	if h.checkParent() == nil {
		return nil
	}
	if err := h.delegateCgroup(p); err != nil {
		return err
	}
	h.written(ctx, kindCgroup, p)
	return nil
}

func (h *hostRun) ensureTmpfiles(ctx context.Context) error {
	body, err := h.tmpfilesBody()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.etc("tmpfiles.d"), 0o755); err != nil {
		return err
	}
	_, err = h.ensureFile(ctx, kindTmpfiles, h.tmpfilesFile(), []byte(body))
	return err
}

func (h *hostRun) ensureModules(ctx context.Context) error {
	mods, err := h.modules()
	if err != nil {
		return err
	}
	for _, m := range mods {
		if err := h.sys.loadModule(m); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(h.etc("modules-load.d"), 0o755); err != nil {
		return err
	}
	_, err = h.ensureFile(ctx, kindModulesLoad, h.modulesFile(), []byte(h.ownerHeader()+strings.Join(mods, "\n")+"\n"))
	return err
}

// ensureReceipt writes the receipt when this run changed the host, or when
// the receipt is missing or names another build or service user.
func (h *hostRun) ensureReceipt(ctx context.Context) error {
	want, err := h.receipt()
	if err != nil {
		return err
	}
	p := filepath.Join(h.configDir(), receiptName)
	var have HostReceipt
	if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &have) == nil && len(h.res.Written) == 0 {
		have.InstalledAt = time.Time{}
		same := want
		same.InstalledAt = time.Time{}
		if have == same {
			return nil
		}
	}
	b, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		return err
	}
	if _, err := h.ensureFile(ctx, kindConfigFile, p, append(b, '\n')); err != nil {
		return fmt.Errorf("write receipt: %w", err)
	}
	return nil
}
