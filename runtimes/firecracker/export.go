//go:build linux

package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/internal/trace"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/image"
)

// The writable drives of an ephemeral machine stay readable after a process
// exit, a timeout, an output limit, a stop, and a guest failure. The guest
// agent sends the drive tars only after its process exits. When a guest
// ended without them, vmcp boots a short export guest on the same drive
// images before teardown. The guest kernel mounts the drives and replays
// their journals; the agent sends the tars. The host never mounts or parses
// a guest image.

const (
	// exportMemoryMiB is the memory of the export guest. It runs only the
	// agent.
	exportMemoryMiB = 256
	// exportFirstDriveIndex is the device index of the first export drive:
	// /dev/vdc. The export guest has no upper disk.
	exportFirstDriveIndex = 2
	// exportBaseTimeout bounds the boot and the mounts of the export guest.
	exportBaseTimeout = 60 * time.Second
	// exportMiBPerSecond bounds the time of the tars by the drive sizes. The
	// drive rate limiter allows 32 MiB/s.
	exportMiBPerSecond = 16
)

// exportReasons are the kill reasons that keep the drives. The empty reason
// is a guest that ended by itself. The manager names the reasons. A delete
// discards the drives, a security kill never boots the drives again, and a
// vmcp stop does not wait for an export.
var exportReasons = map[string]bool{"": true, "timeout": true, "output-limit": true, "stopped": true}

// exportResult records one drive export in the machine proof.
type exportResult struct {
	status     string
	exported   int
	missing    int
	teardown   string
	durationMS float64
}

func (e *exportResult) detail() map[string]any {
	return map[string]any{
		"status": e.status, "drives": e.exported, "missing": e.missing,
		"teardown": e.teardown, "duration_ms": e.durationMS,
	}
}

// missingDrives returns the indexes of the writable spec drives that have no
// tar in the machine out directory.
func (m *Machine) missingDrives() []int {
	var missing []int
	for i, d := range m.spec.Spec.Drives {
		if !d.Writable {
			continue
		}
		if _, err := os.Stat(filepath.Join(m.spec.Dir, "out", d.Name+".tar")); err != nil {
			missing = append(missing, i)
		}
	}
	return missing
}

// exportWanted reports whether a machine that ended with killReason keeps
// its drives.
func (m *Machine) exportWanted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.export && m.booted && exportReasons[m.killReason]
}

// exportDrives sends the missing drive tars through an export guest. It
// returns nil when no export was needed.
func (m *Machine) exportDrives(ctx context.Context) *exportResult {
	if !m.exportWanted() {
		return nil
	}
	missing := m.missingDrives()
	if len(missing) == 0 {
		return nil
	}
	m.mu.Lock()
	logCtx := m.traceCtx
	m.mu.Unlock()
	sctx, span := trace.Start(logCtx, m.log, "drive-export")
	start := time.Now()
	m.event(api.Event{Kind: api.EventStep, Step: "drive-export", Status: "running"})
	res := &exportResult{teardown: "destroyed"}
	err := m.runExport(sctx, missing, res)
	left := len(m.missingDrives())
	res.exported, res.missing = len(missing)-left, left
	if err == nil && left > 0 {
		err = fmt.Errorf("%d of %d drives have no tar after the export", left, len(missing))
	}
	res.durationMS = trace.Millis(time.Since(start))
	detail := fmt.Sprintf("%d of %d drives exported", res.exported, len(missing))
	if err != nil {
		res.status = "failed"
		m.log.WarnContext(logCtx, "drive export failed", "code", "drive_export_failed", "error", trace.BoundedError(err),
			"drives", res.exported, "missing", res.missing, "duration_ms", res.durationMS)
		m.event(api.Event{Kind: api.EventStep, Step: "drive-export", Status: "failed", Detail: detail})
	} else {
		res.status = "completed"
		m.log.InfoContext(logCtx, "drives exported", "drives", res.exported, "duration_ms", res.durationMS)
		m.event(api.Event{Kind: api.EventStep, Step: "drive-export", Status: "completed", Detail: detail})
	}
	span.End(err, "status", res.status, "teardown", res.teardown)
	return res
}

// runExport provisions, boots, and waits for the export guest, and records
// its teardown status in res.
func (m *Machine) runExport(ctx context.Context, missing []int, res *exportResult) error {
	exp, err := m.r.provisionExport(ctx, m, missing)
	if err != nil {
		return fmt.Errorf("provision the export guest: %w", err)
	}
	if err := exp.Boot(ctx); err != nil {
		exp.finish(context.Background(), "boot-failed")
		res.teardown = exp.result.Proof.TeardownStatus
		return fmt.Errorf("boot the export guest: %w", err)
	}
	timer := time.NewTimer(exportTimeout(exp.spec.Spec.Drives))
	defer timer.Stop()
	select {
	case <-exp.done:
	case <-timer.C:
		exp.Kill("timeout")
		err = errors.New("the export guest did not end in time")
	}
	select {
	case <-exp.done:
		res.teardown = exp.result.Proof.TeardownStatus
	case <-time.After(killWait):
		res.teardown = "partial"
		err = errors.Join(err, errors.New("the export guest did not stop after its kill"))
	}
	return err
}

// exportTimeout bounds one export: the boot and the mounts, and the tars at
// exportMiBPerSecond.
func exportTimeout(drives []api.Drive) time.Duration {
	var mib int
	for _, d := range drives {
		mib += d.SizeMiB
	}
	return exportBaseTimeout + time.Duration(mib/exportMiBPerSecond)*time.Second
}

// provisionExport builds the jail of the export guest of src: the kernel, the
// image root, and links to the drive images of src that need an export. The
// guest has no network, no upper disk, no files, and no secrets. It has the
// slot and UID of src, so the drive images keep their owner.
func (r *Runtime) provisionExport(ctx context.Context, src *Machine, drives []int) (exp *Machine, err error) {
	ls := machine.Launch{
		ID: src.spec.ID, Slot: src.spec.Slot, Dir: src.spec.Dir, ImageID: src.spec.ImageID,
		Spec: api.MachineSpec{Resources: api.Resources{VCPUs: 1, MemoryMiB: exportMemoryMiB}},
	}
	for _, i := range drives {
		ls.Spec.Drives = append(ls.Spec.Drives, src.spec.Spec.Drives[i])
	}
	exp = &Machine{
		r: r, spec: ls, jailID: src.jailID + "x", uid: src.uid, tag: src.tag, imgMeta: src.imgMeta,
		done: make(chan struct{}), log: src.log.With("phase", "drive-export"), traceCtx: src.traceCtx, export: true,
	}
	exp.jailRoot = filepath.Join(r.cfg.JailBase, "firecracker", exp.jailID, "root")
	exp.cgroup = filepath.Join(r.cgroupParent(), exp.jailID)
	if !r.enf.healthy() {
		return nil, errors.New("the enforcer is not running")
	}
	if _, err := os.Lstat(filepath.Dir(exp.jailRoot)); err == nil {
		return nil, fmt.Errorf("jail %s already exists", exp.jailID)
	}
	r.enf.add(exp)
	defer func() {
		if err != nil {
			exp.teardown(context.Background())
		}
	}()
	steps := []struct {
		name string
		run  func() error
	}{
		{"export.jail", func() error {
			if err := os.MkdirAll(exp.jailRoot, 0o700); err != nil {
				return fmt.Errorf("create jail: %w", err)
			}
			r.enf.watch(exp.jailRoot)
			return writeMarker(filepath.Dir(exp.jailRoot), r.cfg.InstallID)
		}},
		{"export.drives", func() error { return exp.linkExportFiles(src, drives) }},
		{"export.config", exp.writeExportConfigs},
		{"export.vsock", exp.listen},
	}
	for _, step := range steps {
		_, span := trace.Start(ctx, exp.log, step.name)
		err = step.run()
		span.End(err)
		if err != nil {
			return nil, err
		}
	}
	return exp, nil
}

// linkExportFiles links the kernel, the image root, and the drive images of
// src into the export jail. Export drive j is drive drives[j] of src.
func (m *Machine) linkExportFiles(src *Machine, drives []int) error {
	if err := os.Link(m.r.kernelPath(), filepath.Join(m.jailRoot, "vmlinux")); err != nil {
		return fmt.Errorf("link kernel: %w", err)
	}
	if err := os.Link(filepath.Join(m.r.ImageDir(m.spec.ImageID), image.RootFSName), filepath.Join(m.jailRoot, "rootfs.ext4")); err != nil {
		return fmt.Errorf("link image: %w", err)
	}
	for j, i := range drives {
		from := filepath.Join(src.jailRoot, fmt.Sprintf("drive-%d.ext4", i))
		if err := os.Link(from, filepath.Join(m.jailRoot, fmt.Sprintf("drive-%d.ext4", j))); err != nil {
			return fmt.Errorf("link drive %d: %w", i, err)
		}
	}
	return nil
}

// writeExportConfigs writes the agent and Firecracker configurations of the
// export guest. The drives are read-write, so that the guest kernel can
// replay their journals.
func (m *Machine) writeExportConfigs() error {
	cfg := agentproto.Config{Version: agentproto.Version, Export: true}
	drives := []map[string]any{
		{"drive_id": "rootfs", "path_on_host": "/rootfs.ext4", "is_root_device": true, "is_read_only": true},
		{"drive_id": "config", "path_on_host": "/config.bin", "is_root_device": false, "is_read_only": true},
	}
	for j, d := range m.spec.Spec.Drives {
		cfg.Drives = append(cfg.Drives, agentproto.Drive{
			Name: d.Name, Device: fmt.Sprintf("/dev/vd%c", 'a'+exportFirstDriveIndex+j),
			GuestPath: d.GuestPath, Writable: true,
		})
		drives = append(drives, map[string]any{
			"drive_id": fmt.Sprintf("drive%d", j), "path_on_host": fmt.Sprintf("/drive-%d.ext4", j),
			"is_root_device": false, "is_read_only": false,
		})
	}
	raw, err := agentproto.EncodeConfig(cfg)
	if err != nil {
		return err
	}
	if err := m.writeJailFile("config.bin", raw, 0o400); err != nil {
		return err
	}
	for _, d := range drives {
		d["rate_limiter"] = rateLimiter(32<<20, 2000)
	}
	fc := map[string]any{
		"boot-source":    map[string]any{"kernel_image_path": "/vmlinux", "boot_args": guestBootArgs},
		"drives":         drives,
		"machine-config": map[string]any{"vcpu_count": 1, "mem_size_mib": exportMemoryMiB, "smt": false},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": "/v.sock"},
	}
	b, err := json.Marshal(fc)
	if err != nil {
		return err
	}
	return m.writeJailFile("config.json", b, 0o400)
}
