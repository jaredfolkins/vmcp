//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/internal/trace"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

var driveExportConfig = flag.String("vmcp-drive-export-config", "testdata/drive-export.hujson", "HuJSON file with the drive export cases")

type driveExportInput struct {
	KeepReasons        []string    `json:"keep_reasons"`
	DropReasons        []string    `json:"drop_reasons"`
	Drives             []api.Drive `json:"drives"`
	Tars               []string    `json:"tars"`
	WantMissing        []int       `json:"want_missing"`
	WantDevices        []string    `json:"want_devices"`
	WantTimeoutSeconds int         `json:"want_timeout_seconds"`
	FailureCode        string      `json:"failure_code"`
}

func readDriveExportInput(t *testing.T) driveExportInput {
	t.Helper()
	var in driveExportInput
	readHuJSON(t, *driveExportConfig, &in)
	if len(in.KeepReasons) == 0 || len(in.DropReasons) == 0 || len(in.Drives) == 0 || len(in.WantMissing) == 0 ||
		len(in.WantDevices) == 0 || in.WantTimeoutSeconds == 0 || in.FailureCode == "" {
		t.Fatal("drive export input is incomplete")
	}
	return in
}

// TestDriveExportFollowsTheKillReason proves that a booted machine exports
// its drives after a guest end, a timeout, an output limit, or a stop, and
// never after a delete, a vmcp stop, a security kill, or a failed boot. It
// detects an export that boots the drives of a guest that a security
// control killed, and a lost export after a stop.
func TestDriveExportFollowsTheKillReason(t *testing.T) {
	in := readDriveExportInput(t)
	for _, reason := range in.KeepReasons {
		m := &Machine{booted: true, killReason: reason}
		if !m.exportWanted() {
			t.Errorf("kill reason %q: exportWanted() = false, want true", reason)
		}
		m.export = true
		if m.exportWanted() {
			t.Errorf("kill reason %q: an export guest wants its own export", reason)
		}
		if (&Machine{killReason: reason}).exportWanted() {
			t.Errorf("kill reason %q: a machine that never booted wants an export", reason)
		}
	}
	for _, reason := range in.DropReasons {
		if (&Machine{booted: true, killReason: reason}).exportWanted() {
			t.Errorf("kill reason %q: exportWanted() = true, want false", reason)
		}
	}
}

// TestDriveExportGuestConfig proves the export plan of a machine that ended
// without some drive tars: only the writable drives without a tar are
// exported, the export guest gets them read-write from /dev/vdc on, it runs
// no process and has no network, files, or DNS, and its time bound grows
// with the drive sizes. It detects an export that sends a drive twice, a
// guest that runs the caller process again, and a guest with a network.
func TestDriveExportGuestConfig(t *testing.T) {
	in := readDriveExportInput(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range in.Tars {
		if err := os.WriteFile(filepath.Join(dir, "out", name+".tar"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	src := &Machine{spec: machine.Launch{Dir: dir, Spec: api.MachineSpec{Drives: in.Drives}}}
	missing := src.missingDrives()
	if !slices.Equal(missing, in.WantMissing) {
		t.Fatalf("missingDrives() = %v, want %v", missing, in.WantMissing)
	}

	exp := &Machine{jailRoot: t.TempDir(), uid: os.Getuid(), export: true}
	for _, i := range missing {
		exp.spec.Spec.Drives = append(exp.spec.Spec.Drives, in.Drives[i])
	}
	if err := exp.writeExportConfigs(); err != nil {
		t.Fatalf("writeExportConfigs() error = %v", err)
	}
	f, err := os.Open(filepath.Join(exp.jailRoot, "config.bin"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := agentproto.DecodeConfig(bufio.NewReader(f))
	_ = f.Close()
	if err != nil {
		t.Fatalf("DecodeConfig() error = %v", err)
	}
	if !cfg.Export || len(cfg.Args) != 0 || len(cfg.Env) != 0 || len(cfg.Files) != 0 || cfg.DNS != "" {
		t.Errorf("agent config = %+v, want an export with no process, files, or DNS", cfg)
	}
	var devices []string
	for j, d := range cfg.Drives {
		devices = append(devices, d.Device)
		want := in.Drives[missing[j]]
		if d.Name != want.Name || d.GuestPath != want.GuestPath || !d.Writable {
			t.Errorf("export drive %d = %+v, want %s at %s, writable", j, d, want.Name, want.GuestPath)
		}
	}
	if !slices.Equal(devices, in.WantDevices) {
		t.Errorf("export devices = %v, want %v", devices, in.WantDevices)
	}

	raw, err := os.ReadFile(filepath.Join(exp.jailRoot, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fc struct {
		BootSource map[string]any   `json:"boot-source"`
		Drives     []map[string]any `json:"drives"`
		Machine    map[string]any   `json:"machine-config"`
		Network    []map[string]any `json:"network-interfaces"`
	}
	if err := json.Unmarshal(raw, &fc); err != nil {
		t.Fatal(err)
	}
	if len(fc.Network) != 0 {
		t.Errorf("export guest network = %v, want none", fc.Network)
	}
	if fc.BootSource["boot_args"] != guestBootArgs {
		t.Errorf("boot args = %v, want %q", fc.BootSource["boot_args"], guestBootArgs)
	}
	if fc.Machine["mem_size_mib"] != float64(exportMemoryMiB) {
		t.Errorf("export guest memory = %v MiB, want %d", fc.Machine["mem_size_mib"], exportMemoryMiB)
	}
	if len(fc.Drives) != 2+len(missing) {
		t.Fatalf("Firecracker drives = %d, want rootfs, config, and %d export drives", len(fc.Drives), len(missing))
	}
	for i, d := range fc.Drives {
		wantRO := i < 2
		if d["is_read_only"] != wantRO {
			t.Errorf("Firecracker drive %v read-only = %v, want %v", d["drive_id"], d["is_read_only"], wantRO)
		}
	}
	if got, want := exportTimeout(exp.spec.Spec.Drives), time.Duration(in.WantTimeoutSeconds)*time.Second; got != want {
		t.Errorf("exportTimeout() = %s, want %s", got, want)
	}
}

// TestDriveExportFailureIsLoggedAndReported proves the failure record of an
// export guest that cannot run: one WARN line with the fixed code, the
// machine, and the caller trace, a failed drive-export step event for the
// caller, and a failed export in the proof detail. It detects a silent
// export failure, which would leave a caller without its drives and without
// a cause in the log.
func TestDriveExportFailureIsLoggedAndReported(t *testing.T) {
	in := readDriveExportInput(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range in.Tars {
		if err := os.WriteFile(filepath.Join(dir, "out", name+".tar"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	log := slog.New(trace.NewHandler(slog.NewJSONHandler(&buf, nil))).With("machine", "m-export-failure")
	ctx, span := trace.Start(context.Background(), log, "caller")
	defer span.End(nil)
	rec := &recorder{}
	// A zero enforcer is not healthy, so the export guest is refused.
	m := &Machine{
		r: &Runtime{enf: &enforcer{}}, booted: true, killReason: "stopped", log: log, traceCtx: ctx,
		spec: machine.Launch{Dir: dir, Spec: api.MachineSpec{Drives: in.Drives}, Sink: rec},
	}
	res := m.exportDrives(context.Background())
	if res == nil || res.status != "failed" || res.exported != 0 || res.missing != len(in.WantMissing) {
		t.Fatalf("exportDrives() = %+v, want failed with %d missing drives", res, len(in.WantMissing))
	}
	if d := res.detail(); d["status"] != "failed" {
		t.Errorf("proof detail = %v, want status failed", d)
	}
	var warn map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var got map[string]any
		if json.Unmarshal([]byte(line), &got) == nil && got["msg"] == "drive export failed" {
			warn = got
		}
	}
	if warn == nil || warn["level"] != "WARN" || warn["code"] != in.FailureCode ||
		warn["machine"] != "m-export-failure" || warn["trace_id"] != span.TraceID() || warn["error"] == nil {
		t.Errorf("failure line = %v, want WARN %s with machine, error, and trace %s; log:\n%s", warn, in.FailureCode, span.TraceID(), buf.String())
	}
	rec.mu.Lock()
	var steps []string
	for _, ev := range rec.events {
		if ev.Kind == api.EventStep && ev.Step == "drive-export" {
			steps = append(steps, ev.Status)
		}
	}
	rec.mu.Unlock()
	if !slices.Equal(steps, []string{"running", "failed"}) {
		t.Errorf("drive-export step events = %v, want running then failed", steps)
	}
}
