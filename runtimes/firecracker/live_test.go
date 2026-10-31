//go:build linux

package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
)

var (
	liveConfig = flag.String("vmcp-live-config", "", "HuJSON file for the Firecracker live gate")
	// liveIntruder makes TestLiveIntruder sleep. The enforcer subtest runs
	// the test binary with it as a process that intrudes into a machine
	// cgroup. The AppArmor profile lets vmcp run only its own binary and
	// its tools, so the gate uses no other program.
	liveIntruder = flag.Bool("vmcp-live-intruder", false, "sleep as the intruding process of the live gate")
)

type liveCfg struct {
	StateRoot    string   `json:"state_root"`
	JailBase     string   `json:"jail_base"`
	KernelPath   string   `json:"kernel_path"`
	AgentPath    string   `json:"agent_path"`
	JailerPath   string   `json:"jailer_path"`
	CgroupParent string   `json:"cgroup_parent"`
	Pool         string   `json:"pool"`
	DNSUpstreams []string `json:"dns_upstreams"`
	ImageRef     string   `json:"image_ref"`
	EgressURL    string   `json:"egress_url"`
	// GatewaySSHHost serves SSH on TCP port 22. GatewayResolver answers DNS
	// on UDP port 53. The gateway subtest reaches both directly.
	GatewaySSHHost  string `json:"gateway_ssh_host"`
	GatewayResolver string `json:"gateway_resolver"`
	SecretValue     string `json:"secret_value"`
	SecretFilePath  string `json:"secret_file_path"`
	MissingBinary   string `json:"missing_binary"`
	// StopAfterBootMS are the delays after Boot returns at which the
	// stop-during-boot subtest kills a machine. A delay of 0 kills it
	// before the jailer has created its cgroup.
	StopAfterBootMS []int `json:"stop_after_boot_ms"`
	// StopMarker is what the stopped process would print if it ran.
	StopMarker string `json:"stop_marker"`
	// DeleteAfterStartMS are the delays after StartMachine began at which
	// the manager subtest deletes a machine.
	DeleteAfterStartMS []int `json:"delete_after_start_ms"`
}

func loadLiveCfg(t *testing.T) liveCfg {
	t.Helper()
	if *liveConfig == "" {
		t.Skip("set -vmcp-live-config to run the Firecracker live gate")
	}
	raw, err := os.ReadFile(*liveConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", *liveConfig, err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	var c liveCfg
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode %s: %v", *liveConfig, err)
	}
	return c
}

// recorder is a Sink that keeps every event.
type recorder struct {
	mu     sync.Mutex
	events []api.Event
}

func (r *recorder) Event(ev api.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) dump() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, ev := range r.events {
		fmt.Fprintf(&b, "[%s %s %s %q] ", ev.Kind, ev.Step, ev.Status, ev.Data)
	}
	return b.String()
}

// flows returns the flow of each flow event.
func (r *recorder) flows() []api.Flow {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []api.Flow
	for _, ev := range r.events {
		if ev.Kind == api.EventFlow && ev.Flow != nil {
			out = append(out, *ev.Flow)
		}
	}
	return out
}

func (r *recorder) output(kind api.EventKind) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, ev := range r.events {
		if ev.Kind == kind {
			b.Write(ev.Data)
		}
	}
	return b.String()
}

// TestLiveFirecracker is the Firecracker live gate. It boots real jailed
// guests and proves process I/O, output drives, the posture contract,
// network allow and deny rules, and complete cleanup.
func TestLiveFirecracker(t *testing.T) {
	c := loadLiveCfg(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	logs := &liveLog{}
	rt, err := New(ctx, Config{
		StateRoot: c.StateRoot, JailBase: c.JailBase, KernelPath: c.KernelPath, AgentPath: c.AgentPath,
		JailerPath: c.JailerPath, CgroupRoot: "/sys/fs/cgroup", CgroupParent: c.CgroupParent, InstallID: "live-gate",
		UIDBase: 400000, Pool: netip.MustParsePrefix(c.Pool), DNSUpstreams: c.DNSUpstreams,
		Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	st := rt.Status()
	if !st.Ready {
		t.Fatalf("Status() not ready: %+v", st.Checks)
	}
	start := time.Now()
	meta, err := rt.PrepareImage(ctx, "img-live", api.ImageRequest{Ref: c.ImageRef})
	if err != nil {
		t.Fatalf("PrepareImage() error = %v", err)
	}
	t.Logf("image prepared in %s: %d bytes", time.Since(start).Round(time.Millisecond), meta.SizeBytes)
	// The manager drops an image whose key differs from the runtime key, so
	// a fresh image must carry exactly the runtime key.
	if meta.Compatibility != rt.ImageCompatibility() {
		t.Fatalf("image compatibility = %q, runtime compatibility = %q", meta.Compatibility, rt.ImageCompatibility())
	}
	t.Cleanup(func() { _ = rt.DeleteImage("img-live") })

	t.Run("isolated", func(t *testing.T) {
		script := "echo hello; echo oops >&2; echo data > /out/f; id -u; exit 3"
		rec, res, dir := runLive(t, ctx, rt, "m-0011223344556677", 0, api.MachineSpec{
			Drives:  []api.Drive{{Name: "out", GuestPath: "/out", SizeMiB: 16, Writable: true}},
			Process: api.Process{Args: []string{"/bin/sh", "-c", script}},
		}, "1000:1000")
		if res.Exit == nil || res.Exit.Code != 3 {
			t.Errorf("exit = %+v, want code 3", res.Exit)
		}
		if out := rec.output(api.EventStdout); !strings.Contains(out, "hello") || !strings.Contains(out, "1000") {
			t.Errorf("stdout = %q, want hello and uid 1000", out)
		}
		if errOut := rec.output(api.EventStderr); !strings.Contains(errOut, "oops") {
			t.Errorf("stderr = %q, want oops", errOut)
		}
		if got := tarFile(t, filepath.Join(dir, "out", "out.tar"), "f"); got != "data\n" {
			t.Errorf("out drive file f = %q, want data", got)
		}
		checkProof(t, rt, res)
	})

	t.Run("secrets", func(t *testing.T) {
		if c.SecretValue == "" || !strings.HasPrefix(c.SecretFilePath, "/run/") {
			t.Fatal("live config needs secret_value and a secret_file_path under /run/")
		}
		spec := api.MachineSpec{
			Process: api.Process{
				Args: []string{"/bin/sh", "-c", fmt.Sprintf(
					`[ "$VMCP_LIVE_SECRET" = "$(cat %s)" ] && echo SECRET_MATCH; grep -q ' /run tmpfs ' /proc/mounts && echo RUN_TMPFS; grep -q ' /sys/fs/cgroup cgroup2 ' /proc/mounts && echo CGROUP2; grep -c . %s`,
					c.SecretFilePath, c.SecretFilePath)},
				SecretEnv: []string{"VMCP_LIVE_SECRET=" + c.SecretValue},
			},
			Files: []api.File{{GuestPath: c.SecretFilePath, Mode: 0o400, Body: []byte(c.SecretValue), Secret: true}},
		}
		// The config drive is on host disk; it must not hold the secret.
		dir := filepath.Join(rt.machinesDir(), "m-5566778899aabbcc")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		inst, err := rt.Provision(ctx, machine.Launch{ID: "m-5566778899aabbcc", Slot: 2, Dir: dir, ImageID: "img-live",
			Spec: spec, Args: spec.Process.Args, SecretEnv: spec.Process.SecretEnv, WorkDir: "/", Sink: &recorder{}})
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(inst.(*Machine).jailRoot, "config.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(c.SecretValue)) {
			t.Error("config.bin on host disk holds the secret")
		}
		inst.Destroy(context.Background(), "test-cleanup")
		_ = os.RemoveAll(dir)

		rec, res, _ := runLive(t, ctx, rt, "m-66778899aabbccdd", 2, spec, "")
		out := rec.output(api.EventStdout)
		for _, want := range []string{"SECRET_MATCH", "RUN_TMPFS", "CGROUP2"} {
			if !strings.Contains(out, want) {
				t.Errorf("secrets output missing %s; got %q", want, out)
			}
		}
		checkProof(t, rt, res)
	})

	t.Run("agent-failure", func(t *testing.T) {
		if c.MissingBinary == "" {
			t.Fatal("live config needs missing_binary")
		}
		rec, res, _ := runLive(t, ctx, rt, "m-1122334455667788", 3, api.MachineSpec{
			Process: api.Process{Args: []string{c.MissingBinary}},
		}, "")
		if res.Exit == nil || res.Exit.Code != 127 {
			t.Errorf("exit = %+v, want code 127", res.Exit)
		}
		var detail string
		rec.mu.Lock()
		for _, ev := range rec.events {
			if ev.Kind == api.EventStep && ev.Status == "failed" {
				detail = ev.Detail
			}
		}
		rec.mu.Unlock()
		if !strings.Contains(detail, c.MissingBinary) {
			t.Errorf("failed step detail = %q, want the missing binary %q; events %s", detail, c.MissingBinary, rec.dump())
		}
		checkProof(t, rt, res)
	})

	// A stop during boot must end the machine before its process runs and
	// remove every resource. A kill before the jailer created the cgroup
	// found no process, so the guest ran its process. A kill during boot
	// removed the cgroup while it was still populated, which Linux 6.1
	// refuses, and the proof was partial.
	t.Run("stop-during-boot", func(t *testing.T) {
		if len(c.StopAfterBootMS) == 0 || c.StopMarker == "" {
			t.Fatal("live config needs stop_after_boot_ms and stop_marker")
		}
		for i, delay := range c.StopAfterBootMS {
			id := fmt.Sprintf("m-5f0%013x", i)
			dir := filepath.Join(rt.machinesDir(), id)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			rec := &recorder{}
			args := []string{"/bin/sh", "-c", fmt.Sprintf("echo %s; sleep 600", c.StopMarker)}
			m, err := rt.Provision(ctx, machine.Launch{ID: id, Slot: 4, Dir: dir, ImageID: "img-live",
				Spec: api.MachineSpec{Resources: api.Resources{VCPUs: 1, MemoryMiB: 256, DiskMiB: 256}, Process: api.Process{Args: args}},
				Args: args, Env: []string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin"}, WorkDir: "/", Sink: rec})
			if err != nil {
				t.Fatalf("Provision() error = %v", err)
			}
			if err := m.Boot(ctx); err != nil {
				t.Fatalf("Boot() error = %v", err)
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
			m.(*Machine).Kill("stopped")
			res := waitKilled(t, m.(*Machine), time.Minute)
			t.Logf("stop %d ms after boot: proof %s, reason %s", delay, res.Proof.TeardownStatus, res.Proof.DestroyReason)
			if out := rec.output(api.EventStdout); strings.Contains(out, c.StopMarker) {
				t.Errorf("stop %d ms after boot: the process ran; stdout %q", delay, out)
			}
			p := res.Proof
			if !p.Destroyed || p.TeardownStatus != "destroyed" || p.DestroyReason != "stopped" {
				t.Errorf("stop %d ms after boot: proof = %+v, want destroyed with reason stopped", delay, p)
			}
			if cg, _ := p.Detail["cgroup"].(string); cg != "" {
				if _, err := os.Lstat(cg); err == nil {
					t.Errorf("stop %d ms after boot: cgroup %s remains", delay, cg)
				}
			}
			if jail, _ := p.Detail["jail_id"].(string); jail != "" {
				if _, err := os.Lstat(filepath.Join(rt.cfg.JailBase, "firecracker", jail)); err == nil {
					t.Errorf("stop %d ms after boot: jail %s remains", delay, jail)
				}
			}
		}
	})

	// The manager subtests run the real runtime under the machine manager,
	// as vmcp serve does.
	t.Run("manager", func(t *testing.T) {
		if len(c.DeleteAfterStartMS) == 0 || c.StopMarker == "" {
			t.Fatal("live config needs delete_after_start_ms and stop_marker")
		}
		mgr, err := machine.New(ctx, rt, machine.Config{Dir: c.StateRoot, MaxMachines: 4,
			Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
		if err != nil {
			t.Fatalf("machine.New() error = %v", err)
		}
		img, err := mgr.CreateImage(ctx, api.ImageRequest{Ref: c.ImageRef})
		if err != nil {
			t.Fatalf("CreateImage() error = %v", err)
		}
		t.Cleanup(func() { _ = mgr.DeleteImage(context.Background(), img.ID) })
		spec := func(name string) api.MachineSpec {
			return api.MachineSpec{Name: name, Lifecycle: api.Ephemeral, Image: img.ID, TimeoutSeconds: 120,
				Resources: api.Resources{VCPUs: 1, MemoryMiB: 256, DiskMiB: 256},
				Process:   api.Process{Args: []string{"/bin/sh", "-c", fmt.Sprintf("echo %s; sleep 600", c.StopMarker)}}}
		}

		// A stop before start ends the machine with a proof; the start is
		// refused and nothing boots.
		t.Run("stop-before-start", func(t *testing.T) {
			m, err := mgr.CreateMachine(ctx, spec("live-stop-before-start"))
			if err != nil {
				t.Fatal(err)
			}
			stopped, err := mgr.StopMachine(ctx, m.ID)
			if err != nil || stopped.State != api.StateExited || stopped.Proof == nil || !stopped.Proof.Destroyed {
				t.Errorf("StopMachine() = state %s proof %+v, err %v; want exited with a destroyed proof", stopped.State, stopped.Proof, err)
			}
			var merr *machine.Error
			if _, err := mgr.StartMachine(ctx, m.ID); !errors.As(err, &merr) || merr.Code != api.ErrConflict {
				t.Errorf("StartMachine() after stop error = %v, want %s", err, api.ErrConflict)
			}
			if _, err := mgr.DeleteMachine(ctx, m.ID); err != nil {
				t.Errorf("DeleteMachine() error = %v", err)
			}
			checkNoMachineResources(t, rt, 0)
		})

		// A delete during start returns a destroyed proof. A guest that
		// had not booted never boots, and nothing is left.
		t.Run("delete-during-start", func(t *testing.T) {
			for i, delay := range c.DeleteAfterStartMS {
				// A stream of a machine that the manager lost never ends,
				// so each attempt has its own deadline.
				ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				m, err := mgr.CreateMachine(ctx, spec(fmt.Sprintf("live-delete-during-start-%d", i)))
				if err != nil {
					t.Fatal(err)
				}
				rec := &recorder{}
				streamed := make(chan struct{})
				go func() {
					defer close(streamed)
					_ = mgr.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
						rec.Event(ev)
						return nil
					})
				}()
				started := make(chan error, 1)
				go func() {
					_, err := mgr.StartMachine(ctx, m.ID)
					started <- err
				}()
				time.Sleep(time.Duration(delay) * time.Millisecond)
				final, err := mgr.DeleteMachine(ctx, m.ID)
				<-started
				<-streamed
				booted := false
				rec.mu.Lock()
				for _, ev := range rec.events {
					booted = booted || (ev.Kind == api.EventStep && ev.Step == "boot")
				}
				rec.mu.Unlock()
				// The window that the delete hit: before the start (a
				// manager proof), during Provision (a runtime proof and no
				// boot), or after the boot began.
				window := "after boot began"
				switch {
				case !booted && final.Proof != nil && final.Proof.Runtime == "":
					window = "before start"
				case !booted:
					window = "during provision"
				}
				t.Logf("delete %d ms after start: window %s, proof destroyed %t, teardown %q",
					delay, window, final.Proof != nil && final.Proof.Destroyed, proofTeardown(final.Proof))
				if err != nil || final.Proof == nil || !final.Proof.Destroyed || final.Proof.TeardownStatus != "destroyed" {
					t.Errorf("delete %d ms after start: DeleteMachine() = proof %+v, err %v; want a destroyed proof", delay, final.Proof, err)
				}
				if out := rec.output(api.EventStdout); !booted && strings.Contains(out, c.StopMarker) {
					t.Errorf("delete %d ms after start: an unbooted machine ran its process", delay)
				}
				checkNoMachineResources(t, rt, 5*time.Second)
			}
		})

		// A machine that runs when the vmcp process ends: the next process
		// removes its resources at start and gives it a proof.
		t.Run("restart", func(t *testing.T) {
			m, err := mgr.CreateMachine(ctx, spec("live-running-at-restart"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mgr.StartMachine(ctx, m.ID); err != nil {
				t.Fatalf("StartMachine() error = %v", err)
			}
			running := make(chan struct{})
			ended := make(chan struct{})
			go func() {
				defer close(ended)
				once := false
				_ = mgr.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
					if !once && ev.Kind == api.EventStdout && strings.Contains(string(ev.Data), c.StopMarker) {
						once = true
						close(running)
					}
					return nil
				})
			}()
			select {
			case <-running:
			case <-time.After(time.Minute):
				t.Fatal("the machine did not run its process")
			}
			// The disk state of a vmcp process that ended now: a copy of
			// the records and of the machine event log. The first manager
			// keeps writing to its own state directory, which a dead
			// process cannot do.
			// The AppArmor profile lets vmcp write only under its state root.
			crashed := filepath.Join(c.StateRoot, "live-restart-"+m.ID)
			t.Cleanup(func() { _ = os.RemoveAll(crashed) })
			for _, rel := range []string{"records", filepath.Join("machines", m.ID, "events.ndjson")} {
				if err := copyTree(filepath.Join(c.StateRoot, rel), filepath.Join(crashed, rel)); err != nil {
					t.Fatalf("copy the state of the ended process: %v", err)
				}
			}
			next, err := machine.New(ctx, rt, machine.Config{Dir: crashed, MaxMachines: 4,
				Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
			if err != nil {
				t.Fatalf("machine.New() after the restart error = %v", err)
			}
			got, err := next.Machine(m.ID)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("after restart: state %s exit %+v proof %+v", got.State, got.Exit, got.Proof)
			if got.State != api.StateFailed || got.Proof == nil || !got.Proof.Destroyed || got.Proof.DestroyReason != "vmcp-restarted" {
				t.Errorf("machine after restart = state %s proof %+v; want failed with a destroyed proof, reason vmcp-restarted", got.State, got.Proof)
			}
			checkNoMachineResources(t, rt, 0)
			<-ended
			if _, err := next.DeleteMachine(ctx, m.ID); err != nil {
				t.Errorf("DeleteMachine() after restart error = %v", err)
			}
		})
	})

	t.Run("enforcer", func(t *testing.T) {
		if err := run(ctx, nil, "ip", "tuntap", "add", "dev", "vmcp-stray0", "mode", "tap"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 5*time.Second, "stray tap removal", func() bool {
			return run(ctx, nil, "ip", "link", "show", "dev", "vmcp-stray0") != nil
		})
		if err := run(ctx, nil, "nft", "flush", "chain", "inet", nftTable, "input"); err != nil {
			t.Fatal(err)
		}
		waitFor(t, 5*time.Second, "vmcp table restore", func() bool {
			out, err := toolCommand(ctx, netAdminCaps, "nft", "-j", "list", "table", "inet", nftTable).Output()
			return err == nil && chainRuleCount(out) == expectedChainRules
		})

		m, _ := startLive(t, ctx, rt, "m-aaaa000000000001", 2, "sleep 60")
		evil := filepath.Join(m.jailRoot, "evil")
		if err := os.WriteFile(evil, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(evil, 0o4755); err != nil {
			t.Fatal(err)
		}
		if res := waitKilled(t, m, 10*time.Second); res.Proof.DestroyReason != "enforcer" || !res.Proof.Destroyed {
			t.Errorf("setuid file: proof = %+v, want an enforcer kill and destroyed", res.Proof)
		}

		m2, _ := startLive(t, ctx, rt, "m-aaaa000000000002", 3, "sleep 60")
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		intruder := exec.Command(self, "-test.run=^TestLiveIntruder$", "-vmcp-live-intruder")
		if err := intruder.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- intruder.Wait() }()
		if err := os.WriteFile(filepath.Join(m2.cgroup, "cgroup.procs"), []byte(strconv.Itoa(intruder.Process.Pid)), 0o644); err != nil {
			t.Fatal(err)
		}
		if res := waitKilled(t, m2, 10*time.Second); res.Proof.DestroyReason != "enforcer" || !res.Proof.Destroyed {
			t.Errorf("extra process: proof = %+v, want an enforcer kill and destroyed", res.Proof)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the intruding process survived the machine kill")
		}
	})

	t.Run("posture-mount", func(t *testing.T) {
		// The mount namespace check of the posture contract, on real
		// processes: a jailed Firecracker has its own mount namespace, and
		// a process in the vmcp mount namespace is a violation.
		m, _ := startLive(t, ctx, rt, "m-aaaa000000000003", 4, "sleep 60")
		self, err := os.ReadFile("/proc/self/mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		pids, err := cgroupPIDs(m.cgroup)
		if err != nil || len(pids) != 1 {
			t.Fatalf("machine cgroup processes = %v, %v; want one Firecracker process", pids, err)
		}
		if v := mountViolation(pids[0], self); v != "" {
			t.Errorf("jailed Firecracker PID %d: mountViolation() = %q, want none", pids[0], v)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		shared := exec.Command(exe, "-test.run=^TestLiveIntruder$", "-vmcp-live-intruder")
		if err := shared.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = shared.Process.Kill(); _ = shared.Wait() }()
		if v := mountViolation(shared.Process.Pid, self); !strings.Contains(v, "shares the vmcp mount namespace") {
			t.Errorf("process in the vmcp mount namespace: mountViolation() = %q, want a shared namespace", v)
		}
	})

	t.Run("network", func(t *testing.T) {
		script := strings.Join([]string{
			fmt.Sprintf("wget -q -T 10 -O /dev/null %s && echo EGRESS_OK", c.EgressURL),
			"wget -q -T 5 -O /dev/null http://169.254.169.254/ && echo METADATA_REACHED || echo METADATA_DENIED",
			"wget -q -T 5 -O /dev/null http://10.0.0.1/ && echo PRIVATE_REACHED || echo PRIVATE_DENIED",
			"env -u http_proxy -u HTTP_PROXY wget -q -T 3 -O /dev/null http://1.1.1.1/ && echo DIRECT_REACHED || echo DIRECT_DENIED",
			"gw=$(ip route | awk '/default/ {print $3}'); env -u http_proxy -u HTTP_PROXY wget -q -T 3 -O /dev/null http://$gw:8080/ && echo HOSTPORT_REACHED || echo HOSTPORT_DENIED",
			"nslookup example.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED",
		}, "; ")
		mark := logs.mark()
		rec, res, _ := runLive(t, ctx, rt, "m-8899aabbccddeeff", 1, api.MachineSpec{
			Network: api.Network{DNS: true, PublicEgress: true},
			Process: api.Process{Args: []string{"/bin/sh", "-c", script}},
		}, "")
		out := rec.output(api.EventStdout)
		for _, want := range []string{"EGRESS_OK", "METADATA_DENIED", "PRIVATE_DENIED", "DIRECT_DENIED", "HOSTPORT_DENIED", "DNS_OK"} {
			if !strings.Contains(out, want) {
				t.Errorf("network output missing %s; got %q", want, out)
			}
		}
		checkProof(t, rt, res)
		// The enforcer must own the network of a live machine. A stray
		// removal or failure here means it misread the machine's rules.
		for _, code := range []string{"enforcer_stray_removed", "enforcer_cleanup_failed", "enforcer_table_restored"} {
			if line := logs.since(mark, code); line != "" {
				t.Errorf("enforcer acted on a live machine's network: %s", line)
			}
		}
	})
	// The gateway broker on a real guest: direct TCP to HTTP and SSH ports
	// and direct UDP DNS reach public hosts with no proxy; metadata,
	// private, and host-port destinations stay denied; the broker DNS still
	// works; each connection is a flow event and a log line; and the
	// gateway elements leave with the machine.
	t.Run("gateway", func(t *testing.T) {
		script := strings.Join([]string{
			"env | grep -qi '_proxy=' && echo PROXY_SET || echo PROXY_UNSET",
			// Any HTTP response proves the path. The status belongs to the
			// public server, which can refuse busybox.
			fmt.Sprintf("wget -S -T 10 -O /dev/null %s 2>&1 | grep -q 'HTTP/1' && echo GW_HTTP_OK || echo GW_HTTP_FAILED", c.EgressURL),
			// The server sends its banner first. An early end of input would
			// half-close the connection before it does.
			fmt.Sprintf("(sleep 3) | nc -w 10 %s 22 | head -c 4 | grep -q SSH- && echo GW_SSH_OK || echo GW_SSH_FAILED", c.GatewaySSHHost),
			fmt.Sprintf("nslookup example.com %s >/dev/null 2>&1 && echo GW_UDP_OK || echo GW_UDP_FAILED", c.GatewayResolver),
			"wget -q -T 5 -O /dev/null http://169.254.169.254/ && echo METADATA_REACHED || echo METADATA_DENIED",
			"wget -q -T 5 -O /dev/null http://10.0.0.1/ && echo PRIVATE_REACHED || echo PRIVATE_DENIED",
			"gw=$(ip route | awk '/default/ {print $3}'); wget -q -T 3 -O /dev/null http://$gw:8080/ && echo HOSTPORT_REACHED || echo HOSTPORT_DENIED",
			"nslookup example.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED",
		}, "; ")
		mark := logs.mark()
		rec, res, _ := runLive(t, ctx, rt, "m-99aabbccddeeff00", 5, api.MachineSpec{
			Network: api.Network{DNS: true, Gateway: true},
			Process: api.Process{Args: []string{"/bin/sh", "-c", script}},
		}, "")
		out := rec.output(api.EventStdout)
		for _, want := range []string{"PROXY_UNSET", "GW_HTTP_OK", "GW_SSH_OK", "GW_UDP_OK", "METADATA_DENIED", "PRIVATE_DENIED", "HOSTPORT_DENIED", "DNS_OK"} {
			if !strings.Contains(out, want) {
				t.Errorf("gateway output missing %s; got %q", want, out)
			}
		}
		flows := rec.flows()
		closed := func(proto string, port int, sends bool) bool {
			for _, f := range flows {
				if f.Broker == "gateway" && f.Phase == api.FlowClose && f.Proto == proto && f.Port == port &&
					f.BytesIn > 0 && (f.BytesOut > 0 || !sends) {
					return true
				}
			}
			return false
		}
		// The SSH probe only reads the server banner.
		for _, w := range []struct {
			proto string
			port  int
			sends bool
		}{{"tcp", 80, true}, {"tcp", 22, false}, {"udp", 53, true}} {
			if !closed(w.proto, w.port, w.sends) {
				t.Errorf("no closed gateway %s flow to port %d with its bytes; flows: %+v", w.proto, w.port, flows)
			}
		}
		for _, addr := range []string{"169.254.169.254", "10.0.0.1"} {
			found := false
			for _, f := range flows {
				found = found || (f.Phase == api.FlowDenied && f.Address == addr && f.Reason == "address_not_public")
			}
			if !found {
				t.Errorf("no denied gateway flow to %s; flows: %+v", addr, flows)
			}
		}
		if line := logs.since(mark, "egress_denied"); !strings.Contains(line, `"broker":"gateway"`) {
			t.Errorf("no egress_denied gateway log line; got %q", line)
		}
		checkProof(t, rt, res)
		for _, code := range []string{"enforcer_stray_removed", "enforcer_cleanup_failed", "enforcer_table_restored", "enforcer_route_restored"} {
			if line := logs.since(mark, code); line != "" {
				t.Errorf("enforcer acted on a live gateway machine: %s", line)
			}
		}
		listing, err := toolCommand(ctx, netAdminCaps, "nft", "-j", "list", "table", "inet", nftTable).Output()
		if err != nil {
			t.Fatalf("list the vmcp table: %v", err)
		}
		if els := gatewayElements(listing); len(els) != 0 {
			t.Errorf("gateway elements remain after teardown: %+v", els)
		}
	})
}

// TestLiveIntruder is not a test. With -vmcp-live-intruder it sleeps as
// the process that the enforcer subtest moves into a machine cgroup.
func TestLiveIntruder(t *testing.T) {
	if !*liveIntruder {
		t.Skip("only the live gate runs it, as an intruding process")
	}
	time.Sleep(100 * time.Second)
}

// liveLog keeps the runtime log of the live gate.
type liveLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *liveLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *liveLog) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Len()
}

// since returns the first line after mark with the code, or "".
func (l *liveLog) since(mark int, code string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range strings.Split(l.buf.String()[mark:], "\n") {
		if strings.Contains(line, `"code":"`+code+`"`) {
			return line
		}
	}
	return ""
}

// startLive provisions and boots a machine and waits for its posture
// check. It returns the running machine.
func startLive(t *testing.T, ctx context.Context, rt *Runtime, id string, slot int, script string) (*Machine, *recorder) {
	t.Helper()
	dir := filepath.Join(rt.machinesDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rec := &recorder{}
	inst, err := rt.Provision(ctx, machine.Launch{
		ID: id, Slot: slot, Dir: dir, ImageID: "img-live",
		Spec: api.MachineSpec{Resources: api.Resources{VCPUs: 1, MemoryMiB: 128, DiskMiB: 128}},
		Args: []string{"/bin/sh", "-c", script}, Env: []string{"PATH=/bin:/usr/bin"}, WorkDir: "/", Sink: rec,
	})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	m := inst.(*Machine)
	t.Cleanup(func() { m.Destroy(context.Background(), "test-cleanup") })
	if err := m.Boot(ctx); err != nil {
		t.Fatalf("Boot() error = %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for !m.postureChecked() {
		if time.Now().After(deadline) {
			t.Fatalf("no posture check in 30s; events: %s", rec.dump())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return m, rec
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", d, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitKilled(t *testing.T, m *Machine, d time.Duration) machine.Result {
	t.Helper()
	select {
	case <-m.Done():
	case <-time.After(d):
		t.Fatalf("machine %s was not stopped within %s", m.spec.ID, d)
	}
	return m.Result()
}

func runLive(t *testing.T, ctx context.Context, rt *Runtime, id string, slot int, spec api.MachineSpec, user string) (*recorder, machine.Result, string) {
	t.Helper()
	dir := filepath.Join(rt.machinesDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rec := &recorder{}
	if spec.Resources.MemoryMiB == 0 {
		spec.Resources = api.Resources{VCPUs: 1, MemoryMiB: 256, DiskMiB: 256}
	}
	m, err := rt.Provision(ctx, machine.Launch{
		ID: id, Slot: slot, Dir: dir, ImageID: "img-live", Spec: spec,
		Args: spec.Process.Args, Env: []string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin"}, SecretEnv: spec.Process.SecretEnv,
		WorkDir: "/", User: user, Sink: rec,
	})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	start := time.Now()
	if err := m.Boot(ctx); err != nil {
		t.Fatalf("Boot() error = %v", err)
	}
	select {
	case <-m.Done():
	case <-time.After(2 * time.Minute):
		m.Kill("test-timeout")
		<-m.Done()
		t.Fatalf("machine did not stop in time; serial log tail: %s", tail(filepath.Join(dir, "serial.log")))
	}
	res := m.Result()
	t.Logf("machine %s ran in %s; exit %+v; proof %s", id, time.Since(start).Round(time.Millisecond), res.Exit, res.Proof.TeardownStatus)
	if res.Exit == nil {
		t.Logf("serial log tail: %s", tail(filepath.Join(dir, "serial.log")))
		t.Logf("events: %s", rec.dump())
	}
	return rec, res, dir
}

func proofTeardown(p *api.Proof) string {
	if p == nil {
		return ""
	}
	return p.TeardownStatus
}

// copyTree copies the regular file or the directory tree src to dst.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
}

// checkNoMachineResources waits up to d until no machine cgroup and no
// machine jail of the runtime remain.
func checkNoMachineResources(t *testing.T, rt *Runtime, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		var left []string
		for _, dir := range []string{rt.cgroupParent(), filepath.Join(rt.cfg.JailBase, "firecracker")} {
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "vmcp-") {
					left = append(left, filepath.Join(dir, e.Name()))
				}
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("machine resources remain: %v", left)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func checkProof(t *testing.T, rt *Runtime, res machine.Result) {
	t.Helper()
	p := res.Proof
	if !p.Destroyed || p.TeardownStatus != "destroyed" {
		t.Errorf("proof = %+v, want destroyed", p)
	}
	posture, _ := p.Detail["posture"].(map[string]any)
	if ok, _ := posture["ok"].(bool); !ok {
		t.Errorf("posture = %+v, want ok", posture)
	}
	jail, _ := p.Detail["jail_id"].(string)
	if _, err := os.Lstat(filepath.Join(rt.cfg.JailBase, "firecracker", jail)); err == nil {
		t.Errorf("jail %s remains", jail)
	}
	if cg, _ := p.Detail["cgroup"].(string); cg != "" {
		if _, err := os.Lstat(cg); err == nil {
			t.Errorf("cgroup %s remains", cg)
		}
	}
	if tap, _ := p.Detail["tap"].(string); tap != "" {
		if err := run(context.Background(), nil, "ip", "link", "show", "dev", tap); err == nil {
			t.Errorf("tap %s remains", tap)
		}
	}
}

func tarFile(t *testing.T, path, name string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Errorf("open %s: %v", path, err)
		return ""
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err != nil {
			return ""
		}
		if h.Name == name {
			b, _ := io.ReadAll(tr)
			return string(b)
		}
	}
}

func tail(path string) string {
	b, _ := os.ReadFile(path)
	if len(b) > 3000 {
		b = b[len(b)-3000:]
	}
	return string(b)
}
