//go:build linux

package firecracker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
)

var liveConfig = flag.String("vmcp-live-config", "", "HuJSON file for the Firecracker live gate")

type liveCfg struct {
	StateRoot    string   `json:"state_root"`
	JailBase     string   `json:"jail_base"`
	KernelPath   string   `json:"kernel_path"`
	AgentPath    string   `json:"agent_path"`
	CgroupParent string   `json:"cgroup_parent"`
	Pool         string   `json:"pool"`
	DNSUpstreams []string `json:"dns_upstreams"`
	ImageRef     string   `json:"image_ref"`
	EgressURL    string   `json:"egress_url"`
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
	rt, err := New(ctx, Config{
		StateRoot: c.StateRoot, JailBase: c.JailBase, KernelPath: c.KernelPath, AgentPath: c.AgentPath,
		CgroupRoot: "/sys/fs/cgroup", CgroupParent: c.CgroupParent, InstallID: "live-gate",
		UIDBase: 400000, Pool: netip.MustParsePrefix(c.Pool), DNSUpstreams: c.DNSUpstreams,
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

	t.Run("network", func(t *testing.T) {
		script := strings.Join([]string{
			fmt.Sprintf("wget -q -T 10 -O /dev/null %s && echo EGRESS_OK", c.EgressURL),
			"wget -q -T 5 -O /dev/null http://169.254.169.254/ && echo METADATA_REACHED || echo METADATA_DENIED",
			"wget -q -T 5 -O /dev/null http://10.0.0.1/ && echo PRIVATE_REACHED || echo PRIVATE_DENIED",
			"env -u http_proxy -u HTTP_PROXY wget -q -T 3 -O /dev/null http://1.1.1.1/ && echo DIRECT_REACHED || echo DIRECT_DENIED",
			"gw=$(ip route | awk '/default/ {print $3}'); env -u http_proxy -u HTTP_PROXY wget -q -T 3 -O /dev/null http://$gw:8080/ && echo HOSTPORT_REACHED || echo HOSTPORT_DENIED",
			"nslookup example.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED",
		}, "; ")
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
	})
}

func runLive(t *testing.T, ctx context.Context, rt *Runtime, id string, slot int, spec api.MachineSpec, user string) (*recorder, Result, string) {
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
	m, err := rt.Provision(ctx, LaunchSpec{
		ID: id, Slot: slot, Dir: dir, ImageID: "img-live", Spec: spec,
		Args: spec.Process.Args, Env: []string{"PATH=/bin:/usr/bin:/sbin:/usr/sbin"}, WorkDir: "/", User: user, Sink: rec,
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
	}
	return rec, res, dir
}

func checkProof(t *testing.T, rt *Runtime, res Result) {
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
