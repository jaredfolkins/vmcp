//go:build linux

package firecracker

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var cgroupKillConfig = flag.String("vmcp-cgroup-kill-config", "testdata/cgroup-kill.hujson", "HuJSON file with the killed cgroup case")

// TestKillCgroupWaitsUntilUnpopulated proves that killCgroup returns only
// when cgroup.events reports "populated 0". teardown removes the cgroup
// right after killCgroup. When killCgroup returned as soon as cgroup.procs
// read empty, Linux 6.1 refused the removal with EBUSY, and a stopped
// machine got a partial proof.
func TestKillCgroupWaitsUntilUnpopulated(t *testing.T) {
	var in struct {
		ExitWindowMS      int    `json:"exit_window_ms"`
		Procs             string `json:"procs"`
		EventsPopulated   string `json:"events_populated"`
		EventsUnpopulated string `json:"events_unpopulated"`
	}
	readHuJSON(t, *cgroupKillConfig, &in)
	if in.ExitWindowMS <= 0 || in.EventsPopulated == "" || in.EventsUnpopulated == "" {
		t.Fatal("cgroup kill input is incomplete")
	}
	dir := t.TempDir()
	cg := filepath.Join(dir, "machine")
	if err := os.Mkdir(cg, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"cgroup.kill":   "",
		"cgroup.procs":  in.Procs,
		"cgroup.events": in.EventsPopulated,
	} {
		if err := os.WriteFile(filepath.Join(cg, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	events := filepath.Join(cg, "cgroup.events")
	// The last thread leaves the cgroup one exit window after the kill. The
	// rename replaces cgroup.events in one step, as the kernel does.
	exited := time.AfterFunc(time.Duration(in.ExitWindowMS)*time.Millisecond, func() {
		next := filepath.Join(dir, "cgroup.events.next")
		if err := os.WriteFile(next, []byte(in.EventsUnpopulated), 0o600); err == nil {
			_ = os.Rename(next, events)
		}
	})
	t.Cleanup(func() { exited.Stop() })

	if err := killCgroup(cg); err != nil {
		t.Fatalf("killCgroup() error = %v, want nil", err)
	}

	got, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != in.EventsUnpopulated {
		t.Errorf("cgroup.events when killCgroup returned = %q, want %q", got, in.EventsUnpopulated)
	}
	if kill, err := os.ReadFile(filepath.Join(cg, "cgroup.kill")); err != nil || string(kill) != "1" {
		t.Errorf("cgroup.kill = %q, %v; want 1", kill, err)
	}
}
