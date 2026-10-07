package firecracker

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStatusReadyNeedsEveryCheck proves that a missing device or cgroup v2
// makes the host not ready, and that capacity comes from MemTotal.
func TestStatusReadyNeedsEveryCheck(t *testing.T) {
	dir := t.TempDir()
	file := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ready := Host{
		KVMDevice:      file("kvm", ""),
		TUNDevice:      file("tun", ""),
		CgroupControls: file("cgroup.controllers", "cpu memory pids\n"),
		MemInfo:        file("meminfo", "MemTotal:       8388608 kB\nMemFree:  1 kB\n"),
	}
	st := ready.Status()
	if !st.Ready {
		t.Fatalf("Status().Ready = false with all checks present: %+v", st.Checks)
	}
	if st.Runtime != Name || st.Release == "" {
		t.Errorf("Status() runtime %q release %q, want %q and the baked release", st.Runtime, st.Release, Name)
	}
	if st.Capacity.MemoryMiB != 8192 {
		t.Errorf("Status().Capacity.MemoryMiB = %d, want 8192", st.Capacity.MemoryMiB)
	}

	for name, h := range map[string]Host{
		"no kvm":     {KVMDevice: filepath.Join(dir, "missing"), TUNDevice: ready.TUNDevice, CgroupControls: ready.CgroupControls, MemInfo: ready.MemInfo},
		"no tun":     {KVMDevice: ready.KVMDevice, TUNDevice: filepath.Join(dir, "missing"), CgroupControls: ready.CgroupControls, MemInfo: ready.MemInfo},
		"no cgroup2": {KVMDevice: ready.KVMDevice, TUNDevice: ready.TUNDevice, CgroupControls: filepath.Join(dir, "missing"), MemInfo: ready.MemInfo},
	} {
		if h.Status().Ready {
			t.Errorf("Status().Ready = true with %s, want false", name)
		}
	}
}
