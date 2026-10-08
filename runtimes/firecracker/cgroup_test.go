//go:build linux

package firecracker

import (
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
)

var mountinfoConfig = flag.String("vmcp-mountinfo-config", "testdata/mountinfo.hujson", "HuJSON file with mount table cases")

// TestSharesMounts proves that the posture check finds a jailed process in
// the vmcp mount namespace from the mount tables. It replaced a comparison
// of /proc/<pid>/ns/mnt links, which vmcp cannot read for another user
// without CAP_SYS_PTRACE, so the comparison never found a shared
// namespace.
func TestSharesMounts(t *testing.T) {
	var in struct {
		Self  string `json:"self"`
		Cases []struct {
			Name      string `json:"name"`
			Other     string `json:"other"`
			Shares    bool   `json:"shares"`
			WantError string `json:"want_error"`
		} `json:"cases"`
	}
	readHuJSON(t, *mountinfoConfig, &in)
	if in.Self == "" || len(in.Cases) == 0 {
		t.Fatal("mountinfo input has no cases")
	}
	for _, tc := range in.Cases {
		got, err := sharesMounts([]byte(in.Self), []byte(tc.Other))
		switch {
		case tc.WantError != "":
			if err == nil || !strings.Contains(err.Error(), tc.WantError) {
				t.Errorf("%s: error = %v, want %q", tc.Name, err, tc.WantError)
			}
		case err != nil || got != tc.Shares:
			t.Errorf("%s: sharesMounts() = %t, %v; want %t", tc.Name, got, err, tc.Shares)
		}
	}
}

// TestMountViolationSelf proves that the posture check reports a process in
// the vmcp mount namespace: this test process itself.
func TestMountViolationSelf(t *testing.T) {
	self, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	if v := mountViolation(os.Getpid(), self); !strings.Contains(v, "shares the vmcp mount namespace") {
		t.Errorf("mountViolation(own pid) = %q, want a shared namespace", v)
	}
}

var kvmWorkerConfig = flag.String("vmcp-kvm-worker-config", "testdata/kvm-worker.hujson", "HuJSON file with KVM worker filter cases")

// TestDropKVMWorkers proves the one-process rule of a machine cgroup with
// the KVM worker kernel thread of Linux 6.1: one task outside the vmcp PID
// namespace (PID 0 in cgroup.procs) is allowed, a visible worker of a
// process in the same cgroup is left out, and anything else is counted.
// Before, the enforcer counted the worker as a second process and killed
// every machine.
func TestDropKVMWorkers(t *testing.T) {
	var in struct {
		CountCases []struct {
			Name          string `json:"name"`
			Procs         []int  `json:"procs"`
			WantVisible   []int  `json:"want_visible"`
			WantHidden    int    `json:"want_hidden"`
			WantViolation string `json:"want_violation"`
		} `json:"count_cases"`
		StatCases []struct {
			Name      string `json:"name"`
			Stat      string `json:"stat"`
			Flags     uint64 `json:"flags"`
			WantError string `json:"want_error"`
		} `json:"stat_cases"`
		FilterCases []struct {
			Name  string `json:"name"`
			Procs []struct {
				PID          int    `json:"pid"`
				KernelThread bool   `json:"kernel_thread"`
				Comm         string `json:"comm"`
			} `json:"procs"`
			Want []int `json:"want"`
		} `json:"filter_cases"`
	}
	readHuJSON(t, *kvmWorkerConfig, &in)
	if len(in.CountCases) == 0 || len(in.StatCases) == 0 || len(in.FilterCases) == 0 {
		t.Fatal("KVM worker input has no cases")
	}
	for _, tc := range in.CountCases {
		visible, hidden := splitHidden(tc.Procs)
		if !slices.Equal(visible, tc.WantVisible) || hidden != tc.WantHidden {
			t.Errorf("%s: splitHidden() = %v, %d; want %v, %d", tc.Name, visible, hidden, tc.WantVisible, tc.WantHidden)
		}
		v := machineProcsViolation(visible, hidden)
		if (tc.WantViolation == "") != (v == "") || !strings.Contains(v, tc.WantViolation) {
			t.Errorf("%s: machineProcsViolation() = %q, want %q", tc.Name, v, tc.WantViolation)
		}
	}
	for _, tc := range in.StatCases {
		got, err := statFlags(tc.Stat)
		switch {
		case tc.WantError != "":
			if err == nil || !strings.Contains(err.Error(), tc.WantError) {
				t.Errorf("%s: statFlags() error = %v, want %q", tc.Name, err, tc.WantError)
			}
		case err != nil || got != tc.Flags:
			t.Errorf("%s: statFlags() = %d, %v; want %d", tc.Name, got, err, tc.Flags)
		}
	}
	for _, tc := range in.FilterCases {
		ids := map[int]procIdentity{}
		var pids []int
		for _, p := range tc.Procs {
			ids[p.PID] = procIdentity{kernelThread: p.KernelThread, comm: p.Comm}
			pids = append(pids, p.PID)
		}
		got := dropKVMWorkers(pids, func(pid int) (procIdentity, error) { return ids[pid], nil })
		if !slices.Equal(got, tc.Want) {
			t.Errorf("%s: dropKVMWorkers() = %v, want %v", tc.Name, got, tc.Want)
		}
	}
}

// TestReadProcIdentity proves the kernel-thread flag on real processes:
// kthreadd (PID 2) is a kernel thread, and this test process is not.
func TestReadProcIdentity(t *testing.T) {
	kthreadd, err := readProcIdentity(2)
	if err != nil {
		t.Skipf("PID 2 is not visible: %v", err)
	}
	if !kthreadd.kernelThread {
		t.Errorf("PID 2 %q: kernelThread = false, want true", kthreadd.comm)
	}
	self, err := readProcIdentity(os.Getpid())
	if err != nil || self.kernelThread {
		t.Errorf("own process: %+v, %v; want a user process", self, err)
	}
}
