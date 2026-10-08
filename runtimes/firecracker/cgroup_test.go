//go:build linux

package firecracker

import (
	"flag"
	"os"
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
