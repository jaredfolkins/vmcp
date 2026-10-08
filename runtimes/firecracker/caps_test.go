//go:build linux

package firecracker

import (
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var capsConfig = flag.String("vmcp-caps-config", "testdata/caps.hujson", "HuJSON file with capability cases")

type capsInput struct {
	Process []struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		WantError string `json:"want_error"`
	} `json:"process"`
	File []struct {
		Name      string `json:"name"`
		Xattr     string `json:"xattr"`
		Permitted string `json:"permitted"`
		Effective bool   `json:"effective"`
		WantError string `json:"want_error"`
	} `json:"file"`
}

// TestCheckProcessCapabilities proves that vmcp refuses to start without
// its file capabilities, and that the error names no-new-privileges when
// that option took them away. Without the check, vmcp failed later at the
// first tool or jail.
func TestCheckProcessCapabilities(t *testing.T) {
	var in capsInput
	readHuJSON(t, *capsConfig, &in)
	if len(in.Process) == 0 {
		t.Fatal("caps input has no process cases")
	}
	for _, tc := range in.Process {
		p := filepath.Join(t.TempDir(), "status")
		if err := os.WriteFile(p, []byte(tc.Status), 0o600); err != nil {
			t.Fatal(err)
		}
		err := checkProcessCapabilities(p)
		switch {
		case tc.WantError == "" && err != nil:
			t.Errorf("%s: error = %v, want nil", tc.Name, err)
		case tc.WantError != "" && (err == nil || !strings.Contains(err.Error(), tc.WantError)):
			t.Errorf("%s: error = %v, want one that names %q", tc.Name, err, tc.WantError)
		}
	}
}

// TestParseFileCaps proves the decoding of security.capability values that
// setcap writes. checkJailer compares the result with jailerCaps; a wrong
// decode would accept a jailer without its capabilities.
func TestParseFileCaps(t *testing.T) {
	var in capsInput
	readHuJSON(t, *capsConfig, &in)
	if len(in.File) == 0 {
		t.Fatal("caps input has no file cases")
	}
	for _, tc := range in.File {
		raw, err := hex.DecodeString(tc.Xattr)
		if err != nil {
			t.Fatalf("%s: %v", tc.Name, err)
		}
		prm, eff, err := parseFileCaps(raw)
		if tc.WantError != "" {
			if err == nil || !strings.Contains(err.Error(), tc.WantError) {
				t.Errorf("%s: error = %v, want %q", tc.Name, err, tc.WantError)
			}
			continue
		}
		want, perr := strconv.ParseUint(tc.Permitted, 16, 64)
		if err != nil || perr != nil || prm != want || eff != tc.Effective {
			t.Errorf("%s: parseFileCaps() = %#x, %t, %v; want %#x, %t", tc.Name, prm, eff, err, want, tc.Effective)
		}
	}
	if capMask(jailerCaps) != 0x82000c3 {
		t.Errorf("jailerCaps mask = %#x (%s); the image setcap line and this test name 0x82000c3", capMask(jailerCaps), capList(capMask(jailerCaps)))
	}
}
