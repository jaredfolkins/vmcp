//go:build linux

package firecracker

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
)

var fileSizeLimitTestConfig = flag.String("vmcp-file-size-limit-test-config", "testdata/file-size-limit.hujson", "HuJSON file for the file size limit test")

// TestFileSizeLimitCoversEveryDiskImage proves that the file size limit of
// the Firecracker process is at least 1 GiB and covers the writable root
// layer and each drive, with slack. A limit below the root layer ended the
// guest with SIGXFSZ.
func TestFileSizeLimitCoversEveryDiskImage(t *testing.T) {
	raw, err := os.ReadFile(*fileSizeLimitTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Cases []struct {
			Name      string `json:"name"`
			DiskMiB   int    `json:"disk_mib"`
			DrivesMiB []int  `json:"drives_mib"`
			WantBytes int64  `json:"want_bytes"`
		} `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if len(in.Cases) == 0 {
		t.Fatal("file size limit test input has no cases")
	}
	for _, c := range in.Cases {
		t.Run(c.Name, func(t *testing.T) {
			spec := api.MachineSpec{Resources: api.Resources{DiskMiB: c.DiskMiB}}
			for i, size := range c.DrivesMiB {
				spec.Drives = append(spec.Drives, api.Drive{Name: fmt.Sprintf("d%d", i), SizeMiB: size})
			}
			if got := fileSizeLimit(spec); got != c.WantBytes {
				t.Errorf("fileSizeLimit() = %d, want %d", got, c.WantBytes)
			}
		})
	}
}
