//go:build linux

package firecracker

import (
	"bytes"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tailscale/hujson"
)

var (
	nftElementsConfig   = flag.String("vmcp-nft-elements-config", "testdata/nft-elements.hujson", "HuJSON file with nft listings")
	enforcerSweepConfig = flag.String("vmcp-enforcer-sweep-config", "testdata/enforcer-sweep.hujson", "HuJSON file with enforcer sweep cases")
)

func readHuJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

// TestSweepCgroupsLeavesEndingMachines proves that the enforcer does not
// kill a machine whose Firecracker process exited. Its cgroup is empty
// until teardown removes it. The enforcer once called that a posture
// violation and turned a completed run into a security failure.
func TestSweepCgroupsLeavesEndingMachines(t *testing.T) {
	var in struct {
		EndingMachines []struct {
			Name  string `json:"name"`
			Procs string `json:"procs"`
		} `json:"ending_machines"`
	}
	readHuJSON(t, *enforcerSweepConfig, &in)
	if len(in.EndingMachines) == 0 {
		t.Fatal("enforcer sweep input has no cases")
	}
	for _, tc := range in.EndingMachines {
		t.Run(tc.Name, func(t *testing.T) {
			root := t.TempDir()
			r := &Runtime{cfg: Config{CgroupRoot: root, CgroupParent: "vmcp", Logger: slog.New(slog.DiscardHandler)}}
			e := newEnforcer(r)
			m := &Machine{r: r, jailID: "vmcp-0123456789", uid: 400000, log: slog.New(slog.DiscardHandler),
				posture: map[string]any{"ok": true}, done: make(chan struct{})}
			m.cgroup = filepath.Join(r.cgroupParent(), m.jailID)
			if err := os.MkdirAll(m.cgroup, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.cgroup, "cgroup.procs"), []byte(tc.Procs), 0o600); err != nil {
				t.Fatal(err)
			}
			e.add(m)
			e.sweepCgroups()
			if m.killReason != "" {
				t.Fatalf("enforcer killed an ending machine: reason %q", m.killReason)
			}
		})
	}
}

// TestSetElementsReadsEveryProtocolForm proves that the enforcer reads the
// element keys of the guest_allow set whether nft prints the protocol as a
// name or as a number. With a wrong key, every sweep treated the allowed
// traffic of live machines as stray and tried to delete it.
func TestSetElementsReadsEveryProtocolForm(t *testing.T) {
	raw, err := os.ReadFile(*nftElementsConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Listings []struct {
			Name    string          `json:"name"`
			Listing json.RawMessage `json:"listing"`
			Want    []string        `json:"want"`
		} `json:"listings"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(in.Listings) == 0 {
		t.Fatalf("nft elements input: %v", err)
	}
	for _, tc := range in.Listings {
		t.Run(tc.Name, func(t *testing.T) {
			var got []string
			for _, el := range setElements(tc.Listing) {
				got = append(got, el.key())
			}
			if !slices.Equal(got, tc.Want) {
				t.Errorf("element keys = %q, want %q", got, tc.Want)
			}
		})
	}
}
