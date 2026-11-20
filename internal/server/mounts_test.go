package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
)

var mountsTestConfig = flag.String("vmcp-mounts-test-config", "testdata/mounts.hujson", "HuJSON file for the mount validation test")

type mountsTestInput struct {
	Upstreams []api.Upstream `json:"upstreams"`
	Cases     []struct {
		Name  string    `json:"name"`
		Mount api.Mount `json:"mount"`
		// Drives and Mounts are the other drives and mounts of the spec.
		Drives []api.Drive `json:"drives"`
		Mounts []api.Mount `json:"mounts"`
		Valid  bool        `json:"valid"`
	} `json:"cases"`
}

func readMountsInput(t *testing.T) mountsTestInput {
	t.Helper()
	raw, err := os.ReadFile(*mountsTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in mountsTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if len(in.Upstreams) == 0 || len(in.Cases) == 0 {
		t.Fatal("mount validation test input is incomplete")
	}
	return in
}

// TestCreateValidatesMounts proves that the create route accepts an object
// mount on an upstream of the spec and refuses one with an unknown
// upstream, a write to an upstream without allow_write, an unclean or
// relative guest or upstream path, the guest root, no max_bytes, or an
// uploads count out of range. It also refuses a mount that shares a guest
// folder tree with a drive or with a different mount.
func TestCreateValidatesMounts(t *testing.T) {
	in := readMountsInput(t)
	h := newHarness(t, t.TempDir())
	img := h.image(t)
	for i, c := range in.Cases {
		t.Run(c.Name, func(t *testing.T) {
			m, err := h.c.CreateMachine(context.Background(), api.MachineSpec{
				Name: fmt.Sprintf("mount-%d", i), Lifecycle: api.Ephemeral, Image: img, TimeoutSeconds: 30,
				Network: api.Network{Upstreams: in.Upstreams},
				Drives:  c.Drives,
				Mounts:  append(append([]api.Mount(nil), c.Mounts...), c.Mount),
			})
			if err == nil {
				// The harness has few machine slots. An accepted machine
				// gives its slot back.
				if _, err := h.c.DeleteMachine(context.Background(), m.ID); err != nil {
					t.Fatalf("DeleteMachine() error = %v", err)
				}
			}
			switch {
			case c.Valid && err != nil:
				t.Errorf("CreateMachine() error = %v, want the mount accepted", err)
			case !c.Valid && !client.IsCode(err, api.ErrInvalidRequest):
				t.Errorf("CreateMachine() error = %v, want invalid_request", err)
			}
		})
	}
}
