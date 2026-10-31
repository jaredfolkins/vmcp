package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
)

var stopTestConfig = flag.String("vmcp-stop-test-config", "testdata/stop.hujson", "HuJSON file for the stop test")

type stopTestInput struct {
	Program        string `json:"program"`
	MachineName    string `json:"machine_name"`
	DeadlineMS     int    `json:"deadline_ms"`
	WantState      string `json:"want_state"`
	WantExitReason string `json:"want_exit_reason"`
}

func readStopInput(t *testing.T) stopTestInput {
	t.Helper()
	raw, err := os.ReadFile(*stopTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in stopTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.Program == "" || in.MachineName == "" || in.DeadlineMS <= 0 || in.WantState == "" || in.WantExitReason == "" {
		t.Fatal("stop test input is incomplete")
	}
	return in
}

// TestStopDuringProvisionPreventsBoot proves that a stop that comes while
// vmcp provisions a machine ends the machine before its guest boots. vmcp
// only recorded the stop, because no instance existed yet. It then booted
// the guest, which ran its process to the end or to its timeout.
func TestStopDuringProvisionPreventsBoot(t *testing.T) {
	in := readStopInput(t)
	rt := &fakeRuntime{provisioning: make(chan struct{}), release: make(chan struct{})}
	mgr, err := machine.New(context.Background(), rt, machine.Config{Dir: t.TempDir(), MaxMachines: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.DeadlineMS)*time.Millisecond)
	defer cancel()
	img, err := mgr.CreateImage(ctx, api.ImageRequest{Ref: "example/app@sha256:" + string(bytes.Repeat([]byte("c"), 64))})
	if err != nil {
		t.Fatal(err)
	}
	m, err := mgr.CreateMachine(ctx, api.MachineSpec{Name: in.MachineName, Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 60, Process: api.Process{Args: []string{in.Program}}})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		_, err := mgr.StartMachine(ctx, m.ID)
		started <- err
	}()
	select {
	case <-rt.provisioning:
	case <-ctx.Done():
		t.Fatal("StartMachine did not provision the machine")
	}
	if _, err := mgr.StopMachine(ctx, m.ID); err != nil {
		t.Fatalf("StopMachine() error = %v", err)
	}
	close(rt.release)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("StartMachine did not return")
	}
	if boots := rt.boots.Load(); boots != 0 {
		t.Errorf("guest boots after a stop during provisioning = %d, want 0", boots)
	}
	var exit *api.Exit
	if err := mgr.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
		if ev.Kind == api.EventExit {
			exit = ev.Exit
		}
		return nil
	}); err != nil {
		t.Fatalf("event stream did not end: %v", err)
	}
	if exit == nil || string(exit.Reason) != in.WantExitReason {
		t.Errorf("stream exit = %+v, want reason %s", exit, in.WantExitReason)
	}
	got, err := mgr.Machine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.State) != in.WantState || got.Proof == nil || !got.Proof.Destroyed {
		t.Errorf("machine after the stop = state %s proof %+v, want state %s with a destroyed proof",
			got.State, got.Proof, in.WantState)
	}
	if _, err := mgr.DeleteMachine(context.Background(), m.ID); err != nil {
		t.Errorf("DeleteMachine() error = %v", err)
	}
}
