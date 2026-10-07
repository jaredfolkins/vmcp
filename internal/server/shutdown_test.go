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

var shutdownTestConfig = flag.String("vmcp-shutdown-test-config", "testdata/shutdown.hujson", "HuJSON file for the shutdown test")

type shutdownTestInput struct {
	Program        string `json:"program"`
	MachineName    string `json:"machine_name"`
	WantState      string `json:"want_state"`
	WantExitReason string `json:"want_exit_reason"`
	WantExitDetail string `json:"want_exit_detail"`
}

func readShutdownInput(t *testing.T) shutdownTestInput {
	t.Helper()
	raw, err := os.ReadFile(*shutdownTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in shutdownTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.Program == "" || in.MachineName == "" || in.WantState == "" || in.WantExitReason == "" {
		t.Fatal("shutdown test input is incomplete")
	}
	return in
}

// TestShutdownStopsRunningMachines proves that a vmcp shutdown stops a
// running machine with a teardown proof and an exit event, so that an open
// event stream ends instead of holding the shutdown.
func TestShutdownStopsRunningMachines(t *testing.T) {
	in := readShutdownInput(t)
	dir := t.TempDir()
	mgr, err := machine.New(context.Background(), &fakeRuntime{}, machine.Config{Dir: dir, MaxMachines: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	img, err := mgr.CreateImage(ctx, api.ImageRequest{Ref: "example/app@sha256:" + string(bytes.Repeat([]byte("b"), 64))})
	if err != nil {
		t.Fatal(err)
	}
	m, err := mgr.CreateMachine(ctx, api.MachineSpec{Name: in.MachineName, Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 60, Process: api.Process{Args: []string{in.Program}}, Start: true})
	if err != nil {
		t.Fatal(err)
	}
	streamDone := make(chan *api.Exit, 1)
	go func() {
		var exit *api.Exit
		_ = mgr.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
			if ev.Kind == api.EventExit {
				exit = ev.Exit
			}
			return nil
		})
		streamDone <- exit
	}()

	if err := mgr.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case exit := <-streamDone:
		if exit == nil || string(exit.Reason) != in.WantExitReason || exit.Detail != in.WantExitDetail {
			t.Errorf("stream exit = %+v, want reason %s detail %q", exit, in.WantExitReason, in.WantExitDetail)
		}
	case <-ctx.Done():
		t.Fatal("event stream did not end after Shutdown")
	}
	got, err := mgr.Machine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.State) != in.WantState || got.Proof == nil || !got.Proof.Destroyed {
		t.Errorf("machine after Shutdown = state %s proof %+v, want state %s with a destroyed proof", got.State, got.Proof, in.WantState)
	}
}
