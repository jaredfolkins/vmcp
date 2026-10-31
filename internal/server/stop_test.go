package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
	"github.com/jaredfolkins/vmcp/internal/machine"
)

var stopTestConfig = flag.String("vmcp-stop-test-config", "testdata/stop.hujson", "HuJSON file for the stop test")

// stopCase is one machine of the stop tests and what its record must show.
type stopCase struct {
	Program           string `json:"program"`
	MachineName       string `json:"machine_name"`
	DeadlineMS        int    `json:"deadline_ms"`
	WantState         string `json:"want_state"`
	WantExitReason    string `json:"want_exit_reason"`
	WantExitDetail    string `json:"want_exit_detail"`
	WantDestroyReason string `json:"want_destroy_reason"`
	WantStartStatus   int    `json:"want_start_status"`
	WantStartCode     string `json:"want_start_code"`
}

type stopTestInput struct {
	StopDuringProvision   stopCase `json:"stop_during_provision"`
	DeleteDuringProvision stopCase `json:"delete_during_provision"`
	StopBeforeStart       stopCase `json:"stop_before_start"`
	Restart               stopCase `json:"restart"`
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
	for name, c := range map[string]stopCase{"stop_during_provision": in.StopDuringProvision,
		"delete_during_provision": in.DeleteDuringProvision, "stop_before_start": in.StopBeforeStart, "restart": in.Restart} {
		if c.Program == "" || c.MachineName == "" || c.DeadlineMS <= 0 || c.WantState == "" {
			t.Fatalf("stop test input %s is incomplete", name)
		}
	}
	return in
}

// newStopManager returns a manager over dir with rt and a context that ends
// at the deadline of c.
func newStopManager(t *testing.T, dir string, rt *fakeRuntime, c stopCase) (*machine.Manager, context.Context) {
	t.Helper()
	mgr, err := machine.New(context.Background(), rt, machine.Config{Dir: dir, MaxMachines: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DeadlineMS)*time.Millisecond)
	t.Cleanup(cancel)
	return mgr, ctx
}

// createStopMachine prepares an image and creates the machine of c without
// starting it.
func createStopMachine(t *testing.T, ctx context.Context, mgr *machine.Manager, c stopCase) api.Machine {
	t.Helper()
	img, err := mgr.CreateImage(ctx, api.ImageRequest{Ref: "example/app@sha256:" + string(bytes.Repeat([]byte("c"), 64))})
	if err != nil {
		t.Fatal(err)
	}
	m, err := mgr.CreateMachine(ctx, api.MachineSpec{Name: c.MachineName, Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 60, Process: api.Process{Args: []string{c.Program}}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// startWhileGated starts m in the background and waits until rt holds it in
// Provision. The returned channel gets the Start result after release.
func startWhileGated(t *testing.T, ctx context.Context, mgr *machine.Manager, rt *fakeRuntime, id string) <-chan error {
	t.Helper()
	started := make(chan error, 1)
	go func() {
		_, err := mgr.StartMachine(ctx, id)
		started <- err
	}()
	select {
	case <-rt.provisioning:
	case <-ctx.Done():
		t.Fatal("StartMachine did not provision the machine")
	}
	return started
}

// TestStopDuringProvisionPreventsBoot proves that a stop that comes while
// vmcp provisions a machine ends the machine before its guest boots. vmcp
// only recorded the stop, because no instance existed yet. It then booted
// the guest, which ran its process to the end or to its timeout.
func TestStopDuringProvisionPreventsBoot(t *testing.T) {
	in := readStopInput(t).StopDuringProvision
	rt := &fakeRuntime{provisioning: make(chan struct{}), release: make(chan struct{})}
	mgr, ctx := newStopManager(t, t.TempDir(), rt, in)
	m := createStopMachine(t, ctx, mgr, in)
	started := startWhileGated(t, ctx, mgr, rt, m.ID)
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

// TestDeleteDuringProvisionNeverBoots proves that a delete that comes while
// vmcp provisions a machine waits for the teardown, returns its proof, and
// that the guest never boots. vmcp removed the record at once and returned
// no proof, and the provisioned guest then booted with no record.
func TestDeleteDuringProvisionNeverBoots(t *testing.T) {
	in := readStopInput(t).DeleteDuringProvision
	rt := &fakeRuntime{provisioning: make(chan struct{}), release: make(chan struct{})}
	mgr, ctx := newStopManager(t, t.TempDir(), rt, in)
	m := createStopMachine(t, ctx, mgr, in)
	started := startWhileGated(t, ctx, mgr, rt, m.ID)
	type deleted struct {
		m   api.Machine
		err error
	}
	deletes := make(chan deleted, 1)
	go func() {
		final, err := mgr.DeleteMachine(ctx, m.ID)
		deletes <- deleted{final, err}
	}()
	// The delete must wait for the machine that vmcp still provisions.
	select {
	case d := <-deletes:
		t.Errorf("DeleteMachine() returned during provisioning: state %s proof %+v, err %v", d.m.State, d.m.Proof, d.err)
		deletes <- d
	case <-time.After(20 * time.Millisecond):
	}
	close(rt.release)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("StartMachine did not return")
	}
	var d deleted
	select {
	case d = <-deletes:
	case <-ctx.Done():
		t.Fatal("DeleteMachine did not return")
	}
	if boots := rt.boots.Load(); boots != 0 {
		t.Errorf("guest boots after a delete during provisioning = %d, want 0", boots)
	}
	if d.err != nil || string(d.m.State) != in.WantState || d.m.Proof == nil || !d.m.Proof.Destroyed ||
		d.m.Proof.DestroyReason != in.WantDestroyReason {
		t.Errorf("DeleteMachine() = state %s proof %+v, err %v; want state %s with a destroyed proof, reason %s",
			d.m.State, d.m.Proof, d.err, in.WantState, in.WantDestroyReason)
	}
	if _, err := mgr.Machine(m.ID); err == nil {
		t.Error("the deleted machine still has a record")
	}
}

// TestStopBeforeStartPreventsStart proves the API of a stop before start:
// the stop ends the machine with a proof and an exit event, and a later
// start fails with HTTP 409 and the conflict code. vmcp ignored such a
// stop, and the start booted the guest.
func TestStopBeforeStartPreventsStart(t *testing.T) {
	in := readStopInput(t).StopBeforeStart
	if in.WantStartStatus == 0 || in.WantStartCode == "" || in.WantExitReason == "" || in.WantDestroyReason == "" {
		t.Fatal("stop_before_start needs want_start_status, want_start_code, want_exit_reason, and want_destroy_reason")
	}
	h := newHarness(t, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.DeadlineMS)*time.Millisecond)
	defer cancel()
	img := h.image(t)
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: in.MachineName, Lifecycle: api.Ephemeral, Image: img,
		TimeoutSeconds: 60, Process: api.Process{Args: []string{in.Program}}})
	if err != nil {
		t.Fatal(err)
	}

	stopped, err := h.c.StopMachine(ctx, m.ID, api.StopRequest{})
	if err != nil {
		t.Fatalf("StopMachine() error = %v", err)
	}
	if string(stopped.State) != in.WantState || stopped.Exit == nil || string(stopped.Exit.Reason) != in.WantExitReason ||
		stopped.Proof == nil || !stopped.Proof.Destroyed || stopped.Proof.DestroyReason != in.WantDestroyReason {
		t.Errorf("StopMachine() = state %s exit %+v proof %+v; want state %s, exit %s, a destroyed proof with reason %s",
			stopped.State, stopped.Exit, stopped.Proof, in.WantState, in.WantExitReason, in.WantDestroyReason)
	}
	_, err = h.c.StartMachine(ctx, m.ID)
	var apiErr *client.Error
	if !errors.As(err, &apiErr) || apiErr.Status != in.WantStartStatus || string(apiErr.Code) != in.WantStartCode {
		t.Errorf("StartMachine() after stop error = %v, want HTTP %d %s", err, in.WantStartStatus, in.WantStartCode)
	}
	if boots := h.rt.boots.Load(); boots != 0 {
		t.Errorf("guest boots after a stop before start = %d, want 0", boots)
	}
	var exit *api.Exit
	if err := h.c.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
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
}

// TestRestartGivesFailedMachinesAProof proves that a machine that ran when
// the vmcp process ended gets a destroyed proof from the next process.
// That process removed every machine resource at start, but the machine
// kept no proof, so its caller could not prove the cleanup.
func TestRestartGivesFailedMachinesAProof(t *testing.T) {
	in := readStopInput(t).Restart
	if in.WantExitReason == "" || in.WantExitDetail == "" || in.WantDestroyReason == "" {
		t.Fatal("restart needs want_exit_reason, want_exit_detail, and want_destroy_reason")
	}
	dir := t.TempDir()
	rt := &fakeRuntime{}
	old, ctx := newStopManager(t, dir, rt, in)
	m := createStopMachine(t, ctx, old, in)
	if _, err := old.StartMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	// The old process ends without a shutdown. Its guest stops later.
	t.Cleanup(func() { _, _ = old.StopMachine(context.Background(), m.ID) })

	next, _ := newStopManager(t, dir, rt, in)
	got, err := next.Machine(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.State) != in.WantState || got.Exit == nil || string(got.Exit.Reason) != in.WantExitReason ||
		got.Exit.Detail != in.WantExitDetail {
		t.Errorf("machine after restart = state %s exit %+v; want state %s, exit %s %q",
			got.State, got.Exit, in.WantState, in.WantExitReason, in.WantExitDetail)
	}
	if got.Proof == nil || !got.Proof.Destroyed || got.Proof.TeardownStatus != "destroyed" ||
		got.Proof.DestroyReason != in.WantDestroyReason || got.Proof.MachineID != m.ID {
		t.Errorf("machine proof after restart = %+v, want a destroyed proof for %s with reason %s",
			got.Proof, m.ID, in.WantDestroyReason)
	}
	if rt.recoveredCount() != 2 {
		t.Errorf("runtime recoveries = %d, want 2", rt.recoveredCount())
	}
}
