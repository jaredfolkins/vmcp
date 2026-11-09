package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
)

var gracefulStopTestConfig = flag.String("vmcp-graceful-stop-test-config", "testdata/graceful-stop.hujson",
	"HuJSON file for the graceful stop test")

type gracefulStopTestInput struct {
	DeadlineMS              int    `json:"deadline_ms"`
	RequestedTimeoutSeconds int64  `json:"requested_timeout_seconds"`
	DefaultGraceMS          int    `json:"default_grace_ms"`
	TooLongTimeoutSeconds   int64  `json:"too_long_timeout_seconds"`
	WantInvalidCode         string `json:"want_invalid_code"`
	MachineTimeoutSeconds   int    `json:"machine_timeout_seconds"`
	OutputLimitBytes        int64  `json:"output_limit_bytes"`
}

func readGracefulStopInput(t *testing.T) gracefulStopTestInput {
	t.Helper()
	raw, err := os.ReadFile(*gracefulStopTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in gracefulStopTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.DeadlineMS <= 0 || in.RequestedTimeoutSeconds <= 0 || in.DefaultGraceMS <= 0 || in.TooLongTimeoutSeconds <= 0 ||
		in.WantInvalidCode == "" || in.MachineTimeoutSeconds <= 0 || in.OutputLimitBytes <= 0 {
		t.Fatal("graceful stop test input is incomplete")
	}
	return in
}

// TestStopsAreGracefulWithTheirGrace proves which machine ends are graceful
// and with which grace. A stop request uses its timeout as the grace, or the
// default without one; a grace above the limit is refused and the machine
// keeps running; a machine timeout and an output limit stop with the
// default grace; a delete stays an immediate kill. vmcp ignored the stop
// request body and killed every guest at once, so writes that the guest
// kernel still held in memory were lost.
func TestStopsAreGracefulWithTheirGrace(t *testing.T) {
	in := readGracefulStopInput(t)
	h := newHarness(t, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.DeadlineMS)*time.Millisecond)
	defer cancel()
	img := h.image(t)
	defaultGrace := time.Duration(in.DefaultGraceMS) * time.Millisecond
	run := func(name, program string, timeout int, outputLimit int64) api.Machine {
		t.Helper()
		m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: name, Lifecycle: api.Ephemeral, Image: img,
			TimeoutSeconds: int64(timeout), OutputLimitBytes: outputLimit, Process: api.Process{Args: []string{program}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.c.StartMachine(ctx, m.ID); err != nil {
			t.Fatal(err)
		}
		return m
	}
	waitExit := func(id string) api.Machine {
		t.Helper()
		for {
			m, err := h.c.GetMachine(ctx, id)
			if err == nil && m.State == api.StateExited {
				return m
			}
			select {
			case <-ctx.Done():
				t.Fatalf("machine %s did not end; last state %s, err %v", id, m.State, err)
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	requested := run("graceful-requested", "hang", 60, 0)
	if _, err := h.c.StopMachine(ctx, requested.ID, api.StopRequest{TimeoutSeconds: in.RequestedTimeoutSeconds}); err != nil {
		t.Fatalf("StopMachine(timeout %d) error = %v", in.RequestedTimeoutSeconds, err)
	}
	defaulted := run("graceful-default", "hang", 60, 0)
	if _, err := h.c.StopMachine(ctx, defaulted.ID, api.StopRequest{}); err != nil {
		t.Fatalf("StopMachine() error = %v", err)
	}
	refused := run("graceful-refused", "hang", 60, 0)
	_, err := h.c.StopMachine(ctx, refused.ID, api.StopRequest{TimeoutSeconds: in.TooLongTimeoutSeconds})
	var cerr *client.Error
	if !errors.As(err, &cerr) || string(cerr.Code) != in.WantInvalidCode {
		t.Fatalf("StopMachine(timeout %d) error = %v, want code %s", in.TooLongTimeoutSeconds, err, in.WantInvalidCode)
	}
	if m, err := h.c.GetMachine(ctx, refused.ID); err != nil || m.State != api.StateRunning {
		t.Fatalf("machine after a refused stop = %s, %v; want running", m.State, err)
	}
	if _, err := h.c.DeleteMachine(ctx, refused.ID); err != nil {
		t.Fatalf("DeleteMachine() error = %v", err)
	}
	timedOut := run("graceful-timeout", "hang", in.MachineTimeoutSeconds, 0)
	limited := run("graceful-output-limit", "flood", 60, in.OutputLimitBytes)

	for _, c := range []struct {
		id         string
		wantReason api.ExitReason
	}{
		{requested.ID, api.ExitStopped}, {defaulted.ID, api.ExitStopped},
		{timedOut.ID, api.ExitTimeout}, {limited.ID, api.ExitOutputLimit},
	} {
		if m := waitExit(c.id); m.Exit == nil || m.Exit.Reason != c.wantReason {
			t.Errorf("machine %s exit = %+v, want reason %s", c.id, m.Exit, c.wantReason)
		}
	}
	want := []fakeStop{
		{reason: "stopped", grace: time.Duration(in.RequestedTimeoutSeconds) * time.Second},
		{reason: "stopped", grace: defaultGrace},
		{reason: "timeout", grace: defaultGrace},
		{reason: "output-limit", grace: defaultGrace},
	}
	got := h.rt.stopCalls()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("graceful stops %+v miss %+v", got, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("graceful stops = %+v, want exactly %+v: a delete must stay an immediate kill", got, want)
	}
}
