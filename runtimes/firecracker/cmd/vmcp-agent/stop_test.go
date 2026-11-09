//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/hujson"
)

var stopTestConfig = flag.String("vmcp-agent-stop-config", "testdata/stop.hujson", "HuJSON file for the agent stop test")

type stopTestCase struct {
	Name         string `json:"name"`
	Script       string `json:"script"`
	GraceMS      int    `json:"grace_ms"`
	WaitReady    bool   `json:"wait_ready"`
	RequestFirst bool   `json:"request_first"`
	WantCode     int    `json:"want_code"`
	MinMS        int    `json:"min_ms"`
	MaxMS        int    `json:"max_ms"`
}

func readStopTestCases(t *testing.T) []stopTestCase {
	t.Helper()
	raw, err := os.ReadFile(*stopTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Cases []stopTestCase `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if len(in.Cases) == 0 {
		t.Fatal("agent stop test input has no cases")
	}
	for _, c := range in.Cases {
		if c.Name == "" || c.Script == "" || c.GraceMS <= 0 || c.MaxMS <= 0 {
			t.Fatalf("agent stop case %q is incomplete", c.Name)
		}
	}
	return in.Cases
}

// TestStopperEndsTheProcessGroupGracefully proves the agent side of a
// graceful stop. A stop request sends SIGTERM to the process group, so a
// process that handles it ends by itself well before the grace; SIGKILL
// ends a process that ignores SIGTERM, but only after the grace; and a
// request that comes before the process starts applies when it starts. The
// agent had no stop request: the host killed the guest at once, and writes
// that the guest kernel held in memory never reached the drive tars.
func TestStopperEndsTheProcessGroupGracefully(t *testing.T) {
	for _, c := range readStopTestCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			stdoutR, stdoutW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdoutR.Close() }()
			st := &stopper{}
			grace := time.Duration(c.GraceMS) * time.Millisecond
			if c.RequestFirst {
				st.request(grace)
			}
			start := time.Now()
			proc, err := os.StartProcess("/bin/sh", []string{"/bin/sh", "-c", c.Script}, &os.ProcAttr{
				Files: []*os.File{nil, stdoutW, stdoutW},
				Sys:   &syscall.SysProcAttr{Setsid: true},
			})
			_ = stdoutW.Close()
			if err != nil {
				t.Fatal(err)
			}
			st.started(proc.Pid)
			if c.WaitReady {
				line, err := bufio.NewReader(stdoutR).ReadString('\n')
				if err != nil || line != "ready\n" {
					_ = proc.Kill()
					t.Fatalf("process output = %q, %v; want ready", line, err)
				}
				start = time.Now()
				st.request(grace)
			}
			state, err := proc.Wait()
			elapsed := time.Since(start)
			st.exited()
			if err != nil {
				t.Fatal(err)
			}
			code := state.ExitCode()
			if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
			if c.WantCode >= 0 && code != c.WantCode {
				t.Errorf("exit code = %d, want %d", code, c.WantCode)
			}
			if elapsed < time.Duration(c.MinMS)*time.Millisecond || elapsed > time.Duration(c.MaxMS)*time.Millisecond {
				t.Errorf("process ended after %s, want %d to %d ms", elapsed.Round(time.Millisecond), c.MinMS, c.MaxMS)
			}
		})
	}
}
