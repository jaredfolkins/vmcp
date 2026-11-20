//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

var doneTestConfig = flag.String("vmcp-agent-done-config", "testdata/done.hujson", "HuJSON file for the agent done wait test")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken connection") }

// TestAgentWaitsForTheDoneAnswer proves the last step of the agent before
// it restarts the guest:
//   - the host answer ends the wait with no error;
//   - the end of the host connection, no answer in the limit, and a failed
//     send each end the wait with an error, which the agent writes to the
//     console;
//   - an agent that reads no host messages does not wait.
//
// A failure here detects an agent that restarts the guest before the host
// read the exit report, or an agent that waits without a limit.
func TestAgentWaitsForTheDoneAnswer(t *testing.T) {
	raw, err := os.ReadFile(*doneTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Answer      string `json:"answer"`
		LongWaitMS  int    `json:"long_wait_ms"`
		ShortWaitMS int    `json:"short_wait_ms"`
		MaxMS       int    `json:"max_ms"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.Answer == "" || in.ShortWaitMS <= 0 || in.MaxMS <= in.ShortWaitMS || in.LongWaitMS <= in.MaxMS {
		t.Fatal("done wait input is incomplete")
	}
	long, short := time.Duration(in.LongWaitMS)*time.Millisecond, time.Duration(in.ShortWaitMS)*time.Millisecond

	for _, tc := range []struct {
		name string
		// host is what the host does with its end of the connection.
		host    func(w io.WriteCloser)
		out     io.Writer
		noRead  bool
		wait    time.Duration
		wantErr string
	}{
		{name: "the host answers", host: func(w io.WriteCloser) { _, _ = io.WriteString(w, in.Answer) }, wait: long},
		{name: "the host answers and ends", host: func(w io.WriteCloser) { _, _ = io.WriteString(w, in.Answer); _ = w.Close() }, wait: long},
		{name: "the host connection ends", host: func(w io.WriteCloser) { _ = w.Close() }, wait: long, wantErr: "the host connection ended"},
		{name: "no answer", host: func(io.WriteCloser) {}, wait: short, wantErr: "no answer"},
		{name: "a send failed", host: func(io.WriteCloser) {}, out: failingWriter{}, wait: long, wantErr: "send"},
		{name: "no reader", host: func(io.WriteCloser) {}, noRead: true, wait: long},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostRead, hostWrite := io.Pipe()
			t.Cleanup(func() { _ = hostWrite.Close() })
			out := tc.out
			if out == nil {
				out = io.Discard
			}
			ev := &events{enc: json.NewEncoder(out), r: bufio.NewReader(hostRead),
				acked: make(chan struct{}), gone: make(chan struct{})}
			if !tc.noRead {
				ev.reading = true
				go ev.readHostMessages(&stopper{}, newPorter())
			}
			ev.send(agentproto.Message{Type: agentproto.TypeDone})
			go tc.host(hostWrite)
			start := time.Now()
			err := ev.waitDone(tc.wait)
			if took := time.Since(start); took > time.Duration(in.MaxMS)*time.Millisecond {
				t.Errorf("waitDone() took %s, want at most %d ms", took, in.MaxMS)
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("waitDone() error = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("waitDone() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
