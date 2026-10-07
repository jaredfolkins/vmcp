package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

var loggingTestConfig = flag.String("vmcp-logging-test-config", "testdata/logging.hujson", "HuJSON file for the logging test")

type loggingTestInput struct {
	CallerTraceparent string `json:"caller_traceparent"`
	ImageRef          string `json:"image_ref"`
	MachineName       string `json:"machine_name"`
	Program           string `json:"program"`
	Requests          []struct {
		Route  string `json:"route"`
		Level  string `json:"level"`
		Status int    `json:"status"`
		Code   string `json:"code"`
	} `json:"requests"`
	MachineLines []string `json:"machine_lines"`
	Probes       []struct {
		Path       string `json:"path"`
		Credential bool   `json:"credential"`
		Status     int    `json:"status"`
		Level      string `json:"level"`
		Code       string `json:"code"`
	} `json:"probes"`
}

func readLoggingInput(t *testing.T) loggingTestInput {
	t.Helper()
	raw, err := os.ReadFile(*loggingTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in loggingTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := trace.Parse(in.CallerTraceparent); !ok || in.ImageRef == "" || in.MachineName == "" ||
		in.Program == "" || len(in.Requests) == 0 || len(in.MachineLines) == 0 || len(in.Probes) == 0 {
		t.Fatal("logging test input is incomplete")
	}
	return in
}

// logCapture is a goroutine-safe log sink of JSON lines.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) lines(t *testing.T) []map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(c.buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// TestLogTracesAMachineFlow proves the vmcp log contract for one machine:
// each API call writes one request line with its route, status, and level;
// every request line and every machine lifecycle line carries the trace ID
// that the caller sent; the response and a client error return that trace;
// and probes log at their own levels. It detects a lost trace, a missing
// lifecycle line, and a wrong level.
func TestLogTracesAMachineFlow(t *testing.T) {
	in := readLoggingInput(t)
	wantTrace := strings.Split(in.CallerTraceparent, "-")[1]
	capture := &logCapture{}
	log := slog.New(trace.NewHandler(slog.NewJSONHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	mgr, err := machine.New(context.Background(), &fakeRuntime{}, machine.Config{Dir: t.TempDir(), MaxMachines: 2, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{Credential: []byte(testCredential), Service: mgr, Logger: log}))
	defer srv.Close()
	c, err := client.New(srv.URL, testCredential, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(client.WithTraceparent(context.Background(), in.CallerTraceparent), 10*time.Second)
	defer cancel()

	img, err := c.CreateImage(ctx, api.ImageRequest{Ref: in.ImageRef})
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.CreateMachine(ctx, api.MachineSpec{Name: in.MachineName, Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 30, Process: api.Process{Args: []string{in.Program}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.StartMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.Events(ctx, m.ID, 0, true, func(api.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	_, err = c.GetMachine(ctx, m.ID)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.TraceID != wantTrace {
		t.Fatalf("GetMachine() of a deleted machine error = %v, want a client error with trace %s", err, wantTrace)
	}
	for _, p := range in.Probes {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+p.Path, nil)
		req.Header.Set(api.HeaderTraceparent, in.CallerTraceparent)
		if p.Credential {
			req.Header.Set("Authorization", "Bearer "+testCredential)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != p.Status {
			t.Fatalf("GET %s status = %d, want %d", p.Path, resp.StatusCode, p.Status)
		}
		if got := resp.Header.Get(api.HeaderTraceparent); !strings.HasPrefix(got, "00-"+wantTrace+"-") {
			t.Errorf("GET %s traceparent = %q, want the caller trace %s", p.Path, got, wantTrace)
		}
	}

	lines := capture.lines(t)
	var requests []map[string]any
	byMsg := map[string]map[string]any{}
	for _, l := range lines {
		if l["msg"] == "api request" {
			requests = append(requests, l)
		}
		if msg, _ := l["msg"].(string); msg != "" && byMsg[msg] == nil {
			byMsg[msg] = l
		}
	}
	if len(requests) != len(in.Requests)+len(in.Probes) {
		t.Fatalf("got %d request lines, want %d", len(requests), len(in.Requests)+len(in.Probes))
	}
	for i, want := range in.Requests {
		got := requests[i]
		if got["route"] != want.Route || got["level"] != want.Level || got["status"] != float64(want.Status) ||
			got["trace_id"] != wantTrace || got["machine"] == nil && strings.Contains(want.Route, "{id}") {
			t.Errorf("request line %d = %v, want route %s level %s status %d trace %s", i, got, want.Route, want.Level, want.Status, wantTrace)
		}
		if want.Code != "" && got["code"] != want.Code {
			t.Errorf("request line %d code = %v, want %s", i, got["code"], want.Code)
		}
	}
	for i, want := range in.Probes {
		got := requests[len(in.Requests)+i]
		if got["level"] != want.Level || got["status"] != float64(want.Status) || want.Code != "" && got["code"] != want.Code {
			t.Errorf("probe line for %s = %v, want level %s status %d code %q", want.Path, got, want.Level, want.Status, want.Code)
		}
	}
	for _, msg := range in.MachineLines {
		got := byMsg[msg]
		if got == nil || got["trace_id"] != wantTrace || got["machine"] != m.ID {
			t.Errorf("%q line = %v, want machine %s and trace %s", msg, got, m.ID, wantTrace)
		}
	}
	if ended := byMsg["machine ended"]; ended["level"] != "INFO" || ended["exit_reason"] != string(api.ExitCompleted) ||
		ended["teardown_status"] != "destroyed" || ended["machine_name"] != in.MachineName {
		t.Errorf("machine ended line = %v", ended)
	}
}
