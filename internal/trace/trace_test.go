package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

var testConfig = flag.String("vmcp-trace-test-config", "testdata/trace.hujson", "HuJSON file for the trace tests")

type testInput struct {
	Parse []struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		OK       bool   `json:"ok"`
		TraceID  string `json:"trace_id"`
		ParentID string `json:"parent_id"`
	} `json:"parse"`
	CallerTraceparent string `json:"caller_traceparent"`
}

func readInput(t *testing.T) testInput {
	t.Helper()
	raw, err := os.ReadFile(*testConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in testInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if len(in.Parse) == 0 || in.CallerTraceparent == "" {
		t.Fatal("trace test input needs parse cases and caller_traceparent")
	}
	return in
}

// TestParse proves that vmcp continues only a valid W3C version 00
// traceparent. A wrong value starts a new trace instead.
func TestParse(t *testing.T) {
	for _, tc := range readInput(t).Parse {
		t.Run(tc.Name, func(t *testing.T) {
			traceID, parentID, ok := Parse(tc.Value)
			if ok != tc.OK {
				t.Fatalf("Parse(%q) ok = %v, want %v", tc.Value, ok, tc.OK)
			}
			if !ok {
				return
			}
			if got := (&Span{traceID: traceID}).TraceID(); got != tc.TraceID {
				t.Errorf("trace ID = %s, want %s", got, tc.TraceID)
			}
			if got := (&Span{spanID: parentID}).SpanID(); got != tc.ParentID {
				t.Errorf("parent ID = %s, want %s", got, tc.ParentID)
			}
		})
	}
}

// TestSpansShareTheCallerTrace proves that a remote span and its child keep
// the caller trace ID, that the handler adds trace_id and span_id only to
// records logged with a span context, and that a detached context keeps
// the trace after the request context ends.
func TestSpansShareTheCallerTrace(t *testing.T) {
	in := readInput(t)
	wantTrace, _, _ := Parse(in.CallerTraceparent)
	var buf bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	reqCtx, cancel := context.WithCancel(context.Background())
	ctx, root := StartRemote(reqCtx, log, "api", in.CallerTraceparent)
	childCtx, child := Start(ctx, log, "step")
	child.End(errors.New("step failed"))
	detached := Detach(childCtx)
	cancel()
	log.InfoContext(detached, "after request")
	log.Info("no trace")

	if root.TraceID() != (&Span{traceID: wantTrace}).TraceID() || child.TraceID() != root.TraceID() {
		t.Fatalf("trace IDs root=%s child=%s, want the caller trace", root.TraceID(), child.TraceID())
	}
	if !strings.HasPrefix(root.Traceparent(), "00-"+root.TraceID()+"-"+root.SpanID()) {
		t.Fatalf("Traceparent() = %s", root.Traceparent())
	}
	if detached.Err() != nil {
		t.Fatalf("detached context error = %v, want none", detached.Err())
	}
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d log lines, want 3: %s", len(lines), buf.String())
	}
	span, after, plain := lines[0], lines[1], lines[2]
	if span["msg"] != "span" || span["level"] != "DEBUG" || span["span"] != "step" || span["outcome"] != "error" ||
		span["error"] != "step failed" || span["parent_span_id"] != root.SpanID() || span["span_id"] != child.SpanID() {
		t.Errorf("span line = %v", span)
	}
	if after["trace_id"] != root.TraceID() || after["span_id"] != child.SpanID() {
		t.Errorf("detached line = %v, want trace %s span %s", after, root.TraceID(), child.SpanID())
	}
	if _, ok := plain["trace_id"]; ok {
		t.Errorf("line without a span context has trace_id: %v", plain)
	}
}
