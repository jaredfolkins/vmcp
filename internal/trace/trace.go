// Package trace carries W3C trace context through vmcp and records spans as
// log lines. vmcp has no trace exporter: its JSON log is the trace record.
// A caller that sends a traceparent header finds every vmcp line of its
// request, and of the machine work that the request started, by trace_id.
//
// The span lives in the context.Context. NewHandler adds trace_id and
// span_id to every record that is logged with that context, so code logs
// with the slog Context methods and never adds trace attributes itself.
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"math"
	"time"
)

// Header is the W3C trace context request and response header. It equals
// api.HeaderTraceparent.
const Header = "traceparent"

// maxErrorBytes bounds the error text in a span line.
const maxErrorBytes = 512

// Span is one timed operation in a trace.
type Span struct {
	traceID [16]byte
	spanID  [8]byte
	parent  [8]byte
	name    string
	start   time.Time
	log     *slog.Logger
	ctx     context.Context
}

type contextKey struct{}

// Start begins a span named name as a child of the span in ctx. Without a
// span in ctx it begins a new trace. End logs the span line to log. The
// returned context carries the span.
func Start(ctx context.Context, log *slog.Logger, name string) (context.Context, *Span) {
	s := &Span{name: name, start: time.Now(), log: logger(log)}
	if parent := FromContext(ctx); parent != nil {
		s.traceID, s.parent = parent.traceID, parent.spanID
	} else {
		s.traceID = newTraceID()
	}
	s.spanID = newSpanID()
	s.ctx = context.WithValue(ctx, contextKey{}, s)
	return s.ctx, s
}

// StartRemote begins a span that continues the trace of a caller's
// traceparent value. An empty or invalid value begins a new trace.
func StartRemote(ctx context.Context, log *slog.Logger, name, traceparent string) (context.Context, *Span) {
	if traceID, parentID, ok := Parse(traceparent); ok {
		ctx = context.WithValue(ctx, contextKey{}, &Span{traceID: traceID, spanID: parentID})
	} else {
		ctx = context.WithValue(ctx, contextKey{}, (*Span)(nil))
	}
	return Start(ctx, log, name)
}

// FromContext returns the span of ctx, or nil.
func FromContext(ctx context.Context) *Span {
	s, _ := ctx.Value(contextKey{}).(*Span)
	return s
}

// Detach returns a context with the span of ctx and without its
// cancellation and deadline. Work that outlives a request, such as a
// running machine, logs with it so that its lines keep the request trace.
func Detach(ctx context.Context) context.Context {
	return context.WithValue(context.Background(), contextKey{}, FromContext(ctx))
}

// TraceID returns the trace ID as 32 lowercase hex digits.
func (s *Span) TraceID() string { return hex.EncodeToString(s.traceID[:]) }

// SpanID returns the span ID as 16 lowercase hex digits.
func (s *Span) SpanID() string { return hex.EncodeToString(s.spanID[:]) }

// Traceparent returns the W3C traceparent value of the span.
func (s *Span) Traceparent() string {
	return "00-" + s.TraceID() + "-" + s.SpanID() + "-01"
}

// Elapsed returns the time since the span began.
func (s *Span) Elapsed() time.Duration { return time.Since(s.start) }

// End records the span as one DEBUG line with its name, parent, duration,
// and outcome, and returns its duration. The caller emits the primary
// diagnostic of a failure; the span line is the step timing record. err
// must hold only safe facts that vmcp built.
func (s *Span) End(err error, attrs ...any) time.Duration {
	d := s.Elapsed()
	attrs = append(attrs, "span", s.name, "duration_ms", Millis(d))
	if s.parent != [8]byte{} {
		attrs = append(attrs, "parent_span_id", hex.EncodeToString(s.parent[:]))
	}
	if err != nil {
		attrs = append(attrs, "outcome", "error", "error", BoundedError(err))
	} else {
		attrs = append(attrs, "outcome", "ok")
	}
	s.log.DebugContext(s.ctx, "span", attrs...)
	return d
}

// Millis returns d in milliseconds rounded to two decimals.
func Millis(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Millisecond)*100) / 100
}

// BoundedError returns the error text cut to a safe log size.
func BoundedError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > maxErrorBytes {
		s = s[:maxErrorBytes]
	}
	return s
}

// Parse reads a W3C traceparent value of version 00. It refuses all-zero
// IDs, uppercase hex, and every other version.
func Parse(v string) (traceID [16]byte, parentID [8]byte, ok bool) {
	if len(v) != 55 || v[:3] != "00-" || v[35] != '-' || v[52] != '-' {
		return traceID, parentID, false
	}
	if !lowerHex(v[3:35]) || !lowerHex(v[36:52]) || !lowerHex(v[53:55]) {
		return traceID, parentID, false
	}
	_, _ = hex.Decode(traceID[:], []byte(v[3:35]))
	_, _ = hex.Decode(parentID[:], []byte(v[36:52]))
	if traceID == [16]byte{} || parentID == [8]byte{} {
		return [16]byte{}, [8]byte{}, false
	}
	return traceID, parentID, true
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func newTraceID() [16]byte {
	var id [16]byte
	for id == [16]byte{} {
		_, _ = rand.Read(id[:])
	}
	return id
}

func newSpanID() [8]byte {
	var id [8]byte
	for id == [8]byte{} {
		_, _ = rand.Read(id[:])
	}
	return id
}

// handler adds the trace_id and span_id of the record context.
type handler struct{ next slog.Handler }

// NewHandler returns a handler that adds trace_id and span_id to each record
// whose context carries a span, then passes the record to next.
func NewHandler(next slog.Handler) slog.Handler { return handler{next: next} }

func (h handler) Enabled(ctx context.Context, level slog.Level) bool { return h.next.Enabled(ctx, level) }

func (h handler) Handle(ctx context.Context, r slog.Record) error {
	if s := FromContext(ctx); s != nil {
		r = r.Clone()
		r.AddAttrs(slog.String("trace_id", s.TraceID()), slog.String("span_id", s.SpanID()))
	}
	return h.next.Handle(ctx, r)
}

func (h handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return handler{next: h.next.WithAttrs(attrs)}
}

func (h handler) WithGroup(name string) slog.Handler { return handler{next: h.next.WithGroup(name)} }

func logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return l
}
