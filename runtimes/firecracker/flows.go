//go:build linux

package firecracker

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

// flowEventLimit is the most flow events of one machine. A guest that opens
// connections without end cannot grow its event log without end. The
// brokers keep enforcing the policy after the limit.
const flowEventLimit = 4096

// flowRecorder reports each guest flow of one machine as a machine event
// and a log line. A nil recorder reports nothing.
type flowRecorder struct {
	emit   func(api.Event)
	log    *slog.Logger
	logCtx context.Context

	next    atomic.Uint64
	mu      sync.Mutex
	events  int
	dropped int64
}

func newFlowRecorder(emit func(api.Event), log *slog.Logger, logCtx context.Context) *flowRecorder {
	return &flowRecorder{emit: emit, log: log, logCtx: logCtx}
}

// id returns the next flow ID of the machine.
func (r *flowRecorder) id() uint64 {
	if r == nil {
		return 0
	}
	return r.next.Add(1)
}

// record emits f and logs it: an open flow at DEBUG, every other phase at
// INFO. A denied or failed flow carries the code of the refusal.
func (r *flowRecorder) record(f api.Flow) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.events >= flowEventLimit {
		r.dropped++
		first := r.dropped == 1
		r.mu.Unlock()
		if first {
			r.log.WarnContext(r.logCtx, "guest flow events limited", "code", "flow_events_limited", "limit", flowEventLimit)
			r.emitFlow(api.Flow{Phase: api.FlowLimited, Broker: f.Broker, Proto: f.Proto})
		}
		return
	}
	r.events++
	r.mu.Unlock()
	r.emitFlow(f)
	attrs := []any{"flow", f.ID, "broker", f.Broker, "phase", string(f.Phase), "proto", f.Proto,
		"address", f.Address, "port", f.Port}
	if f.Host != "" {
		attrs = append(attrs, "host", f.Host)
	}
	switch f.Phase {
	case api.FlowOpen:
		r.log.DebugContext(r.logCtx, "guest flow", attrs...)
	case api.FlowDenied:
		attrs = append(attrs, "code", "egress_denied", "reason", f.Reason)
		r.log.InfoContext(r.logCtx, "guest flow", attrs...)
	case api.FlowFailed:
		attrs = append(attrs, "code", "egress_connect_failed", "reason", f.Reason)
		r.log.InfoContext(r.logCtx, "guest flow", attrs...)
	default:
		attrs = append(attrs, "bytes_out", f.BytesOut, "bytes_in", f.BytesIn,
			"duration_ms", trace.Millis(time.Duration(f.DurationMS)*time.Millisecond))
		r.log.InfoContext(r.logCtx, "guest flow", attrs...)
	}
}

func (r *flowRecorder) emitFlow(f api.Flow) {
	if r.emit != nil {
		r.emit(api.Event{Kind: api.EventFlow, Flow: &f})
	}
}

// closeOut logs the count of flow events that the limit dropped.
func (r *flowRecorder) closeOut() {
	if r == nil {
		return
	}
	r.mu.Lock()
	dropped := r.dropped
	r.mu.Unlock()
	if dropped > 0 {
		r.log.InfoContext(r.logCtx, "guest flow events dropped", "dropped", dropped, "limit", flowEventLimit)
	}
}

// flowConn counts the bytes of one connected flow and records its close
// once. Reads are bytes to the guest; writes are bytes from the guest.
type flowConn struct {
	net.Conn
	rec   *flowRecorder
	flow  api.Flow
	start time.Time
	in    atomic.Int64
	out   atomic.Int64
	once  sync.Once
}

// openFlow records f as open and returns c wrapped to record its close.
func openFlow(rec *flowRecorder, c net.Conn, f api.Flow) *flowConn {
	f.Phase = api.FlowOpen
	rec.record(f)
	return &flowConn{Conn: c, rec: rec, flow: f, start: time.Now()}
}

func (c *flowConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	return n, err
}

func (c *flowConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	return n, err
}

// CloseWrite half-closes a TCP flow. It keeps the half-close of splice.
func (c *flowConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *flowConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		f := c.flow
		f.Phase = api.FlowClose
		f.BytesIn, f.BytesOut = c.in.Load(), c.out.Load()
		f.DurationMS = time.Since(c.start).Milliseconds()
		c.rec.record(f)
	})
	return err
}
