//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/api"
)

var flowsConfig = flag.String("vmcp-flows-config", "testdata/flows.hujson", "HuJSON file with flow recorder inputs")

type flowsInput struct {
	Flow      api.Flow `json:"flow"`
	Out       string   `json:"out"`
	In        string   `json:"in"`
	OverLimit int      `json:"over_limit"`
	OrigDst   []string `json:"orig_dst"`
}

// flowSink keeps the flow events of a recorder.
type flowSink struct {
	mu    sync.Mutex
	flows []api.Flow
}

func (s *flowSink) event(ev api.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Kind == api.EventFlow && ev.Flow != nil {
		s.flows = append(s.flows, *ev.Flow)
	}
}

// TestFlowConnRecordsOneCloseWithBytes proves that a connected flow has one
// open and one close event, that the close counts the bytes of each
// direction, and that a second close records nothing. A wrong count hides
// the traffic of a guest; a second close event doubles it.
func TestFlowConnRecordsOneCloseWithBytes(t *testing.T) {
	var in flowsInput
	readHuJSON(t, *flowsConfig, &in)
	sink := &flowSink{}
	var logs bytes.Buffer
	rec := newFlowRecorder(sink.event, slog.New(slog.NewJSONHandler(&logs, nil)), context.Background())
	guestSide, upSide := net.Pipe()
	flow := in.Flow
	flow.ID = rec.id()
	fc := openFlow(rec, guestSide, flow)
	go func() {
		buf := make([]byte, len(in.Out))
		_, _ = io.ReadFull(upSide, buf)
		_, _ = upSide.Write([]byte(in.In))
	}()
	if _, err := fc.Write([]byte(in.Out)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(fc, make([]byte, len(in.In))); err != nil {
		t.Fatal(err)
	}
	_ = fc.Close()
	_ = fc.Close()
	_ = upSide.Close()

	if len(sink.flows) != 2 {
		t.Fatalf("flow events = %+v, want open and close", sink.flows)
	}
	open, closed := sink.flows[0], sink.flows[1]
	if open.Phase != api.FlowOpen || closed.Phase != api.FlowClose || open.ID != closed.ID || open.ID == 0 {
		t.Errorf("flow events = %+v, want open then close of one flow", sink.flows)
	}
	if closed.BytesOut != int64(len(in.Out)) || closed.BytesIn != int64(len(in.In)) {
		t.Errorf("close bytes out/in = %d/%d, want %d/%d", closed.BytesOut, closed.BytesIn, len(in.Out), len(in.In))
	}
	if closed.Address != in.Flow.Address || closed.Port != in.Flow.Port || closed.Broker != in.Flow.Broker {
		t.Errorf("close flow = %+v, want the destination of %+v", closed, in.Flow)
	}
	if n := strings.Count(logs.String(), `"msg":"guest flow"`); n != 1 {
		t.Errorf("guest flow INFO lines = %d, want 1 (the close); log: %s", n, logs.String())
	}
}

// TestFlowRecorderLimit proves that a guest cannot grow its event log
// without end: past the limit, the recorder emits one limited event, logs
// one warning, and counts the rest.
func TestFlowRecorderLimit(t *testing.T) {
	var in flowsInput
	readHuJSON(t, *flowsConfig, &in)
	sink := &flowSink{}
	var logs bytes.Buffer
	rec := newFlowRecorder(sink.event, slog.New(slog.NewJSONHandler(&logs, nil)), context.Background())
	for range flowEventLimit + in.OverLimit {
		f := in.Flow
		f.ID, f.Phase, f.Reason = rec.id(), api.FlowDenied, "address_not_public"
		rec.record(f)
	}
	rec.closeOut()
	if len(sink.flows) != flowEventLimit+1 {
		t.Fatalf("flow events = %d, want %d", len(sink.flows), flowEventLimit+1)
	}
	if last := sink.flows[len(sink.flows)-1]; last.Phase != api.FlowLimited {
		t.Errorf("last flow event = %+v, want limited", last)
	}
	if n := strings.Count(logs.String(), `"code":"flow_events_limited"`); n != 1 {
		t.Errorf("flow_events_limited lines = %d, want 1", n)
	}
	if !strings.Contains(logs.String(), `"dropped":`+strconv.Itoa(in.OverLimit)) {
		t.Errorf("no dropped count %d in the log", in.OverLimit)
	}
}

// TestOrigDstReadsTPROXYDestination proves that the gateway reads the
// destination that the guest chose from IP_ORIGDSTADDR. A wrong port byte
// order sends a guest flow to another service.
func TestOrigDstReadsTPROXYDestination(t *testing.T) {
	var in flowsInput
	readHuJSON(t, *flowsConfig, &in)
	for _, s := range in.OrigDst {
		want := netip.MustParseAddrPort(s)
		got, ok := origDst(origDstControl(want))
		if !ok || got != want {
			t.Errorf("origDst() = %v, %t, want %v", got, ok, want)
		}
	}
	if _, ok := origDst(nil); ok {
		t.Error("origDst() of no control message is ok")
	}
}

// origDstControl builds the IP_ORIGDSTADDR control message of dst.
func origDstControl(dst netip.AddrPort) []byte {
	sa := make([]byte, unix.SizeofSockaddrInet4)
	binary.LittleEndian.PutUint16(sa[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(sa[2:4], dst.Port())
	a := dst.Addr().As4()
	copy(sa[4:8], a[:])
	b := make([]byte, unix.CmsgSpace(len(sa)))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = unix.SOL_IP, unix.IP_ORIGDSTADDR
	h.SetLen(unix.CmsgLen(len(sa)))
	copy(b[unix.CmsgLen(0):], sa)
	return b
}
