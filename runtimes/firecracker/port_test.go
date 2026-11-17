//go:build linux

package firecracker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

var portDialConfig = flag.String("vmcp-port-dial-config", "testdata/port-dial.hujson", "HuJSON file with the port dial case")

// TestDialPortMatchesTheRelayConnection proves the host side of the port
// contract. DialPort sends one connect request for an exposed port on the
// event connection and returns the relay connection whose header has the
// same ID, with no byte of the stream lost. A refusal header gives
// ErrPortRefused. A port that the spec does not expose sends no request. A
// relay connection that no call waits for is closed.
func TestDialPortMatchesTheRelayConnection(t *testing.T) {
	var in struct {
		GuestPort  int    `json:"guest_port"`
		OtherPort  int    `json:"other_port"`
		Payload    string `json:"payload"`
		Refusal    string `json:"refusal"`
		DeadlineMS int    `json:"deadline_ms"`
	}
	readHuJSON(t, *portDialConfig, &in)
	if in.GuestPort <= 0 || in.OtherPort <= 0 || in.Payload == "" || in.Refusal == "" || in.DeadlineMS <= 0 {
		t.Fatal("port dial input is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.DeadlineMS)*time.Millisecond)
	defer cancel()

	hostEvents, agentEvents := net.Pipe()
	defer func() { _ = hostEvents.Close() }()
	defer func() { _ = agentEvents.Close() }()
	m := &Machine{done: make(chan struct{}), eventConn: hostEvents}
	m.spec.Spec.Network.Ports = []api.Port{{Name: "vnc", GuestPort: in.GuestPort, Protocol: api.PortProtocolTCP}}

	// The fake agent answers each connect request. refuse selects a
	// refusal header. It reports the guest port of each request.
	requests := make(chan int, 4)
	refuse := make(chan bool, 4)
	go func() {
		r := bufio.NewReader(agentEvents)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var msg agentproto.Message
			if json.Unmarshal(line, &msg) != nil || msg.Type != agentproto.TypeConnect {
				continue
			}
			requests <- msg.Port
			hostRelay, agentRelay := net.Pipe()
			go m.receivePort(hostRelay)
			header := agentproto.PortHeader{ConnID: msg.ConnID}
			if <-refuse {
				header.Error = in.Refusal
			}
			raw, _ := json.Marshal(header)
			// The header and the first payload go in one write, so the
			// reader must not take a payload byte with the header.
			_, _ = agentRelay.Write(append(append(raw, '\n'), in.Payload...))
			if header.Error != "" {
				_ = agentRelay.Close()
			}
		}
	}()

	refuse <- false
	conn, err := m.DialPort(ctx, in.GuestPort)
	if err != nil {
		t.Fatalf("DialPort() error = %v", err)
	}
	if got := <-requests; got != in.GuestPort {
		t.Fatalf("connect request port = %d, want %d", got, in.GuestPort)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(in.DeadlineMS) * time.Millisecond))
	got := make([]byte, len(in.Payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != in.Payload {
		t.Fatalf("first relayed bytes = %q, error %v; want %q", got, err, in.Payload)
	}
	_ = conn.Close()

	refuse <- true
	if _, err := m.DialPort(ctx, in.GuestPort); !errors.Is(err, machine.ErrPortRefused) {
		t.Fatalf("DialPort() with a refusal header error = %v, want ErrPortRefused", err)
	}
	<-requests

	if _, err := m.DialPort(ctx, in.OtherPort); !errors.Is(err, machine.ErrPortNotExposed) {
		t.Fatalf("DialPort() for a port that is not exposed error = %v, want ErrPortNotExposed", err)
	}
	select {
	case port := <-requests:
		t.Fatalf("a port that is not exposed sent a connect request for %d", port)
	default:
	}

	// A relay connection with an unknown ID is closed.
	hostRelay, agentRelay := net.Pipe()
	go m.receivePort(hostRelay)
	raw, _ := json.Marshal(agentproto.PortHeader{ConnID: "unknown"})
	_ = agentRelay.SetDeadline(time.Now().Add(time.Duration(in.DeadlineMS) * time.Millisecond))
	if _, err := agentRelay.Write(append(raw, '\n')); err != nil {
		t.Fatalf("write unknown header error = %v", err)
	}
	if _, err := agentRelay.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read on an unmatched relay connection error = %v, want EOF", err)
	}
	if len(m.portPending) != 0 {
		t.Fatalf("pending dials = %d, want 0", len(m.portPending))
	}
}
