//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

var portTestConfig = flag.String("vmcp-agent-port-config", "testdata/port.hujson", "HuJSON file for the agent port test")

type portTestInput struct {
	ExposedPort int    `json:"exposed_port"`
	OtherPort   int    `json:"other_port"`
	ConnID      string `json:"conn_id"`
	Payload     string `json:"payload"`
	WantRefusal string `json:"want_refusal"`
	DeadlineMS  int    `json:"deadline_ms"`
}

func readPortTestInput(t *testing.T) portTestInput {
	t.Helper()
	raw, err := os.ReadFile(*portTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in portTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.ExposedPort <= 0 || in.OtherPort <= 0 || in.ConnID == "" || in.Payload == "" || in.WantRefusal == "" || in.DeadlineMS <= 0 {
		t.Fatal("agent port test input is incomplete")
	}
	return in
}

// portTestPorter returns a porter whose host side is hostEnd and whose guest
// dials are recorded in dialed. A guest dial returns one end of a pipe; the
// other end echoes every byte, as a guest service would.
func portTestPorter(agentEnd net.Conn, dialed *[]int) *porter {
	return &porter{
		dialHost: func() (io.ReadWriteCloser, error) { return agentEnd, nil },
		dialGuest: func(port int) (io.ReadWriteCloser, error) {
			*dialed = append(*dialed, port)
			agentSide, service := net.Pipe()
			go func() {
				_, _ = io.Copy(service, service)
				_ = service.Close()
			}()
			return agentSide, nil
		},
	}
}

func readPortTestHeader(t *testing.T, r *bufio.Reader) agentproto.PortHeader {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read port header: %v", err)
	}
	var header agentproto.PortHeader
	if err := json.Unmarshal(line, &header); err != nil {
		t.Fatalf("decode port header %q: %v", line, err)
	}
	return header
}

// TestPorterRelaysOnlyExposedPorts proves the guest side of the port
// contract. A connect request for an exposed port sends the header with the
// request ID and then relays bytes in both directions. A request for a port
// that the configuration does not expose gets a refusal header, and the
// agent connects to no guest process. Without this check, a host message
// could reach any guest loopback service.
func TestPorterRelaysOnlyExposedPorts(t *testing.T) {
	in := readPortTestInput(t)
	deadline := time.Now().Add(time.Duration(in.DeadlineMS) * time.Millisecond)

	t.Run("exposed port", func(t *testing.T) {
		hostEnd, agentEnd := net.Pipe()
		defer func() { _ = hostEnd.Close() }()
		_ = hostEnd.SetDeadline(deadline)
		var dialed []int
		p := portTestPorter(agentEnd, &dialed)
		p.allow([]int{in.ExposedPort})
		done := make(chan struct{})
		go func() {
			p.connect(in.ConnID, in.ExposedPort)
			close(done)
		}()
		r := bufio.NewReader(hostEnd)
		if header := readPortTestHeader(t, r); header.ConnID != in.ConnID || header.Error != "" {
			t.Fatalf("header = %+v, want conn ID %q and no error", header, in.ConnID)
		}
		if _, err := io.WriteString(hostEnd, in.Payload); err != nil {
			t.Fatalf("write error = %v", err)
		}
		got := make([]byte, len(in.Payload))
		if _, err := io.ReadFull(r, got); err != nil || string(got) != in.Payload {
			t.Fatalf("relayed bytes = %q, error %v; want %q", got, err, in.Payload)
		}
		_ = hostEnd.Close()
		<-done
		if len(dialed) != 1 || dialed[0] != in.ExposedPort {
			t.Fatalf("guest dials = %v, want [%d]", dialed, in.ExposedPort)
		}
		if p.active != 0 {
			t.Fatalf("active relays after close = %d, want 0", p.active)
		}
	})

	t.Run("port that is not exposed", func(t *testing.T) {
		hostEnd, agentEnd := net.Pipe()
		defer func() { _ = hostEnd.Close() }()
		_ = hostEnd.SetDeadline(deadline)
		var dialed []int
		p := portTestPorter(agentEnd, &dialed)
		p.allow([]int{in.ExposedPort})
		go p.connect(in.ConnID, in.OtherPort)
		r := bufio.NewReader(hostEnd)
		if header := readPortTestHeader(t, r); header.ConnID != in.ConnID || header.Error != in.WantRefusal {
			t.Fatalf("header = %+v, want conn ID %q and error %q", header, in.ConnID, in.WantRefusal)
		}
		if _, err := r.ReadByte(); err != io.EOF {
			t.Fatalf("read after refusal error = %v, want EOF", err)
		}
		if len(dialed) != 0 {
			t.Fatalf("guest dials = %v, want none", dialed)
		}
	})
}
