package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
)

var portsTestConfig = flag.String("vmcp-ports-test-config", "testdata/ports.hujson", "HuJSON file for the ports test")

type portsTestInput struct {
	Relay struct {
		Program            string `json:"program"`
		MachineName        string `json:"machine_name"`
		DeadlineMS         int    `json:"deadline_ms"`
		PortName           string `json:"port_name"`
		GuestPort          int    `json:"guest_port"`
		RefusedPortName    string `json:"refused_port_name"`
		RefusedGuestPort   int    `json:"refused_guest_port"`
		UnknownPortName    string `json:"unknown_port_name"`
		Payload            string `json:"payload"`
		WantEndpointSuffix string `json:"want_endpoint_suffix"`
	} `json:"relay"`
	InvalidSpecs []struct {
		Name  string     `json:"name"`
		Ports []api.Port `json:"ports"`
	} `json:"invalid_specs"`
}

func readPortsInput(t *testing.T) portsTestInput {
	t.Helper()
	raw, err := os.ReadFile(*portsTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in portsTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	r := in.Relay
	if r.Program == "" || r.MachineName == "" || r.DeadlineMS <= 0 || r.PortName == "" || r.GuestPort <= 0 ||
		r.RefusedPortName == "" || r.RefusedGuestPort <= 0 || r.UnknownPortName == "" || r.Payload == "" ||
		r.WantEndpointSuffix == "" || len(in.InvalidSpecs) == 0 {
		t.Fatal("ports test input is incomplete")
	}
	return in
}

// TestPortRelayThroughClient proves the port contract through the API and
// the Go client: a running machine relays bytes to an exposed guest port in
// both directions; a machine that does not run, a port that the spec does
// not name, a guest port with no listener, a request with no credential,
// and a request with no Upgrade header get no stream.
func TestPortRelayThroughClient(t *testing.T) {
	in := readPortsInput(t).Relay
	h := newHarnessFor(t, t.TempDir(), &fakeRuntime{refusedGuestPort: in.RefusedGuestPort}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(in.DeadlineMS)*time.Millisecond)
	defer cancel()
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: in.MachineName, Lifecycle: api.Ephemeral, Image: h.image(t),
		TimeoutSeconds: 60, Process: api.Process{Args: []string{in.Program}},
		Network: api.Network{Ports: []api.Port{
			{Name: in.PortName, GuestPort: in.GuestPort, Protocol: api.PortProtocolTCP},
			{Name: in.RefusedPortName, GuestPort: in.RefusedGuestPort, Protocol: api.PortProtocolTCP},
		}}})
	if err != nil {
		t.Fatalf("CreateMachine() error = %v", err)
	}
	if len(m.Endpoints) != 2 || m.Endpoints[0].Port != in.PortName || !strings.HasSuffix(m.Endpoints[0].Address, in.WantEndpointSuffix) ||
		!strings.Contains(m.Endpoints[0].Address, m.ID) {
		t.Fatalf("Endpoints = %+v, want the connect path of %q first", m.Endpoints, in.PortName)
	}
	if _, err := h.c.DialPort(ctx, m.ID, in.PortName); !client.IsCode(err, api.ErrConflict) {
		t.Fatalf("DialPort() before start error = %v, want code %s", err, api.ErrConflict)
	}
	if _, err := h.c.StartMachine(ctx, m.ID); err != nil {
		t.Fatalf("StartMachine() error = %v", err)
	}

	stream, err := h.c.DialPort(ctx, m.ID, in.PortName)
	if err != nil {
		t.Fatalf("DialPort() error = %v", err)
	}
	// Two round trips prove that the stream stays open in both directions.
	for round := range 2 {
		if _, err := io.WriteString(stream, in.Payload); err != nil {
			t.Fatalf("round %d: write error = %v", round, err)
		}
		got := make([]byte, len(in.Payload))
		if _, err := io.ReadFull(stream, got); err != nil || string(got) != in.Payload {
			t.Fatalf("round %d: read = %q, error %v; want %q", round, got, err, in.Payload)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for name, tc := range map[string]struct {
		machine, port string
		want          api.ErrorCode
	}{
		"port that the spec does not name": {m.ID, in.UnknownPortName, api.ErrNotFound},
		"machine that does not exist":      {"m-0000000000000000", in.PortName, api.ErrNotFound},
		"guest port with no listener":      {m.ID, in.RefusedPortName, api.ErrUnavailable},
	} {
		if _, err := h.c.DialPort(ctx, tc.machine, tc.port); !client.IsCode(err, tc.want) {
			t.Errorf("DialPort() for a %s error = %v, want code %s", name, err, tc.want)
		}
	}

	path := strings.TrimPrefix(m.Endpoints[0].Address, "/")
	for name, tc := range map[string]struct {
		credential, upgrade string
		want                int
	}{
		"request with no credential":     {"", api.UpgradePort, http.StatusUnauthorized},
		"request with no Upgrade header": {testCredential, "", http.StatusBadRequest},
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url+"/"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if tc.credential != "" {
			req.Header.Set("Authorization", "Bearer "+tc.credential)
		}
		if tc.upgrade != "" {
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", tc.upgrade)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status = %d, want %d", name, resp.StatusCode, tc.want)
		}
	}

	if _, err := h.c.StopMachine(ctx, m.ID, api.StopRequest{}); err != nil {
		t.Fatalf("StopMachine() error = %v", err)
	}
	if _, err := h.c.DialPort(ctx, m.ID, in.PortName); !client.IsCode(err, api.ErrConflict) {
		t.Fatalf("DialPort() after stop error = %v, want code %s", err, api.ErrConflict)
	}
}

// TestCreateRefusesInvalidPorts proves that create refuses each invalid
// port spec. A refused spec must not reach the guest agent, which exposes
// exactly the ports of the spec.
func TestCreateRefusesInvalidPorts(t *testing.T) {
	in := readPortsInput(t)
	h := newHarness(t, t.TempDir())
	image := h.image(t)
	for _, tc := range in.InvalidSpecs {
		_, err := h.c.CreateMachine(context.Background(), api.MachineSpec{Name: "invalid-ports", Lifecycle: api.Ephemeral,
			Image: image, TimeoutSeconds: 60, Process: api.Process{Args: []string{in.Relay.Program}},
			Network: api.Network{Ports: tc.Ports}})
		if !client.IsCode(err, api.ErrInvalidRequest) {
			t.Errorf("CreateMachine() with %s error = %v, want code %s", tc.Name, err, api.ErrInvalidRequest)
		}
	}
}
