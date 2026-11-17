package firecracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

const (
	// portDialTimeout bounds the wait for the guest agent to open a relay
	// connection after a connect request.
	portDialTimeout = 15 * time.Second
	// portHeaderTimeout bounds the read of the header on a relay connection.
	portHeaderTimeout = 5 * time.Second
)

// portDial is the answer of the guest agent to one connect request.
type portDial struct {
	conn net.Conn
	err  error
}

// guestPorts returns the guest TCP ports that the spec exposes.
func (m *Machine) guestPorts() []int {
	var ports []int
	for _, p := range m.spec.Spec.Network.Ports {
		ports = append(ports, p.GuestPort)
	}
	return ports
}

// DialPort opens a connection to an exposed guest loopback TCP port. vmcp
// asks the guest agent on the event connection. The agent connects to the
// guest port and opens a relay connection to the host over vsock. The host
// never connects to a guest network address.
func (m *Machine) DialPort(ctx context.Context, guestPort int) (net.Conn, error) {
	if !slices.Contains(m.guestPorts(), guestPort) {
		return nil, machine.ErrPortNotExposed
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(raw)
	answer := make(chan portDial, 1)
	m.mu.Lock()
	conn := m.eventConn
	if conn == nil || m.finished {
		m.mu.Unlock()
		return nil, machine.ErrPortUnavailable
	}
	if m.portPending == nil {
		m.portPending = make(map[string]chan portDial)
	}
	m.portPending[id] = answer
	m.mu.Unlock()
	// abandon removes the request. An answer that arrived at the same time
	// is closed, so that no relay connection leaks.
	abandon := func() {
		m.mu.Lock()
		_, waiting := m.portPending[id]
		delete(m.portPending, id)
		m.mu.Unlock()
		if !waiting {
			if late := <-answer; late.conn != nil {
				_ = late.conn.Close()
			}
		}
	}
	if err := m.sendHost(conn, agentproto.Message{Type: agentproto.TypeConnect, ConnID: id, Port: guestPort}); err != nil {
		abandon()
		return nil, machine.ErrPortUnavailable
	}
	timer := time.NewTimer(portDialTimeout)
	defer timer.Stop()
	select {
	case got := <-answer:
		return got.conn, got.err
	case <-ctx.Done():
		abandon()
		return nil, ctx.Err()
	case <-m.done:
		abandon()
		return nil, machine.ErrPortUnavailable
	case <-timer.C:
		abandon()
		return nil, machine.ErrPortUnavailable
	}
}

// acceptPorts accepts the relay connections of the guest agent.
func (m *Machine) acceptPorts(ln net.Listener) {
	defer m.listenWG.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.receivePort(c)
	}
}

// receivePort reads the header of one relay connection and gives the
// connection to the DialPort call that asked for it. A connection with no
// waiting call is closed.
func (m *Machine) receivePort(c net.Conn) {
	header, err := readPortHeader(c)
	if err != nil {
		_ = c.Close()
		return
	}
	m.mu.Lock()
	answer := m.portPending[header.ConnID]
	delete(m.portPending, header.ConnID)
	m.mu.Unlock()
	if answer == nil {
		_ = c.Close()
		return
	}
	if header.Error != "" {
		_ = c.Close()
		answer <- portDial{err: fmt.Errorf("%w: %s", machine.ErrPortRefused, bounded(header.Error, 128))}
		return
	}
	answer <- portDial{conn: c}
}

// readPortHeader reads the one header line. It reads single bytes, so that
// it takes no byte of the relayed stream.
func readPortHeader(c net.Conn) (agentproto.PortHeader, error) {
	var header agentproto.PortHeader
	if err := c.SetReadDeadline(time.Now().Add(portHeaderTimeout)); err != nil {
		return header, err
	}
	line := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		if _, err := c.Read(one); err != nil {
			return header, err
		}
		if one[0] == '\n' {
			break
		}
		if len(line) >= agentproto.MaxPortHeaderBytes {
			return header, errors.New("port header exceeds its size limit")
		}
		line = append(line, one[0])
	}
	if err := json.Unmarshal(line, &header); err != nil || header.ConnID == "" {
		return header, errors.New("port header is invalid")
	}
	return header, c.SetReadDeadline(time.Time{})
}
