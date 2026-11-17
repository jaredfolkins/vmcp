//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

const (
	// maxPortConns bounds the relayed connections of one guest.
	maxPortConns = 64
	// guestDialWait bounds the connect to the guest loopback port.
	guestDialWait = 5 * time.Second
)

// porter relays host connections to the guest loopback TCP ports that the
// configuration exposes. The host asks for each connection with a
// TypeConnect message. The agent opens the connection to the host, so the
// guest needs no listener that the host can reach.
type porter struct {
	mu      sync.Mutex
	allowed map[int]bool
	active  int
	// dialGuest and dialHost are the connect steps. Tests replace them.
	dialGuest func(port int) (io.ReadWriteCloser, error)
	dialHost  func() (io.ReadWriteCloser, error)
}

func newPorter() *porter {
	return &porter{
		dialGuest: func(port int) (io.ReadWriteCloser, error) {
			return net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), guestDialWait)
		},
		dialHost: func() (io.ReadWriteCloser, error) { return dialVsock(agentproto.PortPort) },
	}
}

// allow sets the exposed ports. Before it, every port is refused.
func (p *porter) allow(ports []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowed = make(map[int]bool, len(ports))
	for _, port := range ports {
		p.allowed[port] = true
	}
}

// admit reserves one relay slot for an exposed port. It returns the reason
// of a refusal, or "".
func (p *porter) admit(port int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.allowed[port]:
		return "the port is not exposed"
	case p.active >= maxPortConns:
		return "too many port connections"
	}
	p.active++
	return ""
}

func (p *porter) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
}

// connect serves one TypeConnect message. It always answers the host with
// one PortHeader, so that the host does not wait for a refused connection.
func (p *porter) connect(connID string, port int) {
	host, err := p.dialHost()
	if err != nil {
		return
	}
	defer func() { _ = host.Close() }()
	refuse := func(reason string) {
		_ = json.NewEncoder(host).Encode(agentproto.PortHeader{ConnID: connID, Error: reason})
	}
	if reason := p.admit(port); reason != "" {
		refuse(reason)
		return
	}
	defer p.release()
	guest, err := p.dialGuest(port)
	if err != nil {
		refuse("the guest port refused the connection")
		return
	}
	defer func() { _ = guest.Close() }()
	if err := json.NewEncoder(host).Encode(agentproto.PortHeader{ConnID: connID}); err != nil {
		return
	}
	relay(host, guest)
}

// relay copies bytes in both directions. It returns after both copies end.
// The end of one direction closes both connections, which ends the other.
func relay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		_ = a.Close()
		_ = b.Close()
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}

// loopbackUp brings the guest loopback interface up. A guest without a
// network device has no kernel "ip=" argument, so its loopback is down.
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("loopback socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("read loopback flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set loopback up: %w", err)
	}
	return nil
}
