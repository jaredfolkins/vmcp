//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/api"
)

const (
	// gatewayUDPIdle closes a UDP flow that has carried no packet for this
	// long.
	gatewayUDPIdle = 60 * time.Second
	// gatewayMaxFlows bounds the open TCP connections and UDP flows of one
	// machine.
	gatewayMaxFlows = 512
	// gatewayMaxDenied bounds the remembered denied UDP flows of one
	// machine, which keep a packet stream to one refused destination one
	// flow event.
	gatewayMaxDenied = 1024
	maxUDPPayload    = 65535
)

// gateway is the broker of a guest's other TCP and UDP traffic. The gateway
// chain delivers each such packet to its sockets with TPROXY, so a socket
// sees the destination that the guest chose. The gateway connects only to
// public addresses, and each connection and flow is a flow event.
type gateway struct {
	b      *brokers
	deny   []netip.Prefix
	flows  *flowRecorder
	active atomic.Int64

	mu     sync.Mutex
	udp    map[udpKey]*udpFlow
	denied map[udpKey]time.Time
}

type udpKey struct{ src, dst netip.AddrPort }

// startGateway starts the TCP and UDP gateway sockets on the host address.
func (b *brokers) startGateway(host netip.Addr, cfg brokerConfig) error {
	g := &gateway{b: b, deny: cfg.Deny, flows: cfg.Flows, udp: map[udpKey]*udpFlow{}, denied: map[udpKey]time.Time{}}
	addr := netip.AddrPortFrom(host, PortGateway).String()
	lc := net.ListenConfig{Control: transparentControl(false)}
	ln, err := lc.Listen(context.Background(), "tcp4", addr)
	if err != nil {
		return fmt.Errorf("gateway tcp: %w", err)
	}
	b.track(ln)
	lc = net.ListenConfig{Control: transparentControl(true)}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return fmt.Errorf("gateway udp: %w", err)
	}
	b.track(pc)
	go g.serveTCP(ln)
	go g.serveUDP(pc.(*net.UDPConn))
	return nil
}

// transparentControl lets a socket accept packets for any destination. A
// UDP socket also receives the original destination of each datagram.
func transparentControl(udp bool) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
			if serr == nil && udp {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// refuse returns why the gateway refuses dst, or "".
func (g *gateway) refuse(dst netip.Addr) string {
	if !publicAddress(dst, g.deny) {
		return "address_not_public"
	}
	return ""
}

// acquire takes one open flow of the machine. It is false at the limit.
func (g *gateway) acquire() bool {
	if g.active.Add(1) > gatewayMaxFlows {
		g.active.Add(-1)
		return false
	}
	return true
}

func (g *gateway) release() { g.active.Add(-1) }

func (g *gateway) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !g.b.addConn(c) {
			_ = c.Close()
			return
		}
		go g.handleTCP(c)
	}
}

// handleTCP connects one guest TCP connection to its destination. A
// TPROXY socket has the destination of the guest as its local address.
func (g *gateway) handleTCP(c net.Conn) {
	defer g.b.dropConn(c)
	defer func() { _ = c.Close() }()
	dst := c.LocalAddr().(*net.TCPAddr).AddrPort()
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	flow := api.Flow{ID: g.flows.id(), Broker: "gateway", Proto: "tcp", Address: dst.Addr().String(), Port: int(dst.Port())}
	if reason := g.refuse(dst.Addr()); reason != "" {
		g.recordDenied(flow, reason)
		return
	}
	if !g.acquire() {
		g.recordDenied(flow, "flow_limit")
		return
	}
	defer g.release()
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.Dial("tcp4", dst.String())
	if err != nil {
		g.recordFailed(flow, err)
		return
	}
	if !g.b.addConn(up) {
		_ = up.Close()
		return
	}
	defer g.b.dropConn(up)
	splice(c, openFlow(g.flows, up, flow), bytes.NewReader(nil))
}

func (g *gateway) recordDenied(f api.Flow, reason string) {
	f.Phase, f.Reason = api.FlowDenied, reason
	g.flows.record(f)
}

func (g *gateway) recordFailed(f api.Flow, err error) {
	f.Phase, f.Reason = api.FlowFailed, connectFailure(err)
	g.flows.record(f)
}

func (g *gateway) serveUDP(pc *net.UDPConn) {
	buf := make([]byte, maxUDPPayload)
	oob := make([]byte, 128)
	for {
		n, oobn, _, src, err := pc.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		dst, ok := origDst(oob[:oobn])
		if !ok {
			continue
		}
		g.udpPacket(netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), dst, buf[:n])
	}
}

// origDst returns the original destination of a TPROXY datagram.
func origDst(oob []byte) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_IP || m.Header.Type != unix.IP_ORIGDSTADDR || len(m.Data) < unix.SizeofSockaddrInet4 {
			continue
		}
		// struct sockaddr_in: family, port (network order), address.
		port := uint16(m.Data[2])<<8 | uint16(m.Data[3])
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(m.Data[4:8])), port), true
	}
	return netip.AddrPort{}, false
}

// udpPacket sends one guest datagram that reached the gateway socket. It
// starts a flow for a new source and destination pair. Later datagrams of a
// flow reach its reply socket, which TPROXY finds as connected.
func (g *gateway) udpPacket(src, dst netip.AddrPort, payload []byte) {
	key := udpKey{src, dst}
	g.mu.Lock()
	f := g.udp[key]
	_, denied := g.denied[key]
	g.mu.Unlock()
	if f != nil {
		f.toUpstream(payload)
		return
	}
	if denied {
		return
	}
	flow := api.Flow{ID: g.flows.id(), Broker: "gateway", Proto: "udp", Address: dst.Addr().String(), Port: int(dst.Port())}
	if reason := g.refuse(dst.Addr()); reason != "" {
		g.rememberDenied(key)
		g.recordDenied(flow, reason)
		return
	}
	if !g.acquire() {
		g.recordDenied(flow, "flow_limit")
		return
	}
	f, err := g.openUDP(key, flow)
	if err != nil {
		g.release()
		g.recordFailed(flow, err)
		return
	}
	f.toUpstream(payload)
}

// rememberDenied keeps a refused pair for gatewayUDPIdle.
func (g *gateway) rememberDenied(key udpKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, t := range g.denied {
		if now.Sub(t) > gatewayUDPIdle {
			delete(g.denied, k)
		}
	}
	if len(g.denied) >= gatewayMaxDenied {
		clear(g.denied)
	}
	g.denied[key] = now
}

// udpFlow is one guest UDP flow: an upstream socket to the destination and
// a reply socket that has the destination as its local address and the
// guest as its peer.
type udpFlow struct {
	g     *gateway
	key   udpKey
	up    *flowConn
	reply *net.UDPConn
	last  atomic.Int64
	once  sync.Once
}

func (g *gateway) openUDP(key udpKey, flow api.Flow) (*udpFlow, error) {
	up, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(key.dst))
	if err != nil {
		return nil, err
	}
	reply, err := transparentUDP(key.dst, key.src)
	if err != nil {
		_ = up.Close()
		return nil, err
	}
	if !g.b.addConn(up) {
		_ = up.Close()
		_ = reply.Close()
		return nil, net.ErrClosed
	}
	if !g.b.addConn(reply) {
		g.b.dropConn(up)
		_ = up.Close()
		_ = reply.Close()
		return nil, net.ErrClosed
	}
	f := &udpFlow{g: g, key: key, up: openFlow(g.flows, up, flow), reply: reply}
	f.touch()
	g.mu.Lock()
	g.udp[key] = f
	g.mu.Unlock()
	go f.relay(f.up, f.reply)
	go f.relay(f.reply, f.up)
	return f, nil
}

// transparentUDP returns a UDP socket bound to the non-local address local
// and connected to peer.
func transparentUDP(local, peer netip.AddrPort) (*net.UDPConn, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "gateway-udp")
	defer func() { _ = file.Close() }()
	for _, o := range []struct{ level, name int }{{unix.SOL_IP, unix.IP_TRANSPARENT}, {unix.SOL_SOCKET, unix.SO_REUSEADDR}} {
		if err := unix.SetsockoptInt(fd, o.level, o.name, 1); err != nil {
			return nil, err
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: int(local.Port()), Addr: local.Addr().As4()}); err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: int(peer.Port()), Addr: peer.Addr().As4()}); err != nil {
		return nil, err
	}
	c, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

func (f *udpFlow) touch() { f.last.Store(time.Now().UnixNano()) }

func (f *udpFlow) toUpstream(payload []byte) {
	f.touch()
	if _, err := f.up.Write(payload); err != nil {
		f.close()
	}
}

// relay copies datagrams from one socket of the flow to the other until
// the flow is idle for gatewayUDPIdle or a socket closes.
func (f *udpFlow) relay(from, to net.Conn) {
	defer f.close()
	buf := make([]byte, maxUDPPayload)
	for {
		idleEnd := time.Unix(0, f.last.Load()).Add(gatewayUDPIdle)
		_ = from.SetReadDeadline(idleEnd)
		n, err := from.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && time.Until(time.Unix(0, f.last.Load()).Add(gatewayUDPIdle)) > 0 {
				continue
			}
			return
		}
		f.touch()
		if _, err := to.Write(buf[:n]); err != nil {
			return
		}
	}
}

// close ends the flow once and records its close.
func (f *udpFlow) close() {
	f.once.Do(func() {
		f.g.mu.Lock()
		delete(f.g.udp, f.key)
		f.g.mu.Unlock()
		f.g.b.dropConn(f.reply)
		f.g.b.dropConn(f.up.Conn)
		_ = f.reply.Close()
		_ = f.up.Close()
		f.g.release()
	})
}
