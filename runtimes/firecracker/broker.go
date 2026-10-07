//go:build linux

package firecracker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaredfolkins/vmcp/api"
)

const (
	dnsTimeout     = 3 * time.Second
	dialTimeout    = 15 * time.Second
	maxDNSMessage  = 4096
	maxDNSInflight = 64
	headerTimeout  = 15 * time.Second
)

// DefaultDenyPrefixes are the destinations that public egress never
// reaches, on top of every address that is not global unicast.
var DefaultDenyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// brokerConfig is the host policy for every machine's brokers.
type brokerConfig struct {
	DNSUpstreams []string
	Deny         []netip.Prefix
	Log          *slog.Logger
}

// brokers are the services of one machine on its host address.
type brokers struct {
	mu        sync.Mutex
	closers   []io.Closer
	conns     map[net.Conn]struct{}
	closed    bool
	upstreams map[string]string
}

// plannedPorts returns the ports that the network spec opens on the host
// address, and the guest URL of each upstream.
func plannedPorts(n api.Network, host netip.Addr) ([]allowedPort, map[string]string) {
	var ports []allowedPort
	if n.DNS {
		ports = append(ports, allowedPort{"udp", PortDNS}, allowedPort{"tcp", PortDNS})
	}
	if n.PublicEgress {
		ports = append(ports, allowedPort{"tcp", PortEgress})
	}
	urls := map[string]string{}
	for i, u := range n.Upstreams {
		port := PortUpstreamBase + i
		ports = append(ports, allowedPort{"tcp", port})
		urls[u.Name] = "http://" + net.JoinHostPort(host.String(), strconv.Itoa(port))
	}
	return ports, urls
}

// startBrokers listens on the host address. The tap must already have that
// address.
func startBrokers(n api.Network, host netip.Addr, cfg brokerConfig) (*brokers, error) {
	b := &brokers{conns: map[net.Conn]struct{}{}}
	_, b.upstreams = plannedPorts(n, host)
	addr := func(port int) string { return net.JoinHostPort(host.String(), strconv.Itoa(port)) }
	resolver := upstreamResolver(cfg.DNSUpstreams)
	err := func() error {
		if n.DNS {
			pc, err := net.ListenPacket("udp4", addr(PortDNS))
			if err != nil {
				return err
			}
			b.track(pc)
			go serveDNSUDP(pc, cfg.DNSUpstreams)
			ln, err := net.Listen("tcp4", addr(PortDNS))
			if err != nil {
				return err
			}
			b.track(ln)
			go b.serveDNSTCP(ln, cfg.DNSUpstreams)
		}
		if n.PublicEgress {
			ln, err := net.Listen("tcp4", addr(PortEgress))
			if err != nil {
				return err
			}
			b.track(ln)
			e := &egress{resolver: resolver, deny: cfg.Deny, b: b, log: cfg.Log}
			srv := &http.Server{Handler: e, ReadHeaderTimeout: headerTimeout, ConnState: b.connState}
			go func() { _ = srv.Serve(ln) }()
		}
		for i, u := range n.Upstreams {
			h, err := upstreamHandler(u)
			if err != nil {
				return err
			}
			ln, err := net.Listen("tcp4", addr(PortUpstreamBase+i))
			if err != nil {
				return err
			}
			b.track(ln)
			srv := &http.Server{Handler: h, ReadHeaderTimeout: headerTimeout, ConnState: b.connState}
			go func() { _ = srv.Serve(ln) }()
		}
		return nil
	}()
	if err != nil {
		b.close()
		return nil, fmt.Errorf("start brokers: %w", err)
	}
	return b, nil
}

func (b *brokers) track(c io.Closer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closers = append(b.closers, c)
}

func (b *brokers) connState(c net.Conn, s http.ConnState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch s {
	case http.StateNew:
		if b.closed {
			_ = c.Close()
			return
		}
		b.conns[c] = struct{}{}
	case http.StateClosed:
		delete(b.conns, c)
	}
}

// addConn tracks a connection outside an http.Server, such as a tunnel.
func (b *brokers) addConn(c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.conns[c] = struct{}{}
	return true
}

func (b *brokers) dropConn(c net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.conns, c)
}

// close stops every listener and connection of the machine.
func (b *brokers) close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for _, c := range b.closers {
		_ = c.Close()
	}
	for c := range b.conns {
		_ = c.Close()
	}
	b.conns = map[net.Conn]struct{}{}
}

func serveDNSUDP(pc net.PacketConn, upstreams []string) {
	sem := make(chan struct{}, maxDNSInflight)
	buf := make([]byte, maxDNSMessage)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		select {
		case sem <- struct{}{}:
		default:
			continue
		}
		go func() {
			defer func() { <-sem }()
			if resp, err := exchangeUDP(q, upstreams); err == nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}()
	}
}

func exchangeUDP(q []byte, upstreams []string) ([]byte, error) {
	var last error
	for _, up := range upstreams {
		c, err := net.DialTimeout("udp", up, dnsTimeout)
		if err != nil {
			last = err
			continue
		}
		_ = c.SetDeadline(time.Now().Add(dnsTimeout))
		if _, err := c.Write(q); err != nil {
			_ = c.Close()
			last = err
			continue
		}
		buf := make([]byte, maxDNSMessage)
		n, err := c.Read(buf)
		_ = c.Close()
		if err != nil {
			last = err
			continue
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("no DNS upstream answered: %w", last)
}

func (b *brokers) serveDNSTCP(ln net.Listener, upstreams []string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if !b.addConn(c) {
			_ = c.Close()
			return
		}
		go func() {
			defer b.dropConn(c)
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(dnsTimeout * 2))
			q, err := readDNSTCP(c)
			if err != nil {
				return
			}
			for _, up := range upstreams {
				uc, err := net.DialTimeout("tcp", up, dnsTimeout)
				if err != nil {
					continue
				}
				_ = uc.SetDeadline(time.Now().Add(dnsTimeout))
				resp, err := func() ([]byte, error) {
					defer func() { _ = uc.Close() }()
					if err := writeDNSTCP(uc, q); err != nil {
						return nil, err
					}
					return readDNSTCP(uc)
				}()
				if err == nil {
					_ = writeDNSTCP(c, resp)
					return
				}
			}
		}()
	}
}

func readDNSTCP(r io.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 || int(n) > maxDNSMessage*16 {
		return nil, errors.New("DNS message size is invalid")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeDNSTCP(w io.Writer, m []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(m))); err != nil {
		return err
	}
	_, err := w.Write(m)
	return err
}

// upstreamResolver resolves through the configured upstreams, not through
// the vmcp container resolver, so guests cannot learn internal names.
func upstreamResolver(upstreams []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			var last error
			for _, up := range upstreams {
				c, err := d.DialContext(ctx, network, up)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, fmt.Errorf("no DNS upstream: %w", last)
		},
	}
}

// egress is the public egress proxy. It resolves the destination itself,
// refuses any address that is not public, and connects to the checked IP.
type egress struct {
	resolver *net.Resolver
	deny     []netip.Prefix
	b        *brokers
	log      *slog.Logger
}

func (e *egress) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range e.deny {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// dial connects to host:port through the first allowed address.
func (e *egress) dial(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		rctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		if addrs, err = e.resolver.LookupNetIP(rctx, "ip4", host); err != nil {
			return nil, errDenied
		}
	}
	for _, ip := range addrs {
		if !e.allowed(ip) {
			return nil, errDenied
		}
	}
	if len(addrs) == 0 {
		return nil, errDenied
	}
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(addrs[0].String(), port))
}

var errDenied = errors.New("destination is not allowed")

func (e *egress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.connect(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "absolute http URL required", http.StatusBadRequest)
		return
	}
	host := r.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	tr := &http.Transport{
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return e.dial(ctx, host) },
		Proxy:                 nil,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	defer tr.CloseIdleConnections()
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = pr.In.URL
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, errDenied) {
				http.Error(w, "destination is not allowed", http.StatusForbidden)
				return
			}
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

func (e *egress) connect(w http.ResponseWriter, r *http.Request) {
	up, err := e.dial(r.Context(), r.Host)
	if errors.Is(err, errDenied) {
		http.Error(w, "destination is not allowed", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, "connect failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = up.Close()
		http.Error(w, "connect is not supported", http.StatusInternalServerError)
		return
	}
	c, buf, err := hj.Hijack()
	if err != nil {
		_ = up.Close()
		return
	}
	if !e.b.addConn(up) {
		_ = up.Close()
		_ = c.Close()
		return
	}
	defer e.b.dropConn(up)
	_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	splice(c, up, buf.Reader)
}

// splice copies both ways and keeps half-close.
func splice(client, up net.Conn, pending io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, io.MultiReader(pending, client))
		closeWrite(up)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, up)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = up.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// upstreamHandler proxies to one upstream URL. It removes guest
// credentials, adds the upstream token, and allows only GET and HEAD
// unless writes are allowed.
func upstreamHandler(u api.Upstream) (http.Handler, error) {
	target, err := url.Parse(u.URL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return nil, fmt.Errorf("upstream %q URL is invalid", u.Name)
	}
	token := u.Token
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Cookie")
			if token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !u.AllowWrite && r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		rp.ServeHTTP(w, r)
	}), nil
}
