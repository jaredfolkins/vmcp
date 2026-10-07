//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const probeTimeout = 2 * time.Second

// selfTest runs inside a self-test guest. It proves from the guest side
// that the host, metadata, private, and direct destinations are
// unreachable, and that the egress broker refuses metadata. It prints one
// JSON line and exits 0 only when every denial holds.
func selfTest() int {
	gw := defaultGateway()
	type probe struct {
		name   string
		denied func() bool
	}
	probes := []probe{
		{"vmcp-api-port", func() bool { return !tcpOpen(net.JoinHostPort(gw, "8080")) }},
		{"metadata", func() bool { return !tcpOpen("169.254.169.254:80") }},
		{"private-network", func() bool { return !tcpOpen("10.0.0.1:80") }},
		{"direct-internet", func() bool { return !tcpOpen("1.1.1.1:80") }},
		{"broker-metadata", func() bool { return proxyRefuses(net.JoinHostPort(gw, "3128"), "169.254.169.254:80") }},
	}
	results := map[string]bool{"gateway_found": gw != ""}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := gw != "" && p.denied()
			mu.Lock()
			results[p.name+"_denied"] = ok
			mu.Unlock()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ok := gw != "" && dnsAnswers(net.JoinHostPort(gw, "53"))
		mu.Lock()
		results["dns_broker_answers"] = ok
		mu.Unlock()
	}()
	wg.Wait()
	b, _ := json.Marshal(results)
	fmt.Println(string(b))
	for name, ok := range results {
		if strings.HasSuffix(name, "_denied") && !ok || name == "gateway_found" && !ok {
			return 1
		}
	}
	return 0
}

func tcpOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// proxyRefuses reports whether the egress proxy answers 403 to a CONNECT.
func proxyRefuses(proxy, target string) bool {
	c, err := net.DialTimeout("tcp", proxy, probeTimeout)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(probeTimeout * 2))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return false
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	return err == nil && strings.Contains(line, " 403 ")
}

// dnsAnswers sends one A query for example.com and reports whether any
// answer came back.
func dnsAnswers(server string) bool {
	q, _ := hex.DecodeString("abcd01000001000000000000076578616d706c6503636f6d0000010001")
	c, err := net.DialTimeout("udp", server, probeTimeout)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := c.Write(q); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	return err == nil && n >= 12 && binary.BigEndian.Uint16(buf[:2]) == 0xabcd
}

// defaultGateway reads the IPv4 default gateway from /proc/net/route.
func defaultGateway() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 2 && fields[1] == "00000000" {
			b, err := hex.DecodeString(fields[2])
			if err != nil || len(b) != 4 {
				return ""
			}
			return net.IPv4(b[3], b[2], b[1], b[0]).String()
		}
	}
	return ""
}
