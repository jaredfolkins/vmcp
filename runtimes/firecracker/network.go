//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// TapPrefix starts every vmcp tap name. The enforcer and the nftables
	// table match it.
	TapPrefix = "vmcp-"
	nftTable  = "vmcp"
	toolPath  = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
)

// Broker ports on the machine host address.
const (
	PortDNS          = 53
	PortEgress       = 3128
	PortUpstreamBase = 8100
)

// guestNet is the network of one machine: a /30 with the host at .1 and the
// guest at .2.
type guestNet struct {
	Tap   string
	Host  netip.Addr
	Guest netip.Addr
	MAC   string
	// Allowed lists the protocol and port pairs that the guest may open on
	// the host address.
	Allowed []allowedPort
}

type allowedPort struct {
	Proto string
	Port  int
}

// netForSlot returns the network of a machine slot inside pool.
func netForSlot(pool netip.Prefix, slot int, id string) (guestNet, error) {
	base := pool.Masked().Addr()
	if !base.Is4() || pool.Bits() > 28 {
		return guestNet{}, fmt.Errorf("machine pool %s must be an IPv4 prefix of /28 or larger", pool)
	}
	b := base.As4()
	n := binary.BigEndian.Uint32(b[:]) + uint32(slot)*4
	var hb, gb [4]byte
	binary.BigEndian.PutUint32(hb[:], n+1)
	binary.BigEndian.PutUint32(gb[:], n+2)
	host, guest := netip.AddrFrom4(hb), netip.AddrFrom4(gb)
	if !pool.Contains(guest) {
		return guestNet{}, fmt.Errorf("machine slot %d is outside pool %s", slot, pool)
	}
	return guestNet{
		Tap:   TapPrefix + shortID(id),
		Host:  host,
		Guest: guest,
		MAC:   fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", gb[0], gb[1], gb[2], gb[3]),
	}, nil
}

// kernelIPArg is the kernel "ip=" argument for the guest.
func (g guestNet) kernelIPArg() string {
	return fmt.Sprintf("ip=%s::%s:255.255.255.252::eth0:off", g.Guest, g.Host)
}

func shortID(id string) string {
	s := strings.TrimPrefix(id, "m-")
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

// tableTag is the comment of the vmcp nftables table of an install. vmcp
// host teardown finds a table by it.
func tableTag(installID string) string { return "vmcp:" + installID }

// tableRuleset is the vmcp nftables table of an install. Each tap may
// reach only the elements of guest_allow. Nothing is forwarded to or from
// a tap.
func tableRuleset(installID string) string {
	return fmt.Sprintf(`table inet %[1]s {
	comment "%[3]s"
	set guest_allow {
		type ifname . ipv4_addr . ipv4_addr . inet_proto . inet_service
		comment "vmcp guest broker access"
	}
	chain input {
		type filter hook input priority -10; policy accept;
		iifname "%[2]s*" iifname . ip saddr . ip daddr . meta l4proto . th dport @guest_allow accept
		iifname "%[2]s*" drop
	}
	chain forward {
		type filter hook forward priority -10; policy accept;
		iifname "%[2]s*" drop
		oifname "%[2]s*" drop
	}
}
`, nftTable, TapPrefix, tableTag(installID))
}

// setupTable replaces the vmcp table with a fresh one for the install.
func setupTable(ctx context.Context, installID string) error {
	_ = run(ctx, nil, "nft", "delete", "table", "inet", nftTable)
	return run(ctx, []byte(tableRuleset(installID)), "nft", "-f", "-")
}

// addTap creates the tap for uid and gid, tags it, and allows its brokers.
func addTap(ctx context.Context, g guestNet, uid int, tag string) error {
	steps := [][]string{
		{"ip", "tuntap", "add", "dev", g.Tap, "mode", "tap", "user", strconv.Itoa(uid), "group", strconv.Itoa(uid)},
		{"ip", "link", "set", "dev", g.Tap, "alias", tag},
		{"ip", "addr", "add", g.Host.String() + "/30", "dev", g.Tap},
		{"ip", "link", "set", "dev", g.Tap, "up"},
	}
	for _, s := range steps {
		if err := run(ctx, nil, s[0], s[1:]...); err != nil {
			return err
		}
	}
	if len(g.Allowed) == 0 {
		return nil
	}
	return run(ctx, nil, "nft", "add", "element", "inet", nftTable, "guest_allow", g.elements(tag))
}

// removeTap removes the broker access and the tap. It ignores a missing
// tap.
func removeTap(ctx context.Context, g guestNet, tag string) error {
	if len(g.Allowed) > 0 {
		_ = run(ctx, nil, "nft", "delete", "element", "inet", nftTable, "guest_allow", g.elements(tag))
	}
	if !linkExists(ctx, g.Tap) {
		return nil
	}
	return run(ctx, nil, "ip", "link", "del", "dev", g.Tap)
}

func (g guestNet) elements(tag string) string {
	parts := make([]string, 0, len(g.Allowed))
	for _, a := range g.Allowed {
		parts = append(parts, fmt.Sprintf(`"%s" . %s . %s . %s . %d comment "%s"`, g.Tap, g.Guest, g.Host, a.Proto, a.Port, tag))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// netAdminCaps is the ambient capability set of a network tool that
// changes links, addresses, or nftables, or that reads nftables. vmcp runs
// as a non-root user, so a child gets a capability only in its ambient set.
var netAdminCaps = []uintptr{unix.CAP_NET_ADMIN}

// toolCommand returns a host tool command with a fixed environment, no
// shell, and the ambient capabilities caps. A nil caps gives the tool no
// capability.
func toolCommand(ctx context.Context, caps []uintptr, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{toolPath, "LC_ALL=C"}
	if len(caps) > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: caps}
	}
	return cmd
}

// linkExists reports whether the link exists in the vmcp network
// namespace. Reading links needs no capability.
func linkExists(ctx context.Context, name string) bool {
	return toolCommand(ctx, nil, "ip", "link", "show", "dev", name).Run() == nil
}

// run executes a network tool that changes host network state or reads
// nftables. It has CAP_NET_ADMIN and no other capability.
func run(ctx context.Context, stdin []byte, name string, args ...string) error {
	cmd := toolCommand(ctx, netAdminCaps, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, firstLine(out))
	}
	return nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ownedTaps lists the taps whose alias carries this install tag.
func ownedTaps(ctx context.Context, installID string) ([]string, error) {
	out, err := toolCommand(ctx, nil, "ip", "-o", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	prefix := "vmcp:" + installID + ":"
	var taps []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		name, _, _ = strings.Cut(name, "@")
		if !strings.HasPrefix(name, TapPrefix) {
			continue
		}
		if i := strings.Index(line, "alias "); i >= 0 && strings.HasPrefix(line[i+len("alias "):], prefix) {
			taps = append(taps, name)
		}
	}
	return taps, nil
}
