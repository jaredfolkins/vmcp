package firecracker

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// supportedHosts lists the host distributions that vmcp supports, by the
// ID and VERSION_ID of os-release. A release is in this list only after the
// Compose install, the self-test, and a host reboot passed on it. AGENTS.md
// records the evidence.
var supportedHosts = map[string][]string{
	"debian": {"12", "13"},
	"ubuntu": {"24.04", "26.04"},
}

// SupportedHosts returns the supported host distributions as "id version".
func SupportedHosts() []string {
	var out []string
	for id, versions := range supportedHosts {
		for _, v := range versions {
			out = append(out, id+" "+v)
		}
	}
	slices.Sort(out)
	return out
}

// hostOS reads the ID and VERSION_ID of the host os-release. On most hosts
// /etc/os-release is a symlink to ../usr/lib/os-release; hostOS follows it
// inside HostRoot only, so it never reads the os-release of the container.
func (h *hostRun) hostOS() (id, version string, err error) {
	p := h.etc("os-release")
	if fi, lerr := os.Lstat(p); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		link, rerr := os.Readlink(p)
		if rerr != nil {
			return "", "", fmt.Errorf("read the host os-release: %w", rerr)
		}
		if filepath.IsAbs(link) {
			p = filepath.Join(h.cfg.HostRoot, link)
		} else {
			p = filepath.Join(h.etc(), link)
		}
		if rel, rerr := filepath.Rel(h.cfg.HostRoot, p); rerr != nil || strings.HasPrefix(rel, "..") {
			return "", "", fmt.Errorf("the host os-release link %q leaves the host root", link)
		}
	}
	b, rerr := os.ReadFile(p)
	if errors.Is(rerr, os.ErrNotExist) {
		return "", "", fmt.Errorf("the host os-release is not at %s; mount the host /usr/lib/os-release there read-only", p)
	}
	if rerr != nil {
		return "", "", fmt.Errorf("read the host os-release: %w", rerr)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	if id == "" {
		return "", "", errors.New("the host os-release has no ID")
	}
	return id, version, nil
}

// checkHostOS records the host distribution in the result and refuses one
// that is not in supportedHosts, unless the operator allows it.
func (h *hostRun) checkHostOS() error {
	id, version, err := h.hostOS()
	if err != nil {
		if h.cfg.AllowUnsupportedHost {
			return nil
		}
		return err
	}
	h.res.HostOS = strings.TrimSpace(id + " " + version)
	if slices.Contains(supportedHosts[id], version) || h.cfg.AllowUnsupportedHost {
		return nil
	}
	return fmt.Errorf("host %s is not supported; supported: %s; --allow-unsupported-host runs without support",
		h.res.HostOS, strings.Join(SupportedHosts(), ", "))
}
