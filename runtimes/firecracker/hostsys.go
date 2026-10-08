//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// hostSystem is the kernel access of the host commands. Tests replace it
// with a fake host.
type hostSystem interface {
	// euid is the effective user ID of the host command.
	euid() int
	// fileOwner returns the owner of a file.
	fileOwner(path string) (uid, gid int, err error)
	// cgroupOwner returns the ownerXattr value of a cgroup, and false when
	// the cgroup has none.
	cgroupOwner(path string) (string, bool, error)
	tagCgroup(path, owner string) error
	makeCgroup(path string) error
	enableControllers(path string, controllers []string) error
	chown(path string, uid, gid int) error
	// cgroupProcs lists the processes in one cgroup, not its children.
	cgroupProcs(path string) ([]int, error)
	// killCgroup kills every process in the cgroup and its children and
	// waits until none is left.
	killCgroup(path string) error
	// removeCgroup removes one empty cgroup without children.
	removeCgroup(path string) error

	// loadedProfiles returns the mode of each loaded AppArmor profile.
	loadedProfiles() (map[string]string, error)
	// profileNames returns the profiles that a profile file defines.
	profileNames(file string) ([]string, error)
	loadProfile(file string) error
	unloadProfile(file string) error
	// removeLoadedProfile unloads a profile that has no file.
	removeLoadedProfile(name string) error

	loadModule(name string) error

	// links lists the links of the host network namespace.
	links() ([]hostLink, error)
	deleteLink(name string) error
}

// hostLink is a link and its ifalias.
type hostLink struct {
	Name  string `json:"ifname"`
	Alias string `json:"ifalias"`
}

// kernelHost is the real host. The host commands run it as root in a
// privileged container with the host cgroup, network, and securityfs.
type kernelHost struct {
	ctx        context.Context
	securityFS string
}

func (k kernelHost) euid() int { return os.Geteuid() }

func (k kernelHost) fileOwner(path string) (uid, gid int, err error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, 0, fmt.Errorf("inspect %s: %w", path, err)
	}
	return int(st.Uid), int(st.Gid), nil
}

func (k kernelHost) cgroupOwner(path string) (string, bool, error) {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, ownerXattr, buf)
	switch {
	case errors.Is(err, unix.ENODATA):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("read owner of cgroup %s: %w", path, err)
	}
	return string(buf[:n]), true, nil
}

func (k kernelHost) tagCgroup(path, owner string) error {
	if err := unix.Setxattr(path, ownerXattr, []byte(owner), 0); err != nil {
		return fmt.Errorf("tag cgroup %s: %w", path, err)
	}
	return nil
}

func (k kernelHost) makeCgroup(path string) error { return os.Mkdir(path, 0o755) }

func (k kernelHost) enableControllers(path string, controllers []string) error {
	var b strings.Builder
	for i, c := range controllers {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("+" + c)
	}
	return os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte(b.String()), 0o644)
}

func (k kernelHost) chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

func (k kernelHost) cgroupProcs(path string) ([]int, error) { return cgroupPIDs(path) }

func (k kernelHost) killCgroup(path string) error {
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o644); err != nil {
		return fmt.Errorf("kill cgroup %s: %w", path, err)
	}
	deadline := time.Now().Add(killWait)
	for {
		b, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
		if err != nil {
			return fmt.Errorf("read cgroup events of %s: %w", path, err)
		}
		if bytes.Contains(b, []byte("populated 0")) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cgroup %s still has processes after %s", path, killWait)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (k kernelHost) removeCgroup(path string) error { return os.Remove(path) }

func (k kernelHost) loadedProfiles() (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(k.securityFS, "apparmor", "profiles"))
	if err != nil {
		return nil, fmt.Errorf("read loaded AppArmor profiles: %w", err)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndex(line, " (")
		if i <= 0 || !strings.HasSuffix(line, ")") {
			continue
		}
		out[line[:i]] = line[i+2 : len(line)-1]
	}
	return out, sc.Err()
}

func (k kernelHost) profileNames(file string) ([]string, error) {
	out, err := k.tool(nil, "apparmor_parser", "-N", file)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

func (k kernelHost) loadProfile(file string) error {
	_, err := k.tool(nil, "apparmor_parser", "-r", "-W", file)
	return err
}

func (k kernelHost) unloadProfile(file string) error {
	_, err := k.tool(nil, "apparmor_parser", "-R", file)
	return err
}

func (k kernelHost) removeLoadedProfile(name string) error {
	p := filepath.Join(k.securityFS, "apparmor", ".remove")
	if err := os.WriteFile(p, []byte(name), 0o200); err != nil {
		return fmt.Errorf("unload AppArmor profile %s: %w", name, err)
	}
	return nil
}

func (k kernelHost) loadModule(name string) error {
	_, err := k.tool(nil, "modprobe", name)
	return err
}

func (k kernelHost) links() ([]hostLink, error) {
	out, err := k.tool(nil, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var links []hostLink
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("parse host links: %w", err)
	}
	return links, nil
}

func (k kernelHost) deleteLink(name string) error {
	_, err := k.tool(nil, "ip", "link", "del", "dev", name)
	return err
}

// tool runs a host tool as root with a fixed environment and no shell.
func (k kernelHost) tool(stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := toolCommand(k.ctx, nil, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, firstLine(stderr.Bytes()))
	}
	return out, nil
}
