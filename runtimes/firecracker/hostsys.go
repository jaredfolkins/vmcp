//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	// lockCgroup takes the lock of a cgroup that vmcp serve holds while it
	// runs. It returns errCgroupLocked when another process holds it. The
	// returned function releases the lock.
	lockCgroup(path string) (func(), error)
	// hostProcesses returns an error unless the host command sees the
	// processes of the host and can read their file descriptors.
	hostProcesses() error
	// cgroupWatchers returns the host processes that hold an inotify
	// watch on one of the cgroups. Every vmcp version with the enforcer
	// watches its parent cgroup while it runs, also one without the lock.
	cgroupWatchers(paths []string) ([]cgroupWatcher, error)

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

	// nftTables lists the nftables tables of the host network namespace
	// with their comments.
	nftTables() ([]hostTable, error)
	deleteNftTable(family, name string) error
}

// cgroupWatcher is a process that watches a cgroup with inotify.
type cgroupWatcher struct {
	PID    int    `json:"pid"`
	Comm   string `json:"comm"`
	Cgroup string `json:"cgroup"`
}

// hostTable is an nftables table and its comment.
type hostTable struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
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
	return os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte(enableControllersArg(controllers)), 0o644)
}

// enableControllersArg is the cgroup.subtree_control write that enables
// controllers, such as "+cpu +memory +pids".
func enableControllersArg(controllers []string) string {
	var b strings.Builder
	for i, c := range controllers {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("+" + c)
	}
	return b.String()
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

func (k kernelHost) lockCgroup(path string) (func(), error) {
	f, err := lockCgroup(path)
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

func (k kernelHost) hostProcesses() error {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return fmt.Errorf("read the cgroup of the host command: %w", err)
	}
	init, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return fmt.Errorf("read the cgroup of PID 1: %w", err)
	}
	// Without the host PID namespace, PID 1 is the init process of this
	// container, in the same cgroup.
	if bytes.Equal(self, init) {
		return errors.New("the host processes are not visible; run the host command with --pid=host")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			eff, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return fmt.Errorf("parse effective capabilities: %w", err)
			}
			if eff&(1<<unix.CAP_SYS_PTRACE) == 0 {
				return errors.New("the host command cannot read the file descriptors of other users; add CAP_SYS_PTRACE")
			}
			return nil
		}
	}
	return errors.New("process status has no effective capability set")
}

func (k kernelHost) cgroupWatchers(paths []string) ([]cgroupWatcher, error) {
	want := map[inotifyWatch]string{}
	for _, p := range paths {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, fmt.Errorf("inspect cgroup %s: %w", p, err)
		}
		// fdinfo prints the kernel device number: major<<20 | minor.
		dev := uint64(unix.Major(st.Dev))<<20 | uint64(unix.Minor(st.Dev))
		want[inotifyWatch{Ino: st.Ino, Dev: dev}] = p
	}
	if len(want) == 0 {
		return nil, nil
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	self := os.Getpid()
	var out []cgroupWatcher
	for _, e := range procs {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		switch {
		case errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH):
			continue // The process exited.
		case errors.Is(err, fs.ErrPermission):
			return nil, fmt.Errorf("read the file descriptors of PID %d: %w; add CAP_SYS_PTRACE", pid, err)
		case err != nil:
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err != nil || link != "anon_inode:inotify" {
				continue
			}
			info, err := os.ReadFile(filepath.Join("/proc", e.Name(), "fdinfo", fd.Name()))
			if err != nil {
				continue
			}
			for _, w := range parseInotify(info) {
				if cg, ok := want[w]; ok {
					comm, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
					out = append(out, cgroupWatcher{PID: pid, Comm: strings.TrimSpace(string(comm)), Cgroup: cg})
				}
			}
		}
	}
	return out, nil
}

// inotifyWatch is the inode and kernel device number of one watch.
type inotifyWatch struct {
	Ino uint64 `json:"ino"`
	Dev uint64 `json:"dev"`
}

// parseInotify reads the watches of an inotify file descriptor from its
// fdinfo: lines "inotify wd:1 ino:1c7532 sdev:20 mask:...", in hex.
func parseInotify(fdinfo []byte) []inotifyWatch {
	var out []inotifyWatch
	for _, line := range strings.Split(string(fdinfo), "\n") {
		rest, ok := strings.CutPrefix(line, "inotify ")
		if !ok {
			continue
		}
		var w inotifyWatch
		var ino, dev bool
		for _, f := range strings.Fields(rest) {
			k, v, _ := strings.Cut(f, ":")
			n, err := strconv.ParseUint(v, 16, 64)
			if err != nil {
				continue
			}
			switch k {
			case "ino":
				w.Ino, ino = n, true
			case "sdev":
				w.Dev, dev = n, true
			}
		}
		if ino && dev {
			out = append(out, w)
		}
	}
	return out
}

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

func (k kernelHost) nftTables() ([]hostTable, error) {
	// The JSON listing of nft 1.0.6 has no table comment, so read the
	// text ruleset.
	out, err := k.tool(nil, "nft", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseNftTables(out), nil
}

func (k kernelHost) deleteNftTable(family, name string) error {
	_, err := k.tool(nil, "nft", "delete", "table", family, name)
	return err
}

var (
	nftTableLineRE    = regexp.MustCompile(`^table (\S+) (\S+) \{$`)
	nftTableCommentRE = regexp.MustCompile(`^\tcomment "([^"]*)"$`)
)

// parseNftTables reads the tables of a text ruleset. The comment of a
// table is the first line in its block with one tab of indent; the
// comments of sets, chains, and rules have more indent.
func parseNftTables(ruleset []byte) []hostTable {
	var out []hostTable
	for _, line := range strings.Split(string(ruleset), "\n") {
		if m := nftTableLineRE.FindStringSubmatch(line); m != nil {
			out = append(out, hostTable{Family: m[1], Name: m[2]})
			continue
		}
		if m := nftTableCommentRE.FindStringSubmatch(line); m != nil && len(out) > 0 && out[len(out)-1].Comment == "" {
			out[len(out)-1].Comment = m[1]
		}
	}
	return out
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
