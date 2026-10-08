//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

// cgroupControllers are the controllers that the jailer limits. vmcp host
// install enables them in the parent cgroup.
var cgroupControllers = []string{"cpu", "memory", "pids"}

// killCgroup kills every process in the cgroup and waits until it is
// empty. A missing cgroup is not an error.
func killCgroup(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kill cgroup: %w", err)
	}
	deadline := time.Now().Add(killWait)
	for {
		pids, err := cgroupPIDs(path)
		if errors.Is(err, os.ErrNotExist) || (err == nil && len(pids) == 0) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cgroup %s still has processes", filepath.Base(path))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// removeCgroup removes an empty cgroup. A missing cgroup is not an error.
func removeCgroup(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cgroup: %w", err)
	}
	return nil
}

func cgroupPIDs(path string) ([]int, error) {
	b, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			pids = append(pids, n)
		}
	}
	return pids, nil
}

// threadStatus is the part of /proc/<pid>/task/<tid>/status that the
// posture contract checks.
type threadStatus struct {
	uids, gids             []string
	capEff, capPrm, capAmb string
	noNewPrivs, seccomp    string
	nsPIDs                 int
}

func readThreadStatus(path string) (threadStatus, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return threadStatus{}, err
	}
	var st threadStatus
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			st.uids = strings.Fields(v)
		case "Gid":
			st.gids = strings.Fields(v)
		case "CapEff":
			st.capEff = v
		case "CapPrm":
			st.capPrm = v
		case "CapAmb":
			st.capAmb = v
		case "NoNewPrivs":
			st.noNewPrivs = v
		case "Seccomp":
			st.seccomp = v
		case "NSpid":
			st.nsPIDs = len(strings.Fields(v))
		}
	}
	return st, sc.Err()
}

// postureViolations checks every thread of every process in the cgroup
// against the posture contract.
func postureViolations(cgroup string, uid int) (threads int, violations []string, err error) {
	pids, err := cgroupPIDs(cgroup)
	if err != nil {
		return 0, nil, err
	}
	if len(pids) == 0 {
		return 0, []string{"no process in machine cgroup"}, nil
	}
	selfMounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0, nil, fmt.Errorf("read the vmcp mount table: %w", err)
	}
	want := strconv.Itoa(uid)
	zero := "0000000000000000"
	for _, pid := range pids {
		if v := mountViolation(pid, selfMounts); v != "" {
			violations = append(violations, v)
		}
		tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			continue
		}
		for _, t := range tasks {
			st, err := readThreadStatus(fmt.Sprintf("/proc/%d/task/%s/status", pid, t.Name()))
			if err != nil {
				continue
			}
			threads++
			check := func(ok bool, what string) {
				if !ok {
					violations = append(violations, fmt.Sprintf("pid %d tid %s: %s", pid, t.Name(), what))
				}
			}
			check(allEqual(st.uids, want) && allEqual(st.gids, want), "uid or gid is not the machine identity")
			check(st.capEff == zero && st.capPrm == zero && st.capAmb == zero, "capabilities are not empty")
			check(st.noNewPrivs == "1", "no_new_privs is not set")
			check(st.seccomp == "2", "seccomp filter is not active")
			check(st.nsPIDs >= 2, "not in its own PID namespace")
		}
	}
	return threads, violations, nil
}

// mountViolation checks that pid has its own mount namespace. It compares
// mount tables: vmcp cannot read /proc/<pid>/ns/mnt of another user
// without CAP_SYS_PTRACE, but it can read /proc/<pid>/mountinfo. A process
// that exited is not a violation.
func mountViolation(pid int, self []byte) string {
	v := ""
	mounts, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err == nil {
		var shared bool
		shared, err = sharesMounts(self, mounts)
		if shared {
			v = fmt.Sprintf("pid %d shares the vmcp mount namespace", pid)
		}
	}
	if err != nil {
		v = fmt.Sprintf("pid %d: the mount table is unreadable", pid)
	}
	if v != "" && exited(pid) {
		return ""
	}
	return v
}

// sharesMounts reports whether a mount table has a mount of the vmcp mount
// table. A new mount namespace holds copies of the mounts with new mount
// IDs, and the jailer then drops the old root, so a jailed process shares
// no mount ID with vmcp.
func sharesMounts(self, other []byte) (bool, error) {
	ours, theirs := mountIDs(self), mountIDs(other)
	if len(ours) == 0 || len(theirs) == 0 {
		return false, errors.New("a mount table is empty")
	}
	for id := range theirs {
		if ours[id] {
			return true, nil
		}
	}
	return false, nil
}

// mountIDs returns the mount IDs, the first field of each mountinfo line.
func mountIDs(mountinfo []byte) map[string]bool {
	ids := map[string]bool{}
	for _, line := range strings.Split(string(mountinfo), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			ids[f[0]] = true
		}
	}
	return ids
}

// exited reports whether pid is gone or a zombie.
func exited(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	// The state follows the command name, which is in parentheses.
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || i+2 >= len(b) {
		return true
	}
	return b[i+2] == 'Z' || b[i+2] == 'X'
}

func allEqual(vs []string, want string) bool {
	if len(vs) == 0 {
		return false
	}
	for _, v := range vs {
		if v != want {
			return false
		}
	}
	return true
}

// checkPosture enforces the posture contract once the guest agent runs. On
// a violation it kills the machine.
func (m *Machine) checkPosture() {
	threads, violations, err := postureViolations(m.cgroup, m.uid)
	p := map[string]any{"threads": threads, "ok": err == nil && len(violations) == 0}
	if len(violations) > 0 {
		p["violations"] = violations
	}
	m.mu.Lock()
	m.posture = p
	m.mu.Unlock()
	m.mu.Lock()
	logCtx := m.traceCtx
	m.mu.Unlock()
	if err != nil || len(violations) > 0 {
		attrs := []any{"code", "posture_violation", "threads", threads, "violations", len(violations)}
		if len(violations) > 0 {
			attrs = append(attrs, "first_violation", violations[0])
		}
		if err != nil {
			attrs = append(attrs, "error", trace.BoundedError(err))
		}
		m.log.ErrorContext(logCtx, "machine posture violation", attrs...)
		m.event(api.Event{Kind: api.EventStep, Step: "posture", Status: "failed"})
		m.Kill("posture-violation")
		return
	}
	m.log.DebugContext(logCtx, "posture verified", "threads", threads)
	m.event(api.Event{Kind: api.EventStep, Step: "posture", Status: "completed"})
}

// kernelPath is the state-root copy of the guest kernel. Jails hardlink it.
func (r *Runtime) kernelPath() string { return filepath.Join(r.binDir(), "vmlinux") }

// installKernel copies the guest kernel into the state root, read-only.
func (r *Runtime) installKernel() error {
	src, err := os.Open(r.cfg.KernelPath)
	if err != nil {
		return fmt.Errorf("open guest kernel: %w", err)
	}
	defer func() { _ = src.Close() }()
	tmp := r.kernelPath() + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o444)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		return err
	}
	return os.Rename(tmp, r.kernelPath())
}
