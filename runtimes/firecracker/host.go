package firecracker

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/jaredfolkins/vmcp/api"
)

// Name is the runtime name in status and proofs.
const Name = "firecracker"

// Host is the set of host paths that the runtime checks. Tests replace
// them.
type Host struct {
	KVMDevice      string
	TUNDevice      string
	CgroupControls string
	MemInfo        string
}

// DefaultHost is the production host layout.
var DefaultHost = Host{
	KVMDevice:      "/dev/kvm",
	TUNDevice:      "/dev/net/tun",
	CgroupControls: "/sys/fs/cgroup/cgroup.controllers",
	MemInfo:        "/proc/meminfo",
}

// Checks reports whether this host can run Firecracker guests.
func (h Host) Checks() []api.Check {
	checks := []api.Check{releaseCheck()}
	checks = append(checks, deviceCheck("kvm", h.KVMDevice), deviceCheck("tun", h.TUNDevice))
	if _, err := os.Stat(h.CgroupControls); err != nil {
		checks = append(checks, api.Check{Name: "cgroup2", Detail: "cgroup v2 controllers are not readable"})
	} else {
		checks = append(checks, api.Check{Name: "cgroup2", OK: true})
	}
	return checks
}

// Status reports the runtime release, host checks, and host capacity.
// Ready is true only when every check passes.
func (h Host) Status() api.Status {
	st := api.Status{Runtime: Name, Checks: h.Checks(), Ready: true}
	if r, err := BakedRelease(); err == nil {
		st.Release = r.Version
	}
	vcpus, memoryMiB, err := h.Capacity()
	if err != nil {
		st.Checks = append(st.Checks, api.Check{Name: "capacity", Detail: "host capacity is unknown"})
	} else {
		st.Capacity = api.Capacity{VCPUs: vcpus, MemoryMiB: memoryMiB}
	}
	for _, c := range st.Checks {
		st.Ready = st.Ready && c.OK
	}
	return st
}

// Capacity returns the host CPU count and memory in MiB.
func (h Host) Capacity() (vcpus, memoryMiB int, err error) {
	data, err := os.ReadFile(h.MemInfo)
	if err != nil {
		return 0, 0, fmt.Errorf("read host memory: %w", err)
	}
	kib, err := memTotalKiB(data)
	if err != nil {
		return 0, 0, err
	}
	return runtime.NumCPU(), int(kib / 1024), nil
}

func releaseCheck() api.Check {
	r, err := BakedRelease()
	if err != nil {
		return api.Check{Name: "release", Detail: "baked release lock is invalid"}
	}
	return api.Check{Name: "release", OK: true, Detail: r.Version}
}

// deviceCheck opens the device read-write and closes it at once.
func deviceCheck(name, path string) api.Check {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return api.Check{Name: name, Detail: "device is not readable and writable"}
	}
	_ = f.Close()
	return api.Check{Name: name, OK: true}
}

func memTotalKiB(meminfo []byte) (int64, error) {
	s := bufio.NewScanner(bytes.NewReader(meminfo))
	for s.Scan() {
		fields := bytes.Fields(s.Bytes())
		if len(fields) == 3 && string(fields[0]) == "MemTotal:" && string(fields[2]) == "kB" {
			kib, err := strconv.ParseInt(string(fields[1]), 10, 64)
			if err != nil || kib <= 0 {
				return 0, errors.New("host MemTotal is invalid")
			}
			return kib, nil
		}
	}
	return 0, errors.New("host MemTotal is missing")
}
