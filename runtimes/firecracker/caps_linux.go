//go:build linux

package firecracker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// serviceCaps are the capabilities that vmcp needs in its permitted set.
// The image gives them to the vmcp binary as file capabilities, so vmcp
// runs as UID 65532. vmcp uses them itself and raises a subset into the
// ambient set of each tool that needs one:
//   - CHOWN: give jail files, drives, and sockets to the machine user, and
//     keep the owners of image files;
//   - DAC_OVERRIDE: open /dev/kvm, remove jails that the machine user
//     owns, and read root-only image files (mke2fs);
//   - FOWNER and FSETID: keep the mode bits of root-owned image files,
//     also setgid bits of groups that vmcp is not in;
//   - NET_ADMIN: change taps and nftables (ip, nft), and watch nftables;
//   - NET_BIND_SERVICE: the DNS broker on port 53, also where the container
//     runtime does not open low ports to every user.
var serviceCaps = []uintptr{
	unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FOWNER, unix.CAP_FSETID,
	unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE,
}

// jailerCaps are the file capabilities of the baked jailer in the image:
// CHOWN and MKNOD for the jail files and device nodes, DAC_OVERRIDE for
// the root-owned cgroup files, SETUID and SETGID for the machine user, and
// SYS_ADMIN for the mount namespace and pivot_root. The jailer gets them
// from its file, not from the ambient set: a jailer that runs as UID 65532
// keeps its ambient set across its UID change and gives it to Firecracker.
// A file with capabilities clears the ambient set, so Firecracker starts
// with no capability.
var jailerCaps = []uintptr{
	unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_MKNOD,
	unix.CAP_SETGID, unix.CAP_SETUID, unix.CAP_SYS_ADMIN,
}

var capNames = map[uintptr]string{
	unix.CAP_CHOWN: "CHOWN", unix.CAP_DAC_OVERRIDE: "DAC_OVERRIDE", unix.CAP_FOWNER: "FOWNER",
	unix.CAP_FSETID: "FSETID", unix.CAP_MKNOD: "MKNOD", unix.CAP_NET_ADMIN: "NET_ADMIN",
	unix.CAP_NET_BIND_SERVICE: "NET_BIND_SERVICE", unix.CAP_SETGID: "SETGID", unix.CAP_SETUID: "SETUID",
	unix.CAP_SYS_ADMIN: "SYS_ADMIN", unix.CAP_SYS_CHROOT: "SYS_CHROOT", unix.CAP_SYS_RESOURCE: "SYS_RESOURCE",
}

func capMask(caps []uintptr) uint64 {
	var m uint64
	for _, c := range caps {
		m |= 1 << c
	}
	return m
}

func capList(mask uint64) string {
	var names []string
	for c := uintptr(0); c < 64; c++ {
		if mask&(1<<c) == 0 {
			continue
		}
		if n, ok := capNames[c]; ok {
			names = append(names, n)
		} else {
			names = append(names, "cap_"+strconv.Itoa(int(c)))
		}
	}
	return strings.Join(names, ",")
}

// CheckProcessCapabilities refuses to run unless this process holds the
// capabilities that vmcp needs. vmcp serve calls it before it reads the
// credential, which the vmcp user can read only with DAC_OVERRIDE.
func CheckProcessCapabilities() error { return checkProcessCapabilities("/proc/self/status") }

// checkProcessCapabilities refuses to run unless the permitted set holds
// serviceCaps. no-new-privileges stops the kernel from granting file
// capabilities, so the error names it when it is set.
func checkProcessCapabilities(statusPath string) error {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Errorf("read process status: %w", err)
	}
	var prm uint64
	var nnp, found bool
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "CapPrm":
			if prm, err = strconv.ParseUint(v, 16, 64); err != nil {
				return fmt.Errorf("parse permitted capabilities: %w", err)
			}
			found = true
		case "NoNewPrivs":
			nnp = v == "1"
		}
	}
	if !found {
		return errors.New("process status has no permitted capability set")
	}
	if missing := capMask(serviceCaps) &^ prm; missing != 0 {
		if nnp {
			return fmt.Errorf("vmcp lacks capabilities %s: no-new-privileges blocks the file capabilities of vmcp; do not set it", capList(missing))
		}
		return fmt.Errorf("vmcp lacks capabilities %s: add them to the container capability set", capList(missing))
	}
	return nil
}

// checkJailer verifies the baked jailer: its size and SHA-256 match the
// release lock, its file capabilities are exactly jailerCaps with the
// effective flag, and its file system honors file capabilities.
func checkJailer(path string) error {
	if path == "" {
		return errors.New("the jailer path is required")
	}
	if err := VerifyArtifactFile(path, "jailer"); err != nil {
		return err
	}
	prm, eff, err := fileCapabilities(path)
	if err != nil {
		return err
	}
	if want := capMask(jailerCaps); prm != want || !eff {
		return fmt.Errorf("jailer %s has file capabilities %q (effective %t), want %q with effective set",
			path, capList(prm), eff, capList(want))
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return fmt.Errorf("inspect jailer file system: %w", err)
	}
	if fs.Flags&unix.ST_NOSUID != 0 {
		return fmt.Errorf("jailer %s is on a nosuid file system, which ignores file capabilities", path)
	}
	return nil
}

// fileCapabilities reads the permitted set and the effective flag from the
// security.capability attribute of a file.
func fileCapabilities(path string) (permitted uint64, effective bool, err error) {
	buf := make([]byte, 64)
	n, err := unix.Getxattr(path, "security.capability", buf)
	if errors.Is(err, unix.ENODATA) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read file capabilities of %s: %w", path, err)
	}
	return parseFileCaps(buf[:n])
}

// parseFileCaps decodes a vfs_cap_data value of revision 2 or 3.
func parseFileCaps(b []byte) (permitted uint64, effective bool, err error) {
	const (
		revisionMask = 0xff000000
		revision2    = 0x02000000
		revision3    = 0x03000000
		flagEff      = 0x000001
	)
	if len(b) < 4 {
		return 0, false, errors.New("file capabilities are too short")
	}
	magic := binary.LittleEndian.Uint32(b)
	switch rev := magic & revisionMask; {
	case rev == revision2 && len(b) == 20, rev == revision3 && len(b) == 24:
	default:
		return 0, false, fmt.Errorf("file capabilities revision %#x with %d bytes is not supported", rev, len(b))
	}
	lo := binary.LittleEndian.Uint32(b[4:])
	hi := binary.LittleEndian.Uint32(b[12:])
	return uint64(hi)<<32 | uint64(lo), magic&flagEff != 0, nil
}
