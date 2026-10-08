//go:build linux

package image

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// mke2fsAttr gives mke2fs CAP_DAC_OVERRIDE in its ambient set and no other
// capability. vmcp runs as a non-root user, and an image tree holds
// root-owned files that only root can read, such as /etc/shadow and /root.
// A process without the capability, such as a developer test run, runs
// mke2fs without it; vmcp serve refuses to start without it.
func mke2fsAttr() *syscall.SysProcAttr {
	if !permitted(unix.CAP_DAC_OVERRIDE) {
		return nil
	}
	return &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_DAC_OVERRIDE}}
}

// permitted reports whether c is in the permitted set of this thread, so
// that a child can get it in its ambient set.
func permitted(c uintptr) bool {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	return data[c/32].Permitted&(1<<(c%32)) != 0
}
