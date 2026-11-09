//go:build linux

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

// exportDrives runs the drive export guest. It mounts a tmpfs on the merged
// root, mounts each writable drive at its guest path below it, and sends the
// drive tar as a process guest does after its exit. The kernel replays the
// journal of a drive that the first guest did not unmount. A drive that
// fails does not stop the others.
func exportDrives(cfg agentproto.Config) error {
	if err := mountAt("tmpfs", mergedRoot, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return err
	}
	var errs []error
	for _, d := range cfg.Drives {
		if !d.Writable {
			continue
		}
		if err := exportDrive(d); err != nil {
			errs = append(errs, fmt.Errorf("export drive %s: %w", d.Name, err))
		}
	}
	return errors.Join(errs...)
}

func exportDrive(d agentproto.Drive) error {
	target, err := guestPath(d.GuestPath)
	if err != nil {
		return err
	}
	if err := mountAt(d.Device, target, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	return sendDrive(d)
}
