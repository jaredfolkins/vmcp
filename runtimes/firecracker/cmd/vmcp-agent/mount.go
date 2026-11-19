package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/objectmount"
)

// objectSmallFile is the size up to which a new file is sent with its
// exact length.
const objectSmallFile = 1 << 20

// mountObjects serves each object mount in the guest root. One quarter of
// the guest memory is the write-back budget, shared by the mounts.
func mountObjects(mounts []agentproto.Mount) ([]*objectmount.Server, error) {
	if len(mounts) == 0 {
		return nil, nil
	}
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return nil, fmt.Errorf("read guest memory: %w", err)
	}
	budget := int64(info.Totalram) * int64(info.Unit) / 4 / int64(len(mounts))
	var servers []*objectmount.Server
	for _, m := range mounts {
		target, err := guestPath(m.GuestPath)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return nil, fmt.Errorf("create mount %s: %w", m.GuestPath, err)
		}
		server, err := objectmount.Mount(target, objectmount.Options{
			URL:         m.URL,
			ReadOnly:    m.ReadOnly,
			WriteBack:   budget,
			MaxBytes:    m.MaxBytes,
			Uploads:     m.Uploads,
			SmallFile:   objectSmallFile,
			AllowOther:  true,
			DirectMount: true,
			Proc:        filepath.Join(mergedRoot, "proc"),
		})
		if err != nil {
			return nil, fmt.Errorf("mount %s: %w", m.GuestPath, err)
		}
		servers = append(servers, server)
	}
	return servers, nil
}
