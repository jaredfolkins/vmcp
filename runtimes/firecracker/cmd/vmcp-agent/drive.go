//go:build linux

package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

// sendDrive streams the tar of one writable drive to the host. It writes
// directories, regular files, and symlinks. It skips every other type.
func sendDrive(d agentproto.Drive) error {
	root, err := guestPath(d.GuestPath)
	if err != nil {
		return err
	}
	conn, err := dialVsock(agentproto.DrivePort)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(agentproto.DriveHeader{Name: d.Name}); err != nil {
		return fmt.Errorf("send drive header: %w", err)
	}
	tw := tar.NewWriter(conn)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return writeEntry(tw, path, filepath.ToSlash(rel), info)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func writeEntry(tw *tar.Writer, path, name string, info fs.FileInfo) error {
	var link string
	switch {
	case info.Mode().IsRegular(), info.IsDir():
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return err
		}
		link = target
	default:
		return nil
	}
	hdr, err := tar.FileInfoHeader(info, link)
	if err != nil {
		return err
	}
	hdr.Name = name
	if info.IsDir() {
		hdr.Name += "/"
	}
	hdr.Format = tar.FormatPAX
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		hdr.Uid, hdr.Gid = int(st.Uid), int(st.Gid)
	}
	hdr.Uname, hdr.Gname = "", ""
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(tw, f)
	return err
}
