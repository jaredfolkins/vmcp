package machine

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// extractTar writes a caller tar stream into dir. It accepts directories,
// regular files, and symlinks. It refuses paths that leave dir, never
// follows a symlink, skips every other entry type, and stops at maxBytes of
// file content. It also limits the entries and the stream: a tar of empty
// files, links, or skipped entries has no file content, and it would
// otherwise fill the inodes of the state volume or never end.
func extractTar(r io.Reader, dir string, maxBytes int64) error {
	maxEntries := maxBytes/tarBytesPerEntry + tarMinEntries
	lr := &io.LimitedReader{R: r, N: maxBytes + maxEntries*tarEntryOverhead + 1}
	r = lr
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	var written, entries int64
	for {
		hdr, err := tr.Next()
		if lr.N <= 0 {
			return fmt.Errorf("drive tar stream is too large for a drive of %d bytes", maxBytes)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read drive tar: %w", err)
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("drive tar has more than %d entries", maxEntries)
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if name == "" {
			continue
		}
		for _, seg := range strings.Split(hdr.Name, "/") {
			if seg == ".." {
				return fmt.Errorf("drive tar path %q has a .. segment", hdr.Name)
			}
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := noSymlinkParents(dir, name); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(hdr.Mode & 0o777)
		switch hdr.Typeflag {
		case tar.TypeDir:
			// An earlier entry can be a symlink of this name. MkdirAll and
			// Chmod would follow it out of the drive.
			if fi, err := os.Lstat(target); err == nil && !fi.IsDir() {
				if err := os.Remove(target); err != nil {
					return err
				}
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			if err := os.Chmod(target, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if written+hdr.Size > maxBytes {
				return fmt.Errorf("drive tar is larger than %d bytes", maxBytes)
			}
			_ = os.Remove(target)
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode|0o600)
			if err != nil {
				return err
			}
			n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
			cerr := f.Close()
			written += n
			if err != nil || cerr != nil {
				return errors.Join(err, cerr)
			}
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		default:
			continue
		}
		if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil && !errors.Is(err, os.ErrPermission) {
			return err
		}
	}
}

// A drive holds at most one entry for each tarBytesPerEntry of its size,
// plus tarMinEntries. The stream may spend tarEntryOverhead on each entry
// for headers and padding.
const (
	tarBytesPerEntry = 4096
	tarMinEntries    = 4096
	tarEntryOverhead = 4096
)

func noSymlinkParents(dir, name string) error {
	cur := dir
	parts := strings.Split(name, "/")
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("drive tar path %q crosses a non-directory", name)
		}
	}
	return nil
}
