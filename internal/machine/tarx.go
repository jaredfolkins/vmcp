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
// file content.
func extractTar(r io.Reader, dir string, maxBytes int64) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	var written int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read drive tar: %w", err)
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
