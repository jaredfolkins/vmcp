package image

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// Layer media types.
const (
	mediaOCILayer       = "application/vnd.oci.image.layer.v1.tar"
	mediaOCILayerGzip   = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaDockerLayer    = "application/vnd.docker.image.rootfs.diff.tar"
	mediaDockerLayerGzi = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// unpacker applies image layers to one root directory. It refuses paths
// that leave the root, never follows a symlink, and skips device nodes and
// FIFOs so that no special file is created on the host.
type unpacker struct {
	root     string
	maxBytes int64
	written  int64
	dirs     []dirMeta
}

type dirMeta struct {
	path     string
	mode     os.FileMode
	uid, gid int
}

func layerReader(mediaType string, r io.Reader) (io.Reader, func() error, error) {
	switch mediaType {
	case mediaOCILayer, mediaDockerLayer:
		return r, func() error { return nil }, nil
	case mediaOCILayerGzip, mediaDockerLayerGzi:
		zr, err := gzip.NewReader(r)
		if err != nil {
			return nil, nil, fmt.Errorf("open gzip layer: %w", err)
		}
		return zr, zr.Close, nil
	default:
		return nil, nil, fmt.Errorf("unsupported layer media type %q", mediaType)
	}
}

// apply unpacks one uncompressed layer tar stream.
func (u *unpacker) apply(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer: %w", err)
		}
		if err := u.entry(tr, hdr); err != nil {
			return err
		}
	}
}

func (u *unpacker) entry(tr *tar.Reader, hdr *tar.Header) error {
	rel, err := cleanRel(hdr.Name)
	if err != nil {
		return err
	}
	if rel == "" {
		return nil
	}
	dir, base := path.Split(rel)
	if base == ".wh..wh..opq" {
		return u.opaque(dir)
	}
	if name, ok := strings.CutPrefix(base, ".wh."); ok {
		return u.remove(path.Join(dir, name))
	}
	target, err := u.safePath(rel)
	if err != nil {
		return err
	}
	if err := u.mkdirParents(rel); err != nil {
		return err
	}
	mode := tarMode(hdr.Mode)
	switch hdr.Typeflag {
	case tar.TypeDir:
		if fi, err := os.Lstat(target); err == nil && !fi.IsDir() {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		}
		if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create directory %s: %w", rel, err)
		}
		u.dirs = append(u.dirs, dirMeta{path: target, mode: mode, uid: hdr.Uid, gid: hdr.Gid})
		return nil
	case tar.TypeReg:
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		if u.written+hdr.Size > u.maxBytes {
			return fmt.Errorf("image expands beyond %d bytes", u.maxBytes)
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", rel, err)
		}
		n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
		cerr := f.Close()
		u.written += n
		if err != nil || cerr != nil || n != hdr.Size {
			return fmt.Errorf("write %s: %w", rel, errors.Join(err, cerr))
		}
		return setMeta(target, mode, hdr.Uid, hdr.Gid)
	case tar.TypeSymlink:
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		if err := os.Symlink(hdr.Linkname, target); err != nil {
			return fmt.Errorf("create symlink %s: %w", rel, err)
		}
		return os.Lchown(target, hdr.Uid, hdr.Gid)
	case tar.TypeLink:
		srcRel, err := cleanRel(hdr.Linkname)
		if err != nil || srcRel == "" {
			return fmt.Errorf("hardlink %s has an invalid target", rel)
		}
		src, err := u.safePath(srcRel)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(src)
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("hardlink %s target is not a regular file in the image", rel)
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
		return os.Link(src, target)
	default:
		// Character and block devices, FIFOs, and unknown types are skipped.
		return nil
	}
}

// finish applies directory metadata, deepest first.
func (u *unpacker) finish() error {
	for i := len(u.dirs) - 1; i >= 0; i-- {
		d := u.dirs[i]
		if fi, err := os.Lstat(d.path); err != nil || !fi.IsDir() {
			continue
		}
		if err := setMeta(d.path, d.mode, d.uid, d.gid); err != nil {
			return err
		}
	}
	return nil
}

func (u *unpacker) opaque(dir string) error {
	target, err := u.safePath(strings.TrimSuffix(dir, "/"))
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(target, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (u *unpacker) remove(rel string) error {
	target, err := u.safePath(rel)
	if err != nil {
		return err
	}
	return os.RemoveAll(target)
}

// safePath maps rel to a host path and refuses a symlink in any parent.
func (u *unpacker) safePath(rel string) (string, error) {
	cur := u.root
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		if i == len(parts)-1 {
			break
		}
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("image path %s crosses a non-directory", rel)
		}
	}
	return cur, nil
}

func (u *unpacker) mkdirParents(rel string) error {
	cur := u.root
	parts := strings.Split(rel, "/")
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err == nil {
			if !fi.IsDir() {
				return fmt.Errorf("image path %s crosses a non-directory", rel)
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := os.Mkdir(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// cleanRel returns the clean relative form of a tar path, or "" for the
// root. It refuses absolute paths that leave the root and ".." segments.
func cleanRel(name string) (string, error) {
	n := strings.TrimPrefix(name, "./")
	n = strings.TrimPrefix(n, "/")
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return "", fmt.Errorf("image path %q has a .. segment", name)
		}
	}
	n = path.Clean(n)
	if n == "." {
		return "", nil
	}
	return n, nil
}

// tarMode maps tar mode bits, including setuid, setgid, and sticky, to an
// os.FileMode.
func tarMode(m int64) os.FileMode {
	mode := os.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

func setMeta(p string, mode os.FileMode, uid, gid int) error {
	if err := os.Lchown(p, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", p, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", p, err)
	}
	return nil
}
