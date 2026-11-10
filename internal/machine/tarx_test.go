package machine

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestExtractDirDoesNotFollowSymlink proves that a directory entry with
// the name of an earlier symlink entry does not change the link target.
func TestExtractDirDoesNotFollowSymlink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "a", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777},
		{Name: "a", Typeflag: tar.TypeDir, Mode: 0o777},
	} {
		h.Uid, h.Gid = os.Getuid(), os.Getgid()
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "drive")
	if err := extractTar(&buf, dir, 1<<20); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("link target mode = %v (%v), want 0700 unchanged", fi.Mode().Perm(), err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "a")); err != nil || !fi.IsDir() {
		t.Errorf("a is not a directory in the drive: %v", err)
	}
}
