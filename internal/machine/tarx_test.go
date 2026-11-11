package machine

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// TestExtractLimitsEntriesAndStream proves that a tar without file content
// cannot write entries without end, and that skipped content counts.
func TestExtractLimitsEntriesAndStream(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := range tarMinEntries + 2 {
		h := &tar.Header{Name: "f" + strconv.Itoa(i), Typeflag: tar.TypeReg, Mode: 0o644, Uid: os.Getuid(), Gid: os.Getgid()}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	err := extractTar(&buf, filepath.Join(t.TempDir(), "drive"), 0)
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Errorf("many empty files: err = %v, want the entry limit", err)
	}

	// A skipped entry type has content that is not file content.
	buf.Reset()
	tw = tar.NewWriter(&buf)
	body := make([]byte, tarMinEntries*tarEntryOverhead+4096)
	if err := tw.WriteHeader(&tar.Header{Name: "x", Typeflag: 'Z', Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	err = extractTar(&buf, filepath.Join(t.TempDir(), "drive"), 0)
	if err == nil || !strings.Contains(err.Error(), "stream") {
		t.Errorf("large skipped entry: err = %v, want the stream limit", err)
	}
}
