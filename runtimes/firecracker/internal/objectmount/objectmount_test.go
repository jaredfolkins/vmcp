//go:build linux

package objectmount

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/objectmount/objectmounttest"
)

var objectMountTestConfig = flag.String("vmcp-objectmount-config", "testdata/objectmount.hujson", "HuJSON file for the object mount tests")

type objectMountTestInput struct {
	SmallFile      int   `json:"small_file"`
	Uploads        int   `json:"uploads"`
	MaxBytes       int64 `json:"max_bytes"`
	WriteBack      int64 `json:"write_back"`
	SmallSize      int   `json:"small_size"`
	LargeSize      int   `json:"large_size"`
	OverBudgetSize int   `json:"over_budget_size"`
	OverMaxSize    int   `json:"over_max_size"`
	EntryWaitMS    int   `json:"entry_wait_ms"`
	Shell          []struct {
		Name       string `json:"name"`
		Script     string `json:"script"`
		Want       string `json:"want"`
		StoredSize int    `json:"stored_size"`
	} `json:"shell"`
}

func readObjectMountTestInput(t *testing.T) objectMountTestInput {
	t.Helper()
	raw, err := os.ReadFile(*objectMountTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in objectMountTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.SmallSize > in.SmallFile || in.LargeSize <= in.SmallFile || in.OverBudgetSize <= int(in.WriteBack) ||
		int64(in.OverMaxSize) <= in.MaxBytes || len(in.Shell) == 0 {
		t.Fatal("object mount test input sizes do not fit the limits")
	}
	return in
}

func pattern(size int, seed byte) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*31) + seed
	}
	return data
}

func mountFake(t *testing.T, in objectMountTestInput, readOnly bool) (*objectmounttest.Upstream, string, *Server) {
	t.Helper()
	upstream := objectmounttest.New("/root", "")
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	server, err := Mount(dir, Options{
		URL: srv.URL + "/root", ReadOnly: readOnly, WriteBack: in.WriteBack, MaxBytes: in.MaxBytes,
		Uploads: in.Uploads, SmallFile: in.SmallFile,
	})
	if err != nil {
		t.Fatalf("mount: %v (the test needs /dev/fuse and fusermount3)", err)
	}
	t.Cleanup(func() { _ = server.Close(time.Second) })
	return upstream, dir, server
}

// TestObjectMountFileOperations proves that ordinary file calls on the mount
// become object mount protocol requests: a small file goes with its exact
// length and a large one streams; reads, ranged reads, an append, a write
// out of order, a truncate, a rename, folders, and a remove change the
// upstream objects; a file being written stays visible past the entry
// timeout; and a read-write file over the write-back budget fails with
// EFBIG.
func TestObjectMountFileOperations(t *testing.T) {
	in := readObjectMountTestInput(t)
	upstream, dir, server := mountFake(t, in, false)

	small := pattern(in.SmallSize, 1)
	if err := os.WriteFile(filepath.Join(dir, "small.bin"), small, 0o644); err != nil {
		t.Fatalf("write a small file: %v", err)
	}
	if got, ok, chunked := upstream.Object("small.bin"); !ok || !bytes.Equal(got, small) || chunked {
		t.Errorf("small file: stored %v, chunked %v; want its bytes with an exact length", ok, chunked)
	}

	large := pattern(in.LargeSize, 2)
	if err := os.WriteFile(filepath.Join(dir, "large.bin"), large, 0o644); err != nil {
		t.Fatalf("write a large file: %v", err)
	}
	if got, ok, chunked := upstream.Object("large.bin"); !ok || !bytes.Equal(got, large) || !chunked {
		t.Errorf("large file: stored %v (%d bytes), chunked %v; want its bytes in one chunked upload", ok, len(got), chunked)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "large.bin")); err != nil || !bytes.Equal(got, large) {
		t.Errorf("read the large file: %v, equal %v", err, bytes.Equal(got, large))
	}
	// The kernel truncates an existing file after the open, so this proves
	// that an overwrite streams and does not load the old file.
	large = pattern(in.LargeSize, 4)
	if err := os.WriteFile(filepath.Join(dir, "large.bin"), large, 0o644); err != nil {
		t.Fatalf("overwrite the large file: %v", err)
	}
	if got, _, chunked := upstream.Object("large.bin"); !bytes.Equal(got, large) || !chunked {
		t.Errorf("overwrite: stored %d bytes, chunked %v; want the new bytes in one chunked upload", len(got), chunked)
	}
	file, err := os.Open(filepath.Join(dir, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	part := make([]byte, 100)
	if _, err := file.ReadAt(part, int64(in.LargeSize/2)); err != nil || !bytes.Equal(part, large[in.LargeSize/2:in.LargeSize/2+100]) {
		t.Errorf("ranged read: %v", err)
	}
	_ = file.Close()

	appendFile, err := os.OpenFile(filepath.Join(dir, "small.bin"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appendFile.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := appendFile.Close(); err != nil {
		t.Fatalf("close the appended file: %v", err)
	}
	if got, _, _ := upstream.Object("small.bin"); !bytes.Equal(got, append(append([]byte(nil), small...), "tail"...)) {
		t.Errorf("append: stored %d bytes, want the file and the tail", len(got))
	}

	rw, err := os.OpenFile(filepath.Join(dir, "small.bin"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.WriteAt([]byte("XY"), 10); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close the changed file: %v", err)
	}
	if got, _, _ := upstream.Object("small.bin"); len(got) < 12 || string(got[10:12]) != "XY" {
		t.Error("a write out of order did not reach the upstream object")
	}
	if err := os.Truncate(filepath.Join(dir, "small.bin"), 5); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got, _, _ := upstream.Object("small.bin"); len(got) != 5 {
		t.Errorf("truncate: stored %d bytes, want 5", len(got))
	}

	if err := os.Rename(filepath.Join(dir, "small.bin"), filepath.Join(dir, "moved.bin")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, ok, _ := upstream.Object("small.bin"); ok {
		t.Error("rename left the source object")
	}
	if got, ok, _ := upstream.Object("moved.bin"); !ok || len(got) != 5 {
		t.Error("rename did not make the target object")
	}

	if err := os.MkdirAll(filepath.Join(dir, "d", "e"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d", "e", "f.txt"), []byte("f"), 0o644); err != nil {
		t.Fatalf("write in a new folder: %v", err)
	}
	if _, ok, _ := upstream.Object("d/e/f.txt"); !ok {
		t.Error("a file in a new folder did not reach the upstream")
	}
	names := func(path string) []string {
		entries, err := os.ReadDir(path)
		if err != nil {
			t.Fatalf("read dir %s: %v", path, err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	if got := strings.Join(names(dir), ","); got != "d,large.bin,moved.bin" {
		t.Errorf("root listing = %s", got)
	}
	if got := strings.Join(names(filepath.Join(dir, "d")), ","); got != "e" {
		t.Errorf("folder listing = %s", got)
	}

	if err := os.Remove(filepath.Join(dir, "moved.bin")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "moved.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat after remove = %v, want not exist", err)
	}

	open, err := os.Create(filepath.Join(dir, "open.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(in.EntryWaitMS) * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "open.bin")); err != nil {
		t.Errorf("a file being written vanished after the entry timeout: %v", err)
	}
	_ = open.Close()

	over, err := os.OpenFile(filepath.Join(dir, "over.bin"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = over.Write(pattern(in.OverBudgetSize, 3))
	_ = over.Close()
	if !errors.Is(err, syscall.EFBIG) {
		t.Errorf("read-write file over the write-back budget: %v, want EFBIG", err)
	}
	if err := server.Close(time.Second); err != nil {
		t.Errorf("close the mount: %v", err)
	}
}

// TestObjectMountShellWrites proves that shell redirects store the whole
// file although the shell and its children close copies of the descriptor
// before the last write, and that a read right after the close sees it; and
// that a file over the size limit fails and leaves no object.
func TestObjectMountShellWrites(t *testing.T) {
	in := readObjectMountTestInput(t)
	upstream, dir, server := mountFake(t, in, false)
	for i, c := range in.Shell {
		t.Run(c.Name, func(t *testing.T) {
			name := fmt.Sprintf("shell-%d.txt", i)
			cmd := exec.Command("sh", "-c", c.Script)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "FILE=" + filepath.Join(dir, name)}
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != c.Want {
				t.Errorf("script output = %q, %v; want %q", out, err, c.Want)
			}
			if got, ok, _ := upstream.Object(name); !ok || len(got) != c.StoredSize {
				t.Errorf("stored %d bytes (%v), want %d", len(got), ok, c.StoredSize)
			}
		})
	}
	err := os.WriteFile(filepath.Join(dir, "too-large.bin"), pattern(in.OverMaxSize, 5), 0o644)
	if err == nil {
		t.Error("a file over the size limit was written without an error")
	}
	if _, ok, _ := upstream.Object("too-large.bin"); ok {
		t.Error("a file over the size limit left an object")
	}
	if err := server.Close(time.Second); err == nil || !strings.Contains(err.Error(), "1 uploads failed") {
		t.Errorf("close the mount = %v, want the one failed upload", err)
	}
}

// TestObjectMountReadOnlyRefusesWrites proves that a read-only mount reads
// and refuses each change.
func TestObjectMountReadOnlyRefusesWrites(t *testing.T) {
	in := readObjectMountTestInput(t)
	upstream, dir, _ := mountFake(t, in, true)
	upstream.Put("kept.txt", []byte("kept"))
	if got, err := os.ReadFile(filepath.Join(dir, "kept.txt")); err != nil || string(got) != "kept" {
		t.Errorf("read on a read-only mount: %q, %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x"), 0o644); !errors.Is(err, syscall.EROFS) {
		t.Errorf("write on a read-only mount = %v, want EROFS", err)
	}
	if err := os.Remove(filepath.Join(dir, "kept.txt")); !errors.Is(err, syscall.EROFS) {
		t.Errorf("remove on a read-only mount = %v, want EROFS", err)
	}
}
