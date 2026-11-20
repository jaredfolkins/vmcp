//go:build linux

package objectmount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestListingWithoutAnEndIsRefused proves that a folder listing has an end
// in guest memory. The upstream is not in the guest, but one mount must not
// fill the memory of its guest:
//   - pages with a new token each time stop with EOVERFLOW after the entry
//     limit, and the client asks for no page after that;
//   - the same token again stops with EIO;
//   - an empty page with a token stops with EIO.
//
// A failure here detects a listing loop that has no limit.
func TestListingWithoutAnEndIsRefused(t *testing.T) {
	in := readObjectMountTestInput(t)
	for _, tc := range []struct {
		name string
		// page returns the entry count and the next token of request n.
		page func(n int) (int, string)
		want syscall.Errno
		// maxRequests is the largest number of requests that the client
		// may send.
		maxRequests int
	}{
		{
			name:        "new token each time",
			page:        func(n int) (int, string) { return in.ListPageEntries, fmt.Sprintf("t%d", n) },
			want:        syscall.EOVERFLOW,
			maxRequests: in.ListLimit/in.ListPageEntries + 1,
		},
		{
			name:        "same token again",
			page:        func(int) (int, string) { return 1, "same" },
			want:        syscall.EIO,
			maxRequests: 2,
		},
		{
			name:        "empty page with a token",
			page:        func(n int) (int, string) { return 0, fmt.Sprintf("t%d", n) },
			want:        syscall.EIO,
			maxRequests: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := int(requests.Add(1))
				count, next := tc.page(n)
				entries := make([]map[string]any, 0, count)
				for i := range count {
					entries = append(entries, map[string]any{"name": fmt.Sprintf("f-%d-%d", n, i), "size": 1})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries, "next": next})
			}))
			defer srv.Close()
			c := newClient(srv.URL, in.MaxBytes, in.Uploads, http.DefaultTransport)
			c.listLimit = in.ListLimit
			entries, err := c.list(context.Background(), "")
			if !errors.Is(err, tc.want) || entries != nil {
				t.Fatalf("list() = %d entries, %v; want no entries and %v", len(entries), err, tc.want)
			}
			if got := int(requests.Load()); got > tc.maxRequests {
				t.Errorf("list() sent %d requests, want at most %d", got, tc.maxRequests)
			}
		})
	}
}

// TestStalledStreamEndsWithAnError proves that a streamed upload does not
// wait without a limit. The upstream accepts the request, reads no byte of
// the body, and sends no answer. The write or the close of the file must
// fail before the deadline, and the mount must then close with no open
// writer. A failure here detects a process that hangs on a dead upstream.
func TestStalledStreamEndsWithAnError(t *testing.T) {
	in := readObjectMountTestInput(t)
	release := make(chan struct{})
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.NotFound(w, r)
			return
		}
		puts.Add(1)
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	dir := t.TempDir()
	server, err := Mount(dir, Options{
		URL: srv.URL + "/root", WriteBack: NewBudget(in.WriteBack), MaxBytes: in.MaxBytes,
		Uploads: in.Uploads, SmallFile: in.SmallFile,
	})
	if err != nil {
		t.Fatalf("mount: %v (the test needs /dev/fuse and fusermount3)", err)
	}
	server.st.c.stallWait = time.Duration(in.StallWaitMS) * time.Millisecond

	result := make(chan error, 1)
	go func() {
		f, err := os.OpenFile(filepath.Join(dir, "stalled.bin"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			result <- fmt.Errorf("open: %w", err)
			return
		}
		_, writeErr := io.Copy(f, &patternReader{left: in.LargeSize})
		closeErr := f.Close()
		if writeErr == nil && closeErr == nil {
			result <- nil
			return
		}
		result <- errors.Join(writeErr, closeErr)
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("the write and the close of a stalled stream passed, want an error")
		}
		if !errors.Is(err, syscall.EIO) {
			t.Errorf("stalled stream error = %v, want EIO", err)
		}
	case <-time.After(time.Duration(in.StallDeadlineMS) * time.Millisecond):
		t.Fatal("the write of a stalled stream did not end before the deadline")
	}
	if puts.Load() != 1 {
		t.Errorf("the upstream got %d uploads, want 1", puts.Load())
	}
	if err := server.Close(time.Duration(in.StallDeadlineMS) * time.Millisecond); errors.Is(err, ErrOpenWriters) {
		t.Errorf("Close() after the stalled stream = %v, want no open writer", err)
	}
}

// patternReader gives left bytes of the test pattern.
type patternReader struct{ left int }

func (r *patternReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.left)
	for i := range n {
		p[i] = byte(i * 31)
	}
	r.left -= n
	return n, nil
}
