// Package objectmount serves a guest folder from an upstream that speaks
// the object mount protocol (api.Mount). It is a FUSE file system in the
// guest agent: each file operation becomes an HTTP request to the upstream
// broker, so no file byte is stored on a guest or host disk.
//
// A file opened only for writing with O_TRUNC, as cp, shell redirection,
// and curl -o do, streams in order as one upload. Every other write, also
// an append, a write out of order, and a truncate, uses a write-back buffer
// in guest memory within the write-back budget of the mount, and the whole
// file goes on flush, fsync, and release. A file that does not fit fails
// with EFBIG. A file is stored when its last descriptor closes, or on a
// close or fsync by the opening process after a write; a read of a file that
// is being written waits for that. A rename copies the file through the
// mount. The protocol has no empty folders: mkdir makes a folder in memory,
// which lasts until the mount ends or a file is written below it.
package objectmount

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Options configure one mount.
type Options struct {
	// URL is the upstream URL of the mount root.
	URL      string
	ReadOnly bool
	// WriteBack is the byte budget of the write-back buffers; mounts may
	// share one.
	WriteBack *Budget
	// MaxBytes is the declared largest size of a streamed upload.
	MaxBytes int64
	// Uploads is the number of concurrent uploads.
	Uploads int
	// SmallFile is the size up to which a new file is kept and sent with its
	// exact length.
	SmallFile int
	// AllowOther lets processes of other users use the mount; it needs a
	// root mounter.
	AllowOther bool
	// DirectMount mounts with the mount system call, as root does, and not
	// with fusermount.
	DirectMount bool
	// Proc is the proc file system of the processes that use the mount;
	// empty is /proc.
	Proc string
	// Transport is the HTTP transport; nil uses a transport without a proxy.
	Transport http.RoundTripper
}

// ErrOpenWriters reports files that stayed open for writing when a mount
// closed; their changes are lost.
var ErrOpenWriters = errors.New("object mount: files stayed open for writing")

// Server serves one mount.
type Server struct {
	fuse *fuse.Server
	st   *state
}

// Close waits at most wait until no file is open for writing and its
// upload is done, and then unmounts. It reports files that stayed open and
// uploads that failed.
func (s *Server) Close(wait time.Duration) error {
	var errs []error
	if !s.st.writers.wait(context.Background(), wait) {
		errs = append(errs, ErrOpenWriters)
	}
	if err := s.fuse.Unmount(); err != nil {
		errs = append(errs, fmt.Errorf("object mount: unmount: %w", err))
	}
	if n := s.st.failed.Load(); n > 0 {
		errs = append(errs, fmt.Errorf("object mount: %d uploads failed", n))
	}
	return errors.Join(errs...)
}

// Mount serves the mount at dir until Close.
func Mount(dir string, opt Options) (*Server, error) {
	if opt.URL == "" || opt.WriteBack == nil || opt.MaxBytes <= 0 || opt.Uploads <= 0 || opt.SmallFile <= 0 {
		return nil, errors.New("object mount: URL, WriteBack, MaxBytes, Uploads, and SmallFile are required")
	}
	transport := opt.Transport
	if transport == nil {
		transport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: opt.Uploads + 2}
	}
	st := &state{
		c:         newClient(opt.URL, opt.MaxBytes, opt.Uploads, transport),
		readOnly:  opt.ReadOnly,
		smallFile: opt.SmallFile,
		budget:    opt.WriteBack,
		proc:      opt.Proc,
		dirs:      map[string]bool{},
	}
	if st.proc == "" {
		st.proc = "/proc"
	}
	second := time.Second
	server, err := fs.Mount(dir, &dirNode{st: st}, &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:      "vmcp-object",
			Name:        "vmcp",
			AllowOther:  opt.AllowOther,
			DirectMount: opt.DirectMount,
		},
		EntryTimeout:    &second,
		AttrTimeout:     &second,
		NegativeTimeout: &second,
	})
	if err != nil {
		return nil, err
	}
	return &Server{fuse: server, st: st}, nil
}
