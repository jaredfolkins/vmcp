package objectmount

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// state is shared by all nodes of one mount.
type state struct {
	c         *client
	readOnly  bool
	smallFile int
	budget    *Budget
	// proc is the proc file system of the processes that use the mount.
	proc string

	// writers counts the open write handles of the mount, and failed the
	// releases whose upload failed.
	writers activity
	failed  atomic.Int64
	// stopping is set by Server.Stopping; dropped counts the files that a
	// close did not store after it.
	stopping atomic.Bool
	dropped  atomic.Int64

	mu sync.Mutex
	// dirs are folders that mkdir made and that hold no object yet. The
	// protocol has no empty folders, so they last until the mount ends.
	dirs map[string]bool
}

func (s *state) isDir(rel string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirs[rel]
}

func (s *state) setDir(rel string, made bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if made {
		s.dirs[rel] = true
	} else {
		delete(s.dirs, rel)
	}
}

// Budget bounds the bytes that write-back handles hold in guest memory. One
// Budget can serve all mounts of a guest.
type Budget struct {
	mu    sync.Mutex
	limit int64
	used  int64
}

func (b *Budget) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.limit {
		return false
	}
	b.used += n
	return true
}

func (b *Budget) release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func nodePath(n *fs.Inode) string {
	return strings.Trim(n.Path(n.Root()), "/")
}

const dirMode = syscall.S_IFDIR | 0o755

type dirNode struct {
	fs.Inode
	st *state
}

var (
	_ fs.NodeLookuper  = (*dirNode)(nil)
	_ fs.NodeReaddirer = (*dirNode)(nil)
	_ fs.NodeGetattrer = (*dirNode)(nil)
	_ fs.NodeCreater   = (*dirNode)(nil)
	_ fs.NodeMkdirer   = (*dirNode)(nil)
	_ fs.NodeUnlinker  = (*dirNode)(nil)
	_ fs.NodeRmdirer   = (*dirNode)(nil)
	_ fs.NodeRenamer   = (*dirNode)(nil)
	_ fs.NodeStatfser  = (*dirNode)(nil)
)

func (d *dirNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Mode = dirMode
	return 0
}

func (d *dirNode) Statfs(_ context.Context, out *fuse.StatfsOut) syscall.Errno {
	out.Bsize = 4096
	out.Frsize = 4096
	out.Blocks = 1 << 40
	out.Bfree = 1 << 40
	out.Bavail = 1 << 40
	out.Files = 1 << 30
	out.Ffree = 1 << 30
	out.NameLen = 255
	return 0
}

func (d *dirNode) newFile(ctx context.Context, a attr) *fs.Inode {
	if a.mode == 0 {
		a.mode = defaultMode
	}
	return d.NewInode(ctx, &fileNode{st: d.st, size: a.size, modified: a.modified, mode: a.mode}, fs.StableAttr{Mode: syscall.S_IFREG})
}

func (d *dirNode) newDir(ctx context.Context) *fs.Inode {
	return d.NewInode(ctx, &dirNode{st: d.st}, fs.StableAttr{Mode: syscall.S_IFDIR})
}

func (d *dirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	rel := join(nodePath(&d.Inode), name)
	// A file that is still being written is not in the store yet.
	if child := d.GetChild(name); child != nil {
		if file, ok := child.Operations().(*fileNode); ok && file.writing() {
			file.fillEntry(out)
			return child, 0
		}
	}
	a, err := d.st.c.head(ctx, rel)
	if err == nil {
		out.Mode = syscall.S_IFREG | a.mode
		out.Size = uint64(a.size)
		out.SetTimes(nil, &a.modified, &a.modified)
		return d.newFile(ctx, a), 0
	}
	if errno(err) != syscall.ENOENT {
		return nil, errno(err)
	}
	if !d.st.isDir(rel) {
		entries, err := d.st.c.list(ctx, rel)
		if err != nil {
			return nil, errno(err)
		}
		if len(entries) == 0 {
			return nil, syscall.ENOENT
		}
	}
	out.Mode = dirMode
	return d.newDir(ctx), 0
}

func (d *dirNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	rel := nodePath(&d.Inode)
	entries, err := d.st.c.list(ctx, rel)
	if err != nil {
		return nil, errno(err)
	}
	seen := map[string]bool{}
	var out []fuse.DirEntry
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name, "/")
		if name == "" || strings.Contains(name, "/") || seen[name] {
			continue
		}
		seen[name] = true
		mode := uint32(syscall.S_IFREG)
		if e.Folder {
			mode = syscall.S_IFDIR
		}
		out = append(out, fuse.DirEntry{Name: name, Mode: mode})
	}
	d.st.mu.Lock()
	for dir := range d.st.dirs {
		parent, name := "", dir
		if i := strings.LastIndex(dir, "/"); i >= 0 {
			parent, name = dir[:i], dir[i+1:]
		}
		if parent == rel && !seen[name] {
			seen[name] = true
			out = append(out, fuse.DirEntry{Name: name, Mode: syscall.S_IFDIR})
		}
	}
	d.st.mu.Unlock()
	return fs.NewListDirStream(out), 0
}

func (d *dirNode) Create(ctx context.Context, name string, flags, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if d.st.readOnly {
		return nil, nil, 0, syscall.EROFS
	}
	child := d.newFile(ctx, attr{modified: time.Now(), mode: mode & 0o777})
	file := child.Operations().(*fileNode)
	handle, errno := file.writeHandle(ctx, join(nodePath(&d.Inode), name), flags|syscall.O_TRUNC)
	if errno != 0 {
		return nil, nil, 0, errno
	}
	out.Mode = syscall.S_IFREG | file.permissions()
	return child, handle, 0, 0
}

func (d *dirNode) Mkdir(ctx context.Context, name string, _ uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if d.st.readOnly {
		return nil, syscall.EROFS
	}
	d.st.setDir(join(nodePath(&d.Inode), name), true)
	out.Mode = dirMode
	return d.newDir(ctx), 0
}

func (d *dirNode) Unlink(ctx context.Context, name string) syscall.Errno {
	if d.st.readOnly {
		return syscall.EROFS
	}
	return errno(d.st.c.remove(ctx, join(nodePath(&d.Inode), name)))
}

func (d *dirNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	if d.st.readOnly {
		return syscall.EROFS
	}
	rel := join(nodePath(&d.Inode), name)
	entries, err := d.st.c.list(ctx, rel)
	if err != nil {
		return errno(err)
	}
	if len(entries) > 0 {
		return syscall.ENOTEMPTY
	}
	if !d.st.isDir(rel) {
		return syscall.ENOENT
	}
	d.st.setDir(rel, false)
	return 0
}

// Rename copies a file through the mount, as the protocol has no copy, and
// then removes the source. A folder that holds objects cannot move; mv then
// copies it file by file.
func (d *dirNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, _ uint32) syscall.Errno {
	if d.st.readOnly {
		return syscall.EROFS
	}
	from := join(nodePath(&d.Inode), name)
	to := join(nodePath(newParent.EmbeddedInode()), newName)
	if d.st.isDir(from) {
		entries, err := d.st.c.list(ctx, from)
		if err != nil {
			return errno(err)
		}
		if len(entries) > 0 {
			return syscall.EXDEV
		}
		d.st.setDir(from, false)
		d.st.setDir(to, true)
		return 0
	}
	source, err := d.st.c.head(ctx, from)
	if errno(err) == syscall.ENOENT {
		return syscall.EXDEV
	}
	if err != nil {
		return errno(err)
	}
	body, size, err := d.st.c.open(ctx, from)
	if err != nil {
		return errno(err)
	}
	defer func() { _ = body.Close() }()
	if err := d.st.c.acquire(ctx); err != nil {
		return errno(err)
	}
	err = d.st.c.put(ctx, to, body, size, source.mode)
	d.st.c.releaseSlot()
	if err != nil {
		return errno(err)
	}
	return errno(d.st.c.remove(ctx, from))
}

// errStopped cuts an open stream of a stopped job.
var errStopped = errors.New("object mount: the job stopped")

// activity counts the open writers of a file or a mount and signals when
// none remain.
type activity struct {
	mu   sync.Mutex
	n    int
	idle chan struct{}
}

func (a *activity) add() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.n == 0 {
		a.idle = make(chan struct{})
	}
	a.n++
}

func (a *activity) done() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n--
	if a.n == 0 {
		close(a.idle)
		a.idle = nil
	}
}

func (a *activity) active() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n > 0
}

// wait reports whether no writer remains within d.
func (a *activity) wait(ctx context.Context, d time.Duration) bool {
	a.mu.Lock()
	idle := a.idle
	a.mu.Unlock()
	if idle == nil {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-idle:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// process returns the process of the thread that made a request, so that a
// multithreaded program owns its files on every thread. FUSE names the
// thread; its status in proc names the process. It returns the thread when
// the status cannot be read, and 0 when the request names no thread.
func (s *state) process(ctx context.Context) uint32 {
	caller, ok := fuse.FromContext(ctx)
	if !ok || caller.Pid == 0 {
		return 0
	}
	raw, err := os.ReadFile(filepath.Join(s.proc, strconv.FormatUint(uint64(caller.Pid), 10), "status"))
	if err != nil {
		return caller.Pid
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "Tgid:"); ok {
			if tgid, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32); err == nil {
				return uint32(tgid)
			}
		}
	}
	return caller.Pid
}

// releaseContext bounds the upload of a release, which no process waits for
// and which a kernel interrupt must not cancel.
func releaseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), releaseWait)
}

type fileNode struct {
	fs.Inode
	st *state

	mu       sync.Mutex
	size     int64
	modified time.Time
	// mode is the permission bits that the next upload stores.
	mode    uint32
	writers activity
	// pending is the latest write-only handle that has not changed the
	// file. The kernel sends the truncate of an open with O_TRUNC without
	// a handle, so it goes to this one.
	pending *streamHandle
}

func (f *fileNode) setPending(h *streamHandle, set bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if set {
		f.pending = h
	} else if f.pending == h {
		f.pending = nil
	}
}

// truncatePending empties the pending handle for a truncate to size 0,
// and reports whether it did.
func (f *fileNode) truncatePending(ctx context.Context, size uint64) (bool, syscall.Errno) {
	f.mu.Lock()
	h := f.pending
	f.mu.Unlock()
	if h == nil || size != 0 {
		return false, 0
	}
	return true, h.truncate(ctx, 0)
}

var (
	_ fs.NodeGetattrer = (*fileNode)(nil)
	_ fs.NodeSetattrer = (*fileNode)(nil)
	_ fs.NodeOpener    = (*fileNode)(nil)
)

func (f *fileNode) writing() bool { return f.writers.active() }

func (f *fileNode) addWriter() {
	f.writers.add()
	f.st.writers.add()
}

// doneWriter ends one writer; errno is the result of its last upload.
func (f *fileNode) doneWriter(errno syscall.Errno) {
	if errno != 0 {
		f.st.failed.Add(1)
	}
	f.writers.done()
	f.st.writers.done()
}

func (f *fileNode) setSize(size int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.size = size
	f.modified = time.Now()
}

func (f *fileNode) permissions() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode
}

func (f *fileNode) fillEntry(out *fuse.EntryOut) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out.Mode = syscall.S_IFREG | f.mode
	out.Size = uint64(f.size)
	out.SetTimes(nil, &f.modified, &f.modified)
}

func (f *fileNode) fill(out *fuse.AttrOut) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out.Mode = syscall.S_IFREG | f.mode
	out.Size = uint64(f.size)
	out.SetTimes(nil, &f.modified, &f.modified)
}

func (f *fileNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	f.fill(out)
	return 0
}

// Setattr changes the size and the mode. A mode change is a PATCH of the
// stored file; a file that is not stored yet takes the mode with its
// upload, as every upload reads the mode when it starts. The protocol keeps
// no owner or times, so those changes succeed without effect.
func (f *fileNode) Setattr(ctx context.Context, fh fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if mode, ok := in.GetMode(); ok {
		if f.st.readOnly {
			return syscall.EROFS
		}
		f.mu.Lock()
		f.mode = mode & 0o777
		f.mu.Unlock()
		err := f.st.c.chmod(ctx, nodePath(&f.Inode), mode&0o777)
		if err != nil && (errno(err) != syscall.ENOENT || !f.writing()) {
			return errno(err)
		}
	}
	if size, ok := in.GetSize(); ok {
		if f.st.readOnly {
			return syscall.EROFS
		}
		if t, ok := fh.(truncater); ok {
			if errno := t.truncate(ctx, int64(size)); errno != 0 {
				return errno
			}
		} else if done, errno := f.truncatePending(ctx, size); done {
			if errno != 0 {
				return errno
			}
		} else {
			wb, errno := newWriteBack(ctx, f, nodePath(&f.Inode), size > 0)
			if errno != 0 {
				return errno
			}
			errno = wb.truncate(ctx, int64(size))
			if errno == 0 {
				errno = wb.flush(ctx)
			}
			wb.release()
			if errno != 0 {
				return errno
			}
		}
	}
	f.fill(out)
	return 0
}

// Open reads the stored file. A read waits until the file has no writer,
// at most uploadWait, so a file that a process just closed reads complete.
func (f *fileNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	rel := nodePath(&f.Inode)
	if flags&syscall.O_ACCMODE == syscall.O_RDONLY {
		f.writers.wait(ctx, uploadWait)
		a, err := f.st.c.head(ctx, rel)
		if err != nil {
			return nil, 0, errno(err)
		}
		f.mu.Lock()
		f.size, f.modified, f.mode = a.size, a.modified, a.mode
		f.mu.Unlock()
		return &readHandle{st: f.st, rel: rel}, 0, 0
	}
	if f.st.readOnly {
		return nil, 0, syscall.EROFS
	}
	handle, errno := f.writeHandle(ctx, rel, flags)
	return handle, 0, errno
}

// writeHandle chooses the handle of a write open: a stream for a
// write-only open, and a write-back buffer for every other write. The
// kernel sends O_TRUNC only with a create; for an existing file it sends a
// truncate after the open, so a write-only open of one starts pending.
func (f *fileNode) writeHandle(ctx context.Context, rel string, flags uint32) (fs.FileHandle, syscall.Errno) {
	created := flags&syscall.O_TRUNC != 0
	if flags&syscall.O_ACCMODE == syscall.O_WRONLY && flags&syscall.O_APPEND == 0 {
		h := &streamHandle{f: f, rel: rel, owner: f.st.process(ctx), pending: !created, dirty: created}
		if created {
			f.setSize(0)
		} else {
			f.setPending(h, true)
		}
		f.addWriter()
		return h, 0
	}
	wb, errno := newWriteBack(ctx, f, rel, !created)
	if errno != 0 {
		return nil, errno
	}
	if created {
		wb.dirty = true
		f.setSize(0)
	}
	wb.writer = true
	f.addWriter()
	return wb, 0
}

type truncater interface {
	truncate(ctx context.Context, size int64) syscall.Errno
}

// readHandle reads a stored file. It fetches at least readAhead bytes per
// request and serves the following reads from them, so a sequential read
// sends one request for each readAhead bytes, not one for each kernel read.
type readHandle struct {
	st  *state
	rel string

	mu sync.Mutex
	// buf holds the bytes of the file from off; a buf shorter than its
	// request ends at the end of the file.
	off       int64
	buf       []byte
	requested int
}

var _ fs.FileReader = (*readHandle)(nil)

func (h *readHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	end := off + int64(len(dest))
	atEOF := len(h.buf) < h.requested
	if h.buf == nil || off < h.off || (end > h.off+int64(len(h.buf)) && !atEOF) {
		n := max(len(dest), readAhead)
		data, err := h.st.c.read(ctx, h.rel, off, n)
		if err != nil {
			return nil, errno(err)
		}
		h.off, h.buf, h.requested = off, data, n
	}
	start := off - h.off
	if start >= int64(len(h.buf)) {
		return fuse.ReadResultData(nil), 0
	}
	return fuse.ReadResultData(h.buf[start:min(int64(len(h.buf)), end-h.off)]), 0
}

// streamHandle writes a file in order from its start. It keeps the first
// smallFile bytes and stores a file that ends within them with its exact
// length; a longer file streams as one chunked upload. A write out of order
// before the stream starts, and a write to an existing file that was not
// truncated, turn the handle into a write-back buffer.
//
// The kernel sends a flush for every close of a descriptor, also for the
// copy that a shell closes after dup2 and for each child that inherited the
// descriptor. So only a flush from the opening process after a write stores
// the file; the release after the last close always does.
type streamHandle struct {
	f     *fileNode
	rel   string
	owner uint32

	mu sync.Mutex
	// pending is set while the handle has not changed the stored file.
	pending bool
	// dirty is set while buf holds bytes that are not stored.
	dirty   bool
	buf     []byte
	written int64
	pipe    *io.PipeWriter
	done    chan error
	// ended is set when the stream upload ended with result.
	ended  bool
	result syscall.Errno
	wb     *writeBack
}

var (
	_ fs.FileWriter   = (*streamHandle)(nil)
	_ fs.FileReader   = (*streamHandle)(nil)
	_ fs.FileFlusher  = (*streamHandle)(nil)
	_ fs.FileFsyncer  = (*streamHandle)(nil)
	_ fs.FileReleaser = (*streamHandle)(nil)
)

func (h *streamHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wb == nil && (h.pending || off != h.written) {
		if h.pipe != nil || h.ended {
			return 0, syscall.EIO
		}
		if errno := h.toWriteBack(ctx); errno != 0 {
			return 0, errno
		}
	}
	if h.wb != nil {
		return h.wb.Write(ctx, data, off)
	}
	if h.ended {
		return 0, syscall.EIO
	}
	if h.pipe == nil {
		h.buf = append(h.buf, data...)
		h.dirty = true
		if len(h.buf) > h.f.st.smallFile {
			if errno := h.start(ctx); errno != 0 {
				return 0, errno
			}
		}
	} else if _, err := h.pipe.Write(data); err != nil {
		return 0, syscall.EIO
	}
	h.written += int64(len(data))
	h.f.setSize(h.written)
	return uint32(len(data)), 0
}

// toWriteBack moves the handle to a write-back buffer: with the stored
// file while pending, else with the bytes written so far.
func (h *streamHandle) toWriteBack(ctx context.Context) syscall.Errno {
	if h.pending {
		wb, errno := newWriteBack(ctx, h.f, h.rel, true)
		if errno != 0 {
			return errno
		}
		h.wb, h.pending = wb, false
		h.f.setPending(h, false)
		return 0
	}
	if !h.f.st.budget.reserve(int64(len(h.buf))) {
		return syscall.EFBIG
	}
	h.wb = &writeBack{f: h.f, rel: h.rel, data: h.buf, reserved: int64(len(h.buf)), dirty: true}
	h.buf = nil
	return 0
}

func (h *streamHandle) start(ctx context.Context) syscall.Errno {
	c := h.f.st.c
	if err := c.acquire(ctx); err != nil {
		return errno(err)
	}
	reader, writer := io.Pipe()
	h.pipe, h.done = writer, make(chan error, 1)
	go func() {
		err := c.put(context.Background(), h.rel, reader, -1, h.f.permissions())
		_ = reader.CloseWithError(err)
		c.releaseSlot()
		h.done <- err
	}()
	if _, err := writer.Write(h.buf); err != nil {
		return syscall.EIO
	}
	h.buf, h.dirty = nil, false
	return 0
}

// Read lets a process read back a file that it still writes, except
// while the file streams.
func (h *streamHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.wb != nil:
		return h.wb.Read(ctx, dest, off)
	case h.pipe != nil:
		return nil, syscall.EIO
	case h.pending || h.ended:
		data, err := h.f.st.c.read(ctx, h.rel, off, len(dest))
		if err != nil {
			return nil, errno(err)
		}
		return fuse.ReadResultData(data), 0
	case off >= int64(len(h.buf)):
		return fuse.ReadResultData(nil), 0
	default:
		return fuse.ReadResultData(append([]byte(nil), h.buf[off:min(int64(len(h.buf)), off+int64(len(dest)))]...)), 0
	}
}

func (h *streamHandle) truncate(ctx context.Context, size int64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wb == nil {
		switch {
		case h.pending && size == 0:
			h.pending, h.dirty = false, true
			h.f.setPending(h, false)
			h.f.setSize(0)
			return 0
		case !h.pending && size == h.written:
			return 0
		case h.pipe != nil || h.ended:
			return syscall.EIO
		}
		if errno := h.toWriteBack(ctx); errno != 0 {
			return errno
		}
	}
	return h.wb.truncate(ctx, size)
}

// commit stores the changes: a buffered file goes with its exact length
// and stays in the buffer, so later writes can extend it; a stream ends,
// and later writes fail.
func (h *streamHandle) commit(ctx context.Context) syscall.Errno {
	switch {
	case h.wb != nil:
		return h.wb.flush(ctx)
	case h.pipe != nil:
		_ = h.pipe.Close()
		h.result = errno(<-h.done)
		h.pipe, h.ended = nil, true
		return h.result
	case h.ended:
		return h.result
	case h.pending || !h.dirty:
		return 0
	}
	c := h.f.st.c
	if err := c.acquire(ctx); err != nil {
		return errno(err)
	}
	err := c.put(ctx, h.rel, bytes.NewReader(h.buf), int64(len(h.buf)), h.f.permissions())
	c.releaseSlot()
	if err != nil {
		return errno(err)
	}
	h.dirty = false
	return 0
}

func (h *streamHandle) Flush(ctx context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.f.st.stopping.Load() {
		return 0
	}
	if h.wb == nil && (h.f.st.process(ctx) != h.owner || h.written == 0) {
		return 0
	}
	return h.commit(ctx)
}

// drop discards the unstored changes of a stopped job: it cuts an open
// stream, so the upstream aborts it and keeps the earlier object, and
// clears the buffers. The caller holds h.mu.
func (h *streamHandle) drop() {
	changed := h.dirty || h.pipe != nil
	if h.pipe != nil {
		_ = h.pipe.CloseWithError(errStopped)
		<-h.done
		h.pipe, h.ended, h.result = nil, true, 0
	}
	h.dirty = false
	if h.wb != nil {
		h.wb.mu.Lock()
		changed = changed || h.wb.dirty
		h.wb.dirty = false
		h.wb.mu.Unlock()
	}
	if changed {
		h.f.st.dropped.Add(1)
	}
}

// Fsync stores a buffered file. A file that streams is stored when it is
// closed; ending the stream here would fail the writes that follow.
func (h *streamHandle) Fsync(ctx context.Context, _ uint32) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pipe != nil {
		return 0
	}
	return h.commit(ctx)
}

func (h *streamHandle) Release(ctx context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	ctx, cancel := releaseContext(ctx)
	defer cancel()
	if h.f.st.stopping.Load() {
		h.drop()
	}
	errno := h.commit(ctx)
	if h.wb != nil {
		h.wb.release()
	}
	h.buf = nil
	h.f.setPending(h, false)
	h.f.doneWriter(errno)
	return errno
}

// writeBack holds a whole file in guest memory, within the budget of the
// mount, and stores it on flush, fsync, and release.
type writeBack struct {
	f   *fileNode
	rel string

	mu       sync.Mutex
	data     []byte
	reserved int64
	dirty    bool
	// writer marks the handle of an open; it counts as a writer of f.
	writer bool
}

var (
	_ fs.FileReader   = (*writeBack)(nil)
	_ fs.FileWriter   = (*writeBack)(nil)
	_ fs.FileFlusher  = (*writeBack)(nil)
	_ fs.FileFsyncer  = (*writeBack)(nil)
	_ fs.FileReleaser = (*writeBack)(nil)
)

// newWriteBack opens a buffer, with the stored file when load is set.
func newWriteBack(ctx context.Context, f *fileNode, rel string, load bool) (*writeBack, syscall.Errno) {
	wb := &writeBack{f: f, rel: rel}
	if !load {
		return wb, 0
	}
	body, size, err := f.st.c.open(ctx, rel)
	if errno(err) == syscall.ENOENT {
		return wb, 0
	}
	if err != nil {
		return nil, errno(err)
	}
	defer func() { _ = body.Close() }()
	if size < 0 || !f.st.budget.reserve(size) {
		return nil, syscall.EFBIG
	}
	wb.reserved = size
	data, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil || int64(len(data)) != size {
		wb.release()
		return nil, syscall.EIO
	}
	wb.data = data
	return wb, 0
}

func (w *writeBack) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if off >= int64(len(w.data)) {
		return fuse.ReadResultData(nil), 0
	}
	return fuse.ReadResultData(append([]byte(nil), w.data[off:min(int64(len(w.data)), off+int64(len(dest)))]...)), 0
}

func (w *writeBack) grow(size int64) syscall.Errno {
	if size <= int64(len(w.data)) {
		return 0
	}
	if extra := size - w.reserved; extra > 0 {
		if !w.f.st.budget.reserve(extra) {
			return syscall.EFBIG
		}
		w.reserved = size
	}
	w.data = append(w.data, make([]byte, size-int64(len(w.data)))...)
	return 0
}

func (w *writeBack) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if errno := w.grow(off + int64(len(data))); errno != 0 {
		return 0, errno
	}
	copy(w.data[off:], data)
	w.dirty = true
	w.f.setSize(int64(len(w.data)))
	return uint32(len(data)), 0
}

func (w *writeBack) truncate(_ context.Context, size int64) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if size < int64(len(w.data)) {
		w.data = w.data[:size]
	} else if errno := w.grow(size); errno != 0 {
		return errno
	}
	w.dirty = true
	w.f.setSize(size)
	return 0
}

func (w *writeBack) flush(ctx context.Context) syscall.Errno {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.dirty {
		return 0
	}
	c := w.f.st.c
	if err := c.acquire(ctx); err != nil {
		return errno(err)
	}
	err := c.put(ctx, w.rel, bytes.NewReader(w.data), int64(len(w.data)), w.f.permissions())
	c.releaseSlot()
	if err != nil {
		return errno(err)
	}
	w.dirty = false
	return 0
}

func (w *writeBack) Flush(ctx context.Context) syscall.Errno {
	if w.f.st.stopping.Load() {
		return 0
	}
	return w.flush(ctx)
}

func (w *writeBack) Fsync(ctx context.Context, _ uint32) syscall.Errno { return w.flush(ctx) }

func (w *writeBack) Release(ctx context.Context) syscall.Errno {
	ctx, cancel := releaseContext(ctx)
	defer cancel()
	if w.f.st.stopping.Load() {
		w.mu.Lock()
		if w.dirty {
			w.dirty = false
			w.f.st.dropped.Add(1)
		}
		w.mu.Unlock()
	}
	errno := w.flush(ctx)
	w.release()
	if w.writer {
		w.f.doneWriter(errno)
	}
	return errno
}

func (w *writeBack) release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.f.st.budget.release(w.reserved)
	w.reserved = 0
	w.data = nil
}

// NewBudget returns a write-back budget of limit bytes.
func NewBudget(limit int64) *Budget { return &Budget{limit: limit} }
