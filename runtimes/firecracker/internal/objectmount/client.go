package objectmount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jaredfolkins/vmcp/api"
)

// uploadWait bounds the wait for an upload slot, so a process that keeps
// more files open for writing than the mount has slots gets an error, not a
// hang.
const uploadWait = 60 * time.Second

// releaseWait bounds the upload of a file after its last close.
const releaseWait = 5 * time.Minute

// streamStallWait bounds one step of a streamed upload: the upstream must
// take one write, and must answer after the last byte, in this time. A
// stream that makes progress has no total time limit.
const streamStallWait = 5 * time.Minute

// maxListEntries bounds the entries of one folder listing. The listing is in
// guest memory, so an upstream that sends pages without an end must not
// fill it.
const maxListEntries = 100_000

// errStalled ends a streamed upload that the upstream stopped reading.
var errStalled = errors.New("object mount: the upstream stopped reading the upload")

// readAhead is the least number of bytes that one read request fetches.
const readAhead = 4 << 20

// defaultMode is the mode of a file whose upstream names none.
const defaultMode = 0o644

// attr is the size, change time, and permission bits of one file.
type attr struct {
	size     int64
	modified time.Time
	mode     uint32
}

// parseMode reads an ObjectMountModeHeader value.
func parseMode(value string) uint32 {
	mode, err := strconv.ParseUint(value, 8, 32)
	if err != nil || mode == 0 || mode > 0o777 {
		return defaultMode
	}
	return uint32(mode)
}

func formatMode(mode uint32) string {
	return fmt.Sprintf("%04o", mode&0o777)
}

// entry is one entry of a folder listing.
type entry struct {
	Name     string `json:"name"`
	Folder   bool   `json:"folder"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// client speaks the object mount protocol (api.Mount) to one upstream root.
type client struct {
	base     string
	http     *http.Client
	maxBytes int64
	uploads  chan struct{}
	// listLimit is the largest number of entries of one folder listing.
	listLimit int
	// stallWait bounds one step of a streamed upload.
	stallWait time.Duration
}

func newClient(base string, maxBytes int64, uploads int, transport http.RoundTripper) *client {
	return &client{
		base:      strings.TrimSuffix(base, "/"),
		http:      &http.Client{Transport: transport},
		maxBytes:  maxBytes,
		uploads:   make(chan struct{}, uploads),
		listLimit: maxListEntries,
		stallWait: streamStallWait,
	}
}

// url escapes each segment of a mount-relative path.
func (c *client) url(rel string, folder bool, query string) string {
	var b strings.Builder
	b.WriteString(c.base)
	for _, segment := range strings.Split(rel, "/") {
		if segment == "" {
			continue
		}
		b.WriteString("/")
		b.WriteString(url.PathEscape(segment))
	}
	if folder {
		b.WriteString("/")
	}
	b.WriteString(query)
	return b.String()
}

func (c *client) do(ctx context.Context, method, target string, body io.Reader, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	for name, values := range header {
		req.Header[name] = values
	}
	return c.http.Do(req)
}

// statusErrno maps a protocol status to the errno that the file operation
// returns.
func statusErrno(code int) syscall.Errno {
	switch {
	case code == http.StatusNotFound:
		return syscall.ENOENT
	case code == http.StatusRequestEntityTooLarge:
		return syscall.EFBIG
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return syscall.EACCES
	case code == http.StatusTooManyRequests:
		return syscall.EAGAIN
	case code >= 400 && code < 500:
		return syscall.EINVAL
	default:
		return syscall.EIO
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// errno returns the errno of err; an unknown error is EIO.
func errno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return syscall.EIO
}

func (c *client) head(ctx context.Context, rel string) (attr, error) {
	resp, err := c.do(ctx, http.MethodHead, c.url(rel, false, ""), nil, nil)
	if err != nil {
		return attr{}, err
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		return attr{}, statusErrno(resp.StatusCode)
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size < 0 {
		return attr{}, syscall.EIO
	}
	modified, _ := http.ParseTime(resp.Header.Get("Last-Modified"))
	return attr{size: size, modified: modified, mode: parseMode(resp.Header.Get(api.ObjectMountModeHeader))}, nil
}

// list returns every entry of a folder; "" is the mount root.
func (c *client) list(ctx context.Context, folder string) ([]entry, error) {
	var all []entry
	token := ""
	for {
		query := "?list"
		if token != "" {
			query += "&token=" + url.QueryEscape(token)
		}
		resp, err := c.do(ctx, http.MethodGet, c.url(folder, true, query), nil, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			drain(resp)
			return nil, statusErrno(resp.StatusCode)
		}
		var page struct {
			Entries []entry `json:"entries"`
			Next    string  `json:"next"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page)
		drain(resp)
		if err != nil {
			return nil, fmt.Errorf("decode listing: %w", syscall.EIO)
		}
		all = append(all, page.Entries...)
		if len(all) > c.listLimit {
			return nil, fmt.Errorf("listing has more than %d entries: %w", c.listLimit, syscall.EOVERFLOW)
		}
		if page.Next == "" {
			return all, nil
		}
		// An empty page or the same token again is a listing without an end.
		if len(page.Entries) == 0 || page.Next == token {
			return nil, fmt.Errorf("listing does not advance: %w", syscall.EIO)
		}
		token = page.Next
	}
}

// read returns at most n bytes from off; a read past the end is empty.
func (c *client) read(ctx context.Context, rel string, off int64, n int) ([]byte, error) {
	header := http.Header{"Range": {fmt.Sprintf("bytes=%d-%d", off, off+int64(n)-1)}}
	resp, err := c.do(ctx, http.MethodGet, c.url(rel, false, ""), nil, header)
	if err != nil {
		return nil, err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusPartialContent:
	case http.StatusRequestedRangeNotSatisfiable:
		return nil, nil
	case http.StatusOK:
		if off != 0 {
			return nil, syscall.EIO
		}
	default:
		return nil, statusErrno(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(n)))
	if err != nil {
		return nil, syscall.EIO
	}
	return data, nil
}

// open streams a whole file.
func (c *client) open(ctx context.Context, rel string) (io.ReadCloser, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, c.url(rel, false, ""), nil, nil)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		drain(resp)
		return nil, 0, statusErrno(resp.StatusCode)
	}
	return resp.Body, resp.ContentLength, nil
}

// acquire takes an upload slot.
func (c *client) acquire(ctx context.Context) error {
	timer := time.NewTimer(uploadWait)
	defer timer.Stop()
	select {
	case c.uploads <- struct{}{}:
		return nil
	case <-timer.C:
		return syscall.EAGAIN
	case <-ctx.Done():
		return syscall.EINTR
	}
}

func (c *client) releaseSlot() { <-c.uploads }

// put writes a whole file with its mode. size is its exact length, or -1
// for a chunked body of at most maxBytes. The caller holds an upload slot.
func (c *client) put(ctx context.Context, rel string, body io.Reader, size int64, mode uint32) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.url(rel, false, ""), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(api.ObjectMountModeHeader, formatMode(mode))
	if size >= 0 {
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
	} else {
		req.ContentLength = -1
		req.Header.Set(api.ObjectMountMaxBytesHeader, strconv.FormatInt(c.maxBytes, 10))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return statusErrno(resp.StatusCode)
	}
	return nil
}

// chmod changes the mode of a stored file.
func (c *client) chmod(ctx context.Context, rel string, mode uint32) error {
	resp, err := c.do(ctx, http.MethodPatch, c.url(rel, false, ""), nil,
		http.Header{api.ObjectMountModeHeader: {formatMode(mode)}})
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return statusErrno(resp.StatusCode)
	}
	return nil
}

func (c *client) remove(ctx context.Context, rel string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.url(rel, false, ""), nil, nil)
	if err != nil {
		return err
	}
	drain(resp)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return statusErrno(resp.StatusCode)
	}
	return nil
}
