// Package client is the Go client of the vmcp API.
package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jaredfolkins/vmcp/api"
)

// maxErrorBytes bounds an error body that the client reads.
const maxErrorBytes = 64 << 10

// Error is an error response from vmcp.
type Error struct {
	Status  int
	Code    api.ErrorCode
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("vmcp %d %s: %s", e.Status, e.Code, e.Message)
}

// IsCode reports whether err is a vmcp error with the code.
func IsCode(err error, code api.ErrorCode) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Client calls one vmcp service.
type Client struct {
	base       *url.URL
	credential string
	http       *http.Client
}

// New returns a client for the vmcp base URL, such as
// "http://vmcp:8080". A nil hc uses http.DefaultClient. Event streams stay
// open for a long time, so do not set a short timeout on hc.
func New(baseURL, credential string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("vmcp base URL %q must be an absolute http or https URL", baseURL)
	}
	if credential == "" {
		return nil, errors.New("vmcp credential is required")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: u, credential: credential, http: hc}, nil
}

// Status returns the runtime status.
func (c *Client) Status(ctx context.Context) (api.Status, error) {
	var out api.Status
	return out, c.do(ctx, api.RouteStatus, nil, nil, nil, &out)
}

// SelfTest runs the runtime self-test.
func (c *Client) SelfTest(ctx context.Context) (api.SelfTestResult, error) {
	var out api.SelfTestResult
	return out, c.do(ctx, api.RouteSelfTest, nil, nil, nil, &out)
}

// CreateImage prepares an image.
func (c *Client) CreateImage(ctx context.Context, req api.ImageRequest) (api.Image, error) {
	var out api.Image
	return out, c.do(ctx, api.RouteCreateImage, nil, nil, req, &out)
}

// GetImage returns one image.
func (c *Client) GetImage(ctx context.Context, id string) (api.Image, error) {
	var out api.Image
	return out, c.do(ctx, api.RouteGetImage, map[string]string{"id": id}, nil, nil, &out)
}

// ListImages returns every image.
func (c *Client) ListImages(ctx context.Context) ([]api.Image, error) {
	var out []api.Image
	return out, c.do(ctx, api.RouteListImages, nil, nil, nil, &out)
}

// DeleteImage deletes one image.
func (c *Client) DeleteImage(ctx context.Context, id string) error {
	return c.do(ctx, api.RouteDeleteImage, map[string]string{"id": id}, nil, nil, nil)
}

// CreateMachine creates a machine. A repeated create with the same name and
// spec returns the existing machine.
func (c *Client) CreateMachine(ctx context.Context, spec api.MachineSpec) (api.Machine, error) {
	var out api.Machine
	return out, c.do(ctx, api.RouteCreateMachine, nil, nil, spec, &out)
}

// GetMachine returns one machine.
func (c *Client) GetMachine(ctx context.Context, id string) (api.Machine, error) {
	var out api.Machine
	return out, c.do(ctx, api.RouteGetMachine, map[string]string{"id": id}, nil, nil, &out)
}

// ListMachines returns the machines that have every label in labels.
func (c *Client) ListMachines(ctx context.Context, labels map[string]string) ([]api.Machine, error) {
	q := url.Values{}
	for k, v := range labels {
		q.Add("label", k+"="+v)
	}
	var out []api.Machine
	return out, c.do(ctx, api.RouteListMachines, nil, q, nil, &out)
}

// StartMachine boots a created or stopped machine.
func (c *Client) StartMachine(ctx context.Context, id string) (api.Machine, error) {
	var out api.Machine
	return out, c.do(ctx, api.RouteStartMachine, map[string]string{"id": id}, nil, nil, &out)
}

// StopMachine stops a running machine.
func (c *Client) StopMachine(ctx context.Context, id string, req api.StopRequest) (api.Machine, error) {
	var out api.Machine
	return out, c.do(ctx, api.RouteStopMachine, map[string]string{"id": id}, nil, req, &out)
}

// DeleteMachine destroys a machine and returns its final record with the
// proof.
func (c *Client) DeleteMachine(ctx context.Context, id string) (api.Machine, error) {
	var out api.Machine
	return out, c.do(ctx, api.RouteDeleteMachine, map[string]string{"id": id}, nil, nil, &out)
}

// PutDrive replaces a drive with the tar stream.
func (c *Client) PutDrive(ctx context.Context, id, name string, tar io.Reader) error {
	req, err := c.request(ctx, api.RoutePutDrive, map[string]string{"id": id, "name": name}, nil, tar)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.send(req)
	if err != nil {
		return err
	}
	return drain(resp)
}

// GetDrive returns the tar stream of a writable drive. The caller closes
// it.
func (c *Client) GetDrive(ctx context.Context, id, name string) (io.ReadCloser, error) {
	req, err := c.request(ctx, api.RouteGetDrive, map[string]string{"id": id, "name": name}, nil, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Events calls fn for each event after the sequence number. With follow,
// it returns after the machine stops or ctx ends. An error from fn stops
// the stream and is returned.
func (c *Client) Events(ctx context.Context, id string, after uint64, follow bool, fn func(api.Event) error) error {
	q := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if follow {
		q.Set("follow", "true")
	}
	req, err := c.request(ctx, api.RouteMachineEvents, map[string]string{"id": id}, q, nil)
	if err != nil {
		return err
	}
	resp, err := c.send(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var ev api.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("decode vmcp event: %w", err)
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read vmcp events: %w", err)
	}
	return nil
}

func (c *Client) do(ctx context.Context, route string, params map[string]string, q url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode vmcp request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := c.request(ctx, route, params, q, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.send(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode vmcp response: %w", err)
	}
	return nil
}

// request builds a request from a route pattern such as
// "GET /v1/machines/{id}".
func (c *Client) request(ctx context.Context, route string, params map[string]string, q url.Values, body io.Reader) (*http.Request, error) {
	method, path, ok := strings.Cut(route, " ")
	if !ok {
		return nil, fmt.Errorf("invalid route %q", route)
	}
	for name, value := range params {
		if value == "" {
			return nil, fmt.Errorf("route %q needs %s", route, name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
	}
	if strings.Contains(path, "{") {
		return nil, fmt.Errorf("route %q has an unset parameter", route)
	}
	u := c.base.JoinPath(path)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("build vmcp request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.credential)
	return req, nil
}

// send returns the response for a 2xx status and an *Error otherwise.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vmcp %s %s: %w", req.Method, req.URL.Path, err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var er api.ErrorResponse
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
	if json.Unmarshal(raw, &er) != nil || er.Error.Code == "" {
		er.Error = api.Error{Code: api.ErrInternal, Message: http.StatusText(resp.StatusCode)}
	}
	return nil, &Error{Status: resp.StatusCode, Code: er.Error.Code, Message: er.Error.Message}
}

func drain(resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }()
	_, err := io.Copy(io.Discard, resp.Body)
	return err
}
