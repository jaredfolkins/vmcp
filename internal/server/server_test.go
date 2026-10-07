package server

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
	"github.com/jaredfolkins/vmcp/internal/machine"
)

const testCredential = "test-credential-0123456789abcdef0123456789"

// fakeRuntime runs scripted machines. The guest "program" is the first
// spec arg: "echo:<text>" prints and exits 0, "exit:<n>" exits n, "hang"
// runs until killed, "copy" copies drive "in" file "f" to drive "out".
type fakeRuntime struct {
	mu        sync.Mutex
	recovered int
}

func (f *fakeRuntime) Status() api.Status { return api.Status{Runtime: "fake", Ready: true} }

func (f *fakeRuntime) PrepareImage(_ context.Context, _ string, req api.ImageRequest) (machine.ImageInfo, error) {
	return machine.ImageInfo{ImageDigest: req.Ref[strings.Index(req.Ref, "@")+1:], Compatibility: "fake", SizeBytes: 1,
		Process: machine.ProcessConfig{Cmd: []string{"echo:from-image"}, Env: []string{"A=image", "B=image"}, User: "1000", WorkingDir: "/app"}}, nil
}

func (f *fakeRuntime) DeleteImage(string) error { return nil }

func (f *fakeRuntime) PrepareSelfTestImage(context.Context, string) (machine.ImageInfo, error) {
	return machine.ImageInfo{ImageDigest: "sha256:selftest", Process: machine.ProcessConfig{Cmd: []string{"echo:{\"metadata_denied\":true}"}}}, nil
}

func (f *fakeRuntime) Recover(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recovered++
	return nil
}

func (f *fakeRuntime) Provision(_ context.Context, l machine.Launch) (machine.Instance, error) {
	return &fakeInstance{l: l, done: make(chan struct{}), kill: make(chan string, 1)}, nil
}

type fakeInstance struct {
	l      machine.Launch
	done   chan struct{}
	kill   chan string
	result machine.Result
	once   sync.Once
}

func (i *fakeInstance) Boot(context.Context) error {
	go func() {
		prog := i.l.Args[0]
		var exit *api.Exit
		switch {
		case strings.HasPrefix(prog, "echo:"):
			out := strings.TrimPrefix(prog, "echo:") + "\n" + strings.Join(i.l.Env, ",") + "\nuser=" + i.l.User + " dir=" + i.l.WorkDir
			i.l.Sink.Event(api.Event{Kind: api.EventStdout, Data: []byte(out)})
			exit = &api.Exit{Code: 0, Reason: api.ExitCompleted}
		case strings.HasPrefix(prog, "exit:"):
			exit = &api.Exit{Code: 7, Reason: api.ExitCompleted}
		case prog == "copy":
			b, _ := os.ReadFile(filepath.Join(i.l.Dir, "in", "in", "f"))
			writeTar(filepath.Join(i.l.Dir, "out", "out.tar"), "f", b)
			exit = &api.Exit{Code: 0, Reason: api.ExitCompleted}
		case prog == "flood":
			for range 100 {
				i.l.Sink.Event(api.Event{Kind: api.EventStdout, Data: bytes.Repeat([]byte("x"), 1024)})
			}
			<-i.kill
		case prog == "hang":
			<-i.kill
		}
		i.finish(exit)
	}()
	return nil
}

func (i *fakeInstance) finish(exit *api.Exit) {
	i.once.Do(func() {
		i.result = machine.Result{Exit: exit, Proof: api.Proof{MachineID: i.l.ID, Runtime: "fake", Destroyed: true, TeardownStatus: "destroyed"}}
		close(i.done)
	})
}

func (i *fakeInstance) Kill(reason string) {
	select {
	case i.kill <- reason:
	default:
	}
}
func (i *fakeInstance) Done() <-chan struct{}  { return i.done }
func (i *fakeInstance) Result() machine.Result { <-i.done; return i.result }
func (i *fakeInstance) Destroy(_ context.Context, reason string) machine.Result {
	i.Kill(reason)
	return i.Result()
}

func writeTar(path, name string, body []byte) {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = os.WriteFile(path, buf.Bytes(), 0o600)
}

type harness struct {
	c   *client.Client
	url string
	dir string
	rt  *fakeRuntime
}

func newHarness(t *testing.T, dir string) *harness {
	t.Helper()
	rt := &fakeRuntime{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := machine.New(context.Background(), rt, machine.Config{Dir: dir, MaxMachines: 4, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{Credential: []byte(testCredential), Service: mgr, Logger: log}))
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, testCredential, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return &harness{c: c, url: srv.URL, dir: dir, rt: rt}
}

func (h *harness) image(t *testing.T) string {
	t.Helper()
	img, err := h.c.CreateImage(context.Background(), api.ImageRequest{Ref: "example/app@sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatalf("CreateImage() error = %v", err)
	}
	return img.ID
}

// runToExit starts a machine and returns its exit event and stdout.
func (h *harness) runToExit(t *testing.T, id string) (*api.Exit, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.c.StartMachine(ctx, id); err != nil {
		t.Fatalf("StartMachine() error = %v", err)
	}
	var exit *api.Exit
	var out strings.Builder
	var last uint64
	err := h.c.Events(ctx, id, 0, true, func(ev api.Event) error {
		if ev.Seq != last+1 {
			t.Errorf("event seq = %d after %d, want consecutive", ev.Seq, last)
		}
		last = ev.Seq
		if ev.Kind == api.EventStdout {
			out.Write(ev.Data)
		}
		if ev.Kind == api.EventExit {
			exit = ev.Exit
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	return exit, out.String()
}

// TestAuthentication proves that only the health route works without the
// credential, and that a wrong credential gets the same safe error.
func TestAuthentication(t *testing.T) {
	h := newHarness(t, t.TempDir())
	for _, tt := range []struct {
		path, token string
		want        int
	}{
		{"/healthz", "", http.StatusNoContent},
		{"/readyz", "", http.StatusNoContent},
		{"/v1/status", "", http.StatusUnauthorized},
		{"/v1/status", testCredential + "x", http.StatusUnauthorized},
		{"/v1/machines", "", http.StatusUnauthorized},
		{"/v1/status", testCredential, http.StatusOK},
		{"/v1/nothing", testCredential, http.StatusNotFound},
	} {
		req, _ := http.NewRequest(http.MethodGet, h.url+tt.path, nil)
		if tt.token != "" {
			req.Header.Set("Authorization", "Bearer "+tt.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tt.want {
			t.Errorf("GET %s (token set %v) status = %d, want %d", tt.path, tt.token != "", resp.StatusCode, tt.want)
		}
	}
}

// TestEphemeralLifecycle proves the caller flow through the real client,
// server, and manager: image, create, name idempotency, drive upload,
// start, ordered events, image process defaults, drive download, delete,
// and proof.
func TestEphemeralLifecycle(t *testing.T) {
	h := newHarness(t, t.TempDir())
	ctx := context.Background()
	img := h.image(t)
	spec := api.MachineSpec{Name: "copy-job", Lifecycle: api.Ephemeral, Image: img, TimeoutSeconds: 30,
		Labels:  map[string]string{"job": "42"},
		Process: api.Process{Args: []string{"copy"}},
		Drives:  []api.Drive{{Name: "in", GuestPath: "/in", SizeMiB: 1}, {Name: "out", GuestPath: "/out", SizeMiB: 1, Writable: true}}}
	m, err := h.c.CreateMachine(ctx, spec)
	if err != nil {
		t.Fatalf("CreateMachine() error = %v", err)
	}
	again, err := h.c.CreateMachine(ctx, spec)
	if err != nil || again.ID != m.ID {
		t.Errorf("repeated CreateMachine() = %s, %v; want the same machine %s", again.ID, err, m.ID)
	}
	other := spec
	other.TimeoutSeconds = 31
	if _, err := h.c.CreateMachine(ctx, other); !client.IsCode(err, api.ErrConflict) {
		t.Errorf("CreateMachine() with a different spec error = %v, want conflict", err)
	}
	var in bytes.Buffer
	tw := tar.NewWriter(&in)
	_ = tw.WriteHeader(&tar.Header{Name: "f", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	if err := h.c.PutDrive(ctx, m.ID, "in", &in); err != nil {
		t.Fatalf("PutDrive() error = %v", err)
	}
	exit, _ := h.runToExit(t, m.ID)
	if exit == nil || exit.Code != 0 || exit.Reason != api.ExitCompleted {
		t.Fatalf("exit = %+v, want completed 0", exit)
	}
	rc, err := h.c.GetDrive(ctx, m.ID, "out")
	if err != nil {
		t.Fatalf("GetDrive() error = %v", err)
	}
	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	body, _ := io.ReadAll(tr)
	_ = rc.Close()
	if err != nil || hdr.Name != "f" || string(body) != "hello" {
		t.Errorf("out drive = %v %q, want f with hello", err, body)
	}
	if got, err := h.c.ListMachines(ctx, map[string]string{"job": "42"}); err != nil || len(got) != 1 {
		t.Errorf("ListMachines(job=42) = %d, %v; want 1", len(got), err)
	}
	final, err := h.c.DeleteMachine(ctx, m.ID)
	if err != nil || final.State != api.StateDestroyed || final.Proof == nil || !final.Proof.Destroyed {
		t.Errorf("DeleteMachine() = %+v, %v; want destroyed with proof", final, err)
	}
	if _, err := h.c.GetMachine(ctx, m.ID); !client.IsCode(err, api.ErrNotFound) {
		t.Errorf("GetMachine() after delete error = %v, want not_found", err)
	}

	m2, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "image-default", Lifecycle: api.Ephemeral, Image: img,
		TimeoutSeconds: 30, Process: api.Process{Env: []string{"B=spec"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, out := h.runToExit(t, m2.ID)
	if !strings.Contains(out, "from-image") || !strings.Contains(out, "A=image,B=spec") || !strings.Contains(out, "user=1000 dir=/app") {
		t.Errorf("stdout = %q, want the image command, merged env, image user, and image dir", out)
	}
	m3, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "user-override", Lifecycle: api.Ephemeral, Image: img,
		TimeoutSeconds: 30, Process: api.Process{User: "0", Dir: "/work"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, out := h.runToExit(t, m3.ID); !strings.Contains(out, "user=0 dir=/work") {
		t.Errorf("stdout = %q, want the spec user and dir to replace the image values", out)
	}
}

// TestLimits proves timeout, output limit, redaction, and that a machine
// cannot be started twice or get drives after start.
func TestLimits(t *testing.T) {
	h := newHarness(t, t.TempDir())
	ctx := context.Background()
	img := h.image(t)
	for _, tt := range []struct {
		name string
		spec api.MachineSpec
		want api.ExitReason
	}{
		{"timeout", api.MachineSpec{TimeoutSeconds: 1, Process: api.Process{Args: []string{"hang"}}}, api.ExitTimeout},
		{"output", api.MachineSpec{TimeoutSeconds: 30, OutputLimitBytes: 4096, Process: api.Process{Args: []string{"flood"}}}, api.ExitOutputLimit},
	} {
		tt.spec.Name, tt.spec.Lifecycle, tt.spec.Image = tt.name, api.Ephemeral, img
		m, err := h.c.CreateMachine(ctx, tt.spec)
		if err != nil {
			t.Fatal(err)
		}
		exit, _ := h.runToExit(t, m.ID)
		if exit == nil || exit.Reason != tt.want {
			t.Errorf("%s: exit = %+v, want %s", tt.name, exit, tt.want)
		}
		if _, err := h.c.StartMachine(ctx, m.ID); !client.IsCode(err, api.ErrConflict) {
			t.Errorf("%s: second StartMachine() error = %v, want conflict", tt.name, err)
		}
		if err := h.c.PutDrive(ctx, m.ID, "x", strings.NewReader("")); err == nil {
			t.Errorf("%s: PutDrive() after start error = nil", tt.name)
		}
	}
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "secret", Lifecycle: api.Ephemeral, Image: img, TimeoutSeconds: 30,
		Process: api.Process{Args: []string{"echo:token=s3cr3t"}}, Redactions: [][]byte{[]byte("s3cr3t")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, out := h.runToExit(t, m.ID); strings.Contains(out, "s3cr3t") || !strings.Contains(out, "[REDACTED]") {
		t.Errorf("stdout = %q, want the secret redacted", out)
	}
}

// TestRestartMarksUnfinishedMachinesFailed proves recovery: a machine that
// was running when the service stopped is failed after a restart, the
// runtime is asked to recover, and its events end with an exit.
func TestRestartMarksUnfinishedMachinesFailed(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	ctx := context.Background()
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "hang", Lifecycle: api.Ephemeral, Image: h.image(t), TimeoutSeconds: 60,
		Process: api.Process{Args: []string{"hang"}}, Start: true})
	if err != nil {
		t.Fatal(err)
	}
	h2 := newHarness(t, dir)
	if h2.rt.recovered != 1 {
		t.Errorf("Recover() calls = %d, want 1", h2.rt.recovered)
	}
	got, err := h2.c.GetMachine(ctx, m.ID)
	if err != nil || got.State != api.StateFailed || got.Exit == nil || got.Exit.Reason != api.ExitFailed {
		t.Fatalf("machine after restart = %+v, %v; want failed", got, err)
	}
	var kinds []string
	_ = h2.c.Events(ctx, m.ID, 0, false, func(ev api.Event) error {
		kinds = append(kinds, string(ev.Kind))
		return nil
	})
	if len(kinds) == 0 || kinds[len(kinds)-1] != string(api.EventExit) {
		t.Errorf("events after restart = %v, want a final exit", kinds)
	}
}

// TestLoadCredentialRejectsUnsafeFiles proves that the credential must be
// owner-private, not a symlink, and long enough.
func TestLoadCredentialRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", testCredential+"\n", 0o600)
	if got, err := LoadCredential(good); err != nil || string(got) != testCredential {
		t.Fatalf("LoadCredential(good) = %q, %v; want the credential", got, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"group readable": write("group", testCredential, 0o640),
		"too short":      write("short", "short", 0o600),
		"symlink":        link,
	} {
		if _, err := LoadCredential(path); err == nil {
			t.Errorf("LoadCredential(%s) error = nil, want an error", name)
		}
	}
}

// TestSelfTest proves that the self-test runs one machine from the
// built-in image, reports the guest result and the proof, and leaves no
// machine behind.
func TestSelfTest(t *testing.T) {
	h := newHarness(t, t.TempDir())
	ctx := context.Background()
	res, err := h.c.SelfTest(ctx)
	if err != nil {
		t.Fatalf("SelfTest() error = %v", err)
	}
	if !res.Passed || !res.Proof.Destroyed || !strings.Contains(res.Detail, "metadata_denied") {
		t.Errorf("SelfTest() = %+v, want passed with the guest detail and a destroyed proof", res)
	}
	if got, err := h.c.ListMachines(ctx, map[string]string{"vmcp.selftest": "true"}); err != nil || len(got) != 0 {
		t.Errorf("self-test machines left = %d, %v; want 0", len(got), err)
	}
}
