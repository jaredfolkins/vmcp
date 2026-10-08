package machine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

// Error is a manager error with a fixed API code and a safe message.
type Error struct {
	Code    api.ErrorCode
	Message string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

func errorf(code api.ErrorCode, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Limits.
const (
	defaultOutputLimit = 16 << 20
	maxDriveMiB        = 64 << 10
	maxDrives          = 16
	maxFiles           = 512
	maxFileBytes       = 1 << 20
	maxTotalFileBytes  = 16 << 20
	maxSecretEnv       = 256
	maxSecretEnvBytes  = 1 << 20
	maxLabels          = 32
	// minAutoRedaction is the shortest secret value that vmcp redacts by
	// itself. A shorter value would erase common text.
	minAutoRedaction = 8
	// secretRoot is the guest tmpfs for secret files.
	secretRoot = "/run/"
)

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	driveRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Config configures a Manager.
type Config struct {
	// Dir holds records and machine work directories.
	Dir string
	// MaxMachines bounds the machines that hold a slot at once.
	MaxMachines int
	Logger      *slog.Logger
}

// Manager owns every machine and image of one vmcp service.
type Manager struct {
	rt  Runtime
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	machines map[string]*entry
	names    map[string]string
	images   map[string]*api.Image
	imageMu  map[string]*sync.Mutex
	slots    map[int]string
	secrets  secretStore

	selfTestMu sync.Mutex
}

type entry struct {
	// log is the machine logger. traceCtx carries the trace of the request
	// that created or started the machine; lines about the machine log with
	// it.
	log        *slog.Logger
	traceCtx   context.Context
	startedAt  time.Time
	sink       *sink
	rec        record
	inst       Instance
	events     *eventLog
	timer      *time.Timer
	output     int64
	killReason string
	finished   chan struct{}
}

// record is the durable machine record. It never holds tokens or secret
// file bodies.
type record struct {
	Machine  api.Machine     `json:"machine"`
	SpecHash string          `json:"spec_hash"`
	Slot     int             `json:"slot"`
	Spec     api.MachineSpec `json:"spec"`
}

// New loads every record, marks machines that an earlier process left as
// failed, and asks the runtime to remove their resources.
func New(ctx context.Context, rt Runtime, cfg Config) (*Manager, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.MaxMachines <= 0 {
		cfg.MaxMachines = 16
	}
	m := &Manager{rt: rt, cfg: cfg, log: cfg.Logger,
		machines: map[string]*entry{}, names: map[string]string{},
		images: map[string]*api.Image{}, imageMu: map[string]*sync.Mutex{}, slots: map[int]string{}}
	for _, d := range []string{m.recordsDir(), m.imageRecordsDir(), m.workDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	ctx, span := trace.Start(ctx, m.log, "recover")
	if err := rt.Recover(ctx); err != nil {
		span.End(err)
		return nil, fmt.Errorf("recover runtime resources: %w", err)
	}
	failed, err := m.load(ctx)
	span.End(err)
	if err != nil {
		return nil, err
	}
	m.log.InfoContext(ctx, "recovery finished", "machines", len(m.machines), "failed_by_restart", failed,
		"images", len(m.images), "duration_ms", trace.Millis(span.Elapsed()))
	return m, nil
}

func (m *Manager) recordsDir() string      { return filepath.Join(m.cfg.Dir, "records", "machines") }
func (m *Manager) imageRecordsDir() string { return filepath.Join(m.cfg.Dir, "records", "images") }
func (m *Manager) workDir() string         { return filepath.Join(m.cfg.Dir, "machines") }
func (m *Manager) machineDir(id string) string {
	return filepath.Join(m.workDir(), id)
}

// load reads every record. A machine that an earlier process left running
// becomes failed. It returns the number of such machines.
func (m *Manager) load(ctx context.Context) (int, error) {
	failed := 0
	imgs, _ := os.ReadDir(m.imageRecordsDir())
	for _, e := range imgs {
		var img api.Image
		if readJSON(filepath.Join(m.imageRecordsDir(), e.Name()), &img) == nil {
			m.images[img.ID] = &img
		}
	}
	recs, _ := os.ReadDir(m.recordsDir())
	for _, e := range recs {
		var rec record
		if readJSON(filepath.Join(m.recordsDir(), e.Name()), &rec) != nil {
			continue
		}
		ev, err := loadEventLog(filepath.Join(m.machineDir(rec.Machine.ID), "events.ndjson"))
		if err != nil {
			return failed, err
		}
		en := &entry{rec: rec, events: ev, finished: make(chan struct{})}
		switch rec.Machine.State {
		case api.StateCreated, api.StateRunning, api.StateStopping:
			en.rec.Machine.State = api.StateFailed
			en.rec.Machine.Exit = &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "vmcp restarted"}
			en.rec.Machine.UpdatedAt = time.Now().UTC()
			_ = ev.append(api.Event{Kind: api.EventExit, Exit: en.rec.Machine.Exit})
			_ = m.save(en)
			failed++
			m.log.WarnContext(ctx, "machine failed by vmcp restart", "code", "machine_recovered_failed",
				"machine", rec.Machine.ID, "machine_name", rec.Machine.Name)
		}
		ev.close()
		close(en.finished)
		m.machines[rec.Machine.ID] = en
		m.names[rec.Machine.Name] = rec.Machine.ID
	}
	return failed, nil
}

// Status reports the runtime status and the machine count.
func (m *Manager) Status() api.Status {
	st := m.rt.Status()
	m.mu.Lock()
	defer m.mu.Unlock()
	st.Capacity.Machines = len(m.slots)
	for _, id := range m.slots {
		if en := m.machines[id]; en != nil && en.rec.Machine.State == api.StateRunning {
			st.Capacity.UsedVCPUs += max(en.rec.Spec.Resources.VCPUs, 1)
			st.Capacity.UsedMemoryMiB += en.rec.Spec.Resources.MemoryMiB
		}
	}
	return st
}

// CreateImage prepares an image. A repeated request for the same reference
// returns the existing image.
func (m *Manager) CreateImage(ctx context.Context, req api.ImageRequest) (api.Image, error) {
	if !strings.Contains(req.Ref, "@sha256:") {
		return api.Image{}, errorf(api.ErrInvalidRequest, "image ref must be pinned by a sha256 digest")
	}
	sum := sha256.Sum256([]byte(req.Ref + "\n" + req.Registry.URL + "\n" + req.Platform))
	id := "img-" + hex.EncodeToString(sum[:8])
	m.mu.Lock()
	lock := m.imageMu[id]
	if lock == nil {
		lock = &sync.Mutex{}
		m.imageMu[id] = lock
	}
	m.mu.Unlock()
	lock.Lock()
	defer lock.Unlock()
	log := m.log.With("image", id)
	m.mu.Lock()
	if img := m.images[id]; img != nil {
		m.mu.Unlock()
		log.DebugContext(ctx, "image reused", "image_digest", img.ImageDigest)
		return *img, nil
	}
	m.mu.Unlock()
	ctx, span := trace.Start(ctx, log, "image.prepare")
	info, err := m.rt.PrepareImage(ctx, id, req)
	span.End(err)
	if err != nil {
		log.WarnContext(ctx, "image prepare failed", "code", "image_prepare_failed", "ref", req.Ref,
			"duration_ms", trace.Millis(span.Elapsed()), "error", trace.BoundedError(err))
		return api.Image{}, errorf(api.ErrInvalidRequest, "image could not be prepared: %s", safeDetail(err))
	}
	img := api.Image{ID: id, Ref: req.Ref, ImageDigest: info.ImageDigest, Compatibility: info.Compatibility,
		SizeBytes: info.SizeBytes, CreatedAt: time.Now().UTC()}
	if err := writeJSON(filepath.Join(m.imageRecordsDir(), id+".json"), imageRecord{Image: img, Process: info.Process}); err != nil {
		return api.Image{}, err
	}
	m.mu.Lock()
	m.images[id] = &img
	m.mu.Unlock()
	log.InfoContext(ctx, "image prepared", "ref", req.Ref, "image_digest", img.ImageDigest, "size_bytes", img.SizeBytes,
		"duration_ms", trace.Millis(span.Elapsed()))
	return img, nil
}

type imageRecord struct {
	api.Image
	Process ProcessConfig `json:"process"`
}

// Image returns one image.
func (m *Manager) Image(id string) (api.Image, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	img := m.images[id]
	if img == nil {
		return api.Image{}, errorf(api.ErrNotFound, "image not found")
	}
	return *img, nil
}

// Images returns every image.
func (m *Manager) Images() []api.Image {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.Image, 0, len(m.images))
	for _, img := range m.images {
		out = append(out, *img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteImage removes an image that no live machine uses.
func (m *Manager) DeleteImage(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.images[id] == nil {
		return errorf(api.ErrNotFound, "image not found")
	}
	for _, en := range m.machines {
		if en.rec.Machine.Image == id && !terminal(en.rec.Machine.State) {
			return errorf(api.ErrConflict, "image is used by machine %s", en.rec.Machine.ID)
		}
	}
	if err := m.rt.DeleteImage(id); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(m.imageRecordsDir(), id+".json"))
	delete(m.images, id)
	m.log.InfoContext(ctx, "image deleted", "image", id)
	return nil
}

// CreateMachine records a machine and reserves its slot. Start provisions
// and boots it.
func (m *Manager) CreateMachine(ctx context.Context, spec api.MachineSpec) (api.Machine, error) {
	if err := m.validate(spec); err != nil {
		return api.Machine{}, err
	}
	hash := specHash(sanitize(spec))
	m.mu.Lock()
	if id, ok := m.names[spec.Name]; ok {
		en := m.machines[id]
		m.mu.Unlock()
		if en.rec.SpecHash != hash {
			return api.Machine{}, errorf(api.ErrConflict, "machine name %q is used by a different spec", spec.Name)
		}
		return m.Machine(id)
	}
	if m.images[spec.Image] == nil {
		m.mu.Unlock()
		return api.Machine{}, errorf(api.ErrInvalidRequest, "image %q not found", spec.Image)
	}
	slot := -1
	for i := range m.cfg.MaxMachines {
		if _, used := m.slots[i]; !used {
			slot = i
			break
		}
	}
	if slot < 0 {
		m.mu.Unlock()
		return api.Machine{}, errorf(api.ErrCapacity, "every machine slot is in use")
	}
	id := newID()
	now := time.Now().UTC()
	en := &entry{
		log:      m.log.With("machine", id, "machine_name", spec.Name),
		traceCtx: trace.Detach(ctx),
		rec: record{
			Machine: api.Machine{ID: id, Name: spec.Name, Lifecycle: spec.Lifecycle, Labels: spec.Labels,
				Image: spec.Image, State: api.StateCreated, CreatedAt: now, UpdatedAt: now},
			SpecHash: hash, Slot: slot, Spec: sanitize(spec),
		},
		finished: make(chan struct{}),
	}
	m.slots[slot] = id
	m.machines[id] = en
	m.names[spec.Name] = id
	m.mu.Unlock()
	if err := os.MkdirAll(m.machineDir(id), 0o700); err != nil {
		return api.Machine{}, err
	}
	en.events = newEventLog(filepath.Join(m.machineDir(id), "events.ndjson"))
	m.secrets.put(id, spec)
	if err := m.save(en); err != nil {
		return api.Machine{}, err
	}
	_ = en.events.append(api.Event{Kind: api.EventState, State: api.StateCreated})
	en.log.InfoContext(ctx, "machine created", "image", spec.Image, "lifecycle", spec.Lifecycle, "slot", slot,
		"timeout_s", spec.TimeoutSeconds, "vcpus", spec.Resources.VCPUs, "memory_mib", spec.Resources.MemoryMiB,
		"drives", len(spec.Drives), "files", len(spec.Files), "dns", spec.Network.DNS,
		"public_egress", spec.Network.PublicEgress, "upstreams", len(spec.Network.Upstreams), "labels", spec.Labels)
	if spec.Start {
		return m.StartMachine(ctx, id)
	}
	return m.Machine(id)
}

func (m *Manager) validate(spec api.MachineSpec) error {
	switch {
	case !nameRE.MatchString(spec.Name):
		return errorf(api.ErrInvalidRequest, "name must match %s", nameRE)
	case spec.Lifecycle == api.Persistent:
		return errorf(api.ErrInvalidRequest, "persistent machines are not implemented yet")
	case spec.Lifecycle != api.Ephemeral:
		return errorf(api.ErrInvalidRequest, "lifecycle must be ephemeral or persistent")
	case spec.TimeoutSeconds <= 0:
		return errorf(api.ErrInvalidRequest, "an ephemeral machine needs timeout_seconds")
	case len(spec.Network.Ports) > 0:
		return errorf(api.ErrInvalidRequest, "ports apply only to a persistent machine")
	case spec.Resources.VCPUs < 0 || spec.Resources.VCPUs > 32 || spec.Resources.MemoryMiB < 0 || spec.Resources.MemoryMiB > 64<<10:
		return errorf(api.ErrInvalidRequest, "resources are out of range")
	case len(spec.Drives) > maxDrives || len(spec.Files) > maxFiles || len(spec.Labels) > maxLabels:
		return errorf(api.ErrInvalidRequest, "too many drives, files, or labels")
	}
	seen := map[string]bool{}
	for _, d := range spec.Drives {
		if !driveRE.MatchString(d.Name) || seen[d.Name] {
			return errorf(api.ErrInvalidRequest, "drive name %q is invalid or repeated", d.Name)
		}
		seen[d.Name] = true
		if d.SizeMiB <= 0 || d.SizeMiB > maxDriveMiB {
			return errorf(api.ErrInvalidRequest, "drive %q size is out of range", d.Name)
		}
		if !filepath.IsAbs(d.GuestPath) || filepath.Clean(d.GuestPath) != d.GuestPath || d.GuestPath == "/" {
			return errorf(api.ErrInvalidRequest, "drive %q guest path must be a clean absolute path", d.Name)
		}
	}
	total := 0
	for _, f := range spec.Files {
		if !filepath.IsAbs(f.GuestPath) || filepath.Clean(f.GuestPath) != f.GuestPath || len(f.Body) > maxFileBytes {
			return errorf(api.ErrInvalidRequest, "file %q is invalid", f.GuestPath)
		}
		if f.Secret && !strings.HasPrefix(f.GuestPath, secretRoot) {
			return errorf(api.ErrInvalidRequest, "secret file %q must be under %s", f.GuestPath, secretRoot)
		}
		total += len(f.Body)
	}
	if total > maxTotalFileBytes {
		return errorf(api.ErrInvalidRequest, "files exceed %d bytes", maxTotalFileBytes)
	}
	if len(spec.Process.SecretEnv) > maxSecretEnv {
		return errorf(api.ErrInvalidRequest, "too many secret_env entries")
	}
	envBytes := 0
	for _, kv := range spec.Process.SecretEnv {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || !envNameRE.MatchString(k) {
			// Name the index only: the entry may hold a secret.
			return errorf(api.ErrInvalidRequest, "secret_env entries must be NAME=VALUE")
		}
		envBytes += len(kv)
	}
	if envBytes > maxSecretEnvBytes {
		return errorf(api.ErrInvalidRequest, "secret_env exceeds %d bytes", maxSecretEnvBytes)
	}
	return nil
}

// specHash identifies a sanitized spec for name idempotency.
func specHash(spec api.MachineSpec) string {
	spec.Start = false
	b, _ := json.Marshal(spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sanitize removes tokens and file bodies from a stored spec.
func sanitize(spec api.MachineSpec) api.MachineSpec {
	out := spec
	out.Files = nil
	for _, f := range spec.Files {
		out.Files = append(out.Files, api.File{GuestPath: f.GuestPath, Mode: f.Mode, Secret: f.Secret})
	}
	out.Network.Upstreams = nil
	for _, u := range spec.Network.Upstreams {
		u.Token = ""
		out.Network.Upstreams = append(out.Network.Upstreams, u)
	}
	out.Redactions = nil
	// Keep secret entry names for the record; never their values.
	out.Process.SecretEnv = nil
	for _, kv := range spec.Process.SecretEnv {
		k, _, _ := strings.Cut(kv, "=")
		out.Process.SecretEnv = append(out.Process.SecretEnv, k)
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "m-" + hex.EncodeToString(b)
}

// Machine returns one machine.
func (m *Manager) Machine(id string) (api.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	en := m.machines[id]
	if en == nil {
		return api.Machine{}, errorf(api.ErrNotFound, "machine not found")
	}
	return en.rec.Machine, nil
}

// Machines returns the machines that have every label.
func (m *Manager) Machines(labels map[string]string) []api.Machine {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []api.Machine
	for _, en := range m.machines {
		match := true
		for k, v := range labels {
			if en.rec.Machine.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			out = append(out, en.rec.Machine)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// PutDrive replaces the input of a drive before the machine starts.
func (m *Manager) PutDrive(ctx context.Context, id, name string, r io.Reader) error {
	m.mu.Lock()
	en := m.machines[id]
	if en == nil {
		m.mu.Unlock()
		return errorf(api.ErrNotFound, "machine not found")
	}
	state, spec := en.rec.Machine.State, en.rec.Spec
	m.mu.Unlock()
	if state != api.StateCreated {
		return errorf(api.ErrConflict, "drives can be uploaded only before start")
	}
	var size int64 = -1
	for _, d := range spec.Drives {
		if d.Name == name {
			size = int64(d.SizeMiB) << 20
		}
	}
	if size < 0 {
		return errorf(api.ErrNotFound, "drive not found")
	}
	dir := filepath.Join(m.machineDir(id), "in", name)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	_, span := trace.Start(ctx, m.log, "drive.put")
	cr := &countingReader{r: r}
	err := extractTar(cr, dir, size)
	span.End(err, "machine", id, "drive", name, "bytes", cr.n)
	if err != nil {
		_ = os.RemoveAll(dir)
		return errorf(api.ErrInvalidRequest, "drive tar is invalid: %s", safeDetail(err))
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// GetDrive opens the tar of a writable drive after the machine stopped.
func (m *Manager) GetDrive(_ context.Context, id, name string) (*os.File, error) {
	m.mu.Lock()
	en := m.machines[id]
	m.mu.Unlock()
	if en == nil {
		return nil, errorf(api.ErrNotFound, "machine not found")
	}
	if !terminal(en.rec.Machine.State) || en.rec.Machine.State == api.StateDestroyed {
		return nil, errorf(api.ErrConflict, "drives are readable only after the machine stopped")
	}
	f, err := os.Open(filepath.Join(m.machineDir(id), "out", name+".tar"))
	if err != nil {
		return nil, errorf(api.ErrNotFound, "drive output not found")
	}
	return f, nil
}

// StartMachine provisions and boots a created machine.
func (m *Manager) StartMachine(ctx context.Context, id string) (api.Machine, error) {
	m.mu.Lock()
	en := m.machines[id]
	if en == nil {
		m.mu.Unlock()
		return api.Machine{}, errorf(api.ErrNotFound, "machine not found")
	}
	if en.rec.Machine.State != api.StateCreated {
		mach := en.rec.Machine
		m.mu.Unlock()
		if mach.State == api.StateRunning {
			return mach, nil
		}
		return api.Machine{}, errorf(api.ErrConflict, "machine is %s", mach.State)
	}
	en.rec.Machine.State = api.StateRunning
	en.traceCtx = trace.Detach(ctx)
	en.startedAt = time.Now()
	log := en.log
	m.mu.Unlock()
	spec := m.secrets.take(id)
	if spec == nil {
		log.WarnContext(ctx, "machine start refused", "code", "start_secrets_gone")
		return api.Machine{}, m.fail(en, "start secrets are gone; recreate the machine")
	}
	launch, err := m.launch(en, *spec)
	if err != nil {
		log.WarnContext(ctx, "machine start refused", "code", "launch_invalid", "error", trace.BoundedError(err))
		return api.Machine{}, m.fail(en, safeDetail(err))
	}
	m.mu.Lock()
	en.sink, _ = launch.Sink.(*sink)
	m.mu.Unlock()
	pctx, span := trace.Start(ctx, log, "machine.provision")
	launch.Logger = log
	inst, err := m.rt.Provision(pctx, launch)
	clearSpec(spec)
	provisionMS := trace.Millis(span.End(err))
	if err != nil {
		log.WarnContext(ctx, "machine provision failed", "code", "provision_failed", "duration_ms", provisionMS,
			"error", trace.BoundedError(err))
		return api.Machine{}, m.fail(en, "provision failed: "+safeDetail(err))
	}
	m.mu.Lock()
	en.inst = inst
	m.mu.Unlock()
	bctx, span := trace.Start(ctx, log, "machine.boot")
	err = inst.Boot(bctx)
	bootMS := trace.Millis(span.End(err))
	if err != nil {
		log.WarnContext(ctx, "machine boot failed", "code", "boot_failed", "duration_ms", bootMS, "error", trace.BoundedError(err))
		res := inst.Destroy(ctx, "boot-failed")
		m.finish(en, res)
		return m.Machine(id)
	}
	log.InfoContext(ctx, "machine started", "provision_ms", provisionMS, "boot_ms", bootMS)
	_ = m.save(en)
	_ = en.events.append(api.Event{Kind: api.EventState, State: api.StateRunning})
	timeout := time.Duration(en.rec.Spec.TimeoutSeconds) * time.Second
	m.mu.Lock()
	en.timer = time.AfterFunc(timeout, func() { m.kill(en, "timeout") })
	m.mu.Unlock()
	go func() {
		<-inst.Done()
		m.finish(en, inst.Result())
	}()
	return m.Machine(id)
}

// launch resolves the guest process from the image and the spec.
func (m *Manager) launch(en *entry, spec api.MachineSpec) (Launch, error) {
	var ir imageRecord
	if err := readJSON(filepath.Join(m.imageRecordsDir(), spec.Image+".json"), &ir); err != nil {
		return Launch{}, fmt.Errorf("read image record: %w", err)
	}
	p := ir.Process
	args := spec.Process.Args
	if len(args) == 0 {
		args = append(append([]string(nil), p.Entrypoint...), p.Cmd...)
	}
	if len(args) == 0 {
		return Launch{}, errors.New("the image has no command and the spec has no args")
	}
	dir := firstNonEmpty(spec.Process.Dir, p.WorkingDir, "/")
	user := firstNonEmpty(spec.Process.User, p.User)
	return Launch{
		ID: en.rec.Machine.ID, Slot: en.rec.Slot, Dir: m.machineDir(en.rec.Machine.ID), ImageID: spec.Image,
		Spec: spec, Args: args, Env: mergeEnv(p.Env, spec.Process.Env), SecretEnv: spec.Process.SecretEnv,
		WorkDir: dir, User: user,
		Sink: newSink(m, en, secretRedactions(spec), outputLimit(spec)),
	}, nil
}

// secretRedactions returns the sink's own copy of every byte string to
// redact: the caller's redactions, and each secret_env value and secret file
// body of at least minAutoRedaction bytes. StartMachine clears the spec copy
// after provisioning.
func secretRedactions(spec api.MachineSpec) [][]byte {
	var out [][]byte
	add := func(b []byte) {
		if len(b) > 0 {
			out = append(out, append([]byte(nil), b...))
		}
	}
	for _, r := range spec.Redactions {
		add(r)
	}
	for _, kv := range spec.Process.SecretEnv {
		if _, v, _ := strings.Cut(kv, "="); len(v) >= minAutoRedaction {
			add([]byte(v))
		}
	}
	for _, f := range spec.Files {
		if f.Secret && len(f.Body) >= minAutoRedaction {
			add(f.Body)
		}
	}
	return out
}

func outputLimit(spec api.MachineSpec) int64 {
	if spec.OutputLimitBytes > 0 {
		return spec.OutputLimitBytes
	}
	return defaultOutputLimit
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// mergeEnv returns base with every key in over replaced or added.
func mergeEnv(base, over []string) []string {
	idx := map[string]int{}
	out := append([]string(nil), base...)
	for i, kv := range out {
		k, _, _ := strings.Cut(kv, "=")
		idx[k] = i
	}
	for _, kv := range over {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
		} else {
			idx[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

// StopMachine stops a running machine.
func (m *Manager) StopMachine(ctx context.Context, id string) (api.Machine, error) {
	m.mu.Lock()
	en := m.machines[id]
	m.mu.Unlock()
	if en == nil {
		return api.Machine{}, errorf(api.ErrNotFound, "machine not found")
	}
	m.log.InfoContext(ctx, "machine stop requested", "machine", id)
	m.kill(en, "stopped")
	return m.Machine(id)
}

func (m *Manager) kill(en *entry, reason string) {
	m.mu.Lock()
	inst := en.inst
	if en.killReason == "" && en.rec.Machine.State == api.StateRunning {
		en.killReason = reason
	}
	m.mu.Unlock()
	if inst != nil {
		inst.Kill(reason)
	}
}

// DeleteMachine destroys a machine, removes its work directory, and returns
// the final record.
func (m *Manager) DeleteMachine(ctx context.Context, id string) (api.Machine, error) {
	m.mu.Lock()
	en := m.machines[id]
	m.mu.Unlock()
	if en == nil {
		return api.Machine{}, errorf(api.ErrNotFound, "machine not found")
	}
	m.mu.Lock()
	inst, state := en.inst, en.rec.Machine.State
	m.mu.Unlock()
	switch {
	case inst != nil && state == api.StateRunning:
		m.kill(en, "deleted")
		select {
		case <-en.finished:
		case <-ctx.Done():
			return api.Machine{}, ctx.Err()
		}
	case state == api.StateCreated:
		m.secrets.take(id)
		m.finish(en, Result{Proof: api.Proof{MachineID: id, DestroyReason: "deleted", Destroyed: true, TeardownStatus: "destroyed"}})
	}
	m.mu.Lock()
	en.rec.Machine.State = api.StateDestroyed
	en.rec.Machine.UpdatedAt = time.Now().UTC()
	final := en.rec.Machine
	delete(m.machines, id)
	delete(m.names, en.rec.Machine.Name)
	if m.slots[en.rec.Slot] == id {
		delete(m.slots, en.rec.Slot)
	}
	m.mu.Unlock()
	_ = os.RemoveAll(m.machineDir(id))
	_ = os.Remove(filepath.Join(m.recordsDir(), id+".json"))
	m.log.InfoContext(ctx, "machine deleted", "machine", id, "machine_name", final.Name)
	return final, nil
}

// stopReasonShutdown is the kill reason of a machine that vmcp stops
// because vmcp itself stops.
const stopReasonShutdown = "vmcp-stopping"

// Shutdown stops every running machine because vmcp is stopping, and waits
// until each one ended or ctx ends. An ephemeral machine cannot outlive the
// vmcp process, so each gets state failed with the detail "vmcp stopped",
// a teardown proof, and an exit event that ends its event streams.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	var running []*entry
	for _, en := range m.machines {
		if en.rec.Machine.State == api.StateRunning {
			running = append(running, en)
		}
	}
	m.mu.Unlock()
	if len(running) == 0 {
		return nil
	}
	ctx, span := trace.Start(ctx, m.log, "shutdown")
	for _, en := range running {
		m.kill(en, stopReasonShutdown)
	}
	var err error
	for _, en := range running {
		select {
		case <-en.finished:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if err != nil {
			break
		}
	}
	span.End(err)
	if err != nil {
		m.log.ErrorContext(ctx, "machines did not stop before vmcp stopped", "code", "shutdown_incomplete",
			"machines", len(running), "error", trace.BoundedError(err))
		return err
	}
	m.log.InfoContext(ctx, "machines stopped for vmcp shutdown", "machines", len(running),
		"duration_ms", trace.Millis(span.Elapsed()))
	return nil
}

// Events streams the events of a machine.
func (m *Manager) Events(ctx context.Context, id string, after uint64, follow bool, fn func(api.Event) error) error {
	m.mu.Lock()
	en := m.machines[id]
	m.mu.Unlock()
	if en == nil {
		return errorf(api.ErrNotFound, "machine not found")
	}
	return en.events.follow(ctx, after, follow, fn)
}

// finish records the end of a machine once.
func (m *Manager) finish(en *entry, res Result) {
	m.mu.Lock()
	select {
	case <-en.finished:
		m.mu.Unlock()
		return
	default:
	}
	if en.timer != nil {
		en.timer.Stop()
	}
	exit := finalExit(en.killReason, res)
	en.rec.Machine.Exit = exit
	proof := res.Proof
	en.rec.Machine.Proof = &proof
	en.rec.Machine.State = api.StateExited
	if exit.Reason == api.ExitFailed {
		en.rec.Machine.State = api.StateFailed
	}
	en.rec.Machine.UpdatedAt = time.Now().UTC()
	if m.slots[en.rec.Slot] == en.rec.Machine.ID {
		delete(m.slots, en.rec.Slot)
	}
	close(en.finished)
	snk := en.sink
	log, logCtx, state, killReason, output := en.log, en.traceCtx, en.rec.Machine.State, en.killReason, en.output
	var runMS float64
	if !en.startedAt.IsZero() {
		runMS = trace.Millis(time.Since(en.startedAt))
	}
	m.mu.Unlock()
	if snk != nil {
		snk.flush()
		snk.clear()
	}
	_ = m.save(en)
	_ = en.events.append(api.Event{Kind: api.EventExit, Exit: exit, State: en.rec.Machine.State})
	en.events.close()
	if log == nil {
		log = m.log.With("machine", en.rec.Machine.ID, "machine_name", en.rec.Machine.Name)
	}
	if logCtx == nil {
		logCtx = context.Background()
	}
	level, code := slog.LevelInfo, ""
	switch {
	case !proof.Destroyed || proof.TeardownStatus != "destroyed":
		level, code = slog.LevelError, "teardown_incomplete"
	case state == api.StateFailed:
		level, code = slog.LevelWarn, "machine_failed"
	}
	attrs := []any{"state", state, "exit_reason", exit.Reason, "exit_code", exit.Code, "run_ms", runMS,
		"output_bytes", output, "destroy_reason", proof.DestroyReason, "teardown_status", proof.TeardownStatus}
	if exit.Detail != "" {
		attrs = append(attrs, "exit_detail", exit.Detail)
	}
	if killReason != "" {
		attrs = append(attrs, "kill_reason", killReason)
	}
	if code != "" {
		attrs = append(attrs, "code", code)
	}
	log.Log(logCtx, level, "machine ended", attrs...)
}

func finalExit(killReason string, res Result) *api.Exit {
	switch killReason {
	case "timeout":
		return &api.Exit{Code: -1, Reason: api.ExitTimeout}
	case "output-limit":
		return &api.Exit{Code: -1, Reason: api.ExitOutputLimit}
	case "stopped", "deleted":
		return &api.Exit{Code: -1, Reason: api.ExitStopped}
	case stopReasonShutdown:
		return &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "vmcp stopped"}
	}
	switch res.Proof.DestroyReason {
	case "posture-violation":
		return &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "posture violation"}
	case "enforcer":
		return &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "security violation"}
	}
	if res.Exit != nil {
		return res.Exit
	}
	return &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "the guest reported no exit"}
}

func (m *Manager) fail(en *entry, detail string) error {
	m.finish(en, Result{Exit: &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: detail},
		Proof: api.Proof{MachineID: en.rec.Machine.ID, DestroyReason: "start-failed", Destroyed: true, TeardownStatus: "destroyed"}})
	return errorf(api.ErrUnavailable, "machine could not start: %s", detail)
}

func (m *Manager) save(en *entry) error {
	m.mu.Lock()
	rec := en.rec
	m.mu.Unlock()
	return writeJSON(filepath.Join(m.recordsDir(), rec.Machine.ID+".json"), rec)
}

func terminal(s api.MachineState) bool {
	return s == api.StateExited || s == api.StateFailed || s == api.StateDestroyed
}

// sink applies redaction and the output limit, then appends events.
// Redaction streams: a secret split across two output chunks is still
// redacted. Each stream keeps back only the trailing bytes that could start
// a secret, and flush releases them before the exit event.
type sink struct {
	m          *Manager
	en         *entry
	redactions [][]byte
	limit      int64
	limitHit   bool
	pending    map[api.EventKind][]byte
	mu         sync.Mutex
}

func newSink(m *Manager, en *entry, redactions [][]byte, limit int64) *sink {
	return &sink{m: m, en: en, redactions: redactions, limit: limit, pending: map[api.EventKind][]byte{}}
}

func (s *sink) Event(ev api.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Kind != api.EventStdout && ev.Kind != api.EventStderr {
		_ = s.en.events.append(ev)
		return
	}
	buf := append(s.pending[ev.Kind], ev.Data...)
	out, hold := redactStream(buf, s.redactions)
	s.pending[ev.Kind] = hold
	if len(out) == 0 {
		return
	}
	ev.Data = out
	s.emitOutput(ev)
}

// emitOutput counts output against the limit and appends it. The caller
// holds s.mu.
func (s *sink) emitOutput(ev api.Event) {
	s.en.output += int64(len(ev.Data))
	if s.en.output > s.limit {
		if !s.limitHit {
			s.limitHit = true
			s.en.log.WarnContext(s.en.traceCtx, "machine output limit reached", "code", "output_limit", "limit_bytes", s.limit)
		}
		s.m.kill(s.en, "output-limit")
		return
	}
	_ = s.en.events.append(ev)
}

// flush releases the held tail of each stream. The process has ended, so a
// held tail cannot become a secret any more.
func (s *sink) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, kind := range []api.EventKind{api.EventStdout, api.EventStderr} {
		if tail := s.pending[kind]; len(tail) > 0 {
			s.emitOutput(api.Event{Kind: kind, Data: tail})
		}
		delete(s.pending, kind)
	}
}

// clear wipes the redaction secrets after the machine ended.
func (s *sink) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.redactions {
		clear(r)
	}
	s.redactions = nil
	for k, b := range s.pending {
		clear(b)
		delete(s.pending, k)
	}
}

// redactStream replaces every redaction in buf. It returns the bytes that
// are safe to emit and the tail to hold: the longest suffix of buf that is
// a proper prefix of some redaction, which the next chunk may complete.
func redactStream(buf []byte, redactions [][]byte) (out, hold []byte) {
	for _, r := range redactions {
		if len(r) > 0 && bytes.Contains(buf, r) {
			buf = bytes.ReplaceAll(buf, r, []byte(redactedText))
		}
	}
	keep := 0
	for _, r := range redactions {
		if n := partialSuffix(buf, r); n > keep {
			keep = n
		}
	}
	cut := len(buf) - keep
	return buf[:cut:cut], append([]byte(nil), buf[cut:]...)
}

// partialSuffix returns the length of the longest suffix of buf that is a
// proper prefix of r.
func partialSuffix(buf, r []byte) int {
	start := max(0, len(buf)-len(r)+1)
	for i := start; i < len(buf); i++ {
		j := bytes.IndexByte(buf[i:], r[0])
		if j < 0 {
			return 0
		}
		i += j
		if bytes.HasPrefix(r, buf[i:]) {
			return len(buf) - i
		}
	}
	return 0
}

const redactedText = "[REDACTED]"

func safeDetail(err error) string {
	var me *Error
	if errors.As(err, &me) {
		return me.Message
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(p string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// selfTestImage is the ID of the built-in self-test image.
const selfTestImage = "img-selftest"

// SelfTest runs one ephemeral machine from the built-in self-test image
// with DNS and public egress enabled. The guest proves its denials; the
// runtime proves posture and teardown.
func (m *Manager) SelfTest(ctx context.Context) (api.SelfTestResult, error) {
	m.selfTestMu.Lock()
	defer m.selfTestMu.Unlock()
	ctx, span := trace.Start(ctx, m.log, "selftest")
	res, err := m.selfTest(ctx)
	span.End(err)
	attrs := []any{"passed", res.Passed, "duration_ms", trace.Millis(span.Elapsed())}
	if res.Proof.MachineID != "" {
		attrs = append(attrs, "machine", res.Proof.MachineID)
	}
	switch {
	case err != nil:
		m.log.ErrorContext(ctx, "self-test failed", append(attrs, "code", "selftest_error", "error", trace.BoundedError(err))...)
	case !res.Passed:
		m.log.WarnContext(ctx, "self-test failed", append(attrs, "code", "selftest_failed", "detail", bounded(res.Detail, 512))...)
	default:
		m.log.InfoContext(ctx, "self-test passed", attrs...)
	}
	return res, err
}

func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m *Manager) selfTest(ctx context.Context) (api.SelfTestResult, error) {
	info, err := m.rt.PrepareSelfTestImage(ctx, selfTestImage)
	if err != nil {
		return api.SelfTestResult{Detail: "self-test image could not be prepared: " + safeDetail(err)}, nil
	}
	img := api.Image{ID: selfTestImage, Ref: "vmcp-selftest", ImageDigest: info.ImageDigest, Compatibility: info.Compatibility,
		SizeBytes: info.SizeBytes, CreatedAt: time.Now().UTC()}
	if err := writeJSON(filepath.Join(m.imageRecordsDir(), selfTestImage+".json"), imageRecord{Image: img, Process: info.Process}); err != nil {
		return api.SelfTestResult{}, err
	}
	m.mu.Lock()
	m.images[selfTestImage] = &img
	m.mu.Unlock()
	mach, err := m.CreateMachine(ctx, api.MachineSpec{
		Name: "vmcp-selftest-" + newID()[2:], Lifecycle: api.Ephemeral, Image: selfTestImage, TimeoutSeconds: 60,
		Resources: api.Resources{VCPUs: 1, MemoryMiB: 128, DiskMiB: 64},
		Network:   api.Network{DNS: true, PublicEgress: true},
		Labels:    map[string]string{"vmcp.selftest": "true"},
		Start:     true,
	})
	if err != nil {
		return api.SelfTestResult{Detail: "self-test machine could not start: " + safeDetail(err)}, nil
	}
	var out bytes.Buffer
	_ = m.Events(ctx, mach.ID, 0, true, func(ev api.Event) error {
		if ev.Kind == api.EventStdout && out.Len() < 4096 {
			out.Write(ev.Data)
		}
		return nil
	})
	final, err := m.DeleteMachine(ctx, mach.ID)
	if err != nil {
		return api.SelfTestResult{}, err
	}
	res := api.SelfTestResult{Detail: strings.TrimSpace(out.String())}
	if final.Proof != nil {
		res.Proof = *final.Proof
	}
	res.Passed = final.Exit != nil && final.Exit.Code == 0 && final.Exit.Reason == api.ExitCompleted && res.Proof.Destroyed
	return res, nil
}
