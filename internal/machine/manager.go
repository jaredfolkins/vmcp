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
	maxFiles           = 64
	maxFileBytes       = 1 << 20
	maxLabels          = 32
)

var (
	nameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	driveRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
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
}

type entry struct {
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
	if err := rt.Recover(ctx); err != nil {
		return nil, fmt.Errorf("recover runtime resources: %w", err)
	}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) recordsDir() string      { return filepath.Join(m.cfg.Dir, "records", "machines") }
func (m *Manager) imageRecordsDir() string { return filepath.Join(m.cfg.Dir, "records", "images") }
func (m *Manager) workDir() string         { return filepath.Join(m.cfg.Dir, "machines") }
func (m *Manager) machineDir(id string) string {
	return filepath.Join(m.workDir(), id)
}

func (m *Manager) load() error {
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
			return err
		}
		en := &entry{rec: rec, events: ev, finished: make(chan struct{})}
		switch rec.Machine.State {
		case api.StateCreated, api.StateRunning, api.StateStopping:
			en.rec.Machine.State = api.StateFailed
			en.rec.Machine.Exit = &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "vmcp restarted"}
			en.rec.Machine.UpdatedAt = time.Now().UTC()
			_ = ev.append(api.Event{Kind: api.EventExit, Exit: en.rec.Machine.Exit})
			_ = m.save(en)
		}
		ev.close()
		close(en.finished)
		m.machines[rec.Machine.ID] = en
		m.names[rec.Machine.Name] = rec.Machine.ID
	}
	return nil
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
	m.mu.Lock()
	if img := m.images[id]; img != nil {
		m.mu.Unlock()
		return *img, nil
	}
	m.mu.Unlock()
	info, err := m.rt.PrepareImage(ctx, id, req)
	if err != nil {
		m.log.Warn("image prepare failed", "image", id, "code", "image_prepare_failed")
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
func (m *Manager) DeleteImage(id string) error {
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
	for _, f := range spec.Files {
		if !filepath.IsAbs(f.GuestPath) || filepath.Clean(f.GuestPath) != f.GuestPath || len(f.Body) > maxFileBytes {
			return errorf(api.ErrInvalidRequest, "file %q is invalid", f.GuestPath)
		}
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
func (m *Manager) PutDrive(id, name string, r io.Reader) error {
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
	if err := extractTar(r, dir, size); err != nil {
		_ = os.RemoveAll(dir)
		return errorf(api.ErrInvalidRequest, "drive tar is invalid: %s", safeDetail(err))
	}
	return nil
}

// GetDrive opens the tar of a writable drive after the machine stopped.
func (m *Manager) GetDrive(id, name string) (*os.File, error) {
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
	m.mu.Unlock()
	spec := m.secrets.take(id)
	if spec == nil {
		return api.Machine{}, m.fail(en, "start secrets are gone; recreate the machine")
	}
	launch, err := m.launch(en, *spec)
	if err != nil {
		return api.Machine{}, m.fail(en, safeDetail(err))
	}
	m.mu.Lock()
	en.sink, _ = launch.Sink.(*sink)
	m.mu.Unlock()
	inst, err := m.rt.Provision(ctx, launch)
	clearSpec(spec)
	if err != nil {
		m.log.Warn("machine provision failed", "machine", id, "code", "provision_failed")
		return api.Machine{}, m.fail(en, "provision failed: "+safeDetail(err))
	}
	m.mu.Lock()
	en.inst = inst
	m.mu.Unlock()
	if err := inst.Boot(ctx); err != nil {
		m.log.Warn("machine boot failed", "machine", id, "code", "boot_failed")
		res := inst.Destroy(ctx, "boot-failed")
		m.finish(en, res)
		return m.Machine(id)
	}
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
	dir := p.WorkingDir
	if dir == "" {
		dir = "/"
	}
	return Launch{
		ID: en.rec.Machine.ID, Slot: en.rec.Slot, Dir: m.machineDir(en.rec.Machine.ID), ImageID: spec.Image,
		Spec: spec, Args: args, Env: mergeEnv(p.Env, spec.Process.Env), WorkDir: dir, User: p.User,
		Sink: &sink{m: m, en: en, redactions: copyRedactions(spec.Redactions), limit: outputLimit(spec)},
	}, nil
}

// copyRedactions gives the sink its own copy. StartMachine clears the
// spec copy after provisioning.
func copyRedactions(in [][]byte) [][]byte {
	out := make([][]byte, 0, len(in))
	for _, r := range in {
		if len(r) > 0 {
			out = append(out, append([]byte(nil), r...))
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
func (m *Manager) StopMachine(id string) (api.Machine, error) {
	m.mu.Lock()
	en := m.machines[id]
	m.mu.Unlock()
	if en == nil {
		return api.Machine{}, errorf(api.ErrNotFound, "machine not found")
	}
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
	return final, nil
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
	m.mu.Unlock()
	if snk != nil {
		snk.clear()
	}
	_ = m.save(en)
	_ = en.events.append(api.Event{Kind: api.EventExit, Exit: exit, State: en.rec.Machine.State})
	en.events.close()
}

func finalExit(killReason string, res Result) *api.Exit {
	switch killReason {
	case "timeout":
		return &api.Exit{Code: -1, Reason: api.ExitTimeout}
	case "output-limit":
		return &api.Exit{Code: -1, Reason: api.ExitOutputLimit}
	case "stopped", "deleted":
		return &api.Exit{Code: -1, Reason: api.ExitStopped}
	}
	if res.Proof.DestroyReason == "posture-violation" {
		return &api.Exit{Code: -1, Reason: api.ExitFailed, Detail: "posture violation"}
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
type sink struct {
	m          *Manager
	en         *entry
	redactions [][]byte
	limit      int64
	mu         sync.Mutex
}

func (s *sink) Event(ev api.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Kind == api.EventStdout || ev.Kind == api.EventStderr {
		for _, r := range s.redactions {
			if len(r) > 0 {
				ev.Data = bytes.ReplaceAll(ev.Data, r, []byte("[REDACTED]"))
			}
		}
		s.en.output += int64(len(ev.Data))
		if s.en.output > s.limit {
			s.m.kill(s.en, "output-limit")
			return
		}
	}
	_ = s.en.events.append(ev)
}

// clear wipes the redaction secrets after the machine ended.
func (s *sink) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.redactions {
		clear(r)
	}
	s.redactions = nil
}

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
