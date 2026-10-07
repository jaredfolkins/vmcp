package api

import "time"

// Version is the API version in every route path.
const Version = "v1"

// Route patterns in the net/http ServeMux form: a method, a space, and a
// path. Path parameters use the {name} form.
const (
	RouteHealth   = "GET /healthz"
	RouteStatus   = "GET /v1/status"
	RouteSelfTest = "POST /v1/selftest"

	RouteCreateImage = "POST /v1/images"
	RouteListImages  = "GET /v1/images"
	RouteGetImage    = "GET /v1/images/{id}"
	RouteDeleteImage = "DELETE /v1/images/{id}"

	RouteCreateMachine  = "POST /v1/machines"
	RouteListMachines   = "GET /v1/machines"
	RouteGetMachine     = "GET /v1/machines/{id}"
	RouteDeleteMachine  = "DELETE /v1/machines/{id}"
	RouteStartMachine   = "POST /v1/machines/{id}/start"
	RouteStopMachine    = "POST /v1/machines/{id}/stop"
	RouteRestartMachine = "POST /v1/machines/{id}/restart"
	// RouteMachineEvents streams newline-delimited JSON events. The after
	// query parameter resumes after a sequence number. The follow query
	// parameter keeps the stream open until the machine stops.
	RouteMachineEvents = "GET /v1/machines/{id}/events"
	// RoutePutDrive replaces a drive with a tar body. The machine must not
	// be running.
	RoutePutDrive = "PUT /v1/machines/{id}/drives/{name}"
	// RouteGetDrive returns a writable drive as a tar body. The machine must
	// not be running.
	RouteGetDrive = "GET /v1/machines/{id}/drives/{name}"

	// RouteCreateExec starts a process in a running persistent machine.
	RouteCreateExec = "POST /v1/machines/{id}/exec"
	// RouteAttachExec upgrades to a WebSocket that carries ExecFrame
	// messages for one exec session.
	RouteAttachExec = "GET /v1/machines/{id}/exec/{session}"
	// RouteAttachConsole upgrades to a WebSocket that carries ExecFrame
	// messages for the serial console of a persistent machine.
	RouteAttachConsole = "GET /v1/machines/{id}/console"

	RouteCreateSnapshot = "POST /v1/machines/{id}/snapshots"
	RouteListSnapshots  = "GET /v1/machines/{id}/snapshots"
	RouteRestoreMachine = "POST /v1/machines/{id}/restore"
	RouteDeleteSnapshot = "DELETE /v1/snapshots/{id}"
)

// Lifecycle selects how long a machine lives.
type Lifecycle string

// Lifecycles.
const (
	Ephemeral  Lifecycle = "ephemeral"
	Persistent Lifecycle = "persistent"
)

// RestartPolicy controls a persistent machine after its process stops or
// after vmcp restarts.
type RestartPolicy string

// Restart policies.
const (
	RestartNever     RestartPolicy = "never"
	RestartOnFailure RestartPolicy = "on-failure"
	RestartAlways    RestartPolicy = "always"
)

// MachineSpec is the body of RouteCreateMachine.
type MachineSpec struct {
	// Name is unique per caller. A repeated create with the same name and
	// spec returns the existing machine.
	Name      string            `json:"name"`
	Lifecycle Lifecycle         `json:"lifecycle"`
	Labels    map[string]string `json:"labels,omitempty"`
	// Image is an image ID from RouteCreateImage.
	Image     string    `json:"image"`
	Process   Process   `json:"process"`
	Resources Resources `json:"resources"`
	Network   Network   `json:"network"`
	Drives    []Drive   `json:"drives,omitempty"`
	Files     []File    `json:"files,omitempty"`
	// TimeoutSeconds bounds an ephemeral process. Zero means no limit and is
	// valid only for a persistent machine.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
	// OutputLimitBytes bounds the stdout and stderr bytes in events.
	OutputLimitBytes int64 `json:"output_limit_bytes,omitempty"`
	// Redactions are exact byte strings that vmcp removes from every event.
	Redactions [][]byte `json:"redactions,omitempty"`
	// Restart applies only to a persistent machine.
	Restart RestartPolicy `json:"restart,omitempty"`
	// Start boots the machine after create. Leave it false to upload
	// drives first.
	Start bool `json:"start,omitempty"`
}

// Process is the guest process. Empty Args runs the image command.
type Process struct {
	Args []string `json:"args,omitempty"`
	Env  []string `json:"env,omitempty"`
}

// Resources are the machine limits. DiskMiB is the root disk size.
type Resources struct {
	VCPUs     int `json:"vcpus"`
	MemoryMiB int `json:"memory_mib"`
	DiskMiB   int `json:"disk_mib"`
}

// Network is the guest network policy. vmcp always denies host loopback,
// host and private networks, cloud metadata, and container bridges.
type Network struct {
	DNS          bool       `json:"dns"`
	PublicEgress bool       `json:"public_egress"`
	Upstreams    []Upstream `json:"upstreams,omitempty"`
	// Ports apply only to a persistent machine.
	Ports []Port `json:"ports,omitempty"`
}

// Upstream is a service that the guest reaches only through a host broker.
type Upstream struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Token is a bearer token that the broker adds. It never enters the
	// guest and is never returned.
	Token      string `json:"token,omitempty"`
	AllowWrite bool   `json:"allow_write,omitempty"`
}

// Port is one guest port that vmcp exposes on its service network.
type Port struct {
	Name      string `json:"name"`
	GuestPort int    `json:"guest_port"`
	Protocol  string `json:"protocol"`
}

// Drive is a guest directory backed by its own disk image.
type Drive struct {
	Name      string `json:"name"`
	GuestPath string `json:"guest_path"`
	SizeMiB   int    `json:"size_mib"`
	Writable  bool   `json:"writable"`
}

// File is one read-only file that vmcp writes into the guest. vmcp clears
// a secret body after use and never returns it.
type File struct {
	GuestPath string `json:"guest_path"`
	Mode      uint32 `json:"mode"`
	Body      []byte `json:"body"`
	Secret    bool   `json:"secret,omitempty"`
}

// MachineState is the state of a machine.
type MachineState string

// Machine states.
const (
	StateCreated   MachineState = "created"
	StateRunning   MachineState = "running"
	StateStopping  MachineState = "stopping"
	StateStopped   MachineState = "stopped"
	StateExited    MachineState = "exited"
	StateDestroyed MachineState = "destroyed"
	StateFailed    MachineState = "failed"
)

// Machine is the response of the machine routes. It never contains tokens
// or secret file bodies.
type Machine struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Lifecycle Lifecycle         `json:"lifecycle"`
	Labels    map[string]string `json:"labels,omitempty"`
	Image     string            `json:"image"`
	State     MachineState      `json:"state"`
	Exit      *Exit             `json:"exit,omitempty"`
	Endpoints []Endpoint        `json:"endpoints,omitempty"`
	Proof     *Proof            `json:"proof,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// Endpoint is the service-network address of one exposed port.
type Endpoint struct {
	Port    string `json:"port"`
	Address string `json:"address"`
}

// StopRequest is the body of RouteStopMachine and RouteRestartMachine.
// vmcp asks the guest to shut down, then forces it after the timeout.
type StopRequest struct {
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`
}

// EventKind is the type of an event.
type EventKind string

// Event kinds.
const (
	EventStdout EventKind = "stdout"
	EventStderr EventKind = "stderr"
	EventStep   EventKind = "step"
	EventState  EventKind = "state"
	EventExit   EventKind = "exit"
)

// Event is one ordered machine event. Seq increases by one per event.
// Data is bounded and redacted.
type Event struct {
	Seq    uint64       `json:"seq"`
	Time   time.Time    `json:"time"`
	Kind   EventKind    `json:"kind"`
	Step   string       `json:"step,omitempty"`
	Status string       `json:"status,omitempty"`
	State  MachineState `json:"state,omitempty"`
	Data   []byte       `json:"data,omitempty"`
	Exit   *Exit        `json:"exit,omitempty"`
}

// ExitReason is the reason that a process stopped.
type ExitReason string

// Exit reasons.
const (
	ExitCompleted   ExitReason = "completed"
	ExitTimeout     ExitReason = "timeout"
	ExitOutputLimit ExitReason = "output-limit"
	ExitStopped     ExitReason = "stopped"
	ExitFailed      ExitReason = "failed"
)

// Exit is the result of a process.
type Exit struct {
	Code   int        `json:"code"`
	Reason ExitReason `json:"reason"`
	Detail string     `json:"detail,omitempty"`
}

// Proof records how a guest was isolated and destroyed.
type Proof struct {
	MachineID         string `json:"machine_id"`
	Runtime           string `json:"runtime"`
	Release           string `json:"release"`
	ImageDigest       string `json:"image_digest"`
	NetworkPolicyHash string `json:"network_policy_hash"`
	DestroyReason     string `json:"destroy_reason"`
	Destroyed         bool   `json:"destroyed"`
	TeardownStatus    string `json:"teardown_status"`
	// Detail is the runtime proof document. Its schema belongs to the
	// runtime.
	Detail map[string]any `json:"detail,omitempty"`
}

// ImageRequest is the body of RouteCreateImage.
type ImageRequest struct {
	// Ref is an OCI image reference pinned by digest.
	Ref      string   `json:"ref"`
	Platform string   `json:"platform"`
	Registry Upstream `json:"registry"`
}

// Image is a prepared root filesystem.
type Image struct {
	ID          string `json:"id"`
	Ref         string `json:"ref"`
	ImageDigest string `json:"image_digest"`
	// Compatibility identifies the runtime inputs that produced the image.
	Compatibility string    `json:"compatibility"`
	SizeBytes     int64     `json:"size_bytes"`
	CreatedAt     time.Time `json:"created_at"`
}

// ExecRequest is the body of RouteCreateExec.
type ExecRequest struct {
	Args []string `json:"args"`
	Env  []string `json:"env,omitempty"`
	TTY  bool     `json:"tty,omitempty"`
	Cols int      `json:"cols,omitempty"`
	Rows int      `json:"rows,omitempty"`
}

// ExecSession is the response of RouteCreateExec.
type ExecSession struct {
	ID string `json:"id"`
}

// ExecStream is the stream of an ExecFrame.
type ExecStream string

// Exec streams.
const (
	StreamStdin  ExecStream = "stdin"
	StreamStdout ExecStream = "stdout"
	StreamStderr ExecStream = "stderr"
	StreamResize ExecStream = "resize"
	StreamExit   ExecStream = "exit"
)

// ExecFrame is one WebSocket message of an exec or console attach.
type ExecFrame struct {
	Stream ExecStream `json:"stream"`
	Data   []byte     `json:"data,omitempty"`
	Cols   int        `json:"cols,omitempty"`
	Rows   int        `json:"rows,omitempty"`
	Exit   *Exit      `json:"exit,omitempty"`
}

// SnapshotRequest is the body of RouteCreateSnapshot.
type SnapshotRequest struct {
	Name string `json:"name"`
}

// Snapshot is a saved state of a persistent machine. A restore needs the
// same runtime release that created the snapshot.
type Snapshot struct {
	ID        string    `json:"id"`
	MachineID string    `json:"machine_id"`
	Name      string    `json:"name"`
	Release   string    `json:"release"`
	SizeBytes int64     `json:"size_bytes"`
	CreatedAt time.Time `json:"created_at"`
}

// RestoreRequest is the body of RouteRestoreMachine. The machine must be
// stopped.
type RestoreRequest struct {
	SnapshotID string `json:"snapshot_id"`
}

// Status is the response of RouteStatus.
type Status struct {
	Runtime  string   `json:"runtime"`
	Release  string   `json:"release"`
	Ready    bool     `json:"ready"`
	Checks   []Check  `json:"checks"`
	Capacity Capacity `json:"capacity"`
}

// Check is one host or service check.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Capacity is the machine budget of the host and its current use.
type Capacity struct {
	VCPUs         int `json:"vcpus"`
	MemoryMiB     int `json:"memory_mib"`
	UsedVCPUs     int `json:"used_vcpus"`
	UsedMemoryMiB int `json:"used_memory_mib"`
	Machines      int `json:"machines"`
}

// SelfTestResult is the response of RouteSelfTest.
type SelfTestResult struct {
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
	Proof  Proof  `json:"proof"`
}

// ErrorCode is a fixed, safe error class.
type ErrorCode string

// Error codes.
const (
	ErrInvalidRequest ErrorCode = "invalid_request"
	ErrUnauthorized   ErrorCode = "unauthorized"
	ErrNotFound       ErrorCode = "not_found"
	ErrConflict       ErrorCode = "conflict"
	ErrCapacity       ErrorCode = "capacity"
	ErrUnavailable    ErrorCode = "unavailable"
	ErrInternal       ErrorCode = "internal"
)

// ErrorResponse is the body of every error response.
type ErrorResponse struct {
	Error Error `json:"error"`
}

// Error is a safe error. Message never contains tokens, secret bodies, or
// raw guest output.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}
