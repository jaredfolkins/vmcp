package vm

import (
	"context"
	"encoding/json"
	"time"
)

// Backend runs machines with one VM technology on one host.
type Backend interface {
	// Name returns the backend name, such as "firecracker".
	Name() string
	// Status reports the installed release, host checks, and live machines.
	Status(ctx context.Context) (Status, error)
	// SelfTest boots one test machine, verifies its isolation, and destroys
	// it.
	SelfTest(ctx context.Context) (SelfTestResult, error)
	// Recover destroys every machine that an earlier process left and
	// returns one proof for each.
	Recover(ctx context.Context) ([]Proof, error)
	// PrepareRootFS converts a digest-pinned OCI image into a root
	// filesystem artifact that Create can use.
	PrepareRootFS(ctx context.Context, req RootFSRequest) (RootFS, error)
	// Create provisions an isolated machine. It does not boot the guest.
	Create(ctx context.Context, spec Spec) (Machine, error)
}

// Machine is one provisioned guest.
type Machine interface {
	// ID returns the backend-unique machine identity.
	ID() string
	// Start boots the guest and starts its process.
	Start(ctx context.Context) error
	// Events returns the machine events in order. The channel closes after
	// the process exits or the machine is destroyed.
	Events() <-chan Event
	// Wait blocks until the process exits and writable drives are copied
	// back to their host directories.
	Wait(ctx context.Context) (Exit, error)
	// Destroy removes the guest and every resource that the machine owns.
	// It is safe to call more than once.
	Destroy(ctx context.Context, reason string) (Proof, error)
}

// Spec describes one machine.
type Spec struct {
	// Name is a caller label for logs and proofs. It grants nothing.
	Name      string
	RootFS    RootFS
	Process   Process
	Resources Resources
	Network   Network
	Drives    []Drive
	Files     []File
	Timeout   time.Duration
	// OutputLimitBytes bounds the total stdout and stderr bytes.
	OutputLimitBytes int64
	// Redactions are exact byte strings that the backend removes from
	// every event before the caller sees it.
	Redactions [][]byte
}

// Process is the guest process. Empty Args runs the command from the
// image configuration.
type Process struct {
	Args []string
	Env  []string
}

// Resources are the machine limits.
type Resources struct {
	VCPUs     int
	MemoryMiB int
	DiskMiB   int
}

// Network is the guest network policy. Host loopback, host and private
// networks, cloud metadata, and container bridges are always denied.
type Network struct {
	// DNS gives the guest a brokered resolver.
	DNS bool
	// PublicEgress allows brokered egress to public addresses only.
	PublicEgress bool
	// Upstreams are services that the guest reaches only through a host
	// broker.
	Upstreams []Upstream
}

// Upstream is one brokered service.
type Upstream struct {
	// Name is the stable name that the guest uses for this service.
	Name string
	URL  string
	// Token is a bearer token that the broker adds to each request. It
	// never enters the guest.
	Token string
	// AllowWrite permits methods other than GET and HEAD.
	AllowWrite bool
}

// Drive is a directory that the guest mounts. The backend copies HostDir
// into the drive before boot. For a writable drive, Wait copies the drive
// content back to HostDir.
type Drive struct {
	Name      string
	GuestPath string
	HostDir   string
	SizeBytes int64
	Writable  bool
}

// File is one read-only file that the backend writes into the guest. The
// backend clears a secret Body after use.
type File struct {
	GuestPath string
	Mode      uint32
	Body      []byte
	Secret    bool
}

// RootFSRequest selects the OCI image to convert.
type RootFSRequest struct {
	// Image is an image reference pinned by digest.
	Image    string
	Platform string
	// Registry is the upstream that serves the image. Its token is used
	// only on the host.
	Registry Upstream
}

// RootFS is a root filesystem artifact on the host.
type RootFS struct {
	Path        string
	Digest      string
	ImageDigest string
	// Compatibility identifies the backend inputs that produced the
	// artifact. A caller can cache an artifact by image digest and
	// compatibility.
	Compatibility string
}

// EventKind is the type of a machine event.
type EventKind string

// Event kinds.
const (
	EventStdout EventKind = "stdout"
	EventStderr EventKind = "stderr"
	EventStep   EventKind = "step"
)

// Event is one ordered machine event. Data is bounded and redacted.
type Event struct {
	Seq    uint64
	Time   time.Time
	Kind   EventKind
	Step   string
	Status string
	Data   []byte
}

// ExitReason is the reason that a process stopped.
type ExitReason string

// Exit reasons.
const (
	ExitCompleted   ExitReason = "completed"
	ExitTimeout     ExitReason = "timeout"
	ExitOutputLimit ExitReason = "output-limit"
	ExitCanceled    ExitReason = "canceled"
	ExitFailed      ExitReason = "failed"
)

// Exit is the result of a process.
type Exit struct {
	Code   int
	Reason ExitReason
	Detail string
}

// Proof records how a machine was isolated and destroyed.
type Proof struct {
	MachineID         string
	Backend           string
	ImageDigest       string
	NetworkPolicyHash string
	DestroyReason     string
	Destroyed         bool
	TeardownStatus    string
	// Detail is the backend proof document. Its schema belongs to the
	// backend.
	Detail json.RawMessage
}

// Status is the backend state on this host.
type Status struct {
	Backend      string
	Release      string
	BundleDigest string
	Ready        bool
	Checks       []Check
	Machines     []string
}

// Check is one host or install check.
type Check struct {
	Name   string
	OK     bool
	Detail string
}

// SelfTestResult is the result of a self-test machine.
type SelfTestResult struct {
	Passed bool
	Detail string
	Proof  Proof
}
