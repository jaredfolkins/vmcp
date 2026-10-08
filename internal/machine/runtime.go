// Package machine is the runtime-neutral machine manager of vmcp. It owns
// machine records, names, slots, input drives, event logs, timeouts, output
// limits, redaction, and recovery. A Runtime does the VM work.
package machine

import (
	"context"
	"log/slog"

	"github.com/jaredfolkins/vmcp/api"
)

// Runtime runs machines with one VM technology.
type Runtime interface {
	Status() api.Status
	PrepareImage(ctx context.Context, id string, req api.ImageRequest) (ImageInfo, error)
	// PrepareSelfTestImage builds the built-in image that runs the runtime
	// self-test in a guest.
	PrepareSelfTestImage(ctx context.Context, id string) (ImageInfo, error)
	// ImageCompatibility is the compatibility key that a prepared image must
	// have to boot. An image with another key was prepared for another guest
	// agent or unpacker.
	ImageCompatibility() string
	DeleteImage(id string) error
	// Provision builds an isolated machine without booting it.
	Provision(ctx context.Context, l Launch) (Instance, error)
	// Recover removes every machine resource that an earlier process left.
	Recover(ctx context.Context) error
}

// Instance is one provisioned machine.
type Instance interface {
	Boot(ctx context.Context) error
	// Kill stops the guest at once. It is safe to call more than once.
	Kill(reason string)
	// Done is closed after the machine ended and its resources are gone.
	Done() <-chan struct{}
	Result() Result
	// Destroy kills a booted machine or removes one that never booted, and
	// returns its result.
	Destroy(ctx context.Context, reason string) Result
}

// ImageInfo describes a prepared image.
type ImageInfo struct {
	ImageDigest   string
	Compatibility string
	SizeBytes     int64
	Process       ProcessConfig
}

// ProcessConfig is the process from the OCI image configuration.
type ProcessConfig struct {
	Entrypoint []string
	Cmd        []string
	Env        []string
	WorkingDir string
	User       string
}

// Launch is everything a runtime needs to provision one machine.
type Launch struct {
	ID   string
	Slot int
	// Dir is the machine work directory. Input drive trees are in
	// Dir/in/<drive>. Writable drive tars go to Dir/out/<drive>.tar.
	Dir     string
	ImageID string
	Spec    api.MachineSpec
	Args    []string
	Env     []string
	// SecretEnv and the secret Files of Spec must never be written to disk.
	SecretEnv []string
	WorkDir   string
	User      string
	Sink      Sink
	// Logger is the machine logger. Its lines carry the machine identity
	// and the trace of the request that started the machine.
	Logger *slog.Logger
}

// Sink receives machine events in order. The sink sets Seq and Time.
type Sink interface {
	Event(api.Event)
}

// Result is the end of a machine.
type Result struct {
	// Exit is the process exit that the guest reported, or nil.
	Exit  *api.Exit
	Proof api.Proof
}
