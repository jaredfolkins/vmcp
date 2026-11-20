// Package agentproto is the protocol between vmcp and its guest agent.
//
// The host gives the agent its configuration on a raw config drive. The
// agent sends ordered messages to the host over vsock port EventPort and
// the tar of each writable drive over vsock port DrivePort. After the
// agent's Hello, the host sends exactly one Secrets message back on the
// EventPort connection. Secrets never go on the config drive, so they never
// touch host disk.
package agentproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Version is the protocol version in Hello and Config. Version 3 adds
// Config.Export. Version 4 adds the TypeStop host message. Version 5 adds
// Config.Ports, PortPort, and the TypeConnect host message, and is the
// first version number with Config.Mounts.
const Version = 5

// Guest paths and devices.
const (
	// InitPath is the agent path in every prepared image. The kernel starts
	// it as PID 1.
	InitPath = "/.vmcp/init"
	// ConfigDevice is the raw config drive. The root drive is /dev/vda.
	ConfigDevice = "/dev/vdb"
	// UpperDevice is the machine scratch disk that holds the writable
	// overlay layer.
	UpperDevice = "/dev/vdc"
	// FirstDriveIndex is the device index of the first spec drive:
	// /dev/vdd.
	FirstDriveIndex = 3
)

// vsock ports on the host CID.
const (
	EventPort = 1024
	DrivePort = 1025
	// PortPort carries one relayed guest TCP connection per vsock
	// connection. The guest opens it after a TypeConnect message.
	PortPort = 1026
)

// Limits.
const (
	MaxConfigBytes = 16 << 20
	MaxLineBytes   = 64 << 10
	// MaxSecretsBytes bounds the one Secrets line.
	MaxSecretsBytes = 24 << 20
	// SecretRoot is the guest tmpfs that holds every secret file.
	SecretRoot = "/run"
	// MaxPortHeaderBytes bounds the one PortHeader line.
	MaxPortHeaderBytes = 1 << 10
)

var configMagic = [8]byte{'V', 'M', 'C', 'P', 'C', 'F', 'G', '1'}

// Config is the agent configuration.
type Config struct {
	Version int      `json:"version"`
	Args    []string `json:"args"`
	Env     []string `json:"env"`
	Dir     string   `json:"dir"`
	// User is "uid", "uid:gid", "name", or "name:group" from the image or
	// the spec. Empty means root in the guest.
	User   string  `json:"user"`
	Drives []Drive `json:"drives,omitempty"`
	// Mounts are object mounts (api.Mount) with the resolved upstream URL
	// of their root.
	Mounts []Mount `json:"mounts,omitempty"`
	Files  []File  `json:"files,omitempty"`
	// DNS is the resolver address for /etc/resolv.conf. Empty means no
	// DNS.
	DNS string `json:"dns,omitempty"`
	// Export selects the drive export guest. The agent runs no process. It
	// mounts each writable drive, sends its tar, and then sends Done with
	// no Exit. The host boots this guest on the drives of a guest that
	// ended without sending them.
	Export bool `json:"export,omitempty"`
	// Ports are the guest loopback TCP ports that the host may connect to.
	// The agent refuses a TypeConnect message for any other port.
	Ports []int `json:"ports,omitempty"`
}

// Drive is one spec drive.
type Drive struct {
	Name      string `json:"name"`
	Device    string `json:"device"`
	GuestPath string `json:"guest_path"`
	Writable  bool   `json:"writable"`
}

// ObjectMountDrain bounds the wait of the agent, after the process ended,
// for the uploads of the object mounts. The host adds it to the stop time
// of a machine with mounts.
const ObjectMountDrain = 60 * time.Second

// Mount is one object mount: the guest folder, the upstream URL of its
// root as the guest reaches it, and whether it refuses writes.
type Mount struct {
	GuestPath string `json:"guest_path"`
	URL       string `json:"url"`
	ReadOnly  bool   `json:"read_only,omitempty"`
	MaxBytes  int64  `json:"max_bytes"`
	Uploads   int    `json:"uploads"`
}

// File is one file to write before the process starts.
type File struct {
	GuestPath string `json:"guest_path"`
	Mode      uint32 `json:"mode"`
	Body      []byte `json:"body"`
}

// EncodeConfig returns the config drive bytes: an 8-byte magic, an 8-byte
// big-endian length, the JSON, and zero padding to a 4 KiB multiple.
func EncodeConfig(c Config) ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode agent config: %w", err)
	}
	if len(body) > MaxConfigBytes {
		return nil, fmt.Errorf("agent config has %d bytes, limit %d", len(body), MaxConfigBytes)
	}
	var buf bytes.Buffer
	buf.Write(configMagic[:])
	_ = binary.Write(&buf, binary.BigEndian, uint64(len(body)))
	buf.Write(body)
	if pad := buf.Len() % 4096; pad != 0 {
		buf.Write(make([]byte, 4096-pad))
	}
	return buf.Bytes(), nil
}

// DecodeConfig reads a config drive.
func DecodeConfig(r io.Reader) (Config, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Config{}, fmt.Errorf("read agent config header: %w", err)
	}
	if !bytes.Equal(hdr[:8], configMagic[:]) {
		return Config{}, errors.New("agent config drive has no vmcp magic")
	}
	n := binary.BigEndian.Uint64(hdr[8:])
	if n == 0 || n > MaxConfigBytes {
		return Config{}, fmt.Errorf("agent config length %d is invalid", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Config{}, fmt.Errorf("read agent config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(body, &c); err != nil {
		return Config{}, fmt.Errorf("decode agent config: %w", err)
	}
	if c.Version != Version {
		return Config{}, fmt.Errorf("agent config version %d, want %d", c.Version, Version)
	}
	return c, nil
}

// MessageType is the type of a guest message.
type MessageType string

// Message types.
const (
	// TypeHello is the first message. Version is set.
	TypeHello MessageType = "hello"
	// TypeStep reports a guest lifecycle step.
	TypeStep MessageType = "step"
	// TypeStdout and TypeStderr carry one bounded chunk of process output.
	TypeStdout MessageType = "stdout"
	TypeStderr MessageType = "stderr"
	// TypeExit reports the process exit code.
	TypeExit MessageType = "exit"
	// TypeDone is the last message. Every drive tar was sent.
	TypeDone MessageType = "done"
	// TypeDoneAck is the host-to-guest answer to TypeDone. The host read
	// every message before TypeDone. The agent waits for it before it
	// restarts the guest, so the last messages are not lost in the guest.
	TypeDoneAck MessageType = "done-ack"
	// TypeSecrets is the first host-to-guest message, sent once after Hello.
	TypeSecrets MessageType = "secrets"
	// TypeStop is a host-to-guest message after TypeSecrets. The agent sends
	// SIGTERM to the process group, and SIGKILL when the process still runs
	// after GraceMS. It then sends the drive tars as after a process exit.
	TypeStop MessageType = "stop"
	// TypeConnect is a host-to-guest message after TypeSecrets. The agent
	// connects to the guest loopback TCP port Port, opens a PortPort
	// connection, sends one PortHeader with ConnID, and then relays bytes
	// in both directions until one side closes.
	TypeConnect MessageType = "connect"
)

// Message is one newline-delimited JSON message on EventPort.
type Message struct {
	Type    MessageType `json:"type"`
	Version int         `json:"version,omitempty"`
	Step    string      `json:"step,omitempty"`
	Status  string      `json:"status,omitempty"`
	Data    []byte      `json:"data,omitempty"`
	Code    int         `json:"code,omitempty"`
	Detail  string      `json:"detail,omitempty"`
	// GraceMS is set only on TypeStop.
	GraceMS int64 `json:"grace_ms,omitempty"`
	// Secrets is set only on TypeSecrets.
	Secrets *Secrets `json:"secrets,omitempty"`
	// ConnID and Port are set only on TypeConnect.
	ConnID string `json:"conn_id,omitempty"`
	Port   int    `json:"port,omitempty"`
}

// Secrets are the process environment entries and files that must not be
// stored. The agent writes the files under SecretRoot, a tmpfs, and adds
// the entries to the process environment.
type Secrets struct {
	Env   []string `json:"env,omitempty"`
	Files []File   `json:"files,omitempty"`
}

// Clear zeroes the file bodies.
func (s *Secrets) Clear() {
	if s == nil {
		return
	}
	for i := range s.Files {
		clear(s.Files[i].Body)
	}
	s.Env = nil
}

// DriveHeader is the first line on a DrivePort connection. The tar stream
// follows it until the connection closes.
type DriveHeader struct {
	Name string `json:"name"`
}

// PortHeader is the first line on a PortPort connection. ConnID is the
// value of the TypeConnect message. A non-empty Error reports that the agent
// did not connect to the guest port; the agent then closes the connection.
// Without an error, the bytes of the guest TCP connection follow.
type PortHeader struct {
	ConnID string `json:"conn_id"`
	Error  string `json:"error,omitempty"`
}
