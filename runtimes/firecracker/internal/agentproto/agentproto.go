// Package agentproto is the protocol between vmcp and its guest agent.
//
// The host gives the agent its configuration on a raw config drive. The
// agent sends ordered messages to the host over vsock port EventPort and
// the tar of each writable drive over vsock port DrivePort. The host never
// sends commands over vsock in this version.
package agentproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version in Hello and Config.
const Version = 1

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
)

// Limits.
const (
	MaxConfigBytes = 16 << 20
	MaxLineBytes   = 64 << 10
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
	Files  []File  `json:"files,omitempty"`
	// DNS is the resolver address for /etc/resolv.conf. Empty means no
	// DNS.
	DNS string `json:"dns,omitempty"`
}

// Drive is one spec drive.
type Drive struct {
	Name      string `json:"name"`
	Device    string `json:"device"`
	GuestPath string `json:"guest_path"`
	Writable  bool   `json:"writable"`
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
}

// DriveHeader is the first line on a DrivePort connection. The tar stream
// follows it until the connection closes.
type DriveHeader struct {
	Name string `json:"name"`
}
