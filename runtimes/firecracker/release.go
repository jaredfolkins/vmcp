package firecracker

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
)

const (
	releaseDir      = "release"
	releaseLockName = "release-v1.json"
	releaseSchema   = "vmcp/firecracker-release/v1"
)

// requiredArtifacts are the binaries that every baked release must contain.
var requiredArtifacts = []string{"firecracker", "jailer"}

//go:embed release/release-v1.json release/linux
var releaseFiles embed.FS

// Release is the lock of the baked Firecracker release. Firecracker and the
// jailer always come from the same upstream release, so one version covers
// both.
type Release struct {
	Schema    string     `json:"schema"`
	Version   string     `json:"version"`
	Platform  string     `json:"platform"`
	Source    Source     `json:"source"`
	Artifacts []Artifact `json:"artifacts"`
}

// Source is the official upstream archive that the artifacts came from.
type Source struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Artifact is one baked binary.
type Artifact struct {
	Name string `json:"name"`
	// SourcePath is the path of the binary inside the upstream archive.
	SourcePath string `json:"source_path"`
	// Path is the gzip file under the release directory.
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

// BakedRelease returns the validated lock of the baked release.
func BakedRelease() (Release, error) {
	data, err := releaseFiles.ReadFile(path.Join(releaseDir, releaseLockName))
	if err != nil {
		return Release{}, fmt.Errorf("read firecracker release lock: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Release
	if err := dec.Decode(&r); err != nil {
		return Release{}, fmt.Errorf("decode firecracker release lock: %w", err)
	}
	if err := r.validate(); err != nil {
		return Release{}, fmt.Errorf("invalid firecracker release lock: %w", err)
	}
	return r, nil
}

// WriteArtifact writes the named baked binary to w. It verifies the size and
// SHA-256 before it writes any byte.
func WriteArtifact(w io.Writer, name string) error {
	r, err := BakedRelease()
	if err != nil {
		return err
	}
	a, ok := r.artifact(name)
	if !ok {
		return fmt.Errorf("firecracker release has no artifact %q", name)
	}
	data, err := a.read()
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write firecracker artifact %q: %w", name, err)
	}
	return nil
}

// VerifyArtifactFile checks that the file at p is the named baked binary:
// one regular file with the locked size and SHA-256.
func VerifyArtifactFile(p, name string) error {
	r, err := BakedRelease()
	if err != nil {
		return err
	}
	a, ok := r.artifact(name)
	if !ok {
		return fmt.Errorf("firecracker release has no artifact %q", name)
	}
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("open firecracker artifact %q: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect firecracker artifact %q: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("firecracker artifact %q at %s is not a regular file", name, p)
	}
	data, err := io.ReadAll(io.LimitReader(f, a.Size+1))
	if err != nil {
		return fmt.Errorf("read firecracker artifact %q: %w", name, err)
	}
	return a.verify(data)
}

func (r Release) validate() error {
	if r.Schema != releaseSchema {
		return fmt.Errorf("schema %q, want %q", r.Schema, releaseSchema)
	}
	if r.Version == "" || r.Platform == "" || r.Source.URL == "" {
		return errors.New("version, platform, and source url are required")
	}
	if !isSHA256(r.Source.SHA256) {
		return errors.New("source sha256 is not a lowercase hex SHA-256")
	}
	seen := make(map[string]bool, len(r.Artifacts))
	for _, a := range r.Artifacts {
		if seen[a.Name] {
			return fmt.Errorf("duplicate artifact %q", a.Name)
		}
		seen[a.Name] = true
		if a.Name == "" || a.SourcePath == "" || a.Mode == "" {
			return fmt.Errorf("artifact %q needs a name, source path, and mode", a.Name)
		}
		if !isSHA256(a.SHA256) || a.Size <= 0 {
			return fmt.Errorf("artifact %q needs a SHA-256 and a positive size", a.Name)
		}
		if !fs.ValidPath(a.Path) {
			return fmt.Errorf("artifact %q path %q is not a clean relative path", a.Name, a.Path)
		}
	}
	for _, name := range requiredArtifacts {
		if !seen[name] {
			return fmt.Errorf("required artifact %q is missing", name)
		}
	}
	return nil
}

func (r Release) artifact(name string) (Artifact, bool) {
	for _, a := range r.Artifacts {
		if a.Name == name {
			return a, true
		}
	}
	return Artifact{}, false
}

// read decompresses the embedded artifact and verifies it. It reads at most
// one byte more than the locked size.
func (a Artifact) read() ([]byte, error) {
	f, err := releaseFiles.Open(path.Join(releaseDir, a.Path))
	if err != nil {
		return nil, fmt.Errorf("open firecracker artifact %q: %w", a.Name, err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("decompress firecracker artifact %q: %w", a.Name, err)
	}
	defer func() { _ = zr.Close() }()
	data, err := io.ReadAll(io.LimitReader(zr, a.Size+1))
	if err != nil {
		return nil, fmt.Errorf("decompress firecracker artifact %q: %w", a.Name, err)
	}
	if err := a.verify(data); err != nil {
		return nil, err
	}
	return data, nil
}

func (a Artifact) verify(data []byte) error {
	if int64(len(data)) != a.Size {
		return fmt.Errorf("firecracker artifact %q has %d bytes, want %d", a.Name, len(data), a.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return fmt.Errorf("firecracker artifact %q has sha256 %s, want %s", a.Name, got, a.SHA256)
	}
	return nil
}

func isSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
