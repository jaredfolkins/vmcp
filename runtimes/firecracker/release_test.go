package firecracker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteArtifactVerifiesBakedBytes proves that each embedded binary
// decompresses to the exact size and SHA-256 in the lock. It fails when a
// binary or the lock changes without the other.
func TestWriteArtifactVerifiesBakedBytes(t *testing.T) {
	r, err := BakedRelease()
	if err != nil {
		t.Fatalf("BakedRelease() error = %v", err)
	}
	for _, a := range r.Artifacts {
		var buf bytes.Buffer
		if err := WriteArtifact(&buf, a.Name); err != nil {
			t.Errorf("WriteArtifact(%q) error = %v", a.Name, err)
			continue
		}
		if got := int64(buf.Len()); got != a.Size {
			t.Errorf("WriteArtifact(%q) wrote %d bytes, want %d", a.Name, got, a.Size)
		}
	}
}

// TestArtifactVerifyRejectsChangedBytes proves that verification rejects a
// binary that differs from the lock in content or size.
func TestArtifactVerifyRejectsChangedBytes(t *testing.T) {
	r, err := BakedRelease()
	if err != nil {
		t.Fatalf("BakedRelease() error = %v", err)
	}
	a, ok := r.artifact("jailer")
	if !ok {
		t.Fatal("baked release has no jailer artifact")
	}
	data, err := a.read()
	if err != nil {
		t.Fatalf("read(jailer) error = %v", err)
	}
	changed := bytes.Clone(data)
	changed[len(changed)/2] ^= 0xff
	if err := a.verify(changed); err == nil {
		t.Error("verify(changed content) error = nil, want a SHA-256 mismatch")
	}
	if err := a.verify(data[:len(data)-1]); err == nil {
		t.Error("verify(short content) error = nil, want a size mismatch")
	}
}

// TestVerifyArtifactFileChecksTheFile proves that an installed binary is
// accepted only when it holds the exact locked bytes. The image extracts
// the jailer at build time; vmcp must refuse a changed or wrong file.
func TestVerifyArtifactFileChecksTheFile(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteArtifact(&buf, "jailer"); err != nil {
		t.Fatalf("WriteArtifact(jailer) error = %v", err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "jailer")
	if err := os.WriteFile(good, buf.Bytes(), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactFile(good, "jailer"); err != nil {
		t.Errorf("VerifyArtifactFile(locked bytes) error = %v, want nil", err)
	}
	if err := VerifyArtifactFile(good, "firecracker"); err == nil {
		t.Error("VerifyArtifactFile(jailer bytes as firecracker) error = nil, want a mismatch")
	}
	changed := bytes.Clone(buf.Bytes())
	changed[len(changed)/2] ^= 0xff
	bad := filepath.Join(dir, "changed")
	if err := os.WriteFile(bad, changed, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifactFile(bad, "jailer"); err == nil {
		t.Error("VerifyArtifactFile(changed bytes) error = nil, want a SHA-256 mismatch")
	}
	if err := VerifyArtifactFile(dir, "jailer"); err == nil {
		t.Error("VerifyArtifactFile(directory) error = nil, want a refusal")
	}
}
