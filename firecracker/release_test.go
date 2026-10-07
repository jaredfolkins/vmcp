package firecracker

import (
	"bytes"
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
