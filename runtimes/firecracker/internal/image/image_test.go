package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name, link string
	typ        byte
	mode       int64
	body       string
}

func makeTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		hdr := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: mode,
			Size: int64(len(e.body)), Uid: os.Getuid(), Gid: os.Getgid()}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestUnpackerRules proves whiteouts, opaque directories, setuid mapping,
// and that device nodes are skipped.
func TestUnpackerRules(t *testing.T) {
	root := t.TempDir()
	u := &unpacker{root: root, maxBytes: 1 << 20}
	layer1 := makeTar(t, []tarEntry{
		{name: "etc/", typ: tar.TypeDir, mode: 0o755},
		{name: "etc/keep", typ: tar.TypeReg, body: "keep"},
		{name: "etc/gone", typ: tar.TypeReg, body: "gone"},
		{name: "opq/", typ: tar.TypeDir, mode: 0o755},
		{name: "opq/old", typ: tar.TypeReg, body: "old"},
		{name: "bin/tool", typ: tar.TypeReg, mode: 0o4755, body: "tool"},
		{name: "dev/null", typ: tar.TypeChar},
		{name: "link", typ: tar.TypeSymlink, link: "/etc/keep"},
	})
	layer2 := makeTar(t, []tarEntry{
		{name: "etc/.wh.gone", typ: tar.TypeReg},
		{name: "opq/.wh..wh..opq", typ: tar.TypeReg},
		{name: "opq/new", typ: tar.TypeReg, body: "new"},
	})
	for _, l := range [][]byte{layer1, layer2} {
		if err := u.apply(bytes.NewReader(l)); err != nil {
			t.Fatalf("apply() error = %v", err)
		}
	}
	if err := u.finish(); err != nil {
		t.Fatal(err)
	}
	checks := map[string]bool{"etc/keep": true, "etc/gone": false, "opq/old": false, "opq/new": true, "dev/null": false}
	for p, want := range checks {
		_, err := os.Lstat(filepath.Join(root, p))
		if got := err == nil; got != want {
			t.Errorf("%s exists = %v, want %v", p, got, want)
		}
	}
	fi, err := os.Stat(filepath.Join(root, "bin/tool"))
	if err != nil || fi.Mode()&os.ModeSetuid == 0 {
		t.Errorf("bin/tool mode = %v, %v; want setuid kept", fi.Mode(), err)
	}
}

// TestUnpackerRefusesEscapes proves that a layer cannot write outside the
// root through "..", or through a symlink in a parent path.
func TestUnpackerRefusesEscapes(t *testing.T) {
	outside := t.TempDir()
	for name, entries := range map[string][]tarEntry{
		"dot-dot": {{name: "../escape", typ: tar.TypeReg, body: "x"}},
		"symlink parent": {
			{name: "evil", typ: tar.TypeSymlink, link: outside},
			{name: "evil/escape", typ: tar.TypeReg, body: "x"},
		},
		"hardlink outside": {{name: "h", typ: tar.TypeLink, link: "../../etc/passwd"}},
	} {
		root := t.TempDir()
		u := &unpacker{root: root, maxBytes: 1 << 20}
		if err := u.apply(bytes.NewReader(makeTar(t, entries))); err == nil {
			t.Errorf("%s: apply() error = nil, want a refusal", name)
		}
		if _, err := os.Lstat(filepath.Join(outside, "escape")); err == nil {
			t.Fatalf("%s: a file was written outside the root", name)
		}
	}
}

// TestPrepareFromRegistry proves the full path: an index selects the
// platform manifest, blobs are verified, the agent is injected, and mke2fs
// builds the image. It also proves that a changed layer is refused.
func TestPrepareFromRegistry(t *testing.T) {
	if _, err := exec.LookPath("mke2fs"); err != nil {
		t.Skip("mke2fs is not installed")
	}
	layer := gz(t, makeTar(t, []tarEntry{{name: "hello.txt", typ: tar.TypeReg, body: "hello"}}))
	cfg, _ := json.Marshal(imageConfig{OS: "linux", Architecture: "amd64", Config: Config{Cmd: []string{"/bin/sh"}, User: "1000"}})
	blobs := map[string][]byte{digest(layer): layer, digest(cfg): cfg}
	man, _ := json.Marshal(manifest{MediaType: mediaOCIManifest,
		Config: Descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest(cfg), Size: int64(len(cfg))},
		Layers: []Descriptor{{MediaType: mediaOCILayerGzip, Digest: digest(layer), Size: int64(len(layer))}}})
	idx, _ := json.Marshal(manifest{MediaType: mediaOCIIndex, Manifests: []Descriptor{
		{MediaType: mediaOCIManifest, Digest: digest(man), Size: int64(len(man)), Platform: &Platform{OS: "linux", Architecture: "amd64"}}}})
	manifests := map[string][]byte{digest(man): man, digest(idx): idx}
	var tamper bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		d := parts[len(parts)-1]
		switch {
		case strings.Contains(r.URL.Path, "/manifests/") && manifests[d] != nil:
			_, _ = w.Write(manifests[d])
		case strings.Contains(r.URL.Path, "/blobs/") && blobs[d] != nil:
			b := blobs[d]
			if tamper && d == digest(layer) {
				b = append([]byte(nil), b...)
				b[len(b)-1] ^= 0xff
			}
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	agent := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(agent, []byte("#!agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	req := Request{Ref: "test/app@" + digest(idx), Registry: srv.URL, Platform: Platform{OS: "linux", Architecture: "amd64"}, AgentPath: agent, MaxBytes: 1 << 20}
	dir := filepath.Join(t.TempDir(), "img")
	meta, err := Prepare(context.Background(), srv.Client(), dir, req)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if meta.ImageDigest != digest(idx) || meta.Process.User != "1000" || meta.SizeBytes < 128<<20 {
		t.Errorf("Prepare() meta = %+v, want digest, user, and size", meta)
	}
	out, err := exec.Command("debugfs", "-R", "cat /.vmcp/init", filepath.Join(dir, RootFSName)).Output()
	if err != nil || string(out) != "#!agent" {
		t.Errorf("injected agent = %q, %v; want the agent bytes", out, err)
	}

	tamper = true
	if _, err := Prepare(context.Background(), srv.Client(), filepath.Join(t.TempDir(), "img2"), req); err == nil {
		t.Error("Prepare() with a changed layer error = nil, want a digest error")
	}
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(s[:]))
}
