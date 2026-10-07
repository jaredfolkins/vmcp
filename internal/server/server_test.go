package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jaredfolkins/vmcp/api"
)

const testCredential = "test-credential-0123456789abcdef0123456789"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	h := New(Config{
		Credential: []byte(testCredential),
		Status:     func() api.Status { return api.Status{Backend: "test", Ready: true} },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestAuthentication proves that only the health route works without the
// credential, and that a wrong credential gets the same safe error.
func TestAuthentication(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		name  string
		path  string
		token string
		want  int
	}{
		{name: "health without credential", path: "/healthz", want: http.StatusNoContent},
		{name: "status without credential", path: "/v1/status", want: http.StatusUnauthorized},
		{name: "status with wrong credential", path: "/v1/status", token: testCredential + "x", want: http.StatusUnauthorized},
		{name: "unknown route without credential", path: "/v1/machines", want: http.StatusUnauthorized},
		{name: "status with credential", path: "/v1/status", token: testCredential, want: http.StatusOK},
		{name: "unknown route with credential", path: "/v1/nothing", token: testCredential, want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := get(t, srv.URL+tt.path, tt.token)
			if resp.StatusCode != tt.want {
				t.Fatalf("GET %s status = %d, want %d", tt.path, resp.StatusCode, tt.want)
			}
			if resp.StatusCode == http.StatusUnauthorized {
				var body api.ErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
					t.Fatalf("decode error body: %v", err)
				}
				if body.Error.Code != api.ErrUnauthorized {
					t.Errorf("error code = %q, want %q", body.Error.Code, api.ErrUnauthorized)
				}
			}
		})
	}
}

// TestStatusBody proves that status returns the backend report as JSON.
func TestStatusBody(t *testing.T) {
	srv := newTestServer(t)
	resp := get(t, srv.URL+"/v1/status", testCredential)
	var got api.Status
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Backend != "test" || !got.Ready {
		t.Errorf("status = %+v, want backend test and ready", got)
	}
}

// TestLoadCredentialRejectsUnsafeFiles proves that the credential must be
// owner-private, not a symlink, and long enough.
func TestLoadCredentialRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", testCredential+"\n", 0o600)
	if got, err := LoadCredential(good); err != nil || string(got) != testCredential {
		t.Fatalf("LoadCredential(good) = %q, %v; want the credential", got, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"group readable": write("group", testCredential, 0o640),
		"too short":      write("short", "short", 0o600),
		"symlink":        link,
	} {
		if _, err := LoadCredential(path); err == nil {
			t.Errorf("LoadCredential(%s) error = nil, want an error", name)
		}
	}
}
