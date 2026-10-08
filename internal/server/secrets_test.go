package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
)

var secretsTestConfig = flag.String("vmcp-secrets-test-config", "testdata/secrets.hujson", "HuJSON file for the secrets test")

type secretsTestInput struct {
	SecretEnv          []string `json:"secret_env"`
	WantRecordNames    []string `json:"want_record_names"`
	ChunkBytes         int      `json:"chunk_bytes"`
	RejectedSecretFile string   `json:"rejected_secret_file"`
}

func readSecretsInput(t *testing.T) secretsTestInput {
	t.Helper()
	raw, err := os.ReadFile(*secretsTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in secretsTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if len(in.SecretEnv) == 0 || in.ChunkBytes <= 0 || in.RejectedSecretFile == "" {
		t.Fatal("secrets test input is incomplete")
	}
	return in
}

// TestSecretEnvNeverLeaves proves that secret_env values reach the guest
// process but never an event, even when the guest prints a value split
// across output chunks, and that the stored machine record keeps only the
// entry names. It also proves that a secret file outside /run is refused.
func TestSecretEnvNeverLeaves(t *testing.T) {
	in := readSecretsInput(t)
	h := newHarness(t, t.TempDir())
	ctx := context.Background()
	img := h.image(t)
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "leaky", Lifecycle: api.Ephemeral, Image: img, TimeoutSeconds: 30,
		Process: api.Process{Args: []string{fmt.Sprintf("leak:%d", in.ChunkBytes)}, SecretEnv: in.SecretEnv}})
	if err != nil {
		t.Fatalf("CreateMachine() error = %v", err)
	}
	exit, out := h.runToExit(t, m.ID)
	if exit == nil || exit.Code != 0 {
		t.Fatalf("exit = %+v, want code 0", exit)
	}
	for _, kv := range in.SecretEnv {
		_, v, _ := strings.Cut(kv, "=")
		if strings.Contains(out, v) {
			t.Errorf("events hold secret value of %q: %q", kv[:strings.Index(kv, "=")], out)
		}
	}
	if got := strings.Count(out, "value=[REDACTED]\n"); got != len(in.SecretEnv) {
		t.Errorf("output = %q, want %d redacted values with the text around them intact", out, len(in.SecretEnv))
	}
	rec, err := os.ReadFile(h.dir + "/records/machines/" + m.ID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range in.SecretEnv {
		_, v, _ := strings.Cut(kv, "=")
		if bytes.Contains(rec, []byte(v)) {
			t.Errorf("stored record holds a secret value")
		}
	}
	var stored struct {
		Spec api.MachineSpec `json:"spec"`
	}
	if err := json.Unmarshal(rec, &stored); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.Spec.Process.SecretEnv, in.WantRecordNames) {
		t.Errorf("stored secret_env = %q, want names only %q", stored.Spec.Process.SecretEnv, in.WantRecordNames)
	}

	_, err = h.c.CreateMachine(ctx, api.MachineSpec{Name: "bad-secret-file", Lifecycle: api.Ephemeral, Image: img, TimeoutSeconds: 30,
		Files: []api.File{{GuestPath: in.RejectedSecretFile, Mode: 0o400, Body: []byte("x"), Secret: true}}})
	if !client.IsCode(err, api.ErrInvalidRequest) {
		t.Errorf("CreateMachine() with secret file %s error = %v, want invalid_request", in.RejectedSecretFile, err)
	}
}
