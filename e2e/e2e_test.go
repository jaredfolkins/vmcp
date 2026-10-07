// Package e2e drives a running vmcp service through the Go client.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
)

var config = flag.String("vmcp-e2e-config", "", "HuJSON file for the vmcp end-to-end gate")

type e2eCfg struct {
	URL            string `json:"url"`
	CredentialFile string `json:"credential_file"`
	ImageRef       string `json:"image_ref"`
	EgressURL      string `json:"egress_url"`
}

func load(t *testing.T) (e2eCfg, *client.Client) {
	t.Helper()
	if *config == "" {
		t.Skip("set -vmcp-e2e-config to run the end-to-end gate")
	}
	raw, err := os.ReadFile(*config)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	var c e2eCfg
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	credPath := c.CredentialFile
	if !filepath.IsAbs(credPath) {
		credPath = filepath.Join(filepath.Dir(*config), credPath)
	}
	cred, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.New(c.URL, strings.TrimSpace(string(cred)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, cl
}

// TestEphemeralMachine runs one real machine through the public API: image,
// create, drive upload, start, events, drive download, delete, and proof.
func TestEphemeralMachine(t *testing.T) {
	c, cl := load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, err := cl.Status(ctx)
	if err != nil || !st.Ready {
		t.Fatalf("Status() = %+v, %v; want ready", st, err)
	}
	img, err := cl.CreateImage(ctx, api.ImageRequest{Ref: c.ImageRef})
	if err != nil {
		t.Fatalf("CreateImage() error = %v", err)
	}
	script := strings.Join([]string{
		"cat /in/greeting",
		"echo token=topsecret",
		"wget -q -T 10 -O /dev/null " + c.EgressURL + " && echo EGRESS_OK",
		"wget -q -T 5 -O /dev/null http://169.254.169.254/ || echo METADATA_DENIED",
		"tr a-z A-Z < /in/greeting > /out/result",
	}, "; ")
	name := "e2e-" + time.Now().UTC().Format("20060102t150405")
	m, err := cl.CreateMachine(ctx, api.MachineSpec{
		Name: name, Lifecycle: api.Ephemeral, Image: img.ID, TimeoutSeconds: 120,
		Labels:     map[string]string{"suite": "e2e"},
		Process:    api.Process{Args: []string{"/bin/sh", "-c", script}},
		Resources:  api.Resources{VCPUs: 1, MemoryMiB: 256, DiskMiB: 256},
		Network:    api.Network{DNS: true, PublicEgress: true},
		Drives:     []api.Drive{{Name: "in", GuestPath: "/in", SizeMiB: 8}, {Name: "out", GuestPath: "/out", SizeMiB: 8, Writable: true}},
		Redactions: [][]byte{[]byte("topsecret")},
	})
	if err != nil {
		t.Fatalf("CreateMachine() error = %v", err)
	}
	t.Cleanup(func() { _, _ = cl.DeleteMachine(context.Background(), m.ID) })
	var in bytes.Buffer
	tw := tar.NewWriter(&in)
	_ = tw.WriteHeader(&tar.Header{Name: "greeting", Mode: 0o644, Size: 6, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hello\n"))
	_ = tw.Close()
	if err := cl.PutDrive(ctx, m.ID, "in", &in); err != nil {
		t.Fatalf("PutDrive() error = %v", err)
	}
	start := time.Now()
	if _, err := cl.StartMachine(ctx, m.ID); err != nil {
		t.Fatalf("StartMachine() error = %v", err)
	}
	var out strings.Builder
	var exit *api.Exit
	var steps []string
	err = cl.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
		switch ev.Kind {
		case api.EventStdout:
			out.Write(ev.Data)
		case api.EventStep:
			steps = append(steps, ev.Step+":"+ev.Status)
		case api.EventExit:
			exit = ev.Exit
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	t.Logf("machine ran in %s; steps %v", time.Since(start).Round(time.Millisecond), steps)
	if exit == nil || exit.Code != 0 {
		t.Fatalf("exit = %+v, want 0; stdout %q", exit, out.String())
	}
	got := out.String()
	for _, want := range []string{"hello", "token=[REDACTED]", "EGRESS_OK", "METADATA_DENIED"} {
		if !strings.Contains(got, want) {
			t.Errorf("stdout missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "topsecret") {
		t.Errorf("stdout leaked the redacted secret: %q", got)
	}
	rc, err := cl.GetDrive(ctx, m.ID, "out")
	if err != nil {
		t.Fatalf("GetDrive() error = %v", err)
	}
	result := ""
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Name == "result" {
			b, _ := io.ReadAll(tr)
			result = string(b)
		}
	}
	_ = rc.Close()
	if result != "HELLO\n" {
		t.Errorf("out drive result = %q, want HELLO", result)
	}
	final, err := cl.DeleteMachine(ctx, m.ID)
	if err != nil || final.Proof == nil || !final.Proof.Destroyed {
		t.Fatalf("DeleteMachine() = %+v, %v; want a destroyed proof", final.Proof, err)
	}
	if posture, _ := final.Proof.Detail["posture"].(map[string]any); posture["ok"] != true {
		t.Errorf("posture = %+v, want ok", posture)
	}
}
