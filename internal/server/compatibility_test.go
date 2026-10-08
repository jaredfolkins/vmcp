package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/client"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

var compatibilityTestConfig = flag.String("vmcp-compatibility-test-config", "testdata/compatibility.hujson",
	"HuJSON file for the image compatibility test")

type compatibilityTestInput struct {
	ImageRef             string `json:"image_ref"`
	FirstCompatibility   string `json:"first_compatibility"`
	NextCompatibility    string `json:"next_compatibility"`
	RestartCompatibility string `json:"restart_compatibility"`
	Redaction            string `json:"redaction"`
	StepDetail           string `json:"step_detail"`
	WantDetail           string `json:"want_detail"`
}

func readCompatibilityInput(t *testing.T) compatibilityTestInput {
	t.Helper()
	raw, err := os.ReadFile(*compatibilityTestConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in compatibilityTestInput
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		t.Fatal(err)
	}
	if in.ImageRef == "" || in.FirstCompatibility == "" || in.NextCompatibility == "" || in.RestartCompatibility == "" ||
		in.Redaction == "" || !strings.Contains(in.StepDetail, in.Redaction) || in.WantDetail == "" {
		t.Fatal("compatibility test input is incomplete")
	}
	return in
}

func wantConflict(t *testing.T, what string, err error) {
	t.Helper()
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Status != http.StatusConflict || ce.Code != api.ErrConflict {
		t.Fatalf("%s error = %v; want a %d %s", what, err, http.StatusConflict, api.ErrConflict)
	}
}

// TestStaleImagesArePreparedAgain proves that an image prepared for another
// guest agent never boots: a new machine is refused, a repeated image
// request prepares the image again once no live machine uses it, and a
// restart drops the stale image with a log line.
func TestStaleImagesArePreparedAgain(t *testing.T) {
	in := readCompatibilityInput(t)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt := &fakeRuntime{compat: in.FirstCompatibility}
	h := newHarnessFor(t, dir, rt, slog.New(slog.DiscardHandler))

	img, err := h.c.CreateImage(ctx, api.ImageRequest{Ref: in.ImageRef})
	if err != nil || img.Compatibility != in.FirstCompatibility || rt.preparedCount() != 1 {
		t.Fatalf("CreateImage() = %+v, %v, prepared %d; want key %q, prepared 1", img, err, rt.preparedCount(), in.FirstCompatibility)
	}
	busy, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "busy", Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 30, Process: api.Process{Args: []string{"hang"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.StartMachine(ctx, busy.ID); err != nil {
		t.Fatal(err)
	}

	rt.setCompatibility(in.NextCompatibility)
	_, err = h.c.CreateMachine(ctx, api.MachineSpec{Name: "stale", Lifecycle: api.Ephemeral, Image: img.ID,
		TimeoutSeconds: 30, Process: api.Process{Args: []string{"echo:x"}}})
	wantConflict(t, "CreateMachine(stale image)", err)
	_, err = h.c.CreateImage(ctx, api.ImageRequest{Ref: in.ImageRef})
	wantConflict(t, "CreateImage(stale image in use)", err)

	if _, err := h.c.DeleteMachine(ctx, busy.ID); err != nil {
		t.Fatal(err)
	}
	again, err := h.c.CreateImage(ctx, api.ImageRequest{Ref: in.ImageRef})
	if err != nil || again.ID != img.ID || again.Compatibility != in.NextCompatibility || rt.preparedCount() != 2 {
		t.Fatalf("CreateImage() again = %+v, %v, prepared %d; want %s with key %q, prepared 2",
			again, err, rt.preparedCount(), img.ID, in.NextCompatibility)
	}

	capture := &logCapture{}
	log := slog.New(trace.NewHandler(slog.NewJSONHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	restarted := newHarnessFor(t, dir, &fakeRuntime{compat: in.RestartCompatibility}, log)
	imgs, err := restarted.c.ListImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range imgs {
		if i.ID == img.ID {
			t.Fatalf("ListImages() after restart has stale image %+v", i)
		}
	}
	dropped := false
	for _, l := range capture.lines(t) {
		if l["msg"] == "image dropped" && l["image"] == img.ID && l["reason"] == "compatibility_changed" &&
			l["compatibility"] == in.NextCompatibility && l["runtime_compatibility"] == in.RestartCompatibility {
			dropped = true
		}
	}
	if !dropped {
		t.Fatalf("restart log has no image dropped line for %s", img.ID)
	}
}

// TestGuestStepFailureKeepsRedactedDetail proves that the guest agent's
// reason for a failed step reaches the event stream and one WARN line, with
// the machine redactions applied.
func TestGuestStepFailureKeepsRedactedDetail(t *testing.T) {
	in := readCompatibilityInput(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capture := &logCapture{}
	log := slog.New(trace.NewHandler(slog.NewJSONHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	h := newHarnessFor(t, t.TempDir(), &fakeRuntime{}, log)
	m, err := h.c.CreateMachine(ctx, api.MachineSpec{Name: "stepfail", Lifecycle: api.Ephemeral, Image: h.image(t),
		TimeoutSeconds: 30, Redactions: [][]byte{[]byte(in.Redaction)}, Process: api.Process{Args: []string{"stepfail:" + in.StepDetail}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.c.StartMachine(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	var got []string
	if err := h.c.Events(ctx, m.ID, 0, true, func(ev api.Event) error {
		if ev.Kind == api.EventStep && ev.Status == "failed" {
			got = append(got, ev.Detail)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != in.WantDetail {
		t.Fatalf("failed step details = %q; want [%q]", got, in.WantDetail)
	}
	warned := 0
	for _, l := range capture.lines(t) {
		if d, _ := l["detail"].(string); strings.Contains(d, in.Redaction) {
			t.Fatalf("log line has the redaction value: %v", l)
		}
		if l["msg"] == "guest step failed" && l["level"] == "WARN" && l["code"] == "guest_step_failed" &&
			l["step"] == "agent" && l["detail"] == in.WantDetail {
			warned++
		}
	}
	if warned != 1 {
		t.Fatalf("guest step failed WARN lines = %d; want 1", warned)
	}
}
