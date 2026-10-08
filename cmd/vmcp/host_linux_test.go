package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

var hostFlagsConfig = flag.String("vmcp-host-flags-config", "testdata/host-flags.hujson", "HuJSON file with refused host command lines")

// TestHostCommandRefusesBadLines proves that vmcp host decodes its command
// line strictly: an unknown command, flag, or argument, or a missing or bad
// value, fails before the command reads or changes the host, and prints no
// result.
func TestHostCommandRefusesBadLines(t *testing.T) {
	raw, err := os.ReadFile(*hostFlagsConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Refused []struct {
			Args      []string `json:"args"`
			WantError string   `json:"want_error"`
		} `json:"refused"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(in.Refused) == 0 {
		t.Fatalf("decode %s: %v", *hostFlagsConfig, err)
	}
	for _, tc := range in.Refused {
		var out bytes.Buffer
		err := hostCommand(context.Background(), tc.Args, &out, slog.New(slog.DiscardHandler))
		if err == nil || !strings.Contains(err.Error(), tc.WantError) {
			t.Errorf("vmcp host %q: error = %v, want one with %q", tc.Args, err, tc.WantError)
		}
		if out.Len() != 0 {
			t.Errorf("vmcp host %q printed a result: %s", tc.Args, out.String())
		}
	}
}
