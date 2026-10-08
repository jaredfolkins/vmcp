//go:build linux

package firecracker

import (
	"flag"
	"net/url"
	"testing"
)

var locationConfig = flag.String("vmcp-location-config", "testdata/location.hujson", "HuJSON file with upstream Location cases")

// TestRewriteLocation proves that an upstream redirect to its own origin,
// such as a registry upload session, is rewritten to the guest-facing
// broker address, and that other locations are left alone. Without it, a
// guest followed an upload Location to a host that it cannot reach.
func TestRewriteLocation(t *testing.T) {
	var in struct {
		Target    string `json:"target"`
		GuestBase string `json:"guest_base"`
		Cases     []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
			Want     string `json:"want"`
		} `json:"cases"`
	}
	readHuJSON(t, *locationConfig, &in)
	target, err := url.Parse(in.Target)
	if err != nil || len(in.Cases) == 0 {
		t.Fatalf("location input: %v", err)
	}
	for _, tc := range in.Cases {
		if got := rewriteLocation(tc.Location, target, in.GuestBase); got != tc.Want {
			t.Errorf("%s: rewriteLocation(%q) = %q, want %q", tc.Name, tc.Location, got, tc.Want)
		}
	}
}
