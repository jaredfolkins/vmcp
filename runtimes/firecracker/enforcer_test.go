//go:build linux

package firecracker

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"testing"

	"github.com/tailscale/hujson"
)

var nftElementsConfig = flag.String("vmcp-nft-elements-config", "testdata/nft-elements.hujson", "HuJSON file with nft listings")

// TestSetElementsReadsEveryProtocolForm proves that the enforcer reads the
// element keys of the guest_allow set whether nft prints the protocol as a
// name or as a number. With a wrong key, every sweep treated the allowed
// traffic of live machines as stray and tried to delete it.
func TestSetElementsReadsEveryProtocolForm(t *testing.T) {
	raw, err := os.ReadFile(*nftElementsConfig)
	if err != nil {
		t.Fatal(err)
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		Listings []struct {
			Name    string          `json:"name"`
			Listing json.RawMessage `json:"listing"`
			Want    []string        `json:"want"`
		} `json:"listings"`
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(in.Listings) == 0 {
		t.Fatalf("nft elements input: %v", err)
	}
	for _, tc := range in.Listings {
		t.Run(tc.Name, func(t *testing.T) {
			var got []string
			for _, el := range setElements(tc.Listing) {
				got = append(got, el.key())
			}
			if !slices.Equal(got, tc.Want) {
				t.Errorf("element keys = %q, want %q", got, tc.Want)
			}
		})
	}
}
