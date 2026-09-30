package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// rehearsalKeyID names the throwaway key a rehearsal bundle is signed with.
// No build accepts it (pricingfeed.CompiledKeySet never lists it), so a
// snapshot generated here can never verify as a real feed anywhere else.
const rehearsalKeyID = "rehearsal-throwaway-not-a-feed-key"

// TestRehearsalSnapshot is a TEST-ONLY bridge for rehearsing a Tokenomics
// database change BEFORE it is published: it turns an UNSIGNED envelope that
// model-pricing/cmd/observerpublish wrote against a throwaway rehearsal
// database into a snapshot, so the cost package's tests can be run against the
// prices that database would publish.
//
// The production path stays exactly as strict as before: `run` verifies only
// against the compiled vendor keys, and there is still no flag, env var or
// code path in the generator binary that accepts an unsigned bundle. This test
// signs the rehearsal envelope with a key minted here and verifies it through
// runWith - the same seam TestRunWith_SignedBundleRoundTrip uses - so the
// digest check, the row validation and the projection are the real ones.
//
// It runs only when both variables are set, and writes only to the -out path
// given (never the committed snapshot unless that is what the caller names):
//
//	PRICING_SNAPSHOTGEN_REHEARSAL_BUNDLE=<unsigned observer-pricing-vN.json> \
//	PRICING_SNAPSHOTGEN_REHEARSAL_OUT=<path to write> \
//	  go test ./tools/pricing-snapshotgen -run TestRehearsalSnapshot -count=1
func TestRehearsalSnapshot(t *testing.T) {
	in := os.Getenv("PRICING_SNAPSHOTGEN_REHEARSAL_BUNDLE")
	out := os.Getenv("PRICING_SNAPSHOTGEN_REHEARSAL_OUT")
	if in == "" || out == "" {
		t.Skip("set PRICING_SNAPSHOTGEN_REHEARSAL_BUNDLE and PRICING_SNAPSHOTGEN_REHEARSAL_OUT to generate a rehearsal snapshot")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatalf("read %s: %v", in, err)
	}
	var env pricingfeed.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode %s: %v", in, err)
	}
	if env.Signature != "" {
		t.Fatalf("%s is already signed; generate a real snapshot with `make pricing-snapshot BUNDLE=%s`", in, in)
	}
	// A hand-assembled rehearsal envelope (e.g. a published feed with a
	// migration's curated rows substituted in) may leave the digest blank; it
	// is then computed here. A digest that IS present is kept, so runWith's
	// digest check still proves an observerpublish body is self-consistent.
	if env.Digest == "" {
		if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
			t.Fatalf("Digest: %v", err)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env.KeyID = rehearsalKeyID
	if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The bundle keeps its own file name: runWith records it as the snapshot's
	// `source`, which is how a reader tells a rehearsal snapshot from a real one.
	signed := filepath.Join(t.TempDir(), "REHEARSAL-UNSIGNED-"+filepath.Base(in))
	if err := os.WriteFile(signed, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	keys, err := pricingfeed.NewKeySet(map[string]string{rehearsalKeyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	if err := runWith(signed, out, false, keys); err != nil {
		t.Fatalf("runWith: %v", err)
	}
}
