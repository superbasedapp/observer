package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// TestRun_RefusesUnverifiableBundle is the gate this generator exists to
// enforce. An unsigned body is exactly what a compromised or merely careless
// publish produces, and it must never become a shipped price table - so the
// failure is a refusal to write, not a warning beside a written file.
func TestRun_RefusesUnverifiableBundle(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundle := filepath.Join(dir, "unsigned.json")
	body, err := json.Marshal(pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   1,
		Rows:          []pricingfeed.Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(bundle, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := filepath.Join(dir, "snapshot.json")

	err = run(bundle, out, false)
	if err == nil {
		t.Fatal("an unsigned bundle was accepted")
	}
	if !strings.Contains(err.Error(), "unverifiable") {
		t.Errorf("error should name the refusal reason, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a snapshot was written despite the refusal")
	}
}

func TestRun_RequiresBundle(t *testing.T) {
	t.Parallel()
	if err := run("", "irrelevant", false); err == nil {
		t.Fatal("an empty -bundle was accepted")
	}
}

// TestRunWith_SignedBundleRoundTrip proves the SUCCESS path end to end with a
// throwaway key: a signed envelope becomes a snapshot the cost package's
// vocabulary can read, and -check then agrees with the file it just wrote.
//
// The real signing key is operator-held and is not in this tree, which is why
// runWith takes the key set. Without this the suite could only ever prove the
// refusal, and "it always refuses" is not evidence that it ever works.
func TestRunWith_SignedBundleRoundTrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "test-key"
	keys, err := pricingfeed.NewKeySet(map[string]string{keyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	in, out := 4.0, 20.0
	minCache := int64(512)
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   7,
		GeneratedAt:   "2026-09-22T19:00:00Z",
		KeyID:         keyID,
		Rows: []pricingfeed.Row{{
			PricingPolicyRow: orgcontract.PricingPolicyRow{
				Model: "claude-opus-5-5", InputPerMTok: &in, OutputPerMTok: &out,
			},
			Grade:     "operator_supplied",
			Economics: &pricingfeed.Economics{MinCacheableTokens: &minCache},
		}},
	}
	if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	dir := t.TempDir()
	bundle := filepath.Join(dir, "observer-pricing-v7.json")
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(bundle, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	snapshot := filepath.Join(dir, "pricing_snapshot.json")

	if err := runWith(bundle, snapshot, false, keys); err != nil {
		t.Fatalf("generate: %v", err)
	}

	written, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var doc snapshotDoc
	if err := json.Unmarshal(written, &doc); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != snapshotSchemaVersion {
		t.Errorf("schema_version = %d, want %d", doc.SchemaVersion, snapshotSchemaVersion)
	}
	if doc.FeedVersion != 7 || doc.Digest != env.Digest || doc.KeyID != keyID {
		t.Errorf("provenance not carried across: %+v", doc)
	}
	if doc.Source != "observer-pricing-v7.json" {
		t.Errorf("Source = %q, want the bundle's base name", doc.Source)
	}
	if len(doc.Rows) != 1 || doc.Rows[0].Model != "claude-opus-5-5" {
		t.Fatalf("rows = %+v", doc.Rows)
	}
	if doc.Rows[0].MinCacheableTokens == nil || *doc.Rows[0].MinCacheableTokens != 512 {
		t.Error("min-cacheable did not survive the projection")
	}

	// -check must AGREE with the file the generator just wrote. A drift gate
	// that disagrees with its own generator fails every build for nothing.
	if err := runWith(bundle, snapshot, true, keys); err != nil {
		t.Errorf("-check disagreed with the file it just generated: %v", err)
	}

	// ...and must DISAGREE once the file is touched by hand, which is the
	// whole point of committing a generated artifact.
	if err := os.WriteFile(snapshot, append(written, ' '), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := runWith(bundle, snapshot, true, keys); err == nil {
		t.Error("-check accepted a hand-edited snapshot")
	} else if !strings.Contains(err.Error(), "STALE") {
		t.Errorf("-check error should name the staleness, got: %v", err)
	}
}

// TestRowsOf pins the projection: a straight field copy, pointers re-boxed so
// the artifact never aliases the caller's envelope, nil preserved as nil, a
// quoted zero preserved as a quoted zero, and a deterministic model order so
// the generated file is byte-stable.
func TestRowsOf(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	i := func(v int64) *int64 { return &v }

	zero := 0.0
	in := []pricingfeed.Row{
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "zebra", InputPerMTok: f(1), OutputPerMTok: f(2)}},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "flat", InputPerMTok: f(1), OutputPerMTok: f(2), LongContextThreshold: i(0)}},
		{
			PricingPolicyRow: orgcontract.PricingPolicyRow{
				Model:                "alpha",
				InputPerMTok:         f(4),
				OutputPerMTok:        f(20),
				CacheReadPerMTok:     &zero, // QUOTED FREE, not "unknown"
				LongContextThreshold: i(272_000),
			},
			Economics: &pricingfeed.Economics{MinCacheableTokens: i(512)},
		},
	}
	out := rowsOf(in)

	if len(out) != 3 {
		t.Fatalf("rowsOf returned %d rows, want 3", len(out))
	}
	if out[0].Model != "alpha" || out[1].Model != "flat" || out[2].Model != "zebra" {
		t.Fatalf("rows are not sorted by model: %v, %v, %v", out[0].Model, out[1].Model, out[2].Model)
	}
	a := out[0]
	if a.CacheReadPerMTok == nil || *a.CacheReadPerMTok != 0 {
		t.Error("a quoted zero must survive as a quoted zero, not collapse to nil")
	}
	if a.CacheWritePerMTok != nil {
		t.Error("an unquoted rate must stay nil so the hand literal keeps its value")
	}
	if a.LongContextThreshold == nil || *a.LongContextThreshold != 272_000 {
		t.Errorf("LongContextThreshold = %v, want 272000", a.LongContextThreshold)
	}
	// Presence (server migration 175 / pg 0041): a feed row that OMITS the
	// threshold does not know the tier, so it projects as absent and the
	// literal's tier stays in force (finding 1); a row that STATES 0 quotes
	// "flat" and is carried across as a stated 0.
	if out[2].LongContextThreshold != nil {
		t.Errorf("an absent feed threshold must project as absent, got %v", *out[2].LongContextThreshold)
	}
	if out[1].LongContextThreshold == nil || *out[1].LongContextThreshold != 0 {
		t.Errorf("a stated 0 feed threshold must project as a stated 0, got %v", out[1].LongContextThreshold)
	}
	if a.MinCacheableTokens == nil || *a.MinCacheableTokens != 512 {
		t.Error("min-cacheable must be lifted out of Economics onto the row")
	}
	if a.CacheReadPerMTok == in[1].CacheReadPerMTok {
		t.Error("pointers must be re-boxed, not aliased to the envelope's")
	}
	// Everything else in Economics is display-only today and is deliberately
	// NOT copied: carrying a fact nothing reads is noise in a generated diff.
	if out[2].MinCacheableTokens != nil {
		t.Error("a row with no Economics must carry no min-cacheable")
	}
}

// TestRowsOf_CarriesPeakAndFast pins the rest of finding 1's projection: the
// feed's peak variant and Economics.FastMultiplier reach the snapshot (deep
// copied), and their absence stays absent.
func TestRowsOf_CarriesPeakAndFast(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	peak := &orgcontract.PeakRates{
		RateSet:  orgcontract.RateSet{Input: 1.32, Output: 3.96, CacheRead: 0.044},
		Schedule: orgcontract.PeakSchedule{Windows: []orgcontract.PeakWindow{{Days: []time.Weekday{time.Monday}, StartUTC: "01:00", EndUTC: "04:00"}}},
	}
	out := rowsOf([]pricingfeed.Row{
		{
			PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "a", InputPerMTok: f(0.66), OutputPerMTok: f(1.98), Peak: peak},
			Economics:        &pricingfeed.Economics{FastMultiplier: f(2)},
		},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "b", InputPerMTok: f(1), OutputPerMTok: f(2)}},
	})
	a, b := out[0], out[1]
	if a.Peak == nil || a.Peak.Input != 1.32 || len(a.Peak.Schedule.Windows) != 1 {
		t.Fatalf("peak not carried: %+v", a.Peak)
	}
	if a.Peak == peak || &a.Peak.Schedule.Windows[0] == &peak.Schedule.Windows[0] {
		t.Error("peak must be deep-copied, not aliased")
	}
	if a.FastMultiplier == nil || *a.FastMultiplier != 2 {
		t.Errorf("FastMultiplier = %v, want 2 lifted out of Economics", a.FastMultiplier)
	}
	if b.Peak != nil || b.FastMultiplier != nil {
		t.Errorf("absent peak/fast must stay absent: %+v", b)
	}
}

// signedBundleFile writes a signed bundle at the given version to dir.
func signedBundleFile(t *testing.T, dir string, priv ed25519.PrivateKey, keyID string, version int64, input float64) string {
	t.Helper()
	out := input * 5
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   version,
		GeneratedAt:   "2026-09-22T19:00:00Z",
		KeyID:         keyID,
		Rows: []pricingfeed.Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{
			Model: "claude-opus-5-5", InputPerMTok: &input, OutputPerMTok: &out, EffectiveFrom: "2026-09-22T19:00:00Z",
		}}},
	}
	var err error
	if env.Digest, err = pricingfeed.Digest(env.Rows); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if env.Signature, err = pricingfeed.Sign(priv, env); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "observer-pricing-v"+strconv.FormatInt(version, 10)+"-"+strconv.FormatFloat(input, 'f', -1, 64)+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestRunWith_RefusesReplay pins review finding 2 in both directions: a
// signed bundle older than the compiled floor or than the committed snapshot
// is refused and writes nothing; the same bundle again (byte-identical
// regeneration) and a newer one are accepted.
func TestRunWith_RefusesReplay(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "test-key"
	keys, err := pricingfeed.NewKeySet(map[string]string{keyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "pricing_snapshot.json")

	// Below the compiled floor: refused even with no committed snapshot.
	old := signedBundleFile(t, dir, priv, keyID, snapshotMinFeedVersion-1, 4)
	if err := runWith(old, snapshot, false, keys); err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("a bundle below the floor was not refused: %v", err)
	}
	if _, statErr := os.Stat(snapshot); statErr == nil {
		t.Fatal("a refused bundle wrote a snapshot")
	}

	// A first generation at v5.
	v5 := signedBundleFile(t, dir, priv, keyID, 5, 4)
	if err := runWith(v5, snapshot, false, keys); err != nil {
		t.Fatalf("v5 generate: %v", err)
	}
	written, _ := os.ReadFile(snapshot)

	// Regenerating the SAME bundle is accepted (and -check agrees).
	if err := runWith(v5, snapshot, false, keys); err != nil {
		t.Errorf("byte-identical regeneration refused: %v", err)
	}
	if err := runWith(v5, snapshot, true, keys); err != nil {
		t.Errorf("-check against the same bundle refused: %v", err)
	}

	// An OLDER, validly signed bundle is refused and leaves the file intact.
	v4 := signedBundleFile(t, dir, priv, keyID, 4, 5)
	if err := runWith(v4, snapshot, false, keys); err == nil || !strings.Contains(err.Error(), "only moves forward") {
		t.Fatalf("an older bundle was not refused: %v", err)
	}
	// Same version, different content: refused.
	v5b := signedBundleFile(t, dir, priv, keyID, 5, 6)
	if err := runWith(v5b, snapshot, false, keys); err == nil || !strings.Contains(err.Error(), "same version") {
		t.Fatalf("a same-version different-digest bundle was not refused: %v", err)
	}
	if after, _ := os.ReadFile(snapshot); string(after) != string(written) {
		t.Fatal("a refused bundle modified the committed snapshot")
	}

	// A NEWER bundle is accepted.
	v6 := signedBundleFile(t, dir, priv, keyID, 6, 3)
	if err := runWith(v6, snapshot, false, keys); err != nil {
		t.Fatalf("a newer bundle was refused: %v", err)
	}
	var doc snapshotDoc
	raw, _ := os.ReadFile(snapshot)
	if err := json.Unmarshal(raw, &doc); err != nil || doc.FeedVersion != 6 {
		t.Fatalf("snapshot after v6 = %+v (err %v), want feed_version 6", doc, err)
	}
}
