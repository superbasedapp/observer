package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// signFeedWire mints a signed feed envelope whose digest and signature cover the
// RAW rows bytes, so a test can include a row field this build does not model (a
// stand-in for a future field). rowsJSON must already be compact and hold a
// single row so that pricingfeed.canonicalRawRows(rowsJSON) == rowsJSON (each
// element compacted, then sorted — a no-op for one compact element), which is
// what makes the manually computed digest and SigningMessage agree with Verify.
func signFeedWire(t *testing.T, priv ed25519.PrivateKey, keyID string, feedVersion int64, rowsJSON string) []byte {
	t.Helper()
	canonical := []byte(rowsJSON)
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, pricingfeed.SigningMessage(feedVersion, canonical))
	env := fmt.Sprintf(`{"schema_version":%d,"feed_version":%d,"generated_at":"2026-09-11T00:00:00Z","rows":%s,"digest":%q,"signature":%q,"key_id":%q}`,
		pricingfeed.SupportedSchemaVersion, feedVersion, rowsJSON, digest,
		base64.StdEncoding.EncodeToString(sig), keyID)
	return []byte(env)
}

// A feed envelope carrying a field this build does not model must survive
// persist -> reload -> re-verify without a digest mismatch (N1 / P2-0). The
// CONTROL half proves the fix is load-bearing: the typed persist path (no raw
// bytes) drops the unknown field, so the reloaded envelope FAILS re-verify.
func TestPricingFeedCacheRawEnvelopeSurvivesUnknownFieldAcrossReload(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "test-feed-key"
	keys, err := pricingfeed.NewKeySet(map[string]string{keyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	rows := `[{"model":"m","input_per_mtok":1,"future_unknown_field":{"x":1},"grade":"verified"}]`
	rawEnv := signFeedWire(t, priv, keyID, 9, rows)

	var env pricingfeed.Envelope
	if uerr := json.Unmarshal(rawEnv, &env); uerr != nil {
		t.Fatalf("unmarshal envelope: %v", uerr)
	}
	if verr := pricingfeed.Verify(env, keys); verr != nil {
		t.Fatalf("received envelope must verify: %v", verr)
	}

	// CONTROL: the typed path loses the unknown field, so the reload cannot
	// re-verify. If this ever passes, the raw-bytes fix proves nothing.
	control, _ := newTestStore(t)
	if serr := control.SavePricingFeed(ctx, env, "verified"); serr != nil {
		t.Fatalf("typed save: %v", serr)
	}
	frozen, lerr := control.LoadPricingFeed(ctx)
	if lerr != nil {
		t.Fatalf("load typed: %v", lerr)
	}
	if verr := pricingfeed.Verify(frozen.Envelope, keys); verr == nil {
		t.Fatal("typed persist must LOSE the unknown field and fail re-verify — the freeze P2-0 fixes")
	}

	// THE FIX: verbatim persist keeps the unknown field alive in rawRows.
	s, _ := newTestStore(t)
	if serr := s.SavePricingFeedRaw(ctx, env, rawEnv, "verified"); serr != nil {
		t.Fatalf("SavePricingFeedRaw: %v", serr)
	}
	got, lerr := s.LoadPricingFeed(ctx)
	if lerr != nil {
		t.Fatalf("LoadPricingFeed: %v", lerr)
	}
	if !got.Have || got.Version != 9 {
		t.Fatalf("cache = %+v, want the applied v9 feed", got)
	}
	if verr := pricingfeed.Verify(got.Envelope, keys); verr != nil {
		t.Fatalf("reloaded envelope must still verify (N1 no-freeze): %v", verr)
	}
	if len(got.Envelope.Rows) != 1 || got.Envelope.Rows[0].Model != "m" ||
		got.Envelope.Rows[0].InputPerMTok == nil || *got.Envelope.Rows[0].InputPerMTok != 1 {
		t.Fatalf("known fields did not load: %+v", got.Envelope.Rows)
	}
}

// A body_json written in the pre-P2-0 shape (a plain typed marshal of the
// envelope, no verbatim bytes) must still load via the fallback path, so an
// in-place upgrade does not wipe the cache on first boot.
func TestPricingFeedCacheLoadsTypedFallbackBlob(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   4,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		KeyID:         pricingfeed.PricingFeedKeyIDV1,
		Digest:        "d",
		Signature:     "s",
		Rows: []pricingfeed.Row{{
			PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: orgcontract.Rate(2), Source: "list"},
		}},
	}
	blob, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal typed envelope: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE pricing_feed_cache SET body_json = ?, version = 4, key_id = ?, digest = 'd', fetched_at = '2026-09-11T00:00:00Z', state = 'verified' WHERE id = 1`,
		string(blob), pricingfeed.PricingFeedKeyIDV1); err != nil {
		t.Fatalf("seed typed blob: %v", err)
	}
	got, err := s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed: %v", err)
	}
	if !got.Have || got.Version != 4 {
		t.Fatalf("typed fallback blob = %+v, want v4", got)
	}
	if len(got.Envelope.Rows) != 1 || got.Envelope.Rows[0].Model != "m" ||
		got.Envelope.Rows[0].InputPerMTok == nil || *got.Envelope.Rows[0].InputPerMTok != 2 {
		t.Fatalf("typed fallback rows did not load: %+v", got.Envelope.Rows)
	}
}

// A fresh node has the seeded row and NO feed; a verified envelope round-trips
// with its provenance (version, key id, digest, state) and its rows.
func TestPricingFeedCacheRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	got, err := s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed on a fresh node: %v", err)
	}
	if got.Have {
		t.Fatalf("a fresh node reports a stored feed: %+v", got)
	}

	env := pricingfeed.Envelope{
		SchemaVersion: pricingfeed.SupportedSchemaVersion,
		FeedVersion:   7,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		KeyID:         pricingfeed.PricingFeedKeyIDV1,
		Digest:        "sha-digest-abc",
		Signature:     "c2ln",
		Rows: []pricingfeed.Row{{
			PricingPolicyRow: orgcontract.PricingPolicyRow{
				Model:         "claude-opus-4-8",
				InputPerMTok:  orgcontract.Rate(4),
				OutputPerMTok: orgcontract.Rate(20),
				Source:        "list",
			},
			Grade: "verified",
			Economics: &pricingfeed.Economics{
				CacheMode:        pricingfeed.CacheModeExplicit,
				ReasoningBilling: pricingfeed.ReasoningBillingOutputRate,
			},
		}},
	}
	if err := s.SavePricingFeed(ctx, env, "verified"); err != nil {
		t.Fatalf("SavePricingFeed: %v", err)
	}

	got, err = s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed: %v", err)
	}
	if !got.Have || got.Version != 7 || got.State != "verified" {
		t.Fatalf("cache = %+v, want the applied v7 feed", got)
	}
	if got.KeyID != pricingfeed.PricingFeedKeyIDV1 || got.Digest != "sha-digest-abc" {
		t.Errorf("provenance = key %q digest %q, want the stored values", got.KeyID, got.Digest)
	}
	if len(got.Envelope.Rows) != 1 || got.Envelope.Rows[0].InputPerMTok == nil || *got.Envelope.Rows[0].InputPerMTok != 4 {
		t.Fatalf("rows = %+v, want the stored rate", got.Envelope.Rows)
	}
	if got.Envelope.Rows[0].Economics == nil || got.Envelope.Rows[0].Economics.CacheMode != pricingfeed.CacheModeExplicit {
		t.Errorf("economics did not round-trip: %+v", got.Envelope.Rows[0].Economics)
	}
	if got.FetchedAt.IsZero() {
		t.Error("fetched_at did not round-trip")
	}
}

// The table is a singleton: a second save UPDATEs in place rather than adding a
// row, so a node always holds exactly one applied feed.
func TestPricingFeedCacheStaysASingleton(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	for _, v := range []int64{1, 2, 3} {
		env := pricingfeed.Envelope{
			SchemaVersion: pricingfeed.SupportedSchemaVersion,
			FeedVersion:   v,
			KeyID:         pricingfeed.PricingFeedKeyIDV1,
			Digest:        "d",
			Signature:     "s",
			Rows:          []pricingfeed.Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: orgcontract.Rate(1)}}},
		}
		if err := s.SavePricingFeed(ctx, env, "verified"); err != nil {
			t.Fatalf("SavePricingFeed v%d: %v", v, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pricing_feed_cache`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("pricing_feed_cache holds %d rows, want exactly 1", n)
	}
	got, err := s.LoadPricingFeed(ctx)
	if err != nil {
		t.Fatalf("LoadPricingFeed: %v", err)
	}
	if got.Version != 3 {
		t.Fatalf("version = %d, want the last-written 3", got.Version)
	}
}

// A corrupt body is reported as an error WITH an empty cache, so a caller
// degrades to the seed table rather than mistaking a bad blob for a node that
// never synced.
func TestPricingFeedCacheDegradesOnACorruptBody(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`UPDATE pricing_feed_cache SET body_json = '{not json', version = 5 WHERE id = 1`); err != nil {
		t.Fatalf("seed corrupt body: %v", err)
	}
	got, err := s.LoadPricingFeed(ctx)
	if err == nil {
		t.Fatal("a corrupt body must be reported as an error")
	}
	if got.Have {
		t.Fatalf("a corrupt body must degrade to an empty cache, got %+v", got)
	}
}
