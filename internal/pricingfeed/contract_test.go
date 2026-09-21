package pricingfeed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// testKeyID is the id the throwaway test keypair signs under. Tests NEVER embed
// a production private key; they mint one per run with crypto/ed25519.
const testKeyID = "test-feed-key"

func rate(v float64) *float64 { return &v }

// newSignedEnvelope builds a fully signed, verifiable envelope around rows plus
// the matching single-key KeySet, minting a throwaway keypair.
func newSignedEnvelope(t *testing.T, feedVersion int64, rows []Row) (Envelope, KeySet) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keys, err := NewKeySet(map[string]string{testKeyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	digest, err := Digest(rows)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	env := Envelope{
		SchemaVersion: SupportedSchemaVersion,
		FeedVersion:   feedVersion,
		GeneratedAt:   "2026-09-11T00:00:00Z",
		Rows:          rows,
		Digest:        digest,
		KeyID:         testKeyID,
	}
	sig, err := Sign(priv, env)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	env.Signature = sig
	return env, keys
}

func sampleRows() []Row {
	return []Row{
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "claude-opus-5", InputPerMTok: rate(15), OutputPerMTok: rate(75)}, Grade: "verified"},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "claude-haiku-5", InputPerMTok: rate(1), OutputPerMTok: rate(5), CacheReadPerMTok: rate(0)}, Grade: "observed"},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		feedVersion int64
		rows        []Row
	}{
		{"typical", 7, sampleRows()},
		{"empty rows", 1, nil},
		{"single row", 42, []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}}}},
		{"quoted-free rate", 3, []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "free-model", InputPerMTok: rate(0), OutputPerMTok: rate(0)}, Grade: "verified"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, keys := newSignedEnvelope(t, tt.feedVersion, tt.rows)
			if err := Verify(env, keys); err != nil {
				t.Fatalf("Verify on a freshly signed envelope: %v", err)
			}
		})
	}
}

func TestVerifyErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(env *Envelope, keys *KeySet)
		wantErr error
	}{
		{
			name:    "unsupported schema",
			mutate:  func(env *Envelope, _ *KeySet) { env.SchemaVersion = 999 },
			wantErr: ErrUnsupportedSchema,
		},
		{
			name:    "non-positive feed version",
			mutate:  func(env *Envelope, _ *KeySet) { env.FeedVersion = 0 },
			wantErr: ErrInvalidRows,
		},
		{
			name: "empty model id",
			mutate: func(env *Envelope, _ *KeySet) {
				env.Rows = []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "  "}}}
			},
			wantErr: ErrInvalidRows,
		},
		{
			name:    "digest mismatch",
			mutate:  func(env *Envelope, _ *KeySet) { env.Digest = "deadbeef" },
			wantErr: ErrDigestMismatch,
		},
		{
			name:    "unsigned",
			mutate:  func(env *Envelope, _ *KeySet) { env.Signature = "" },
			wantErr: ErrUnsigned,
		},
		{
			name:    "unknown key id",
			mutate:  func(env *Envelope, _ *KeySet) { env.KeyID = "nope" },
			wantErr: ErrUnknownKey,
		},
		{
			name:    "signature not base64",
			mutate:  func(env *Envelope, _ *KeySet) { env.Signature = "!!!not base64!!!" },
			wantErr: ErrBadSignature,
		},
		{
			name: "signature over wrong bytes",
			mutate: func(env *Envelope, _ *KeySet) {
				// A structurally valid but wrong 64-byte signature.
				env.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "tampered row after signing",
			mutate: func(env *Envelope, _ *KeySet) {
				// Change a rate AND its digest so the digest check passes and
				// the signature check is the one that trips.
				env.Rows[0].InputPerMTok = rate(999)
				d, _ := Digest(env.Rows)
				env.Digest = d
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "verified with a different key",
			mutate: func(_ *Envelope, keys *KeySet) {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				ks, _ := NewKeySet(map[string]string{testKeyID: hex.EncodeToString(pub)})
				*keys = ks
			},
			wantErr: ErrBadSignature,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, keys := newSignedEnvelope(t, 5, sampleRows())
			tt.mutate(&env, &keys)
			err := Verify(env, keys)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalDeterministicUnderShuffle(t *testing.T) {
	rows := sampleRows()
	rows = append(rows,
		Row{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "zeta"}},
		Row{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "alpha"}},
		Row{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "mid"}},
	)
	want, err := CanonicalRows(rows)
	if err != nil {
		t.Fatalf("CanonicalRows: %v", err)
	}
	r := mrand.New(mrand.NewSource(1))
	for i := 0; i < 50; i++ {
		shuffled := make([]Row, len(rows))
		copy(shuffled, rows)
		r.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got, err := CanonicalRows(shuffled)
		if err != nil {
			t.Fatalf("CanonicalRows(shuffled): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shuffle %d produced different canonical bytes:\n got %s\nwant %s", i, got, want)
		}
	}
}

func TestCanonicalRowsDoesNotMutateInput(t *testing.T) {
	rows := []Row{
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "zeta"}},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "alpha"}},
	}
	if _, err := CanonicalRows(rows); err != nil {
		t.Fatalf("CanonicalRows: %v", err)
	}
	if rows[0].Model != "zeta" || rows[1].Model != "alpha" {
		t.Fatalf("CanonicalRows mutated caller order: %+v", rows)
	}
}

// TestNilVsQuotedZeroCanonicaliseDistinctly is the migration-135 invariant at
// the feed boundary: a rate that is NOT quoted (nil) and a rate quoted FREE
// (&0.0) must sign and digest as DIFFERENT documents.
func TestNilVsQuotedZeroCanonicaliseDistinctly(t *testing.T) {
	nilRow := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}}}                         // InputPerMTok nil
	freeRow := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: rate(0)}}} // quoted free

	nilBytes, err := CanonicalRows(nilRow)
	if err != nil {
		t.Fatalf("CanonicalRows(nil): %v", err)
	}
	freeBytes, err := CanonicalRows(freeRow)
	if err != nil {
		t.Fatalf("CanonicalRows(free): %v", err)
	}
	if bytes.Equal(nilBytes, freeBytes) {
		t.Fatalf("nil and quoted-zero canonicalised to the same bytes: %s", nilBytes)
	}
	// And a nil rate must be ABSENT from the JSON, a free one present as 0.
	if bytes.Contains(nilBytes, []byte("input_per_mtok")) {
		t.Fatalf("a nil rate should be omitted, got %s", nilBytes)
	}
	if !bytes.Contains(freeBytes, []byte(`"input_per_mtok":0`)) {
		t.Fatalf("a quoted-free rate should render as 0, got %s", freeBytes)
	}

	// The distinction must survive a sign/verify round trip on each.
	for _, rows := range [][]Row{nilRow, freeRow} {
		env, keys := newSignedEnvelope(t, 1, rows)
		if err := Verify(env, keys); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

func TestSigningMessageBindsDomainAndVersion(t *testing.T) {
	canonical := []byte(`[]`)
	msg := SigningMessage(12, canonical)
	want := append([]byte(FeedSigningDomain), 0)
	want = append(want, []byte("12")...)
	want = append(want, 0)
	want = append(want, canonical...)
	if !bytes.Equal(msg, want) {
		t.Fatalf("SigningMessage = %q, want %q", msg, want)
	}
	// A different feed version must change the bytes (replay defence).
	if bytes.Equal(msg, SigningMessage(13, canonical)) {
		t.Fatalf("SigningMessage did not bind the feed version")
	}
}

func i64(v int64) *int64 { return &v }
func boolp(v bool) *bool { return &v }

func TestEconomicsEnumValidation(t *testing.T) {
	tests := []struct {
		name string
		econ *Economics
		ok   bool
	}{
		{"nil is fine", nil, true},
		{"empty strings are unknown", &Economics{}, true},
		{"all valid enums", &Economics{
			CacheMode:         CacheModeExplicit,
			CacheWriteBilling: CacheWriteBillingPerWrite,
			ReasoningBilling:  ReasoningBillingSeparateRate,
			ReasoningPerMTok:  rate(3),
		}, true},
		{"implicit + included", &Economics{CacheMode: CacheModeImplicit, CacheWriteBilling: CacheWriteBillingIncluded, ReasoningBilling: ReasoningBillingOutputRate}, true},
		{"none across the board", &Economics{CacheMode: CacheModeNone, CacheWriteBilling: CacheWriteBillingNone, ReasoningBilling: ReasoningBillingNone}, true},
		{"full pointer fields set", &Economics{
			CacheTTLSeconds:     i64(300),
			CacheTTL1HAvailable: boolp(true),
			MinCacheableTokens:  i64(1024),
			ReasoningSupported:  boolp(true),
			ContextWindowTokens: i64(200000),
			FastMultiplier:      rate(1.5),
			Notes:               "published list price, USD",
		}, true},
		{"bad cache_mode", &Economics{CacheMode: "magic"}, false},
		{"bad cache_write_billing", &Economics{CacheWriteBilling: "sometimes"}, false},
		{"bad reasoning_billing", &Economics{ReasoningBilling: "maybe"}, false},
		{"notes with a control char", &Economics{Notes: "line\x07bell"}, false},
		{"notes with ESC/ANSI", &Economics{Notes: "clean\x1b[31mred"}, false},
		{"notes with a bidi override", &Economics{Notes: "a‮b"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}, Economics: tt.econ}}
			env, keys := newSignedEnvelope(t, 1, rows)
			err := Verify(env, keys)
			if tt.ok && err != nil {
				t.Fatalf("Verify = %v, want ok", err)
			}
			if !tt.ok && !errors.Is(err, ErrInvalidRows) {
				t.Fatalf("Verify = %v, want ErrInvalidRows", err)
			}
		})
	}
}

// TestEconomicsCanonicalPresentVsAbsent proves Economics is covered by the
// canonical bytes (so the signature protects it) and that present-vs-absent and
// nil-vs-set pointer fields canonicalise distinctly.
func TestEconomicsCanonicalPresentVsAbsent(t *testing.T) {
	absent := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}}}
	present := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}, Economics: &Economics{CacheMode: CacheModeExplicit}}}
	emptyEcon := []Row{{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "m"}, Economics: &Economics{}}}

	ab, err := CanonicalRows(absent)
	if err != nil {
		t.Fatalf("CanonicalRows(absent): %v", err)
	}
	pb, err := CanonicalRows(present)
	if err != nil {
		t.Fatalf("CanonicalRows(present): %v", err)
	}
	eb, err := CanonicalRows(emptyEcon)
	if err != nil {
		t.Fatalf("CanonicalRows(empty econ): %v", err)
	}
	if bytes.Equal(ab, pb) {
		t.Fatalf("present economics did not change the canonical bytes")
	}
	// A nil Economics omits the key; a non-nil-but-empty one renders {}.
	if bytes.Contains(ab, []byte("economics")) {
		t.Fatalf("nil economics should be omitted, got %s", ab)
	}
	if !bytes.Contains(eb, []byte(`"economics":{}`)) {
		t.Fatalf("empty economics should render {}, got %s", eb)
	}

	// Determinism under shuffle with economics present on some rows.
	rows := []Row{
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "b"}, Economics: &Economics{CacheMode: CacheModeImplicit, ContextWindowTokens: i64(128000)}},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "a"}},
		{PricingPolicyRow: orgcontract.PricingPolicyRow{Model: "c"}, Economics: &Economics{FastMultiplier: rate(2)}},
	}
	want, err := CanonicalRows(rows)
	if err != nil {
		t.Fatalf("CanonicalRows: %v", err)
	}
	r := mrand.New(mrand.NewSource(7))
	for i := 0; i < 30; i++ {
		shuffled := make([]Row, len(rows))
		copy(shuffled, rows)
		r.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got, err := CanonicalRows(shuffled)
		if err != nil {
			t.Fatalf("CanonicalRows(shuffled): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("economics canonical bytes not deterministic under shuffle %d", i)
		}
	}

	// The present-economics envelope round-trips.
	env, keys := newSignedEnvelope(t, 1, present)
	if err := Verify(env, keys); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignRejectsBadPrivateKey(t *testing.T) {
	if _, err := Sign(ed25519.PrivateKey{1, 2, 3}, Envelope{}); err == nil {
		t.Fatal("Sign accepted a short private key")
	}
}

// TestVerifyOverReceivedBytes_NoFreezeForKnownEnvelopes is the HARD
// fleet-no-freeze compatibility proof (docs/plans/
// peak-off-peak-pricing-plan-2026-09-20.md §3.4/§R M1+M2): for an envelope
// with no unknown fields, verify-over-received-bytes must be byte-identical
// to the pre-existing verify-by-typed-remarshal path, so every already-
// signed, currently-published feed still verifies on an upgraded consumer.
//
// It signs a representative envelope, round-trips it through
// json.Marshal/json.Unmarshal (exactly what a real HTTP/bundle consumer
// does — see internal/pricingfeed/client, internal/orgserver/pricingfeed's
// bundle.go and poller.go, all of which decode via encoding/json and so
// transparently populate Envelope.rawRows through UnmarshalJSON with ZERO
// code change), and asserts:
//  1. Verify still passes against the original KeySet.
//  2. canonicalRawRows(rawRows) is byte-for-byte identical to
//     CanonicalRows(the decoded typed Rows) — the actual no-freeze property,
//     not just an end-to-end pass/fail.
func TestVerifyOverReceivedBytes_NoFreezeForKnownEnvelopes(t *testing.T) {
	env, keys := newSignedEnvelope(t, 11, sampleRows())

	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal(env): %v", err)
	}

	var decoded Envelope
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(wire): %v", err)
	}
	if decoded.rawRows == nil {
		t.Fatalf("decoded envelope has no rawRows captured — UnmarshalJSON did not run or did not populate it")
	}

	if err := Verify(decoded, keys); err != nil {
		t.Fatalf("Verify(decoded) = %v, want nil — a known-shape envelope must still verify after the raw-bytes fix", err)
	}

	fromRaw, err := canonicalRawRows(decoded.rawRows)
	if err != nil {
		t.Fatalf("canonicalRawRows: %v", err)
	}
	fromTyped, err := CanonicalRows(decoded.Rows)
	if err != nil {
		t.Fatalf("CanonicalRows: %v", err)
	}
	if !bytes.Equal(fromRaw, fromTyped) {
		t.Fatalf("canonicalRawRows and CanonicalRows diverged for a known-shape envelope:\n  raw:   %s\n  typed: %s", fromRaw, fromTyped)
	}
}

// TestVerifyOverReceivedBytes_GracefulDegradationOnUnknownField is the
// graceful-degradation proof: a feed body carrying a field THIS BUILD's
// Row/PricingPolicyRow/Economics structs don't know about (e.g. some future
// nested "reserved_capacity" object) must still VERIFY — proving an
// already-deployed consumer degrades to base pricing instead of freezing with
// ErrDigestMismatch, which is the entire point of the fix. ("peak" was this
// test's original exemplar, but it is now a REAL field on PricingPolicyRow
// per docs/plans/peak-off-peak-pricing-plan-2026-09-20.md, so the exemplar
// moved to a still-genuinely-unknown nested field.)
//
// It hand-assembles a full envelope JSON body the way a publisher would,
// with an extra "reserved_capacity" key inside one row, signs it with a
// throwaway key exactly as the real publisher signs (digest/signature over the
// canonical bytes of the RAW rows — the publisher never has typed knowledge of
// a field added after this consumer build was compiled either), and asserts:
//  1. Verify passes on THIS build, which has never heard of "reserved_capacity".
//  2. The decoded typed Row for that model has dropped the unknown field
//     (proving the degradation is real — the field is truly gone from the
//     typed side, just not from what was verified).
func TestVerifyOverReceivedBytes_GracefulDegradationOnUnknownField(t *testing.T) {
	const feedVersion = int64(4)
	const keyID = "test-future-field-key"

	rowsJSON := `[` +
		`{"model":"claude-haiku-5","input_per_mtok":1,"output_per_mtok":5,"cache_read_per_mtok":0,"grade":"observed","reserved_capacity":{"input":0.3,"output":1.5}},` +
		`{"model":"claude-opus-5","input_per_mtok":15,"output_per_mtok":75,"grade":"verified"}` +
		`]`

	canonical, err := canonicalRawRows([]byte(rowsJSON))
	if err != nil {
		t.Fatalf("canonicalRawRows(rowsJSON): %v", err)
	}
	digest := digestOf(canonical)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(priv, SigningMessage(feedVersion, canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	keys, err := NewKeySet(map[string]string{keyID: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	envJSON := fmt.Sprintf(
		`{"schema_version":%d,"feed_version":%d,"generated_at":"2026-09-20T00:00:00Z","rows":%s,"digest":%q,"signature":%q,"key_id":%q}`,
		SupportedSchemaVersion, feedVersion, rowsJSON, digest, sigB64, keyID,
	)

	var env Envelope
	if err := json.Unmarshal([]byte(envJSON), &env); err != nil {
		t.Fatalf("json.Unmarshal(envJSON): %v", err)
	}

	if err := Verify(env, keys); err != nil {
		t.Fatalf("Verify(env with unknown future field) = %v, want nil — an old consumer must degrade gracefully, not freeze", err)
	}

	// Prove the degradation is real: the typed row for claude-haiku-5 has NO
	// memory of "reserved_capacity" — this build genuinely does not understand
	// the field, it simply didn't let that stop verification.
	var haiku *Row
	for i := range env.Rows {
		if env.Rows[i].Model == "claude-haiku-5" {
			haiku = &env.Rows[i]
		}
	}
	if haiku == nil {
		t.Fatalf("claude-haiku-5 row missing from decoded typed Rows")
	}
	typedJSON, err := json.Marshal(haiku)
	if err != nil {
		t.Fatalf("marshal typed row: %v", err)
	}
	if bytes.Contains(typedJSON, []byte("reserved_capacity")) {
		t.Fatalf("typed row unexpectedly retained the unknown 'reserved_capacity' field: %s", typedJSON)
	}
}
