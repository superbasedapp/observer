package orgcontract

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The pricing rail's signature must be domain-separated from every other
// Ed25519 use in the protocol, and the ONE rail it is most likely to be
// confused with is the sibling budget rail: both are governance documents,
// both are signed with the SAME org key, both ride the same push cycle, and
// both land on the same node. ROUTING-SIG-1 is the ledger entry that says a
// signature minted on one rail must never verify on another.
//
// The table walks both directions rather than one, because a one-directional
// test passes for the wrong reason as soon as the two bodies happen to
// marshal to different bytes: the property under test is that the DOMAIN TAG
// separates them, not that their JSON differs.
func TestPricingAndBudgetDomainsNeverVerifyEachOther(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const orgID = "org-1"
	const subject = "user-1"

	pricingBody := PricingPolicyBody{
		Version:     7,
		GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []PricingPolicyRow{
			{Model: "claude-opus-4-8", InputPerMTok: Rate(4), OutputPerMTok: Rate(20), Source: "negotiated"},
		},
	}
	budgetBody := BudgetPolicyBody{Version: 7, Period: "rolling_30d", Enforcement: "hard"}

	pricingDoc, err := SignPricingPolicy(priv, orgID, pricingBody)
	if err != nil {
		t.Fatalf("SignPricingPolicy: %v", err)
	}
	budgetDoc, err := SignBudgetPolicy(priv, orgID, subject, budgetBody)
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}

	// Sanity: each verifies on its own rail.
	if err := VerifyPricingPolicy(pub, orgID, pricingDoc); err != nil {
		t.Fatalf("pricing doc must verify on its own rail: %v", err)
	}
	if err := VerifyBudgetPolicy(pub, orgID, subject, budgetDoc); err != nil {
		t.Fatalf("budget doc must verify on its own rail: %v", err)
	}

	// Cross-rail: a budget signature carried on a pricing document.
	crossed := PricingPolicyDoc{PricingPolicyBody: pricingBody, Signature: budgetDoc.Signature}
	if err := VerifyPricingPolicy(pub, orgID, crossed); !errors.Is(err, ErrPricingPolicySignature) {
		t.Errorf("a BUDGET signature verified on the PRICING rail (err=%v) — the domain tags are not separating them", err)
	}
	// And the other direction.
	crossedBudget := BudgetPolicyDoc{BudgetPolicyBody: budgetBody, Signature: pricingDoc.Signature}
	if err := VerifyBudgetPolicy(pub, orgID, subject, crossedBudget); !errors.Is(err, ErrBudgetPolicySignature) {
		t.Errorf("a PRICING signature verified on the BUDGET rail (err=%v)", err)
	}
}

// The org id is bound into the signing message (F10): a document genuinely
// signed for one tenant must not verify for another, or a shared signing key
// across a multi-tenant control plane would be a cross-tenant price lever.
func TestPricingPolicyBindsOrgAndVersion(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body := PricingPolicyBody{Version: 3, GeneratedAt: "2026-09-08T00:00:00Z"}
	doc, err := SignPricingPolicy(priv, "org-a", body)
	if err != nil {
		t.Fatalf("SignPricingPolicy: %v", err)
	}
	if err := VerifyPricingPolicy(pub, "org-b", doc); !errors.Is(err, ErrPricingPolicySignature) {
		t.Errorf("a document signed for org-a verified for org-b (err=%v)", err)
	}
	// Version is bound both inside the body and explicitly in the message, so
	// an inflated version on a replayed body cannot verify.
	tampered := doc
	tampered.Version = 99
	if err := VerifyPricingPolicy(pub, "org-a", tampered); !errors.Is(err, ErrPricingPolicySignature) {
		t.Errorf("a version-tampered document verified (err=%v)", err)
	}
}

// A malformed signature must be a typed refusal, never a panic and never a
// silent accept: the node's ONLY defence on this rail is the signature.
func TestPricingPolicyRefusesMalformedInput(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := PricingPolicyBody{Version: 1}
	doc, _ := SignPricingPolicy(priv, "org", body)

	cases := []struct {
		name string
		pub  ed25519.PublicKey
		doc  PricingPolicyDoc
	}{
		{"empty signature", pub, PricingPolicyDoc{PricingPolicyBody: body}},
		{"not base64", pub, PricingPolicyDoc{PricingPolicyBody: body, Signature: "!!!!"}},
		{"short key", ed25519.PublicKey{1, 2, 3}, doc},
		{"wrong length signature", pub, PricingPolicyDoc{
			PricingPolicyBody: body,
			Signature:         base64.StdEncoding.EncodeToString([]byte("short")),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyPricingPolicy(tc.pub, "org", tc.doc); err == nil {
				t.Fatal("verify accepted a malformed document")
			}
		})
	}
}

// The digest is the ETag substrate. It must move when ANY part of the
// document moves — the rows included — because a node that echoes a stale tag
// gets a 304 and keeps pricing at the old rates.
func TestPricingPolicyDigestCoversTheWholeDocument(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(nil)
	base := PricingPolicyBody{
		Version:     2,
		GeneratedAt: "2026-09-08T00:00:00Z",
		Rows:        []PricingPolicyRow{{Model: "m", InputPerMTok: Rate(1), OutputPerMTok: Rate(2)}},
	}
	docA, _ := SignPricingPolicy(priv, "org", base)
	digestA, err := PricingPolicyDigest(docA)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digestA == "" {
		t.Fatal("digest is empty")
	}
	// Same input, same digest: the ETag must be stable across re-signing, or
	// every poll would look like a change.
	docA2, _ := SignPricingPolicy(priv, "org", base)
	if d2, _ := PricingPolicyDigest(docA2); d2 != digestA {
		t.Errorf("digest is not stable for identical input: %q vs %q", d2, digestA)
	}
	// A changed RATE must move the digest even though the version did not:
	// a rate correction that reuses a version is exactly the case a
	// version-only ETag would answer 304 to.
	changed := base
	changed.Rows = []PricingPolicyRow{{Model: "m", InputPerMTok: Rate(9), OutputPerMTok: Rate(2)}}
	docB, _ := SignPricingPolicy(priv, "org", changed)
	if dB, _ := PricingPolicyDigest(docB); dB == digestA {
		t.Error("digest did not move when a rate changed — a node would 304 onto stale prices")
	}
}

// TestPricingPolicyNilAndZeroRatesAreDifferentDocuments pins the wire half of
// server migration 135. Before it the document could not say "not set": a rate
// was a bare float64 with omitempty, so an unquoted rate and a negotiated FREE
// rate produced byte-identical JSON and therefore an identical signature and
// an identical ETag. A node could not have told them apart because there was
// nothing to tell apart.
func TestPricingPolicyNilAndZeroRatesAreDifferentDocuments(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(nil)

	unquoted := PricingPolicyBody{
		Version: 1, GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []PricingPolicyRow{{Model: "m", InputPerMTok: Rate(3), OutputPerMTok: nil}},
	}
	free := PricingPolicyBody{
		Version: 1, GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []PricingPolicyRow{{Model: "m", InputPerMTok: Rate(3), OutputPerMTok: Rate(0)}},
	}

	// The signing bytes differ, so a signature minted over one cannot verify
	// the other. That is the property that makes the distinction real rather
	// than cosmetic.
	msgUnquoted, err := PricingPolicySigningMessage("org", unquoted)
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	msgFree, err := PricingPolicySigningMessage("org", free)
	if err != nil {
		t.Fatalf("signing message: %v", err)
	}
	if string(msgUnquoted) == string(msgFree) {
		t.Fatal("an unquoted rate and a negotiated free rate signed identically")
	}

	docUnquoted, _ := SignPricingPolicy(priv, "org", unquoted)
	docFree, _ := SignPricingPolicy(priv, "org", free)
	dU, _ := PricingPolicyDigest(docUnquoted)
	dF, _ := PricingPolicyDigest(docFree)
	if dU == dF {
		t.Error("digest did not move between an unquoted and a free rate")
	}

	// Deterministic in both spellings: re-signing the same body must not move
	// the digest, or every poll would look like a change.
	for _, tc := range []struct {
		name string
		body PricingPolicyBody
		want string
	}{
		{"unquoted", unquoted, dU},
		{"free", free, dF},
	} {
		again, _ := SignPricingPolicy(priv, "org", tc.body)
		got, _ := PricingPolicyDigest(again)
		if got != tc.want {
			t.Errorf("%s: digest is not stable: %q vs %q", tc.name, got, tc.want)
		}
	}

	// And the JSON says which is which, plainly: omitempty on a POINTER omits
	// nil only.
	rawUnquoted, _ := json.Marshal(unquoted)
	if bytes.Contains(rawUnquoted, []byte(`"output_per_mtok"`)) {
		t.Errorf("an unquoted rate appeared on the wire: %s", rawUnquoted)
	}
	rawFree, _ := json.Marshal(free)
	if !bytes.Contains(rawFree, []byte(`"output_per_mtok":0`)) {
		t.Errorf("a negotiated free rate did not appear as 0: %s", rawFree)
	}
}

// TestPricingPolicyCanonicalBytesArePinned is a GOLDEN over the document's
// signing bytes, and it exists because of a design residual the nullable-rate
// review (finding P1-1) made explicit.
//
// A node does not verify over the bytes it RECEIVED. It decodes the document
// into PricingPolicyDoc and [VerifyPricingPolicy] re-derives the signing message
// by RE-MARSHALING the decoded struct. So the signature is over "what this
// build's struct renders", not "what the server sent" -- and ANY change to the
// shape of PricingPolicyRow or PricingPolicyBody (a field added, removed,
// renamed, reordered, or retyped between value and pointer) makes every node
// running the older struct compute different bytes and refuse a perfectly
// genuine document as `unverified`. It keeps its persisted table and stops
// taking price updates: a fleet freeze, not a parse error.
//
// Pinning the bytes here is what makes that consequence LOUD at authoring time.
// A shape change fails this test first, in the package that owns the contract,
// where the author can decide to version the document rather than discovering
// the freeze on a fleet.
//
// The two rows are the pair the whole nullable-rate change turns on: one rate
// unquoted (absent from the bytes) and one quoted free (present as 0).
func TestPricingPolicyCanonicalBytesArePinned(t *testing.T) {
	t.Parallel()
	body := PricingPolicyBody{
		Version:     7,
		GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []PricingPolicyRow{
			// Everything unquoted except the input rate: the org quotes one
			// number and falls through for the rest.
			{Model: "m-unquoted", InputPerMTok: Rate(3), Source: "negotiated"},
			// A negotiated FREE token pair, quoted at zero.
			{Model: "m-free", InputPerMTok: Rate(0), OutputPerMTok: Rate(0), Source: "negotiated"},
		},
	}
	const want = `{"version":7,"generated_at":"2026-09-08T00:00:00Z","rows":[` +
		`{"model":"m-unquoted","input_per_mtok":3,"source":"negotiated"},` +
		`{"model":"m-free","input_per_mtok":0,"output_per_mtok":0,"source":"negotiated"}` +
		`]}`
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != want {
		t.Errorf("the pricing document's canonical bytes moved.\n got: %s\nwant: %s\n\n"+
			"A node verifies by RE-MARSHALING the document it decoded, so a shape change here "+
			"makes every node on the older build refuse a genuine document as `unverified` and "+
			"stop taking price updates. If this change is intended, version the document rather "+
			"than editing this golden.", raw, want)
	}

	// The residual itself, asserted rather than described: a decode followed by
	// a re-marshal must reproduce the received bytes exactly. That round trip IS
	// the verification path, so the day it stops holding for a field, that
	// field's documents stop verifying.
	var back PricingPolicyBody
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	again, err := json.Marshal(back)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(raw, again) {
		t.Errorf("decode -> re-marshal is not byte-stable:\n sent: %s\nre-derived: %s", raw, again)
	}
}

// TestPricingPolicyByteCompatNoUnknownFields is the FLEET-NO-FREEZE proof for
// the raw verification path (docs/plans/peak-off-peak-pricing-plan-2026-09-20.md
// §R "Phase 0"). It asserts that for a document with NO unknown fields the raw
// canonicalisation ([canonicalPricingBodyRaw]) produces bytes IDENTICAL to the
// typed one ([canonicalPricingBody]), so a document a currently-deployed server
// signed over the typed bytes still verifies on an upgraded node that verifies
// over the received bytes. If this ever fails, every deployed server's document
// would land `unverified` on upgraded nodes — the exact freeze the change exists
// to remove.
func TestPricingPolicyByteCompatNoUnknownFields(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const orgID = "org-compat"
	// The pair the nullable-rate change turns on: one rate unquoted (absent
	// from the bytes) and one quoted free (present as 0).
	body := PricingPolicyBody{
		Version:     12,
		GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []PricingPolicyRow{
			{Model: "m-unquoted", InputPerMTok: Rate(3), Source: "negotiated"},
			{Model: "m-free", InputPerMTok: Rate(0), OutputPerMTok: Rate(0), Source: "negotiated"},
		},
	}

	// SignPricingPolicy uses the TYPED path — these are the current wire bytes a
	// deployed server produces.
	doc, err := SignPricingPolicy(priv, orgID, body)
	if err != nil {
		t.Fatalf("SignPricingPolicy: %v", err)
	}

	// Round-trip through JSON exactly as the node does (json.Marshal on the
	// server, Decode/Unmarshal on the node), which triggers UnmarshalJSON and
	// populates rawRows.
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	var decoded PricingPolicyDoc
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal doc: %v", err)
	}
	if decoded.rawRows == nil {
		t.Fatal("UnmarshalJSON did not capture rawRows — the raw verification path would never engage")
	}

	// The hard requirement: the two canonicalisations must be byte-identical for
	// a no-unknown-field document.
	rawBytes, err := canonicalPricingBodyRaw(decoded.Version, decoded.GeneratedAt, decoded.rawRows)
	if err != nil {
		t.Fatalf("canonicalPricingBodyRaw: %v", err)
	}
	typedBytes, err := canonicalPricingBody(body)
	if err != nil {
		t.Fatalf("canonicalPricingBody: %v", err)
	}
	if !bytes.Equal(rawBytes, typedBytes) {
		t.Fatalf("raw and typed canonical bytes differ (fleet-freeze):\n raw: %s\ntyped: %s", rawBytes, typedBytes)
	}

	// And the property that matters operationally: a genuine, decoded document
	// verifies over the received bytes.
	if err := VerifyPricingPolicy(pub, orgID, decoded); err != nil {
		t.Fatalf("a decoded genuine document failed to verify: %v", err)
	}

	// Marshalling the doc is UNCHANGED by UnmarshalJSON/rawRows: the re-marshal
	// of the decoded doc reproduces the wire bytes exactly (unexported field is
	// never emitted).
	reWire, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal decoded doc: %v", err)
	}
	if !bytes.Equal(wire, reWire) {
		t.Errorf("json.Marshal(doc) changed after decode:\n first: %s\nsecond: %s", wire, reWire)
	}
}

// TestPricingPolicyFutureRowFieldStillVerifies is the GRACEFUL-DEGRADATION
// proof: a document a FUTURE server emits — carrying a row field this build's
// PricingPolicyRow has no place for (a nested "reserved_capacity" object,
// standing in for whatever field ships after this one; "peak" itself became a
// real, KNOWN field in Phase 2 and so no longer exemplifies an unknown one)
// — must VERIFY on this old build, not freeze it. The future server signs
// over the raw canonicalisation of its rows; this build captures those exact
// raw rows on decode and verifies over them, even though its typed decode
// drops the unknown field.
func TestPricingPolicyFutureRowFieldStillVerifies(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const orgID = "org-future"
	const version = int64(20)
	const generatedAt = "2026-09-08T00:00:00Z"

	// The rows a future server serves: an extra nested "reserved_capacity"
	// object inside a row that this build does not model. Compact, as
	// json.Marshal would emit.
	rawRows := []byte(`[` +
		`{"model":"m","input_per_mtok":3,"reserved_capacity":{"discount_pct":10},"source":"negotiated"}` +
		`]`)

	// The future server signs over the RAW canonicalisation of exactly these
	// rows (which equals what its own typed canonicalPricingBody would render).
	signBody, err := canonicalPricingBodyRaw(version, generatedAt, rawRows)
	if err != nil {
		t.Fatalf("canonicalPricingBodyRaw: %v", err)
	}
	sig := ed25519.Sign(priv, pricingSigningHash(orgID, version, signBody))

	// Assemble the full wire document with those exact raw rows.
	docJSON := []byte(`{"version":20,"generated_at":"` + generatedAt + `","rows":` +
		string(rawRows) + `,"signature":"` + base64.StdEncoding.EncodeToString(sig) + `"}`)

	var doc PricingPolicyDoc
	if err := json.Unmarshal(docJSON, &doc); err != nil {
		t.Fatalf("unmarshal future-field document: %v", err)
	}

	// The headline: an OLD struct verifies a FUTURE-field document instead of
	// refusing it as `unverified`.
	if err := VerifyPricingPolicy(pub, orgID, doc); err != nil {
		t.Fatalf("a future-field document failed to verify on this build (fleet freeze): %v", err)
	}

	// The typed decode dropped the unknown field — logic runs against only what
	// this build knows — yet verification still succeeded above.
	if len(doc.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(doc.Rows))
	}
	if doc.Rows[0].Model != "m" {
		t.Errorf("model = %q, want %q", doc.Rows[0].Model, "m")
	}
	if doc.Rows[0].InputPerMTok == nil || *doc.Rows[0].InputPerMTok != 3 {
		t.Errorf("input = %v, want a SET 3", doc.Rows[0].InputPerMTok)
	}
	// Re-marshalling the typed row cannot reproduce the "reserved_capacity"
	// field — proof the field was dropped from the typed view (and hence why a
	// typed re-marshal would have failed to verify, which the raw path is
	// exactly what fixes).
	reTyped, err := json.Marshal(doc.Rows[0])
	if err != nil {
		t.Fatalf("marshal typed row: %v", err)
	}
	if bytes.Contains(reTyped, []byte(`"reserved_capacity"`)) {
		t.Errorf("the typed row unexpectedly carried the unknown field: %s", reTyped)
	}
	// And Peak — now a REAL field — must have decoded as genuinely absent
	// (nil), not as a spuriously-populated zero value: the raw row above never
	// named "peak" at all.
	if doc.Rows[0].Peak != nil {
		t.Errorf("Peak = %+v, want nil — the raw row named no peak field", doc.Rows[0].Peak)
	}

	// Tamper proof: flipping a byte inside the received rows must fail — the raw
	// path is verifying the actual bytes, not blindly accepting anything.
	tampered := doc
	tampered.rawRows = []byte(`[{"model":"m","input_per_mtok":9,"peak":{"input_per_mtok":0.3},"source":"negotiated"}]`)
	if err := VerifyPricingPolicy(pub, orgID, tampered); !errors.Is(err, ErrPricingPolicySignature) {
		t.Errorf("a tampered rows body verified (err=%v)", err)
	}
}

// TestPricingPolicyDecodesAnOlderServersZero pins the compat direction that
// matters: a server built BEFORE 135 always sent every rate, spelling "not
// negotiated" as 0. Decoding that into the pointer type must still work.
func TestPricingPolicyDecodesAnOlderServersZero(t *testing.T) {
	t.Parallel()
	const old = `{"version":3,"generated_at":"2026-09-08T00:00:00Z","rows":[` +
		`{"model":"m","input_per_mtok":3,"output_per_mtok":0,"cache_read_per_mtok":0}]}`
	var body PricingPolicyBody
	if err := json.Unmarshal([]byte(old), &body); err != nil {
		t.Fatalf("decode a pre-135 document: %v", err)
	}
	if len(body.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(body.Rows))
	}
	r := body.Rows[0]
	if r.InputPerMTok == nil || *r.InputPerMTok != 3 {
		t.Errorf("input = %v, want 3", r.InputPerMTok)
	}
	if r.OutputPerMTok == nil || *r.OutputPerMTok != 0 {
		t.Errorf("output = %v, want a SET 0 (that is what the old server sent)", r.OutputPerMTok)
	}
	// A field the old server simply did not carry stays nil, which is the
	// same answer the new spelling gives.
	if r.WebSearchPerRequest != nil {
		t.Errorf("web search = %v, want nil", r.WebSearchPerRequest)
	}
}

// legacyPricingPolicyRow is PricingPolicyRow as it was BEFORE server
// migration 175 (b922604c2^), copied field for field: a bare `int64,omitempty`
// threshold (so a 0 never reached the wire) and no presence markers. It stands
// for a node built before the nullable threshold, and for the server it
// shipped with.
type legacyPricingPolicyRow struct {
	Model string `json:"model"`

	InputPerMTok        *float64 `json:"input_per_mtok,omitempty"`
	OutputPerMTok       *float64 `json:"output_per_mtok,omitempty"`
	CacheReadPerMTok    *float64 `json:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok   *float64 `json:"cache_write_per_mtok,omitempty"`
	CacheWrite1hPerMTok *float64 `json:"cache_write_1h_per_mtok,omitempty"`

	LongContextThreshold           int64    `json:"long_context_threshold,omitempty"`
	LongContextInputPerMTok        *float64 `json:"long_context_input_per_mtok,omitempty"`
	LongContextOutputPerMTok       *float64 `json:"long_context_output_per_mtok,omitempty"`
	LongContextCacheReadPerMTok    *float64 `json:"long_context_cache_read_per_mtok,omitempty"`
	LongContextCacheWritePerMTok   *float64 `json:"long_context_cache_write_per_mtok,omitempty"`
	LongContextCacheWrite1hPerMTok *float64 `json:"long_context_cache_write_1h_per_mtok,omitempty"`

	WebSearchPerRequest *float64 `json:"web_search_per_request,omitempty"`

	EffectiveFrom string `json:"effective_from,omitempty"`
	Source        string `json:"source,omitempty"`

	Peak *PeakRates `json:"peak,omitempty"`
}

type legacyPricingPolicyBody struct {
	Version     int64                    `json:"version"`
	GeneratedAt string                   `json:"generated_at"`
	Rows        []legacyPricingPolicyRow `json:"rows"`
}

// legacyOverlay is what a pre-175 node did with a decoded org row's two
// structural dimensions (b922604c2^:internal/intelligence/cost/orgprice.go:
// 127,138): BOTH were overlaid unconditionally, so the row's threshold (0 when
// omitted) and its peak (nil when omitted) always replaced the seed's.
func legacyOverlay(r legacyPricingPolicyRow) (threshold int64, peakWindows int) {
	if r.Peak != nil {
		peakWindows = len(r.Peak.Schedule.Windows)
	}
	return r.LongContextThreshold, peakWindows
}

func windowedPeak() *PeakRates {
	return &PeakRates{
		RateSet:  RateSet{Input: 2, Output: 6},
		Schedule: PeakSchedule{Windows: []PeakWindow{{StartUTC: "01:00", EndUTC: "04:00"}}},
	}
}

func threshold(v int64) *int64 { return &v }

// TestPricingPolicyRowOrgRailLegacyCompat pins review finding F1 (session 3,
// 2026-09-26) at the wire: the org rail's encoding of migration 175's three
// threshold states and the peak's two presence states, in BOTH directions
// against a pre-175 peer.
//
//   - NEW SERVER -> OLD NODE: every state a pre-175 store could hold (a 0 or
//     positive threshold; a peak with or without windows) marshals to rows
//     BYTE-IDENTICAL to the old server's, so an old node verifies the
//     signature on either verify path and bills exactly as before. The two
//     states only a post-175 store can hold (NULL threshold, NULL peak) add a
//     marker the old node ignores; it then reads them as it read every
//     unstated dimension - flat - which is the best a node that cannot say
//     "keep my seed" can do.
//   - OLD SERVER -> NEW NODE: a legacy row decodes, through OrgThreshold /
//     OrgPeak, to exactly what the old node's unconditional overlay applied.
func TestPricingPolicyRowOrgRailLegacyCompat(t *testing.T) {
	for _, tc := range []struct {
		name           string
		storedThresh   *int64
		storedPeak     *PeakRates
		legacy         *legacyPricingPolicyRow // the old server's row for the same stored data; nil = inexpressible pre-175
		wantThresh     int64
		wantThreshSet  bool
		wantPeakSet    bool
		wantPeakWindow int
		// notByteIdentical names the ONE state the new server cannot spell
		// as a pre-175 server did (review round 2, finding 3; SetOrgPeak's
		// doc; docs/pricing.md): a pre-175 row that STORED an explicit
		// all-zero, window-less peak object decodes to the same value as
		// the cut-over's '{}', which must be omitted. For that state the
		// test asserts the documented difference (omitted, not the object)
		// and that both spellings still overlay flat on an old node.
		notByteIdentical bool
	}{
		{
			name: "quoted flat, flat peak (every pre-175 row)", storedThresh: threshold(0), storedPeak: &PeakRates{},
			legacy: &legacyPricingPolicyRow{Model: "m", InputPerMTok: Rate(1)}, wantThreshSet: true, wantPeakSet: true,
		},
		{
			name: "own tier, windowed peak", storedThresh: threshold(272000), storedPeak: windowedPeak(),
			legacy:     &legacyPricingPolicyRow{Model: "m", InputPerMTok: Rate(1), LongContextThreshold: 272000, Peak: windowedPeak()},
			wantThresh: 272000, wantThreshSet: true, wantPeakSet: true, wantPeakWindow: 1,
		},
		{
			name: "own tier, window-less peak object WITH rates (validation admits it)", storedThresh: threshold(5), storedPeak: &PeakRates{RateSet: RateSet{Input: 9}},
			legacy:     &legacyPricingPolicyRow{Model: "m", InputPerMTok: Rate(1), LongContextThreshold: 5, Peak: &PeakRates{RateSet: RateSet{Input: 9}}},
			wantThresh: 5, wantThreshSet: true, wantPeakSet: true,
		},
		{
			name: "window-less peak with rates and a long-context sub-tier", storedThresh: threshold(0), storedPeak: &PeakRates{RateSet: RateSet{Input: 9, Output: 3, LongContextThreshold: 100, LongContextInput: 18}},
			legacy:        &legacyPricingPolicyRow{Model: "m", InputPerMTok: Rate(1), Peak: &PeakRates{RateSet: RateSet{Input: 9, Output: 3, LongContextThreshold: 100, LongContextInput: 18}}},
			wantThreshSet: true, wantPeakSet: true,
		},
		{
			name: "pre-175 STORED all-zero window-less peak object (the one non-byte-identical state)", storedThresh: threshold(0), storedPeak: &PeakRates{},
			legacy:        &legacyPricingPolicyRow{Model: "m", InputPerMTok: Rate(1), Peak: &PeakRates{}},
			wantThreshSet: true, wantPeakSet: true, notByteIdentical: true,
		},
		{name: "not quoted (post-175 only)", storedThresh: nil, storedPeak: nil, wantThreshSet: false, wantPeakSet: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := PricingPolicyRow{Model: "m", InputPerMTok: Rate(1)}
			row.SetOrgThreshold(tc.storedThresh)
			row.SetOrgPeak(tc.storedPeak)
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			// NEW SERVER -> OLD NODE.
			if tc.legacy != nil {
				old, err := json.Marshal(tc.legacy)
				if err != nil {
					t.Fatalf("marshal legacy: %v", err)
				}
				switch {
				case !tc.notByteIdentical && !bytes.Equal(raw, old):
					t.Fatalf("a pre-175-expressible row changed bytes:\n new %s\n old %s", raw, old)
				case tc.notByteIdentical && (bytes.Equal(raw, old) || bytes.Contains(raw, []byte(`"peak"`))):
					t.Fatalf("the documented non-byte-identical state changed shape: new %s old %s (want the peak omitted)", raw, old)
				}
			} else if !bytes.Contains(raw, []byte(`"long_context_threshold_unquoted":true`)) ||
				!bytes.Contains(raw, []byte(`"peak_unquoted":true`)) {
				t.Fatalf("a NULL threshold/peak must carry its marker: %s", raw)
			}
			var oldNode legacyPricingPolicyRow
			if err := json.Unmarshal(raw, &oldNode); err != nil {
				t.Fatalf("an old node cannot decode the new row: %v", err)
			}
			gotT, gotW := legacyOverlay(oldNode)
			if gotT != tc.wantThresh || gotW != tc.wantPeakWindow {
				t.Errorf("old node overlays (threshold %d, peak windows %d), want (%d, %d)", gotT, gotW, tc.wantThresh, tc.wantPeakWindow)
			}

			// NEW SERVER -> NEW NODE: the three states stay distinct.
			var back PricingPolicyRow
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if v, set := back.OrgThreshold(); v != tc.wantThresh || set != tc.wantThreshSet {
				t.Errorf("OrgThreshold = (%d, %v), want (%d, %v)", v, set, tc.wantThresh, tc.wantThreshSet)
			}
			p, set := back.OrgPeak()
			if set != tc.wantPeakSet {
				t.Errorf("OrgPeak quoted = %v, want %v", set, tc.wantPeakSet)
			}
			if w := 0; p != nil {
				w = len(p.Schedule.Windows)
				if w != tc.wantPeakWindow {
					t.Errorf("OrgPeak windows = %d, want %d", w, tc.wantPeakWindow)
				}
			}

			// OLD SERVER -> NEW NODE: the legacy bytes read back as the old
			// node's overlay, never as "keep the seed".
			if tc.legacy != nil {
				old, _ := json.Marshal(tc.legacy)
				var fromOld PricingPolicyRow
				if err := json.Unmarshal(old, &fromOld); err != nil {
					t.Fatalf("new node cannot decode a legacy row: %v", err)
				}
				wantT, wantW := legacyOverlay(*tc.legacy)
				if v, set := fromOld.OrgThreshold(); !set || v != wantT {
					t.Errorf("legacy row OrgThreshold = (%d, %v), want the old overlay's (%d, true)", v, set, wantT)
				}
				p, set := fromOld.OrgPeak()
				gotW := 0
				if p != nil {
					gotW = len(p.Schedule.Windows)
				}
				if !set || gotW != wantW {
					t.Errorf("legacy row OrgPeak = (%+v, %v), want quoted with %d windows", p, set, wantW)
				}
			}
		})
	}
}

// TestPricingPolicyLegacyStateBodyVerifiesOnATypedPre175Node pins the
// strongest form of the byte-compat claim: a body signed by THIS server over
// rows holding only pre-175-expressible states re-marshals, through a pre-175
// node's TYPED struct (the verify path every node before rc.8 used), to the
// exact bytes that were signed - so the signature verifies there too.
func TestPricingPolicyLegacyStateBodyVerifiesOnATypedPre175Node(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	flat := PricingPolicyRow{Model: "a", InputPerMTok: Rate(1), OutputPerMTok: Rate(2)}
	flat.SetOrgThreshold(threshold(0))
	flat.SetOrgPeak(&PeakRates{})
	tiered := PricingPolicyRow{Model: "b", InputPerMTok: Rate(1), LongContextInputPerMTok: Rate(2)}
	tiered.SetOrgThreshold(threshold(200000))
	tiered.SetOrgPeak(windowedPeak())
	body := PricingPolicyBody{Version: 4, GeneratedAt: "2026-09-26T00:00:00Z", Rows: []PricingPolicyRow{flat, tiered}}
	doc, err := SignPricingPolicy(priv, "org-1", body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	var old struct {
		legacyPricingPolicyBody
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(wire, &old); err != nil {
		t.Fatalf("pre-175 decode: %v", err)
	}
	reMarshal, err := json.Marshal(old.legacyPricingPolicyBody)
	if err != nil {
		t.Fatalf("pre-175 re-marshal: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(old.Signature)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	if !ed25519.Verify(pub, pricingSigningHash("org-1", old.Version, reMarshal), sig) {
		t.Fatal("a legacy-state document does not verify on a typed pre-175 node: the new server would freeze it")
	}
}

// TestPricingPolicyContextWindowsVerifyOnEveryNodeGeneration is the
// regression for the 2026-09-29 review finding: the context windows lane
// G-WIRE2 stamped INTO the signed rows broke verification on every node built
// before the raw-rows verify (v1.33.0 .. rc.7), which re-marshals the struct it
// decoded and so drops a row key it does not know. The windows now ride as an
// unsigned top-level sibling (PricingPolicyDoc.ContextWindows), outside the
// signed body, so the document verifies on:
//
//   - the current node (raw received rows),
//   - a pre-rc.8 node (typed re-marshal of the decoded body, no rawRows),
//
// and the signing message is byte-identical with and without windows.
func TestPricingPolicyContextWindowsVerifyOnEveryNodeGeneration(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := PricingPolicyBody{Version: 7, GeneratedAt: "2026-09-29T00:00:00Z", Rows: []PricingPolicyRow{{
		Model: "claude-sonnet-4-5", InputPerMTok: Rate(3), OutputPerMTok: Rate(15), Source: "imported",
	}}}
	doc, err := SignPricingPolicy(priv, "org-1", body)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// Outside the signature: the server attaches windows AFTER signing, for a
	// model the price book does not name as well as one it does.
	doc.ContextWindows = []ModelContextWindow{{Model: "claude-sonnet-4-5", Tokens: 200_000}, {Model: "gpt-5.6", Tokens: 400_000}}
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"context_windows"`)) {
		t.Fatalf("windows missing from the wire: %s", wire)
	}
	if bytes.Contains(wire, []byte(`"rows":[{"model":"claude-sonnet-4-5","input_per_mtok":3,"output_per_mtok":15,"source":"imported","context`)) {
		t.Fatalf("a window leaked into the signed rows: %s", wire)
	}

	var got PricingPolicyDoc
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPricingPolicy(pub, "org-1", got); err != nil {
		t.Fatalf("current (raw rows) node refuses the windowed document: %v", err)
	}
	if len(got.ContextWindows) != 2 || got.ContextWindows[1].Model != "gpt-5.6" || got.ContextWindows[1].Tokens != 400_000 {
		t.Fatalf("windows lost in transit: %+v", got.ContextWindows)
	}
	// A pre-rc.8 node: no rawRows, verifies by re-marshalling the typed body
	// it decoded. Its struct has no ContextWindows either, which is exactly
	// what building the doc from the body alone models.
	old := PricingPolicyDoc{PricingPolicyBody: got.PricingPolicyBody, Signature: got.Signature}
	if err := VerifyPricingPolicy(pub, "org-1", old); err != nil {
		t.Fatalf("pre-raw-verify node REFUSES the windowed document: %v", err)
	}
	// The signed bytes do not move with the windows.
	var gotBare PricingPolicyDoc
	if err := json.Unmarshal(bare, &gotBare); err != nil {
		t.Fatal(err)
	}
	withMsg, err := pricingVerifyMessage("org-1", got)
	if err != nil {
		t.Fatal(err)
	}
	withoutMsg, err := pricingVerifyMessage("org-1", gotBare)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withMsg, withoutMsg) {
		t.Fatal("the signing message changed when context_windows were attached")
	}
	// But the ETag substrate does move, so a window change re-fetches.
	d1, _ := PricingPolicyDigest(gotBare)
	d2, _ := PricingPolicyDigest(got)
	if d1 == d2 {
		t.Fatal("the document digest ignores context_windows; a node would never re-fetch a window change")
	}
}

// TestPricingPolicyNoWindowsKeepsLegacyBytes pins that a document with no
// windows marshals exactly as before the sibling existed.
func TestPricingPolicyNoWindowsKeepsLegacyBytes(t *testing.T) {
	doc := PricingPolicyDoc{PricingPolicyBody: PricingPolicyBody{
		Version: 3, GeneratedAt: "2026-09-29T00:00:00Z",
		Rows: []PricingPolicyRow{{Model: "m", InputPerMTok: Rate(1)}},
	}, Signature: "c2ln"}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "context_window") {
		t.Fatalf("a document with no windows must carry no window key: %s", raw)
	}
}
