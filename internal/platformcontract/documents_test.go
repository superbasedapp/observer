package platformcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

const testOrg = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func pubOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub
}

// rawDocMessage replays the documented layout with any domain, so the test can
// build the message another rail would sign over the same fields.
func rawDocMessage(domain, scope string, version int64, body []byte) []byte {
	h := sha256.New()
	for i, part := range [][]byte{[]byte(domain), []byte(scope), []byte(strconv.FormatInt(version, 10)), body} {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write(part)
	}
	return h.Sum(nil)
}

func goldenAvailabilityBody() AvailabilityBody {
	return AvailabilityBody{
		IssuedAt: "2026-11-13T12:00:00Z",
		Components: []ComponentAvailability{
			{Component: "org.enrichment", Reach: ReachNamed, Orgs: []string{testOrg}, Reason: "beta", Author: "staff:ops-1"},
			{Component: "org.gateway", Reach: ReachOff, Reason: "incident 42", Author: "staff:ops-1"},
		},
		OrgControls: []OrgControl{
			{Org: testOrg, Ingest: &IngestControl{Mode: IngestThrottle, RatePerMinute: 600}, Reason: "noisy neighbour", Author: "staff:ops-2"},
			{Org: AllOrgs, Inference: []InferenceControl{{Route: "luna", Admission: InferencePaused, Dispatch: InferenceOn}}, Reason: "provider brownout", Author: "system"},
		},
		ReleaseFlags: []ReleaseFlagAvailability{
			{Flag: "rf-new-ingest-path", Reach: ReachCohort, Cohort: "ring-5pct", Reason: "rollout", Author: "staff:ops-1"},
		},
	}
}

func checkGolden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // G306: a committed golden fixture
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(want), "\r\n", "\n") != string(got) {
		t.Fatalf("golden mismatch for %s:\n got %s\nwant %s", name, got, want)
	}
}

func TestDocumentGolden(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(goldenAvailabilityBody())
	if err != nil {
		t.Fatal(err)
	}
	avail, err := SignAvailability(seedKey(2), 7, body)
	if err != nil {
		t.Fatal(err)
	}
	ent, err := SignEntitlements(seedKey(1), testOrg, 3, []byte(`{"plan":"team","caps":{"seats":10}}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]any{
		"availability_body":     goldenAvailabilityBody(),
		"availability_document": avail,
		"entitlements_document": ent,
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkGolden(t, name, v)
		})
	}
}

func TestDocumentSigningMessageLayout(t *testing.T) {
	t.Parallel()
	body := []byte(`{"a":1}`)
	cases := []struct {
		kind   DocumentKind
		scope  string
		domain string
	}{
		{KindEntitlements, testOrg, "sbo-entitlements-v1"},
		{KindAvailability, AvailabilityScope, "sbo-availability-v1"},
	}
	for _, tc := range cases {
		got, err := DocumentSigningMessage(tc.kind, tc.scope, 9, body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, rawDocMessage(tc.domain, tc.scope, 9, body)) {
			t.Errorf("%s: message is not SHA-256(domain 0 scope 0 version 0 body)", tc.kind)
		}
	}
}

// TestDomainSeparation signs the same (scope, version, body) under each of
// six signature families with ONE key and checks that no signature verifies
// as any other family: entitlements, availability, the host-API request and
// response envelopes, and the org server's pricing and display-policy rails.
func TestDomainSeparation(t *testing.T) {
	t.Parallel()
	priv := seedKey(9)
	pub := pubOf(priv)
	body := []byte(`{"x":1}`)
	const version = 4
	env := Envelope{KeyID: DocumentKeyID(pub), Timestamp: 1_700_000_000, Nonce: "n-1", BodyDigest: BodyDigest(body)}
	reqIn, err := SigningInput("PUT", PathTenantEntitlements(testOrg), env)
	if err != nil {
		t.Fatal(err)
	}
	respIn, err := ResponseSigningInput("PUT", PathTenantEntitlements(testOrg), env)
	if err != nil {
		t.Fatal(err)
	}
	entMsg, err := DocumentSigningMessage(KindEntitlements, testOrg, version, body)
	if err != nil {
		t.Fatal(err)
	}
	availMsg, err := DocumentSigningMessage(KindAvailability, AvailabilityScope, version, body)
	if err != nil {
		t.Fatal(err)
	}
	families := []struct {
		name string
		msg  []byte
	}{
		{"entitlements", entMsg},
		{"availability", availMsg},
		{"availability-tag-over-org-scope", rawDocMessage(AvailabilitySigningDomain, testOrg, version, body)},
		{"host-api-request", reqIn},
		{"host-api-response", respIn},
		{"pricing", rawDocMessage("sbo-pricing-policy-v1", testOrg, version, body)},
		{"display-policy", orgcontract.DisplayPolicySigningMessage(testOrg, version, string(body))},
	}
	for i, signer := range families {
		sig := ed25519.Sign(priv, signer.msg)
		for j, verifier := range families {
			if i == j {
				if !ed25519.Verify(pub, verifier.msg, sig) {
					t.Fatalf("%s does not verify as itself", signer.name)
				}
				continue
			}
			if ed25519.Verify(pub, verifier.msg, sig) {
				t.Errorf("a %s signature verifies as %s", signer.name, verifier.name)
			}
		}
	}
}

// TestDocumentsRefuseEachOther drives the public verifiers: an entitlements
// document never verifies as availability or as a host-API envelope, and the
// reverse.
func TestDocumentsRefuseEachOther(t *testing.T) {
	t.Parallel()
	priv := seedKey(3)
	keys := KeySet{NewDocumentKey(pubOf(priv))}
	body := []byte(`{"x":1}`)
	ent, err := SignEntitlements(priv, testOrg, 2, body)
	if err != nil {
		t.Fatal(err)
	}
	avail, err := SignAvailability(priv, 2, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEntitlements(ent, testOrg, keys, 0); err != nil {
		t.Fatalf("entitlements: %v", err)
	}
	if err := VerifyAvailability(avail, keys, 0); err != nil {
		t.Fatalf("availability: %v", err)
	}
	if err := VerifyAvailability(AvailabilityDocument(ent), keys, 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("entitlements verified as availability: %v", err)
	}
	if err := VerifyEntitlements(EntitlementDocument(avail), testOrg, keys, 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("availability verified as entitlements: %v", err)
	}
	if err := VerifyEntitlements(ent, "1b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f", keys, 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("org A's document verified for org B: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	for _, sig := range [][]byte{ent.Signature, avail.Signature} {
		e := Envelope{KeyID: ent.KeyID, Timestamp: now.Unix(), Nonce: "n", BodyDigest: BodyDigest(body), Signature: b64(sig)}
		if err := e.Verify(pubOf(priv), "PUT", PathTenantEntitlements(testOrg), body, now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("a document signature verified as a host-API envelope: %v", err)
		}
	}
	e, err := NewEnvelope(priv, ent.KeyID, "n", "PUT", PathTenantEntitlements(testOrg), body, now)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := decodeB64(e.Signature)
	forged := EntitlementDocument{Version: 2, Body: body, Signature: sig, KeyID: ent.KeyID}
	if err := VerifyEntitlements(forged, testOrg, keys, 0); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a host-API envelope signature verified as entitlements: %v", err)
	}
}

func TestCheckDocumentVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		last, next int64
		want       error
	}{
		{"next-positive: zero", 0, 0, ErrDocumentVersion},
		{"next-positive: negative", 0, -1, ErrDocumentVersion},
		{"last-non-negative", -1, 5, ErrDocumentVersion},
		{"strictly-newer: equal", 5, 5, ErrVersionNotNewer},
		{"strictly-newer: older", 5, 4, ErrVersionNotNewer},
		{"first version", 0, 1, nil},
		{"newer", 5, 6, nil},
	}
	for _, tc := range cases {
		err := CheckDocumentVersion(tc.last, tc.next)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: CheckDocumentVersion(%d, %d) = %v, want %v", tc.name, tc.last, tc.next, err, tc.want)
		}
	}
}

func TestVerifyRefusesOlderOrEqualVersion(t *testing.T) {
	t.Parallel()
	priv := seedKey(4)
	keys := KeySet{NewDocumentKey(pubOf(priv))}
	doc, err := SignEntitlements(priv, testOrg, 5, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, last := range []int64{5, 6} {
		if err := VerifyEntitlements(doc, testOrg, keys, last); !errors.Is(err, ErrVersionNotNewer) {
			t.Errorf("last %d: %v, want ErrVersionNotNewer", last, err)
		}
	}
	if err := VerifyEntitlements(doc, testOrg, keys, 4); err != nil {
		t.Errorf("last 4: %v", err)
	}
	inflated := doc
	inflated.Version = 50
	if err := VerifyEntitlements(inflated, testOrg, keys, 5); !errors.Is(err, ErrBadSignature) {
		t.Errorf("an inflated version verified: %v", err)
	}
}

func TestKeyRolloverTwoKeys(t *testing.T) {
	t.Parallel()
	oldKey, newKey, stranger := seedKey(5), seedKey(6), seedKey(7)
	keys := KeySet{NewDocumentKey(pubOf(oldKey)), NewDocumentKey(pubOf(newKey))}
	for i, k := range []ed25519.PrivateKey{oldKey, newKey} {
		doc, err := SignAvailability(k, int64(i+1), []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyAvailability(doc, keys, int64(i)); err != nil {
			t.Errorf("key %d: %v", i, err)
		}
	}
	doc, err := SignAvailability(stranger, 9, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAvailability(doc, keys, 0); !errors.Is(err, ErrUnknownDocumentKey) {
		t.Errorf("an unpinned key verified: %v", err)
	}
	// A pinned id that is not the key's own derived id is never used.
	lying := KeySet{{KeyID: doc.KeyID, Public: pubOf(oldKey)}}
	if err := VerifyAvailability(doc, lying, 0); !errors.Is(err, ErrUnknownDocumentKey) {
		t.Errorf("a mislabelled key verified: %v", err)
	}
}

func TestValidateDocumentScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind  DocumentKind
		scope string
		ok    bool
	}{
		{KindEntitlements, testOrg, true},
		{KindEntitlements, "", false},
		{KindEntitlements, AvailabilityScope, false},
		{KindEntitlements, "org with space", false},
		{KindEntitlements, "org\x00nul", false},
		{KindEntitlements, strings.Repeat("o", maxScopeLen+1), false},
		{KindAvailability, AvailabilityScope, true},
		{KindAvailability, testOrg, false},
		{DocumentKind("licence"), testOrg, false},
	}
	for _, tc := range cases {
		if err := ValidateDocumentScope(tc.kind, tc.scope); (err == nil) != tc.ok {
			t.Errorf("ValidateDocumentScope(%q, %q) = %v, want ok=%v", tc.kind, tc.scope, err, tc.ok)
		}
	}
}

func TestDocumentSigningMessageRefusesBadInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		version int64
		body    []byte
		want    error
	}{
		{"zero version", 0, []byte("x"), ErrDocumentVersion},
		{"empty body", 1, nil, ErrDocumentBody},
		{"oversized body", 1, make([]byte, MaxDocumentBody+1), ErrDocumentBody},
	}
	for _, tc := range cases {
		if _, err := DocumentSigningMessage(KindEntitlements, testOrg, tc.version, tc.body); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
