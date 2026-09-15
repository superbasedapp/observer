package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// signedTestResource builds a verifiable SignedPolicyResource envelope. body
// must be valid canonical JSON for family (policyfam's DecodeBody rejects
// unknown fields), or gate 4 (decode/compile) will reject it.
func signedTestResource(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, family string, version int64, body string, caps []string) orgcontract.SignedPolicyResource {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	r := orgcontract.SignedPolicyResource{
		ID:                   "default",
		Version:              version,
		Family:               family,
		CompilerVersion:      "v1",
		Body:                 body,
		BodyHash:             hex.EncodeToString(sum[:]),
		RequiredCapabilities: caps,
		SelectorsJSON:        "{}",
		PublicKey:            base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:             "2026-08-12T00:00:00Z",
	}
	sig, err := orgcontract.SignPolicyResource(priv, r)
	if err != nil {
		t.Fatalf("SignPolicyResource: %v", err)
	}
	r.Signature = sig
	return r
}

// policyResourceServer serves GET /api/agent/policy/{family} with a strong
// ETag over the resource's own signing-message digest (unlike
// policyBundleServer's version-only ETag, this lets a same-version,
// different-content republish produce a DIFFERENT ETag — the realistic
// shape needed to exercise the version_replay gate, since a stale client
// ETag would otherwise short-circuit to 304 before the digest comparison
// ever runs).
type policyResourceServer struct {
	srv       *httptest.Server
	resources map[string]*orgcontract.SignedPolicyResource // family -> resource; absent/nil = 404
	seen      []string
}

func newPolicyResourceServer(t *testing.T) *policyResourceServer {
	t.Helper()
	ps := &policyResourceServer{resources: map[string]*orgcontract.SignedPolicyResource{}}
	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		family := strings.TrimPrefix(r.URL.Path, "/api/agent/policy/")
		ps.seen = append(ps.seen, r.Header.Get("If-None-Match"))
		res := ps.resources[family]
		if res == nil {
			writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "no_policy_resource"})
			return
		}
		digest, err := orgcontract.PolicyResourceMessageDigest(*res)
		if err != nil {
			t.Fatalf("PolicyResourceMessageDigest: %v", err)
		}
		etag := `"` + digest + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		writeTestJSON(w, http.StatusOK, res)
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

// enrolledPRClient mirrors enrolledClient (policy_test.go) but returns a
// CacheDir for policy-resource options instead of a single bundle-cache
// file path. It also bumps the enrolment generation to 1, standing in for
// the Phase W wiring (not yet implemented) where Enroll itself calls
// store.BumpEnrolmentGeneration — FetchAndAcceptPolicyResource only READS
// the generation row (Phase A scope), so a client whose generation was
// never bumped would fetch under generation 0, which is a valid but
// untested-by-Phase-W state.
func enrolledPRClient(t *testing.T, srvURL string) (*Client, *store.Store, string) {
	t.Helper()
	s := newAgentStore(t)
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	if _, err := s.BumpEnrolmentGeneration(context.Background(), OrgKey(srvURL, "org-1"), false); err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	bs := &memBearerStore{bearer: "bearer-xyz"}
	return newTestClient(t, s, bs), s, t.TempDir()
}

const observeAdmissionBody = `{"mode":"observe"}`

const enforceAdmissionBody = `{"mode":"enforce"}`

// TestFetchAndAcceptPolicyResource_AppliedThenUnchanged is the happy path
// end to end: a verified resource is durably cached, the durable state row
// is upserted, and the second poll rides If-None-Match into a 304.
func TestFetchAndAcceptPolicyResource_AppliedThenUnchanged(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r1 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r1

	c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRApplied || res.Version != 1 || !res.EnforceAllowed {
		t.Fatalf("result = %+v, want applied v1 enforce-allowed (observe mode needs no preauth)", res)
	}
	raw, err := os.ReadFile(res.CachePath)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	var cached orgcontract.SignedPolicyResource
	if err := json.Unmarshal(raw, &cached); err != nil || cached.Version != 1 || cached.Body != observeAdmissionBody {
		t.Fatalf("cache mismatch: %+v err=%v", cached, err)
	}

	enr, err := s.LoadEnrolment(context.Background())
	if err != nil || enr == nil {
		t.Fatalf("LoadEnrolment: %+v %v", enr, err)
	}
	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := s.LoadEnrolmentGeneration(context.Background(), orgKey)
	if err != nil || !ok || gen.Generation != 1 {
		t.Fatalf("LoadEnrolmentGeneration = %+v ok=%v err=%v, want generation=1", gen, ok, err)
	}
	st, ok, err := s.LoadPolicyResourceState(context.Background(), orgKey, policyfamAdmissionInput)
	if err != nil || !ok || st.FloorVersion != 1 {
		t.Fatalf("LoadPolicyResourceState = %+v ok=%v err=%v, want floor=1", st, ok, err)
	}

	// Second poll: If-None-Match -> 304 -> unchanged, cache untouched.
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if res.Status != PRUnchanged {
		t.Fatalf("second result = %+v, want unchanged", res)
	}
	if len(ps.seen) != 2 || ps.seen[1] == "" {
		t.Errorf("If-None-Match not sent on second poll: %q", ps.seen)
	}
}

// TestFetchAndAcceptPolicyResource_VersionDowngradeRejected pins the
// monotonic version check: after applying v5, a validly signed v3 is
// rejected and the v5 cache/state survive untouched.
func TestFetchAndAcceptPolicyResource_VersionDowngradeRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r5 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 5, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r5

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	if res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts); err != nil || res.Status != PRApplied {
		t.Fatalf("apply v5: %+v err=%v", res, err)
	}

	r3 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 3, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r3
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("fetch v3: %v", err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectVersionDowngrade {
		t.Fatalf("result = %+v, want rejected/version_downgrade", res)
	}
	raw, rerr := os.ReadFile(filepath.Join(cacheDir, orgKeyForTest(t, c), "1", policyfamAdmissionInput+".json"))
	if rerr != nil {
		t.Fatalf("read cache: %v", rerr)
	}
	var cached orgcontract.SignedPolicyResource
	if err := json.Unmarshal(raw, &cached); err != nil || cached.Version != 5 {
		t.Errorf("cache no longer holds v5: %+v err=%v", cached, err)
	}
}

// TestFetchAndAcceptPolicyResource_VersionReplayRejected pins the P0-5
// equal-floor digest rule (plan §6.3/§6.5): a re-served envelope at the SAME
// version but DIFFERENT content (a non-monotonic republish) is rejected
// version_replay, and the durable state stays at the original content.
func TestFetchAndAcceptPolicyResource_VersionReplayRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r3a := signedTestResource(t, priv, pub, policyfamAdmissionInput, 3, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r3a

	c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	if res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts); err != nil || res.Status != PRApplied {
		t.Fatalf("apply v3a: %+v err=%v", res, err)
	}

	// Same version, DIFFERENT body -> different BodyHash/digest/ETag, so the
	// server does not 304 and the client actually re-verifies content.
	const altBody = `{"mode":"observe","strict":true}`
	r3b := signedTestResource(t, priv, pub, policyfamAdmissionInput, 3, altBody, nil)
	ps.resources[policyfamAdmissionInput] = &r3b

	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("fetch v3b: %v", err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectVersionReplay {
		t.Fatalf("result = %+v, want rejected/version_replay", res)
	}

	enr, _ := s.LoadEnrolment(context.Background())
	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	st, ok, err := s.LoadPolicyResourceState(context.Background(), orgKey, policyfamAdmissionInput)
	if err != nil || !ok || st.BodyHash != r3a.BodyHash {
		t.Fatalf("state after replay attempt = %+v ok=%v err=%v, want unchanged at r3a's hash", st, ok, err)
	}
}

// TestFetchAndAcceptPolicyResource_DeliveredUnaccepted pins plan §6.6: a
// family verified through every gate but NOT in accept_families is reported
// as delivered_unaccepted and NEVER cached.
func TestFetchAndAcceptPolicyResource_DeliveredUnaccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r1 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r1

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir} // accept_families empty
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRDeliveredUnaccepted {
		t.Fatalf("result = %+v, want delivered_unaccepted", res)
	}
	// W-2: the accept_families gate must report its OWN honest reject code,
	// distinct from the generic PRRejectCapabilityMismatch — the resource
	// verified fine, this node's own accept_families allow-list just doesn't
	// name it. MUTATION intent: reverting this call site back to
	// PRRejectCapabilityMismatch fails this assertion.
	if res.RejectCode != PRRejectFamilyNotAccepted {
		t.Fatalf("RejectCode = %q, want %q (W-2 honest reject code)", res.RejectCode, PRRejectFamilyNotAccepted)
	}
	if _, statErr := os.Stat(filepath.Join(cacheDir, orgKeyForTest(t, c), "1", policyfamAdmissionInput+".json")); !os.IsNotExist(statErr) {
		t.Error("unaccepted family must not be cached")
	}
}

// TestFetchAndAcceptPolicyResource_CapabilityMismatchRejected pins gate 5: a
// resource requiring a capability the runtime doesn't advertise is rejected
// outright (never cached, unlike the inert-but-cached not_preauthorized
// case) — the runtime literally cannot execute it.
func TestFetchAndAcceptPolicyResource_CapabilityMismatchRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r1 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, []string{"judge"})
	ps.resources[policyfamAdmissionInput] = &r1

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}} // LiveCapabilities nil
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectCapabilityMismatch {
		t.Fatalf("result = %+v, want rejected/capability_mismatch", res)
	}
	if _, statErr := os.Stat(filepath.Join(cacheDir, orgKeyForTest(t, c), "1", policyfamAdmissionInput+".json")); !os.IsNotExist(statErr) {
		t.Error("capability-mismatched resource must not be cached")
	}

	// Sanity: the SAME resource with the capability advertised applies clean.
	opts.LiveCapabilities = []string{"judge"}
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil || res.Status != PRApplied {
		t.Fatalf("apply with capability advertised: %+v err=%v", res, err)
	}
}

// TestFetchAndAcceptPolicyResource_ClosedEnvelopeViolationRejected pins
// gate 3 (v1's fixed closed envelope): an ID other than "default" is
// rejected even though the signature itself is perfectly valid over that
// non-default ID (the envelope is signed as submitted; the CLIENT enforces
// the v1 shape restriction).
func TestFetchAndAcceptPolicyResource_ClosedEnvelopeViolationRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	r.ID = "not-default"
	sig, err := orgcontract.SignPolicyResource(priv, r)
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	r.Signature = sig
	ps.resources[policyfamAdmissionInput] = &r

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectClosedEnvelope {
		t.Fatalf("result = %+v, want rejected/closed_envelope_violation", res)
	}
}

// TestFetchAndAcceptPolicyResource_SigInvalidAndKeyPinMismatch is the
// baseline gate-1/gate-2 rejection table, mirroring
// TestFetchPolicyBundle_Rejections for the unified-resource rail.
func TestFetchAndAcceptPolicyResource_SigInvalidAndKeyPinMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name       string
		resource   func(t *testing.T) orgcontract.SignedPolicyResource
		prePin     ed25519.PublicKey
		wantCode   PolicyResourceRejectCode
		wantDetail string
	}{
		{
			name: "tampered body breaks the signature",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				r := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
				r.Body = `{"mode":"enforce"}` // BodyHash now stale -> VerifyPolicyResource fails
				return r
			},
			wantCode:   PRRejectSigInvalid,
			wantDetail: "signature verification failed",
		},
		{
			name: "key does not match the enrolment pin",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				return signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
			},
			prePin:   otherPub,
			wantCode: PRRejectKeyPinMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyResourceServer(t)
			r := tc.resource(t)
			ps.resources[policyfamAdmissionInput] = &r
			c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
			if tc.prePin != nil {
				enr, _ := s.LoadEnrolment(context.Background())
				if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
					Layer: "org", Path: PolicyKeyPinPath(enr.OrgServerURL),
					ContentHash: orgcontract.PublicKeyPinHash(tc.prePin),
					LoadedAt:    time.Now().UTC(),
				}); err != nil {
					t.Fatalf("pre-pin: %v", err)
				}
			}
			opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
			res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
			if err != nil {
				t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
			}
			if res.Status != PRRejected || res.RejectCode != tc.wantCode {
				t.Fatalf("result = %+v, want rejected/%s", res, tc.wantCode)
			}
			if tc.wantDetail != "" && !strings.Contains(res.Detail, tc.wantDetail) {
				t.Fatalf("Detail = %q, want substring %q", res.Detail, tc.wantDetail)
			}
		})
	}
}

// TestFetchAndAcceptPolicyResource_AppliedInertNotPreauthorized pins the
// preauthorization gate distinguishing capability_mismatch (outright reject)
// from not_preauthorized (accepted, CACHED, but flagged non-enforceable): a
// body requesting "enforce" mode for a family NOT in preauthorize_enforce
// installs applied_inert.
func TestFetchAndAcceptPolicyResource_AppliedInertNotPreauthorized(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, enforceAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}} // PreauthorizeEnforce empty
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRAppliedInert || res.EnforceAllowed || res.InertReason != "not_preauthorized" {
		t.Fatalf("result = %+v, want applied_inert/not_preauthorized/EnforceAllowed=false", res)
	}
	if _, statErr := os.Stat(res.CachePath); statErr != nil {
		t.Fatalf("applied_inert must still be cached: %v", statErr)
	}

	// Sanity: preauthorizing the family flips it to fully applied.
	opts.PreauthorizeEnforce = []string{policyfamAdmissionInput}
	r2 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 2, enforceAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r2
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil || res.Status != PRApplied || !res.EnforceAllowed {
		t.Fatalf("preauthorized apply: %+v err=%v", res, err)
	}
}

// TestFetchAndAcceptPolicyResource_NoneAndAuth covers the non-200 statuses.
func TestFetchAndAcceptPolicyResource_NoneAndAuth(t *testing.T) {
	ps := newPolicyResourceServer(t) // no resources -> 404
	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("404 fetch: %v", err)
	}
	if res.Status != PRNone {
		t.Fatalf("result = %+v, want none", res)
	}

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer_invalid"})
	}))
	defer authSrv.Close()
	c2, _, cacheDir2 := enrolledPRClient(t, authSrv.URL)
	if _, err := c2.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, PolicyResourceOptions{CacheDir: cacheDir2}); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("401 fetch err = %v, want ErrAuthFailed", err)
	}
}

// TestFetchAndAcceptPolicyResource_NotEnrolled pins the idle path.
func TestFetchAndAcceptPolicyResource_NotEnrolled(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	_, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, PolicyResourceOptions{CacheDir: t.TempDir()})
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

// TestFetchAndAcceptPolicyResource_UnsupportedFamily pins the input-
// validation guard: a family outside the v1 closed set is a programmer
// error (hard error), never silently treated as delivered_unaccepted.
func TestFetchAndAcceptPolicyResource_UnsupportedFamily(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	_, err := c.FetchAndAcceptPolicyResource(context.Background(), "not.a.family", PolicyResourceOptions{CacheDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "unsupported family") {
		t.Fatalf("err = %v, want unsupported-family error", err)
	}
}

// TestFetchAndAcceptPolicyResource_NoGenerationRowYet pins the fail-closed
// posture (plan §6.9 / R6-B2): an enrolled client whose generation was
// NEVER bumped (LoadEnrolmentGeneration ok=false) must NOT fetch/install
// under a synthetic generation 0 — missing generation ≡ not enrolled.
func TestFetchAndAcceptPolicyResource_NoGenerationRowYet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r

	s := newAgentStore(t)
	srvURL := ps.srv.URL
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	cacheDir := t.TempDir()
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v (result=%+v), want ErrNotEnrolled when generation row is missing", err, res)
	}
}

// TestOrgKey_ScopedByURLAndOrgID pins plan §6.2: the enrolment-identity key
// is a function of BOTH the org URL and the org id, normalized the same way
// Enroll normalizes the URL, so two organisations at one control-plane URL
// never collide.
func TestOrgKey_ScopedByURLAndOrgID(t *testing.T) {
	base := OrgKey("https://org.example", "org-1")
	if got := OrgKey("https://org.example/", "org-1"); got != base {
		t.Errorf("trailing slash changed the key: %q vs %q", got, base)
	}
	if got := OrgKey("  https://org.example  ", "org-1"); got != base {
		t.Errorf("whitespace changed the key: %q vs %q", got, base)
	}
	if got := OrgKey("https://org.example", "org-2"); got == base {
		t.Error("different org id produced the SAME key — two orgs at one URL would share replay floors")
	}
	if got := OrgKey("https://other.example", "org-1"); got == base {
		t.Error("different org URL produced the SAME key")
	}
}

// TestClassifyPolicyResourceFetch_Total mirrors TestGuardFetchOutcomeIsTotal
// for the unified-resource rail: every input maps to exactly one state.
// context.Canceled skips; ErrNotEnrolled emits Cleared (Codex SF4).
func TestClassifyPolicyResourceFetch_Total(t *testing.T) {
	cases := []struct {
		name     string
		res      PolicyResourceResult
		err      error
		want     PolicyResourceFetchOutcome
		wantEmit bool
	}{
		{"context canceled skips", PolicyResourceResult{}, context.Canceled, PolicyResourceFetchOutcome{}, false},
		{"not enrolled clears", PolicyResourceResult{}, ErrNotEnrolled, PolicyResourceFetchOutcome{Cleared: true}, true},
		{"auth failed reached", PolicyResourceResult{}, fmt.Errorf("x: %w", ErrAuthFailed), PolicyResourceFetchOutcome{AuthFailed: true, Reached: true}, true},
		{"transport unreachable not reached", PolicyResourceResult{}, fmt.Errorf("x: %w", errPolicyResourceTransport), PolicyResourceFetchOutcome{Unreachable: true}, true},
		{"reached-other indeterminate reached", PolicyResourceResult{}, fmt.Errorf("x: %w", errPolicyResourceIndeterminate), PolicyResourceFetchOutcome{Indeterminate: true, Reached: true}, true},
		{"unclassified error is indeterminate", PolicyResourceResult{}, errors.New("boom"), PolicyResourceFetchOutcome{Indeterminate: true}, true},
		{"applied ok reached", PolicyResourceResult{Status: PRApplied, Version: 5}, nil, PolicyResourceFetchOutcome{OK: true, Reached: true, Version: 5}, true},
		{"rejected ok+code", PolicyResourceResult{Status: PRRejected, RejectCode: PRRejectVersionReplay, Version: 3}, nil, PolicyResourceFetchOutcome{OK: true, Reached: true, RejectCode: PRRejectVersionReplay, Version: 3}, true},
		{"none ok reached", PolicyResourceResult{Status: PRNone}, nil, PolicyResourceFetchOutcome{OK: true, Reached: true}, true},
		{"unchanged ok reached", PolicyResourceResult{Status: PRUnchanged}, nil, PolicyResourceFetchOutcome{OK: true, Reached: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, emit := ClassifyPolicyResourceFetch(tc.res, tc.err)
			if emit != tc.wantEmit {
				t.Fatalf("emit = %v, want %v", emit, tc.wantEmit)
			}
			if !emit {
				return
			}
			if got != tc.want {
				t.Fatalf("outcome = %+v, want %+v", got, tc.want)
			}
			n := 0
			for _, b := range []bool{got.OK, got.Unreachable, got.AuthFailed, got.Indeterminate, got.Cleared} {
				if b {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("outcome asserts %d states, want exactly 1: %+v", n, got)
			}
		})
	}
}

// policyfamAdmissionInput duplicates internal/policyfam.FamilyAdmissionInput
// as a literal so this test file doesn't need to import policyfam only for a
// string constant (matches the family-enum duplication convention documented
// on policyfam.SupportedFamilies).
const policyfamAdmissionInput = "admission.input"

// orgKeyForTest resolves the OrgKey for c's (single, test-seeded) enrolment,
// for tests that need to build the exact generation-scoped cache path
// independently of the client's own internals.
func orgKeyForTest(t *testing.T, c *Client) string {
	t.Helper()
	enr, err := c.store.LoadEnrolment(context.Background())
	if err != nil || enr == nil {
		t.Fatalf("LoadEnrolment: %+v %v", enr, err)
	}
	return OrgKey(enr.OrgServerURL, enr.OrgID)
}

// TestFetchAndAcceptPolicyResource_ConcurrentTOFUPinSingleWinner is the
// end-to-end half of the B-B6 regression proof (the store-layer half is
// store.TestEstablishOrgPolicyKeyPin_ConcurrentSingleWinner): N concurrent
// first-fetches against ONE unpinned agent, served an envelope signed by
// one of TWO different org keys, must converge on a single pin — and every
// accept that PROCEEDED must have verified against that pin, with every
// other accept refused key_pin_mismatch. Before the fix, each racer read
// "no pin", appended its OWN key, and proceeded: two different signing keys
// could both install policy on the same node.
//
// The server holds every response until all N requests have arrived, so the
// racers reach the pin gate together rather than sequentially. Run with
// -race.
func TestFetchAndAcceptPolicyResource_ConcurrentTOFUPinSingleWinner(t *testing.T) {
	const n = 12
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	hashA := orgcontract.PublicKeyPinHash(pubA)
	hashB := orgcontract.PublicKeyPinHash(pubB)

	var mu sync.Mutex
	arrived := 0
	servedByKeyHash := map[string]int{}
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		// Alternate the signing key so both candidates race for the pin.
		res := signedTestResource(t, privA, pubA, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
		keyHash := hashA
		if arrived%2 == 1 {
			res = signedTestResource(t, privB, pubB, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
			keyHash = hashB
		}
		servedByKeyHash[keyHash]++
		arrived++
		if arrived == n {
			close(release)
		}
		mu.Unlock()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		writeTestJSON(w, http.StatusOK, res)
	}))
	defer srv.Close()

	c, s, cacheDir := enrolledPRClient(t, srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}

	results := make([]PolicyResourceResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
		}(i)
	}
	wg.Wait()

	pin := orgStateRow(t, s, PolicyKeyPinPath(srv.URL))
	if pin == nil {
		t.Fatal("no key pin recorded after the race")
	}
	winner := pin.ContentHash
	if winner != hashA && winner != hashB {
		t.Fatalf("pinned hash %q is neither served key", winner)
	}
	loser := hashA
	if winner == hashA {
		loser = hashB
	}

	proceeded, refused := 0, 0
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: FetchAndAcceptPolicyResource: %v", i, errs[i])
		}
		switch res.Status {
		case PRApplied, PRAppliedInert, PRUnchanged:
			proceeded++
		case PRRejected:
			if res.RejectCode != PRRejectKeyPinMismatch {
				t.Fatalf("goroutine %d: rejected %s (%s), want key_pin_mismatch", i, res.RejectCode, res.Detail)
			}
			refused++
		default:
			t.Fatalf("goroutine %d: unexpected status %s (%s)", i, res.Status, res.Detail)
		}
	}
	mu.Lock()
	wonServed, lostServed := servedByKeyHash[winner], servedByKeyHash[loser]
	mu.Unlock()
	// The load-bearing assertion: the set of accepts that proceeded is
	// EXACTLY the set served the pinned key. Any racer that proceeded on the
	// other key would break this equality.
	if proceeded != wonServed {
		t.Fatalf("proceeded = %d but %d requests were served the pinned key %q (an accept verified against a key that is not the pin)",
			proceeded, wonServed, winner)
	}
	if refused != lostServed {
		t.Fatalf("refused = %d, want %d (every non-pinned-key delivery must be refused)", refused, lostServed)
	}
	if wonServed == 0 || lostServed == 0 {
		t.Fatalf("degenerate race: served won=%d lost=%d — both keys must reach the pin gate", wonServed, lostServed)
	}
	// The cached envelope on disk must be the winner's, not a loser's.
	cachePath := filepath.Join(cacheDir, OrgKey(srv.URL, "org-1"), "1", policyfamAdmissionInput+".json")
	raw, rerr := os.ReadFile(cachePath)
	if rerr != nil {
		t.Fatalf("read cache: %v", rerr)
	}
	var cached orgcontract.SignedPolicyResource
	if uerr := json.Unmarshal(raw, &cached); uerr != nil {
		t.Fatalf("decode cache: %v", uerr)
	}
	cachedPub, verr := orgcontract.VerifyPolicyResource(cached)
	if verr != nil {
		t.Fatalf("verify cached envelope: %v", verr)
	}
	if got := orgcontract.PublicKeyPinHash(cachedPub); got != winner {
		t.Fatalf("cached envelope signed by %q, want the pinned key %q", got, winner)
	}
}

// TestFetchAndAcceptPolicyResource_KeyPinEstablishment is the sequential
// companion to the concurrent proof above: the three pin states an accept
// can meet (absent / already pinned to the same key / already pinned to a
// different key) must resolve to establish-and-apply, apply-without-
// re-pinning, and refuse-without-overwriting respectively. The pin the node
// ends up with is asserted in every arm — a rejected accept must leave the
// established pin exactly as it was.
func TestFetchAndAcceptPolicyResource_KeyPinEstablishment(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyHash := orgcontract.PublicKeyPinHash(pub)
	otherHash := orgcontract.PublicKeyPinHash(otherPub)

	cases := []struct {
		name       string
		prePin     string // "" = no pin established yet
		wantStatus PolicyResourceStatus
		wantCode   PolicyResourceRejectCode
		wantPin    string
	}{
		{name: "pin absent — TOFU establishes and applies", prePin: "", wantStatus: PRApplied, wantPin: keyHash},
		{name: "pin already established, same key — applies", prePin: keyHash, wantStatus: PRApplied, wantPin: keyHash},
		{name: "pin already established, different key — refused", prePin: otherHash, wantStatus: PRRejected, wantCode: PRRejectKeyPinMismatch, wantPin: otherHash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ps := newPolicyResourceServer(t)
			r := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
			ps.resources[policyfamAdmissionInput] = &r
			c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
			if tc.prePin != "" {
				pinned, established, err := s.EstablishOrgPolicyKeyPin(ctx, PolicyKeyPinPath(ps.srv.URL), tc.prePin, railPinProvenance)
				if err != nil || !established || pinned != tc.prePin {
					t.Fatalf("pre-pin: pinned=%q established=%v err=%v", pinned, established, err)
				}
			}
			res, err := c.FetchAndAcceptPolicyResource(ctx, policyfamAdmissionInput,
				PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}})
			if err != nil {
				t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
			}
			if res.Status != tc.wantStatus || res.RejectCode != tc.wantCode {
				t.Fatalf("result = %s/%s (%s), want %s/%s", res.Status, res.RejectCode, res.Detail, tc.wantStatus, tc.wantCode)
			}
			row := orgStateRow(t, s, PolicyKeyPinPath(ps.srv.URL))
			if row == nil || row.ContentHash != tc.wantPin {
				t.Fatalf("pin row = %+v, want content_hash %q", row, tc.wantPin)
			}
		})
	}
}

// TestMaybeKickPolicyResourceFetch pins the push-ack propagation-nudge
// semantics (2026-09-01): the first acknowledgment after boot never kicks
// (the poll loop's immediate first fetch covers it), a version advance kicks
// exactly once (buffered-1 coalescing), an unchanged or absent map never
// kicks, and a malformed body is ignored.
func TestMaybeKickPolicyResourceFetch(t *testing.T) {
	c := New(config.OrgClientConfig{}, nil, nil, "test", nil, nil)

	kicked := func() bool {
		select {
		case <-c.policyResourceKick:
			return true
		default:
			return false
		}
	}

	c.maybeKickPolicyResourceFetch([]byte(`{"policy_versions":{"admission.input":7}}`))
	if kicked() {
		t.Fatal("first ack after boot must not kick")
	}
	c.maybeKickPolicyResourceFetch([]byte(`{"policy_versions":{"admission.input":7}}`))
	if kicked() {
		t.Fatal("unchanged versions must not kick")
	}
	c.maybeKickPolicyResourceFetch([]byte(`{"policy_versions":{"admission.input":8}}`))
	if !kicked() {
		t.Fatal("a version advance must kick")
	}
	c.maybeKickPolicyResourceFetch([]byte(`{"policy_versions":{"admission.input":8,"node.features":1}}`))
	if !kicked() {
		t.Fatal("a new family appearing must kick")
	}
	c.maybeKickPolicyResourceFetch([]byte(`not json`))
	if kicked() {
		t.Fatal("malformed body must not kick")
	}
	c.maybeKickPolicyResourceFetch([]byte(`{"accepted_rows":3}`))
	if kicked() {
		t.Fatal("an ack without policy_versions must not kick")
	}
}
