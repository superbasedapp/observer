package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// signedTestBundle builds a verifiable envelope around bundleTOML.
func signedTestBundle(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, bundleTOML string) orgcontract.PolicyBundle {
	t.Helper()
	return orgcontract.PolicyBundle{
		Version:    version,
		BundleTOML: bundleTOML,
		Signature:  orgcontract.SignPolicyBundle(priv, version, []byte(bundleTOML)),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:   "2026-06-11T09:00:00Z",
	}
}

// policyBundleServer serves GET /api/v1/policy-bundle with ETag/304
// semantics over a mutable bundle pointer (nil = 404). It records the
// If-None-Match values it saw.
type policyBundleServer struct {
	srv    *httptest.Server
	bundle *orgcontract.PolicyBundle
	seen   []string
	hits   chan struct{}
}

func newPolicyBundleServer(t *testing.T) *policyBundleServer {
	t.Helper()
	ps := &policyBundleServer{hits: make(chan struct{}, 64)}
	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case ps.hits <- struct{}{}:
		default:
		}
		ps.seen = append(ps.seen, r.Header.Get("If-None-Match"))
		if ps.bundle == nil {
			writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "no_policy_bundle"})
			return
		}
		etag := `"pb-v` + string(rune('0'+ps.bundle.Version)) + `"`
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		writeTestJSON(w, http.StatusOK, ps.bundle)
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

// enrolledClient returns a Client whose store carries an enrolment row
// pointing at srvURL plus a loaded bearer, and a cache path under a
// temp dir.
func enrolledClient(t *testing.T, srvURL string) (*Client, *store.Store, string) {
	t.Helper()
	s := newAgentStore(t)
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	bs := &memBearerStore{bearer: "bearer-xyz"}
	return newTestClient(t, s, bs), s, filepath.Join(t.TempDir(), "org-policy-bundle.json")
}

// orgStateRow returns the latest guard_policy_state row for (org, path),
// or nil.
func orgStateRow(t *testing.T, s *store.Store, path string) *store.GuardPolicyStateRow {
	t.Helper()
	states, err := s.LatestGuardPolicyStates(context.Background())
	if err != nil {
		t.Fatalf("LatestGuardPolicyStates: %v", err)
	}
	for i := range states {
		if states[i].Layer == "org" && states[i].Path == path {
			return &states[i]
		}
	}
	return nil
}

const escalatingTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n"

// TestFetchPolicyBundle_AppliedThenUnchanged covers the happy path end
// to end: a verified bundle is cached atomically, the TOFU key pin and
// the version row land in guard_policy_state, the ETag persists, and
// the second poll rides If-None-Match into a 304.
func TestFetchPolicyBundle_AppliedThenUnchanged(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyBundleServer(t)
	b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
	ps.bundle = &b

	c, s, cachePath := enrolledClient(t, ps.srv.URL)
	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("FetchPolicyBundle: %v", err)
	}
	if res.Status != PolicyApplied || res.Version != 3 {
		t.Fatalf("result = %+v, want applied v3", res)
	}

	// Cache holds the envelope verbatim.
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	var cached orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &cached); err != nil || cached.Version != 3 || cached.BundleTOML != escalatingTOML {
		t.Fatalf("cache mismatch: %+v err=%v", cached, err)
	}

	// TOFU pin row + bundle version row.
	pin := orgStateRow(t, s, PolicyKeyPinPath(ps.srv.URL))
	if pin == nil || pin.ContentHash != orgcontract.PublicKeyPinHash(pub) {
		t.Fatalf("key pin row = %+v, want hash of the served key", pin)
	}
	st := orgStateRow(t, s, ps.srv.URL+"/api/v1/policy-bundle")
	if st == nil || st.Version != "3" || st.Signature != b.Signature {
		t.Fatalf("bundle state row = %+v, want version 3 + signature", st)
	}

	// Second poll: If-None-Match → 304 → unchanged.
	res, err = c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if res.Status != PolicyUnchanged {
		t.Fatalf("second result = %+v, want unchanged", res)
	}
	if len(ps.seen) != 2 || ps.seen[1] == "" {
		t.Errorf("If-None-Match not sent on second poll: %q", ps.seen)
	}
}

// TestFetchPolicyBundle_Rejections is the acceptance-gate table: each
// failing gate yields PolicyRejected with a naming detail, writes NO
// cache, and never errors (rejection is a result the caller turns into
// R-205).
func TestFetchPolicyBundle_Rejections(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name       string
		bundle     func(t *testing.T) orgcontract.PolicyBundle
		prePin     ed25519.PublicKey // pre-recorded enrolment pin (nil = none)
		wantDetail string
	}{
		{
			name: "tampered body breaks the signature",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
				b.BundleTOML += "# evil\n"
				return b
			},
			wantDetail: "signature verification failed",
		},
		{
			name: "key does not match the enrolment pin",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				return signedTestBundle(t, priv, pub, 3, escalatingTOML)
			},
			prePin:     otherPub,
			wantDetail: "does not match the enrolment pin",
		},
		{
			name: "floor-violating TOML fails the org lint",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				return signedTestBundle(t, priv, pub, 3, "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n")
			},
			wantDetail: "does not lint as an org policy file",
		},
		{
			// GUARD-FWD-1 boundary: an unknown KEY is tolerated (see
			// TestFetchPolicyBundle_UnknownKeyIsAcceptedWithNotes), but a
			// genuinely bad rule id is still fatal — the consumer gate
			// dropped the unknown-key report, not the real checks.
			name: "override on an unknown rule id is still fatal",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				return signedTestBundle(t, priv, pub, 3, "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n")
			},
			wantDetail: "does not lint as an org policy file",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyBundleServer(t)
			b := tc.bundle(t)
			ps.bundle = &b
			c, s, cachePath := enrolledClient(t, ps.srv.URL)
			if tc.prePin != nil {
				if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
					Layer: "org", Path: PolicyKeyPinPath(ps.srv.URL),
					ContentHash: orgcontract.PublicKeyPinHash(tc.prePin),
					LoadedAt:    time.Now().UTC(),
				}); err != nil {
					t.Fatalf("pre-pin: %v", err)
				}
			}
			res, err := c.FetchPolicyBundle(context.Background(), cachePath)
			if err != nil {
				t.Fatalf("FetchPolicyBundle: %v", err)
			}
			if res.Status != PolicyRejected || !strings.Contains(res.Detail, tc.wantDetail) {
				t.Fatalf("result = %+v, want rejected with %q", res, tc.wantDetail)
			}
			if _, serr := os.Stat(cachePath); !os.IsNotExist(serr) {
				t.Error("rejected bundle must not be cached")
			}
		})
	}
}

// TestFetchPolicyBundle_VersionRegression pins gate 3: after applying
// v5, a served (validly signed) v3 is rejected and the v5 cache stays.
func TestFetchPolicyBundle_VersionRegression(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyBundleServer(t)
	v5 := signedTestBundle(t, priv, pub, 5, escalatingTOML)
	ps.bundle = &v5

	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied {
		t.Fatalf("apply v5: %+v err=%v", res, err)
	}

	v3 := signedTestBundle(t, priv, pub, 3, escalatingTOML)
	ps.bundle = &v3
	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("fetch v3: %v", err)
	}
	if res.Status != PolicyRejected || !strings.Contains(res.Detail, "version regression") {
		t.Fatalf("result = %+v, want version-regression rejection", res)
	}
	var cached orgcontract.PolicyBundle
	raw, _ := os.ReadFile(cachePath)
	if err := json.Unmarshal(raw, &cached); err != nil || cached.Version != 5 {
		t.Errorf("cache no longer holds v5: %+v err=%v", cached, err)
	}
}

// TestFetchPolicyBundle_NoBundleAndAuth covers the non-200 statuses:
// 404 → PolicyNone (old server / nothing published; an existing cache
// stays), 401 → ErrAuthFailed.
func TestFetchPolicyBundle_NoBundleAndAuth(t *testing.T) {
	ps := newPolicyBundleServer(t) // bundle nil → 404
	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("404 fetch: %v", err)
	}
	if res.Status != PolicyNone {
		t.Fatalf("result = %+v, want none", res)
	}

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer_invalid"})
	}))
	defer authSrv.Close()
	c2, _, cache2 := enrolledClient(t, authSrv.URL)
	if _, err := c2.FetchPolicyBundle(context.Background(), cache2); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("401 fetch err = %v, want ErrAuthFailed", err)
	}
}

// TestFetchPolicyBundle_ReachedCorruptBodyIsIndeterminateNotUnreachable pins
// Blocker 1 (R5-B5/R5-B3): a 200 that PROVES the control plane answered but
// whose body fails to decode must classify as reached-Indeterminate, never
// transport Unreachable — the generated WithResponse parser's (nil, err) on a
// body-read/json.Unmarshal failure for a RECEIVED body was the root cause this
// pins against a regression. Sibling assertions on the same table drive a
// genuine transport failure (closed server -> Unreachable/not-reached), 401
// (-> AuthFailed/reached), and 404 (-> OK/reached, none published).
func TestFetchPolicyBundle_ReachedCorruptBodyIsIndeterminateNotUnreachable(t *testing.T) {
	malformedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version": 3, "bundle_toml": `)) // truncated/malformed JSON
	}))
	defer malformedSrv.Close()

	unreachableSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachableSrv.Close() // closed before use: connections to it refuse

	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "bearer_invalid"})
	}))
	defer authSrv.Close()

	noneSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "no_policy_bundle"})
	}))
	defer noneSrv.Close()

	cases := []struct {
		name    string
		srvURL  string
		want    GuardFetchOutcome
		wantErr bool // whether FetchPolicyBundle itself returns a non-nil error
	}{
		{"reached corrupt body is Indeterminate reached, NOT Unreachable", malformedSrv.URL, GuardFetchOutcome{Indeterminate: true, Reached: true}, true},
		{"genuine transport failure is Unreachable, not reached", unreachableSrv.URL, GuardFetchOutcome{Unreachable: true, Reached: false}, true},
		{"401 is AuthFailed, reached", authSrv.URL, GuardFetchOutcome{AuthFailed: true, Reached: true}, true},
		{"404 is OK, reached (none published)", noneSrv.URL, GuardFetchOutcome{OK: true, Reached: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, cachePath := enrolledClient(t, tc.srvURL)
			res, err := c.FetchPolicyBundle(context.Background(), cachePath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FetchPolicyBundle err = %v, wantErr = %v", err, tc.wantErr)
			}
			got, emit := classifyGuardFetch(res, err)
			if !emit {
				t.Fatalf("classifyGuardFetch did not emit for %+v / %v", res, err)
			}
			if got != tc.want {
				t.Fatalf("outcome = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestFetchPolicyBundle_NotEnrolled pins the idle path.
func TestFetchPolicyBundle_NotEnrolled(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	if _, err := c.FetchPolicyBundle(context.Background(), filepath.Join(t.TempDir(), "b.json")); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

// TestPolicyPollLoop_ImmediateFirstFetch pins the §14.2 "on observer
// start" half: the loop fetches once BEFORE the first interval wait
// (interval here is an hour — only the immediate cycle can be the one
// that lands) and reports through onResult.
func TestPolicyPollLoop_ImmediateFirstFetch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyBundleServer(t)
	b := signedTestBundle(t, priv, pub, 1, escalatingTOML)
	ps.bundle = &b

	c, _, cachePath := enrolledClient(t, ps.srv.URL)
	results := make(chan PolicyResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.PolicyPollLoop(ctx, cachePath, func(r PolicyResult) {
			select {
			case results <- r:
			default:
			}
		})
	}()
	select {
	case r := <-results:
		if r.Status != PolicyApplied || r.Version != 1 {
			t.Fatalf("first poll result = %+v, want applied v1", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("immediate first fetch never happened")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("loop returned %v, want context.Canceled", err)
	}
}

// TestRejectCodeSetAtEachGate pins that EACH of the four §14.2 acceptance
// gates records its matching typed PolicyRejectCode on the delivered-rejected
// PolicyResult (P0-6 §2.5). Dropping a gate's RejectCode assignment makes that
// case's RejectCode empty (RejectNone), which fails here — the mutation proof.
func TestRejectCodeSetAtEachGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	single := []struct {
		name     string
		bundle   func(t *testing.T) orgcontract.PolicyBundle
		prePin   ed25519.PublicKey
		wantCode PolicyRejectCode
	}{
		{
			name: "gate 1 signature -> sig_invalid",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				b := signedTestBundle(t, priv, pub, 3, escalatingTOML)
				b.BundleTOML += "# evil\n"
				return b
			},
			wantCode: RejectSigInvalid,
		},
		{
			name: "gate 2 key pin -> key_pin_mismatch",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				return signedTestBundle(t, priv, pub, 3, escalatingTOML)
			},
			prePin:   otherPub,
			wantCode: RejectKeyPinMismatch,
		},
		{
			name: "gate 4 lint -> lint_failed",
			bundle: func(t *testing.T) orgcontract.PolicyBundle {
				return signedTestBundle(t, priv, pub, 3, "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n")
			},
			wantCode: RejectLintFailed,
		},
	}
	for _, tc := range single {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyBundleServer(t)
			b := tc.bundle(t)
			ps.bundle = &b
			c, s, cachePath := enrolledClient(t, ps.srv.URL)
			if tc.prePin != nil {
				if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
					Layer: "org", Path: PolicyKeyPinPath(ps.srv.URL),
					ContentHash: orgcontract.PublicKeyPinHash(tc.prePin),
					LoadedAt:    time.Now().UTC(),
				}); err != nil {
					t.Fatalf("pre-pin: %v", err)
				}
			}
			res, err := c.FetchPolicyBundle(context.Background(), cachePath)
			if err != nil {
				t.Fatalf("FetchPolicyBundle: %v", err)
			}
			if res.Status != PolicyRejected {
				t.Fatalf("status = %v, want rejected", res.Status)
			}
			if res.RejectCode != tc.wantCode {
				t.Fatalf("RejectCode = %q, want %q (dropping the gate's code fails here)", res.RejectCode, tc.wantCode)
			}
		})
	}

	t.Run("gate 3 version downgrade -> version_downgrade", func(t *testing.T) {
		ps := newPolicyBundleServer(t)
		v5 := signedTestBundle(t, priv, pub, 5, escalatingTOML)
		ps.bundle = &v5
		c, _, cachePath := enrolledClient(t, ps.srv.URL)
		if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied {
			t.Fatalf("apply v5: %+v err=%v", res, err)
		}
		v3 := signedTestBundle(t, priv, pub, 3, escalatingTOML)
		ps.bundle = &v3
		res, err := c.FetchPolicyBundle(context.Background(), cachePath)
		if err != nil {
			t.Fatalf("fetch v3: %v", err)
		}
		if res.Status != PolicyRejected || res.RejectCode != RejectVersionDowngrade {
			t.Fatalf("result = %+v, want rejected/version_downgrade", res)
		}
	})
}

// countGuardStates returns how many mutually-exclusive top-level states the
// outcome asserts. Exactly one must hold for any emitted guard outcome
// (RejectCode is a sub-qualifier of OK for the guard rail, never its own state).
func countGuardStates(o GuardFetchOutcome) int {
	n := 0
	for _, b := range []bool{o.OK, o.Unreachable, o.AuthFailed, o.Indeterminate} {
		if b {
			n++
		}
	}
	return n
}

// TestGuardFetchOutcomeIsTotal drives classifyGuardFetch directly (P0-6 §2.5c /
// §7.1): FetchPolicyBundle classifies AT THE SOURCE via typed sentinels, so a
// LOCAL pin-read/cache/decode error maps to Indeterminate — NEVER Unreachable
// (inferring the outcome from a bare error would make the local case
// stale_lkg, R4-B2). Success/reject/unreachable/auth/indeterminate map
// distinctly, Reached is correct, and every input maps to exactly one state.
func TestGuardFetchOutcomeIsTotal(t *testing.T) {
	cases := []struct {
		name     string
		res      PolicyResult
		err      error
		want     GuardFetchOutcome
		wantEmit bool
	}{
		{"context canceled skips", PolicyResult{}, context.Canceled, GuardFetchOutcome{}, false},
		{"not enrolled skips", PolicyResult{}, ErrNotEnrolled, GuardFetchOutcome{}, false},
		{"idle skips", PolicyResult{}, errIdle, GuardFetchOutcome{}, false},
		{"auth failed reached", PolicyResult{}, fmt.Errorf("x: %w", ErrAuthFailed), GuardFetchOutcome{AuthFailed: true, Reached: true}, true},
		{"transport unreachable not reached", PolicyResult{}, fmt.Errorf("x: %w", errPolicyTransport), GuardFetchOutcome{Unreachable: true, Reached: false}, true},
		{"reached-other indeterminate reached", PolicyResult{}, fmt.Errorf("x: %w", errPolicyReachedIndeterminate), GuardFetchOutcome{Indeterminate: true, Reached: true}, true},
		{"local pre-response indeterminate NOT unreachable", PolicyResult{}, fmt.Errorf("x: %w", errPolicyLocalPreResponse), GuardFetchOutcome{Indeterminate: true, Reached: false}, true},
		{"unclassified error is local indeterminate", PolicyResult{}, errors.New("boom"), GuardFetchOutcome{Indeterminate: true, Reached: false}, true},
		{"accepted ok reached", PolicyResult{Status: PolicyApplied, Version: 5}, nil, GuardFetchOutcome{OK: true, Reached: true, Version: 5}, true},
		{"delivered-rejected ok+code", PolicyResult{Status: PolicyRejected, RejectCode: RejectSigInvalid, Version: 3}, nil, GuardFetchOutcome{OK: true, Reached: true, RejectCode: RejectSigInvalid, Version: 3}, true},
		{"none 404 ok reached", PolicyResult{Status: PolicyNone}, nil, GuardFetchOutcome{OK: true, Reached: true}, true},
		{"unchanged ok reached", PolicyResult{Status: PolicyUnchanged}, nil, GuardFetchOutcome{OK: true, Reached: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, emit := classifyGuardFetch(tc.res, tc.err)
			if emit != tc.wantEmit {
				t.Fatalf("emit = %v, want %v", emit, tc.wantEmit)
			}
			if !emit {
				return
			}
			if got != tc.want {
				t.Fatalf("outcome = %+v, want %+v", got, tc.want)
			}
			if n := countGuardStates(got); n != 1 {
				t.Fatalf("outcome asserts %d states, want exactly 1: %+v", n, got)
			}
			// Explicit anti-regression: a local pre-response error must never be Unreachable.
			if errors.Is(tc.err, errPolicyLocalPreResponse) && got.Unreachable {
				t.Fatal("local pre-response error classified Unreachable (R4-B2 regression)")
			}
		})
	}
}

// TestEnroll_PinsPolicyKey covers the enrol-time pin: a server that
// delivers org_policy_public_key gets its key hash recorded under the
// "#policy-key" guard_policy_state row.
func TestEnroll_PinsPolicyKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	s := newAgentStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
			OrgPolicyPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		})
	}))
	defer srv.Close()

	c := newTestClient(t, s, &memBearerStore{})
	if _, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	pin := orgStateRow(t, s, PolicyKeyPinPath(srv.URL))
	if pin == nil || pin.ContentHash != orgcontract.PublicKeyPinHash(pub) {
		t.Fatalf("pin row = %+v, want enrol-time key hash", pin)
	}
}

// writeCacheBundle writes a SIGNED bundle-cache envelope (the same shape
// FetchPolicyBundle atomically writes on accept) directly to path. The
// signature+pubkey are required because readCachedBundle re-verifies
// them (P0-7 SHOULD-FIX 1) before treating the cache as a reliable
// baseline.
func writeCacheBundle(t *testing.T, path string, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64, bundleTOML string) {
	t.Helper()
	b := signedTestBundle(t, priv, pub, version, bundleTOML)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal cache bundle: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write cache bundle: %v", err)
	}
}

// TestApplyBundleGates_EqualVersionGate pins the P0-7 B6/SF-B equal-version
// arm of applyBundleGates's gate 3 (§14.2): a re-served bundle at the SAME
// version as the last verified one (guard_policy_state) is compared against
// the verified CACHED ENVELOPE's content hash (readCachedBundle) — never the
// guard_policy_state row, whose hash-only dedup would give an unreliable
// baseline. Identical content is a no-op (PolicyUnchanged, CachedVersion
// set, no re-apply); different content is a non-monotonic republish
// (PolicyRejected, RejectVersionReplay). The higher/lower-version cases are
// regression guards proving the equal-version tightening left ordinary
// monotonic acceptance/rejection untouched, and the missing/corrupt-cache
// cases pin the documented fallback: no reliable baseline means fall
// through to gate 4 and re-materialise, never reject on a phantom mismatch.
func TestApplyBundleGates_EqualVersionGate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const orgURL = "https://org.example"
	const altTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n" +
		"[[override]]\nrule = \"R-111\"\ndecision = \"deny\"\nenforce = true\n"

	// Fixture sanity: escalatingTOML and altTOML must differ AND both must
	// lint clean as an org policy file, or the cases below aren't
	// exercising a genuine content-hash mismatch under gate 4's approval.
	if escalatingTOML == altTOML {
		t.Fatal("test fixture bug: escalatingTOML and altTOML must differ")
	}
	for _, toml := range []string{escalatingTOML, altTOML} {
		if problems := guard.Lint([]byte(toml), "org"); len(problems) > 0 {
			t.Fatalf("fixture TOML fails org lint: %v: %q", problems, toml)
		}
	}

	// setup seeds a fresh store with the signing key pinned (gate 2 passes
	// unconditionally) and, when lastVersion > 0, the last-verified-version
	// row applyBundleGates's lastBundleVersion reads for gate 3.
	setup := func(t *testing.T, lastVersion int64) (*Client, *store.Enrolment) {
		t.Helper()
		s := newAgentStore(t)
		c := newTestClient(t, s, &memBearerStore{})
		ctx := context.Background()
		if _, err := s.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
			Layer: "org", Path: PolicyKeyPinPath(orgURL),
			ContentHash: orgcontract.PublicKeyPinHash(pub),
			LoadedAt:    time.Now().UTC(),
		}); err != nil {
			t.Fatalf("pin key: %v", err)
		}
		if lastVersion > 0 {
			if _, err := s.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
				Layer: "org", Path: policyBundleStatePath(orgURL),
				Version:     strconv.FormatInt(lastVersion, 10),
				ContentHash: "irrelevant-to-gate3-the-cache-file-is-the-baseline",
				LoadedAt:    time.Now().UTC(),
			}); err != nil {
				t.Fatalf("record last version: %v", err)
			}
		}
		return c, &store.Enrolment{OrgServerURL: orgURL}
	}

	type want struct {
		handled       bool // applyBundleGates returned (result, true, nil): unchanged OR rejected
		status        PolicyStatus
		rejectCode    PolicyRejectCode
		cachedVersion int64
	}

	cases := []struct {
		name        string
		lastVersion int64
		cacheWrite  string // "valid" | "corrupt" | "none"
		cacheVer    int64
		cacheTOML   string
		servedVer   int64
		servedTOML  string
		want        want
	}{
		{
			// Catches: policy.go's `if ok && cachedVer == b.Version { if
			// incoming == cachedHash { return Unchanged } }` — reverting
			// this to unconditional accept turns handled=false (the
			// accept-fallthrough shape), failing this case.
			name:        "equal version, identical content -> unchanged (no re-apply), CachedVersion set",
			lastVersion: 3,
			cacheWrite:  "valid", cacheVer: 3, cacheTOML: escalatingTOML,
			servedVer: 3, servedTOML: escalatingTOML,
			want: want{handled: true, status: PolicyUnchanged, cachedVersion: 3},
		},
		{
			// Catches: the same accept-fallthrough regression, PLUS an
			// inverted hash comparison (== flipped to !=) or a wrong
			// RejectVersionReplay literal — either mutation flips this
			// case's status/RejectCode.
			name:        "equal version, different content -> rejected (version_replay)",
			lastVersion: 3,
			cacheWrite:  "valid", cacheVer: 3, cacheTOML: escalatingTOML,
			servedVer: 3, servedTOML: altTOML,
			want: want{handled: true, status: PolicyRejected, rejectCode: RejectVersionReplay},
		},
		{
			// Regression guard: proves the equal-version arm is gated on
			// `b.Version == lastVersion`, not `>=`. cacheTOML deliberately
			// differs from servedTOML (escalatingTOML vs altTOML) so a
			// mutant widening the guard to catch version>lastVersion too
			// would wrongly reject this as version_replay instead of
			// accepting it.
			name:        "higher version -> accepted (equal-version gate must not fire)",
			lastVersion: 3,
			cacheWrite:  "valid", cacheVer: 3, cacheTOML: escalatingTOML,
			servedVer: 4, servedTOML: altTOML,
			want: want{handled: false},
		},
		{
			// Regression guard on the pre-existing `if b.Version <
			// lastVersion` monotonic check: the equal-version tightening
			// must not have disturbed it.
			name:        "lower version -> rejected (version_downgrade, unchanged by the tightening)",
			lastVersion: 5,
			cacheWrite:  "none",
			servedVer:   3, servedTOML: escalatingTOML,
			want: want{handled: true, status: PolicyRejected, rejectCode: RejectVersionDowngrade},
		},
		{
			// Catches: readCachedBundle's ok=false (absent cache) being
			// treated as a mismatch/reject instead of "no reliable
			// baseline, fall through" — a mutation there would flip
			// handled to true/PolicyRejected.
			name:        "equal version, cache absent -> falls through to accept (re-materialise)",
			lastVersion: 3,
			cacheWrite:  "none",
			servedVer:   3, servedTOML: escalatingTOML,
			want: want{handled: false},
		},
		{
			// Same fallback, corrupt-JSON cache instead of a missing file
			// (readCachedBundle's json.Unmarshal error path, ok=false,
			// err=nil).
			name:        "equal version, cache corrupt -> falls through to accept (no reliable baseline)",
			lastVersion: 3,
			cacheWrite:  "corrupt",
			servedVer:   3, servedTOML: escalatingTOML,
			want: want{handled: false},
		},
		{
			// P0-7 BLOCKER 2: after an identical-content v1→v2 bump the
			// DB row stays at v1 (hash-only dedup suppresses the v2 row)
			// while the verified cache holds v2. A replayed signed v1
			// must REJECT as version_downgrade against the cache
			// baseline — not fall through and overwrite the v2 cache.
			// lastVersion seeds the DB at 1; cacheWrite puts v2 on disk.
			name:        "DB-suppressed v2 cache + replayed v1 -> rejected (version_downgrade)",
			lastVersion: 1,
			cacheWrite:  "valid", cacheVer: 2, cacheTOML: escalatingTOML,
			servedVer: 1, servedTOML: escalatingTOML,
			want: want{handled: true, status: PolicyRejected, rejectCode: RejectVersionDowngrade},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, enr := setup(t, tc.lastVersion)
			cachePath := filepath.Join(t.TempDir(), "org-policy-bundle.json")
			switch tc.cacheWrite {
			case "valid":
				writeCacheBundle(t, cachePath, priv, pub, tc.cacheVer, tc.cacheTOML)
			case "corrupt":
				if err := os.WriteFile(cachePath, []byte("{not valid json"), 0o600); err != nil {
					t.Fatalf("write corrupt cache: %v", err)
				}
			case "none":
				// cachePath intentionally left nonexistent.
			default:
				t.Fatalf("unknown cacheWrite %q", tc.cacheWrite)
			}

			b := signedTestBundle(t, priv, pub, tc.servedVer, tc.servedTOML)
			res, handled, err := c.applyBundleGates(context.Background(), b, enr, cachePath)
			if err != nil {
				t.Fatalf("applyBundleGates: %v", err)
			}
			if handled != tc.want.handled {
				t.Fatalf("handled = %v, want %v (res=%+v)", handled, tc.want.handled, res)
			}
			if !tc.want.handled {
				if res != (PolicyResult{}) {
					t.Fatalf("accept-fallthrough result = %+v, want zero value (caller proceeds to apply)", res)
				}
				return
			}
			if res.Status != tc.want.status {
				t.Fatalf("Status = %v, want %v (res=%+v)", res.Status, tc.want.status, res)
			}
			if res.RejectCode != tc.want.rejectCode {
				t.Fatalf("RejectCode = %q, want %q", res.RejectCode, tc.want.rejectCode)
			}
			if tc.want.status == PolicyUnchanged && res.CachedVersion != tc.want.cachedVersion {
				t.Fatalf("CachedVersion = %d, want %d", res.CachedVersion, tc.want.cachedVersion)
			}
		})
	}
}

// TestFetchPolicyBundle_UnknownKeyIsAcceptedWithNotes closes the fetch
// half of GUARD-FWD-1: a validly signed bundle whose TOML carries a key
// this (older) binary does not know is ACCEPTED and cached verbatim,
// not rejected. Running the authoring lint at this gate used to refuse
// it before the cache was ever written — fail-OPEN, since the org layer
// is escalate-only, so a stale-or-absent org layer can only loosen
// policy. The unknown key is a WARN, and the known override still lands.
func TestFetchPolicyBundle_UnknownKeyIsAcceptedWithNotes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const futureTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\nquarantine = true\n"

	// Sanity: the AUTHORING gate still refuses this body, so the
	// asymmetry under test is real and not a vacuous pass.
	if problems := guard.Lint([]byte(futureTOML), "org"); len(problems) == 0 {
		t.Fatal("guard.Lint(org) accepted an unknown key — the publish gate must stay strict")
	}

	ps := newPolicyBundleServer(t)
	b := signedTestBundle(t, priv, pub, 4, futureTOML)
	ps.bundle = &b

	c, s, cachePath := enrolledClient(t, ps.srv.URL)
	res, err := c.FetchPolicyBundle(context.Background(), cachePath)
	if err != nil {
		t.Fatalf("FetchPolicyBundle: %v", err)
	}
	if res.Status != PolicyApplied || res.Version != 4 {
		t.Fatalf("result = %+v, want applied v4 (an unknown key must not reject)", res)
	}

	// Cached verbatim — the node hands the ORIGINAL bytes to the
	// loader, which re-verifies the signature over them.
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	var cached orgcontract.PolicyBundle
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatalf("decode cache: %v", err)
	}
	if cached.BundleTOML != futureTOML || cached.Version != 4 {
		t.Fatalf("cache mismatch: %+v", cached)
	}

	// The version row landed, so the node converges instead of sitting
	// on an older bundle forever.
	if st := orgStateRow(t, s, ps.srv.URL+"/api/v1/policy-bundle"); st == nil || st.Version != "4" {
		t.Fatalf("bundle state row = %+v, want version 4", st)
	}

	// And the loader's consumer gate agrees: accept, with the ignored
	// key named.
	problems, notes := guard.AcceptOrgBundleTOML([]byte(cached.BundleTOML))
	if len(problems) != 0 {
		t.Fatalf("AcceptOrgBundleTOML problems = %v, want accept", problems)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "override.quarantine") {
		t.Errorf("notes = %q, want one naming override.quarantine", notes)
	}
}
