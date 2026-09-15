package cloudgateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- fakes ------------------------------------------------------------------

// memCred is an in-memory credential store. Tests MUST NOT use cloudcred.Open,
// which probes (and on success writes to) the host's real OS keychain.
type memCred struct {
	refresh  string
	deviceOK bool
	device   ed25519.PrivateKey
	token    string
}

func (m *memCred) SaveWorkOSRefresh(r string) error { m.refresh = r; return nil }

func (m *memCred) LoadWorkOSRefresh() (string, error) {
	if m.refresh == "" {
		return "", cloudcred.ErrNotFound
	}
	return m.refresh, nil
}

func (m *memCred) SaveDeviceKey(k ed25519.PrivateKey) error {
	m.device, m.deviceOK = k, true
	return nil
}

func (m *memCred) LoadDeviceKey() (ed25519.PrivateKey, error) {
	if !m.deviceOK {
		return nil, cloudcred.ErrNotFound
	}
	return m.device, nil
}

func (m *memCred) SaveAPIToken(t string) error { m.token = t; return nil }

func (m *memCred) LoadAPIToken() (string, error) {
	if m.token == "" {
		return "", cloudcred.ErrNotFound
	}
	return m.token, nil
}

func (m *memCred) Clear() error {
	m.refresh, m.token, m.device, m.deviceOK = "", "", nil, false
	return nil
}

func (m *memCred) Backend() string            { return "memory" }
func (m *memCred) SecurityDiagnostic() string { return "" }

// fakeGrants is an in-memory GrantStore.
type fakeGrants struct {
	receipts []store.CloudConsentReceipt
	err      error
	calls    int
}

func (f *fakeGrants) ListLiveCloudConsentReceipts(_ context.Context, purpose string) ([]store.CloudConsentReceipt, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []store.CloudConsentReceipt
	for _, r := range f.receipts {
		if r.InvalidatedAt != nil {
			continue // the real store filters these in SQL
		}
		if purpose != "" && r.Purpose != purpose {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// liveStandingReceipt is a live standing grant for the structural purpose.
func liveStandingReceipt() store.CloudConsentReceipt {
	return store.CloudConsentReceipt{
		ID:                   "rcpt_standing",
		Purpose:              string(cloudcontract.PurposeStructuralInsights),
		GrantMode:            store.CloudGrantStanding,
		Endpoint:             "https://cloud.invalid/v1/structural-insights",
		DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
		DeclaredTimezone:     "UTC",
		SourceWindowRule:     "completed_utc_days_trailing_30",
		ConsentGeneration:    1,
		CreatedAt:            time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}

// livePerUploadReceipt is a live per-upload grant for the structural purpose.
func livePerUploadReceipt() store.CloudConsentReceipt {
	return store.CloudConsentReceipt{
		ID:        "rcpt_per_upload",
		Purpose:   string(cloudcontract.PurposeStructuralInsights),
		GrantMode: store.CloudGrantPerUpload,
		Endpoint:  "https://cloud.invalid/v1/jobs",
		CreatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}

// liveCommunityReceipt is a live standing grant for the cohort-benchmarking
// (community) purpose, with its OWN community-specific endpoint and data
// dictionary digest — never the structural rail's values (Sol review F2).
// endpoint should normally be built from the same base URL the test's fake
// server / gateway use, so a correctly-behaving upload's Endpoint field
// compares equal to the gateway's live CommunityEndpoint().
func liveCommunityReceipt(endpoint string) store.CloudConsentReceipt {
	return store.CloudConsentReceipt{
		ID:                   "rcpt_community",
		Purpose:              string(cloudcontract.PurposeCohortBenchmarking),
		GrantMode:            store.CloudGrantStanding,
		Endpoint:             endpoint,
		DataDictionaryDigest: cloudcontract.CommunityDataDictionaryDigest(),
		DeclaredTimezone:     cloudcontract.CommunityDeclaredTimezone,
		SourceWindowRule:     cloudcontract.CommunitySourceWindowRule,
		ConsentGeneration:    1,
		CreatedAt:            time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
	}
}

// noopLease is a DispatchLease that grants unconditionally, for tests whose
// subject is something other than the lease (which has its own tests below).
func noopLease(context.Context) (time.Time, func(), error) { return time.Time{}, nil, nil }

// communityRequestFor builds a well-formed community upload for receipt — the
// full standing-grant binding the client now requires on the wire (N1/N5).
func communityRequestFor(receipt store.CloudConsentReceipt) CommunityUploadRequest {
	return CommunityUploadRequest{
		Payload: []byte(`{"x":1}`), Digest: "sha256:x",
		ConsentGeneration:    1,
		DataDictionaryDigest: cloudcontract.CommunityDataDictionaryDigest(),
		SourceWindowRule:     receipt.SourceWindowRule,
		DeclaredTimezone:     receipt.DeclaredTimezone,
		Endpoint:             receipt.Endpoint,
		PreAttempt:           func() error { return nil },
		DispatchLease:        noopLease,
	}
}

// noRequestServer fails the test on ANY inbound request. It is how "no network
// attempt was made" is proven rather than asserted.
func noRequestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("EGRESS WITHOUT CONSENT: the gateway made a %s %s request that no live grant authorized",
			r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestGateway(t *testing.T, grants GrantStore, baseURL string) *Gateway {
	t.Helper()
	g, err := Open(Options{
		Grants:     grants,
		Cred:       &memCred{},
		BaseURL:    baseURL,
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
		Now:        func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return g
}

// --- the invariant ----------------------------------------------------------

// TestFeatureSendWithoutGrantMakesNoRequest is the package's reason to exist:
// with no consent recorded, a feature send is refused BEFORE the network.
func TestFeatureSendWithoutGrantMakesNoRequest(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{}, srv.URL)

	var ran bool
	err := g.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(UploadSession) error {
		ran = true
		return nil
	})
	if !errors.Is(err, ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant, got %v", err)
	}
	if ran {
		t.Fatal("the send callback ran without a live grant — the network handle escaped the check")
	}
}

// TestFeatureSendWithRevokedGrantIsRefused proves an invalidated receipt does
// not authorize egress.
func TestFeatureSendWithRevokedGrantIsRefused(t *testing.T) {
	srv := noRequestServer(t)
	revoked := liveStandingReceipt()
	at := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	revoked.InvalidatedAt = &at
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{revoked}}, srv.URL)

	err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(StructuralSession) error {
		t.Error("callback ran under a revoked grant")
		return nil
	})
	if !errors.Is(err, ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant for a revoked receipt, got %v", err)
	}
}

// TestFeatureSendWithExpiredGrantIsRefused proves review_at is enforced: a grant
// past its review date is not live, even though the store still returns it.
func TestFeatureSendWithExpiredGrantIsRefused(t *testing.T) {
	srv := noRequestServer(t)
	expired := liveStandingReceipt()
	past := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC) // before the injected now
	expired.ReviewAt = &past
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{expired}}, srv.URL)

	err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(StructuralSession) error {
		t.Error("callback ran under an expired grant")
		return nil
	})
	if !errors.Is(err, ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant for an expired receipt, got %v", err)
	}
}

// TestStandingSendRefusesPerUploadGrant proves a per-upload receipt cannot
// authorize the standing rail: it bound one byte-string, not a schema.
func TestStandingSendRefusesPerUploadGrant(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{livePerUploadReceipt()}}, srv.URL)

	if err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(StructuralSession) error {
		t.Error("callback ran under a per-upload grant")
		return nil
	}); !errors.Is(err, ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant, got %v", err)
	}

	// ...but the SAME receipt does authorize an ordinary feature send.
	var ran bool
	if err := g.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(UploadSession) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("a live per-upload grant must authorize FeatureSend: %v", err)
	}
	if !ran {
		t.Fatal("FeatureSend did not run its callback under a live grant")
	}
}

// TestFeatureSendWithoutConsentSourceFailsClosed proves an unconfigured consent
// source is a refusal, not a bypass.
func TestFeatureSendWithoutConsentSourceFailsClosed(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, nil, srv.URL)
	err := g.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(UploadSession) error {
		t.Error("callback ran with no consent source")
		return nil
	})
	if !errors.Is(err, ErrNoConsentSource) {
		t.Fatalf("want ErrNoConsentSource, got %v", err)
	}
}

// TestFeatureSendRejectsBootstrapPurpose proves the bootstrap purpose cannot be
// laundered through the feature lane.
func TestFeatureSendRejectsBootstrapPurpose(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{}, srv.URL)
	err := g.FeatureSend(context.Background(), cloudcontract.PurposeAccountDeviceOps, func(UploadSession) error {
		t.Error("callback ran for a bootstrap purpose")
		return nil
	})
	if !errors.Is(err, ErrBootstrapPurpose) {
		t.Fatalf("want ErrBootstrapPurpose, got %v", err)
	}
}

// TestFeatureSendSurfacesStoreErrorsAsRefusals proves a consent read that FAILS
// is a refusal, not a pass (fail-closed on the unhappy path too).
func TestFeatureSendSurfacesStoreErrorsAsRefusals(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{err: errors.New("db is locked")}, srv.URL)
	err := g.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(UploadSession) error {
		t.Error("callback ran after a failed consent read")
		return nil
	})
	if err == nil {
		t.Fatal("a failed consent read must refuse the send")
	}
}

// TestFeatureFetchRequiresSomeLiveGrant proves the results pull is gated too:
// refused with nothing granted, allowed under any live feature grant.
func TestFeatureFetchRequiresSomeLiveGrant(t *testing.T) {
	srv := noRequestServer(t)
	empty := newTestGateway(t, &fakeGrants{}, srv.URL)
	if err := empty.FeatureFetch(context.Background(), func(ReadSession) error {
		t.Error("results pull ran with no live grant")
		return nil
	}); !errors.Is(err, ErrNoLiveGrant) {
		t.Fatalf("want ErrNoLiveGrant, got %v", err)
	}

	granted := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{livePerUploadReceipt()}}, srv.URL)
	var ran bool
	if err := granted.FeatureFetch(context.Background(), func(ReadSession) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("FeatureFetch under a live grant: %v", err)
	}
	if !ran {
		t.Fatal("FeatureFetch did not run its callback under a live grant")
	}
}

// TestSendRunsThePreSendRevocationRecheck proves the resolution happens TWICE —
// the pre-send re-check the R1 protocol requires.
func TestSendRunsThePreSendRevocationRecheck(t *testing.T) {
	srv := noRequestServer(t)
	grants := &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}
	g := newTestGateway(t, grants, srv.URL)
	if err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(StructuralSession) error {
		return nil
	}); err != nil {
		t.Fatalf("StandingSend: %v", err)
	}
	if grants.calls != 2 {
		t.Fatalf("consent was read %d time(s); want 2 (resolve + pre-send revocation re-check)", grants.calls)
	}
}

// TestSendAbortsWhenGrantIsRevokedMidFlight drives the re-check: the grant is
// live at resolution and gone by dispatch.
func TestSendAbortsWhenGrantIsRevokedMidFlight(t *testing.T) {
	srv := noRequestServer(t)
	grants := &revokeOnSecondRead{receipt: liveStandingReceipt()}
	g := newTestGateway(t, grants, srv.URL)
	err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(StructuralSession) error {
		t.Error("callback ran after the grant was revoked mid-flight")
		return nil
	})
	if !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("want ErrGrantRevoked, got %v", err)
	}
}

// revokeOnSecondRead is live on the first consent read and empty on every one
// after — the revoked-between-decision-and-dispatch race.
type revokeOnSecondRead struct {
	receipt store.CloudConsentReceipt
	reads   int
}

func (r *revokeOnSecondRead) ListLiveCloudConsentReceipts(context.Context, string) ([]store.CloudConsentReceipt, error) {
	r.reads++
	if r.reads == 1 {
		return []store.CloudConsentReceipt{r.receipt}, nil
	}
	return nil, nil
}

// --- bootstrap lane ---------------------------------------------------------

// TestBootstrapLaneWorksWithoutAnyGrant proves the sign-in lane is NOT gated on
// consent: with zero receipts (and no consent source at all), the exchange,
// logout and deletion calls still reach the server. This is the R2/F10
// disposition — the sign-in action authorizes account/device operations.
func TestBootstrapLaneWorksWithoutAnyGrant(t *testing.T) {
	var hits []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "nonce")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"n1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "exchange")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_token":"tok-1","device_id":"dev-1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/logout", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "logout")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"signed_out"}`))
	})
	mux.HandleFunc("/v1/deletion-requests", func(w http.ResponseWriter, _ *http.Request) {
		hits = append(hits, "deletion")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"del-1","state":"processing"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cred := &memCred{}
	g, err := Open(Options{
		Grants:     nil, // deliberately no consent source at all
		Cred:       cred,
		BaseURL:    srv.URL,
		DevToken:   "workos-dev-token",
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	if err := g.BootstrapExchange(ctx); err != nil {
		t.Fatalf("BootstrapExchange: %v", err)
	}
	if !g.APITokenPresent() {
		t.Fatal("exchange did not store an API token")
	}
	if err := g.BootstrapLogout(ctx); err != nil {
		t.Fatalf("BootstrapLogout: %v", err)
	}
	if _, err := g.BootstrapRequestDeletion(ctx); err != nil {
		t.Fatalf("BootstrapRequestDeletion: %v", err)
	}
	want := []string{"nonce", "exchange", "logout", "deletion"}
	if len(hits) != len(want) {
		t.Fatalf("bootstrap hits = %v, want %v", hits, want)
	}
	for i := range want {
		if hits[i] != want[i] {
			t.Fatalf("bootstrap hits = %v, want %v", hits, want)
		}
	}
}

// TestUnconfiguredGatewayRefusesNetworkButServesLocalReads proves a node with no
// base URL still answers credential questions and can clear locally.
func TestUnconfiguredGatewayRefusesNetworkButServesLocalReads(t *testing.T) {
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, "")
	if g.Configured() {
		t.Fatal("a gateway with no base URL must not report itself configured")
	}
	if err := g.BootstrapLogout(context.Background()); !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("want ErrNoBaseURL, got %v", err)
	}
	if err := g.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(UploadSession) error {
		t.Error("callback ran with no base URL")
		return nil
	}); !errors.Is(err, ErrNoBaseURL) {
		t.Fatalf("want ErrNoBaseURL, got %v", err)
	}
	if g.CredentialBackend() != "memory" {
		t.Fatalf("credential backend = %q", g.CredentialBackend())
	}
	if err := g.ClearCredentials(); err != nil {
		t.Fatalf("ClearCredentials: %v", err)
	}
}

// --- the purpose rule table -------------------------------------------------

// TestPurposeRulesCoverEveryPurpose pins the table exhaustive over the closed
// contract vocabulary: a new purpose must be classified deliberately, never
// default silently into the feature lane.
func TestPurposeRulesCoverEveryPurpose(t *testing.T) {
	for _, p := range cloudcontract.AllPurposes() {
		rule, ok := purposeRules[p]
		if !ok {
			t.Errorf("purpose %q has no rule row — classify it deliberately", p)
			continue
		}
		if !rule.standingGrantable && rule.notYetReason == "" {
			t.Errorf("purpose %q is not standing-grantable but carries no honest reason copy", p)
		}
	}
	if len(purposeRules) != len(cloudcontract.AllPurposes()) {
		t.Errorf("purposeRules has %d rows for %d purposes — the table must be exactly the vocabulary",
			len(purposeRules), len(cloudcontract.AllPurposes()))
	}
}

// TestStandingGrantableScope pins this arc's scope: the structural-insights and
// community_cohort_benchmarking purposes may be granted standing (W5 added the
// latter with its cohort definitions, ≥30 floor and removal path), and every
// other purpose still refuses with honest copy.
func TestStandingGrantableScope(t *testing.T) {
	grantable := map[cloudcontract.Purpose]bool{
		cloudcontract.PurposeStructuralInsights: true,
		cloudcontract.PurposeCohortBenchmarking: true,
	}
	got := StandingGrantablePurposes()
	if len(got) != len(grantable) {
		t.Fatalf("standing-grantable purposes = %v, want the %d-purpose scope", got, len(grantable))
	}
	for _, p := range got {
		if !grantable[p] {
			t.Errorf("purpose %q is standing-grantable but not in the pinned scope", p)
		}
	}
	for _, p := range cloudcontract.AllPurposes() {
		ok, reason := StandingGrantable(p)
		if grantable[p] {
			if !ok {
				t.Errorf("purpose %q must be standing-grantable in this arc", p)
			}
			continue
		}
		if ok {
			t.Errorf("purpose %q must not be standing-grantable in this arc", p)
		}
		if reason == "" {
			t.Errorf("purpose %q refuses a standing grant with no explanation", p)
		}
	}
	if ok, _ := StandingGrantable("not_a_purpose"); ok {
		t.Error("an unknown purpose must never be standing-grantable")
	}
}

// TestResolveStandingGrantReturnsTheBinding proves the capture path gets the
// binding facts it needs without any network call.
func TestResolveStandingGrantReturnsTheBinding(t *testing.T) {
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, "")
	grant, err := g.ResolveStandingGrant(context.Background(), cloudcontract.PurposeStructuralInsights)
	if err != nil {
		t.Fatalf("ResolveStandingGrant: %v", err)
	}
	if grant.ReceiptID != "rcpt_standing" || !grant.Standing {
		t.Fatalf("unexpected grant: %+v", grant)
	}
	if grant.DeclaredTimezone != "UTC" || grant.SourceWindowRule != "completed_utc_days_trailing_30" {
		t.Fatalf("grant lost its binding facts: %+v", grant)
	}
	if grant.DataDictionaryDigest != cloudcontract.StructuralDataDictionaryDigest() {
		t.Fatalf("grant data-dictionary digest = %q", grant.DataDictionaryDigest)
	}
}

// TestHTTPStatusClassifiesAPIErrors proves callers can classify outcomes without
// importing the network lane.
func TestHTTPStatusClassifiesAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such route", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	var upErr error
	if err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(s StructuralSession) error {
		_, upErr = s.UploadStructural(context.Background(), StructuralUploadRequest{
			Payload:           []byte(`{"x":1}`),
			Period:            "2026-08-31",
			PeriodRuleVersion: 1,
			SchemaVersion:     cloudcontract.StructuralSnapshotSchemaVersion,
			Revision:          1,
			Digest:            "sha256:deadbeef",
			// The R1 standing-grant binding is REQUIRED on the wire (W2 server
			// half): without it the client refuses before dispatching, so this
			// test would never reach the 404 it is about. The values mirror what
			// ResolveStandingGrant returns for liveStandingReceipt().
			ConsentGeneration:    1,
			DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
			SourceWindowRule:     "completed_utc_days_trailing_30",
			PreAttempt:           func() error { return nil },
			DispatchLease:        noopLease,
		})
		return upErr
	}); err == nil {
		t.Fatal("expected the 404 to surface")
	}
	status, ok := HTTPStatus(upErr)
	if !ok || status != http.StatusNotFound {
		t.Fatalf("HTTPStatus = (%d, %v), want (404, true)", status, ok)
	}
	if _, ok := HTTPStatus(errors.New("transport")); ok {
		t.Fatal("a transport error must not report an HTTP status")
	}
}

// --- F1: capability narrowing ------------------------------------------------

// TestFetchSessionCannotUpload is the COMPILE-LEVEL pin for F1. FeatureFetch is
// authorized by ANY live grant — including one for a purpose that has nothing to
// do with uploading — so the handle it yields must not carry a write at all.
//
// The proof is a type assertion, not a call: if ReadSession ever grows an Upload
// or UploadStructural method, these interface assertions start succeeding and
// the test fails. That is stronger than asserting a runtime refusal, because a
// runtime refusal can be forgotten at one call site while a missing method
// cannot be called from any.
func TestFetchSessionCannotUpload(t *testing.T) {
	var read any = ReadSession{}
	if _, ok := read.(interface {
		Upload(context.Context, UploadRequest) (UploadResult, error)
	}); ok {
		t.Error("ReadSession exposes Upload — a results fetch, authorized by ANY live grant, can now write")
	}
	if _, ok := read.(interface {
		UploadStructural(context.Context, StructuralUploadRequest) (StructuralUploadResult, error)
	}); ok {
		t.Error("ReadSession exposes UploadStructural — the fetch handle can write snapshots")
	}

	// The two write handles are narrow in the other direction too: neither can
	// perform the other's operation class, and neither can read results.
	var upload any = UploadSession{}
	if _, ok := upload.(interface {
		UploadStructural(context.Context, StructuralUploadRequest) (StructuralUploadResult, error)
	}); ok {
		t.Error("UploadSession exposes UploadStructural — an evidence grant now authorizes the standing rail")
	}
	if _, ok := upload.(interface {
		Results(context.Context, string) (ResultsPage, error)
	}); ok {
		t.Error("UploadSession exposes Results")
	}
	var structural any = StructuralSession{}
	if _, ok := structural.(interface {
		Upload(context.Context, UploadRequest) (UploadResult, error)
	}); ok {
		t.Error("StructuralSession exposes Upload — a standing grant now authorizes a session-evidence body")
	}
	if _, ok := structural.(interface {
		Results(context.Context, string) (ResultsPage, error)
	}); ok {
		t.Error("StructuralSession exposes Results")
	}
}

// TestFeatureSendRefusesNonUploadablePurpose proves a live grant is necessary but
// NOT sufficient: a purpose whose consuming surface does not exist in this
// release cannot authorize a body leaving the machine, and the refusal happens
// before the network.
func TestFeatureSendRefusesNonUploadablePurpose(t *testing.T) {
	srv := noRequestServer(t)
	live := livePerUploadReceipt()
	live.Purpose = string(cloudcontract.PurposeResearch)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{live}}, srv.URL)

	err := g.FeatureSend(context.Background(), cloudcontract.PurposeResearch, func(UploadSession) error {
		t.Error("callback ran for a purpose that authorizes no evidence upload")
		return nil
	})
	if !errors.Is(err, ErrPurposeNotUploadable) {
		t.Fatalf("want ErrPurposeNotUploadable, got %v", err)
	}
	if err.Error() == "" || !strings.Contains(err.Error(), "research") {
		t.Errorf("the refusal must name the purpose and explain itself: %v", err)
	}
}

// TestEvidenceUploadableCoversEveryPurpose pins the second column of the rule
// table exhaustive and honest: every purpose is classified, and every refusal
// carries copy naming what is missing.
func TestEvidenceUploadableCoversEveryPurpose(t *testing.T) {
	for _, p := range cloudcontract.AllPurposes() {
		ok, reason := EvidenceUploadable(p)
		if !ok && reason == "" {
			t.Errorf("purpose %q refuses an evidence upload with no explanation", p)
		}
		if ok && reason != "" {
			t.Errorf("purpose %q is uploadable but carries a refusal reason %q", p, reason)
		}
	}
	if ok, _ := EvidenceUploadable(cloudcontract.PurposeAccountDeviceOps); ok {
		t.Error("the bootstrap purpose must never authorize a feature upload")
	}
	if ok, reason := EvidenceUploadable("not_a_purpose"); ok || reason == "" {
		t.Error("an unknown purpose must be refused, with an explanation")
	}
}

// --- F2: the required per-attempt re-check ------------------------------------

// TestUploadsRequireAPreAttemptHook proves the seam refuses an upload submitted
// without a per-item authorization re-check, on BOTH write handles and before
// any request. This is what stops a future call site from silently reintroducing
// the defect the structural drain had: a send that cannot notice a revocation
// issued after the gateway's one-shot grant check.
func TestUploadsRequireAPreAttemptHook(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(s StructuralSession) error {
		_, uerr := s.UploadStructural(context.Background(), StructuralUploadRequest{
			Payload: []byte(`{"x":1}`), Period: "2026-08-31", PeriodRuleVersion: 1,
			SchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion, Revision: 1, Digest: "sha256:x",
			ConsentGeneration:    1,
			DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
			SourceWindowRule:     "completed_utc_days_trailing_30",
		})
		return uerr
	}); !errors.Is(err, ErrPreAttemptRequired) {
		t.Fatalf("UploadStructural without a PreAttempt: want ErrPreAttemptRequired, got %v", err)
	}

	perUpload := livePerUploadReceipt()
	g2 := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{perUpload}}, srv.URL)
	if err := g2.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	if err := g2.FeatureSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(s UploadSession) error {
		_, uerr := s.Upload(context.Background(), UploadRequest{
			CloudSessionID: "cs-1", Feature: "session_enrichment", Envelope: []byte(`{"x":1}`),
		})
		return uerr
	}); !errors.Is(err, ErrPreAttemptRequired) {
		t.Fatalf("Upload without a PreAttempt: want ErrPreAttemptRequired, got %v", err)
	}
}

// TestUploadRechecksTheGrantBeforeEveryAttempt proves the gateway composes its
// OWN grant re-resolve in front of the caller's hook, so a revocation that lands
// while a long callback is running stops the next physical attempt even if the
// caller's own check has not noticed it yet.
func TestUploadRechecksTheGrantBeforeEveryAttempt(t *testing.T) {
	srv := noRequestServer(t)
	grants := &revokeAfterNReads{receipt: liveStandingReceipt(), liveReads: 2}
	g := newTestGateway(t, grants, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	var callerChecks int
	err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(s StructuralSession) error {
		_, uerr := s.UploadStructural(context.Background(), StructuralUploadRequest{
			Payload: []byte(`{"x":1}`), Period: "2026-08-31", PeriodRuleVersion: 1,
			SchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion, Revision: 1, Digest: "sha256:x",
			ConsentGeneration:    1,
			DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
			SourceWindowRule:     "completed_utc_days_trailing_30",
			// The caller's own hook is deliberately permissive: the gateway's
			// re-resolve is what must stop this, and it runs first.
			PreAttempt:    func() error { callerChecks++; return nil },
			DispatchLease: noopLease,
		})
		return uerr
	})
	if !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("want ErrGrantRevoked from the pre-attempt re-resolve, got %v", err)
	}
	if callerChecks != 0 {
		t.Errorf("the caller's hook ran %d time(s); the gateway re-resolve must short-circuit first", callerChecks)
	}
}

// revokeAfterNReads is live for the first liveReads consent reads and empty
// afterwards — a revocation landing partway through a send.
type revokeAfterNReads struct {
	receipt   store.CloudConsentReceipt
	liveReads int
	reads     int
}

func (r *revokeAfterNReads) ListLiveCloudConsentReceipts(context.Context, string) ([]store.CloudConsentReceipt, error) {
	r.reads++
	if r.reads <= r.liveReads {
		return []store.CloudConsentReceipt{r.receipt}, nil
	}
	return nil, nil
}

// --- Sol review remediation: endpoint-mismatch-fails-closed (F3) -----------

// TestUploadCommunityFailsClosedOnEndpointMismatch proves a community upload
// refuses to send when the receipt's bound endpoint no longer matches the
// gateway's live CommunityEndpoint() — the config/--base-url-moved-after-grant
// attack the Sol review flagged (F3). No request must reach the network.
func TestUploadCommunityFailsClosedOnEndpointMismatch(t *testing.T) {
	srv := noRequestServer(t)
	// The receipt is bound to a DIFFERENT origin than the gateway is actually
	// configured to talk to right now — simulating base_url having moved
	// since the grant was minted.
	receipt := liveCommunityReceipt("https://attacker.invalid/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		_, uerr := s.UploadCommunity(context.Background(), communityRequestFor(receipt)) // Endpoint = the STALE, receipt-bound one
		return uerr
	})
	if !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("want ErrEndpointMismatch, got %v", err)
	}
}

// TestUploadCommunitySucceedsWhenEndpointMatches is the control: an upload
// whose Endpoint agrees with the gateway's live CommunityEndpoint() must NOT
// be refused on endpoint grounds (proves the check isn't just always-fail).
func TestUploadCommunitySucceedsWhenEndpointMatches(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		_, uerr := s.UploadCommunity(context.Background(), communityRequestFor(receipt))
		return uerr
	})
	if err != nil {
		t.Fatalf("matching endpoint: want success, got %v", err)
	}
	if gotPath != "/v1/community/contribution" {
		t.Fatalf("request landed at %q, want /v1/community/contribution", gotPath)
	}
}

// --- Sol review remediation: standing-lane-purpose-exact (F4) --------------

// TestStandingSendRefusesCommunityPurpose proves the STRUCTURAL rail refuses a
// grant minted for the COMMUNITY purpose, even though both are standing —
// exact-purpose, not "any standing purpose" (Sol review F4).
func TestStandingSendRefusesCommunityPurpose(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{
		liveCommunityReceipt(srv.URL + "/v1/community/contribution"),
	}}, srv.URL)

	err := g.StandingSend(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(StructuralSession) error {
		t.Fatal("StandingSend ran its callback for a non-structural purpose")
		return nil
	})
	if !errors.Is(err, ErrPurposeMismatch) {
		t.Fatalf("want ErrPurposeMismatch, got %v", err)
	}
}

// TestStandingSendCommunityRefusesStructuralPurpose is the mirror: the
// COMMUNITY rail refuses a grant minted for the STRUCTURAL purpose.
func TestStandingSendCommunityRefusesStructuralPurpose(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, srv.URL)

	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeStructuralInsights, func(CommunitySession) error {
		t.Fatal("StandingSendCommunity ran its callback for a non-community purpose")
		return nil
	})
	if !errors.Is(err, ErrPurposeMismatch) {
		t.Fatalf("want ErrPurposeMismatch, got %v", err)
	}
}

// TestStandingSendCommunityAcceptsItsOwnPurpose is the control: the exact
// PurposeCohortBenchmarking purpose IS authorized on the community rail.
func TestStandingSendCommunityAcceptsItsOwnPurpose(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		_, uerr := s.UploadCommunity(context.Background(), communityRequestFor(receipt))
		return uerr
	})
	if err != nil {
		t.Fatalf("own purpose: want success, got %v", err)
	}
	if gotPath != "/v1/community/contribution" {
		t.Fatalf("request landed at %q, want /v1/community/contribution", gotPath)
	}
}

// TestFeatureFetchSelfHealsAnExpiredToken proves the API-token self-heal
// works THROUGH the consent seam with no gateway code of its own: a live grant
// authorizes the read, the server rejects the aged-out bearer once, the client
// re-exchanges through the (bootstrap-lane) broker, and the read succeeds.
// The heal runs INSIDE an already-authorized call, so it can never widen a
// grant — without a grant the network is never reached (pinned above).
func TestFeatureFetchSelfHealsAnExpiredToken(t *testing.T) {
	var exchanges, results int
	var bearers []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"n1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, _ *http.Request) {
		exchanges++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_token":"tok-fresh","device_id":"dev-1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		results++
		bearers = append(bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.Header().Set("Content-Type", "application/json")
		if results == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid or expired token","code":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[],"next_cursor":"v2:3"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cred := &memCred{token: "tok-expired"}
	var healed int
	g, err := Open(Options{
		Grants:        &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}},
		Cred:          cred,
		BaseURL:       srv.URL,
		DevToken:      "workos-dev-token",
		MaxRetries:    0,
		Backoff:       func(int) time.Duration { return 0 },
		Now:           func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) },
		OnTokenHealed: func() { healed++ },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var page ResultsPage
	err = g.FeatureFetch(context.Background(), func(s ReadSession) error {
		var ferr error
		page, ferr = s.Results(context.Background(), "")
		return ferr
	})
	if err != nil {
		t.Fatalf("FeatureFetch: %v", err)
	}
	if page.NextCursor != "v2:3" {
		t.Errorf("cursor = %q, want v2:3", page.NextCursor)
	}
	if exchanges != 1 || results != 2 || healed != 1 {
		t.Errorf("exchanges=%d results=%d healed=%d; want 1/2/1", exchanges, results, healed)
	}
	if len(bearers) != 2 || bearers[0] != "tok-expired" || bearers[1] != "tok-fresh" {
		t.Errorf("bearers = %v, want [tok-expired tok-fresh]", bearers)
	}
	if cred.token != "tok-fresh" {
		t.Errorf("stored token = %q, want the re-exchanged tok-fresh", cred.token)
	}
}

// TestFeatureFetchSurfacesSignInExpired proves a failed heal is the gateway's
// re-exported ErrSignInExpired — classifiable by cmd/observer without importing
// the network lane — and that exactly one exchange was attempted.
func TestFeatureFetchSurfacesSignInExpired(t *testing.T) {
	var exchanges, results int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"n1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, _ *http.Request) {
		exchanges++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"api_token":"tok-fresh","device_id":"dev-1","expires_at":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, _ *http.Request) {
		results++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid or expired token","code":"unauthorized"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	g, err := Open(Options{
		Grants:     &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}},
		Cred:       &memCred{token: "tok-expired"},
		BaseURL:    srv.URL,
		DevToken:   "workos-dev-token",
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
		Now:        func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	err = g.FeatureFetch(context.Background(), func(s ReadSession) error {
		_, ferr := s.Results(context.Background(), "")
		return ferr
	})
	if !errors.Is(err, ErrSignInExpired) {
		t.Fatalf("want ErrSignInExpired, got %v", err)
	}
	if status, ok := HTTPStatus(err); !ok || status != http.StatusUnauthorized {
		t.Errorf("the 401 must still be classifiable through HTTPStatus, got ok=%v status=%d", ok, status)
	}
	if !strings.Contains(err.Error(), "observer cloud login") {
		t.Errorf("error must name the recovery, got %q", err)
	}
	if exchanges != 1 || results != 2 {
		t.Errorf("exchanges=%d results=%d; want exactly 1 and 2", exchanges, results)
	}
}

// TestWorkOSSignInPresentIsLocal pins the status surface: sign-in presence is
// read from the credential store with no network call and no credential
// creation.
func TestWorkOSSignInPresentIsLocal(t *testing.T) {
	srv := noRequestServer(t)
	cred := &memCred{}
	g, err := Open(Options{Cred: cred, BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if g.WorkOSSignInPresent() {
		t.Fatal("fresh store must report no sign-in")
	}
	cred.refresh = "rt-1"
	if !g.WorkOSSignInPresent() {
		t.Fatal("stored refresh material must report a sign-in")
	}
	if cred.deviceOK {
		t.Fatal("asking about the sign-in must not create a device key")
	}
}

// --- per-host credential scoping ---------------------------------------------

// TestHostFromBaseURLTable pins the pure derivation Open uses to scope the
// credential store to the cloud estate a node is currently configured
// against.
func TestHostFromBaseURLTable(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{"empty is unconfigured", "", ""},
		{"staging with trailing slash", "https://staging-cloud.superbased.app/", "staging-cloud.superbased.app"},
		{"production no trailing slash", "https://cloud.superbased.app", "cloud.superbased.app"},
		{"mixed case is lower-cased", "https://Cloud.SuperBased.App", "cloud.superbased.app"},
		{"port is stripped", "https://cloud.superbased.app:8443/v1", "cloud.superbased.app"},
		{"unparseable falls back to legacy scope", "://not a url", ""},
		{"test server URL keeps its host", "http://127.0.0.1:54321", "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostFromBaseURL(tt.baseURL); got != tt.want {
				t.Errorf("hostFromBaseURL(%q) = %q, want %q", tt.baseURL, got, tt.want)
			}
		})
	}
}

// TestOpenDerivesHostScopedCredStoreFromBaseURL proves Open wires the derived
// host through to cloudcred.OpenForHost end to end: a gateway opened against
// one cloud estate must not see a credential saved by a gateway opened
// against a different estate over the same CredDir, and the on-disk record
// name must carry the "@host" suffix cloudcred.OpenForHost documents.
//
// This deliberately exercises the REAL (non-injected) credential store —
// opts.Cred is left nil — because the point under test is Open's own wiring,
// not a fake's behaviour. It never touches the operator's real store: CredDir
// is a fresh t.TempDir(). If this host's OS keychain answers the
// availability probe (unlike this sandbox, which has none), the test skips
// rather than asserting on-disk file names that would not apply.
func TestOpenDerivesHostScopedCredStoreFromBaseURL(t *testing.T) {
	dir := t.TempDir()
	now := func() time.Time { return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) }

	staging, err := Open(Options{Grants: &fakeGrants{}, CredDir: dir, BaseURL: "https://staging-cloud.superbased.app/", Now: now})
	if err != nil {
		t.Fatalf("Open (staging): %v", err)
	}
	if staging.CredentialBackend() != "file" {
		t.Skipf("this host's OS keychain answered the probe (backend=%q); this test needs the file fallback to observe on-disk record names", staging.CredentialBackend())
	}
	if err := staging.cred.SaveAPIToken("staging-token"); err != nil {
		t.Fatalf("staging SaveAPIToken: %v", err)
	}

	wantPath := filepath.Join(dir, "cloud-cred", cloudcred.ServiceName+".sbo-api-token@staging-cloud.superbased.app")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected host-scoped credential file at %s: %v", wantPath, err)
	}

	prod, err := Open(Options{Grants: &fakeGrants{}, CredDir: dir, BaseURL: "https://cloud.superbased.app/", Now: now})
	if err != nil {
		t.Fatalf("Open (prod): %v", err)
	}
	if _, err := prod.cred.LoadAPIToken(); !errors.Is(err, cloudcred.ErrNotFound) {
		t.Fatalf("prod-host gateway LoadAPIToken = %v, want ErrNotFound — must not see staging's token", err)
	}
}
