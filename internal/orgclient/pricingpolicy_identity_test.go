package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type pricingIdentityRoundTripFunc func(*http.Request) (*http.Response, error)

func (f pricingIdentityRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func signedPricingIdentityDoc(t *testing.T, priv ed25519.PrivateKey, subject string, version int64, input float64) orgcontract.PricingPolicyDoc {
	t.Helper()
	doc, err := orgcontract.SignPricingPolicy(priv, subject, pricingBody(version, "m", input, input*2))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func pricingIdentityHTTPResponse(t *testing.T, status int, doc orgcontract.PricingPolicyDoc, etag string) *http.Response {
	t.Helper()
	header := make(http.Header)
	if etag != "" {
		header.Set("ETag", etag)
	}
	body := io.ReadCloser(http.NoBody)
	if status == http.StatusOK {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return &http.Response{StatusCode: status, Header: header, Body: body, Request: &http.Request{}}
}

func currentPricingIdentity(t *testing.T, st *store.Store) store.OrgBudgetIdentity {
	t.Helper()
	identity, active, err := CurrentBudgetIdentity(context.Background(), st)
	if err != nil || !active {
		t.Fatalf("CurrentBudgetIdentity: active=%v err=%v", active, err)
	}
	return identity
}

func TestFetchPricingPolicyLateOldEnrollmentCannotPersistOrNotify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	started := make(chan struct{})
	release := make(chan struct{})
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return pricingIdentityHTTPResponse(t, http.StatusOK, oldDoc, `"old"`), nil
	})}
	var outcomes []PricingFetchOutcome
	c.SetPricingRail(func() bool { return true }, func(out PricingFetchOutcome) { outcomes = append(outcomes, out) })

	type result struct {
		out PricingFetchOutcome
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		resultCh <- result{out: out, err: err}
	}()
	<-started
	replaceBudgetTestEnrollment(t, st, "member-two", "2026-09-14T02:00:00Z")
	close(release)
	got := <-resultCh
	if !errors.Is(got.err, store.ErrOrgPricingIdentityChanged) || got.out.HaveBody {
		t.Fatalf("late response = %+v err=%v, want fenced empty outcome", got.out, got.err)
	}
	if len(outcomes) != 1 || outcomes[0].HaveBody || outcomes[0].Binding == "" {
		t.Fatalf("sink outcomes = %+v, want one current-binding empty outcome", outcomes)
	}
	cached, err := st.LoadOrgPricing(context.Background())
	if err != nil || cached.Have {
		t.Fatalf("late old member body entered durable cache: %+v err=%v", cached, err)
	}
	_, _, have, _, _ := c.pricing.snapshot()
	if have {
		t.Fatal("late old member body entered the in-memory cache")
	}
}

func TestLoadPersistedPricingRejectsLegacyAndMismatchedBinding(t *testing.T) {
	tests := []struct {
		name       string
		mismatch   bool
		wantLegacy bool
	}{
		{name: "legacy", wantLegacy: true},
		{name: "replacement enrollment", mismatch: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			c, st, _ := enrolledClient(t, "https://org.example.test")
			enabledPricing(c)
			pinRoutingKey(t, st, encodeStdKey(pub))
			doc := signedPricingIdentityDoc(t, priv, "org-1", 3, 7)
			if tc.wantLegacy {
				if err := st.SaveOrgPricing(context.Background(), doc, orgcontract.PublicKeyPinHash(pub), orgcontract.PricingFetchVerified); err != nil {
					t.Fatal(err)
				}
			} else {
				identity := currentPricingIdentity(t, st)
				if err := st.SaveOrgPricing(context.Background(), doc, orgcontract.PublicKeyPinHash(pub), orgcontract.PricingFetchVerified, identity); err != nil {
					t.Fatal(err)
				}
				replaceBudgetTestEnrollment(t, st, "member-two", "2026-09-14T02:00:00Z")
			}
			out, err := c.LoadPersistedPricing(context.Background())
			if err == nil || !errors.Is(err, store.ErrOrgPricingIdentityChanged) {
				t.Fatalf("LoadPersistedPricing err=%v, want identity rejection", err)
			}
			if out.State != orgcontract.PricingFetchUnverified || out.HaveBody {
				t.Fatalf("outcome = %+v, want unverified without body", out)
			}
			if _, _, have, _, _ := c.pricing.snapshot(); have {
				t.Fatal("rejected persisted document entered the in-memory cache")
			}
		})
	}
}

func TestLoadPersistedPricingVerifiesCurrentOrgKeyAndSignature(t *testing.T) {
	tests := []struct {
		name      string
		docMutate func(orgcontract.PricingPolicyDoc, ed25519.PrivateKey) orgcontract.PricingPolicyDoc
		wantErr   bool
	}{
		{name: "valid current document", docMutate: func(doc orgcontract.PricingPolicyDoc, _ ed25519.PrivateKey) orgcontract.PricingPolicyDoc { return doc }},
		{name: "wrong subject", wantErr: true, docMutate: func(doc orgcontract.PricingPolicyDoc, priv ed25519.PrivateKey) orgcontract.PricingPolicyDoc {
			wrong, _ := orgcontract.SignPricingPolicy(priv, "other-org", doc.PricingPolicyBody)
			return wrong
		}},
		{name: "wrong signature key", wantErr: true, docMutate: func(doc orgcontract.PricingPolicyDoc, _ ed25519.PrivateKey) orgcontract.PricingPolicyDoc {
			_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
			wrong, _ := orgcontract.SignPricingPolicy(wrongPriv, "org-1", doc.PricingPolicyBody)
			return wrong
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			c, st, _ := enrolledClient(t, "https://org.example.test")
			enabledPricing(c)
			pinRoutingKey(t, st, encodeStdKey(pub))
			doc := signedPricingIdentityDoc(t, priv, "org-1", 3, 7)
			doc = tc.docMutate(doc, priv)
			identity := currentPricingIdentity(t, st)
			if err := st.SaveOrgPricing(context.Background(), doc, orgcontract.PublicKeyPinHash(pub), orgcontract.PricingFetchVerified, identity); err != nil {
				t.Fatal(err)
			}
			out, err := c.LoadPersistedPricing(context.Background())
			if tc.wantErr {
				if err == nil || out.HaveBody {
					t.Fatalf("LoadPersistedPricing = %+v err=%v, want verification failure", out, err)
				}
				return
			}
			if err != nil || !out.HaveBody || out.Binding != identity.Binding {
				t.Fatalf("LoadPersistedPricing = %+v err=%v, want current verified document", out, err)
			}
			if !out.Witness.Valid() || !out.Witness.Present {
				t.Fatalf("LoadPersistedPricing witness = %+v, want known present", out.Witness)
			}
		})
	}
}

func TestFetchPricingPolicyReenrollmentClearsStaleMemoryBeforeRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	old := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	oldIdentity := currentPricingIdentity(t, st)
	c.pricing.store(`"old"`, old.PricingPolicyBody, orgcontract.PublicKeyPinHash(pub), oldIdentity)
	replaceBudgetTestEnrollment(t, st, "member-two", "2026-09-14T02:00:00Z")
	var seenETag atomic.Value
	seenETag.Store("")
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seenETag.Store(req.Header.Get("If-None-Match"))
		return nil, errors.New("offline")
	})}
	out, err := c.FetchPricingPolicy(context.Background())
	if err == nil || out.HaveBody || out.Binding == "" {
		t.Fatalf("reenrollment fetch = %+v err=%v, want empty current-binding failure", out, err)
	}
	if got, _ := seenETag.Load().(string); got != "" {
		t.Fatalf("re-enrollment reused old ETag %q", got)
	}
	_, _, have, identity, _ := c.pricing.snapshot()
	if have || identity.Binding != "" {
		t.Fatalf("stale in-memory pricing survived re-enrollment: have=%v identity=%+v", have, identity)
	}
}

func TestFetchPricingPolicyConcurrentResponsesDoNotRewindCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	newDoc := signedPricingIdentityDoc(t, priv, "org-1", 2, 4)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return pricingIdentityHTTPResponse(t, http.StatusOK, oldDoc, `"old"`), nil
		}
		return pricingIdentityHTTPResponse(t, http.StatusOK, newDoc, `"new"`), nil
	})}

	type result struct {
		out PricingFetchOutcome
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		firstDone <- result{out: out, err: err}
	}()
	<-started
	second, secondErr := c.FetchPricingPolicy(context.Background())
	if secondErr != nil || second.State != orgcontract.PricingFetchVerified || second.Body.Version != 2 {
		t.Fatalf("newer concurrent response = %+v err=%v, want v2 accepted", second, secondErr)
	}
	close(release)
	first := <-firstDone
	if first.err == nil || !strings.Contains(first.err.Error(), "pricing cache changed during request") {
		t.Fatalf("older concurrent response err=%v out=%+v, want optimistic cache rejection", first.err, first.out)
	}
	if first.out.Body.Version != 2 || first.out.Witness != second.Witness {
		t.Fatalf("older response outcome = %+v, want current v2 witness %+v", first.out, second.Witness)
	}
	cached, err := st.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || cached.Version != 2 || cached.Witness != second.Witness {
		t.Fatalf("concurrent cache = %+v err=%v, want durable v2 witness %+v", cached, err, second.Witness)
	}
}

func TestFetchPricingPolicyLate304UsesCurrentPublishedWitness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	v1 := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	v2 := signedPricingIdentityDoc(t, priv, "org-1", 2, 4)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var outcomesMu sync.Mutex
	var outcomes []PricingFetchOutcome
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v1, `"v1"`), nil
		case 2:
			close(started)
			<-release
			return pricingIdentityHTTPResponse(t, http.StatusNotModified, orgcontract.PricingPolicyDoc{}, ""), nil
		default:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v2, `"v2"`), nil
		}
	})}
	c.SetPricingRail(func() bool { return true }, func(out PricingFetchOutcome) {
		outcomesMu.Lock()
		outcomes = append(outcomes, out)
		outcomesMu.Unlock()
	})
	seed, err := c.FetchPricingPolicy(context.Background())
	if err != nil || seed.Body.Version != 1 {
		t.Fatalf("seed pricing = %+v err=%v", seed, err)
	}

	type result struct {
		out PricingFetchOutcome
		err error
	}
	lateDone := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		lateDone <- result{out: out, err: err}
	}()
	<-started
	current, err := c.FetchPricingPolicy(context.Background())
	if err != nil || current.Body.Version != 2 || !current.Witness.Valid() {
		t.Fatalf("current pricing = %+v err=%v", current, err)
	}
	close(release)
	late := <-lateDone
	if late.err != nil || late.out.Body.Version != 2 || late.out.Witness != current.Witness {
		t.Fatalf("late 304 = %+v err=%v, want current v2 witness %+v", late.out, late.err, current.Witness)
	}

	cached, err := st.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || cached.Version != 2 || cached.Witness != current.Witness {
		t.Fatalf("late 304 durable cache = %+v err=%v, want v2 witness %+v", cached, err, current.Witness)
	}
	outcomesMu.Lock()
	defer outcomesMu.Unlock()
	if len(outcomes) != 3 || outcomes[0].Body.Version != 1 || outcomes[1].Body.Version != 2 || outcomes[2].Body.Version != 2 {
		t.Fatalf("late 304 sink outcomes = %+v, want v1 then current v2 twice", outcomes)
	}
}

func TestFetchPricingPolicyLateTransportFailureUsesCurrentPublishedWitness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	v1 := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	v2 := signedPricingIdentityDoc(t, priv, "org-1", 2, 4)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v1, `"v1"`), nil
		case 2:
			close(started)
			<-release
			return nil, errors.New("late transport failure")
		default:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v2, `"v2"`), nil
		}
	})}
	seed, err := c.FetchPricingPolicy(context.Background())
	if err != nil || seed.Body.Version != 1 {
		t.Fatalf("seed pricing = %+v err=%v", seed, err)
	}

	type result struct {
		out PricingFetchOutcome
		err error
	}
	lateDone := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		lateDone <- result{out: out, err: err}
	}()
	<-started
	current, err := c.FetchPricingPolicy(context.Background())
	if err != nil || current.Body.Version != 2 || !current.Witness.Valid() {
		t.Fatalf("current pricing = %+v err=%v", current, err)
	}
	close(release)
	late := <-lateDone
	if late.err == nil || late.out.State != orgcontract.PricingFetchUnreachable || late.out.Body.Version != 2 || late.out.Witness != current.Witness {
		t.Fatalf("late transport failure = %+v err=%v, want current v2 witness %+v", late.out, late.err, current.Witness)
	}

	cached, err := st.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || cached.Version != 2 || cached.Witness != current.Witness {
		t.Fatalf("late transport durable cache = %+v err=%v, want v2 witness %+v", cached, err, current.Witness)
	}
}

func TestFetchPricingPolicyPublicationLockOrdersBlockingSinks(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	v1 := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	v2 := signedPricingIdentityDoc(t, priv, "org-1", 2, 4)
	v1SinkEntered := make(chan struct{})
	releaseV1Sink := make(chan struct{})
	v2HTTPDone := make(chan struct{})
	sinkOutcomes := make(chan PricingFetchOutcome, 2)
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v1, `"v1"`), nil
		case 2:
			close(v2HTTPDone)
			return pricingIdentityHTTPResponse(t, http.StatusOK, v2, `"v2"`), nil
		default:
			return pricingIdentityHTTPResponse(t, http.StatusOK, v2, `"v2"`), nil
		}
	})}
	c.SetPricingRail(func() bool { return true }, func(out PricingFetchOutcome) {
		sinkOutcomes <- out
		if out.Body.Version == 1 {
			close(v1SinkEntered)
			<-releaseV1Sink
		}
	})

	type result struct {
		out PricingFetchOutcome
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		firstDone <- result{out: out, err: err}
	}()
	<-v1SinkEntered
	firstSink := <-sinkOutcomes
	if firstSink.Body.Version != 1 {
		t.Fatalf("first sink outcome = %+v, want v1", firstSink)
	}

	secondDone := make(chan result, 1)
	go func() {
		out, err := c.FetchPricingPolicy(context.Background())
		secondDone <- result{out: out, err: err}
	}()
	<-v2HTTPDone
	timer := time.NewTimer(100 * time.Millisecond)
	select {
	case got := <-sinkOutcomes:
		t.Fatalf("v2 sink ran while v1 sink was blocked: %+v", got)
	case <-timer.C:
	}
	close(releaseV1Sink)
	first := <-firstDone
	second := <-secondDone
	if first.err != nil || first.out.Body.Version != 1 {
		t.Fatalf("first fetch = %+v err=%v", first.out, first.err)
	}
	if second.err != nil || second.out.Body.Version != 2 {
		t.Fatalf("second fetch = %+v err=%v", second.out, second.err)
	}
	secondSink := <-sinkOutcomes
	if secondSink.Body.Version != 2 || secondSink.Witness != second.out.Witness {
		t.Fatalf("second sink outcome = %+v, want v2 witness %+v", secondSink, second.out.Witness)
	}
}

func newExposedPricingIdentityClient(t *testing.T) (*Client, *store.Store, *sql.DB) {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{
		Path:        filepath.Join(t.TempDir(), "pricing.db"),
		BusyTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	if err := st.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.example.test",
		UserID: "scim-42", UserEmail: "dev@acme.example", EnrolledAt: "2026-09-14T01:00:00Z", BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	return newTestClient(t, st, &memBearerStore{bearer: "bearer-xyz"}), st, database
}

func TestFetchPricingPolicyPersistenceFailurePreservesETagAndWitness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, database := newExposedPricingIdentityClient(t)
	enabledPricing(c)
	pinRoutingKey(t, st, encodeStdKey(pub))
	v1 := signedPricingIdentityDoc(t, priv, "org-1", 1, 9)
	v2 := signedPricingIdentityDoc(t, priv, "org-1", 2, 4)
	var calls atomic.Int32
	var seenETagsMu sync.Mutex
	var seenETags []string
	c.httpClient = &http.Client{Transport: pricingIdentityRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		seenETagsMu.Lock()
		seenETags = append(seenETags, req.Header.Get("If-None-Match"))
		seenETagsMu.Unlock()
		if calls.Add(1) == 1 {
			return pricingIdentityHTTPResponse(t, http.StatusOK, v1, `"v1"`), nil
		}
		return pricingIdentityHTTPResponse(t, http.StatusOK, v2, `"v2"`), nil
	})}
	first, err := c.FetchPricingPolicy(context.Background())
	if err != nil || first.Body.Version != 1 || !first.Witness.Valid() {
		t.Fatalf("seed pricing = %+v err=%v", first, err)
	}

	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatalf("database.Conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	fetchCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	failed, fetchErr := c.FetchPricingPolicy(fetchCtx)
	cancel()
	if fetchErr == nil || failed.Body.Version != 1 || failed.Witness != first.Witness || failed.State != orgcontract.PricingFetchUnverified {
		t.Fatalf("persistence failure = %+v err=%v, want prior v1 witness %+v", failed, fetchErr, first.Witness)
	}
	etag, body, have, identity, witness := c.pricing.snapshot()
	if !have || body.Version != 1 || witness != first.Witness || etag != `"v1"` || identity.Binding != first.Binding {
		t.Fatalf("in-memory cache after persistence failure = etag=%q body=%+v have=%v identity=%+v witness=%+v", etag, body, have, identity, witness)
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}

	retried, err := c.FetchPricingPolicy(context.Background())
	if err != nil || retried.Body.Version != 2 || !retried.Witness.Valid() || retried.Witness == first.Witness {
		t.Fatalf("retry pricing = %+v err=%v", retried, err)
	}
	seenETagsMu.Lock()
	defer seenETagsMu.Unlock()
	if len(seenETags) != 3 || seenETags[0] != "" || seenETags[1] != `"v1"` || seenETags[2] != `"v1"` {
		t.Fatalf("request ETags = %q, want empty then old ETag twice", seenETags)
	}
	cached, err := st.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || cached.Version != 2 || cached.Witness != retried.Witness {
		t.Fatalf("retry durable cache = %+v err=%v, want v2 witness %+v", cached, err, retried.Witness)
	}
}
