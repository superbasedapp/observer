package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

type budgetRoundTripFunc func(*http.Request) (*http.Response, error)

func (f budgetRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func signedBudgetIdentityDoc(t *testing.T, priv ed25519.PrivateKey, subject string, version, tokens int64) orgcontract.BudgetPolicyDoc {
	t.Helper()
	body := budgetBody(version, tokens)
	body.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", subject, body)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func budgetHTTPResponse(t *testing.T, status int, doc orgcontract.BudgetPolicyDoc, etag string) *http.Response {
	t.Helper()
	header := make(http.Header)
	if etag != "" {
		header.Set("ETag", etag)
	}
	var body io.ReadCloser = http.NoBody
	if status == http.StatusOK {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		body = io.NopCloser(strings.NewReader(string(raw)))
	}
	return &http.Response{StatusCode: status, Header: header, Body: body}
}

func replaceBudgetTestEnrollment(t *testing.T, st *store.Store, userID, enrolledAt string) store.OrgBudgetIdentity {
	t.Helper()
	ctx := context.Background()
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		t.Fatalf("load enrollment: enrollment=%+v err=%v", enr, err)
	}
	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	if _, err := st.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("bump enrollment generation: %v", err)
	}
	enr.UserID = userID
	enr.EnrolledAt = enrolledAt
	if err := st.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatalf("replace enrollment: %v", err)
	}
	identity, active, err := CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("current budget identity: active=%v err=%v", active, err)
	}
	return identity
}

func TestFetchBudgetPolicyLateOldMember200CannotPublish(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
		close(requestStarted)
		<-releaseResponse
		return budgetHTTPResponse(t, http.StatusOK, oldDoc, `"same"`), nil
	})}

	type result struct {
		out BudgetFetchOutcome
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		out, err := c.FetchBudgetPolicy(context.Background())
		resultCh <- result{out: out, err: err}
	}()
	<-requestStarted
	replaceBudgetTestEnrollment(t, st, "scim-99", "2026-09-14T02:00:00Z")
	c.budget.clear()
	if err := st.ClearOrgBudget(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(releaseResponse)
	got := <-resultCh
	if !errors.Is(got.err, store.ErrOrgBudgetIdentityChanged) || got.out.HaveBody {
		t.Fatalf("late response = %+v err=%v, want fenced unverified outcome", got.out, got.err)
	}
	_, _, have, _, cachedIdentity, _ := c.budget.snapshot()
	if have || cachedIdentity.Binding != "" {
		t.Fatalf("late old member body entered memory cache: %+v", cachedIdentity)
	}
	persisted, err := st.LoadOrgBudget(context.Background())
	if err != nil || persisted.Have {
		t.Fatalf("late old member body entered durable cache: %+v err=%v", persisted, err)
	}
}

func TestFetchBudgetPolicySameETagAfterReenrollmentIsUnconditional(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	newDoc := signedBudgetIdentityDoc(t, priv, "scim-99", 1, 10)
	var calls atomic.Int32
	var secondIfNoneMatch atomic.Value
	secondIfNoneMatch.Store("")
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return budgetHTTPResponse(t, http.StatusOK, oldDoc, `"same"`), nil
		}
		secondIfNoneMatch.Store(req.Header.Get("If-None-Match"))
		return budgetHTTPResponse(t, http.StatusOK, newDoc, `"same"`), nil
	})}
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed old member: %v", err)
	}
	newIdentity := replaceBudgetTestEnrollment(t, st, "scim-99", "2026-09-14T02:00:00Z")
	out, err := c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("fetch new member: %v", err)
	}
	if got, _ := secondIfNoneMatch.Load().(string); got != "" {
		t.Fatalf("new member reused old If-None-Match %q", got)
	}
	if !out.HaveBody || out.Body.CapTokens != 10 || out.Binding != newIdentity.Binding {
		t.Fatalf("new member outcome = %+v", out)
	}
}

func TestFetchBudgetPolicyConcurrentNewBindingResponsesRejectStaleWitness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	firstDoc := signedBudgetIdentityDoc(t, priv, "scim-99", 2, 10)
	secondDoc := signedBudgetIdentityDoc(t, priv, "scim-99", 3, 1_000)
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	newBindingETags := make(chan string, 2)
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return budgetHTTPResponse(t, http.StatusOK, oldDoc, `"old"`), nil
		case 2:
			newBindingETags <- req.Header.Get("If-None-Match")
			close(firstStarted)
			<-releaseFirst
			return budgetHTTPResponse(t, http.StatusOK, firstDoc, `"first"`), nil
		default:
			newBindingETags <- req.Header.Get("If-None-Match")
			close(secondStarted)
			<-releaseSecond
			return budgetHTTPResponse(t, http.StatusOK, secondDoc, `"second"`), nil
		}
	})}
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed old member: %v", err)
	}
	_, oldBody, oldHave, _, oldIdentity, oldWitness := c.budget.snapshot()
	if !oldHave || oldBody.CapTokens != 100 || oldIdentity.Binding == "" || !oldWitness.Valid() || !oldWitness.Present {
		t.Fatalf("old-binding cache was not seeded: body=%+v identity=%+v witness=%+v", oldBody, oldIdentity, oldWitness)
	}
	newIdentity := replaceBudgetTestEnrollment(t, st, "scim-99", "2026-09-14T02:00:00Z")

	type result struct {
		out BudgetFetchOutcome
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		out, err := c.FetchBudgetPolicy(context.Background())
		firstDone <- result{out: out, err: err}
	}()
	<-firstStarted
	secondDone := make(chan result, 1)
	go func() {
		out, err := c.FetchBudgetPolicy(context.Background())
		secondDone <- result{out: out, err: err}
	}()
	<-secondStarted
	firstETag, secondETag := <-newBindingETags, <-newBindingETags

	close(releaseFirst)
	first := <-firstDone
	close(releaseSecond)
	second := <-secondDone
	if firstETag != "" || secondETag != "" {
		t.Fatalf("new-binding requests reused old ETags %q and %q", firstETag, secondETag)
	}
	if first.err != nil || !first.out.HaveBody || first.out.Body.CapTokens != 10 ||
		first.out.Binding != newIdentity.Binding {
		t.Fatalf("first new-binding publication = %+v err=%v", first.out, first.err)
	}
	if second.err == nil || !strings.Contains(second.err.Error(), "budget cache changed during request") {
		t.Fatalf("second new-binding response = %+v err=%v, want optimistic cache rejection", second.out, second.err)
	}
	if !second.out.HaveBody || second.out.Body.CapTokens != 10 || second.out.Witness != first.out.Witness {
		t.Fatalf("second outcome = %+v, want first publication witness %+v", second.out, first.out.Witness)
	}
	persisted, err := st.LoadOrgBudget(context.Background())
	if err != nil || !persisted.Have || persisted.Body.CapTokens != 10 ||
		persisted.Binding != newIdentity.Binding || persisted.Witness != first.out.Witness {
		t.Fatalf("durable cache = %+v err=%v, want first new-binding publication", persisted, err)
	}
}

func TestFetchBudgetPolicyLateOldMember404CannotClearNewCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	newDoc := signedBudgetIdentityDoc(t, priv, "scim-99", 2, 10)
	oldRequestStarted := make(chan struct{})
	releaseOld404 := make(chan struct{})
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return budgetHTTPResponse(t, http.StatusOK, oldDoc, `"old"`), nil
		case 2:
			close(oldRequestStarted)
			<-releaseOld404
			return budgetHTTPResponse(t, http.StatusNotFound, orgcontract.BudgetPolicyDoc{}, ""), nil
		default:
			return budgetHTTPResponse(t, http.StatusOK, newDoc, `"new"`), nil
		}
	})}
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed old member: %v", err)
	}
	oldResult := make(chan error, 1)
	go func() {
		_, err := c.FetchBudgetPolicy(context.Background())
		oldResult <- err
	}()
	<-oldRequestStarted
	newIdentity := replaceBudgetTestEnrollment(t, st, "scim-99", "2026-09-14T02:00:00Z")
	c.budget.clear()
	if err := st.ClearOrgBudget(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out, err := c.FetchBudgetPolicy(context.Background()); err != nil ||
		!out.HaveBody || out.Binding != newIdentity.Binding {
		t.Fatalf("new member fetch = %+v err=%v", out, err)
	}
	close(releaseOld404)
	if err := <-oldResult; !errors.Is(err, store.ErrOrgBudgetIdentityChanged) {
		t.Fatalf("late 404 error = %v, want identity fence", err)
	}
	_, body, have, _, cachedIdentity, _ := c.budget.snapshot()
	if !have || body.CapTokens != 10 || cachedIdentity.Binding != newIdentity.Binding {
		t.Fatalf("late 404 cleared new memory cache: body=%+v identity=%+v", body, cachedIdentity)
	}
	persisted, err := st.LoadOrgBudget(context.Background())
	if err != nil || !persisted.Have || persisted.Body.CapTokens != 10 || persisted.Binding != newIdentity.Binding {
		t.Fatalf("late 404 cleared new durable cache: %+v err=%v", persisted, err)
	}
}

func TestFetchBudgetPolicyLateSameMember404CannotClearNewDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	oldDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	newDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 2, 1_000)
	oldRequestStarted := make(chan struct{})
	releaseOld404 := make(chan struct{})
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return budgetHTTPResponse(t, http.StatusOK, oldDoc, `"old"`), nil
		case 2:
			close(oldRequestStarted)
			<-releaseOld404
			return budgetHTTPResponse(t, http.StatusNotFound, orgcontract.BudgetPolicyDoc{}, ""), nil
		default:
			return budgetHTTPResponse(t, http.StatusOK, newDoc, `"new"`), nil
		}
	})}
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	late := make(chan error, 1)
	go func() {
		_, err := c.FetchBudgetPolicy(context.Background())
		late <- err
	}()
	<-oldRequestStarted
	newOutcome, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || newOutcome.Body.CapTokens != 1_000 {
		t.Fatalf("new publication=%+v err=%v", newOutcome, err)
	}
	close(releaseOld404)
	if err := <-late; err == nil || !strings.Contains(err.Error(), "cache changed during request") {
		t.Fatalf("late same-member 404 error=%v", err)
	}
	persisted, err := st.LoadOrgBudget(context.Background())
	if err != nil || !persisted.Have || persisted.Body.CapTokens != 1_000 || persisted.Witness != newOutcome.Witness {
		t.Fatalf("late 404 changed current body: %+v err=%v", persisted, err)
	}
}

func TestLoadPersistedBudgetRejectsReplacedEnrollment(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	doc := signedBudgetIdentityDoc(t, priv, "scim-42", 1, 100)
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return budgetHTTPResponse(t, http.StatusOK, doc, `"old"`), nil
	})}
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	current := replaceBudgetTestEnrollment(t, st, "scim-99", "2026-09-14T02:00:00Z")
	restarted := newTestClient(t, st, &memBearerStore{bearer: "bearer-xyz"})
	out, err := restarted.LoadPersistedBudget(context.Background())
	if !errors.Is(err, store.ErrOrgBudgetIdentityChanged) {
		t.Fatalf("LoadPersistedBudget error = %v, want identity fence", err)
	}
	if out.HaveBody || out.Binding != current.Binding || out.State != orgcontract.BudgetFetchUnverified {
		t.Fatalf("replaced enrollment restored old cap: %+v", out)
	}
}

func TestLoadPersistedBudgetRejectsLegacyUnboundCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	enr := store.Enrolment{
		OrgID: "org-1", OrgServerURL: "https://org.example.test",
		UserID: "scim-42", EnrolledAt: "2026-09-14T01:00:00Z",
	}
	if err := st.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BumpEnrolmentGeneration(ctx, OrgKey(enr.OrgServerURL, enr.OrgID), false); err != nil {
		t.Fatal(err)
	}
	doc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{Version: 7}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 7, etag = '"legacy"', org_key_fingerprint = 'key',
       body_json = ?, fetched_at = '2026-09-14T01:00:00Z'
 WHERE id = 1`, string(raw)); err != nil {
		t.Fatal(err)
	}
	identity, active, err := CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("current identity: active=%v err=%v", active, err)
	}
	c := newTestClient(t, st, &memBearerStore{bearer: "bearer-xyz"})
	out, err := c.LoadPersistedBudget(ctx)
	if !errors.Is(err, store.ErrOrgBudgetIdentityChanged) {
		t.Fatalf("LoadPersistedBudget error = %v, want unbound-cache refusal", err)
	}
	if out.HaveBody || out.Binding != identity.Binding || out.State != orgcontract.BudgetFetchUnverified {
		t.Fatalf("legacy cache restored on managed identity: %+v", out)
	}
}

func TestLoadPersistedBudgetReverifiesStoredDocument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	identity, active, err := CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("current identity: active=%v err=%v", active, err)
	}
	doc := signedBudgetIdentityDoc(t, wrongPriv, "scim-42", 1, 100)
	if err := st.SaveOrgBudget(ctx, doc, `"bad"`, orgcontract.PublicKeyPinHash(pub), identity); err != nil {
		t.Fatal(err)
	}
	out, err := c.LoadPersistedBudget(ctx)
	if err == nil || out.HaveBody || out.State != orgcontract.BudgetFetchUnverified ||
		!out.Witness.Valid() || !out.Witness.Present {
		t.Fatalf("unverified stored document restored: outcome=%+v err=%v", out, err)
	}
}

func TestFetchBudgetPolicySameVersionChangedBodyGetsNewDurableWitness(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, st, _ := enrolledClient(t, "https://org.example.test")
	pinRoutingKey(t, st, encodeStdKey(pub))
	firstDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 7, 100)
	secondDoc := signedBudgetIdentityDoc(t, priv, "scim-42", 7, 1_000)
	var calls atomic.Int32
	c.httpClient = &http.Client{Transport: budgetRoundTripFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return budgetHTTPResponse(t, http.StatusOK, firstDoc, `"same"`), nil
		}
		// A conforming server changes its ETag with the signed document. Keep it
		// fixed here to prove the node's Changed/witness semantics are tied to
		// exact durable bytes rather than transport metadata or version alone.
		return budgetHTTPResponse(t, http.StatusOK, secondDoc, `"same"`), nil
	})}
	first, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || !first.Changed || !first.Witness.Valid() || !first.Witness.Present {
		t.Fatalf("first outcome=%+v err=%v", first, err)
	}
	second, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || !second.Changed || second.Body.CapTokens != 1_000 ||
		!second.Witness.Valid() || second.Witness == first.Witness {
		t.Fatalf("same-version replacement=%+v first=%+v err=%v", second, first, err)
	}
	persisted, err := st.LoadOrgBudget(context.Background())
	if err != nil || persisted.Body.CapTokens != 1_000 || persisted.Witness != second.Witness {
		t.Fatalf("durable replacement=%+v err=%v", persisted, err)
	}
}

func TestLoadPersistedBudgetDistinguishesMissingAndMalformedWitness(t *testing.T) {
	for _, tc := range []struct {
		name      string
		malformed bool
		wantState string
		present   bool
	}{
		{name: "missing", wantState: orgcontract.BudgetFetchUnreachable},
		{name: "malformed", malformed: true, wantState: orgcontract.BudgetFetchUnverified, present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			st := store.New(database)
			if err := st.WriteEnrolment(ctx, store.Enrolment{
				OrgID: "org-1", OrgServerURL: "https://org.example.test", UserID: "scim-42",
				EnrolledAt: "2026-09-14T01:00:00Z",
			}); err != nil {
				t.Fatal(err)
			}
			c := newTestClient(t, st, &memBearerStore{bearer: "bearer-xyz"})
			if tc.malformed {
				if _, err := database.ExecContext(ctx, `UPDATE org_budget_cache SET body_json = '{' WHERE id = 1`); err != nil {
					t.Fatal(err)
				}
			}
			out, err := c.LoadPersistedBudget(ctx)
			if tc.malformed && err == nil {
				t.Fatal("malformed durable body was accepted")
			}
			if !tc.malformed && err != nil {
				t.Fatal(err)
			}
			if out.HaveBody || out.State != tc.wantState || !out.Witness.Valid() || out.Witness.Present != tc.present {
				t.Fatalf("durable state=%+v err=%v", out, err)
			}
		})
	}
}
