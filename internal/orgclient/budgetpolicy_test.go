package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// budgetBody is a one-period signed-body payload for the tests below.
func budgetBody(version int64, capTokens int64) orgcontract.BudgetPolicyBody {
	return orgcontract.BudgetPolicyBody{
		Version: version, ResolvedScope: "team:eng", CapTokens: capTokens,
		Period: orgcontract.BudgetPolicyPeriodCalendarMonth, Timezone: "UTC",
		Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		Caps: []orgcontract.BudgetPolicyCap{{
			Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: capTokens,
			Enforcement: orgcontract.BudgetPolicyEnforcementHard, ResolvedScope: "team:eng",
		}},
	}
}

// budgetServer serves GET /api/agent/budget with a settable doc + ETag and
// records the If-None-Match it received.
type budgetServer struct {
	srv    *httptest.Server
	doc    atomic.Pointer[orgcontract.BudgetPolicyDoc]
	etag   atomic.Value // string
	status atomic.Int32 // 0 = serve the doc
	gotINM atomic.Value // string
	// gotMachine records the NON-AUTHORITATIVE X-SBO-Machine disambiguation
	// header, so a test can pin that this node says which of its machines is
	// polling — the server cannot infer it from a bearer that names a member.
	gotMachine atomic.Value // string
}

func newBudgetServer(t *testing.T) *budgetServer {
	t.Helper()
	bs := &budgetServer{}
	bs.etag.Store("")
	bs.gotINM.Store("")
	bs.gotMachine.Store("")
	bs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/budget" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		bs.gotINM.Store(r.Header.Get("If-None-Match"))
		bs.gotMachine.Store(r.Header.Get(orgcontract.HeaderMachineIdentity))
		if st := bs.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			return
		}
		etag, _ := bs.etag.Load().(string)
		if etag != "" {
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
		}
		writeTestJSON(w, http.StatusOK, bs.doc.Load())
	}))
	t.Cleanup(bs.srv.Close)
	return bs
}

// TestFetchBudgetPolicyAcceptsAVerifiedBody is the happy path: a body signed
// for THIS caller verifies against the org key another rail pinned, and lands
// in the in-memory cache.
func TestFetchBudgetPolicyAcceptsAVerifiedBody(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	bs.doc.Store(&doc)

	out, err := c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("FetchBudgetPolicy: %v", err)
	}
	if out.State != orgcontract.BudgetFetchOK || !out.HaveBody {
		t.Fatalf("outcome = %+v, want ok + a body", out)
	}
	if out.Body.CapTokens != 40_000_000 {
		t.Errorf("cap_tokens = %d, want 40000000", out.Body.CapTokens)
	}
}

// TestFetchBudgetPolicyRefusesAWrongKeyOrTamperedBody is the plan's
// failing-first signature case: a body signed by a DIFFERENT key, and a body
// whose numbers were edited after signing, must both be refused — never
// applied unsigned, never applied partially.
func TestFetchBudgetPolicyRefusesAWrongKeyOrTamperedBody(t *testing.T) {
	orgPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("a body signed by another key", func(t *testing.T) {
		bs := newBudgetServer(t)
		c, s, _ := enrolledClient(t, bs.srv.URL)
		pinRoutingKey(t, s, encodeStdKey(orgPub))
		doc, _ := orgcontract.SignBudgetPolicy(attackerPriv, "org-1", "scim-42", budgetBody(41, 1))
		bs.doc.Store(&doc)

		out, err := c.FetchBudgetPolicy(context.Background())
		if err == nil {
			t.Fatal("a body signed by an unpinned key was accepted")
		}
		if out.State != orgcontract.BudgetFetchUnverified || out.HaveBody {
			t.Fatalf("outcome = %+v, want unverified with no body", out)
		}
	})

	t.Run("a body edited after signing", func(t *testing.T) {
		bs := newBudgetServer(t)
		c, s, _ := enrolledClient(t, bs.srv.URL)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		pinRoutingKey(t, s, encodeStdKey(pub))
		doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 1_000))
		// The cap is raised in flight; the signature is left untouched.
		doc.CapTokens = 999_999_999
		bs.doc.Store(&doc)

		out, err := c.FetchBudgetPolicy(context.Background())
		if err == nil || !errors.Is(err, orgcontract.ErrBudgetPolicySignature) {
			t.Fatalf("a tampered body was accepted (err = %v)", err)
		}
		if out.State != orgcontract.BudgetFetchUnverified {
			t.Fatalf("state = %q, want unverified", out.State)
		}
	})

	t.Run("a body minted for another member", func(t *testing.T) {
		bs := newBudgetServer(t)
		c, s, _ := enrolledClient(t, bs.srv.URL)
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		pinRoutingKey(t, s, encodeStdKey(pub))
		// Genuinely signed, but for a different subject: without the caller
		// binding in the signing message this would verify.
		doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-99", budgetBody(41, 1))
		bs.doc.Store(&doc)

		if _, err := c.FetchBudgetPolicy(context.Background()); err == nil {
			t.Fatal("another member's signed body was accepted for this caller")
		}
	})
}

// TestFetchBudgetPolicyWithNoPinnedOrgKeyIsUnverified pins the documented
// trust dependency: with no rail having pinned the org key, the body is
// refused rather than trusted.
func TestFetchBudgetPolicyWithNoPinnedOrgKeyIsUnverified(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	bs := newBudgetServer(t)
	c, _, _ := enrolledClient(t, bs.srv.URL) // no pinRoutingKey
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 1))
	bs.doc.Store(&doc)

	out, err := c.FetchBudgetPolicy(context.Background())
	if err == nil || !errors.Is(err, errNoPinnedOrgKey) {
		t.Fatalf("err = %v, want errNoPinnedOrgKey", err)
	}
	if out.State != orgcontract.BudgetFetchUnverified || out.HaveBody {
		t.Fatalf("outcome = %+v, want unverified with no body", out)
	}
}

// TestFetchBudgetPolicyETag304KeepsTheCachedDoc: the steady state is a
// conditional GET, and a 304 must keep the body in force rather than dropping
// it (a dropped body would silently release the cap).
func TestFetchBudgetPolicyETag304KeepsTheCachedDoc(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	bs.etag.Store(`"bp-abc123"`)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)

	first, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || !first.Changed {
		t.Fatalf("first fetch: %+v err=%v, want a changed accept", first, err)
	}

	second, err := c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got, _ := bs.gotINM.Load().(string); got != `"bp-abc123"` {
		t.Errorf("If-None-Match = %q, want the cached ETag — a poll that did not send it would re-download every cycle", got)
	}
	if second.State != orgcontract.BudgetFetchOK || !second.HaveBody {
		t.Fatalf("304 outcome = %+v, want ok WITH the cached body still in force", second)
	}
	if second.Body.CapTokens != 40_000_000 {
		t.Errorf("304 dropped the cached cap: cap_tokens = %d, want 40000000", second.Body.CapTokens)
	}
	if second.Changed {
		t.Error("a 304 reported Changed — it would churn the guard engine every cycle")
	}
}

// TestFetchBudgetPolicyStatusMap walks the server's documented statuses onto
// the closed posture vocabulary, including the fail-open cases.
func TestFetchBudgetPolicyStatusMap(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{http.StatusNotFound, orgcontract.BudgetFetchNoBudget},
		{http.StatusUnauthorized, orgcontract.BudgetFetchAuthFailed},
		{http.StatusForbidden, orgcontract.BudgetFetchAuthFailed},
		{http.StatusConflict, orgcontract.BudgetFetchChannelOff},
		{http.StatusInternalServerError, orgcontract.BudgetFetchUnreachable},
	}
	for _, tc := range cases {
		bs := newBudgetServer(t)
		bs.status.Store(int32(tc.status))
		c, _, _ := enrolledClient(t, bs.srv.URL)
		out, _ := c.FetchBudgetPolicy(context.Background())
		if out.State != tc.want {
			t.Errorf("HTTP %d -> %q, want %q", tc.status, out.State, tc.want)
		}
	}
}

// TestFetchBudgetPolicy404DropsTheCachedCap: an admin who DELETED the budget
// must not keep enforcing it through this node's memory.
func TestFetchBudgetPolicy404DropsTheCachedCap(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	bs.status.Store(int32(http.StatusNotFound))
	out, err := c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("404 fetch: %v", err)
	}
	if out.State != orgcontract.BudgetFetchNoBudget || out.HaveBody {
		t.Fatalf("outcome = %+v, want no_budget with NO body", out)
	}
	// The next cycle must be unconditional again: a stale If-None-Match after
	// a 404 could revive the deleted cap through a 304.
	bs.status.Store(0)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("post-404 fetch: %v", err)
	}
	if got, _ := bs.gotINM.Load().(string); got != "" {
		t.Errorf("If-None-Match after a 404 = %q, want empty", got)
	}
}

// TestFetchBudgetPolicyUnreachableKeepsTheCachedBody: a transport failure is
// fail-open in the CORRECT direction — the last verified body stays in force
// and the state names the reason.
func TestFetchBudgetPolicyUnreachableKeepsTheCachedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	bs.srv.Close() // the org is now unreachable
	out, err := c.FetchBudgetPolicy(context.Background())
	if err == nil {
		t.Fatal("an unreachable org produced no error")
	}
	if out.State != orgcontract.BudgetFetchUnreachable {
		t.Fatalf("state = %q, want unreachable", out.State)
	}
	if !out.HaveBody || out.Body.CapTokens != 40_000_000 {
		t.Errorf("outcome = %+v, want the last verified body still in force", out)
	}
}

// TestFetchBudgetPolicyNotEnrolled: an unenrolled node reports not_enrolled and
// makes no claim about a budget.
func TestFetchBudgetPolicyNotEnrolled(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	out, err := c.FetchBudgetPolicy(context.Background())
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
	if out.State != orgcontract.BudgetFetchNotEnrolled || out.HaveBody {
		t.Fatalf("outcome = %+v, want not_enrolled with no body", out)
	}
}

// encodeStdKey renders an Ed25519 public key the way the routing rail's
// node-local pin stores it (base64 std) — the encoding orgSigningKey decodes.
func encodeStdKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// TestFetchBudgetPolicyRefusesAReplayedOlderVersion is LOW-3 (review fix round
// 2): the signature BINDS Version, but binding it only helps if the consumer
// checks it. An intermediary on this rail could otherwise replay yesterday's
// correctly signed 100M-token document over today's 1M one and the node would
// apply the looser cap.
//
// The refusal is fail-open: the cached document stays in force and the outcome
// carries it, so a confused server can never leave the node uncapped.
func TestFetchBudgetPolicyRefusesAReplayedOlderVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	tight, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 1_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	bs.doc.Store(&tight)
	if out, err := c.FetchBudgetPolicy(context.Background()); err != nil || out.Body.CapTokens != 1_000_000 {
		t.Fatalf("first fetch = %+v (err %v), want the 1M cap", out, err)
	}

	// The replay: an OLDER, correctly signed, looser document.
	loose, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(40, 100_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	bs.doc.Store(&loose)
	out, err := c.FetchBudgetPolicy(context.Background())
	if err == nil {
		t.Fatal("a replayed older budget document was accepted silently")
	}
	if out.Body.CapTokens != 1_000_000 || !out.HaveBody {
		t.Errorf("outcome = %+v, want the CACHED 1M cap still in force — the refusal must be fail-open", out)
	}
	if out.State != orgcontract.BudgetFetchUnverified {
		t.Errorf("state = %q, want %q", out.State, orgcontract.BudgetFetchUnverified)
	}

	// The SAME version is fine: a membership change re-resolves the body
	// without bumping org_budget_policy_version, which is exactly why the ETag
	// (not the version) is this rail's change token.
	same, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 2_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	bs.doc.Store(&same)
	if out, err := c.FetchBudgetPolicy(context.Background()); err != nil || out.Body.CapTokens != 2_000_000 {
		t.Fatalf("same-version fetch = %+v (err %v), want the re-resolved 2M cap", out, err)
	}

	// A KEY ROTATION restarts the lineage: the version comparison must not
	// pin the node to a number the old key signed.
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pinRoutingKey(t, s, encodeStdKey(newPub))
	rotated, err := orgcontract.SignBudgetPolicy(newPriv, "org-1", "scim-42", budgetBody(1, 5_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}
	bs.doc.Store(&rotated)
	if out, err := c.FetchBudgetPolicy(context.Background()); err != nil || out.Body.CapTokens != 5_000_000 {
		t.Fatalf("after a key rotation: %+v (err %v), want the new key's version-1 document accepted", out, err)
	}
}

// TestFetchBudgetPolicySignedExplicitNoneIsAVerifiedUncappedBody is the
// follow-up's node half: the org answering "no budget applies to you" with a
// SIGNED none document must land as ok + HaveBody + uncapped, and must clear
// any cap the node had cached.
//
// The distinction it pins is the whole point of the none document: an unsigned
// 404 stays HaveBody=false (so a fail-closed managed node keeps blocking),
// while this verified answer is something the node may safely run on.
func TestFetchBudgetPolicySignedExplicitNoneIsAVerifiedUncappedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	// Seed a real cap, so the none has something to clear.
	capped, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&capped)
	bs.etag.Store(`"bp-capped"`)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	// The admin deletes every budget; the version advances and the org signs
	// an explicit none.
	none, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", orgcontract.EmptyBudgetPolicyBody(42))
	if err != nil {
		t.Fatalf("SignBudgetPolicy(none): %v", err)
	}
	bs.doc.Store(&none)
	bs.etag.Store(`"bp-none"`)

	out, err := c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("none fetch: %v", err)
	}
	if out.State != orgcontract.BudgetFetchOK {
		t.Fatalf("state = %q, want ok — the org SIGNED this answer", out.State)
	}
	if !out.HaveBody {
		t.Fatal("HaveBody = false on a verified none; a fail-closed node would keep blocking forever")
	}
	if !out.Body.Empty() || out.Body.CapTokens != 0 || len(out.Body.Caps) != 0 {
		t.Fatalf("body = %+v, want the explicit none", out.Body)
	}
	if out.Body.ResolvedScope != orgcontract.BudgetPolicyScopeNone {
		t.Errorf("resolved_scope = %q, want %q", out.Body.ResolvedScope, orgcontract.BudgetPolicyScopeNone)
	}
	if !out.Changed {
		t.Error("Changed = false; the cached cap was replaced by a none and the sink must be told")
	}

	// The cap is GONE from the cache: a later unreachable poll must not revive
	// it, which is the property the 404 branch provided and this must match.
	bs.status.Store(int32(http.StatusInternalServerError))
	out, _ = c.FetchBudgetPolicy(context.Background())
	if out.HaveBody && !out.Body.Empty() {
		t.Fatalf("a failed poll revived the deleted cap: %+v", out.Body)
	}
}

// TestFetchBudgetPolicyNoneDoesNotTripTheReplayGuard: the none body carries
// the org's CURRENT version, so it is never older than the capped document it
// replaces. A none minted at an older version IS refused, exactly like any
// other replay.
func TestFetchBudgetPolicyNoneDoesNotTripTheReplayGuard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	capped, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&capped)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	stale, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", orgcontract.EmptyBudgetPolicyBody(40))
	bs.doc.Store(&stale)
	out, err := c.FetchBudgetPolicy(context.Background())
	if err == nil {
		t.Fatal("an OLDER none was accepted; a replayed none is a way to drop a cap")
	}
	if out.State != orgcontract.BudgetFetchUnverified || out.Body.CapTokens != 40_000_000 {
		t.Fatalf("outcome = %+v, want unverified with the cached cap still in force", out)
	}
}

// TestBudgetPolicySurvivesASimulatedRestart is finding H3's node half: the
// verified document is written through to org_budget_cache, and a FRESH client
// over the SAME store restores it before making any request.
//
// Without it a restarted daemon starts from "no verified body ever", which on
// a node that requires one is either a block (during an org outage,
// indefinitely) or — before it learns it is required — a push interval of
// uncapped, unarmed operation that a developer can re-open at will.
func TestBudgetPolicySurvivesASimulatedRestart(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)
	bs.etag.Store(`"bp-41"`)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	// A NEW process over the same database, before any request.
	restarted := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	out, err := restarted.LoadPersistedBudget(context.Background())
	if err != nil {
		t.Fatalf("LoadPersistedBudget: %v", err)
	}
	if !out.HaveBody || out.Body.CapTokens != 40_000_000 {
		t.Fatalf("restored outcome = %+v, want the verified 40M cap", out)
	}
	if out.State != orgcontract.BudgetFetchUnreachable {
		t.Errorf("state = %q, want unreachable — this process has not spoken to the org yet, and saying `ok` would make last_fetch_ok a lie",
			out.State)
	}

	// The restored ETag makes the restarted daemon's FIRST request conditional.
	bs.gotINM.Store("")
	if _, err := restarted.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("post-restart fetch: %v", err)
	}
	if got, _ := bs.gotINM.Load().(string); got != `"bp-41"` {
		t.Errorf("If-None-Match after a restart = %q, want the restored ETag", got)
	}
}

// TestBudgetPolicyRestartKeepsTheReplayFloor: the stored key FINGERPRINT is
// what the replay guard compares, so a restarted daemon still refuses an older
// signed document. Storing the raw key instead would make the guard compare a
// fingerprint against a key, find them unequal, and skip the check exactly
// once per restart.
func TestBudgetPolicyRestartKeepsTheReplayFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	restarted := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	if _, err := restarted.LoadPersistedBudget(context.Background()); err != nil {
		t.Fatalf("LoadPersistedBudget: %v", err)
	}
	older, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(40, 90_000_000))
	bs.doc.Store(&older)
	out, err := restarted.FetchBudgetPolicy(context.Background())
	if err == nil {
		t.Fatal("an older signed document was accepted after a restart — the replay floor did not survive")
	}
	if out.Body.CapTokens != 40_000_000 {
		t.Errorf("outcome = %+v, want the restored 40M cap still in force", out)
	}
}

// TestBudgetPolicyUnsignedWithdrawalClearsTheStoredBody: the two signals that
// legitimately mean "this node holds no org budget" — an explicit not-found
// and an unenrol — must clear the PERSISTED copy too, or a restart would
// revive a budget the admin deleted.
func TestBudgetPolicyUnsignedWithdrawalClearsTheStoredBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(41, 40_000_000))
	bs.doc.Store(&doc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	bs.status.Store(int32(http.StatusNotFound))
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("404 fetch: %v", err)
	}
	restarted := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	out, err := restarted.LoadPersistedBudget(context.Background())
	if err != nil {
		t.Fatalf("LoadPersistedBudget: %v", err)
	}
	if out.HaveBody {
		t.Fatalf("a deleted budget survived the restart: %+v", out.Body)
	}
}

// TestFetchBudgetPolicyRefusesAStaleNoneOnAColdCache is finding M3's pin, and
// it is the exact shape the signature and the version check BOTH miss.
//
// The cache is COLD (a restart, a fresh install), so there is no cached
// version to compare and no cached body to fall back on. The document is
// genuinely the org's — correctly signed, for this caller — it is simply OLD:
// an explicit none the org minted yesterday and has since replaced with a cap.
// Anyone able to answer on this rail can hold that document and serve it
// forever, and a fail-closed managed node would UNBLOCK on it.
//
// Only issued_at dates the document, and only the org can set it, because it
// is inside the signed body.
func TestFetchBudgetPolicyRefusesAStaleNoneOnAColdCache(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.SetBudgetClock(func() time.Time { return now })

	stale := orgcontract.EmptyBudgetPolicyBody(9)
	stale.IssuedAt = now.Add(-26 * time.Hour).Format(time.RFC3339)
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", stale)
	bs.doc.Store(&doc)

	out, err := c.FetchBudgetPolicy(context.Background())
	if err == nil {
		t.Fatal("a day-old signed none was accepted on a cold cache; it is a standing credential to unblock a managed node")
	}
	if out.State != orgcontract.BudgetFetchUnverified {
		t.Errorf("State = %q, want unverified", out.State)
	}
	if out.HaveBody {
		t.Fatal("HaveBody is true; a refused document must not arm a fail-closed node's release")
	}

	// The SAME document, freshly minted, is accepted — so the refusal is
	// about the date and not about the shape.
	fresh := orgcontract.EmptyBudgetPolicyBody(9)
	fresh.IssuedAt = now.Add(-time.Minute).Format(time.RFC3339)
	freshDoc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", fresh)
	bs.doc.Store(&freshDoc)
	out, err = c.FetchBudgetPolicy(context.Background())
	if err != nil {
		t.Fatalf("a freshly minted none was refused: %v", err)
	}
	if !out.HaveBody || !out.Body.Empty() {
		t.Fatalf("outcome = %+v, want a verified explicit none", out)
	}
}

// TestFetchBudgetPolicyRefusesAFutureDocument: an issued_at hours ahead is a
// document minted to outlive its own freshness window. Small skew is fine —
// node and org clocks drift and refusing over NTP jitter would be an outage
// we manufactured.
func TestFetchBudgetPolicyRefusesAFutureDocument(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs := newBudgetServer(t)
	c, s, _ := enrolledClient(t, bs.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c.SetBudgetClock(func() time.Time { return now })

	future := budgetBody(3, 40_000_000)
	future.IssuedAt = now.Add(6 * time.Hour).Format(time.RFC3339)
	doc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", future)
	bs.doc.Store(&doc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err == nil {
		t.Fatal("a document issued six hours in the future was accepted")
	}

	// A minute of skew is accepted.
	skewed := budgetBody(3, 40_000_000)
	skewed.IssuedAt = now.Add(time.Minute).Format(time.RFC3339)
	skewDoc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", skewed)
	bs.doc.Store(&skewDoc)
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("a minute of clock skew was treated as an attack: %v", err)
	}
}

// TestBudgetPolicyETagIgnoresIssuedAt: the document is re-minted per request,
// so an ETag that covered issued_at would change every second and every
// conditional GET would be a full 200 — the 304 fast path is what makes a
// per-caller rail affordable.
func TestBudgetPolicyETagIgnoresIssuedAt(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	first := budgetBody(4, 1_000)
	first.IssuedAt = "2026-09-13T12:00:00Z"
	second := budgetBody(4, 1_000)
	second.IssuedAt = "2026-09-13T12:00:05Z"

	a, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", first)
	b, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", second)
	da, err := orgcontract.BudgetPolicyDigest(a)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	db, err := orgcontract.BudgetPolicyDigest(b)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if da != db {
		t.Fatal("the ETag moved with issued_at; every poll would be a full 200")
	}

	// A real content change still moves it.
	changed := budgetBody(5, 2_000)
	changed.IssuedAt = first.IssuedAt
	cDoc, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", changed)
	dc, _ := orgcontract.BudgetPolicyDigest(cDoc)
	if dc == da {
		t.Fatal("the ETag did not move for a changed cap")
	}
}

// TestFetchBudgetPolicySendsTheMachineHeader pins the node half of the
// disambiguation rail.
//
// GET /api/agent/budget identifies its caller by the bearer alone, and a
// bearer names a MEMBER — so a developer running a laptop and a devbox under
// one member gave the server no way to know whose spend rows to subtract from
// the cross-machine baseline, and it therefore sent none. The node closes that
// by naming its own machine.
//
// Two properties are asserted and both matter. The value must be the SAME one
// PushEnvelope.MachineIdentity carries (the server matches the header against
// the identities its ingest recorded from those very pushes, so a second
// derivation would drift into never matching), and an UNMANAGED enrolment —
// which has no machine identity at all — must omit the header rather than send
// an empty one.
func TestFetchBudgetPolicySendsTheMachineHeader(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sign := func(t *testing.T, bs *budgetServer) {
		t.Helper()
		doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(7, 1_000))
		if err != nil {
			t.Fatalf("SignBudgetPolicy: %v", err)
		}
		bs.doc.Store(&doc)
	}

	t.Run("a managed node names its own machine", func(t *testing.T) {
		bs := newBudgetServer(t)
		c, s, _ := enrolledClient(t, bs.srv.URL)
		promoteToManaged(t, s, bs.srv.URL)
		pinRoutingKey(t, s, encodeStdKey(pub))
		sign(t, bs)

		want := c.ManagedMachineIdentity(context.Background())
		if want == "" {
			t.Skip("this host resolves no machine identity, so there is nothing to disambiguate with")
		}
		if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
			t.Fatalf("FetchBudgetPolicy: %v", err)
		}
		got, _ := bs.gotMachine.Load().(string)
		if got != want {
			t.Errorf("%s = %q, want the push envelope's own machine identity %q",
				orgcontract.HeaderMachineIdentity, got, want)
		}
	})

	t.Run("an individual enrolment omits the header", func(t *testing.T) {
		bs := newBudgetServer(t)
		c, s, _ := enrolledClient(t, bs.srv.URL)
		pinRoutingKey(t, s, encodeStdKey(pub))
		sign(t, bs)

		if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
			t.Fatalf("FetchBudgetPolicy: %v", err)
		}
		if got, _ := bs.gotMachine.Load().(string); got != "" {
			t.Errorf("%s = %q, want it omitted — an unmanaged node has no machine identity to name",
				orgcontract.HeaderMachineIdentity, got)
		}
	})
}

// promoteToManaged rewrites the singleton enrolment row as MANAGED tenancy,
// which is the only class that resolves a machine identity (the same rule
// PushEnvelope.MachineIdentity follows).
func promoteToManaged(t *testing.T, s *store.Store, srvURL string) {
	t.Helper()
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
		Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatalf("WriteEnrolment (managed): %v", err)
	}
}

// TestFetchBudgetPolicyReMeasuredBaselineReachesTheNode is the end-to-end
// regression for the ETag P1 (adversarial review of the cross-machine
// baseline).
//
// THE SCENARIO. Laptop plus an idle devbox on one org cap. The devbox spent
// $12.34 and stopped. The server re-measures that same $12.34 on every poll and
// re-stamps the measurement time; the node must keep RECEIVING that stamp,
// because internal/orgbudget stops applying a baseline older than
// BaselineMaxAge (two cadences plus a minute) and a dropped baseline composes to
// ZERO — the node would then enforce the org's cap against its local spend alone
// and silently allow $12.34 more than the org can see.
//
// While orgcontract.BudgetPolicyDigest blanked SpentAsOf, the re-stamped body
// digested identically, the server answered 304, and the node kept poll #1's
// stamp forever. This test drives the REAL server rule — measure, sign, digest,
// then compare If-None-Match — so it fails if that exclusion ever comes back.
//
// It also pins the other half: within one measurement minute the 304 fast path
// still works, so the fix costs a small 200 per cadence and nothing more.
func TestFetchBudgetPolicyReMeasuredBaselineReachesTheNode(t *testing.T) {
	const (
		pushInterval = 120 * time.Second
		idleSpend    = 12.34
	)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	start := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	maxAge := orgbudget.BaselineMaxAge(pushInterval)

	// asOf is what the server's NEXT measurement will stamp; the test moves it
	// the way a real clock would.
	var asOf atomic.Value
	asOf.Store(start)
	var served, notModified atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/budget" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// The real handler's order: measure, stamp (minute-truncated), sign,
		// digest, and only THEN consider the conditional request.
		at, _ := asOf.Load().(time.Time)
		body := budgetBody(9, 40_000_000)
		body.Caps[0].SpentUSD = idleSpend
		body.Caps[0].SpentExcludesMachine = true
		body.Caps[0].SpentAsOf = at.UTC().Truncate(time.Minute).Format(time.RFC3339)
		body.IssuedAt = time.Now().UTC().Format(time.RFC3339)
		doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		digest, err := orgcontract.BudgetPolicyDigest(doc)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		etag := `"bp-` + digest + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		served.Add(1)
		writeTestJSON(w, http.StatusOK, doc)
	}))
	t.Cleanup(srv.Close)

	c, s, _ := enrolledClient(t, srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	first, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || !first.HaveBody {
		t.Fatalf("first fetch: %+v err=%v", first, err)
	}

	// Same measurement minute: the fast path must still be a 304 and the body
	// must survive it unchanged.
	if _, err := c.FetchBudgetPolicy(context.Background()); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if notModified.Load() != 1 {
		t.Fatalf("a poll inside one measurement minute did not 304 (304s=%d, 200s=%d) — the fast path is gone",
			notModified.Load(), served.Load())
	}

	// Now the clock runs PAST the staleness window while the devbox stays idle:
	// identical amounts, a later measurement.
	later := start.Add(maxAge).Add(pushInterval)
	asOf.Store(later)
	out, err := c.FetchBudgetPolicy(context.Background())
	if err != nil || !out.HaveBody {
		t.Fatalf("third fetch: %+v err=%v", out, err)
	}
	wantStamp := later.UTC().Truncate(time.Minute).Format(time.RFC3339)
	if got := out.Body.Caps[0].SpentAsOf; got != wantStamp {
		t.Fatalf("SpentAsOf = %q, want the re-measured %q — a 304 froze the stamp and the baseline will age out",
			got, wantStamp)
	}
	if out.Body.Caps[0].SpentUSD != idleSpend {
		t.Fatalf("SpentUSD = %v, want the unchanged %v", out.Body.Caps[0].SpentUSD, idleSpend)
	}

	// The whole point, asserted where it bites: at that later instant the cap is
	// still APPLIED and the other machine's spend is still composing.
	eff, posture := orgbudget.Compose(orgbudget.Thresholds{}, out.Body, orgbudget.Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
		GuardMode: "enforce", Now: later, BaselineMaxAge: maxAge,
	})
	if posture.OrgBaseline != orgcontract.BudgetBaselineApplied {
		t.Fatalf("OrgBaseline = %q, want applied — the node stopped counting the other machine's spend",
			posture.OrgBaseline)
	}
	if eff.Baseline.MonthlyUSD != idleSpend {
		t.Fatalf("composed baseline = %v, want %v", eff.Baseline.MonthlyUSD, idleSpend)
	}
}
