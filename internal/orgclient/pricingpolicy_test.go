package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// THE NODE PRICING RAIL, node half (enterprise-pricing plan §3.3, W2).
//
// Every rung of the ladder gets a case, because on THIS rail the difference
// between two rungs is the difference between a fleet pricing at negotiated
// rates and a fleet permanently mis-pricing captured turns (ruling R8: there
// is no retroactive re-pricing).

func pricingBody(version int64, model string, in, out float64) orgcontract.PricingPolicyBody {
	return orgcontract.PricingPolicyBody{
		Version:     version,
		GeneratedAt: "2026-09-08T00:00:00Z",
		Rows: []orgcontract.PricingPolicyRow{
			{Model: model, InputPerMTok: orgcontract.Rate(in), OutputPerMTok: orgcontract.Rate(out), Source: "negotiated"},
		},
	}
}

type pricingServer struct {
	srv    *httptest.Server
	doc    atomic.Pointer[orgcontract.PricingPolicyDoc]
	etag   atomic.Value // string
	status atomic.Int32 // 0 = serve the doc
	gotINM atomic.Value // string
	hits   atomic.Int32
}

func newPricingServer(t *testing.T) *pricingServer {
	t.Helper()
	ps := &pricingServer{}
	ps.etag.Store("")
	ps.gotINM.Store("")
	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/pricing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ps.hits.Add(1)
		ps.gotINM.Store(r.Header.Get("If-None-Match"))
		if st := ps.status.Load(); st != 0 {
			w.WriteHeader(int(st))
			return
		}
		etag, _ := ps.etag.Load().(string)
		if etag != "" {
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
		}
		writeTestJSON(w, http.StatusOK, ps.doc.Load())
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

// enabledPricing turns the rail on the way `observer start` does.
func enabledPricing(c *Client) { c.SetPricingRail(func() bool { return true }, nil) }

// THE HAPPY PATH: a signed body verifies against the key another rail pinned,
// is APPLIED, and is PERSISTED — the last part being the whole reason this
// rail has a table when the sibling budget rail does not.
func TestFetchPricingPolicyAcceptsAndPersists(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	enabledPricing(c)
	pinRoutingKey(t, s, encodeStdKey(pub))

	doc, err := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(7, "claude-opus-4-8", 4, 20))
	if err != nil {
		t.Fatalf("SignPricingPolicy: %v", err)
	}
	ps.doc.Store(&doc)
	ps.etag.Store(`"pp-abc"`)

	out, err := c.FetchPricingPolicy(context.Background())
	if err != nil {
		t.Fatalf("FetchPricingPolicy: %v", err)
	}
	if out.State != orgcontract.PricingFetchVerified || !out.HaveBody || !out.Changed {
		t.Fatalf("outcome = %+v, want a verified, changed body", out)
	}
	if len(out.Body.Rows) != 1 || rateOfRow(out.Body.Rows[0]) != 4 {
		t.Fatalf("body rows = %+v", out.Body.Rows)
	}
	cached, err := s.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || cached.Version != 7 {
		t.Fatalf("the accepted document did not persist: %+v err=%v — a restart would silently re-price at list rates", cached, err)
	}
	if !out.Witness.Valid() || cached.Witness != out.Witness {
		t.Fatalf("accepted witness = %+v, cached witness = %+v; fetch and durable state must agree", out.Witness, cached.Witness)
	}

	// Second poll: the ETag rides out and a 304 keeps the document.
	out2, err := c.FetchPricingPolicy(context.Background())
	if err != nil {
		t.Fatalf("second FetchPricingPolicy: %v", err)
	}
	if got, _ := ps.gotINM.Load().(string); got != `"pp-abc"` {
		t.Errorf("If-None-Match = %q, want the cached ETag", got)
	}
	if out2.State != orgcontract.PricingFetchVerified || !out2.HaveBody || out2.Changed {
		t.Errorf("304 outcome = %+v, want the cached body unchanged", out2)
	}
	if out2.Witness != out.Witness {
		t.Errorf("304 witness = %+v, want the durable witness %+v", out2.Witness, out.Witness)
	}
}

// A verified EMPTY body is the ONE thing that may clear the node's table.
func TestFetchPricingPolicySignedEmptyClearsTheTable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	enabledPricing(c)
	pinRoutingKey(t, s, encodeStdKey(pub))

	full, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(1, "m", 1, 2))
	ps.doc.Store(&full)
	if _, err := c.FetchPricingPolicy(context.Background()); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	empty, _ := orgcontract.SignPricingPolicy(priv, "org-1", orgcontract.PricingPolicyBody{
		Version: 2, GeneratedAt: "2026-09-09T00:00:00Z", Rows: []orgcontract.PricingPolicyRow{},
	})
	ps.doc.Store(&empty)
	out, err := c.FetchPricingPolicy(context.Background())
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if out.State != orgcontract.PricingFetchNoPricing {
		t.Fatalf("state = %q, want no_pricing", out.State)
	}
	if len(out.Body.Rows) != 0 {
		t.Errorf("rows = %+v, want the withdrawal applied", out.Body.Rows)
	}
	cached, _ := s.LoadOrgPricing(context.Background())
	if !cached.Have || len(cached.Body.Rows) != 0 || cached.State != orgcontract.PricingFetchNoPricing {
		t.Errorf("cache = %+v, want the signed withdrawal STORED (not merely forgotten)", cached)
	}
}

// The rest of the ladder: every non-200 leaves the persisted document exactly
// as it was and names its own state. A 404 is called out separately below
// because it is the one that used to be a cache-clearing lever (N1).
func TestFetchPricingPolicyLadderFailsOpen(t *testing.T) {
	cases := []struct {
		name   string
		status int
		want   string
	}{
		{"an older server has no rail", http.StatusNotFound, orgcontract.PricingFetchNotSupported},
		{"a refused credential", http.StatusUnauthorized, orgcontract.PricingFetchAuthFailed},
		{"a forbidden credential", http.StatusForbidden, orgcontract.PricingFetchAuthFailed},
		{"the org published no signing key", http.StatusConflict, orgcontract.PricingFetchChannelOff},
		{"a server error", http.StatusInternalServerError, orgcontract.PricingFetchUnreachable},
		{"a gateway error", http.StatusBadGateway, orgcontract.PricingFetchUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			ps := newPricingServer(t)
			c, s, _ := enrolledClient(t, ps.srv.URL)
			enabledPricing(c)
			pinRoutingKey(t, s, encodeStdKey(pub))

			good, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(3, "m", 5, 10))
			ps.doc.Store(&good)
			if _, err := c.FetchPricingPolicy(context.Background()); err != nil {
				t.Fatalf("seed fetch: %v", err)
			}

			ps.status.Store(int32(tc.status))
			out, _ := c.FetchPricingPolicy(context.Background())
			if out.State != tc.want {
				t.Errorf("state = %q, want %q", out.State, tc.want)
			}
			if !out.HaveBody || len(out.Body.Rows) != 1 || rateOfRow(out.Body.Rows[0]) != 5 {
				t.Errorf("outcome body = %+v, want the previously verified document to stay in force (fail-open)", out.Body)
			}
			cached, _ := s.LoadOrgPricing(context.Background())
			if !cached.Have || cached.Version != 3 || len(cached.Body.Rows) != 1 {
				t.Errorf("cache = %+v after a %d — every non-200 must leave the persisted document untouched",
					cached, tc.status)
			}
		})
	}
}

// A REPLAYED older version is refused, and a body signed for the wrong DOMAIN
// or the wrong org never verifies. Both leave the node on its previous table.
func TestFetchPricingPolicyRefusesReplayAndWrongDomain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	enabledPricing(c)
	pinRoutingKey(t, s, encodeStdKey(pub))

	newer, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(9, "m", 5, 10))
	ps.doc.Store(&newer)
	if _, err := c.FetchPricingPolicy(context.Background()); err != nil {
		t.Fatalf("seed fetch: %v", err)
	}

	// A genuinely signed OLDER document, replayed by an intermediary.
	older, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(4, "m", 99, 200))
	ps.doc.Store(&older)
	out, err := c.FetchPricingPolicy(context.Background())
	if err == nil {
		t.Error("a replayed lower version was accepted without complaint")
	}
	if out.State != orgcontract.PricingFetchUnverified {
		t.Errorf("state = %q, want unverified", out.State)
	}
	if rateOfRow(out.Body.Rows[0]) != 5 {
		t.Errorf("the replay took effect: %v", out.Body.Rows[0].InputPerMTok)
	}
	cached, _ := s.LoadOrgPricing(context.Background())
	if cached.Version != 9 {
		t.Errorf("cached version = %d, want the newer 9 to survive the replay", cached.Version)
	}

	// A signature minted on the sibling BUDGET rail, carried on a pricing
	// document. The domain tag is what refuses it.
	budgetSig, _ := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(20, 1))
	crossed := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: pricingBody(20, "m", 77, 100),
		Signature:         budgetSig.Signature,
	}
	ps.doc.Store(&crossed)
	out2, err := c.FetchPricingPolicy(context.Background())
	if err == nil {
		t.Error("a budget-rail signature was accepted on the pricing rail")
	}
	if out2.State != orgcontract.PricingFetchUnverified || rateOfRow(out2.Body.Rows[0]) != 5 {
		t.Errorf("outcome = %+v, want the previous document kept", out2)
	}

	_ = pub
}

// NO PINNED KEY: the body is refused, never applied unsigned. The node's only
// defence on this rail is a signature it can check, and this rail establishes
// no pin of its own (F23) — it borrows the routing/announcement pin.
func TestFetchPricingPolicyRefusesWithNoPin(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	enabledPricing(c)

	doc, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(1, "m", 1, 2))
	ps.doc.Store(&doc)

	out, err := c.FetchPricingPolicy(context.Background())
	if err == nil {
		t.Error("a body was accepted with no pinned org key")
	}
	if out.State != orgcontract.PricingFetchUnverified || out.HaveBody {
		t.Fatalf("outcome = %+v, want unverified with no body", out)
	}
	cached, _ := s.LoadOrgPricing(context.Background())
	if cached.Have {
		t.Error("an unverifiable body was persisted")
	}
	// And the PRICING cache must not become a third pin source: a later poll
	// with still no pin must still refuse.
	out2, _ := c.FetchPricingPolicy(context.Background())
	if out2.State != orgcontract.PricingFetchUnverified {
		t.Errorf("second poll state = %q — the pricing cache became a pin source", out2.State)
	}
}

// Ruling R2: the rail is gated by [guard.budget].from_org. A node that never
// opted in makes NO REQUEST at all — the switch is about what this machine
// applies AND about what it asks for.
func TestFetchPricingPolicyDisabledMakesNoRequest(t *testing.T) {
	ps := newPricingServer(t)
	c, _, _ := enrolledClient(t, ps.srv.URL)
	// No SetPricingRail call at all: the zero state.
	out, err := c.FetchPricingPolicy(context.Background())
	if err != nil {
		t.Fatalf("FetchPricingPolicy on a disabled rail returned an error: %v", err)
	}
	if out.State != orgcontract.PricingFetchDisabled {
		t.Errorf("state = %q, want disabled", out.State)
	}
	if ps.hits.Load() != 0 {
		t.Errorf("the disabled rail made %d request(s)", ps.hits.Load())
	}
}

// An UNENROLLED node reports not_enrolled and touches nothing.
func TestFetchPricingPolicyNotEnrolled(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{bearer: "b"})
	enabledPricing(c)
	out, err := c.FetchPricingPolicy(context.Background())
	if err == nil {
		t.Error("an unenrolled node reported no error")
	}
	if out.State != orgcontract.PricingFetchNotEnrolled {
		t.Errorf("state = %q, want not_enrolled", out.State)
	}
}

// The sink receives every cycle's outcome, which is how the live cost engine
// learns a new document landed without the fetch rail knowing what an engine
// is.
func TestFetchPricingPolicyNotifiesTheSink(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	pinRoutingKey(t, s, encodeStdKey(pub))

	var got []PricingFetchOutcome
	c.SetPricingRail(func() bool { return true }, func(o PricingFetchOutcome) { got = append(got, o) })

	doc, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(2, "m", 3, 6))
	ps.doc.Store(&doc)
	if _, err := c.FetchPricingPolicy(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || got[0].State != orgcontract.PricingFetchVerified {
		t.Fatalf("sink saw %+v, want one verified outcome", got)
	}
	if len(got[0].Body.Rows) != 1 {
		t.Errorf("the sink's outcome carried no rows: %+v", got[0])
	}
}

// A cold start with a PERSISTED document reports it before any poll: that is
// the whole point of persisting, and a node that had to wait for a poll would
// price every turn in between at list rates, permanently.
func TestLoadPersistedPricingOnColdStart(t *testing.T) {
	s := newAgentStore(t)
	doc := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: pricingBody(6, "m", 2, 8), Signature: "c2ln",
	}
	if err := s.SaveOrgPricing(context.Background(), doc, "fp", orgcontract.PricingFetchVerified); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}
	cached, err := s.LoadOrgPricing(context.Background())
	if err != nil || !cached.Have || rateOfRow(cached.Body.Rows[0]) != 2 {
		t.Fatalf("cold-start load = %+v err=%v", cached, err)
	}
}

// COLD-START REPLAY (W7 review F1): the persisted document's signer
// fingerprint is restored on LoadPersistedPricing, so the first poll after a
// restart still refuses a validly-signed OLDER document under the same key. A
// document signed by a DIFFERENT key (a rotation) is the one case the guard
// stands down for.
func TestLoadPersistedPricingRestoresReplayGuard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPricingServer(t)
	c, s, _ := enrolledClient(t, ps.srv.URL)
	enabledPricing(c)
	pinRoutingKey(t, s, encodeStdKey(pub))

	newer, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(12, "m", 5, 10))
	identity := currentPricingIdentity(t, s)
	if err := s.SaveOrgPricing(context.Background(), newer, orgcontract.PublicKeyPinHash(pub), orgcontract.PricingFetchVerified, identity); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}
	if _, err := c.LoadPersistedPricing(context.Background()); err != nil {
		t.Fatalf("LoadPersistedPricing: %v", err)
	}
	if got := c.pricing.signedBy(); got != orgcontract.PublicKeyPinHash(pub) {
		t.Fatalf("cold start restored signer fingerprint %q, want the persisted one", got)
	}

	older, _ := orgcontract.SignPricingPolicy(priv, "org-1", pricingBody(11, "m", 99, 200))
	ps.doc.Store(&older)
	out, err := c.FetchPricingPolicy(context.Background())
	if err == nil {
		t.Error("first poll after a restart accepted a replayed lower version")
	}
	if out.State != orgcontract.PricingFetchUnverified || rateOfRow(out.Body.Rows[0]) != 5 {
		t.Errorf("outcome = %+v, want the persisted v12 kept", out)
	}
	cached, _ := s.LoadOrgPricing(context.Background())
	if cached.Version != 12 {
		t.Errorf("cached version = %d, want 12 to survive the cold-start replay", cached.Version)
	}

	// A persisted row with NO fingerprint (pre-fingerprint lineage) is treated
	// as the same key: the replay is still refused.
	c.pricing.store("", cached.Body, "")
	out, err = c.FetchPricingPolicy(context.Background())
	if err == nil || rateOfRow(out.Body.Rows[0]) != 5 {
		t.Errorf("unknown cached signer let a replay through: err=%v out=%+v", err, out)
	}
}

var _ = store.Enrolment{}

// rateOfRow reads a nullable wire rate for an assertion, returning a sentinel
// no test expects when the rate was not quoted at all. Since server migration
// 135 an absent rate and a rate of zero are different documents, so a test
// that wants "4" must not be satisfied by "nothing".
func rateOfRow(r orgcontract.PricingPolicyRow) float64 {
	if r.InputPerMTok == nil {
		return -1
	}
	return *r.InputPerMTok
}
