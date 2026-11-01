package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// recordingSinks captures every outcome per rail.
type recordingSinks struct {
	mu  sync.Mutex
	got map[string][]ManagedPullOutcome
}

func (r *recordingSinks) sink(rail string) ManagedPullSink {
	return func(o ManagedPullOutcome) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.got == nil {
			r.got = map[string][]ManagedPullOutcome{}
		}
		r.got[rail] = append(r.got[rail], o)
	}
}

func (r *recordingSinks) last(t *testing.T, rail string) ManagedPullOutcome {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got[rail]) == 0 {
		t.Fatalf("no outcome recorded for rail %q", rail)
	}
	return r.got[rail][len(r.got[rail])-1]
}

// TestPollManagedPullRails_OnlyRegisteredRails: a rail with no sink makes no
// request; the registered one is polled with the consent the resolver gave
// for ITS rail, and the outcome reaches its sink.
func TestPollManagedPullRails_OnlyRegisteredRails(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	var (
		mu    sync.Mutex
		paths []string
	)
	doc := signFor(t, priv, "sandbox", "scim-42", 1, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)
	m.set(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		writeTestJSON(w, http.StatusOK, doc)
	})
	var consentRails []string
	rec := &recordingSinks{}
	c.SetManagedPullRails(func(_ context.Context, rail orgcontract.ManagedPullRail) ManagedPullConsent {
		consentRails = append(consentRails, rail.Name)
		return ManagedPullConsent{Managed: true, HoldsAuthority: rail.Authority == "enforce.sandbox"}
	}, map[string]ManagedPullSink{"sandbox": rec.sink("sandbox"), "not-a-rail": rec.sink("x")})
	c.pollManagedPullRails(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/api/agent/sandbox" {
		t.Fatalf("only the sandbox rail may be fetched, got %v", paths)
	}
	if len(consentRails) != 1 || consentRails[0] != "sandbox" {
		t.Fatalf("consent asked for %v", consentRails)
	}
	if out := rec.last(t, "sandbox"); !out.InForce || out.Version != 1 {
		t.Fatalf("sandbox outcome: %+v", out)
	}
}

// TestPollManagedPullRails_NoSinksNoRequests is the existing-install case: a
// client with nothing registered makes no managed-pull request at all.
func TestPollManagedPullRails_NoSinksNoRequests(t *testing.T) {
	m := newMPServer(t)
	c, _, _ := managedPullFixture(t, m.srv.URL)
	hits := 0
	m.set(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(http.StatusNotFound) })
	c.pollManagedPullRails(context.Background())
	c.PrimeManagedPullRails(context.Background())
	if hits != 0 {
		t.Fatalf("no sink registered, but %d requests were made", hits)
	}
}

// TestPollManagedPullRails_NoConsentNoRequest: a rail without full consent
// (an individual node, a managed node without the rail's authority, a nil
// resolver) makes no request; its sink hears an inert outcome (SBX-P1C merge
// finding 8).
func TestPollManagedPullRails_NoConsentNoRequest(t *testing.T) {
	for _, consent := range []*ManagedPullConsent{nil, {}, {Managed: true}, {HoldsAuthority: true}} {
		m := newMPServer(t)
		c, priv, now := managedPullFixture(t, m.srv.URL)
		hits := 0
		doc := signFor(t, priv, "sandbox", "scim-42", 3, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)
		m.set(func(w http.ResponseWriter, _ *http.Request) { hits++; writeTestJSON(w, http.StatusOK, doc) })
		var resolver ManagedPullConsentFunc
		if consent != nil {
			cc := *consent
			resolver = func(context.Context, orgcontract.ManagedPullRail) ManagedPullConsent { return cc }
		}
		rec := &recordingSinks{}
		c.SetManagedPullRails(resolver, map[string]ManagedPullSink{"sandbox": rec.sink("sandbox")})
		c.pollManagedPullRails(context.Background())
		if out := rec.last(t, "sandbox"); hits != 0 || out.InForce {
			t.Fatalf("consent %+v: hits=%d outcome %+v", consent, hits, out)
		}
	}
}

// TestPollManagedPullRails_RevokedAuthorityStopsApplying: a stored body that
// applied stops applying at the next cycle once the authority is revoked,
// with no request.
func TestPollManagedPullRails_RevokedAuthorityStopsApplying(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 3, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)))
	if out, err := c.FetchManagedPull(context.Background(), "sandbox", managed); err != nil || !out.InForce {
		t.Fatalf("install: %+v %v", out, err)
	}
	hits := 0
	m.set(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(http.StatusInternalServerError) })
	rec := &recordingSinks{}
	c.SetManagedPullRails(func(context.Context, orgcontract.ManagedPullRail) ManagedPullConsent {
		return ManagedPullConsent{Managed: true}
	},
		map[string]ManagedPullSink{"sandbox": rec.sink("sandbox")})
	c.pollManagedPullRails(context.Background())
	if out := rec.last(t, "sandbox"); hits != 0 || out.InForce || out.Version != 3 {
		t.Fatalf("revoked: hits=%d %+v", hits, out)
	}
}

// TestPrimeManagedPullRails_FromStore: at daemon start the stored document
// reaches the sink without a request, re-verified, never state ok.
func TestPrimeManagedPullRails_FromStore(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 2, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)))
	full := func(context.Context, orgcontract.ManagedPullRail) ManagedPullConsent { return managed }
	if _, err := c.FetchManagedPull(context.Background(), "sandbox", managed); err != nil {
		t.Fatal(err)
	}
	hits := 0
	m.set(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(http.StatusInternalServerError) })
	rec := &recordingSinks{}
	c.SetManagedPullRails(full, map[string]ManagedPullSink{"sandbox": rec.sink("sandbox")})
	c.PrimeManagedPullRails(context.Background())
	out := rec.last(t, "sandbox")
	if hits != 0 || !out.InForce || out.Version != 2 || out.State == ManagedPullStateOK {
		t.Fatalf("prime: hits=%d %+v", hits, out)
	}
}

// TestPollManagedPullRails_404NeverClears: a stored body survives a 404.
func TestPollManagedPullRails_404NeverClears(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 4, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)))
	rec := &recordingSinks{}
	c.SetManagedPullRails(func(context.Context, orgcontract.ManagedPullRail) ManagedPullConsent { return managed },
		map[string]ManagedPullSink{"sandbox": rec.sink("sandbox")})
	c.pollManagedPullRails(context.Background())
	m.set(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "not_supported"})
	})
	c.pollManagedPullRails(context.Background())
	out := rec.last(t, "sandbox")
	if !out.InForce || out.Version != 4 || out.State != ManagedPullStateNotSupported {
		t.Fatalf("a 404 must keep the stored body: %+v", out)
	}
}

// TestFetchManagedPull_FloorSurvivesClearAndKeyRotation is the two-step
// ladder of audit SHR-KIT finding 2 over a real round trip: install v5,
// clear at v6, replay v5 (refused); then the org key rotates and v5 is
// replayed under the old key (unverified) and re-signed under the new key
// (rollback refused). The highest accepted version is kept outside the
// signed document, so neither the clear nor the failed re-verification
// lowers the floor.
func TestFetchManagedPull_FloorSurvivesClearAndKeyRotation(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	body := `{"schema":"sbo-sandbox-managed-v1","enabled":true}`
	v5 := signFor(t, priv, "sandbox", "scim-42", 5, exp, body)
	m.set(serveDoc(v5))
	if out, err := c.FetchManagedPull(ctx, "sandbox", managed); err != nil || out.Action != ManagedPullInstall {
		t.Fatalf("install v5: %+v %v", out, err)
	}
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 6, exp, `{}`)))
	if out, err := c.FetchManagedPull(ctx, "sandbox", managed); err != nil || out.State != ManagedPullStateCleared {
		t.Fatalf("clear at v6: %+v %v", out, err)
	}
	m.set(serveDoc(v5))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.State != ManagedPullStateRollbackRefused || out.InForce {
		t.Fatalf("replay v5 after the clear: %+v", out)
	}

	// The org key rotates on the node's pin.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	seedEnrolmentKey(t, c, m.srv.URL, newPub)
	m.set(serveDoc(v5))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.InForce || out.Action == ManagedPullInstall {
		t.Fatalf("v5 under the old key after rotation must not install: %+v", out)
	}
	m.set(serveDoc(signFor(t, newPriv, "sandbox", "scim-42", 5, exp, body)))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.State != ManagedPullStateRollbackRefused || out.InForce {
		t.Fatalf("v5 re-signed under the new key must be refused by the floor: %+v", out)
	}
	m.set(serveDoc(signFor(t, newPriv, "sandbox", "scim-42", 7, exp, body)))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.Action != ManagedPullInstall || !out.InForce {
		t.Fatalf("a newer version under the new key installs: %+v", out)
	}
	// And a stored document that no longer verifies after a SECOND rotation
	// keeps its floor too.
	thirdPub, thirdPriv, _ := ed25519.GenerateKey(rand.Reader)
	seedEnrolmentKey(t, c, m.srv.URL, thirdPub)
	m.set(serveDoc(signFor(t, thirdPriv, "sandbox", "scim-42", 6, exp, body)))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.State != ManagedPullStateRollbackRefused {
		t.Fatalf("v6 under a third key below the stored v7: %+v", out)
	}
}

// TestSandboxRailAcceptanceRows is the P1c acceptance over a real round
// trip on the sandbox rail, from an installed v3: a body signed for another
// node, a replayed lower version, an expired body and an unsigned body are
// each refused and keep v3; a 404 never clears; a signed empty body clears;
// and the same body is inert without the authority and on an individual
// node.
func TestSandboxRailAcceptanceRows(t *testing.T) {
	m := newMPServer(t)
	c, priv, now := managedPullFixture(t, m.srv.URL)
	ctx := context.Background()
	exp := now.Unix() + 3600
	body := `{"schema":"sbo-sandbox-managed-v1","enabled":true}`
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 3, exp, body)))
	if out, err := c.FetchManagedPull(ctx, "sandbox", managed); err != nil || !out.InForce || out.Version != 3 {
		t.Fatalf("install v3: %+v %v", out, err)
	}
	unsigned := signFor(t, priv, "sandbox", "scim-42", 9, exp, body)
	unsigned.Signature = ""
	refusals := []struct {
		name string
		doc  orgcontract.ManagedPullDoc
		want string
	}{
		{"signed for another node", signFor(t, priv, "sandbox", "scim-99", 9, exp, body), ManagedPullStateUnverified},
		{"replayed lower version", signFor(t, priv, "sandbox", "scim-42", 2, exp, body), ManagedPullStateRollbackRefused},
		{"expired", signFor(t, priv, "sandbox", "scim-42", 9, now.Unix()-1, body), ManagedPullStateExpiredOnArrival},
		{"unsigned", unsigned, ManagedPullStateUnverified},
		{"the security rail's body", signFor(t, priv, "security", "scim-42", 9, exp, body), ManagedPullStateUnverified},
	}
	for _, r := range refusals {
		m.set(serveDoc(r.doc))
		out, err := c.FetchManagedPull(ctx, "sandbox", managed)
		if err != nil || out.State != r.want || !out.InForce || out.Version != 3 {
			t.Fatalf("%s: want %s keeping v3 in force, got %+v %v", r.name, r.want, out, err)
		}
	}
	m.set(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusNotFound, map[string]string{"error": "not_supported"})
	})
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); !out.InForce || out.Version != 3 {
		t.Fatalf("a 404 must never clear: %+v", out)
	}
	for _, consent := range []ManagedPullConsent{{Managed: true}, {HoldsAuthority: true}, {}} {
		m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 3, exp, body)))
		if out, _ := c.FetchManagedPull(ctx, "sandbox", consent); out.InForce || out.Version != 3 {
			t.Fatalf("consent %+v must leave the body inert: %+v", consent, out)
		}
	}
	m.set(serveDoc(signFor(t, priv, "sandbox", "scim-42", 4, exp, `{}`)))
	if out, _ := c.FetchManagedPull(ctx, "sandbox", managed); out.State != ManagedPullStateCleared || out.InForce || len(out.Body) != 0 {
		t.Fatalf("a signed empty body clears: %+v", out)
	}
}
