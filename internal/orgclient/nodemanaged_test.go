package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// acceptSwitch accepts the org's signed fleet replacement at generation gen
// with the given authority (empty = the switch back's narrowing document).
func acceptSwitch(t *testing.T, c *Client, priv ed25519.PrivateKey, pub ed25519.PublicKey, orgURL, orgID string, gen int64, authority []string) {
	t.Helper()
	r := orgcontract.GrantReplacement{
		OrgID: orgID, OrgServerURL: orgURL, KeyPinSHA256: orgcontract.PublicKeyPinHash(pub),
		Generation: gen, PublicKey: base64.RawURLEncoding.EncodeToString(pub), Authority: authority,
		GrantedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		ConsentMode: govern.ConsentManaged, ConsentActor: "fleet",
	}
	r.Signature = orgcontract.SignGrantReplacement(priv, r)
	ok, err := c.AcceptGrantReplacement(context.Background(), r)
	if err != nil || !ok {
		t.Fatalf("accept generation %d: ok=%v err=%v", gen, ok, err)
	}
}

// TestNodeManaged (operator ruling P-204, audit R1): the one node-side
// predicate. An individual enrolment is not managed until its org's switch
// replacement is accepted, is managed while it holds it, and stops being
// managed when the switch back's narrowing replacement arrives; a managed
// enrolment is managed without any grant.
func TestNodeManaged(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	const orgURL = "https://org.example.com"
	pub, priv := seedEnrolledNode(t, s, orgURL, "org-1")
	check := func(want bool, when string) {
		t.Helper()
		got, err := NodeManaged(ctx, s)
		if err != nil || got != want {
			t.Fatalf("%s: NodeManaged = %v, %v; want %v", when, got, err, want)
		}
	}
	check(false, "individual, before the switch")
	acceptSwitch(t, c, priv, pub, orgURL, "org-1", 1, []string{govern.AuthorityEnforceBudget})
	check(true, "after the switch")
	acceptSwitch(t, c, priv, pub, orgURL, "org-1", 2, nil)
	check(false, "after the switch back")
	enr, _ := s.LoadEnrolment(ctx)
	enr.Tenancy = orgcontract.TenancyManaged
	if err := s.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatal(err)
	}
	check(true, "managed enrolment")
	if got, err := NodeManaged(ctx, nil); err != nil || got {
		t.Fatalf("no store: %v %v", got, err)
	}
}

// TestSwitchedNodeFetchesAgentConfigPolicy (audit R1): the AI tool settings
// rail asks the org for a switched node, as for a managed enrolment, and
// not for an individual node whose org has not switched.
func TestSwitchedNodeFetchesAgentConfigPolicy(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == orgcontract.AgentConfigPolicyPath {
			calls.Add(1)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_supported"})
	}))
	t.Cleanup(srv.Close)
	s := newAgentStore(t)
	pub, priv := seedEnrolledNode(t, s, srv.URL, "org-1")
	enr, _ := s.LoadEnrolment(ctx)
	if enr.Tenancy != orgcontract.TenancyIndividual {
		t.Fatalf("fixture tenancy %q", enr.Tenancy)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	c.SetAgentConfigPolicyGate(func(context.Context) bool { return true })
	if _, err := c.FetchAgentConfigPolicy(ctx); err != nil || calls.Load() != 0 {
		t.Fatalf("individual node asked: calls=%d err=%v", calls.Load(), err)
	}
	acceptSwitch(t, c, priv, pub, srv.URL, "org-1", 1, []string{govern.AuthorityEnforceBudget})
	if _, err := c.FetchAgentConfigPolicy(ctx); err != nil || calls.Load() != 1 {
		t.Fatalf("switched node did not ask: calls=%d err=%v", calls.Load(), err)
	}
}
