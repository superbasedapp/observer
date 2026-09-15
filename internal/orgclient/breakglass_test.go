package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sealbox"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// leaseBearerStore is memBearerStore plus the optional fourth (break-glass)
// slot, so persistence across a fresh Client is provable.
type leaseBearerStore struct {
	memBearerStore
	mu     sync.Mutex
	leases []byte
}

func (l *leaseBearerStore) SaveBreakGlassLeases(raw []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leases = append([]byte(nil), raw...)
	return nil
}

func (l *leaseBearerStore) LoadBreakGlassLeases() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.leases) == 0 {
		return nil, ErrNoSecret
	}
	return append([]byte(nil), l.leases...), nil
}

// bgServer is a fake org server that verifies the node's seal-key header,
// seals a credential to the advertised key, and hands back leases /
// revocations on the push response. It records what it saw.
type bgServer struct {
	t       *testing.T
	orgKey  ed25519.PrivateKey
	orgPub  ed25519.PublicKey
	mu      sync.Mutex
	sealKey orgcontract.SealKeyAdvertisement
	acks    []string
	// per-push scripted responses
	leases  []orgcontract.BreakGlassLease
	revoked []string
}

func (b *bgServer) handler(agentPub func() ed25519.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		adv, present, err := orgcontract.ParseSealKeyHeader(r.Header.Get(orgcontract.HeaderSealKey))
		if err != nil || !present {
			b.t.Errorf("push carried no seal-key advertisement (err=%v)", err)
		} else if verr := orgcontract.VerifySealKeyAdvertisement(agentPub(), "org-1", "scim-42", adv); verr != nil {
			b.t.Errorf("seal-key advertisement did not verify: %v", verr)
		} else {
			b.sealKey = adv
		}
		if ack := r.Header.Get(orgcontract.HeaderBreakGlassAck); ack != "" {
			b.acks = append(b.acks, strings.Split(ack, ",")...)
		}
		resp := orgcontract.PushResponse{
			AcceptedRows: 1, NextCursor: 1,
			BreakGlassLeases: b.leases, BreakGlassRevokedLeaseIDs: b.revoked,
		}
		b.leases, b.revoked = nil, nil
		writeTestJSON(w, http.StatusOK, resp)
	}
}

// mintLease seals cred to the node's advertised key and signs the lease under
// the org key — exactly what breakglass.Approve + X25519Sealer produce.
func (b *bgServer) mintLease(id, upstream, cred, serverURL string, expires time.Time, mutate func(*orgcontract.BreakGlassLease)) orgcontract.BreakGlassLease {
	b.mu.Lock()
	adv := b.sealKey
	b.mu.Unlock()
	pub, err := sealbox.ParsePublicB64(adv.PublicKey)
	if err != nil {
		b.t.Fatalf("advertised key: %v", err)
	}
	blob, err := sealbox.Seal(nil, pub, []byte(cred), sealbox.LeaseAAD("org-1", "scim-42", upstream))
	if err != nil {
		b.t.Fatal(err)
	}
	l := orgcontract.BreakGlassLease{
		LeaseID: id, RequestID: "bgr-1", OrgID: "org-1", OrgServerURL: serverURL,
		KeyPinSHA256: orgcontract.PublicKeyPinHash(b.orgPub), UserID: "scim-42",
		UpstreamID: upstream, Rung: "break_glass", SealScheme: adv.Scheme, SealedCredential: blob,
		PublicKey: base64.RawURLEncoding.EncodeToString(b.orgPub), ApprovedBy: "super-1",
		GrantedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: expires.UTC().Format(time.RFC3339),
	}
	if mutate != nil {
		mutate(&l)
	}
	l.Signature = orgcontract.SignBreakGlassLease(b.orgKey, l)
	return l
}

func pinOrgKey(t *testing.T, s *store.Store, orgURL string, pub ed25519.PublicKey) {
	t.Helper()
	if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
		Layer: "org", Path: PolicyKeyPinPath(orgURL), ContentHash: orgcontract.PublicKeyPinHash(pub),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestBreakGlass_PushRoundTrip proves the node half end-to-end against a fake
// server: seal key published+verified on push 1 → lease sealed to that key and
// delivered on push 2 → redeemed (credential readable, custody-suspension
// logged) → ACKed on push 3 → early revoke on push 3 drops it. Persistence
// across a fresh Client rides the bearer-store slot.
func TestBreakGlass_PushRoundTrip(t *testing.T) {
	s := newAgentStore(t)
	bs := &leaseBearerStore{}
	orgPub, orgKey, _ := ed25519.GenerateKey(rand.Reader)
	srvState := &bgServer{t: t, orgKey: orgKey, orgPub: orgPub}
	var agentPub ed25519.PublicKey
	srv := httptest.NewServer(srvState.handler(func() ed25519.PublicKey { return agentPub }))
	defer srv.Close()
	agentPub = enrolFixture(t, s, &bs.memBearerStore, srv.URL)
	pinOrgKey(t, s, srv.URL, orgPub)
	c := newTestClient(t, s, bs)

	// Push 1: publishes the seal key; nothing to redeem yet. (seedActivity is
	// idempotent per event id, so each push seeds one MORE row than the last.)
	seedActivity(t, s, 1)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatalf("push 1: %v", err)
	}
	if srvState.sealKey.Scheme != sealbox.SchemeV1 || srvState.sealKey.PublicKey == "" {
		t.Fatalf("server recorded no seal key: %+v", srvState.sealKey)
	}
	if _, ok := c.BreakGlassCredential("anthropic-prod"); ok {
		t.Fatal("credential present before any lease")
	}

	// Push 2: the server delivers a sealed lease.
	exp := time.Now().Add(time.Hour)
	srvState.leases = []orgcontract.BreakGlassLease{srvState.mintLease("bgl-1", "anthropic-prod", "sk-ant-LEASED", srv.URL, exp, nil)}
	seedActivity(t, s, 2)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatalf("push 2: %v", err)
	}
	cred, ok := c.BreakGlassCredential("anthropic-prod")
	if !ok || cred.Credential != "sk-ant-LEASED" || cred.LeaseID != "bgl-1" {
		t.Fatalf("credential after delivery = %+v ok=%v", cred, ok)
	}
	if got := c.LiveBreakGlassLeases(); len(got) != 1 || got[0].UpstreamID != "anthropic-prod" {
		t.Fatalf("live leases = %+v", got)
	}
	if _, ok := c.BreakGlassCredential("openai-prod"); ok {
		t.Fatal("a lease for one upstream answered for another")
	}
	// The credential is in the bearer-store slot, not the agent DB.
	if raw, _ := bs.LoadBreakGlassLeases(); !strings.Contains(string(raw), "sk-ant-LEASED") {
		t.Fatal("lease not persisted to the bearer-store slot")
	}
	if got := c.pendingBreakGlassAcks(); len(got) != 1 || got[0] != "bgl-1" {
		t.Fatalf("pending acks = %v", got)
	}

	// A FRESH client (daemon restart) rehydrates from the slot.
	c2 := newTestClient(t, s, bs)
	if cred2, ok := c2.BreakGlassCredential("anthropic-prod"); !ok || cred2.Credential != "sk-ant-LEASED" {
		t.Fatalf("fresh client credential = %+v ok=%v", cred2, ok)
	}

	// Push 3: ACK rides the header; the server announces an early revoke.
	srvState.revoked = []string{"bgl-1"}
	seedActivity(t, s, 3)
	if _, err := c2.PushOnce(context.Background()); err != nil {
		t.Fatalf("push 3: %v", err)
	}
	if len(srvState.acks) != 1 || srvState.acks[0] != "bgl-1" {
		t.Fatalf("server saw acks %v, want [bgl-1]", srvState.acks)
	}
	if _, ok := c2.BreakGlassCredential("anthropic-prod"); ok {
		t.Fatal("revoked lease still answers")
	}
	if raw, _ := bs.LoadBreakGlassLeases(); strings.Contains(string(raw), "sk-ant-LEASED") {
		t.Fatal("revoked credential still persisted")
	}
}

// TestBreakGlass_RedeemRefusals walks every accept gate: each mutated lease is
// refused (accepted=false, err=nil) and leaves no credential behind.
func TestBreakGlass_RedeemRefusals(t *testing.T) {
	s := newAgentStore(t)
	bs := &leaseBearerStore{}
	orgPub, orgKey, _ := ed25519.GenerateKey(rand.Reader)
	srvState := &bgServer{t: t, orgKey: orgKey, orgPub: orgPub}
	var agentPub ed25519.PublicKey
	srv := httptest.NewServer(srvState.handler(func() ed25519.PublicKey { return agentPub }))
	defer srv.Close()
	agentPub = enrolFixture(t, s, &bs.memBearerStore, srv.URL)
	pinOrgKey(t, s, srv.URL, orgPub)
	c := newTestClient(t, s, bs)
	seedActivity(t, s, 1)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	enr, _ := s.LoadEnrolment(context.Background())
	exp := time.Now().Add(time.Hour)
	_, otherOrgKey, _ := ed25519.GenerateKey(rand.Reader)
	otherOrgPub := otherOrgKey.Public().(ed25519.PublicKey)

	cases := []struct {
		name  string
		lease orgcontract.BreakGlassLease
	}{
		{"different org", srvState.mintLease("x1", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.OrgID = "org-2" })},
		{"different server", srvState.mintLease("x2", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.OrgServerURL = "https://evil.example" })},
		{"different node", srvState.mintLease("x3", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.UserID = "scim-99" })},
		{"unknown rung", srvState.mintLease("x4", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.Rung = "direct" })},
		{"expired", srvState.mintLease("x5", "u", "c", srv.URL, time.Now().Add(-time.Minute), nil)},
		{"unknown scheme", srvState.mintLease("x6", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.SealScheme = "rot13" })},
		{"tampered signature", func() orgcontract.BreakGlassLease {
			l := srvState.mintLease("x7", "u", "c", srv.URL, exp, nil)
			l.ApprovedBy = "attacker"
			return l
		}()},
		{"unpinned signing key", func() orgcontract.BreakGlassLease {
			l := srvState.mintLease("x8", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) {
				l.PublicKey = base64.RawURLEncoding.EncodeToString(otherOrgPub)
				l.KeyPinSHA256 = orgcontract.PublicKeyPinHash(otherOrgPub)
			})
			l.Signature = orgcontract.SignBreakGlassLease(otherOrgKey, l)
			return l
		}()},
		{"declared pin mismatch", srvState.mintLease("x9", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.KeyPinSHA256 = "cafe" })},
		{"sealed for another upstream", srvState.mintLease("x10", "u", "c", srv.URL, exp, func(l *orgcontract.BreakGlassLease) { l.UpstreamID = "other" })},
	}
	for _, tc := range cases {
		accepted, err := c.RedeemBreakGlassLease(context.Background(), tc.lease, bs.key, enr)
		if err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if accepted {
			t.Errorf("%s: accepted, want refusal", tc.name)
		}
	}
	if got := c.LiveBreakGlassLeases(); len(got) != 0 {
		t.Fatalf("refused leases left state behind: %+v", got)
	}
	// And the honest one is accepted, idempotently.
	good := srvState.mintLease("ok-1", "u", "c", srv.URL, exp, nil)
	for i := 0; i < 2; i++ {
		if accepted, err := c.RedeemBreakGlassLease(context.Background(), good, bs.key, enr); !accepted || err != nil {
			t.Fatalf("good lease attempt %d: accepted=%v err=%v", i, accepted, err)
		}
	}
	if got, ok := c.BreakGlassCredential("u"); !ok || got.Credential != "c" {
		t.Fatalf("good lease credential = %+v ok=%v", got, ok)
	}
	// No pin recorded at all ⇒ refused (never TOFU).
	s2 := newAgentStore(t)
	bs2 := &leaseBearerStore{}
	enrolFixture(t, s2, &bs2.memBearerStore, srv.URL)
	c3 := newTestClient(t, s2, bs2)
	enr2, _ := s2.LoadEnrolment(context.Background())
	if accepted, _ := c3.RedeemBreakGlassLease(context.Background(), good, bs2.key, enr2); accepted {
		t.Fatal("accepted a lease with no pinned org key")
	}
}

// TestBreakGlass_UnenrollForgetsLeases pins that unenrol clears redeemed
// leases (custody suspension never outlives the enrolment).
func TestBreakGlass_UnenrollForgetsLeases(t *testing.T) {
	s := newAgentStore(t)
	bs := &leaseBearerStore{}
	orgPub, orgKey, _ := ed25519.GenerateKey(rand.Reader)
	srvState := &bgServer{t: t, orgKey: orgKey, orgPub: orgPub}
	var agentPub ed25519.PublicKey
	srv := httptest.NewServer(srvState.handler(func() ed25519.PublicKey { return agentPub }))
	defer srv.Close()
	agentPub = enrolFixture(t, s, &bs.memBearerStore, srv.URL)
	pinOrgKey(t, s, srv.URL, orgPub)
	c := newTestClient(t, s, bs)
	seedActivity(t, s, 1)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	srvState.leases = []orgcontract.BreakGlassLease{srvState.mintLease("bgl-9", "up", "cred", srv.URL, time.Now().Add(time.Hour), nil)}
	seedActivity(t, s, 2)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.BreakGlassCredential("up"); !ok {
		t.Fatal("lease not redeemed")
	}
	if err := c.Unenroll(context.Background()); err != nil {
		t.Fatalf("Unenroll: %v", err)
	}
	if _, ok := c.BreakGlassCredential("up"); ok {
		t.Fatal("lease survived unenrol")
	}
}
