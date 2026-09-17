package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// pinRoutingKey seeds the routing-policy rail's node-local cache the way
// FetchRoutingPolicy would after verifying a document — i.e. it pins
// that rail's TOFU key.
func pinRoutingKey(t *testing.T, s *store.Store, pubB64 string) {
	t.Helper()
	if err := s.UpsertOrgRoutingPolicy(context.Background(), store.OrgRoutingPolicyRow{
		Version: 1, Body: "[routing]\n", BodyHash: "hash", Signature: "sig",
		ServerPubkey: pubB64, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy: %v", err)
	}
}

// pinAnnouncementKey seeds the announcement rail's node-local cache the
// way FetchOrgAnnouncement would after verifying a document.
func pinAnnouncementKey(t *testing.T, s *store.Store, pubB64 string) {
	t.Helper()
	if err := s.UpsertOrgAnnouncement(context.Background(), store.OrgAnnouncementRow{
		Version: 1, Body: "", BodyHash: "hash", Signature: "sig",
		ServerPubkey: pubB64, ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgAnnouncement: %v", err)
	}
}

// TestFetchOrgAnnouncement_RefusesKeyPinnedByRoutingRail is security
// finding 2: announcement TOFU used to consult only its OWN rail's
// cache, so a node that had been enrolled for months — routing key K1
// long since pinned — would trust ANY key on its first announcement
// fetch, because that rail had never seen one.
//
// One org has ONE distribution signing identity (since ruling R1 the
// server signs every rail with routingpolicy.SigningKeyWith — the
// configured file key when there is one, the database row otherwise), so
// a second key is never a legitimate state unless the ENROLMENT channel
// vouches for it: it is otherwise a substituted server or a MITM, and
// the node already holds the evidence to say so.
func TestFetchOrgAnnouncement_RefusesKeyPinnedByRoutingRail(t *testing.T) {
	ctx := context.Background()
	k1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, k2Priv, _ := ed25519.GenerateKey(rand.Reader)
	as := newAnnouncementServer(t)
	c, s, _ := enrolledClient(t, as.srv.URL)

	pinRoutingKey(t, s, base64.StdEncoding.EncodeToString(k1Pub))

	// Genuinely signed — by the WRONG key. Only the cross-rail pin can
	// refuse this, because the announcement rail has no pin of its own.
	doc := signAnnouncementDoc(1, testAnnBody, k2Priv, k2Pub)
	as.doc = &doc

	changed, err := c.FetchOrgAnnouncement(ctx)
	if err == nil || changed {
		t.Fatalf("a key the routing rail contradicts was accepted: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(err.Error(), "key CHANGED") {
		t.Errorf("error = %v, want the loud key-change refusal class", err)
	}
	if !strings.Contains(err.Error(), routingPolicyRail) {
		t.Errorf("error = %v, want it to name the rail holding the conflicting pin", err)
	}
	if _, ok, _ := s.GetOrgAnnouncement(ctx); ok {
		t.Error("cache row written for a refused key — the refusal must leave state untouched")
	}
}

// TestFetchOrgAnnouncement_AcceptsKeyMatchingRoutingPin is the
// false-positive guard: the SAME key already pinned by the routing rail
// must pass straight through to normal TOFU behaviour. (This is the
// only state a healthy org can be in, so a fix that broke it would
// break every real fleet.)
func TestFetchOrgAnnouncement_AcceptsKeyMatchingRoutingPin(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	as := newAnnouncementServer(t)
	c, s, _ := enrolledClient(t, as.srv.URL)

	pinRoutingKey(t, s, base64.StdEncoding.EncodeToString(pub))
	doc := signAnnouncementDoc(1, testAnnBody, priv, pub)
	as.doc = &doc

	changed, err := c.FetchOrgAnnouncement(ctx)
	if err != nil || !changed {
		t.Fatalf("the org's own pinned key was refused: changed=%v err=%v", changed, err)
	}
	row, ok, _ := s.GetOrgAnnouncement(ctx)
	if !ok || row.Body != testAnnBody {
		t.Errorf("cached row = %+v ok=%v", row, ok)
	}
}

// TestFetchRoutingPolicy_RefusesKeyPinnedByAnnouncementRail pins the
// symmetric direction. It is cheap (one single-row read this package
// already owns) and non-breaking (the pins can only disagree when the
// key genuinely changed), so the identity check is enforced on BOTH
// rails rather than one — a rail whose first fetch happens to come
// second must not be the weak one.
func TestFetchRoutingPolicy_RefusesKeyPinnedByAnnouncementRail(t *testing.T) {
	ctx := context.Background()
	k1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k2Pub, k2Priv, _ := ed25519.GenerateKey(rand.Reader)
	body := "[routing]\n"
	sum := sha256.Sum256([]byte(body))
	doc := orgcontract.RoutingPolicyDoc{
		Version: 1, Body: body, BodyHash: hex.EncodeToString(sum[:]),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k2Priv, []byte(body))),
		PublicKey: base64.StdEncoding.EncodeToString(k2Pub),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/routing-policy" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeTestJSON(w, http.StatusOK, doc)
	}))
	t.Cleanup(srv.Close)
	c, s, _ := enrolledClient(t, srv.URL)

	pinAnnouncementKey(t, s, base64.StdEncoding.EncodeToString(k1Pub))

	changed, _, err := c.FetchRoutingPolicy(ctx)
	if err == nil || changed {
		t.Fatalf("a key the announcement rail contradicts was accepted: changed=%v err=%v", changed, err)
	}
	if !strings.Contains(err.Error(), "key CHANGED") {
		t.Errorf("error = %v, want the loud key-change refusal class", err)
	}
	if _, ok, _ := s.GetOrgRoutingPolicy(ctx); ok {
		t.Error("cache row written for a refused key")
	}
}

// TestCheckOrgKeyIdentity_DistinguishesStoreReadFromMismatch is the R5-B6
// sentinel proof: checkOrgKeyIdentity must return DISTINGUISHABLE typed errors
// for a LOCAL pin-store read failure (non-decisive → the routing classifier
// maps it to Indeterminate) versus a GENUINE cross-rail key mismatch (decisive
// → RejectKeyPinMismatch). Collapsing them (returning one undifferentiated
// error) would make a transient SQLite failure look like a security rejection.
func TestCheckOrgKeyIdentity_DistinguishesStoreReadFromMismatch(t *testing.T) {
	ctx := context.Background()

	t.Run("genuine mismatch is errPinMismatch, not errPinStoreRead", func(t *testing.T) {
		s := newAgentStore(t)
		c := newTestClient(t, s, &memBearerStore{})
		k1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
		k2Pub, _, _ := ed25519.GenerateKey(rand.Reader)
		// Another rail pinned K1; offering K2 on the routing rail is a real
		// cross-rail key change.
		pinAnnouncementKey(t, s, base64.StdEncoding.EncodeToString(k1Pub))
		err := c.checkOrgKeyIdentity(ctx, routingPolicyRail, base64.StdEncoding.EncodeToString(k2Pub))
		if err == nil {
			t.Fatal("a conflicting key was accepted")
		}
		if !errors.Is(err, errPinMismatch) {
			t.Fatalf("err = %v, want errPinMismatch", err)
		}
		if errors.Is(err, errPinStoreRead) {
			t.Fatal("a genuine mismatch must NOT be classified as a store-read failure")
		}
	})

	t.Run("store read failure is errPinStoreRead, not errPinMismatch", func(t *testing.T) {
		database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
		if err != nil {
			t.Fatalf("db.Open: %v", err)
		}
		s := store.New(database)
		c := newTestClient(t, s, &memBearerStore{})
		// Force loadRailPins' GetOrgRoutingPolicy read to fail.
		_ = database.Close()
		kPub, _, _ := ed25519.GenerateKey(rand.Reader)
		err = c.checkOrgKeyIdentity(ctx, routingPolicyRail, base64.StdEncoding.EncodeToString(kPub))
		if err == nil {
			t.Fatal("a closed pin store did not surface an error")
		}
		if !errors.Is(err, errPinStoreRead) {
			t.Fatalf("err = %v, want errPinStoreRead", err)
		}
		if errors.Is(err, errPinMismatch) {
			t.Fatal("a store-read failure must NOT be classified as a pin mismatch")
		}
	})
}

// TestUnenrolThenReEnrolWithNewKeyIsAccepted is the other half of
// security finding 3, and the reason the cross-rail pin of finding 2
// could not ship alone: pins that outlive their enrolment poison
// re-enrolment. A node that leaves org A and joins org B must accept
// org B's key — the enrolment channel is the trust root, and unenrolment
// is exactly the operator action that withdraws the old trust.
func TestUnenrolThenReEnrolWithNewKeyIsAccepted(t *testing.T) {
	ctx := context.Background()
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	as := newAnnouncementServer(t)
	s := newAgentStore(t)
	bs := &memBearerStore{bearer: "bearer-org-a"}
	c := newTestClient(t, s, bs)
	if err := s.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: as.srv.URL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}

	// Org A: both rails pinned to the old key.
	pinRoutingKey(t, s, base64.StdEncoding.EncodeToString(oldPub))
	docA := signAnnouncementDoc(1, testAnnBody, oldPriv, oldPub)
	as.doc = &docA
	if _, err := c.FetchOrgAnnouncement(ctx); err != nil {
		t.Fatalf("org A fetch: %v", err)
	}

	if err := c.Unenroll(ctx); err != nil {
		t.Fatalf("Unenroll: %v", err)
	}

	// Org B: new enrolment (a fresh credential, as a real re-enrol
	// mints), new key, and (deliberately) a LOWER version than org A's
	// cache carried — a surviving row would refuse this on the key AND
	// swallow it on the monotonic short-circuit.
	if err := bs.SaveBearer("bearer-org-b"); err != nil {
		t.Fatalf("SaveBearer: %v", err)
	}
	if err := s.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-2", OrgName: "Globex", OrgServerURL: as.srv.URL,
		UserID: "scim-9", UserEmail: "dev@globex.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	docB := signAnnouncementDoc(1, testAnnBody, newPriv, newPub)
	as.doc = &docB

	changed, err := c.FetchOrgAnnouncement(ctx)
	if err != nil || !changed {
		t.Fatalf("re-enrolment into a new org was refused: changed=%v err=%v", changed, err)
	}
	row, ok, _ := s.GetOrgAnnouncement(ctx)
	if !ok || row.ServerPubkey != base64.StdEncoding.EncodeToString(newPub) {
		t.Errorf("pinned key = %q, want the new org's key", row.ServerPubkey)
	}
}
