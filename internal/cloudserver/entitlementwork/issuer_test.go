package entitlementwork_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

const (
	orgA = "aaaaaaaa-0000-4000-8000-000000000001"
	orgB = "bbbbbbbb-0000-4000-8000-000000000002"
)

var testNow = time.Unix(1_800_000_000, 0).UTC()

func edKey(seed string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte(seed))
	return ed25519.NewKeyFromSeed(s[:])
}

var entKey = edKey("entitlements")

func keySet(keys ...ed25519.PrivateKey) pc.KeySet {
	var ks pc.KeySet
	for _, k := range keys {
		ks = append(ks, pc.NewDocumentKey(k.Public().(ed25519.PublicKey)))
	}
	return ks
}

// memSigner is the document signer's entitlements half: a per-org last
// version, refused when not newer, signing with key.
type memSigner struct {
	mu    sync.Mutex
	key   ed25519.PrivateKey
	last  map[string]int64
	calls int
	err   error
}

func newMemSigner(k ed25519.PrivateKey) *memSigner {
	return &memSigner{key: k, last: map[string]int64{}}
}

func (s *memSigner) SignEntitlements(_ context.Context, org string, v int64, body []byte) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, "", s.err
	}
	if err := pc.CheckDocumentVersion(s.last[org], v); err != nil {
		return nil, "", err
	}
	sig, kid, err := pc.SignDocument(s.key, pc.KindEntitlements, org, v, body)
	if err != nil {
		return nil, "", err
	}
	s.last[org] = v
	return sig, kid, nil
}

// memStore is the issuer's store seam in memory.
type memStore struct {
	mu       sync.Mutex
	orgs     []store.OrgEntitlementView
	docs     map[string][]pc.EntitlementDocument
	intents  []store.OrgIntent
	issueErr error
	// floors is each org's version floor (cloud 0097, W16-D6).
	floors   map[string]int64
	floorErr error
}

func newStore(orgs ...store.OrgEntitlementView) *memStore {
	return &memStore{orgs: orgs, docs: map[string][]pc.EntitlementDocument{}, floors: map[string]int64{}}
}

func (m *memStore) ListOrgsForEntitlements(_ context.Context, after string, limit int) ([]store.OrgEntitlementView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OrgEntitlementView
	for _, o := range m.orgs {
		if o.OrgID > after && len(out) < limit {
			out = append(out, o)
		}
	}
	return out, nil
}

func (m *memStore) LatestEntitlementDocument(_ context.Context, org string) (pc.EntitlementDocument, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.docs[org]
	if len(d) == 0 {
		return pc.EntitlementDocument{}, store.ErrNotFound
	}
	return d[len(d)-1], nil
}

func (m *memStore) IssueEntitlementDocument(_ context.Context, org string, doc pc.EntitlementDocument, by string, _ time.Time, in store.OrgIntent) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.issueErr != nil {
		return false, m.issueErr
	}
	last := m.floors[org]
	if d := m.docs[org]; len(d) > 0 {
		last = max(last, d[len(d)-1].Version)
	}
	if err := pc.CheckDocumentVersion(last, doc.Version); err != nil {
		return false, err
	}
	if by != store.IssuedBySystem || in.OrgID != org || in.Verb != store.OutboxSetEntitlements {
		return false, errors.New("memStore: bad issue")
	}
	m.docs[org] = append(m.docs[org], doc)
	m.intents = append(m.intents, in)
	return true, nil
}

func (m *memStore) OrgForEntitlements(_ context.Context, org string) (store.OrgEntitlementView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.orgs {
		if o.OrgID == org {
			return o, nil
		}
	}
	return store.OrgEntitlementView{}, store.ErrNotFound
}

func (m *memStore) DocumentVersionFloor(_ context.Context, kind pc.DocumentKind, scope string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if kind != pc.KindEntitlements {
		return 0, fmt.Errorf("memStore: floor of kind %s", kind)
	}
	if m.floorErr != nil {
		return 0, m.floorErr
	}
	return m.floors[scope], nil
}

func team(org, status string) store.OrgEntitlementView {
	return store.OrgEntitlementView{OrgID: org, Kind: store.OrgTeam, Status: status}
}

func newIssuer(t *testing.T, st entitlementwork.Store, sg entitlementwork.Signer, keys pc.KeySet, plans entitlementwork.PlanSource, now *time.Time) *entitlementwork.Issuer {
	t.Helper()
	iss, err := entitlementwork.New(entitlementwork.Config{
		Store: st, Signer: sg, Keys: keys, Plans: plans, Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

// planBox is a PlanSource whose answer a test changes.
type planBox struct {
	mu   sync.Mutex
	plan entitlementwork.Plan
}

func (p *planBox) set(name string, v int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.plan = entitlementwork.Plan{Name: name, Version: v}
}

func (p *planBox) PlanFor(context.Context, store.OrgEntitlementView, entitlements.Kind) (entitlementwork.Plan, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.plan, nil
}

// TestIssuerLifecycle walks one org through the issuer: the floor document
// is issued once, a second pass changes nothing, a plan change issues the
// next version, and every stored document verifies and carries its intent.
func TestIssuerLifecycle(t *testing.T) {
	t.Parallel()
	now := testNow
	st := newStore(team(orgA, "provisioning"), store.OrgEntitlementView{OrgID: orgB, Kind: store.OrgPersonal, Status: "active"})
	sg := newMemSigner(entKey)
	iss := newIssuer(t, st, sg, keySet(entKey), nil, &now)

	stats, err := iss.IssueOnce(context.Background())
	if err != nil || stats.Issued != 2 || stats.Orgs != 2 {
		t.Fatalf("first pass = %+v, %v", stats, err)
	}
	for org, wantKind := range map[string]entitlements.Kind{orgA: entitlements.KindTeam, orgB: entitlements.KindPersonal} {
		doc, _ := st.LatestEntitlementDocument(context.Background(), org)
		got, err := entitlements.Verify(doc, entitlements.Binding{Org: org, Kind: wantKind}, keySet(entKey), 0)
		if err != nil {
			t.Fatalf("%s: stored document does not verify: %v", org, err)
		}
		floor, _ := entitlements.Floor(wantKind)
		if got.Body.Plan != floor.Plan || doc.Version != now.Unix() {
			t.Fatalf("%s: plan %+v v%d, want the floor %+v at v%d", org, got.Body.Plan, doc.Version, floor.Plan, now.Unix())
		}
	}
	if len(st.intents) != 2 {
		t.Fatalf("intents = %d", len(st.intents))
	}
	var p hostapi.EntitlementsPayload
	if err := json.Unmarshal(st.intents[0].Payload, &p); err != nil || p.TenantID != st.intents[0].OrgID || p.Document.Version != now.Unix() {
		t.Fatalf("intent payload = %+v, %v", p, err)
	}
	if want := fmt.Sprintf("entitlements:%s:%d", st.intents[0].OrgID, now.Unix()); st.intents[0].IdempotencyKey != want {
		t.Fatalf("intent key = %q, want %q", st.intents[0].IdempotencyKey, want)
	}

	// Nothing changed: nothing is signed or stored.
	calls := sg.calls
	if stats, err := iss.IssueOnce(context.Background()); err != nil || stats.Current != 2 || stats.Issued != 0 || sg.calls != calls {
		t.Fatalf("second pass = %+v, %v (signer calls %d -> %d)", stats, err, calls, sg.calls)
	}

	// The plan changes within the same second: the next version is last+1.
	plans := &planBox{}
	plans.set("team", 1)
	iss = newIssuer(t, st, sg, keySet(entKey), plans, &now)
	if o, err := iss.Ensure(context.Background(), team(orgA, "active")); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("plan change = %v, %v", o, err)
	}
	doc, _ := st.LatestEntitlementDocument(context.Background(), orgA)
	if doc.Version != now.Unix()+1 {
		t.Fatalf("version = %d, want %d", doc.Version, now.Unix()+1)
	}
	if b, _ := entitlements.Decode(doc.Body); b.Plan.Name != "team" {
		t.Fatalf("plan = %+v", b.Plan)
	}
}

// TestIssuerOutcomes is one row per decision the issuer makes for an org.
func TestIssuerOutcomes(t *testing.T) {
	t.Parallel()
	other := edKey("not the published key")
	cases := []struct {
		name    string
		org     store.OrgEntitlementView
		prepare func(st *memStore, sg *memSigner)
		keys    pc.KeySet
		signer  func() *memSigner
		want    entitlementwork.Outcome
		wantErr bool
		stored  int
	}{
		{name: "provisioning org is issued", org: team(orgA, "provisioning"), want: entitlementwork.OutcomeIssued, stored: 1},
		{name: "suspended org is issued", org: team(orgA, "suspended"), want: entitlementwork.OutcomeIssued, stored: 1},
		{name: "pending deletion is skipped", org: team(orgA, "pending_deletion"), want: entitlementwork.OutcomeSkipped},
		{name: "purging is skipped", org: team(orgA, "purging"), want: entitlementwork.OutcomeSkipped},
		{name: "unknown kind is skipped", org: store.OrgEntitlementView{OrgID: orgA, Kind: "dedicated", Status: "active"}, want: entitlementwork.OutcomeSkipped},
		{
			name: "signer ahead of the store is asked again", org: team(orgA, "active"),
			prepare: func(_ *memStore, sg *memSigner) { sg.last[orgA] = testNow.Unix() + 1 },
			want:    entitlementwork.OutcomeIssued, stored: 1,
		},
		{
			name: "signer far ahead fails after the bound", org: team(orgA, "active"),
			prepare: func(_ *memStore, sg *memSigner) { sg.last[orgA] = testNow.Unix() + 100 },
			wantErr: true,
		},
		{
			name: "signature under an unpublished key is not stored", org: team(orgA, "active"),
			signer: func() *memSigner { return newMemSigner(other) }, wantErr: true,
		},
		{
			name: "store raced by another issuer", org: team(orgA, "active"),
			prepare: func(st *memStore, _ *memSigner) {
				st.issueErr = fmt.Errorf("wrapped: %w", pc.ErrVersionNotNewer)
			},
			want: entitlementwork.OutcomeRaced,
		},
		{
			name: "signer down", org: team(orgA, "active"),
			prepare: func(_ *memStore, sg *memSigner) { sg.err = errors.New("dial: no such socket") },
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := testNow
			st := newStore(tc.org)
			sg := newMemSigner(entKey)
			if tc.signer != nil {
				sg = tc.signer()
			}
			if tc.prepare != nil {
				tc.prepare(st, sg)
			}
			iss := newIssuer(t, st, sg, keySet(entKey), nil, &now)
			got, err := iss.Ensure(context.Background(), tc.org)
			if tc.wantErr != (err != nil) || (!tc.wantErr && got != tc.want) {
				t.Fatalf("Ensure = %q, %v; want %q (err %v)", got, err, tc.want, tc.wantErr)
			}
			if n := len(st.docs[tc.org.OrgID]); n != tc.stored {
				t.Fatalf("stored %d documents, want %d", n, tc.stored)
			}
			if len(st.intents) != tc.stored {
				t.Fatalf("enqueued %d intents, want %d", len(st.intents), tc.stored)
			}
		})
	}
}

func TestIssueOnceJoinsPerOrgErrorsAndContinues(t *testing.T) {
	t.Parallel()
	now := testNow
	st := newStore(team(orgA, "active"), team(orgB, "active"))
	sg := newMemSigner(entKey)
	sg.last[orgA] = testNow.Unix() + 1000 // orgA cannot be signed
	iss := newIssuer(t, st, sg, keySet(entKey), nil, &now)
	stats, err := iss.IssueOnce(context.Background())
	if err == nil || stats.Failed != 1 || stats.Issued != 1 || len(st.docs[orgB]) != 1 {
		t.Fatalf("pass = %+v, %v", stats, err)
	}
}

func TestIssueOncePages(t *testing.T) {
	t.Parallel()
	now := testNow
	var orgs []store.OrgEntitlementView
	for i := range 5 {
		orgs = append(orgs, team(fmt.Sprintf("cccccccc-0000-4000-8000-00000000000%d", i), "active"))
	}
	st := newStore(orgs...)
	iss, err := entitlementwork.New(entitlementwork.Config{
		Store: st, Signer: newMemSigner(entKey), Keys: keySet(entKey), Now: func() time.Time { return now }, PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats, err := iss.IssueOnce(context.Background()); err != nil || stats.Orgs != 5 || stats.Issued != 5 {
		t.Fatalf("paged pass = %+v, %v", stats, err)
	}
}

func TestNewRequiresItsSeams(t *testing.T) {
	t.Parallel()
	for name, cfg := range map[string]entitlementwork.Config{
		"no store":  {Signer: newMemSigner(entKey), Keys: keySet(entKey)},
		"no signer": {Store: newStore(), Keys: keySet(entKey)},
		"no keys":   {Store: newStore(), Signer: newMemSigner(entKey)},
	} {
		if _, err := entitlementwork.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKindFor(t *testing.T) {
	t.Parallel()
	for org, want := range map[store.OrgKind]entitlements.Kind{store.OrgPersonal: entitlements.KindPersonal, store.OrgTeam: entitlements.KindTeam} {
		if got, ok := entitlementwork.KindFor(org); !ok || got != want {
			t.Errorf("KindFor(%s) = %s, %v", org, got, ok)
		}
		if _, ok := entitlements.Floor(want); !ok {
			t.Errorf("kind %s has no floor", want)
		}
	}
	if _, ok := entitlementwork.KindFor("dedicated"); ok {
		t.Error("an org kind outside the registry vocabulary resolved")
	}
}

// TestCreateResolver: the create extras come from the stored document and
// the owner source; each gap is a typed refusal the dispatcher records.
func TestCreateResolver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st := newStore()
	r := entitlementwork.CreateResolver{Docs: st, Owners: entitlementwork.NoOwnerSource{}}
	wantReason := func(err error, reason string) {
		t.Helper()
		var re *hostclient.ResolveError
		if !errors.As(err, &re) || re.Reason != reason {
			t.Fatalf("err = %v, want reason %s", err, reason)
		}
	}
	_, err := r.ResolveCreate(ctx, orgA)
	wantReason(err, entitlementwork.ReasonEntitlementsNotIssued)

	now := testNow
	if _, err := newIssuer(t, newStoreWith(st, team(orgA, "provisioning")), newMemSigner(entKey), keySet(entKey), nil, &now).IssueOnce(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = r.ResolveCreate(ctx, orgA)
	wantReason(err, entitlementwork.ReasonOwnerIdentityUnavailable)

	r.Owners = fixedOwner{entitlementwork.Owner{Sub: "user_1", Email: "o@example.test"}}
	x, err := r.ResolveCreate(ctx, orgA)
	if err != nil || x.OwnerSub != "user_1" || x.OwnerEmail != "o@example.test" || x.Entitlements.Version != now.Unix() {
		t.Fatalf("extras = %+v, %v", x, err)
	}
	if _, err := (entitlementwork.CreateResolver{}).ResolveCreate(ctx, orgA); err == nil {
		t.Fatal("a resolver with no seams resolved")
	}
}

// newStoreWith adds orgs to st and returns it.
func newStoreWith(st *memStore, orgs ...store.OrgEntitlementView) *memStore {
	st.orgs = append(st.orgs, orgs...)
	return st
}

type fixedOwner struct{ o entitlementwork.Owner }

func (f fixedOwner) Owner(context.Context, string) (entitlementwork.Owner, error) { return f.o, nil }

// TestIssuerAsksForFloorPlusOne is W16-D6's worker half: after a database
// restore behind the document signer's record (the signer already signed
// up to the floor, the database holds less), the issuer asks the signer for
// max(latest stored version, floor) + 1 and the document is stored; without
// the floor it would stall on version_not_newer answers. One case per
// (stored, floor) shape; a floor read failure keeps the org's document.
func TestIssuerAsksForFloorPlusOne(t *testing.T) {
	t.Parallel()
	ahead := testNow.Unix() + 10_000 // the signer's record, past the clock
	cases := []struct {
		name        string
		stored      int64 // the org's latest stored version (0: none)
		floor       int64
		floorErr    error
		wantVersion int64
		wantErr     bool
	}{
		{name: "floor ahead of an empty database", floor: ahead, wantVersion: ahead + 1},
		{name: "floor ahead of a stored document", stored: testNow.Unix() - 50, floor: ahead, wantVersion: ahead + 1},
		{name: "stored ahead of the floor", stored: ahead + 5, floor: ahead, wantVersion: ahead + 6},
		{name: "no floor: the clock rule", wantVersion: testNow.Unix()},
		{name: "floor read fails: nothing issued", floor: ahead, floorErr: errors.New("db down"), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			now := testNow
			st := newStore(team(orgA, "active"))
			sg := newMemSigner(entKey)
			// The signer's own record: it already signed up to the floor.
			sg.last[orgA] = max(c.floor, c.stored)
			if c.stored > 0 {
				body, err := entitlements.Compose("team", 1, orgA, now.Unix(), 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := body.Encode()
				sig, kid, err := pc.SignDocument(entKey, pc.KindEntitlements, orgA, c.stored, raw)
				if err != nil {
					t.Fatal(err)
				}
				st.docs[orgA] = []pc.EntitlementDocument{{Version: c.stored, Body: raw, Signature: sig, KeyID: kid}}
			}
			st.floors[orgA] = c.floor
			st.floorErr = c.floorErr
			iss := newIssuer(t, st, sg, keySet(entKey), nil, &now)
			out, err := iss.Ensure(context.Background(), team(orgA, "active"))
			if c.wantErr {
				if err == nil {
					t.Fatalf("Ensure = %s, want an error", out)
				}
				if len(st.intents) != 0 || sg.calls != 0 {
					t.Fatalf("a failed floor read reached the signer (%d calls) or stored an intent", sg.calls)
				}
				return
			}
			if err != nil || out != entitlementwork.OutcomeIssued {
				t.Fatalf("Ensure = %s, %v; want issued", out, err)
			}
			if sg.calls != 1 {
				t.Fatalf("signer called %d times, want 1 (the first ask is above the record)", sg.calls)
			}
			doc, _ := st.LatestEntitlementDocument(context.Background(), orgA)
			if doc.Version != c.wantVersion {
				t.Fatalf("stored version %d, want %d", doc.Version, c.wantVersion)
			}
		})
	}
}

// TestIssuerMovesPersonalOrgsToV2 is the L-166 move (2026-11-24): a personal
// org that holds a document issued before the v2 personal plans is issued
// v2 at the worker's next pass. The free org is on the floor (whose plan is
// now personal_free v2); the Pro org's subscription row still names
// personal_pro v1 (migrate-personal's re-key), which the catalog carries
// forward. A second pass issues nothing.
func TestIssuerMovesPersonalOrgsToV2(t *testing.T) {
	t.Parallel()
	const orgC = "cccccccc-0000-4000-8000-000000000003"
	now := testNow
	freeOrg := store.OrgEntitlementView{OrgID: orgB, Kind: store.OrgPersonal, Status: "active"}
	proOrg := store.OrgEntitlementView{OrgID: orgC, Kind: store.OrgPersonal, Status: "active"}
	st := newStore(freeOrg, proOrg)
	sg := newMemSigner(entKey)

	// Before L-166: each org holds its v1 document.
	old := &planBox{}
	old.set("personal_free", 1)
	if o, err := newIssuer(t, st, sg, keySet(entKey), old, &now).Ensure(context.Background(), freeOrg); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("seed free v1 = %v, %v", o, err)
	}
	old.set("personal_pro", 1)
	if o, err := newIssuer(t, st, sg, keySet(entKey), old, &now).Ensure(context.Background(), proOrg); err != nil || o != entitlementwork.OutcomeIssued {
		t.Fatalf("seed pro v1 = %v, %v", o, err)
	}

	// After: the production plan source over the unchanged rows.
	now = now.Add(time.Hour)
	subs := &fakeSubs{subs: map[string]store.PaddleSubscription{}}
	subs.set(orgC, sub("personal_pro", 1, "active"))
	iss := newIssuer(t, st, sg, keySet(entKey), entitlementwork.SubscriptionPlans{Subs: subs, Now: func() time.Time { return now }}, &now)
	stats, err := iss.IssueOnce(context.Background())
	if err != nil || stats.Issued != 2 {
		t.Fatalf("move pass = %+v, %v", stats, err)
	}
	for _, c := range []struct {
		org         string
		plan        string
		events, gbs int64
	}{
		{orgB, "personal_free", entitlements.PersonalFreePlaneAEvents, entitlements.PersonalFreePlaneAGB},
		{orgC, "personal_pro", entitlements.PersonalProPlaneAEvents, entitlements.PersonalProPlaneAGB},
	} {
		doc, _ := st.LatestEntitlementDocument(context.Background(), c.org)
		got, err := entitlements.Verify(doc, entitlements.Binding{Org: c.org, Kind: entitlements.KindPersonal}, keySet(entKey), 0)
		if err != nil {
			t.Fatalf("%s: %v", c.org, err)
		}
		// The catalog carries v1 holders to the newest carried version (v2
		// at L-166, v3 since the hosted AI gateway's v3 rows).
		want, _ := entitlements.Current(c.plan, 1)
		if got.Body.Plan.Name != c.plan || got.Body.Plan.Version != want.Plan.Version || want.Plan.Version < 2 {
			t.Fatalf("%s: plan %+v, want %s v%d", c.org, got.Body.Plan, c.plan, want.Plan.Version)
		}
		e := entitlements.Evaluate(entitlements.KindPersonal, &got, now)
		if !e.Has(entitlements.CapabilityPlaneAGateway) || e.Cap(entitlements.CapPlaneAEventsMonthly).N != c.events || e.Cap(entitlements.CapPlaneAGBMonthly).N != c.gbs {
			t.Fatalf("%s: gateway %v caps %+v / %+v", c.org, e.Has(entitlements.CapabilityPlaneAGateway), e.Cap(entitlements.CapPlaneAEventsMonthly), e.Cap(entitlements.CapPlaneAGBMonthly))
		}
	}
	if stats, err := iss.IssueOnce(context.Background()); err != nil || stats.Issued != 0 || stats.Current != 2 {
		t.Fatalf("second pass = %+v, %v", stats, err)
	}
}
