package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/entitlementwork"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// tenantcreate_e2e_test.go drives the control plane's side of creating a
// team org end to end (wave 14 lane tenant-cloud; W14-D1a, W14-D2, W14-D3,
// W14-D4): the worker store on PostgreSQL as sbci_worker, the REAL document
// signer, the worker's own file loaders and composition (newHostAPIWorker
// with the production owner source, the 0093 lookups), and a fake tenant
// host built only from internal/platformcontract: it verifies every request
// envelope against the signer's host-API key, signs every answer, verifies
// every entitlements document as a host must, can put a create on its
// capacity waitlist (503 capacity_waitlist, which the tenant-host lane
// implements in the real host), and answers the usage verb (also the
// tenant-host lane's). The plan source reads an OrgPlanReader fake: the
// front-door lane builds the store function and the lead wires it at merge.

// contractTenant is one tenant on the contract host.
type contractTenant struct {
	req pc.CreateTenantRequest
	doc pc.EntitlementDocument
	// verified is the document in force, as the host verified it.
	verified entitlements.Document
	body     entitlements.Body
}

// contractHost is a tenant host built from the contract alone.
type contractHost struct {
	mu       sync.Mutex
	now      func() time.Time
	reqPub   ed25519.PublicKey
	respKey  ed25519.PrivateKey
	entKeys  pc.KeySet
	waitlist bool
	asked    int // create requests received, waitlisted ones included
	tenants  map[string]*contractTenant
	usage    []pc.TenantUsage
	bad      []string // what the host refused to accept, for the test to fail on
}

func (h *contractHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	target := pc.SigningTarget(r.URL.EscapedPath(), r.URL.RawQuery)
	env, err := pc.ParseEnvelopeHeaders(r.Header.Get)
	if err != nil || env.Verify(h.reqPub, r.Method, target, body, h.now()) != nil {
		// Unsigned, as a real host refuses before authenticating.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"bad_signature"}`))
		return
	}
	status, answer := h.route(r, body)
	out, err := json.Marshal(answer)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	renv, err := pc.NewResponseEnvelope(h.respKey, "host-r1", env.Nonce, r.Method, target, out, h.now())
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	for _, p := range renv.HeaderPairs() {
		w.Header().Set(p[0], p[1])
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func refusal(status int, code pc.ErrorCode) (int, any) {
	return status, pc.ErrorResponse{Code: code}
}

func (h *contractHost) route(r *http.Request, body []byte) (int, any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && p == pc.PathTenants:
		var req pc.CreateTenantRequest
		if json.Unmarshal(body, &req) != nil || req.Validate() != nil {
			return refusal(http.StatusBadRequest, pc.CodeInvalid)
		}
		h.asked++
		if h.waitlist {
			return refusal(http.StatusServiceUnavailable, pc.CodeCapacityWaitlist)
		}
		if _, ok := h.tenants[req.TenantID]; ok {
			return http.StatusOK, pc.CreateTenantResponse{TenantID: req.TenantID, Outcome: pc.CreateReplayed, State: pc.StateActive, LifecycleGen: 1}
		}
		v, err := entitlements.Verify(req.Entitlements, entitlements.Binding{Org: req.TenantID, Kind: entitlements.KindTeam}, h.entKeys, 0)
		if err != nil {
			h.bad = append(h.bad, "create document: "+err.Error())
			return refusal(http.StatusBadRequest, pc.CodeInvalid)
		}
		h.tenants[req.TenantID] = &contractTenant{req: req, doc: req.Entitlements, verified: v, body: v.Body}
		return http.StatusOK, pc.CreateTenantResponse{TenantID: req.TenantID, Outcome: pc.CreateReady, State: pc.StateActive, LifecycleGen: 1}
	case r.Method == http.MethodPut && strings.HasSuffix(p, "/entitlements"):
		var req pc.SetEntitlementsRequest
		if json.Unmarshal(body, &req) != nil || req.Validate() != nil || pc.PathTenantEntitlements(req.TenantID) != p {
			return refusal(http.StatusBadRequest, pc.CodeInvalid)
		}
		t, ok := h.tenants[req.TenantID]
		if !ok {
			return refusal(http.StatusNotFound, pc.CodeUnknownTenant)
		}
		if req.Document.Version <= t.doc.Version {
			return http.StatusOK, pc.SetEntitlementsResponse{Version: t.doc.Version, Applied: false}
		}
		v, err := entitlements.Verify(req.Document, entitlements.Binding{Org: req.TenantID, Kind: entitlements.KindTeam}, h.entKeys, t.doc.Version)
		if err != nil {
			h.bad = append(h.bad, "push document: "+err.Error())
			return refusal(http.StatusBadRequest, pc.CodeInvalid)
		}
		t.doc, t.verified, t.body = req.Document, v, v.Body
		return http.StatusOK, pc.SetEntitlementsResponse{Version: req.Document.Version, Applied: true}
	case r.Method == http.MethodPost && p == pc.PathRouteCheck:
		var req pc.RouteCheckRequest
		_ = json.Unmarshal(body, &req)
		if _, ok := h.tenants[req.TenantID]; !ok {
			return http.StatusOK, pc.RouteCheckResponse{}
		}
		return http.StatusOK, pc.RouteCheckResponse{Served: true, State: pc.StateActive, LifecycleGen: 1}
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/health"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, pc.PathTenants+"/"), "/health")
		return http.StatusOK, pc.HealthResponse{
			TenantID: id, Status: pc.HealthHealthy, LastPush: pc.PushRecent,
			Backlog: pc.BacklogClear, Quota: pc.QuotaOK, Error: pc.ErrNone,
		}
	case r.Method == http.MethodGet && p == pc.PathUsage:
		day := r.URL.Query().Get("day")
		if !pc.ValidDay(day) {
			return refusal(http.StatusBadRequest, pc.CodeInvalid)
		}
		return http.StatusOK, pc.UsageResponse{Day: day, Tenants: append([]pc.TenantUsage(nil), h.usage...)}
	}
	return refusal(http.StatusNotFound, pc.CodeUnknownRoute)
}

func (h *contractHost) tenant(id string) (contractTenant, int, []string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.tenants[id]
	if !ok {
		return contractTenant{}, h.asked, append([]string(nil), h.bad...), false
	}
	return *t, h.asked, append([]string(nil), h.bad...), true
}

// orgSubs is the OrgPlanReader fake (store.OrgSubscription at merge).
type orgSubs struct {
	mu   sync.Mutex
	subs map[string]store.PaddleSubscription
}

func (o *orgSubs) OrgSubscription(_ context.Context, org string) (store.PaddleSubscription, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, ok := o.subs[org]
	if !ok {
		return store.PaddleSubscription{}, store.ErrNotFound
	}
	return s, nil
}

// drainOutbox dispatches until a pass claims nothing (each pass sends at
// most one row per org, in order).
func drainOutbox(t *testing.T, w *hostAPIWorker) {
	t.Helper()
	for range 10 {
		st, err := w.dispatcher.DispatchOnce(context.Background())
		if err != nil {
			t.Fatalf("DispatchOnce: %v", err)
		}
		if st.Claimed == 0 {
			return
		}
	}
	t.Fatal("the outbox did not drain in 10 passes")
}

// TestTenantCreateEndToEnd: a team org is provisioned; the create waits on
// the host's capacity waitlist (the outbox row stays open with the
// capacity_waitlist class, the org stays provisioning, no launch document);
// once admitted, the create carries the owner bound by WorkOS subject (the
// 0093 lookup, the issuer's rule) with the address as an unverified hint,
// and the org's slug and kind; the create's ack issues the launch document,
// which the host verifies and applies, so the org runs on the Team plan for
// the launch window, not on its lapsed floor; a subscription then moves it
// to its paid plan; the reconciler pulls the host's signed usage report.
func TestTenantCreateEndToEnd(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	// Two links: the older dev link and the WorkOS one; the subject the host
	// binds is the WorkOS one, as the issuer's sub claim is.
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_links (account_id, provider, subject, created_at) VALUES
		    ($1::uuid, 'dev', 'dev-owner', now() - interval '1 day'),
		    ($1::uuid, 'workos', 'user_01TEAMOWNER', now())`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO account_verified_emails (account_id, email, email_verified) VALUES ($1::uuid, 'owner@acme.test', true)`, owner); err != nil {
		t.Fatal(err)
	}
	org, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: "acme-w14", DisplayName: "Acme", Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}

	dir := t.TempDir()
	clock := &testClock{t: time.Now().UTC().Add(time.Minute).Truncate(time.Second)} // after every row's default next_attempt_at
	entKey, availKey, hostAPIKey := seededKey("w14-ent"), seededKey("w14-avail"), seededKey("w14-host-api")
	responseKey := seededKey("w14-host-response")
	signer := startDocSigner(t, dir, clock, entKey, availKey, hostAPIKey)
	host := &contractHost{
		now: clock.Now, reqPub: hostAPIKey.Public().(ed25519.PublicKey), respKey: responseKey,
		entKeys: pc.KeySet{pc.NewDocumentKey(entKey.Public().(ed25519.PublicKey))},
		tenants: map[string]*contractTenant{}, waitlist: true,
	}
	caFile, certFile, keyFile, serverTLS := testPKI(t, dir)
	srv := httptest.NewUnstartedServer(host)
	srv.TLS = serverTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)
	hostsJSON, err := json.Marshal(map[string]any{
		"place_on": "host-1",
		"hosts": []map[string]any{{
			"id": "host-1", "base_url": srv.URL,
			"response_keys": map[string]string{"host-r1": base64.StdEncoding.EncodeToString(responseKey.Public().(ed25519.PublicKey))},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hostsFile := filepath.Join(dir, "hosts.json")
	if err := os.WriteFile(hostsFile, hostsJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, enabled, err := resolveHostAPIWorkerConfig(envMap(map[string]string{
		envHostAPIHostsFile: hostsFile, envHostAPICAFile: caFile, envHostAPICertFile: certFile, envHostAPIKeyFile: keyFile,
	}))
	if err != nil || !enabled {
		t.Fatalf("config: %v (enabled %v)", err, enabled)
	}
	tlsc, hosts, err := loadHostAPIFiles(cfg, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	subs := &orgSubs{subs: map[string]store.PaddleSubscription{}}
	w, err := newHostAPIWorker(ctx, hostAPIWorkerDeps{
		store: worker, signer: signer, tls: tlsc, hosts: hosts, now: clock.Now,
		// The production owner source (owners nil: StoreOwners over the
		// 0093 lookups); the production plan source over the subscription
		// fake (the merge wires store.OrgSubscription the same way).
		plans:        entitlementwork.SubscriptionPlans{Subs: subs, Now: clock.Now},
		allowAddress: func(a netip.Addr) bool { return a.IsLoopback() },
	})
	if err != nil {
		t.Fatalf("newHostAPIWorker: %v", err)
	}

	// 1. The first document the create carries: the floor (the create is
	// not acked, so no launch yet).
	if st, err := w.issuer.IssueOnce(ctx); err != nil || st.Issued != 1 {
		t.Fatalf("first issuer pass = %+v, %v", st, err)
	}

	// 2. Waitlisted: the host refuses with a signed capacity_waitlist. The
	// create stays open with that class; nothing exists on the host.
	drainOutbox(t, w)
	if r := readOutbox(t, pool, org.OrgID); r.state != "pending" || r.errClass != "refused:"+string(pc.CodeCapacityWaitlist) {
		t.Fatalf("waitlisted create row = %+v", r)
	}
	if _, asked, _, ok := host.tenant(org.OrgID); ok || asked != 1 {
		t.Fatalf("host after the waitlist: tenant %v, asked %d", ok, asked)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM orgs WHERE org_id = $1::uuid`, org.OrgID).Scan(&status); err != nil || status != "provisioning" {
		t.Fatalf("org status while waitlisted = %q, %v", status, err)
	}
	var docs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_entitlement_docs WHERE org_id = $1::uuid`, org.OrgID).Scan(&docs); err != nil || docs != 1 {
		t.Fatalf("documents while waitlisted = %d, %v; want the floor only", docs, err)
	}
	// Not due again before WaitlistMinDelay.
	clock.Advance(hostapi.WaitlistMinDelay / 2)
	drainOutbox(t, w)
	if _, asked, _, _ := host.tenant(org.OrgID); asked != 1 {
		t.Fatalf("a waitlisted create was resent after %s (asked %d)", hostapi.WaitlistMinDelay/2, asked)
	}

	// 3. Admitted: the create carries the owner by subject, the hint
	// unverified, the slug and kind; its ack issues the launch document.
	host.mu.Lock()
	host.waitlist = false
	host.mu.Unlock()
	clock.Advance(2 * time.Hour)
	ackAt := clock.Now()
	drainOutbox(t, w)
	tenant, _, bad, ok := host.tenant(org.OrgID)
	if !ok || len(bad) != 0 {
		t.Fatalf("host after the admit: tenant %v, refused %v", ok, bad)
	}
	req := tenant.req
	// The owner's address was verified by WorkOS (the seeded
	// account_verified_emails row), so it is sent as verified
	// (C2.tenant-cloud-2, cloud 0096); the host still binds by subject.
	if req.OwnerSub != "user_01TEAMOWNER" || req.OwnerEmail != "owner@acme.test" || !req.OwnerEmailVerified ||
		req.Slug != "acme-w14" || req.Kind != pc.OrgKindTeam || req.Name != "Acme" {
		t.Fatalf("create request = sub %q email %q verified %v slug %q kind %q name %q",
			req.OwnerSub, req.OwnerEmail, req.OwnerEmailVerified, req.Slug, req.Kind, req.Name)
	}
	if r := readOutbox(t, pool, org.OrgID); r.state != "acked" {
		t.Fatalf("create row = %+v", r)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM orgs WHERE org_id = $1::uuid`, org.OrgID).Scan(&status); err != nil || status != "active" {
		t.Fatalf("org status after the create = %q, %v", status, err)
	}
	wantEnd := ackAt.Add(entitlementwork.DefaultLaunchWindow).Unix()
	if tenant.body.Plan.Name != "team" || tenant.body.NotAfter != wantEnd {
		t.Fatalf("the host's plan after the create = %+v not_after %d; want the launch plan team until %d", tenant.body.Plan, tenant.body.NotAfter, wantEnd)
	}
	// The launch document is in force on the host: Team caps, not the
	// lapsed floor's zeros.
	eff := entitlements.Evaluate(entitlements.KindTeam, &tenant.verified, clock.Now())
	if eff.Source() != entitlements.SourceDocument || eff.Plan().Name != "team" || !eff.Cap(entitlements.CapPushMBPerDay).Allows(1) {
		t.Fatalf("in force: source %v plan %+v push cap %+v; the org sits on its lapsed floor", eff.Source(), eff.Plan(), eff.Cap(entitlements.CapPushMBPerDay))
	}
	floor := entitlements.Evaluate(entitlements.KindTeam, nil, clock.Now())
	if floor.Cap(entitlements.CapPushMBPerDay).Allows(1) {
		t.Fatal("the lapsed floor allows pushes; this test no longer proves the launch document matters")
	}
	// The issuer's next pass finds it current.
	if st, err := w.issuer.IssueOnce(ctx); err != nil || st.Issued != 0 || st.Current != 1 {
		t.Fatalf("issuer pass after the launch = %+v, %v", st, err)
	}

	// 4. A subscription: the paid plan replaces the launch document.
	subs.mu.Lock()
	subs.subs[org.OrgID] = store.PaddleSubscription{SubscriptionID: "sub_1", PlanName: "business", PlanVersion: 1, Status: "active"}
	subs.mu.Unlock()
	if st, err := w.issuer.IssueOnce(ctx); err != nil || st.Issued != 1 {
		t.Fatalf("subscribed pass = %+v, %v", st, err)
	}
	drainOutbox(t, w)
	if tenant, _, bad, _ := host.tenant(org.OrgID); tenant.body.Plan.Name != "business" || tenant.body.NotAfter != 0 || len(bad) != 0 {
		t.Fatalf("host after the subscription = %+v not_after %d, refused %v", tenant.body.Plan, tenant.body.NotAfter, bad)
	}

	// 5. The reconciler finds the host in step and pulls its signed usage;
	// an entry for an org the control plane did not place there is dropped.
	host.mu.Lock()
	host.usage = []pc.TenantUsage{
		{TenantID: org.OrgID, ActiveSeatMemberIDs: []string{"member-1", "member-2"}, Sessions: 5, Members: 2},
		{TenantID: "99999999-0000-4000-8000-000000000009", ActiveSeatMemberIDs: []string{"x"}, Sessions: 1},
	}
	host.mu.Unlock()
	rs, err := w.reconciler.ReconcileOnce(ctx)
	if err != nil || rs.Corrections != 0 || rs.Usage.Recorded != hostapi.DefaultUsageDays || rs.Usage.Dropped[hostapi.UsageDropNotPlaced] != hostapi.DefaultUsageDays {
		t.Fatalf("reconcile = %+v, %v", rs, err)
	}
	days, err := worker.OrgUsageDays(ctx, org.OrgID, "2000-01-01", "2100-01-01")
	if err != nil || len(days) != hostapi.DefaultUsageDays {
		t.Fatalf("stored usage days = %d, %v", len(days), err)
	}
	for _, d := range days {
		if d.Usage.Sessions != 5 || len(d.Usage.ActiveSeatMemberIDs) != 2 || len(d.ReportDigest) != 64 {
			t.Fatalf("stored usage = %+v", d)
		}
	}
	var stray int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM org_usage_days WHERE org_id <> $1::uuid`, org.OrgID).Scan(&stray); err != nil || stray != 0 {
		t.Fatalf("usage stored for an org not placed on the host: %d, %v", stray, err)
	}
}

// TestCreateWaitsForAnOwnerSubject: with the production owner source, an
// owner with no identity link keeps the create in the outbox with the typed
// reason and the host sees nothing; an owner with a link but no recorded
// address waits with the hint reason.
func TestCreateWaitsForAnOwnerSubject(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	org, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: "acme-wait", DisplayName: "Acme", Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := entitlementwork.StoreOwners{Store: worker}
	_, err = r.Owner(ctx, org.OrgID)
	if reason := resolveReasonOf(err); reason != entitlementwork.ReasonOwnerIdentityUnavailable {
		t.Fatalf("no link: %v (reason %q)", err, reason)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO identity_links (account_id, provider, subject) VALUES ($1::uuid, 'workos', 'user_01WAIT')`, owner); err != nil {
		t.Fatal(err)
	}
	_, err = r.Owner(ctx, org.OrgID)
	if reason := resolveReasonOf(err); reason != entitlementwork.ReasonOwnerEmailHintUnavailable {
		t.Fatalf("no address: %v (reason %q)", err, reason)
	}
}

func resolveReasonOf(err error) string {
	var re *hostclient.ResolveError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

// TestOrgPlanReaderWiring reports whether the store already implements the
// org-scoped subscription reader (the front-door lane's store.OrgSubscription,
// W14-D3): when it does, orgPlanReaderFor wires it with no edit; until then
// every team org runs on its launch plan and then its floor. A nil store is
// never wired.
func TestOrgPlanReaderWiring(t *testing.T) {
	t.Parallel()
	if orgPlanReaderFor(nil) != nil {
		t.Fatal("a nil store was wired as the subscription reader")
	}
	_, wired := any((*store.Store)(nil)).(entitlementwork.OrgPlanReader)
	t.Logf("store.Store implements entitlementwork.OrgPlanReader: %v", wired)
}
