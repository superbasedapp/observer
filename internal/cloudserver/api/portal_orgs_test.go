package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// portal_orgs_test.go covers the console's org BFF (portal_orgs*.go; plan 07
// M6.5; docs/security.md PORTALORG-1..8) over a real PostgreSQL with the
// server bound to the least-privilege sbci_api role: auth, CSRF and Origin on
// every mutation, the slug rules and the availability read, the create's
// outbox enqueue (and its replay), the provisioning and waitlist stages, the
// rename block while provisioning, billing per org, and the org checkout to
// webhook round trip.

const (
	orgsTenantDomain = "example.test"
	orgsPriceTeam    = "pri_test_team"
	orgsPricePlus    = "pri_test_plus"
)

type orgsHarness struct {
	*harness
	pool *pgxpool.Pool
}

func newOrgsHarness(t *testing.T) orgsHarness {
	t.Helper()
	return newOrgsHarnessWith(t, nil)
}

// newOrgsHarnessWith is newOrgsHarness with edit applied to the server's
// options before it is built (nil: none).
func newOrgsHarnessWith(t *testing.T, edit func(*api.Options)) orgsHarness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	prices := map[string]store.PaddlePlan{
		orgsPricePlus: {Name: "plus_beta", Version: 1, Interval: "month"},
		orgsPriceTeam: {Name: "team", Version: 1, Interval: "month", Display: "$12/seat"},
	}
	s.SetPaddlePriceMap(prices)
	apiStore.SetPaddlePriceMap(prices)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	opts := api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            identity.NewDevAuth(),
		ExternalBaseURL:     base,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PaddleWebhookSecret: paddleSecret,
		PaddleCheckout: api.PaddleCheckout{
			Environment: "sandbox", ClientToken: "test_client_token",
			Prices: []api.PaddlePriceEntry{
				{PriceID: orgsPricePlus, PlanName: "plus_beta", PlanVersion: 1, Interval: "month"},
				{PriceID: orgsPriceTeam, PlanName: "team", PlanVersion: 1, Interval: "month", Display: "$12/seat"},
			},
		},
		TenantDomain: orgsTenantDomain,
	}
	if edit != nil {
		edit(&opts)
	}
	handler := api.New(opts).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return orgsHarness{harness: &harness{srv: srv, store: s}, pool: pool}
}

// orgReq sends a JSON request as c, with the CSRF header csrf ("" for none)
// and an explicit Origin ("" for none).
func orgReq(t *testing.T, c *portalClient, method, path string, body any, csrf, origin string) *http.Response {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

type orgDetail struct {
	Org struct {
		OrgID       string `json:"org_id"`
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
		Tenancy     string `json:"tenancy"`
		ConsoleRole string `json:"console_role"`
		Host        string `json:"host"`
		// MachinesPageURL is the tenant page of the caller's machines
		// (C2.front-door-4 B: a link, no browser-side tenant read).
		MachinesPageURL string `json:"machines_page_url"`
		Provisioning    *struct {
			Stage          string `json:"stage"`
			Attempts       int    `json:"attempts"`
			LastErrorClass string `json:"last_error_class"`
		} `json:"provisioning"`
	} `json:"org"`
	LaunchURL string `json:"launch_url"`
	// MachinesURL is the retired tenant read (A13); it must stay absent.
	MachinesURL string `json:"machines_url"`
	Plan        *struct {
		Name     string `json:"name"`
		Source   string `json:"source"`
		NotAfter string `json:"not_after"`
		SeatsMin int    `json:"seats_min"`
	} `json:"plan"`
	Can struct {
		Rename      bool `json:"rename"`
		ViewBilling bool `json:"view_billing"`
		Checkout    bool `json:"checkout"`
	} `json:"can"`
	Replayed bool `json:"replayed"`
}

func errCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var e struct {
		Code string `json:"code"`
	}
	decode(t, resp, &e)
	return e.Code
}

// createTeam creates a team org as c and returns its detail.
func createTeam(t *testing.T, c *portalClient, name, slug string) orgDetail {
	t.Helper()
	resp := orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": name, "slug": slug}, c.csrf, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create team status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var d orgDetail
	decode(t, resp, &d)
	return d
}

func getOrgDetail(t *testing.T, c *portalClient, id string) orgDetail {
	t.Helper()
	resp := c.get("/portal/api/orgs/" + id)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get org status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var d orgDetail
	decode(t, resp, &d)
	return d
}

func TestPortalSlugAvailability(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "slug-alice")
	createTeam(t, c, "Taken", "taken-co")
	cases := []struct {
		slug      string
		available bool
		reason    string
		host      string
	}{
		{"fresh-co", true, "", "fresh-co.example.test"},
		{"  Fresh-Co ", true, "", "fresh-co.example.test"}, // trimmed, lower-cased
		{"taken-co", false, "taken", "taken-co.example.test"},
		{"admin", false, "reserved", ""},
		{"ab", false, "invalid", ""},
		{"u-abcdefgh", false, "invalid", ""},
		{"bad--slug", false, "invalid", ""},
		{"-edge", false, "invalid", ""},
		{"no_underscore", false, "invalid", ""},
	}
	for _, tc := range cases {
		resp := c.get("/portal/api/orgs/slug-availability?slug=" + strings.ReplaceAll(tc.slug, " ", "%20"))
		var got struct {
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
			Host      string `json:"host"`
		}
		decode(t, resp, &got)
		if got.Available != tc.available || got.Reason != tc.reason || got.Host != tc.host {
			t.Errorf("%q: got %+v, want available=%v reason=%q host=%q", tc.slug, got, tc.available, tc.reason, tc.host)
		}
	}
	// Signed out: no answer.
	if resp, _ := http.Get(h.srv.URL + "/portal/api/orgs/slug-availability?slug=fresh-co"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed-out availability status=%d, want 401", resp.StatusCode)
	}
}

func TestPortalCreateTeamGuardsAndEnqueue(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "create-bob")
	body := map[string]string{"display_name": "Bob's Team", "slug": "bobs-team"}

	if resp := orgReq(t, c, "POST", "/portal/api/orgs", body, "", ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "csrf_failed" {
		t.Fatalf("no CSRF: want 403 csrf_failed")
	}
	if resp := orgReq(t, c, "POST", "/portal/api/orgs", body, "wrong-token", ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "csrf_failed" {
		t.Fatalf("wrong CSRF: want 403 csrf_failed")
	}
	if resp := orgReq(t, c, "POST", "/portal/api/orgs", body, c.csrf, "https://bobs-team.example.test"); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "origin_mismatch" {
		t.Fatalf("tenant Origin: want 403 origin_mismatch")
	}
	if resp, _ := http.Post(h.srv.URL+"/portal/api/orgs", "application/json", strings.NewReader(`{}`)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("signed out create status=%d, want 401", resp.StatusCode)
	}

	d := createTeam(t, c, "Bob's Team", "Bobs-Team")
	if d.Org.Slug != "bobs-team" || d.Org.Status != "provisioning" || d.Org.Tenancy != "managed" || d.Org.ConsoleRole != "owner" ||
		d.Org.Host != "bobs-team.example.test" || d.Org.Provisioning == nil || d.Org.Provisioning.Stage != "queued" {
		t.Fatalf("created org = %+v", d.Org)
	}
	if d.LaunchURL != "" || d.MachinesURL != "" || d.Org.MachinesPageURL != "" {
		t.Errorf("a provisioning org got links: %q %q %q", d.LaunchURL, d.MachinesURL, d.Org.MachinesPageURL)
	}
	// The EXISTING create intent was enqueued in the same transaction, keyed
	// by the org id, and nothing else.
	var verb, key, state string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT verb, idempotency_key, state FROM org_outbox WHERE org_id=$1::uuid`, d.Org.OrgID).Scan(&verb, &key, &state); err != nil {
		t.Fatalf("outbox row: %v", err)
	}
	if verb != "create_tenant" || key != d.Org.OrgID || state != "pending" {
		t.Fatalf("outbox row = %s %s %s", verb, key, state)
	}

	// A repeat of the same create answers with the same org (replayed).
	resp := orgReq(t, c, "POST", "/portal/api/orgs", body, c.csrf, "")
	var again orgDetail
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	decode(t, resp, &again)
	if !again.Replayed || again.Org.OrgID != d.Org.OrgID {
		t.Fatalf("replay = %+v", again)
	}
	var n int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM org_outbox WHERE verb='create_tenant'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("create intents = %d err=%v, want 1", n, err)
	}

	// Another account, the same slug: taken. A different name by the same
	// caller is not a replay either.
	other := h.portalLogin(t, "create-carol")
	if resp := orgReq(t, other, "POST", "/portal/api/orgs", body, other.csrf, ""); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "slug_taken" {
		t.Fatalf("other account same slug: want 409 slug_taken")
	}
	if resp := orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": "Other", "slug": "bobs-team"}, c.csrf, ""); resp.StatusCode != http.StatusConflict {
		t.Fatalf("same slug, other name: status=%d, want 409", resp.StatusCode)
	}

	refusals := []struct {
		name, display, slug, code string
		status                    int
	}{
		{"reserved", "X", "billing", "slug_reserved", 400},
		{"too short", "X", "ab", "slug_invalid", 400},
		{"personal shape", "X", "u-abcdefgh", "slug_invalid", 400},
		{"empty name", "  ", "valid-slug", "display_name_invalid", 400},
		{"long name", strings.Repeat("n", 101), "valid-slug-2", "display_name_invalid", 400},
	}
	for _, r := range refusals {
		resp := orgReq(t, c, "POST", "/portal/api/orgs", map[string]string{"display_name": r.display, "slug": r.slug}, c.csrf, "")
		if resp.StatusCode != r.status || errCode(t, resp) != r.code {
			t.Errorf("%s: want %d %s", r.name, r.status, r.code)
		}
	}

	// The account home lists it.
	lresp := c.get("/portal/api/orgs")
	var list struct {
		Orgs []struct {
			Slug         string `json:"slug"`
			Provisioning *struct {
				Stage string `json:"stage"`
			} `json:"provisioning"`
		} `json:"orgs"`
		TenantDomain string `json:"tenant_domain"`
	}
	decode(t, lresp, &list)
	if len(list.Orgs) != 1 || list.Orgs[0].Slug != "bobs-team" || list.Orgs[0].Provisioning == nil || list.TenantDomain != orgsTenantDomain {
		t.Fatalf("list = %+v", list)
	}
}

// TestPortalOrgProvisioningStages reads one org through every create stage
// the worker can leave it in, and the links appear only once it is active.
func TestPortalOrgProvisioningStages(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "stage-dan")
	d := createTeam(t, c, "Dan", "dan-team")
	ctx := context.Background()
	steps := []struct {
		name, sql, stage string
	}{
		{"sent, no answer yet", `UPDATE org_outbox SET state='sent', attempts=1 WHERE org_id=$1::uuid`, "creating"},
		{"waitlisted", `UPDATE org_outbox SET state='pending', last_error_class='refused:capacity_waitlist' WHERE org_id=$1::uuid`, "waitlisted"},
		{"retrying", `UPDATE org_outbox SET last_error_class='transport:timeout' WHERE org_id=$1::uuid`, "retrying"},
		{"parked", `UPDATE org_outbox SET state='failed', done_at=now() WHERE org_id=$1::uuid`, "failed"},
		{"acked, status lagging", `UPDATE org_outbox SET state='acked', last_error_class=NULL, done_at=now() WHERE org_id=$1::uuid`, "finishing"},
	}
	for _, st := range steps {
		if _, err := h.pool.Exec(ctx, st.sql, d.Org.OrgID); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		got := getOrgDetail(t, c, d.Org.OrgID)
		if got.Org.Provisioning == nil || got.Org.Provisioning.Stage != st.stage {
			t.Fatalf("%s: provisioning=%+v, want %s", st.name, got.Org.Provisioning, st.stage)
		}
	}
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	got := getOrgDetail(t, c, d.Org.OrgID)
	if got.Org.Provisioning != nil {
		t.Errorf("an active org still carries provisioning: %+v", got.Org.Provisioning)
	}
	// The machines link is a page on the team's own dashboard; the console
	// no longer reads the tenant's machine API from the browser.
	if got.LaunchURL != "https://dan-team.example.test/me/install" || got.MachinesURL != "" ||
		got.Org.MachinesPageURL != "https://dan-team.example.test/me/profile" {
		t.Fatalf("links = %q %q %q", got.LaunchURL, got.MachinesURL, got.Org.MachinesPageURL)
	}
	// The create was acked just now: the org runs on its launch plan.
	if got.Plan == nil || got.Plan.Name != "team" || got.Plan.Source != "launch" || got.Plan.NotAfter == "" || got.Plan.SeatsMin != 3 {
		t.Fatalf("plan = %+v, want the team launch plan", got.Plan)
	}
	// Non-member: not found, never a hint.
	stranger := h.portalLogin(t, "stage-eve")
	if resp := stranger.get("/portal/api/orgs/" + d.Org.OrgID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stranger status=%d, want 404", resp.StatusCode)
	}
	if resp := c.get("/portal/api/orgs/not-a-uuid"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("malformed id status=%d, want 404", resp.StatusCode)
	}
}

func TestPortalRenameBlockedWhileProvisioning(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "rename-fay")
	d := createTeam(t, c, "Fay", "fay-team")
	path := "/portal/api/orgs/" + d.Org.OrgID
	rename := map[string]string{"display_name": "Fay Two"}

	if d.Can.Rename {
		t.Error("a provisioning org offers rename")
	}
	if resp := orgReq(t, c, "PATCH", path, rename, c.csrf, ""); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "org_provisioning" {
		t.Fatalf("rename while provisioning: want 409 org_provisioning")
	}
	if resp := orgReq(t, c, "PATCH", path, rename, "", ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "csrf_failed" {
		t.Fatalf("rename without CSRF: want 403 csrf_failed")
	}
	if _, err := h.pool.Exec(context.Background(), `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	if resp := orgReq(t, c, "PATCH", path, map[string]string{"slug": "new-slug"}, c.csrf, ""); resp.StatusCode != http.StatusBadRequest || errCode(t, resp) != "slug_rename_unsupported" {
		t.Fatalf("slug rename: want 400 slug_rename_unsupported")
	}
	resp := orgReq(t, c, "PATCH", path, rename, c.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var got orgDetail
	decode(t, resp, &got)
	if got.Org.DisplayName != "Fay Two" || got.Org.Slug != "fay-team" || !got.Can.Rename {
		t.Fatalf("renamed = %+v", got)
	}
	stranger := h.portalLogin(t, "rename-gus")
	if resp := orgReq(t, stranger, "PATCH", path, rename, stranger.csrf, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stranger rename status=%d, want 404", resp.StatusCode)
	}
}

// TestPortalOrgBillingCheckoutWebhook is billing per org end to end: the org
// page offers only team prices and the personal page only account prices,
// the billing owner mints an org checkout, the signed webhook binds the
// subscription to the org, and the page and the plan follow it.
func TestPortalOrgBillingCheckoutWebhook(t *testing.T) {
	h := newOrgsHarness(t)
	c := h.portalLogin(t, "bill-hal")
	d := createTeam(t, c, "Hal", "hal-team")
	ctx := context.Background()
	if _, err := h.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, d.Org.OrgID); err != nil {
		t.Fatal(err)
	}
	billingPath := "/portal/api/orgs/" + d.Org.OrgID + "/billing"

	type billingView struct {
		HasSubscription bool `json:"has_subscription"`
		Subscription    *struct {
			PlanName string `json:"plan_name"`
			Status   string `json:"status"`
		} `json:"subscription"`
		Checkout struct {
			Available bool `json:"available"`
			Prices    []struct {
				PriceID string `json:"price_id"`
			} `json:"prices"`
		} `json:"checkout"`
		CanCheckout bool `json:"can_checkout"`
		Plan        *struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"plan"`
	}
	var bv billingView
	decode(t, c.get(billingPath), &bv)
	if bv.HasSubscription || !bv.CanCheckout || !bv.Checkout.Available || len(bv.Checkout.Prices) != 1 || bv.Checkout.Prices[0].PriceID != orgsPriceTeam {
		t.Fatalf("org billing before checkout = %+v", bv)
	}
	if bv.Plan == nil || bv.Plan.Name != "team_lapsed" || bv.Plan.Source != "floor" {
		t.Fatalf("plan before any create ack or subscription = %+v, want the floor", bv.Plan)
	}
	var personal billingView
	decode(t, c.get("/portal/api/billing"), &personal)
	if len(personal.Checkout.Prices) != 1 || personal.Checkout.Prices[0].PriceID != orgsPricePlus {
		t.Fatalf("personal billing offers %+v, want only the Plus price", personal.Checkout.Prices)
	}
	if resp := orgReq(t, c, "POST", "/portal/api/billing/checkout", map[string]string{"price_id": orgsPriceTeam}, c.csrf, ""); resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("team price on the account checkout status=%d, want 501", resp.StatusCode)
	}

	checkoutPath := billingPath + "/checkout"
	if resp := orgReq(t, c, "POST", checkoutPath, map[string]string{"price_id": orgsPriceTeam}, "", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("org checkout without CSRF status=%d, want 403", resp.StatusCode)
	}
	if resp := orgReq(t, c, "POST", checkoutPath, map[string]string{"price_id": orgsPricePlus}, c.csrf, ""); resp.StatusCode != http.StatusNotImplemented || errCode(t, resp) != "checkout_unavailable" {
		t.Fatalf("Plus price on the org checkout: want 501 checkout_unavailable")
	}
	resp := orgReq(t, c, "POST", checkoutPath, map[string]string{"price_id": orgsPriceTeam}, c.csrf, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("org checkout status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var intent struct {
		CustomData map[string]string `json:"custom_data"`
	}
	decode(t, resp, &intent)
	if intent.CustomData["org_id"] != d.Org.OrgID || intent.CustomData["account_id"] != c.accountID || intent.CustomData["checkout_nonce"] == "" {
		t.Fatalf("custom_data = %v", intent.CustomData)
	}

	whBody := []byte(`{
		"event_id": "evt_org_web_1", "event_type": "subscription.activated", "occurred_at": "` + time.Now().UTC().Format(time.RFC3339) + `",
		"data": {
			"id": "sub_org_web", "customer_id": "ctm_org_web", "status": "active",
			"custom_data": {"account_id": "` + c.accountID + `", "org_id": "` + d.Org.OrgID + `", "checkout_nonce": "` + intent.CustomData["checkout_nonce"] + `"},
			"items": [{"price": {"id": "` + orgsPriceTeam + `"}}]
		}
	}`)
	// A bad signature changes nothing.
	if r := signedPaddle(t, h.srv.URL, whBody, time.Now(), "wrong-secret"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad signature status=%d, want 401", r.StatusCode)
	}
	decode(t, c.get(billingPath), &bv)
	if bv.HasSubscription {
		t.Fatal("a refused delivery wrote a subscription")
	}
	r := signedPaddle(t, h.srv.URL, whBody, time.Now(), paddleSecret)
	var wh struct {
		Applied bool   `json:"applied"`
		Outcome string `json:"outcome"`
	}
	decode(t, r, &wh)
	if !wh.Applied || wh.Outcome != "applied" {
		t.Fatalf("org webhook = %+v", wh)
	}
	// Replayed: a duplicate, nothing more.
	r = signedPaddle(t, h.srv.URL, whBody, time.Now(), paddleSecret)
	var dup struct {
		Status string `json:"status"`
	}
	decode(t, r, &dup)
	if dup.Status != "duplicate" {
		t.Fatalf("replay status=%q, want duplicate", dup.Status)
	}

	decode(t, c.get(billingPath), &bv)
	if !bv.HasSubscription || bv.Subscription == nil || bv.Subscription.PlanName != "team" || bv.Subscription.Status != "active" || bv.CanCheckout {
		t.Fatalf("org billing after webhook = %+v", bv)
	}
	if bv.Plan == nil || bv.Plan.Name != "team" || bv.Plan.Source != "subscription" {
		t.Fatalf("plan after webhook = %+v, want the subscription's team", bv.Plan)
	}
	// The personal page still shows no subscription.
	var personalAfter billingView
	decode(t, c.get("/portal/api/billing"), &personalAfter)
	if personalAfter.HasSubscription {
		t.Fatal("the org subscription showed on the personal billing page")
	}
	if resp := orgReq(t, c, "POST", checkoutPath, map[string]string{"price_id": orgsPriceTeam}, c.csrf, ""); resp.StatusCode != http.StatusConflict || errCode(t, resp) != "already_subscribed" {
		t.Fatalf("second org checkout: want 409 already_subscribed")
	}

	// A plain member sees neither billing nor checkout.
	member := h.portalLogin(t, "bill-ivy")
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`,
		d.Org.OrgID, member.accountID); err != nil {
		t.Fatal(err)
	}
	if resp := member.get(billingPath); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member billing status=%d, want 403", resp.StatusCode)
	}
	if resp := orgReq(t, member, "POST", checkoutPath, map[string]string{"price_id": orgsPriceTeam}, member.csrf, ""); resp.StatusCode != http.StatusForbidden || errCode(t, resp) != "billing_owner_required" {
		t.Fatalf("member checkout: want 403 billing_owner_required")
	}
	if md := getOrgDetail(t, member, d.Org.OrgID); md.Plan != nil || md.Can.ViewBilling || md.Can.Checkout {
		t.Fatalf("member detail shows billing: %+v", md)
	}
}
