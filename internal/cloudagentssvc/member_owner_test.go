package cloudagentssvc

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Member scope of the OpenHands Cloud and Warp connectors (CLOUDAGENTS-6,
// task CA-T8): an OpenHands key's search lists every conversation the key
// can see and a Warp key its teams' runs, so the account names the
// developer's own vendor user and only that user's sessions land, exactly as
// Devin's does (devin_owner_test.go). The pass dispatches on the row's
// MemberUsers capability; these tests pin that the two rows declare it.

const (
	openHandsMe        = "user-synth-0001"
	openHandsColleague = "user-synth-0002"
)

// ohConv is one conversation of a synthetic OpenHands search page; creator
// "" is a conversation naming no creator.
func ohConv(id, creator string, updated time.Time, usd string) string {
	by := "null"
	if creator != "" {
		by = `"` + creator + `"`
	}
	metrics := "null"
	if usd != "" {
		metrics = `{"accumulated_cost":` + usd + `,"accumulated_token_usage":{"prompt_tokens":100,"completion_tokens":10}}`
	}
	return fmt.Sprintf(`{"id":%q,"created_by_user_id":%s,"selected_repository":"acme/widget","git_provider":"github",`+
		`"title":"SYNTHETIC TITLE","trigger":"gui","llm_model":"litellm_proxy/gpt-5","metrics":%s,`+
		`"created_at":%q,"updated_at":%q,"sandbox_status":"PAUSED","execution_status":"finished",`+
		`"session_api_key":"synthetic-session-placeholder"}`,
		id, by, metrics, updated.Add(-time.Minute).Format(time.RFC3339), updated.Format(time.RFC3339))
}

// ohOrgAPI answers a synthetic OpenHands account whose search page is list.
type ohOrgAPI struct {
	mu   sync.Mutex
	list []string
}

func (o *ohOrgAPI) fake() *fakeAPI {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		o.mu.Lock()
		defer o.mu.Unlock()
		switch {
		case strings.Contains(req.URL, "/app-conversations/search?"):
			return []byte(`{"items":[` + strings.Join(o.list, ",") + `],"next_page_id":null}`), nil
		case strings.Contains(req.URL, "/events/search?"):
			return []byte(`{"items":[],"next_page_id":null}`), nil
		}
		return nil, notFound(req)
	}
	return api
}

func connectKeyed(t *testing.T, svc *Service, connector string) int64 {
	t.Helper()
	_, av, err := svc.ConnectWith(context.Background(), connector, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatalf("connect %s: %+v %v", connector, av, err)
	}
	if av.UserState != cloudagents.VendorUserNotChosen {
		t.Fatalf("a new %s account reads %q, want vendor_user_not_chosen", connector, av.UserState)
	}
	return av.ID
}

// TestMemberScopedRowsDeclareTheCapability: the catalog says OpenHands and
// Warp take a user, with their labels, so the CLI and the dashboard picker
// (generic over the capability) offer it.
func TestMemberScopedRowsDeclareTheCapability(t *testing.T) {
	for id, label := range map[string]string{
		cloudagents.ConnectorDevin: "Devin user", cloudagents.ConnectorOpenHandsCloud: "OpenHands user", cloudagents.ConnectorWarpCloud: "Warp user",
	} {
		c, ok := connectorInfo(Catalog(), id)
		if !ok || !c.ChoosesUser || c.UserLabel != label {
			t.Errorf("%s catalog: %+v", id, c)
		}
	}
}

// TestOpenHandsUnchosenUserPullsNothing: an OpenHands account with no user
// chosen makes no call and lands nothing. Old code pulled every
// conversation the key could see.
func TestOpenHandsUnchosenUserPullsNothing(t *testing.T) {
	o := &ohOrgAPI{list: []string{ohConv("oh-me-1", openHandsMe, t0, "0.5")}}
	api := o.fake()
	clk := &clock{t: t0.Add(time.Minute)}
	svc, _, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectKeyed(t, svc, cloudagents.ConnectorOpenHandsCloud)
	api.reset()
	api.forbid = true
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.UserState != cloudagents.VendorUserNotChosen || res.Tasks != 0 || res.Pages != 0 {
		t.Fatalf("unchosen sync: %v %+v", err, res)
	}
	clk.set(t0.Add(time.Hour))
	svc.SyncDue(ctx)
	if calls := api.reset(); len(calls) != 0 {
		t.Fatalf("an unchosen account called the vendor: %v", calls)
	}
	var n int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE tool = ?`, cloudagents.ToolOpenHands).Scan(&n)
	if n != 0 {
		t.Fatalf("%d OpenHands sessions landed with no user chosen", n)
	}
}

// TestOpenHandsOwnConversationsOnly: with the developer's user chosen, a
// colleague's conversation and one naming no creator never land (no events
// read, no ledger row); choosing the colleague first and then the developer
// removes the colleague's landed conversations on the next pass.
func TestOpenHandsOwnConversationsOnly(t *testing.T) {
	o := &ohOrgAPI{list: []string{
		ohConv("oh-me-1", openHandsMe, t0, "0.5"),
		ohConv("oh-col-1", openHandsColleague, t0.Add(-time.Minute), "1.25"),
		ohConv("oh-none-1", "", t0.Add(-2*time.Minute), "0.75"),
	}}
	api := o.fake()
	clk := &clock{t: t0.Add(time.Minute)}
	svc, _, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectKeyed(t, svc, cloudagents.ConnectorOpenHandsCloud)
	// The colleague's conversations land first (the account named them).
	if _, err := svc.ChooseVendorUser(ctx, id, openHandsColleague); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.SyncAccount(ctx, id); err != nil || res.Tasks != 1 || res.SkippedOtherMember != 1 || res.SkippedNoUser != 1 {
		t.Fatalf("first sync: %v %+v", err, res)
	}
	var n int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = 'oh-col-1'`).Scan(&n)
	if n == 0 {
		t.Fatal("setup: the colleague's conversation did not land")
	}
	av, err := svc.ChooseVendorUser(ctx, id, openHandsMe)
	if err != nil || !av.PurgePending {
		t.Fatalf("choose: %v %+v", err, av)
	}
	api.reset()
	clk.set(t0.Add(20 * time.Minute))
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.ErrorClass != "" {
		t.Fatalf("purge pass: %v %+v", err, res)
	}
	if res.Tasks != 1 || res.SkippedOtherMember != 1 || res.SkippedNoUser != 1 || res.PurgedOtherMember != 1 {
		t.Fatalf("purge pass counts: %+v", res)
	}
	for _, c := range api.reset() {
		if strings.Contains(c, "oh-col-1") || strings.Contains(c, "oh-none-1") {
			t.Errorf("read the events of a conversation the account does not keep: %s", c)
		}
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"my conversation", `SELECT COUNT(*) FROM sessions WHERE id = 'oh-me-1'`, 1},
		{"my usd row", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = 'oh-me-1'`, 1},
		{"others' conversations", `SELECT COUNT(*) FROM sessions WHERE id IN ('oh-col-1','oh-none-1')`, 0},
		{"others' actions", `SELECT COUNT(*) FROM actions WHERE session_id IN ('oh-col-1','oh-none-1')`, 0},
		{"others' token rows", `SELECT COUNT(*) FROM token_usage WHERE session_id IN ('oh-col-1','oh-none-1')`, 0},
		{"others' usd rows", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session IN ('oh-col-1','oh-none-1')`, 0},
		{"others' checkpoints", `SELECT COUNT(*) FROM cloud_sync_checkpoints WHERE scope IN ('oh-col-1','oh-none-1')`, 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, q.sql).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, got, q.want)
		}
	}
	if v, _ := svc.Status(ctx); v.Accounts[0].PurgePending || v.Accounts[0].VendorUser != openHandsMe {
		t.Fatalf("account view: %+v", v.Accounts[0])
	}
}

// warpFixtureAPI answers the Warp driver fixtures as they are (one run a
// service account created).
func warpFixtureAPI(t *testing.T) *fakeAPI {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		switch {
		case strings.Contains(u, "/agent/runs?") && strings.Contains(u, "cursor=synthRunsCursor0002"):
			return vendorFixture(t, "warp/warp.agent_api.runs_list/last_page.json"), nil
		case strings.Contains(u, "/agent/runs?"):
			return vendorFixture(t, "warp/warp.agent_api.runs_list/normal_page.json"), nil
		case strings.HasSuffix(u, "/harness-usage"):
			return vendorFixture(t, "warp/warp.agent_api.run_harness_usage/normal_page.json"), nil
		case strings.HasSuffix(u, "/conversation"):
			return vendorFixture(t, "warp/warp.agent_api.run_conversation/normal_page.json"), nil
		}
		return nil, notFound(req)
	}
	return api
}

const (
	warpRunClaude = "7c1e2a40-0000-4000-8000-000000000001"
	warpRunSvc    = "7c1e2a40-0000-4000-8000-000000000002" // the service account's (codex harness)
	warpRunOz     = "7c1e2a40-0000-4000-8000-000000000003"
)

// TestWarpOwnRunsOnly: with the developer's Warp user chosen, a run the
// team's service account created (what an Agent key starts) is skipped as a
// service user's: no session, no harness usage or conversation read, no
// ledger row. The developer's runs land as before; an unchosen account makes
// no call.
func TestWarpOwnRunsOnly(t *testing.T) {
	api := warpFixtureAPI(t)
	clk := &clock{t: t0}
	svc, _, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectKeyed(t, svc, cloudagents.ConnectorWarpCloud)
	api.reset()
	api.forbid = true
	if res, err := svc.SyncAccount(ctx, id); err != nil || res.UserState != cloudagents.VendorUserNotChosen || res.Pages != 0 {
		t.Fatalf("unchosen sync: %v %+v", err, res)
	}
	api.forbid = false
	if _, err := svc.ChooseVendorUser(ctx, id, warpMe); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.ErrorClass != "" {
		t.Fatalf("sync: %v %+v", err, res)
	}
	if res.Tasks != 3 || res.SkippedServiceUser != 1 || res.SkippedOtherMember != 0 || res.NoToolRows != 2 {
		t.Fatalf("counts: %+v", res)
	}
	for _, c := range api.reset() {
		if strings.Contains(c, warpRunSvc) {
			t.Errorf("read a service account's run: %s", c)
		}
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"my claude run", `SELECT COUNT(*) FROM sessions WHERE id = '` + warpRunClaude + `'`, 1},
		{"my oz run's ledger", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = '` + warpRunOz + `'`, 2},
		{"the service run", `SELECT COUNT(*) FROM sessions WHERE id = '` + warpRunSvc + `'`, 0},
		{"the service run's ledger", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = '` + warpRunSvc + `'`, 0},
		{"the service run's checkpoint", `SELECT COUNT(*) FROM cloud_sync_checkpoints WHERE scope = '` + warpRunSvc + `'`, 0},
		{"lineage to the service run", `SELECT COUNT(*) FROM cloud_sync_checkpoints WHERE cursor LIKE '%` + warpRunSvc + `%'`, 0},
	} {
		var got int
		if err := database.QueryRowContext(ctx, q.sql).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, got, q.want)
		}
	}
}

// TestWarpChoosingUserPurgesOthers: runs landed under another person (the
// account first named the fixtures' creator) are removed on the pass after
// the developer's choice: the Claude Code run's session with its rows, and
// the oz run's ledger rows (it landed no session); a ledger row the list
// does not name stays.
func TestWarpChoosingUserPurgesOthers(t *testing.T) {
	api := warpFixtureAPI(t)
	clk := &clock{t: t0}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectKeyed(t, svc, cloudagents.ConnectorWarpCloud)
	if _, err := svc.ChooseVendorUser(ctx, id, warpMe); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.SyncAccount(ctx, id); err != nil || res.Tasks != 3 {
		t.Fatalf("first sync: %v %+v", err, res)
	}
	if _, _, err := st.InsertCloudUsage(ctx, store.CloudUsageEntry{
		Connector: cloudagents.ConnectorWarpCloud, SourceRecordID: "unlisted-run:credit", MeasurementSource: models.UsageSourceProviderRunTotal,
		ValueType: models.UsageValueCumulative, Unit: "warp_credit", Value: 3, MonetaryStatus: models.UsageMonetaryNone,
		ScopeSession: "unlisted-run", ReportedAt: t0,
	}); err != nil {
		t.Fatal(err)
	}
	av, err := svc.ChooseVendorUser(ctx, id, "synthMeUid0009")
	if err != nil || !av.PurgePending {
		t.Fatalf("choose: %v %+v", err, av)
	}
	clk.set(t0.Add(20 * time.Minute))
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.ErrorClass != "" {
		t.Fatalf("purge pass: %v %+v", err, res)
	}
	if res.Tasks != 0 || res.SkippedOtherMember != 3 || res.SkippedServiceUser != 1 || res.PurgedOtherMember != 1 || res.PurgedLedgerOnly != 2 {
		t.Fatalf("purge pass counts: %+v", res)
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"the claude run", `SELECT COUNT(*) FROM sessions WHERE id = '` + warpRunClaude + `'`, 0},
		{"the claude run's actions", `SELECT COUNT(*) FROM actions WHERE session_id = '` + warpRunClaude + `'`, 0},
		{"the claude run's tokens", `SELECT COUNT(*) FROM token_usage WHERE session_id = '` + warpRunClaude + `'`, 0},
		{"the claude run's ledger", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = '` + warpRunClaude + `'`, 0},
		{"the oz run's ledger", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = '` + warpRunOz + `'`, 0},
		{"an unlisted ledger row", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = 'unlisted-run'`, 1},
	} {
		var got int
		if err := database.QueryRowContext(ctx, q.sql).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, got, q.want)
		}
	}
	if v, _ := svc.Status(ctx); v.Accounts[0].PurgePending {
		t.Fatal("the removal still reads owed after its pass")
	}
}

// TestMemberUserCandidatesFromTheList: the Warp picker names its users from
// the list page itself (one call, no message read; the service account is
// counted, never offered, and its e-mail never read); the OpenHands picker
// offers ids only (one call). Choosing refuses an id outside the row's
// grammar without a vendor call.
func TestMemberUserCandidatesFromTheList(t *testing.T) {
	ctx := context.Background()
	wAPI := warpFixtureAPI(t)
	wsvc, _, _, _, _ := newAPIService(t, wAPI, &clock{t: t0})
	wid := connectKeyed(t, wsvc, cloudagents.ConnectorWarpCloud)
	wAPI.reset()
	uc, err := wsvc.UserCandidates(ctx, wid)
	if err != nil || uc.ErrorClass != "" {
		t.Fatalf("warp candidates: %v %+v", err, uc)
	}
	want := []cloudagents.VendorUserCandidate{{UserID: warpMe, Username: "Synthetic User", Sessions: 2}}
	if fmt.Sprint(uc.Candidates) != fmt.Sprint(want) || uc.ServiceUserSessions != 1 || uc.MessageReads != 0 || !uc.More || uc.UserLabel != "Warp user" {
		t.Fatalf("warp candidates = %+v", uc)
	}
	if calls := wAPI.reset(); len(calls) != 1 || !strings.HasPrefix(calls[0], "https://app.warp.dev/api/v1/agent/runs?") {
		t.Fatalf("warp calls = %v", calls)
	}
	for _, bad := range []string{"", "a.b", "uid with space", "synthetic.user@example.com", warpMe + "\n", strings.Repeat("a", 129)} {
		if _, err := wsvc.ChooseVendorUser(ctx, wid, bad); err == nil {
			t.Errorf("warp choose accepted %q", bad)
		}
	}

	o := &ohOrgAPI{list: []string{
		ohConv("oh-me-1", openHandsMe, t0, ""), ohConv("oh-me-2", openHandsMe, t0, ""),
		ohConv("oh-col-1", openHandsColleague, t0, ""), ohConv("oh-none-1", "", t0, ""),
	}}
	oAPI := o.fake()
	osvc, _, _, _, _ := newAPIService(t, oAPI, &clock{t: t0})
	oid := connectKeyed(t, osvc, cloudagents.ConnectorOpenHandsCloud)
	oAPI.reset()
	uc, err = osvc.UserCandidates(ctx, oid)
	if err != nil || uc.ErrorClass != "" {
		t.Fatalf("openhands candidates: %v %+v", err, uc)
	}
	want = []cloudagents.VendorUserCandidate{{UserID: openHandsMe, Sessions: 2}, {UserID: openHandsColleague, Sessions: 1}}
	if fmt.Sprint(uc.Candidates) != fmt.Sprint(want) || uc.NoUserSessions != 1 || uc.MessageReads != 0 || uc.More {
		t.Fatalf("openhands candidates = %+v", uc)
	}
	if calls := oAPI.reset(); len(calls) != 1 {
		t.Fatalf("openhands calls = %v", calls)
	}
	for _, bad := range []string{"", "-lead", "a/b", "me@example.com", "has space"} {
		if _, err := osvc.ChooseVendorUser(ctx, oid, bad); err == nil {
			t.Errorf("openhands choose accepted %q", bad)
		}
	}
	if len(oAPI.reset()) != 0 {
		t.Error("choosing called the vendor")
	}
}
