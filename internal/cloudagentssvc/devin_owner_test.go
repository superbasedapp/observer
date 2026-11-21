package cloudagentssvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Member scope of the Devin connector (CLOUDAGENTS-6): an organization key
// lists every member's sessions, so the account names the developer's Devin
// user and only that user's sessions land.

const (
	devinOwnerOrg  = "org-00112233445566778899aabbccddeeff"
	devinMe        = "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	devinColleague = "user-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	devinService   = "service_user-cccccccccccccccccccccccccccccccc"
)

// devinItem is one session of a synthetic organization list.
type devinItem struct {
	id, user, service, parent, prURL string
	acus                             string
	updated                          time.Time
}

func (it devinItem) json() string {
	str := func(v string) string {
		if v == "" {
			return "null"
		}
		return `"` + v + `"`
	}
	prs := "[]"
	if it.prURL != "" {
		prs = `[{"pr_url":"` + it.prURL + `","pr_state":"open"}]`
	}
	acus := "null"
	if it.acus != "" {
		acus = it.acus
	}
	return fmt.Sprintf(`{"session_id":%q,"url":"https://app.devin.ai/sessions/%s","status":"finished","title":"SYNTHETIC TITLE","tags":[],`+
		`"user_id":%s,"service_user_id":%s,"org_id":%q,"created_at":%d,"updated_at":%d,"acus_consumed":%s,`+
		`"pull_requests":%s,"parent_session_id":%s,"child_session_ids":[],"origin":"webapp","status_detail":null}`,
		it.id, it.id, str(it.user), str(it.service), devinOwnerOrg, it.updated.Add(-time.Minute).Unix(), it.updated.Unix(), acus, prs, str(it.parent))
}

func devinList(items ...devinItem) []byte {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, it.json())
	}
	return []byte(`{"items":[` + strings.Join(parts, ",") + `],"end_cursor":null,"has_next_page":false,"total":null}`)
}

// devinMessages is one message page of a session: a user message by user
// (named username) and Devin's answer.
func devinMessages(sessionID, user, username string, at time.Time) []byte {
	js := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	return []byte(fmt.Sprintf(`{"items":[`+
		`{"event_id":"event-%s-1","source":"user","message":"SYNTHETIC USER MESSAGE","created_at":%d,"username":%s,"user_id":%s,"origin":"web"},`+
		`{"event_id":"event-%s-2","source":"devin","message":"SYNTHETIC DEVIN MESSAGE","created_at":%d,"username":null,"user_id":null,"origin":null}`+
		`],"end_cursor":null,"has_next_page":false,"total":null}`, sessionID, at.Unix(), js(username), js(user), sessionID, at.Add(time.Second).Unix()))
}

// devinOrgAPI answers the synthetic organization: list is the current list
// document; messages names each session's user.
type devinOrgAPI struct {
	mu    sync.Mutex
	list  []byte
	users map[string][2]string // session id -> {user id, username}
}

func (d *devinOrgAPI) fake() *fakeAPI {
	api := &fakeAPI{}
	api.call = func(req cloudagents.Request) ([]byte, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		u := req.URL
		if !strings.HasPrefix(u, "https://api.devin.ai/v3/organizations/"+devinOwnerOrg+"/sessions") {
			return nil, notFound(req)
		}
		rest := strings.TrimPrefix(u, "https://api.devin.ai/v3/organizations/"+devinOwnerOrg+"/sessions")
		if strings.HasPrefix(rest, "?") {
			return d.list, nil
		}
		sid, tail, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
		if !strings.HasPrefix(tail, "messages") {
			return nil, notFound(req)
		}
		who := d.users[sid]
		return devinMessages(sid, who[0], who[1], t0), nil
	}
	return api
}

func connectDevin(t *testing.T, svc *Service) int64 {
	t.Helper()
	_, av, err := svc.ConnectWith(context.Background(), cloudagents.ConnectorDevin, Credentials{Key: apiKey, Params: map[string]string{"org_id": devinOwnerOrg}})
	if err != nil || av == nil {
		t.Fatalf("connect: %+v %v", av, err)
	}
	if av.UserState != cloudagents.VendorUserNotChosen {
		t.Fatalf("a new Devin account reads %q, want vendor_user_not_chosen", av.UserState)
	}
	return av.ID
}

// TestDevinUnchosenUserPullsNothing: a Devin account with no user chosen (a
// new connect, or one linked before the member scope) makes no call and
// lands nothing, on a manual sync and on the daemon's tick; the state says
// so. Old code pulled the whole organization here.
func TestDevinUnchosenUserPullsNothing(t *testing.T) {
	org := &devinOrgAPI{list: devinList(devinItem{id: "s-me-1", user: devinMe, updated: t0, acus: "1.5"})}
	api := org.fake()
	clk := &clock{t: t0}
	svc, _, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectDevin(t, svc)
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
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE tool = ?`, models.ToolDevin).Scan(&n)
	if n != 0 {
		t.Fatalf("%d Devin sessions landed with no user chosen", n)
	}
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_usage_ledger`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d ledger rows landed with no user chosen", n)
	}
	v, err := svc.Status(ctx)
	if err != nil || len(v.Accounts) != 1 || v.Accounts[0].UserState != cloudagents.VendorUserNotChosen || v.Accounts[0].VendorUser != "" {
		t.Fatalf("status: %v %+v", err, v.Accounts)
	}
	if c, ok := connectorInfo(v.Connectors, cloudagents.ConnectorDevin); !ok || !c.ChoosesUser || c.UserLabel == "" {
		t.Fatalf("catalog does not say Devin takes a user: %+v", c)
	}
}

func connectorInfo(cs []ConnectorInfo, id string) (ConnectorInfo, bool) {
	for _, c := range cs {
		if c.ID == id {
			return c, true
		}
	}
	return ConnectorInfo{}, false
}

// TestDevinOtherMembersNeverLand: with the developer's user chosen, another
// member's session, its messages, its ACUs, its PR link and its lineage
// never land; a service user's session neither. Only counts are reported.
func TestDevinOtherMembersNeverLand(t *testing.T) {
	org := &devinOrgAPI{
		list: devinList(
			devinItem{id: "s-me-1", user: devinMe, updated: t0, acus: "1.5", prURL: "https://github.com/acme/widget/pull/7"},
			devinItem{id: "s-col-1", user: devinColleague, updated: t0.Add(-time.Minute), acus: "9.25", prURL: "https://github.com/acme/secret/pull/3"},
			devinItem{id: "s-col-child", user: devinColleague, parent: "s-me-1", updated: t0.Add(-2 * time.Minute), acus: "2"},
			devinItem{id: "s-me-child", user: devinMe, parent: "s-col-1", updated: t0.Add(-3 * time.Minute)},
			devinItem{id: "s-svc-1", service: devinService, updated: t0.Add(-4 * time.Minute), acus: "4"},
			devinItem{id: "s-none-1", updated: t0.Add(-5 * time.Minute)},
		),
		users: map[string][2]string{
			"s-me-1": {devinMe, "me"}, "s-me-child": {devinMe, "me"},
			"s-col-1": {devinColleague, "colleague"}, "s-col-child": {devinColleague, "colleague"},
		},
	}
	api := org.fake()
	clk := &clock{t: t0.Add(time.Minute)}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectDevin(t, svc)
	if _, err := svc.ChooseVendorUser(ctx, id, devinMe); err != nil {
		t.Fatal(err)
	}
	api.reset()
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.ErrorClass != "" {
		t.Fatalf("sync: %v %+v", err, res)
	}
	if res.Tasks != 2 || res.SkippedOtherMember != 2 || res.SkippedServiceUser != 1 || res.SkippedNoUser != 1 {
		t.Fatalf("ownership counts: %+v", res)
	}
	for _, c := range api.reset() {
		for _, other := range []string{"s-col-1", "s-col-child", "s-svc-1", "s-none-1"} {
			if strings.Contains(c, "/"+other+"/") {
				t.Errorf("read the history of %s, a session the account does not keep: %s", other, c)
			}
		}
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"sessions", `SELECT COUNT(*) FROM sessions WHERE tool = 'devin'`, 2},
		{"sessions not mine", `SELECT COUNT(*) FROM sessions WHERE id IN ('s-col-1','s-col-child','s-svc-1','s-none-1')`, 0},
		{"actions not mine", `SELECT COUNT(*) FROM actions WHERE session_id IN ('s-col-1','s-col-child','s-svc-1','s-none-1')`, 0},
		{"actions mine", `SELECT COUNT(*) FROM actions WHERE session_id = 's-me-1' AND action_type IN ('user_prompt','assistant_message')`, 2},
		{"acu rows not mine", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session IN ('s-col-1','s-col-child','s-svc-1','s-none-1')`, 0},
		{"acu rows mine", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = 's-me-1' AND unit = 'acu'`, 1},
		{"links not mine", `SELECT COUNT(*) FROM cloud_session_links WHERE session_id IN ('s-col-1','s-col-child')`, 0},
		{"lineage to a colleague", `SELECT COUNT(*) FROM sessions WHERE COALESCE(parent_thread_id,'') = 's-col-1'`, 0},
	} {
		var n int
		if err := database.QueryRowContext(ctx, q.sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, n, q.want)
		}
	}
	live, err := st.ListCloudSyncCheckpoints(ctx, id, models.SyncStreamLive)
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range live {
		if strings.Contains(cp.Scope, "s-col") || strings.Contains(cp.Cursor, "s-col") {
			t.Errorf("a pending link names a colleague's session: %+v", cp)
		}
	}
	// The pass after the choice completed the removal: nothing is owed.
	v, _ := svc.Status(ctx)
	if v.Accounts[0].VendorUser != devinMe || v.Accounts[0].PurgePending || v.Accounts[0].UserState != cloudagents.VendorUserChosen {
		t.Fatalf("account view: %+v", v.Accounts[0])
	}
}

// TestDevinChoosingUserPurgesOtherMembers: sessions landed under another
// user (here: the account first named the colleague, as an account from
// before the member scope landed everyone) are removed on the pass after
// the developer's choice, with their actions, ACU rows, links and
// checkpoints; the developer's own Devin sessions, a Devin session the list
// does not name and a session of another tool stay.
func TestDevinChoosingUserPurgesOtherMembers(t *testing.T) {
	org := &devinOrgAPI{
		list: devinList(
			devinItem{id: "s-me-1", user: devinMe, updated: t0, acus: "1.5"},
			devinItem{id: "s-col-1", user: devinColleague, updated: t0.Add(-time.Minute), acus: "9.25", prURL: "https://github.com/acme/secret/pull/3"},
			devinItem{id: "s-col-2", user: devinColleague, updated: t0.Add(-2 * time.Minute), acus: "3"},
		),
		users: map[string][2]string{
			"s-me-1": {devinMe, "me"}, "s-col-1": {devinColleague, "colleague"}, "s-col-2": {devinColleague, "colleague"},
		},
	}
	api := org.fake()
	clk := &clock{t: t0.Add(time.Minute)}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectDevin(t, svc)
	// The colleague's sessions land first (the account named them).
	if _, err := svc.ChooseVendorUser(ctx, id, devinColleague); err != nil {
		t.Fatal(err)
	}
	if res, err := svc.SyncAccount(ctx, id); err != nil || res.Tasks != 2 {
		t.Fatalf("first sync: %v %+v", err, res)
	}
	// A Devin session the list does not name and another tool's session.
	ev := func(sid, tool string) models.ToolEvent {
		return models.ToolEvent{
			SourceFile: "synthetic", SourceEventID: sid + "-e1", SessionID: sid, ProjectRoot: "/work/other",
			Timestamp: t0, Tool: tool, ActionType: models.ActionUserPrompt,
		}
	}
	if _, err := st.Ingest(ctx, []models.ToolEvent{ev("devin-local-1", models.ToolDevin), ev("cc-local-1", models.ToolClaudeCode)}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var before int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session IN ('s-col-1','s-col-2')`).Scan(&before)
	if before == 0 {
		t.Fatal("setup: the colleague's ACU rows did not land")
	}

	// The developer names their own user: the next pass removes the rest.
	av, err := svc.ChooseVendorUser(ctx, id, devinMe)
	if err != nil || !av.PurgePending {
		t.Fatalf("choose: %v %+v", err, av)
	}
	clk.set(t0.Add(20 * time.Minute))
	res, err := svc.SyncAccount(ctx, id)
	if err != nil || res.ErrorClass != "" {
		t.Fatalf("purge pass: %v %+v", err, res)
	}
	if res.PurgedOtherMember != 2 || res.Tasks != 1 || res.SkippedOtherMember != 2 {
		t.Fatalf("purge pass counts: %+v", res)
	}
	for _, q := range []struct {
		what string
		sql  string
		want int
	}{
		{"colleague sessions", `SELECT COUNT(*) FROM sessions WHERE id IN ('s-col-1','s-col-2')`, 0},
		{"colleague actions", `SELECT COUNT(*) FROM actions WHERE session_id IN ('s-col-1','s-col-2')`, 0},
		{"colleague acu rows", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session IN ('s-col-1','s-col-2')`, 0},
		{"colleague links", `SELECT COUNT(*) FROM cloud_session_links WHERE session_id IN ('s-col-1','s-col-2')`, 0},
		{"colleague checkpoints", `SELECT COUNT(*) FROM cloud_sync_checkpoints WHERE scope IN ('s-col-1','s-col-2')`, 0},
		{"my session", `SELECT COUNT(*) FROM sessions WHERE id = 's-me-1'`, 1},
		{"my acu row", `SELECT COUNT(*) FROM cloud_usage_ledger WHERE scope_session = 's-me-1'`, 1},
		{"an unlisted Devin session", `SELECT COUNT(*) FROM sessions WHERE id = 'devin-local-1'`, 1},
		{"another tool's session", `SELECT COUNT(*) FROM sessions WHERE id = 'cc-local-1'`, 1},
	} {
		var n int
		if err := database.QueryRowContext(ctx, q.sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != q.want {
			t.Errorf("%s: %d rows, want %d", q.what, n, q.want)
		}
	}
	v, _ := svc.Status(ctx)
	if v.Accounts[0].PurgePending {
		t.Fatal("the removal still reads owed after its pass")
	}
	// A later pass purges nothing more and lands nothing of theirs.
	clk.set(t0.Add(40 * time.Minute))
	if res, err := svc.SyncAccount(ctx, id); err != nil || res.PurgedOtherMember != 0 {
		t.Fatalf("later pass: %v %+v", err, res)
	}
	var n int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id IN ('s-col-1','s-col-2')`).Scan(&n)
	if n != 0 {
		t.Fatal("a later pass brought a colleague's session back")
	}
}

// TestDevinUserCandidates: the picker lists the users of one list page with
// their session counts and the username one message names (sanitized), one
// message read per user, on the connector's own host; a service user is
// counted, never offered. Choosing validates the id's grammar; an account of
// a connector that is not member scoped takes no user.
func TestDevinUserCandidates(t *testing.T) {
	org := &devinOrgAPI{
		list: devinList(
			devinItem{id: "s-me-1", user: devinMe, updated: t0},
			devinItem{id: "s-col-1", user: devinColleague, updated: t0.Add(-time.Minute)},
			devinItem{id: "s-col-2", user: devinColleague, updated: t0.Add(-2 * time.Minute)},
			devinItem{id: "s-svc-1", service: devinService, updated: t0.Add(-3 * time.Minute)},
		),
		users: map[string][2]string{
			"s-me-1": {devinMe, "me‮\u0007"}, "s-col-1": {devinColleague, "colleague"}, "s-col-2": {devinColleague, "colleague"},
		},
	}
	api := org.fake()
	clk := &clock{t: t0}
	svc, _, _, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	id := connectDevin(t, svc)
	api.reset()
	uc, err := svc.UserCandidates(ctx, id)
	if err != nil || uc.ErrorClass != "" {
		t.Fatalf("candidates: %v %+v", err, uc)
	}
	want := []cloudagents.VendorUserCandidate{
		{UserID: devinColleague, Username: "colleague", Sessions: 2},
		{UserID: devinMe, Username: "me??", Sessions: 1},
	}
	if fmt.Sprint(uc.Candidates) != fmt.Sprint(want) || uc.ServiceUserSessions != 1 || uc.MessageReads != 2 || uc.More {
		t.Fatalf("candidates = %+v", uc)
	}
	calls := api.reset()
	if len(calls) != 3 {
		t.Fatalf("calls = %v (one list page and one message page per user)", calls)
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "https://api.devin.ai/") {
			t.Errorf("call off the connector's host: %s", c)
		}
	}
	if !containsCall(calls, "/s-col-1/messages") || containsCall(calls, "/s-col-2/") {
		t.Errorf("not the newest session of each user: %v", calls)
	}
	for _, bad := range []string{"", "user_synth0001", devinService, "user-" + strings.Repeat("g", 32), devinMe + " "} {
		if _, err := svc.ChooseVendorUser(ctx, id, bad); err == nil {
			t.Errorf("choose accepted %q", bad)
		}
	}
	if len(api.reset()) != 0 {
		t.Error("choosing called the vendor")
	}
	// A Cursor account names no user.
	cur, _, _, _, _ := newAPIService(t, &fakeAPI{call: func(cloudagents.Request) ([]byte, error) {
		return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
	}}, clk)
	_, cav, err := cur.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || cav == nil {
		t.Fatalf("cursor connect: %+v %v", cav, err)
	}
	if cav.UserState != cloudagents.VendorUserNotApplicable {
		t.Fatalf("a Cursor account reads user state %q", cav.UserState)
	}
	if _, err := cur.ChooseVendorUser(ctx, cav.ID, devinMe); err == nil {
		t.Fatal("a Cursor account took a vendor user")
	}
	if _, err := cur.UserCandidates(ctx, cav.ID); err == nil {
		t.Fatal("a Cursor account listed vendor users")
	}
}
