package cloudagents

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/warp"
)

const (
	ownerMe   = "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ownerThem = "user-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// TestDecideOwnership walks ownershipRules, one case per row (and the
// shapes that must fall through a row to the next).
func TestDecideOwnership(t *testing.T) {
	cases := []struct {
		name string
		in   OwnershipInput
		want Ownership
	}{
		// Row 1: a service user and no person.
		{"service user", OwnershipInput{Chosen: ownerMe, ServiceUser: "service_user-1"}, OwnerSkipServiceUser},
		// Row 2: nobody named.
		{"no user", OwnershipInput{Chosen: ownerMe}, OwnerSkipNoUser},
		// Row 3: the chosen user, with or without a service user beside it.
		{"the chosen user", OwnershipInput{Chosen: ownerMe, User: ownerMe}, OwnerKeep},
		{"the chosen user, service user too", OwnershipInput{Chosen: ownerMe, User: ownerMe, ServiceUser: "service_user-1"}, OwnerKeep},
		// Row 4: anyone else.
		{"another member", OwnershipInput{Chosen: ownerMe, User: ownerThem}, OwnerSkipOtherMember},
		{"case differs", OwnershipInput{Chosen: ownerMe, User: strings.ToUpper(ownerMe)}, OwnerSkipOtherMember},
		{"nothing chosen keeps nothing", OwnershipInput{User: ownerMe}, OwnerSkipOtherMember},
	}
	for _, c := range cases {
		if got := DecideOwnership(c.in); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// memberScopedRows are the rows whose list holds other people's sessions
// (CLOUDAGENTS-6: Devin; CA-T8: OpenHands and Warp).
var memberScopedRows = map[string]bool{ConnectorDevin: true, ConnectorOpenHandsCloud: true, ConnectorWarpCloud: true}

// TestOwnershipIsMemberScopeOnly: a connector whose list is the key owner's
// keeps every task; a member-scoped one keeps only the chosen user's.
func TestOwnershipIsMemberScopeOnly(t *testing.T) {
	for _, c := range Connectors {
		if c.MemberScoped() != memberScopedRows[c.ID] {
			t.Errorf("%s: member scoped = %v", c.ID, c.MemberScoped())
		}
		if c.MemberScoped() {
			d := apiTable[c.ID]
			if c.Kind != SourceAPI || c.MemberUsers.Label == "" {
				t.Errorf("%s: a member-scoped row needs an API list and a user label", c.ID)
			}
			if d.userName != nil && d.listUserNames != nil {
				t.Errorf("%s: names its users from both the history and the list", c.ID)
			}
			if OwnershipOf(c, "", Task{User: ownerThem}) == OwnerKeep {
				t.Errorf("%s kept a task with no user chosen", c.ID)
			}
			continue
		}
		if OwnershipOf(c, "", Task{User: ownerThem}) != OwnerKeep {
			t.Errorf("%s dropped a task with no member scope", c.ID)
		}
	}
	devin := mustConn(t, ConnectorDevin)
	if OwnershipOf(devin, ownerMe, Task{User: ownerThem}) != OwnerSkipOtherMember || OwnershipOf(devin, ownerMe, Task{User: ownerMe}) != OwnerKeep {
		t.Fatal("devin ownership")
	}
	for id, want := range map[string]bool{
		ownerMe: true, "user-0123456789ABCDEF0123456789abcdef": true,
		"": false, "user_synth0001": false, "user-" + strings.Repeat("a", 31): false, "user-" + strings.Repeat("g", 32): false,
		ownerMe + "\n": false, "service_user-" + strings.Repeat("a", 32): false,
	} {
		if ValidVendorUser(devin, id) != want {
			t.Errorf("ValidVendorUser(%q) = %v", id, !want)
		}
	}
	if ValidVendorUser(mustConn(t, ConnectorCursorCloud), ownerMe) {
		t.Error("a connector that is not member scoped took a vendor user")
	}
	for _, c := range []struct {
		chosen string
		want   VendorUserState
	}{{"", VendorUserNotChosen}, {ownerMe, VendorUserChosen}} {
		if got := VendorUserStateOf(devin, c.chosen); got != c.want {
			t.Errorf("state(%q) = %q", c.chosen, got)
		}
	}
	if VendorUserStateOf(mustConn(t, ConnectorCursorCloud), "") != VendorUserNotApplicable {
		t.Error("cursor reads a user state")
	}
}

// TestDevinServiceUserIsNotTheUser: a session a service user started keeps
// its service user apart; it is never read as a person's (the old mapping
// folded service_user_id into User).
func TestDevinServiceUserIsNotTheUser(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	p, err := ParseAPIList(devin, map[string]string{ParamOrgID: "org_synth01"}, "", vendorFixture(t, "cognition/cognition.devin_v3.org_sessions/normal_page.json"))
	if err != nil || len(p.Tasks) != 2 {
		t.Fatalf("page: %v %+v", err, p)
	}
	svc := p.Tasks[1]
	if svc.ID != "devin-synth0002" || svc.User != "" || svc.ServiceUser != "service_user_synth01" {
		t.Fatalf("service user session = user %q service %q", svc.User, svc.ServiceUser)
	}
	if OwnershipOf(devin, ownerMe, svc) != OwnerSkipServiceUser {
		t.Fatal("a service user's session was not skipped as one")
	}
}

// TestPlanUserCandidates: one candidate per user id of the grammar, most
// sessions first, its newest session probed; service users and malformed
// ids are counted, never offered; probes are capped.
func TestPlanUserCandidates(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	tasks := []Task{
		{ID: "a1", User: ownerMe, UpdatedAt: t0},
		{ID: "b1", User: ownerThem, UpdatedAt: t0.Add(-time.Hour)},
		{ID: "b2", User: ownerThem, UpdatedAt: t0.Add(time.Hour)},
		{ID: "s1", ServiceUser: "service_user-1", UpdatedAt: t0},
		{ID: "n1", UpdatedAt: t0},
		{ID: "x1", User: "user_synth0001", UpdatedAt: t0},
	}
	plan := PlanUserCandidates(devin, tasks)
	if len(plan.Candidates) != 2 || plan.Candidates[0] != (VendorUserCandidate{UserID: ownerThem, Sessions: 2}) ||
		plan.Candidates[1] != (VendorUserCandidate{UserID: ownerMe, Sessions: 1}) {
		t.Fatalf("candidates = %+v", plan.Candidates)
	}
	if plan.ServiceUserSessions != 1 || plan.NoUserSessions != 2 {
		t.Fatalf("counts = %+v", plan)
	}
	if len(plan.Probes) != 2 || plan.Probes[0] != (UserProbe{UserID: ownerThem, SessionID: "b2"}) {
		t.Fatalf("probes = %+v", plan.Probes)
	}
	var many []Task
	for i := 0; i < MaxUserNameReads+5; i++ {
		many = append(many, Task{ID: fmt.Sprintf("m%d", i), User: fmt.Sprintf("user-%032x", i+1), UpdatedAt: t0})
	}
	if p := PlanUserCandidates(devin, many); len(p.Candidates) != MaxUserNameReads+5 || len(p.Probes) != MaxUserNameReads {
		t.Fatalf("cap: %d candidates, %d probes", len(p.Candidates), len(p.Probes))
	}
	if p := PlanUserCandidates(mustConn(t, ConnectorCursorCloud), tasks); len(p.Candidates) != 0 {
		t.Fatal("cursor offered vendor users")
	}
}

// TestParseUserName: the username of the probe's own user message, never
// another user's or Devin's; control and bidi characters become '?'; a page
// the history driver refuses is an error.
func TestParseUserName(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	params := map[string]string{ParamOrgID: "org-00112233445566778899aabbccddeeff"}
	page := `{"items":[` +
		`{"event_id":"event-1","source":"devin","message":"m","created_at":1793350805,"username":"devin","user_id":"` + ownerMe + `","origin":null},` +
		`{"event_id":"event-2","source":"user","message":"m","created_at":1793350806,"username":"them","user_id":"` + ownerThem + `","origin":"web"},` +
		`{"event_id":"event-3","source":"user","message":"m","created_at":1793350807,"username":"me‮\u0007x","user_id":"` + ownerMe + `","origin":"web"}` +
		`],"end_cursor":null,"has_next_page":false,"total":null}`
	got, err := ParseUserName(devin, params, UserProbe{UserID: ownerMe, SessionID: "abc"}, []byte(page))
	if err != nil || got != "me??x" {
		t.Fatalf("username = %q %v", got, err)
	}
	if got, _ := ParseUserName(devin, params, UserProbe{UserID: "user-" + strings.Repeat("c", 32), SessionID: "abc"}, []byte(page)); got != "" {
		t.Fatalf("a user with no message got name %q", got)
	}
	if _, err := ParseUserName(devin, params, UserProbe{UserID: ownerMe, SessionID: "abc"}, []byte(`{"nope":1}`)); err == nil {
		t.Fatal("an undocumented page was accepted")
	}
	req, err := UserNameRequest(devin, params, UserProbe{UserID: ownerMe, SessionID: "abc"})
	if err != nil || req.URL != "https://api.devin.ai/v3/organizations/org-00112233445566778899aabbccddeeff/sessions/abc/messages?first=200" || req.Op != OpHistory {
		t.Fatalf("request = %+v %v", req, err)
	}
	if long := cleanDisplayName(strings.Repeat("é", 200)); len(long) > maxDisplayName || !strings.HasPrefix(long, "é") {
		t.Fatalf("bounded name = %q", long)
	}
}

// TestWarpCreatorOwnership (CA-T8): a run a person created carries that
// person's uid as its User; a run the team's service account created (what
// an Agent key starts) carries it as ServiceUser and is never kept; a
// creator type with no row names no one and is never kept either.
func TestWarpCreatorOwnership(t *testing.T) {
	w := mustConn(t, ConnectorWarpCloud)
	p, err := ParseAPIList(w, nil, "", vendorFixture(t, "warp/warp.agent_api.runs_list/normal_page.json"))
	if err != nil || len(p.Tasks) != 3 {
		t.Fatalf("page: %v %+v", err, p)
	}
	const me = "synthUserUid0001"
	want := []struct {
		user, service string
		own           Ownership
	}{
		{me, "", OwnerKeep},
		{"", "synthServiceAcct0001", OwnerSkipServiceUser},
		{me, "", OwnerKeep},
	}
	for i, tk := range p.Tasks {
		if tk.User != want[i].user || tk.ServiceUser != want[i].service {
			t.Errorf("run %d: user %q service %q", i, tk.User, tk.ServiceUser)
		}
		if got := OwnershipOf(w, me, tk); got != want[i].own {
			t.Errorf("run %d: %s, want %s", i, got, want[i].own)
		}
		if got := OwnershipOf(w, "otherUserUid0002", tk); got == OwnerKeep {
			t.Errorf("run %d kept for another chosen user", i)
		}
	}
	for _, c := range []struct {
		kind          string
		user, service string
		own           Ownership
	}{
		{"user", me, "", OwnerKeep},
		{"USER", me, "", OwnerKeep},
		{"service_account", "", me, OwnerSkipServiceUser},
		{"integration", "", "", OwnerSkipNoUser},
		{"", "", "", OwnerSkipNoUser},
	} {
		body := map[string]string{
			"created_at": "2026-10-30T09:00:00Z", "updated_at": "2026-10-30T09:01:00Z", "state": "succeeded",
			"creator_uid": me, "harness": "oz",
		}
		if c.kind != "" {
			body["creator_type"] = c.kind
		}
		tk, ok := TaskFromSnapshot(ConnectorWarpCloud, vendorapi.VendorSnapshot{Class: warp.RunClass, Subject: "r1", Body: body}, nil)
		if !ok || tk.User != c.user || tk.ServiceUser != c.service || OwnershipOf(w, me, tk) != c.own {
			t.Errorf("creator type %q: %v user %q service %q", c.kind, ok, tk.User, tk.ServiceUser)
		}
	}
}

// TestOpenHandsCreatorOwnership (CA-T8): a conversation's created_by_user_id
// is its User; one naming no creator is never assumed to be the key
// owner's (skip_no_user).
func TestOpenHandsCreatorOwnership(t *testing.T) {
	oh := mustConn(t, ConnectorOpenHandsCloud)
	const me = "user-synth-0001"
	p, err := ParseAPIList(oh, nil, "", vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/normal_page.json"))
	if err != nil || len(p.Tasks) != 2 {
		t.Fatalf("page: %v %+v", err, p)
	}
	for _, tk := range p.Tasks {
		if tk.User != me || OwnershipOf(oh, me, tk) != OwnerKeep || OwnershipOf(oh, "user-synth-0002", tk) != OwnerSkipOtherMember {
			t.Errorf("conversation %s: user %q", tk.ID, tk.User)
		}
	}
	last, err := ParseAPIList(oh, nil, "", vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/last_page.json"))
	if err != nil || len(last.Tasks) != 1 || last.Tasks[0].User != "" || OwnershipOf(oh, me, last.Tasks[0]) != OwnerSkipNoUser {
		t.Fatalf("no creator: %v %+v", err, last.Tasks)
	}
}

// TestMemberUserGrammars: the OpenHands and Warp id grammars are the
// conservative id tokens the hand-back records (not grounded live).
func TestMemberUserGrammars(t *testing.T) {
	oh, w := mustConn(t, ConnectorOpenHandsCloud), mustConn(t, ConnectorWarpCloud)
	for _, c := range []struct {
		conn Connector
		id   string
		want bool
	}{
		{oh, "user-synth-0001", true},
		{oh, "0f8fad5b-d9cb-469f-a165-70867728950e", true},
		{oh, "a.b_c", true},
		{oh, "", false},
		{oh, "-lead", false},
		{oh, "has space", false},
		{oh, "a/b", false},
		{oh, "a:b", false},
		{oh, "me@example.com", false},
		{oh, "x\n", false},
		{oh, strings.Repeat("a", 129), false},
		{w, "synthUserUid0001", true},
		{w, "Zx9_k-Q", true},
		{w, strings.Repeat("a", 128), true},
		{w, "a.b", false},
		{w, "", false},
		{w, "_lead", false},
		{w, "uid with space", false},
		{w, "uid‮", false},
		{w, strings.Repeat("a", 129), false},
	} {
		if got := ValidVendorUser(c.conn, c.id); got != c.want {
			t.Errorf("%s ValidVendorUser(%q) = %v", c.conn.ID, c.id, got)
		}
	}
}

// TestPlanUserCandidatesNamesFromList: OpenHands (ids only) and Warp (names
// on the list itself) plan no message read; Devin still does.
func TestPlanUserCandidatesNamesFromList(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	for _, id := range []string{ConnectorOpenHandsCloud, ConnectorWarpCloud} {
		c := mustConn(t, id)
		plan := PlanUserCandidates(c, []Task{
			{ID: "a1", User: "uidA", UpdatedAt: t0},
			{ID: "a2", User: "uidA", UpdatedAt: t0},
			{ID: "b1", User: "uidB", UpdatedAt: t0},
			{ID: "s1", ServiceUser: "svc", UpdatedAt: t0},
			{ID: "x1", User: "bad id", UpdatedAt: t0},
		})
		if len(plan.Candidates) != 2 || plan.Candidates[0] != (VendorUserCandidate{UserID: "uidA", Sessions: 2}) ||
			plan.ServiceUserSessions != 1 || plan.NoUserSessions != 1 || len(plan.Probes) != 0 {
			t.Errorf("%s plan = %+v", id, plan)
		}
		if _, err := ParseUserName(c, nil, UserProbe{UserID: "uidA", SessionID: "a1"}, []byte(`{}`)); err == nil {
			t.Errorf("%s read a username from a history page", id)
		}
	}
	if p := PlanUserCandidates(mustConn(t, ConnectorDevin), []Task{{ID: "d1", User: ownerMe, UpdatedAt: t0}}); len(p.Probes) != 1 {
		t.Fatalf("devin probes = %+v", p.Probes)
	}
}

// TestParseListUserNames: Warp's list names its users: the first display
// name of each person creator, sanitized; a service account, an id outside
// the grammar and the e-mail never; a page the list driver refuses is an
// error. OpenHands and Devin read no names from the list.
func TestParseListUserNames(t *testing.T) {
	w := mustConn(t, ConnectorWarpCloud)
	names, err := ParseListUserNames(w, nil, "", vendorFixture(t, "warp/warp.agent_api.runs_list/normal_page.json"))
	if err != nil || len(names) != 1 || names["synthUserUid0001"] != "Synthetic User" {
		t.Fatalf("fixture names = %v %v", names, err)
	}
	run := func(id, kind, uid, name string) string {
		return `{"run_id":"` + id + `","state":"SUCCEEDED","execution_location":"REMOTE","created_at":"2026-10-30T09:00:00Z",` +
			`"updated_at":"2026-10-30T09:01:00Z","creator":{"type":"` + kind + `","uid":"` + uid + `","display_name":` + name +
			`,"email":"someone@example.com"}}`
	}
	page := `{"runs":[` + strings.Join([]string{
		run("r1", "user", "meUid0001", `"Me ‮\u0007x"`),
		run("r2", "user", "meUid0001", `"Second Name"`),
		run("r3", "service_account", "svcUid0001", `"Team Bot"`),
		run("r4", "user", "themUid0002", `null`),
		run("r5", "user", "otherUid03", `"   "`),
	}, ",") + `],"page_info":{"has_next_page":false}}`
	names, err = ParseListUserNames(w, nil, "", []byte(page))
	if err != nil || len(names) != 1 || names["meUid0001"] != "Me ??x" {
		t.Fatalf("names = %q %v", names, err)
	}
	for _, v := range names {
		if strings.Contains(v, "@") {
			t.Fatalf("an e-mail became a name: %q", v)
		}
	}
	if _, err := ParseListUserNames(w, nil, "", []byte(`{"nope":1}`)); err == nil {
		t.Fatal("an undocumented page was accepted")
	}
	for _, id := range []string{ConnectorOpenHandsCloud, ConnectorDevin, ConnectorCursorCloud} {
		if n, err := ParseListUserNames(mustConn(t, id), nil, "", []byte(`{}`)); n != nil || err != nil {
			t.Errorf("%s read list names: %v %v", id, n, err)
		}
	}
}
