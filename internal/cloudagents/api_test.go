package cloudagents

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// vendorFixture reads a lane CA-A4 driver fixture.
func vendorFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vendorapi", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

func TestAPIConnectorRows(t *testing.T) {
	for _, id := range []string{ConnectorCursorCloud, ConnectorDevin, ConnectorOpenHandsCloud} {
		c := mustConn(t, id)
		if c.Kind != SourceAPI || len(c.APIHosts) != 1 || c.Auth == "" || c.KeyLabel == "" {
			t.Errorf("%s: an API row names one exact host, an auth scheme and its key", id)
		}
		if c.Viewable || c.Command != "" {
			t.Errorf("%s: an API row has no CLI view or command", id)
		}
		if _, ok := apiTable[id]; !ok {
			t.Errorf("%s: no driver binding", id)
		}
		if strings.Contains(c.BaseURL(), "/") && !strings.HasPrefix(c.BaseURL(), "https://") {
			t.Errorf("%s: base URL %q is not https", id, c.BaseURL())
		}
	}
	for _, r := range APIOps() {
		host := strings.TrimPrefix(r.URL, "https://")
		host, _, _ = strings.Cut(host, "/")
		c := mustConn(t, r.Connector)
		// A row with a region table sends each account's requests to its
		// region's host; every other row has one host.
		inTable := host == c.APIHosts[0]
		for _, rg := range c.Regions {
			inTable = inTable || host == rg.Host
		}
		if !inTable {
			t.Errorf("%s %s: request goes to %q, not the row's host", r.Connector, r.Op, host)
		}
		if r.Auth != c.Auth || r.Accept == "" || r.Argv != nil {
			t.Errorf("%s %s: bad request %+v", r.Connector, r.Op, r)
		}
	}
	if len(APIOps()) < 9 {
		t.Errorf("APIOps lists %d shapes, want every operation of the three rows", len(APIOps()))
	}
}

func TestValidateParams(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	cur := mustConn(t, ConnectorCursorCloud)
	cases := []struct {
		name string
		c    Connector
		in   map[string]string
		ok   bool
	}{
		{"devin org id", devin, map[string]string{ParamOrgID: "org_synth01"}, true},
		{"devin needs the org", devin, nil, false},
		{"devin refuses a path", devin, map[string]string{ParamOrgID: "../x"}, false},
		{"cursor takes none", cur, nil, true},
		{"cursor refuses an extra", cur, map[string]string{ParamOrgID: "x"}, false},
		{"empty extras are ignored", cur, map[string]string{ParamOrgID: " "}, true},
	}
	for _, tc := range cases {
		_, err := ValidateParams(tc.c, tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.name, err)
		}
	}
	if got := AccountParams(devin, "org_synth01")[ParamOrgID]; got != "org_synth01" {
		t.Errorf("devin account params = %q", got)
	}
	if len(AccountParams(cur, KeychainKeyAccount)) != 0 {
		t.Error("cursor account params should be empty")
	}
}

func TestAPIRequestsAreDriverBuilt(t *testing.T) {
	cur := mustConn(t, ConnectorCursorCloud)
	devin := mustConn(t, ConnectorDevin)
	oh := mustConn(t, ConnectorOpenHandsCloud)
	since := ts("2026-10-30T09:00:00Z")
	until := ts("2026-10-31T10:00:00Z")
	cases := []struct {
		name string
		req  func() (Request, error)
		want string
	}{
		{"cursor me", func() (Request, error) { return APIIdentityRequest(cur, nil) }, "https://api.cursor.com/v1/me"},
		{"cursor list", func() (Request, error) { return APIListRequest(cur, nil, since, until, "") }, "https://api.cursor.com/v1/agents?limit=100"},
		{
			"cursor list page 2", func() (Request, error) { return APIListRequest(cur, nil, since, until, "bc-x+y/z=") },
			"https://api.cursor.com/v1/agents?cursor=bc-x%2By%2Fz%3D&limit=100",
		},
		{"cursor runs", func() (Request, error) { return APIDetailRequest(cur, DetailRuns, "bc-abc") }, "https://api.cursor.com/v1/agents/bc-abc/runs?limit=100"},
		{"cursor usage", func() (Request, error) { return APIDetailRequest(cur, DetailUsage, "bc-abc") }, "https://api.cursor.com/v1/agents/bc-abc/usage"},
		{"cursor stream", func() (Request, error) { return APIStreamRequest(cur, "bc-abc", "run-1", "7") }, "https://api.cursor.com/v1/agents/bc-abc/runs/run-1/stream"},
		{
			"devin probe", func() (Request, error) { return APIIdentityRequest(devin, map[string]string{ParamOrgID: "org_1"}) },
			"https://api.devin.ai/v3/organizations/org_1/sessions?first=200",
		},
		{"devin first pass lists everything", func() (Request, error) {
			return APIListRequest(devin, map[string]string{ParamOrgID: "org_1"}, time.Time{}, until, "")
		}, "https://api.devin.ai/v3/organizations/org_1/sessions?first=200"},
		{
			"devin window", func() (Request, error) {
				return APIListRequest(devin, map[string]string{ParamOrgID: "org_1"}, since, until, "c1")
			},
			"https://api.devin.ai/v3/organizations/org_1/sessions?after=c1&first=200&updated_after=1793350800&updated_before=1793440800",
		},
		{"devin messages", func() (Request, error) {
			return APIHistoryRequest(devin, map[string]string{ParamOrgID: "org_1"}, "devin-1", "c2", time.Time{}, until)
		}, "https://api.devin.ai/v3/organizations/org_1/sessions/devin-1/messages?after=c2&first=200"},
		{
			"openhands search window", func() (Request, error) { return APIListRequest(oh, nil, since, until, "") },
			"https://app.all-hands.dev/api/v1/app-conversations/search?include_sub_conversations=true&limit=100&updated_at__gte=2026-10-30T09%3A00%3A00Z&updated_at__lt=2026-10-31T10%3A00%3A00Z",
		},
		{
			"openhands events", func() (Request, error) { return APIHistoryRequest(oh, nil, "conv-1", "", since, until) },
			"https://app.all-hands.dev/api/v1/conversation/conv-1/events/search?limit=100&sort_order=TIMESTAMP&timestamp__gte=2026-10-30T09%3A00%3A00Z&timestamp__lt=2026-10-31T10%3A00%3A00Z",
		},
	}
	for _, tc := range cases {
		r, err := tc.req()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if r.URL != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, r.URL, tc.want)
		}
	}
	// Ids and resume positions are validated before they reach a URL.
	for name, f := range map[string]func() (Request, error){
		"agent id traversal": func() (Request, error) { return APIDetailRequest(cur, DetailRuns, "../v1/me") },
		"run id traversal":   func() (Request, error) { return APIStreamRequest(cur, "bc-abc", "../x", "") },
		"event id newline":   func() (Request, error) { return APIStreamRequest(cur, "bc-abc", "run-1", "1\r\nX: y") },
		"devin bad session": func() (Request, error) {
			return APIHistoryRequest(devin, map[string]string{ParamOrgID: "o"}, "a/b", "", time.Time{}, until)
		},
		"cursor has no history": func() (Request, error) {
			return APIHistoryRequest(cur, nil, "bc-abc", "", time.Time{}, until)
		},
		"devin has no detail": func() (Request, error) { return APIDetailRequest(devin, DetailRuns, "x") },
		"cli connector": func() (Request, error) {
			return APIListRequest(mustConn(t, ConnectorCodexCloud), nil, since, until, "")
		},
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseAPIIdentity(t *testing.T) {
	cur := mustConn(t, ConnectorCursorCloud)
	id, err := ParseAPIIdentity(cur, nil, vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"))
	if err != nil || id.AccountID != "user:42" || id.Display != "developer@example.com" {
		t.Fatalf("cursor identity = %+v, %v", id, err)
	}
	// A vendor e-mail that is not address-shaped (here a terminal escape)
	// is dropped from the display, never stored raw.
	if id, err := ParseAPIIdentity(cur, nil, []byte(`{"userId":42,"userEmail":"dev\u001b]0;pwned\u0007@corp.example"}`)); err != nil || id.AccountID != "user:42" || id.Display != "" {
		t.Errorf("escape-laden e-mail kept: %+v %v", id, err)
	}
	if _, err := ParseAPIIdentity(cur, nil, []byte(`{"apiKeyName":"x"}`)); ClassOf(err) != ErrWrongShape {
		t.Errorf("no user id: %v", err)
	}
	devin := mustConn(t, ConnectorDevin)
	params := map[string]string{ParamOrgID: "org_synth01"}
	id, err = ParseAPIIdentity(devin, params, vendorFixture(t, "cognition/cognition.devin_v3.org_sessions/normal_page.json"))
	if err != nil || id.AccountID != "org_synth01" {
		t.Fatalf("devin identity = %+v, %v", id, err)
	}
	oh := mustConn(t, ConnectorOpenHandsCloud)
	id, err = ParseAPIIdentity(oh, nil, vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/last_page.json"))
	if err != nil || id.AccountID != KeychainKeyAccount {
		t.Fatalf("openhands identity = %+v, %v", id, err)
	}
	if _, err := ParseAPIIdentity(oh, nil, vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/error_401.json")); ClassOf(err) != ErrWrongShape {
		t.Errorf("an error body is not an identity: %v", err)
	}
}

func TestParseCursorListAndDetail(t *testing.T) {
	cur := mustConn(t, ConnectorCursorCloud)
	p, err := ParseAPIList(cur, nil, "", vendorFixture(t, "cursor/cursor.cloudagent.agents/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 1 || p.Cursor != "bc-00000000-0000-0000-0000-000000000002" {
		t.Fatalf("page = %+v", p)
	}
	task := p.Tasks[0]
	if task.ID != "bc-00000000-0000-0000-0000-000000000001" || task.Lifecycle != LifecycleUnknown || !task.DetailPending ||
		!task.CreatedAt.Equal(ts("2026-04-13T18:30:00Z")) || !task.UpdatedAt.Equal(ts("2026-04-13T18:45:00Z")) {
		t.Fatalf("agent task = %+v", task)
	}
	task, err = ApplyAPIDetail(cur, DetailRuns, task, vendorFixture(t, "cursor/cursor.cloudagent.runs/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if task.RepoRemote != "github.com/your-org/your-repo" || task.Lifecycle != LifecycleRunning || len(task.Runs) != 1 ||
		task.Runs[0].ID != "run-00000000-0000-0000-0000-000000000002" || !task.UpdatedAt.Equal(ts("2026-04-13T18:51:00Z")) {
		t.Fatalf("after runs = %+v", task)
	}
	// The run's git.branches entry becomes a delivery link (lane CA-C5).
	if got := DeliveryLinks(task); len(got) != 1 || got[0] != (DeliveryLink{Remote: "github.com/your-org/your-repo", Branch: "cursor/add-readme-a1b2"}) {
		t.Fatalf("delivery links = %+v", got)
	}
	task, err = ApplyAPIDetail(cur, DetailUsage, task, vendorFixture(t, "cursor/cursor.cloudagent.usage/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := TokenFigure{Kind: TokenFromProviderRunTotal, Input: 12480, Output: 3110, CacheRead: 42600, CacheCreation: 18200, ReportedAt: task.UpdatedAt}
	if task.Tokens == nil || *task.Tokens != want {
		t.Fatalf("tokens = %+v", task.Tokens)
	}
	// Runs of another agent are drift, not silently filed.
	other := task
	other.ID = "bc-ffffffff-0000-0000-0000-000000000009"
	if _, err := ApplyAPIDetail(cur, DetailRuns, other, vendorFixture(t, "cursor/cursor.cloudagent.runs/normal_page.json")); ClassOf(err) != ErrWrongShape {
		t.Errorf("runs of another agent: %v", err)
	}
}

func TestParseDevinList(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	params := map[string]string{ParamOrgID: "org_synth01"}
	p, err := ParseAPIList(devin, params, "", vendorFixture(t, "cognition/cognition.devin_v3.org_sessions/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 2 || p.Cursor != "synthsession0002" {
		t.Fatalf("page = %+v", p)
	}
	a, b := p.Tasks[0], p.Tasks[1]
	if a.ID != "devin-synth0001" || a.Lifecycle != LifecycleRunning || a.RepoRemote != "github.com/acme/widget" ||
		a.User != "user_synth0001" || !a.UpdatedAt.Equal(time.Unix(1793353200, 0).UTC()) {
		t.Fatalf("first = %+v", a)
	}
	units := map[string]UsageFigure{}
	for _, u := range a.Usage {
		units[u.Unit] = u
	}
	if acu := units["acu"]; acu.Value != 3.75 || acu.MonetaryStatus != models.UsageMonetaryNone || acu.ValueType != models.UsageValueCumulative {
		t.Errorf("acu = %+v", acu)
	}
	if usd := units["usd"]; usd.Value != 0 || usd.MonetaryStatus != models.UsageMonetaryReported || usd.IncludesChildren == nil || *usd.IncludesChildren {
		t.Errorf("on-demand usd = %+v", usd)
	}
	if a.Tokens != nil {
		t.Error("Devin reports ACUs, never tokens")
	}
	// The session's pull_requests[0].pr_url becomes a stated-PR delivery
	// link (lane CA-C5).
	if a.PullRequestNumber != 42 || len(DeliveryLinks(a)) != 1 || DeliveryLinks(a)[0] != (DeliveryLink{Remote: "github.com/acme/widget", PRNumber: 42}) {
		t.Fatalf("pr = %d, links = %+v", a.PullRequestNumber, DeliveryLinks(a))
	}
	if b.Lifecycle != LifecycleSucceeded || b.ParentID != "devin-synth0001" || b.RepoRemote != "" || len(b.Usage) != 0 || b.CompletedAt.IsZero() {
		t.Fatalf("second = %+v (an absent ACU figure is no row, never zero)", b)
	}
	// ACUs reach the ledger in their own unit, never token_usage.
	led := MapLedger(devin, a, a.ID, "org_synth01")
	if len(led) != 2 || MapTokens(devin, a, a.ID, "/r") != nil {
		t.Fatalf("ledger = %+v", led)
	}
}

func TestParseOpenHandsList(t *testing.T) {
	oh := mustConn(t, ConnectorOpenHandsCloud)
	body := vendorFixture(t, "openhands/openhands.cloud.app_conversations_search/normal_page.json")
	if bytes.Contains(body, []byte("session_api_key")) == false {
		t.Fatal("fixture should carry the runtime key the parser must ignore")
	}
	p, err := ParseAPIList(oh, nil, "", body)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 2 || p.Cursor != "synthpage0002" {
		t.Fatalf("page = %+v", p)
	}
	a, b := p.Tasks[0], p.Tasks[1]
	if a.Lifecycle != LifecycleSucceeded || a.RepoRemote != "github.com/acme/widget" || a.User != "user-synth-0001" {
		t.Fatalf("first = %+v", a)
	}
	want := TokenFigure{
		Kind: TokenFromProviderRunTotal, Model: "litellm_proxy/claude-sonnet-4-5",
		Input: 182340 - 150200, Output: 6120, CacheRead: 150200, CacheCreation: 21400, ReportedAt: ts("2026-10-30T09:40:12Z"),
	}
	if a.Tokens == nil || *a.Tokens != want {
		t.Fatalf("tokens = %+v", a.Tokens)
	}
	if len(a.Usage) != 1 || a.Usage[0].Unit != "usd" || a.Usage[0].Value != 0.4215 || a.Usage[0].MonetaryStatus != models.UsageMonetaryReported {
		t.Fatalf("usd = %+v", a.Usage)
	}
	toks := MapTokens(oh, a, a.ID, "/repo")
	if len(toks) != 1 || toks[0].Source != models.TokenSourceSessionSummary || toks[0].Tool != ToolOpenHands {
		t.Fatalf("token events = %+v", toks)
	}
	if b.Lifecycle != LifecycleRunning || b.ParentID != a.ID || b.Tokens != nil || len(b.Usage) != 0 {
		t.Fatalf("child = %+v (metrics null is no figure)", b)
	}
	for _, s := range []string{a.ID, a.User, a.RepoRemote} {
		if strings.Contains(s, "placeholder") {
			t.Fatal("the runtime key leaked into a task")
		}
	}
}

func TestParseHistory(t *testing.T) {
	devin := mustConn(t, ConnectorDevin)
	params := map[string]string{ParamOrgID: "org_synth01"}
	hp, err := ParseAPIHistory(devin, params, "devin-synth0001", "", vendorFixture(t, "cognition/cognition.devin_v3.session_messages/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if hp.Next != "synthmessage0003" || len(hp.Activity) != 3 || hp.Activity[0].Kind != ActivityPrompt || hp.Activity[1].Kind != ActivityResponse {
		t.Fatalf("devin history = %+v", hp)
	}
	events := MapActivity(devin, "devin-synth0001", "/repo", hp.Activity)
	if len(events) != 3 || events[0].ActionType != models.ActionUserPrompt || events[1].ActionType != models.ActionAssistantMessage {
		t.Fatalf("devin events = %+v", events)
	}
	for _, e := range events {
		if e.Target != "" || e.RawToolInput != "" || e.ToolOutput != "" || e.PrecedingReasoning != "" {
			t.Fatalf("message text landed: %+v", e)
		}
	}

	oh := mustConn(t, ConnectorOpenHandsCloud)
	hp, err = ParseAPIHistory(oh, nil, "5b8f0c3e-0000-4000-8000-000000000001", "", vendorFixture(t, "openhands/openhands.cloud.events_search/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if hp.Next != "syntheventpage0002" || hp.Newest.IsZero() {
		t.Fatalf("openhands history = %+v", hp)
	}
	kinds := map[ActivityKind]int{}
	for _, a := range hp.Activity {
		kinds[a.Kind]++
		if a.Kind == ActivityToolCall && a.Tool != "terminal" {
			t.Errorf("tool = %q", a.Tool)
		}
	}
	if kinds[ActivityPrompt] != 1 || kinds[ActivityToolCall] != 1 {
		t.Fatalf("kinds = %v", kinds)
	}
	events = MapActivity(oh, "c", "/repo", hp.Activity)
	if len(events) != len(hp.Activity) {
		t.Fatalf("events = %+v", events)
	}
}

func TestHistoryCursorRoundTrip(t *testing.T) {
	h := HistoryCursor{After: "synthmessage0003", Since: ts("2026-10-30T09:12:11Z"), DetailPending: true}
	got := DecodeHistoryCursor(EncodeHistoryCursor(h))
	if got.After != h.After || !got.Since.Equal(h.Since) || !got.DetailPending {
		t.Fatalf("round trip = %+v", got)
	}
	if DecodeHistoryCursor("succeeded") != (HistoryCursor{}) {
		t.Error("a CLI lifecycle cursor decodes as the zero cursor")
	}
	if len(EncodeHistoryCursor(HistoryCursor{After: strings.Repeat("a", 500)})) > 512 {
		t.Error("cursor exceeds the store bound")
	}
}

func TestRemoteFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/acme/widget/pull/42":            "github.com/acme/widget",
		"github.com/your-org/your-repo":                     "github.com/your-org/your-repo",
		"https://GitHub.com/acme/widget.git":                "github.com/acme/widget",
		"https://gitlab.com/acme/widget/-/merge_requests/3": "github.com/acme/widget",
		"https://github.com/acme/widget/tree/main":          "",
		"https://user@github.com/acme/widget":               "",
		"widget":                                            "",
		"":                                                  "",
	}
	cases["https://gitlab.com/acme/widget/-/merge_requests/3"] = "gitlab.com/acme/widget"
	for in, want := range cases {
		if got := RemoteFromURL(in); got != want {
			t.Errorf("RemoteFromURL(%q) = %q, want %q", in, got, want)
		}
	}
	if remoteFromProvider("github", "acme/widget") != "github.com/acme/widget" || remoteFromProvider("azure", "a/b") != "" {
		t.Error("provider table")
	}
}

// readSSE feeds a recorded stream through the decoder and reducer.
func readSSE(t *testing.T, rel string, r *RunStream, d *SSEDecoder, at time.Time) {
	t.Helper()
	sc := bufio.NewScanner(bytes.NewReader(fixture(t, rel)))
	for sc.Scan() {
		if ev, ok := d.Line(sc.Text()); ok {
			if !r.Add(ev, at) {
				return
			}
		}
	}
	if ev, ok := d.Line(""); ok {
		r.Add(ev, at)
	}
}

func TestSSEDecoder(t *testing.T) {
	var d SSEDecoder
	var got []SSEEvent
	for _, l := range []string{": comment", "retry: 10", "id: 1", "event: status", "data: {\"a\":1}", "data: two", "", "", "data:x", "", "id: bad\x00", "data: y", ""} {
		if ev, ok := d.Line(l); ok {
			got = append(got, ev)
		}
	}
	if len(got) != 3 || got[0] != (SSEEvent{ID: "1", Event: "status", Data: "{\"a\":1}\ntwo"}) ||
		got[1] != (SSEEvent{ID: "1", Event: "message", Data: "x"}) || got[2].ID != "1" {
		t.Fatalf("events = %+v", got)
	}
}

func TestStreamPlanTable(t *testing.T) {
	run := Run{ID: "r", Lifecycle: LifecycleRunning}
	cases := []struct {
		name  string
		cp    StreamCursor
		found bool
		want  StreamAction
	}{
		{"never read", StreamCursor{}, false, StreamFromStart},
		{"done", StreamCursor{State: StreamDone, LastEventID: "9"}, true, StreamSkip},
		{"expired", StreamCursor{State: StreamExpired}, true, StreamSkip},
		{"open with position", StreamCursor{State: StreamOpen, LastEventID: "6"}, true, StreamResume},
		{"open without position", StreamCursor{State: StreamOpen}, true, StreamFromStart},
	}
	for _, tc := range cases {
		if got, rule := PlanStream(StreamPlanInput{Run: run, Cursor: tc.cp, Found: tc.found}); got != tc.want {
			t.Errorf("%s: %s (%s), want %s", tc.name, got, rule, tc.want)
		}
	}
	c := StreamCursor{LastEventID: "6", State: StreamOpen}
	if DecodeStreamCursor(EncodeStreamCursor(c)) != c || DecodeStreamCursor("junk") != (StreamCursor{}) {
		t.Error("stream cursor round trip")
	}
}
