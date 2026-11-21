package cloudagents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	"github.com/marmutapp/superbased-observer/internal/vendorapi/qoder"
)

func qoderFixture(t *testing.T, surface, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vendorapi", "qoder", surface, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var qoderGlobal = map[string]string{ParamRegion: "global"}

func qoderRow(t *testing.T) Connector {
	t.Helper()
	c, ok := ConnectorByID(ConnectorQoderCloud)
	if !ok {
		t.Fatal("no qoder-cloud row")
	}
	return c
}

// TestQoderStatusMapping is one mapping case per session status the SDK
// documents (sessions.search Literal running, idle, rescheduling,
// terminated), plus an undocumented one: lifecycle, end marker and its
// target, through the same list parse a pass uses.
func TestQoderStatusMapping(t *testing.T) {
	c := qoderRow(t)
	cases := []struct {
		status   string
		want     Lifecycle
		endEvent bool
	}{
		{"running", LifecycleRunning, false},
		{"rescheduling", LifecycleRunning, false},
		{"idle", LifecycleWaiting, false},
		{"terminated", LifecycleCancelled, true},
		{"something_new", LifecycleUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			body := `{"data":[{"id":"sess_s1","status":"` + tc.status + `","created_at":"2026-10-30T09:00:00Z",` +
				`"updated_at":"2026-10-30T09:30:00Z"}],"has_more":false,"next_page":null}`
			p, err := ParseAPIList(c, qoderGlobal, "", []byte(body))
			if err != nil || len(p.Tasks) != 1 {
				t.Fatalf("parse: %+v %v", p, err)
			}
			task := p.Tasks[0]
			if task.Lifecycle != tc.want || task.VendorStatus != tc.status {
				t.Fatalf("lifecycle %s (%s), want %s", task.Lifecycle, task.VendorStatus, tc.want)
			}
			ev := MapEvents(c, task, task.ID, "[qoder-cloud]")
			if got := len(ev) == 2; got != tc.endEvent {
				t.Fatalf("end marker %v, want %v (%d events)", got, tc.endEvent, len(ev))
			}
			if tc.endEvent {
				end := ev[1]
				if end.Target != string(LifecycleCancelled) || end.Success || end.RawToolName != "cloud_task:terminated" ||
					!end.Timestamp.Equal(time.Date(2026, 10, 30, 9, 30, 0, 0, time.UTC)) {
					t.Fatalf("end marker %+v", end)
				}
			}
			if ev[0].Tool != models.ToolQoder || ev[0].ActionType != models.ActionSessionStart {
				t.Fatalf("start marker %+v", ev[0])
			}
		})
	}
}

// TestQoderRegionSelection: the region is picked from the row's table,
// never free text, rides on the account id, and selects the one host every
// request of the account goes to.
func TestQoderRegionSelection(t *testing.T) {
	c := qoderRow(t)
	if len(c.Params) != 1 || c.Params[0].Name != ParamRegion || len(c.Params[0].Choices) != 2 {
		t.Fatalf("params %+v", c.Params)
	}
	for _, bad := range []map[string]string{
		{},
		{ParamRegion: ""},
		{ParamRegion: "eu"},
		{ParamRegion: "api.qoder.com.cn"},
		{ParamRegion: "https://evil.example"},
		{ParamRegion: "cn", ParamOrgID: "org-1"},
	} {
		if _, err := ValidateParams(c, bad); err == nil {
			t.Errorf("params %v accepted", bad)
		}
	}
	for region, host := range map[string]string{"global": "api.qoder.com", "cn": "api.qoder.com.cn"} {
		params, err := ValidateParams(c, map[string]string{ParamRegion: region})
		if err != nil {
			t.Fatal(err)
		}
		id, err := ParseAPIIdentity(c, params, qoderFixture(t, "qoder.ca.sessions", "last_page.json"))
		if err != nil || id.AccountID != KeychainKeyAccount+"@"+region {
			t.Fatalf("%s identity %+v %v", region, id, err)
		}
		acct := AccountParams(c, id.AccountID)
		if acct[ParamRegion] != region {
			t.Fatalf("account params %v", acct)
		}
		want := "https://" + host + "/api/v1/cloud/"
		reqs := []func() (Request, error){
			func() (Request, error) { return APIIdentityRequest(c, acct) },
			func() (Request, error) { return APIListRequest(c, acct, time.Time{}, time.Time{}, "page_2") },
			func() (Request, error) {
				return APIDetailRequestFor(c, acct, DetailEnvironment, Task{ID: "sess_1", EnvironmentID: "env_1"})
			},
			func() (Request, error) {
				return APIHistoryRequest(c, acct, "sess_1", "", time.Unix(1_790_000_000, 0), time.Unix(1_790_000_600, 0))
			},
		}
		for i, f := range reqs {
			r, err := f()
			if err != nil || !strings.HasPrefix(r.URL, want) || r.Auth != AuthBearer {
				t.Fatalf("%s request %d: %+v %v", region, i, r, err)
			}
		}
	}
	// An account whose stored region is gone or forged calls nothing.
	for _, acct := range []string{KeychainKeyAccount, KeychainKeyAccount + "@eu", "keychain-key@"} {
		if _, err := APIListRequest(c, AccountParams(c, acct), time.Time{}, time.Time{}, ""); err == nil {
			t.Errorf("account %q built a request", acct)
		}
	}
	// The history window is sent (created_at), the environment path is the
	// environment's, and every host is in the row's table.
	r, _ := APIHistoryRequest(c, qoderGlobal, "sess_1", "", time.Unix(1_790_000_000, 0), time.Unix(1_790_000_600, 0))
	if !strings.Contains(r.URL, "created_at%5Bgte%5D=") || !strings.Contains(r.URL, "/sessions/sess_1/events?") {
		t.Fatalf("history url %s", r.URL)
	}
	r, _ = APIDetailRequestFor(c, qoderGlobal, DetailEnvironment, Task{ID: "sess_1", EnvironmentID: "env_9"})
	if !strings.HasSuffix(r.URL, "/api/v1/cloud/environments/env_9") {
		t.Fatalf("environment url %s", r.URL)
	}
	if strings.Join(c.APIHosts, ",") != "api.qoder.com,api.qoder.com.cn" {
		t.Fatalf("hosts %v", c.APIHosts)
	}
}

// TestQoderSessionMapping: the fixture's sessions through the one snapshot
// mapping: repository, tokens at the provider-run-total tier, the surface
// host, and execution_location only from the environment table.
func TestQoderSessionMapping(t *testing.T) {
	c := qoderRow(t)
	p, err := ParseAPIList(c, qoderGlobal, "", qoderFixture(t, "qoder.ca.sessions", "normal_page.json"))
	if err != nil || len(p.Tasks) != 3 || p.Cursor != "page_synth0002" {
		t.Fatalf("list %+v %v", p, err)
	}
	s1 := p.Tasks[0]
	if s1.ID != "sess_synth0001" || s1.RepoRemote != "github.com/acme/widget" || s1.EnvironmentID != "env_synth01" ||
		!s1.DetailPending || !s1.ExecutionPending || s1.Lifecycle != LifecycleWaiting {
		t.Fatalf("task %+v", s1)
	}
	if ref := ResolveProject(c, s1, nil); ref.Remote != "github.com/acme/widget" || ref.Rule != "repository field" {
		t.Fatalf("project %+v", ref)
	}
	// A git_repository URL with user information was dropped by the
	// driver: no repository, so the placeholder.
	if ref := ResolveProject(c, p.Tasks[1], nil); ref.Placeholder != "[qoder-cloud]" {
		t.Fatalf("second project %+v", ref)
	}
	tok := MapTokens(c, s1, s1.ID, "/repo")
	if len(tok) != 1 || tok[0].Source != models.TokenSourceSessionSummary || tok[0].InputTokens != 41200 ||
		tok[0].OutputTokens != 6100 || tok[0].CacheReadTokens != 220400 || tok[0].CacheCreationTokens != 18000 ||
		tok[0].Model != "ultimate" || tok[0].Tool != models.ToolQoder {
		t.Fatalf("tokens %+v", tok)
	}
	if MapTokens(c, p.Tasks[1], "sess_synth0002", "/repo") != nil {
		t.Fatal("a session with null usage must land no token row (absent, not zero)")
	}
	// The session's total_credits is its one credit figure: cumulative,
	// provider run total, not money (CA-D11), revisable so a re-read with a
	// higher total supersedes the row instead of freezing the first one.
	if len(s1.Usage) != 1 {
		t.Fatalf("session usage figures %+v", s1.Usage)
	}
	if f := s1.Usage[0]; f.Unit != UnitQoderCredit || f.Value != 8 || f.ValueType != models.UsageValueCumulative ||
		f.Source != models.UsageSourceProviderRunTotal || f.MonetaryStatus != models.UsageMonetaryNone ||
		f.Revisable != RevisableQoderCredits {
		t.Fatalf("credit figure %+v", f)
	}
	led := MapLedger(c, s1, s1.ID, "acct")
	if len(led) != 1 || !led[0].Revisable || led[0].SourceRecordID != "sess_synth0001:qoder_credits_total:not_monetary" {
		t.Fatalf("ledger %+v", led)
	}
	// Numbered against the stored rows: the first read lands revision 1, an
	// unchanged total lands nothing, a higher total supersedes the live row.
	first := ResolveRevisions(led, nil)
	if len(first) != 1 || first[0].SourceRecordID != "sess_synth0001:qoder_credits_total:not_monetary#r1" || first[0].SupersedesID != 0 {
		t.Fatalf("first revision %+v", first)
	}
	prior := []PriorLedgerRow{{ID: 7, SourceRecordID: first[0].SourceRecordID, Value: 8}}
	if same := ResolveRevisions(led, prior); len(same) != 0 {
		t.Fatalf("an unchanged total landed %+v", same)
	}
	grown := s1
	grown.Usage = []UsageFigure{s1.Usage[0]}
	grown.Usage[0].Value = 8.5
	next := ResolveRevisions(MapLedger(c, grown, grown.ID, "acct"), prior)
	if len(next) != 1 || next[0].SupersedesID != 7 || next[0].Value != 8.5 ||
		next[0].SourceRecordID != "sess_synth0001:qoder_credits_total:not_monetary#r2" {
		t.Fatalf("grown total %+v", next)
	}
	// The live check of 2026-11-02 raised the connector to Live verified.
	if c.Grounding() != GroundingVerified {
		t.Fatalf("grounding %s", c.Grounding())
	}
	// The live-shaped session (credits only, no token members): one credit
	// figure, no token row, its github_repository resource still files it.
	s3 := p.Tasks[2]
	if MapTokens(c, s3, s3.ID, "/repo") != nil || len(s3.Usage) != 1 || s3.Usage[0].Value != 0.2 ||
		s3.RepoRemote != "github.com/synth-owner/synth-repo" || s3.Lifecycle != LifecycleCancelled {
		t.Fatalf("live-shaped session %+v", s3)
	}
	if sf := Surface(c, s1.ID); len(sf) != 1 || sf[0].SurfaceHost != SurfaceHostQoderCloud || sf[0].Surface != "" {
		t.Fatalf("surface %+v", sf)
	}

	// Execution: nothing stamped before the environment read; then the
	// environment table decides.
	if ex := Execution(s1.ID, s1); ex.ExecutionLocation != "" {
		t.Fatalf("location before the environment read: %q", ex.ExecutionLocation)
	}
	env := func(kind string) []byte {
		return []byte(`{"id":"env_synth01","config":{"type":"` + kind + `"}}`)
	}
	for kind, want := range map[string]string{
		"self_hosted": models.ExecutionCustomerWorker, "cloud": models.ExecutionVendorCloud, "brand_new": "",
	} {
		got, err := ApplyAPIDetail(c, DetailEnvironment, s1, env(kind))
		if err != nil {
			t.Fatal(err)
		}
		if ex := Execution(got.ID, got); ex.ExecutionLocation != want || got.ExecutionPending {
			t.Errorf("%s: location %q, want %q", kind, ex.ExecutionLocation, want)
		}
	}
	got, err := ApplyAPIDetail(c, DetailEnvironment, s1, qoderFixture(t, "qoder.ca.environment_retrieve", "normal_page.json"))
	if err != nil || Execution(got.ID, got).ExecutionLocation != models.ExecutionCustomerWorker {
		t.Fatalf("fixture environment: %+v %v", got, err)
	}
	// A different environment's answer changes nothing.
	other, _ := ApplyAPIDetail(c, DetailEnvironment, s1, []byte(`{"id":"env_other","config":{"type":"cloud"}}`))
	if !other.ExecutionPending {
		t.Fatal("another environment's answer resolved the location")
	}
	// A session that names no environment keeps the connector default.
	s4 := Task{ID: "sess_4", Lifecycle: LifecycleRunning}
	if Execution(s4.ID, s4).ExecutionLocation != models.ExecutionVendorCloud {
		t.Fatal("no environment: vendor_cloud")
	}
	// A 403/404 on the environment read is skipped, any other class is not.
	if !DetailSkippable(DetailEnvironment, NewError(ErrPermissionDenied, "")) ||
		DetailSkippable(DetailEnvironment, NewError(ErrNotSignedIn, "")) || DetailSkippable(DetailRuns, NewError(ErrPermissionDenied, "")) {
		t.Fatal("skippable table")
	}
	// The org projection maps the same snapshot the same way.
	if _, ok := TaskFromSnapshot(ConnectorQoderCloud, vendorapi.VendorSnapshot{
		Class: qoder.CloudSessionClass, Subject: "sess_x", Body: map[string]string{"status": "idle", "created_at": "2026-10-30T09:00:00Z"},
	}, nil); !ok {
		t.Fatal("TaskFromSnapshot refused a qoder session")
	}
}

// TestQoderHistory: messages and tool calls as metadata, results patching
// their calls, and no usage figure from events (their credits repeat the
// session's cumulative total).
func TestQoderHistory(t *testing.T) {
	c := qoderRow(t)
	hp, err := ParseAPIHistory(c, qoderGlobal, "sess_synth0001", "", qoderFixture(t, "qoder.ca.session_events", "normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if hp.Next != "evpage_synth0002" || hp.Records != 14 || len(hp.Activity) != 4 {
		t.Fatalf("page %+v", hp)
	}
	want := []struct {
		id      string
		kind    ActivityKind
		tool    string
		known   bool
		pending bool
	}{
		{"ev:evt_synth0001", ActivityPrompt, "", false, false},
		{"ev:evt_synth0002", ActivityToolCall, "Bash", true, false},
		{"ev:evt_synth0004", ActivityToolCall, "search_issues", false, true},
		{"ev:evt_synth0005", ActivityResponse, "", false, false},
	}
	for i, w := range want {
		a := hp.Activity[i]
		if a.ID != w.id || a.Kind != w.kind || a.Tool != w.tool || a.OutcomeKnown != w.known || a.Pending != w.pending || a.Failed {
			t.Errorf("activity %d %+v, want %+v", i, a, w)
		}
	}
	if !hp.Newest.Equal(time.Date(2026, 10, 30, 9, 5, 0, 0, time.UTC)) {
		t.Fatalf("newest %s", hp.Newest)
	}
	if len(hp.Usage) != 0 || hp.Tokens != nil {
		t.Fatalf("events reported usage %+v %+v", hp.Usage, hp.Tokens)
	}
	// The second page's result answers a call on the same page (failed),
	// and actions land under tool qoder through the taxonomy.
	hp2, err := ParseAPIHistory(c, qoderGlobal, "sess_synth0001", "evpage_synth0002", qoderFixture(t, "qoder.ca.session_events", "last_page.json"))
	if err != nil || hp2.Next != "" || len(hp2.Activity) != 1 || !hp2.Activity[0].Failed || !hp2.Activity[0].OutcomeKnown {
		t.Fatalf("second page %+v %v", hp2, err)
	}
	acts := MapActivity(c, "sess_synth0001", "/repo", append(hp.Activity, hp2.Activity...))
	if len(acts) != 5 || acts[1].Tool != models.ToolQoder || acts[1].RawToolName != "Bash" {
		t.Fatalf("actions %+v", acts)
	}
	// A result read on a later page than its call patches the call.
	late := []byte(`{"data":[{"id":"evt_r","type":"agent.mcp_tool_result","processed_at":"2026-10-30T09:20:00Z",` +
		`"mcp_tool_use_id":"evt_synth0004","is_error":true}],"has_more":false,"next_page":null}`)
	hp3, err := ParseAPIHistory(c, qoderGlobal, "sess_synth0001", "", late)
	if err != nil || len(hp3.Activity) != 1 {
		t.Fatalf("late result %+v %v", hp3, err)
	}
	up := MapOutcomes(c, "sess_synth0001", hp3.Activity)
	if len(up) != 1 || up[0].SourceEventID != "qoder-cloud:sess_synth0001:ev:evt_synth0004" || up[0].Success {
		t.Fatalf("outcome patch %+v", up)
	}
}
