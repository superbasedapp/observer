package cloudagents

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloudagents", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

func mustConn(t *testing.T, id string) Connector {
	t.Helper()
	c, ok := ConnectorByID(id)
	if !ok {
		t.Fatalf("connector %s missing", id)
	}
	return c
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestConnectorTableWellFormed(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range Connectors {
		if ids[c.ID] {
			t.Errorf("duplicate connector %s", c.ID)
		}
		ids[c.ID] = true
		if c.ID == "" || c.Provider == "" || (c.Tool == "") == (c.HarnessTools == nil) || c.Label == "" || c.Issuer == "" {
			t.Errorf("%s: id, provider, label, issuer and exactly one of tool or harness tools are required", c.ID)
		}
		if c.Kind == SourceCLI && c.Command == "" {
			t.Errorf("%s: a CLI connector names its command", c.ID)
		}
		if c.Kind == SourceAPI && len(c.APIHosts) == 0 {
			t.Errorf("%s: an API connector names its exact hosts", c.ID)
		}
		if c.PageLimit <= 0 || c.MaxPages <= 0 || c.Interval <= 0 || c.Overlap <= 0 {
			t.Errorf("%s: page limit, page budget, interval and overlap must be positive", c.ID)
		}
		for s, st := range c.Ceiling {
			if !KnownCoverageState(st) {
				t.Errorf("%s: ceiling of %s is %q, not a coverage state", c.ID, s, st)
			}
		}
		for st, l := range c.Statuses {
			if st != strings.ToLower(st) || l == "" || l == LifecycleUnknown {
				t.Errorf("%s: status row %q -> %q", c.ID, st, l)
			}
		}
	}
	for _, id := range []string{ConnectorCodexCloud, ConnectorCopilotAgent} {
		if !ids[id] {
			t.Errorf("first-wave connector %s missing", id)
		}
	}
}

func TestArgvFixed(t *testing.T) {
	codex := mustConn(t, ConnectorCodexCloud)
	gh := mustConn(t, ConnectorCopilotAgent)
	cases := []struct {
		name string
		got  func() (Request, error)
		want []string
		err  bool
	}{
		{
			"codex list", func() (Request, error) { return codex.ListRequest("") },
			[]string{"codex", "cloud", "list", "--json", "--limit", "20"},
			false,
		},
		{
			"codex list cursor", func() (Request, error) { return codex.ListRequest("eyJvZmZzZXQiOjJ9") },
			[]string{"codex", "cloud", "list", "--json", "--limit", "20", "--cursor", "eyJvZmZzZXQiOjJ9"},
			false,
		},
		{"codex cursor flag injection", func() (Request, error) { return codex.ListRequest("--config=x") }, nil, true},
		{"codex cursor with space", func() (Request, error) { return codex.ListRequest("a b") }, nil, true},
		{"codex identity", codex.IdentityRequest, []string{"codex", "cloud", "list", "--json", "--limit", "1"}, false},
		{"codex has no view", func() (Request, error) { return codex.ViewRequest("task_e_1") }, nil, true},
		{
			"gh list", func() (Request, error) { return gh.ListRequest("") },
			[]string{"gh", "agent-task", "list", "--json", copilotFields, "-L", "100"},
			false,
		},
		{"gh list has no cursor", func() (Request, error) { return gh.ListRequest("x") }, nil, true},
		{
			"gh view", func() (Request, error) { return gh.ViewRequest("8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f") },
			[]string{"gh", "agent-task", "view", "8f1c2d3e-4b5a-4c6d-9e7f-0a1b2c3d4e5f", "--json", copilotFields},
			false,
		},
		{"gh view flag injection", func() (Request, error) { return gh.ViewRequest("--web") }, nil, true},
		{"gh view path", func() (Request, error) { return gh.ViewRequest("../x") }, nil, true},
		{"gh identity", gh.IdentityRequest, []string{"gh", "api", "user"}, false},
	}
	for _, tc := range cases {
		r, err := tc.got()
		if tc.err {
			if ClassOf(err) != ErrInvalid {
				t.Errorf("%s: want ErrInvalid, got %v", tc.name, err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(r.Argv, tc.want) {
			t.Errorf("%s: argv %q err %v, want %q", tc.name, r.Argv, err, tc.want)
		}
	}
	for _, argv := range AllArgv() {
		ok := false
		for _, c := range Commands() {
			ok = ok || argv[0] == c
		}
		if !ok || strings.ContainsAny(argv[0], `/\`) {
			t.Errorf("argv[0] %q is not a bare declared command", argv[0])
		}
	}
	if got := Commands(); !reflect.DeepEqual(got, []string{"codex", "gh"}) {
		t.Errorf("Commands() = %v", got)
	}
}

func TestLifecycleTables(t *testing.T) {
	codex := mustConn(t, ConnectorCodexCloud)
	gh := mustConn(t, ConnectorCopilotAgent)
	cases := []struct {
		c      Connector
		status string
		want   Lifecycle
	}{
		{codex, "pending", LifecycleRunning},
		{codex, "READY", LifecycleSucceeded},
		{codex, "error", LifecycleFailed},
		{codex, "something-new", LifecycleUnknown},
		{gh, "queued", LifecycleRunning},
		{gh, "waiting_for_user", LifecycleWaiting},
		{gh, "completed", LifecycleSucceeded},
		{gh, "timed_out", LifecycleFailed},
		{gh, "cancelled", LifecycleCancelled},
		{gh, "", LifecycleUnknown},
	}
	for _, tc := range cases {
		if got := tc.c.LifecycleOf(tc.status); got != tc.want {
			t.Errorf("%s %q: got %s want %s", tc.c.ID, tc.status, got, tc.want)
		}
	}
	if LifecycleUnknown.Terminal() || LifecycleWaiting.Terminal() || !LifecycleCancelled.Terminal() {
		t.Error("terminal set wrong")
	}
}

func TestClassifyCLIFailure(t *testing.T) {
	cases := []struct {
		cmd    string
		exit   int
		stderr string
		want   ErrorClass
	}{
		{"codex", 1, "Not signed in. Please run 'codex login' to sign in with ChatGPT, then re-run 'codex cloud'.", ErrNotSignedIn},
		{"gh", 1, "This command requires an OAuth token. Re-authenticate with: gh auth login", ErrNotSignedIn},
		{"gh", 4, "", ErrNotSignedIn},
		{"gh", 1, "HTTP 403: forbidden (HTTP 403)", ErrPermissionDenied},
		{"gh", 1, "API rate limit exceeded", ErrRateLimited},
		{"gh", 1, `unknown command "agent-task" for "gh"`, ErrNotInstalled},
		{"codex", 1, "error sending request: dns error: could not resolve host", ErrUnreachable},
		{"codex", 2, "something odd", ErrFailed},
	}
	for _, tc := range cases {
		if got := ClassifyCLIFailure(tc.cmd, tc.exit, tc.stderr); got != tc.want {
			t.Errorf("%s %q: got %q want %q", tc.cmd, tc.stderr, got, tc.want)
		}
	}
}

func TestCoverage(t *testing.T) {
	cases := []struct {
		prev  CoverageState
		class ErrorClass
		want  CoverageState
	}{
		{"", ErrNone, CoverageVerified},
		{CoverageVerified, ErrNotSignedIn, CoverageDisconnected},
		{CoverageVerified, ErrRateLimited, CoverageVerified},
		{"", ErrUnreachable, CoverageNotEstablished},
		{CoverageVerified, ErrServerError, CoverageVerified},
		{CoveragePartialHistory, ErrServerError, CoveragePartialHistory},
		{"", ErrServerError, CoverageNotEstablished},
		{CoverageVerified, ErrNotInstalled, CoverageAvailable},
		{CoverageVerified, ErrPermissionDenied, CoveragePermissionRequired},
		{CoverageVerified, ErrWrongShape, CoveragePartialHistory},
		{CoverageDisconnected, ErrFailed, CoverageDisconnected},
	}
	for _, tc := range cases {
		if got := CoverageAfter(tc.prev, tc.class); got != tc.want {
			t.Errorf("CoverageAfter(%q,%q) = %q want %q", tc.prev, tc.class, got, tc.want)
		}
	}
	for _, s := range CoverageStates() {
		if s.Label() == "" {
			t.Errorf("%s has no label", s)
		}
	}
	gh := mustConn(t, ConnectorCopilotAgent)
	if got := gh.CoverageFor(SignalIdentity, CoverageVerified); got != CoverageVerified {
		t.Errorf("identity ceiling: %s", got)
	}
	if got := gh.CoverageFor(SignalIdentity, CoverageDisconnected); got != CoverageDisconnected {
		t.Errorf("identity on a disconnected account: %s", got)
	}
	if got := gh.CoverageFor(SignalTokens, CoverageVerified); got != CoverageNotEstablished {
		t.Errorf("tokens must stay not established: %s", got)
	}
	if got := gh.CoverageFor(SignalDiscovery, CoveragePartialHistory); got != CoveragePartialHistory {
		t.Errorf("discovery follows the account: %s", got)
	}
}

func TestParseCodexFixtures(t *testing.T) {
	p1, err := ParseCodexList(fixture(t, "codex-cloud/list-page1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Tasks) != 2 || p1.Cursor != "eyJvZmZzZXQiOjJ9" {
		t.Fatalf("page1: %d tasks cursor %q", len(p1.Tasks), p1.Cursor)
	}
	a := p1.Tasks[0]
	if a.ID != "task_e_6720aa01b2c3d4e5f6a7b8c9d0e1f2a3" || a.Lifecycle != LifecycleRunning ||
		!a.UpdatedAt.Equal(ts("2026-10-31T09:40:00Z")) || a.EnvironmentLabel != "acme-dev/observer-demo" ||
		a.Attempts != 1 || !a.CompletedAt.IsZero() {
		t.Errorf("task a: %+v", a)
	}
	b := p1.Tasks[1]
	if b.Lifecycle != LifecycleSucceeded || !b.CompletedAt.Equal(b.UpdatedAt) || b.Attempts != 4 {
		t.Errorf("task b: %+v", b)
	}
	p2, err := ParseCodexList(fixture(t, "codex-cloud/list-page2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Tasks) != 1 || p2.Cursor != "" || p2.Tasks[0].Lifecycle != LifecycleFailed || p2.Tasks[0].Attempts != 0 {
		t.Fatalf("page2: %+v", p2)
	}
	for _, bad := range []string{`[]`, `{"cursor":"x"}`, `not json`, `{"tasks":[],"cursor":"-bad"}`} {
		if _, err := ParseCodexList([]byte(bad)); ClassOf(err) != ErrWrongShape {
			t.Errorf("%q: want wrong_shape, got %v", bad, err)
		}
	}
	// Empty list and an unknown status are honest, not errors.
	p, err := ParseCodexList([]byte(`{"tasks":[{"id":"task_x","status":"brand-new","updated_at":1793440800}]}`))
	if err != nil || len(p.Tasks) != 1 || p.Tasks[0].Lifecycle != LifecycleUnknown || p.Tasks[0].UpdatedAt.IsZero() {
		t.Errorf("tolerant decode: %+v %v", p, err)
	}
	// An id that could act as a flag or path is dropped, never kept.
	p, _ = ParseCodexList([]byte(`{"tasks":[{"id":"--evil","status":"ready"},{"id":"../x","status":"ready"}]}`))
	if len(p.Tasks) != 0 {
		t.Errorf("unsafe ids kept: %+v", p.Tasks)
	}
	// Content fields never reach the task.
	if strings.Contains(strings.ToLower(strings.Join([]string{a.VendorStatus, a.EnvironmentID, a.User}, " ")), "flaky") {
		t.Error("title leaked")
	}
}

func TestParseCopilotFixtures(t *testing.T) {
	p, err := ParseCopilotList(fixture(t, "copilot-agent/list.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 3 || p.Cursor != "" {
		t.Fatalf("list: %+v", p)
	}
	live := p.Tasks[0]
	if live.Lifecycle != LifecycleRunning || live.RepoRemote != "github.com/acme-dev/observer-demo" ||
		live.User != "octo-dev" || live.PullRequestNumber != 412 || !live.CreatedAt.Equal(ts("2026-10-31T09:02:11Z")) ||
		!live.CompletedAt.IsZero() {
		t.Errorf("live: %+v", live)
	}
	timedOut := p.Tasks[2]
	if timedOut.Lifecycle != LifecycleFailed || timedOut.RepoRemote != "" || timedOut.User != "" || timedOut.PullRequestNumber != 0 {
		t.Errorf("timed out: %+v", timedOut)
	}
	v, err := ParseCopilotView(fixture(t, "copilot-agent/view.json"))
	if err != nil || v.ID != live.ID || v.Lifecycle != LifecycleSucceeded || !v.CompletedAt.Equal(ts("2026-10-31T10:12:30Z")) {
		t.Errorf("view: %+v %v", v, err)
	}
	if p, err := ParseCopilotList([]byte(`[]`)); err != nil || len(p.Tasks) != 0 {
		t.Errorf("empty list: %+v %v", p, err)
	}
	if _, err := ParseCopilotList([]byte(`{"x":1}`)); ClassOf(err) != ErrWrongShape {
		t.Errorf("object for list: %v", err)
	}
	id, err := ParseGHUser(fixture(t, "copilot-agent/user.json"))
	if err != nil || id.AccountID != "5551234" || id.Display != "octo-dev" {
		t.Errorf("user: %+v %v", id, err)
	}
	if _, err := ParseGHUser([]byte(`{"login":"x"}`)); ClassOf(err) != ErrWrongShape {
		t.Errorf("user without id: %v", err)
	}
	if id, err := ParseIdentity(ConnectorCodexCloud, fixture(t, "codex-cloud/list-page2.json")); err != nil || id.AccountID != LocalLoginAccount {
		t.Errorf("codex identity: %+v %v", id, err)
	}
	// A repository that is not a plain slug is not trusted as a remote.
	p, _ = ParseCopilotList([]byte(`[{"id":"a1","state":"completed","repository":"../../etc","updatedAt":"2026-10-30T00:00:00Z"}]`))
	if len(p.Tasks) != 1 || p.Tasks[0].RepoRemote != "" {
		t.Errorf("bad repository kept: %+v", p.Tasks)
	}
}

func TestResolveProjectRules(t *testing.T) {
	codex := mustConn(t, ConnectorCodexCloud)
	gh := mustConn(t, ConnectorCopilotAgent)
	known := func(remotes ...string) KnownRemote {
		return func(r string) bool {
			for _, k := range remotes {
				if k == r {
					return true
				}
			}
			return false
		}
	}
	demo := known("github.com/acme-dev/observer-demo")
	bucket := func(c string) ProjectRef {
		return ProjectRef{Placeholder: "[" + c + "]", Note: NoteRepositoryNotReported, Rule: "placeholder"}
	}
	cases := []struct {
		name  string
		c     Connector
		t     Task
		known KnownRemote
		want  ProjectRef
	}{
		{"repository field", gh, Task{RepoRemote: "github.com/a/b"}, nil, ProjectRef{Remote: "github.com/a/b", Rule: "repository field"}},
		{"repository field wins over a label", codex, Task{RepoRemote: "github.com/a/b", EnvironmentLabel: "acme-dev/observer-demo"}, demo, ProjectRef{Remote: "github.com/a/b", Rule: "repository field"}},
		{"gh without repository", gh, Task{EnvironmentLabel: "acme-dev/observer-demo"}, demo, bucket("copilot-agent")},
		{
			"codex env label matches a known project", codex,
			Task{EnvironmentLabel: "acme-dev/observer-demo"},
			demo,
			ProjectRef{Remote: "github.com/acme-dev/observer-demo", Inferred: true, Rule: "environment label matches a known project remote"},
		},
		// CA-D16: a slug naming no known project is never a new project.
		{"codex env label slug, unknown remote", codex, Task{EnvironmentLabel: "acme-dev/other"}, demo, bucket("codex-cloud")},
		{"codex env label slug, no lookup", codex, Task{EnvironmentLabel: "acme-dev/observer-demo"}, nil, bucket("codex-cloud")},
		{"codex env label prose", codex, Task{EnvironmentLabel: "Scratch environment"}, demo, bucket("codex-cloud")},
		{"codex env label path", codex, Task{EnvironmentLabel: "../etc"}, known("github.com/../etc"), bucket("codex-cloud")},
	}
	for _, tc := range cases {
		if got := ResolveProject(tc.c, tc.t, tc.known); got != tc.want {
			t.Errorf("%s: %+v want %+v", tc.name, got, tc.want)
		}
	}
}

func TestPrecedence(t *testing.T) {
	got, ok := PreferredTokenSource([]TokenSourceKind{TokenFromOrgDailyReport, TokenFromProviderRunTotal, TokenFromOTelProvisional})
	if !ok || got != TokenFromProviderRunTotal {
		t.Errorf("preferred: %s", got)
	}
	got, _ = PreferredTokenSource([]TokenSourceKind{TokenFromProviderRunTotal, TokenFromSandboxTranscript})
	if got != TokenFromSandboxTranscript {
		t.Errorf("sandbox transcript must win: %s", got)
	}
	if _, ok := PreferredTokenSource(nil); ok {
		t.Error("nothing present must report not found")
	}
	if _, ok := PreferredTokenSource([]TokenSourceKind{"made_up"}); ok {
		t.Error("an unknown source never wins")
	}
	if !TokenSupersedes(TokenFromProviderRunTotal, TokenFromOTelProvisional) || TokenSupersedes(TokenFromOTelProvisional, TokenFromProviderRunTotal) {
		t.Error("supersedes order wrong")
	}
	want := []TokenSourceKind{TokenFromSandboxTranscript, TokenFromProviderRunTotal, TokenFromOTelProvisional, TokenFromOrgDailyReport}
	if !reflect.DeepEqual(TokenPrecedence(), want) {
		t.Errorf("order: %v", TokenPrecedence())
	}

	refs := map[string]string{"cse_123": "session-from-rail-s"}
	byRef := func(r string) (string, bool) { id, ok := refs[r]; return id, ok }
	cases := []struct {
		task  Task
		id    string
		match SessionMatch
	}{
		{Task{ID: "native", VendorRef: "cse_123"}, "session-from-rail-s", MatchVendorRef},
		{Task{ID: "native", VendorRef: "cse_999"}, "native", MatchNativeID},
		{Task{ID: "native"}, "native", MatchNativeID},
		{Task{}, "", ""},
	}
	for _, tc := range cases {
		id, m := ResolveSessionID(tc.task, byRef)
		if id != tc.id || m != tc.match {
			t.Errorf("%+v: %s/%s want %s/%s", tc.task, id, m, tc.id, tc.match)
		}
	}
}

func TestMapEvents(t *testing.T) {
	gh := mustConn(t, ConnectorCopilotAgent)
	p, _ := ParseCopilotList(fixture(t, "copilot-agent/list.json"))
	live, done := p.Tasks[0], p.Tasks[1]
	ev := MapEvents(gh, live, live.ID, "/repo")
	if len(ev) != 1 || ev[0].ActionType != models.ActionSessionStart || ev[0].Tool != models.ToolCopilot ||
		ev[0].SourceFile != "cloud-agents/copilot-agent" || !ev[0].Timestamp.Equal(live.CreatedAt) ||
		ev[0].SourceEventID != "copilot-agent:"+live.ID+":start" {
		t.Errorf("live: %+v", ev)
	}
	ev = MapEvents(gh, done, done.ID, "/repo")
	if len(ev) != 2 || ev[1].ActionType != models.ActionSessionEnd || !ev[1].Success || ev[1].Target != "succeeded" ||
		!ev[1].Timestamp.Equal(done.CompletedAt) {
		t.Errorf("done: %+v", ev)
	}
	failed := p.Tasks[2]
	ev = MapEvents(gh, failed, failed.ID, "[copilot-agent]")
	if len(ev) != 2 || ev[1].Success || ev[1].Target != "failed" || ev[1].RawToolName != "cloud_task:timed_out" {
		t.Errorf("failed: %+v", ev)
	}
	// Re-mapping is byte-stable (ingest dedups on SourceFile+SourceEventID).
	if !reflect.DeepEqual(ev, MapEvents(gh, failed, failed.ID, "[copilot-agent]")) {
		t.Error("mapping is not deterministic")
	}
	// No time, no session, no root: nothing is fabricated.
	if got := MapEvents(gh, Task{ID: "x"}, "x", "/r"); got != nil {
		t.Errorf("timeless task produced %v", got)
	}
	for _, e := range MapEvents(gh, done, done.ID, "/repo") {
		if strings.Contains(e.Target+e.RawToolName+e.RawToolInput, "Document") {
			t.Error("task title leaked into an action")
		}
	}
	ex := Execution(done.ID, done)
	if ex.ExecutionLocation != models.ExecutionVendorCloud || ex.SessionID != done.ID {
		t.Errorf("execution: %+v", ex)
	}
}

func TestMapTokensAndLedger(t *testing.T) {
	c := mustConn(t, ConnectorCodexCloud)
	at := ts("2026-10-31T10:00:00Z")
	task := Task{ID: "t1", UpdatedAt: at}
	if MapTokens(c, task, "t1", "/r") != nil || MapLedger(c, task, "t1", "acct") != nil {
		t.Fatal("absent figures must map to nothing, never zero rows")
	}
	task.Tokens = &TokenFigure{Kind: TokenFromProviderRunTotal, Input: 100, Output: 20}
	tok := MapTokens(c, task, "t1", "/r")
	if len(tok) != 1 || tok[0].Source != models.TokenSourceSessionSummary || tok[0].InputTokens != 100 || !tok[0].Timestamp.Equal(at) {
		t.Errorf("tokens: %+v", tok)
	}
	yes := true
	task.Usage = []UsageFigure{
		{
			Unit: "acu", Value: 2.5, ValueType: models.UsageValueInterval, Source: models.UsageSourceProviderRunTotal,
			MonetaryStatus: models.UsageMonetaryNone, IncludesChildren: &yes,
		},
		{Unit: "credit", Value: 1, ValueType: "bogus", Source: models.UsageSourceProviderRunTotal, MonetaryStatus: models.UsageMonetaryNone},
	}
	l := MapLedger(c, task, "t1", "acct")
	if len(l) != 1 || l[0].Unit != "acu" || l[0].ScopeSession != "t1" || l[0].ScopeAccount != "acct" || l[0].SourceRecordID == "" {
		t.Errorf("ledger: %+v", l)
	}
}

func TestDiscoveryOverlapAndGaps(t *testing.T) {
	codex := mustConn(t, ConnectorCodexCloud)
	p1, _ := ParseCodexList(fixture(t, "codex-cloud/list-page1.json"))
	p2, _ := ParseCodexList(fixture(t, "codex-cloud/list-page2.json"))
	now := ts("2026-10-31T10:00:00Z")

	// First pass: no checkpoint, reads both pages, no gap.
	d := NewDiscovery(codex, Since(Checkpoint{}))
	if !d.Add(p1) {
		t.Fatal("first page with a cursor must continue")
	}
	if d.Add(p2) {
		t.Fatal("last page without a cursor must stop")
	}
	cp, partial := d.Next(Checkpoint{}, now)
	if partial || len(d.Tasks()) != 3 || !cp.HighWater.Equal(ts("2026-10-31T09:40:00Z")) || len(cp.Gaps) != 0 || cp.Overlap != codex.Overlap {
		t.Fatalf("first pass: %+v partial=%v tasks=%d", cp, partial, len(d.Tasks()))
	}
	// Round-trip through the cursor text.
	if !DecodeHighWater(EncodeHighWater(cp.HighWater)).Equal(cp.HighWater) || !DecodeHighWater("junk").IsZero() {
		t.Error("high-water encoding")
	}

	// Second pass: the overlap window re-reads task a (09:40 >= 09:25) and
	// stops at task b (08:15 < 09:25), so the second page is not read.
	d = NewDiscovery(codex, Since(cp))
	if d.Add(p1) {
		t.Fatal("reaching the window start must stop paging")
	}
	if len(d.Tasks()) != 1 || d.Tasks()[0].ID != p1.Tasks[0].ID {
		t.Fatalf("overlap kept %+v", d.Tasks())
	}
	cp2, partial := d.Next(cp, now.Add(time.Hour))
	if partial || !cp2.HighWater.Equal(cp.HighWater) || len(cp2.Gaps) != 0 {
		t.Fatalf("second pass: %+v partial=%v", cp2, partial)
	}

	// A pass that runs out of page budget before reaching the window
	// records the uncovered interval as a gap.
	tight := codex
	tight.MaxPages = 1
	old := Checkpoint{HighWater: ts("2026-10-29T00:00:00Z"), Overlap: codex.Overlap}
	d = NewDiscovery(tight, Since(old))
	if d.Add(p1) {
		t.Fatal("page budget exhausted must stop")
	}
	cp3, partial := d.Next(old, now)
	if !partial || !d.Truncated() || len(cp3.Gaps) != 1 ||
		!cp3.Gaps[0].From.Equal(old.HighWater) || !cp3.Gaps[0].To.Equal(ts("2026-10-31T08:15:30Z")) {
		t.Fatalf("gap pass: %+v partial=%v", cp3, partial)
	}

	// An unpaged list that comes back full is truncated too.
	gh := mustConn(t, ConnectorCopilotAgent)
	gh.PageLimit = 3
	pl, _ := ParseCopilotList(fixture(t, "copilot-agent/list.json"))
	d = NewDiscovery(gh, Since(Checkpoint{HighWater: ts("2026-10-01T00:00:00Z"), Overlap: time.Minute}))
	d.Add(pl)
	if _, partial := d.Next(Checkpoint{HighWater: ts("2026-10-01T00:00:00Z")}, now); !partial {
		t.Error("a full unpaged list must report partial history")
	}
	// Duplicates across pages are kept once.
	d = NewDiscovery(codex, time.Time{})
	d.Add(p1)
	d.Add(Page{Tasks: p1.Tasks})
	if len(d.Tasks()) != 2 {
		t.Errorf("dedup: %d", len(d.Tasks()))
	}
}

func TestRefreshCandidates(t *testing.T) {
	gh := mustConn(t, ConnectorCopilotAgent)
	gh.MaxViews = 2
	got := RefreshCandidates(gh, []string{"c", "a", "b", "--x", "d"}, map[string]bool{"b": true})
	if !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Errorf("candidates: %v", got)
	}
	if RefreshCandidates(mustConn(t, ConnectorCodexCloud), []string{"a"}, nil) != nil {
		t.Error("a connector without view has no candidates")
	}
}

func TestClassOf(t *testing.T) {
	if ClassOf(nil) != ErrNone || ClassOf(errors.New("x")) != ErrFailed {
		t.Error("ClassOf basics")
	}
	wrapped := errors.Join(errors.New("ctx"), NewError(ErrRateLimited, "slow down"))
	if ClassOf(wrapped) != ErrRateLimited {
		t.Errorf("wrapped: %s", ClassOf(wrapped))
	}
	for _, c := range []ErrorClass{ErrNotInstalled, ErrServerError, ErrFailed} {
		if !KnownErrorClass(c) {
			t.Errorf("%s unknown", c)
		}
	}
}

func TestChooseProjectRoot(t *testing.T) {
	cases := []struct{ existing, resolved, want string }{
		{"", "cloud:github.com/a/b", "cloud:github.com/a/b"},
		{"", "[codex-cloud]", "[codex-cloud]"},
		{"/home/u/src/b", "cloud:github.com/a/b", "/home/u/src/b"},
		{"cloud:github.com/a/b", "/home/u/src/b", "cloud:github.com/a/b"},
		{"[copilot-agent]", "cloud:github.com/a/b", "cloud:github.com/a/b"},
		{"[copilot-agent]", "[copilot-agent]", "[copilot-agent]"},
	}
	for _, tc := range cases {
		if got := ChooseProjectRoot(tc.existing, tc.resolved); got != tc.want {
			t.Errorf("ChooseProjectRoot(%q,%q) = %q want %q", tc.existing, tc.resolved, got, tc.want)
		}
	}
	if !IsPlaceholderRoot("[cursor]") || IsPlaceholderRoot("[]") || IsPlaceholderRoot("/x") {
		t.Error("IsPlaceholderRoot")
	}
}

// TestSurfaceStamp pins CA-D15: the copilot-agent row stamps the host
// "copilot-coding-agent" under tool copilot with no surface kind; a row with
// no host stamps nothing.
func TestSurfaceStamp(t *testing.T) {
	gh, _ := ConnectorByID(ConnectorCopilotAgent)
	cx, _ := ConnectorByID(ConnectorCodexCloud)
	cases := []struct {
		name string
		c    Connector
		sid  string
		want []models.SessionSurface
	}{
		{"copilot coding agent", gh, "s1", []models.SessionSurface{{SessionID: "s1", SurfaceHost: SurfaceHostCopilotCodingAgent}}},
		{"no session id", gh, "", nil},
		{"connector without a host", cx, "s1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Surface(tc.c, tc.sid)
			if len(got) != len(tc.want) || (len(got) == 1 && got[0] != tc.want[0]) {
				t.Fatalf("Surface = %+v, want %+v", got, tc.want)
			}
		})
	}
	if gh.Tool != models.ToolCopilot {
		t.Fatalf("copilot-agent tool = %q, want %q (CA-D15 keeps the tool id)", gh.Tool, models.ToolCopilot)
	}
}

// TestDiscoveryHighWaterIgnoresFutureTimestamps pins the clamp: a vendor
// task stamped far in the future is kept by the pass but cannot lift the
// high-water mark past now plus MaxFutureSkew, and a checkpoint already
// poisoned by one is discarded with the pass reported partial.
func TestDiscoveryHighWaterIgnoresFutureTimestamps(t *testing.T) {
	codex := mustConn(t, ConnectorCodexCloud)
	now := ts("2026-10-31T10:00:00Z")
	page := Page{Tasks: []Task{
		{ID: "task_e_future", UpdatedAt: ts("2099-01-01T00:00:00Z")},
		{ID: "task_e_skewok", UpdatedAt: now.Add(2 * time.Minute)},
		{ID: "task_e_real", UpdatedAt: ts("2026-10-31T09:00:00Z")},
	}}
	d := NewDiscovery(codex, Since(Checkpoint{}))
	d.Add(page)
	if len(d.Tasks()) != 3 {
		t.Fatalf("every listed task is kept for ingest: %d", len(d.Tasks()))
	}
	cp, partial := d.Next(Checkpoint{}, now)
	if partial {
		t.Error("a future-dated task alone is not partial history")
	}
	if !cp.HighWater.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("mark = %v, want the in-skew timestamp", cp.HighWater)
	}

	// A later pass still sees a real task updated after the first pass.
	d = NewDiscovery(codex, Since(cp))
	d.Add(Page{Tasks: []Task{{ID: "task_e_later", UpdatedAt: now.Add(time.Hour)}}})
	if len(d.Tasks()) != 1 {
		t.Fatal("a real update after the pass must be inside the next window")
	}

	// Only future tasks: the mark does not move at all.
	d = NewDiscovery(codex, Since(Checkpoint{}))
	d.Add(Page{Tasks: []Task{{ID: "task_e_future", UpdatedAt: ts("2099-01-01T00:00:00Z")}}})
	if cp, _ := d.Next(Checkpoint{}, now); !cp.HighWater.IsZero() {
		t.Fatalf("a future-only pass moved the mark to %v", cp.HighWater)
	}

	// A checkpoint already poisoned (written before the clamp) is discarded
	// and the pass is reported partial, with no gap built on the bad mark.
	bad := Checkpoint{HighWater: ts("2099-01-01T00:00:00Z"), Overlap: codex.Overlap}
	d = NewDiscovery(codex, Since(bad))
	d.Add(Page{Tasks: []Task{{ID: "task_e_real", UpdatedAt: ts("2026-10-31T09:00:00Z")}}})
	cp, partial = d.Next(bad, now)
	if !partial || !cp.HighWater.IsZero() || len(cp.Gaps) != 0 {
		t.Fatalf("poisoned checkpoint: %+v partial=%v", cp, partial)
	}
}
