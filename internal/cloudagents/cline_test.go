package cloudagents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// clineList parses a Cline session list body through the connector.
func clineList(t *testing.T, body string) []Task {
	t.Helper()
	p, err := ParseAPIList(mustConn(t, ConnectorClineCloud), nil, "", []byte(body))
	if err != nil {
		t.Fatalf("ParseAPIList: %v", err)
	}
	return p.Tasks
}

// clineRecord renders one session record with status, an optional phase
// and an optional expiry.
func clineRecord(id, status, phase, expiredAt string) string {
	meta := `{"taskId":"task-` + id + `"`
	if phase != "" {
		meta += `,"provisioningPhase":"` + phase + `"`
	}
	meta += `}`
	exp := "null"
	if expiredAt != "" {
		exp = `"` + expiredAt + `"`
	}
	return `{"id":"` + id + `","status":"` + status + `","metadata":` + meta + `,"expiredAt":` + exp +
		`,"createdAt":"2026-10-30T09:00:00.000Z","updatedAt":"2026-10-30T10:00:00.000Z"}`
}

// TestClineConnectorRow: the cline-cloud row is an API connector on the one
// exact host, Bearer, tool cline with surface host cline-cloud, and its
// grounding is "Observed in vendor client, undocumented".
func TestClineConnectorRow(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	if c.Kind != SourceAPI || len(c.APIHosts) != 1 || c.APIHosts[0] != "api.cline.bot" || c.Auth != AuthBearer ||
		c.Tool != models.ToolCline || c.SurfaceHost != SurfaceHostClineCloud || c.ToolVocabulary != models.ToolClineCLI ||
		!strings.Contains(c.KeyLabel, "app.cline.bot") || !strings.Contains(c.KeyLabel, "API Keys") ||
		strings.Contains(c.KeyLabel, "live-check") {
		t.Fatalf("row %+v", c)
	}
	if c.Grounding() != GroundingObservedUndocumented {
		t.Fatalf("grounding %s", c.Grounding())
	}
	if got := c.Surfaces(); len(got) != 3 {
		t.Fatalf("surfaces %v", got)
	}
}

// TestClineStatusMapping is one mapping case per Cline status (and phase,
// and expiry): what each lands as.
func TestClineStatusMapping(t *testing.T) {
	past := "2026-10-01T00:00:00.000Z"
	future := time.Now().UTC().Add(240 * time.Hour).Format(time.RFC3339)
	cases := []struct {
		name, status, phase, expiredAt string
		want                           Lifecycle
		vendor                         string
	}{
		{"provisioning", "provisioning", "cloning_repo", "", LifecycleRunning, "provisioning"},
		{"pending", "pending", "", "", LifecycleRunning, "pending"},
		{"provisioning failed phase", "provisioning", "failed", "", LifecycleFailed, "provisioning"},
		{"ready is unknown (REST cannot tell busy from idle)", "ready", "ready", "", LifecycleUnknown, "ready"},
		{"active is unknown (sandbox up only)", "active", "ready", "", LifecycleUnknown, "active"},
		{"suspended", "suspended", "ready", "", LifecycleWaiting, "suspended"},
		{"failed", "failed", "failed", "", LifecycleFailed, "failed"},
		{"expired by time", "suspended", "", past, LifecycleCancelled, ClineStatusExpired},
		{"expiry still ahead", "active", "", future, LifecycleUnknown, "active"},
		{"an unlisted status", "hibernating", "", "", LifecycleUnknown, "hibernating"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tasks := clineList(t, `{"data":[`+clineRecord("ses-a1", tc.status, tc.phase, tc.expiredAt)+`]}`)
			if len(tasks) != 1 {
				t.Fatalf("tasks %d", len(tasks))
			}
			got := tasks[0]
			if got.Lifecycle != tc.want || got.VendorStatus != tc.vendor {
				t.Fatalf("lifecycle %s (%s), want %s (%s)", got.Lifecycle, got.VendorStatus, tc.want, tc.vendor)
			}
			switch {
			case tc.vendor == ClineStatusExpired:
				if !got.CompletedAt.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
					t.Errorf("an expired session ends at its expiry, got %v", got.CompletedAt)
				}
			case got.Lifecycle.Terminal() != !got.CompletedAt.IsZero():
				t.Errorf("completed at %v for lifecycle %s", got.CompletedAt, got.Lifecycle)
			}
		})
	}
}

// TestClineListMapping: the fixture's sessions land under tool cline with
// the task id as vendor reference (CA-D12 join), the repository from
// repoContext, the handoff source as a fork parent, the cline-cloud
// surface host and execution vendor_cloud.
func TestClineListMapping(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	p, err := ParseAPIList(c, nil, "", vendorFixture(t, "cline/cline.cloud.sessions/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 2 || p.Cursor != "" {
		t.Fatalf("tasks %d cursor %q", len(p.Tasks), p.Cursor)
	}
	a, b := p.Tasks[0], p.Tasks[1]
	if a.ID != "ses-synth0001" || a.VendorRef != "task-synth-0001" || a.RepoRemote != "github.com/acme/widget" ||
		a.ForkedFromID != "1793351400123" || a.Lifecycle != LifecycleUnknown || a.ParentID != "" ||
		!a.CreatedAt.Equal(time.Date(2026, 10, 30, 9, 12, 0, 0, time.UTC)) || a.Tokens != nil || len(a.Usage) != 0 {
		t.Fatalf("first task %+v", a)
	}
	if b.VendorStatus != ClineStatusExpired || b.Lifecycle != LifecycleCancelled || b.RepoRemote != "" || b.ForkedFromID != "" {
		t.Fatalf("second task %+v", b)
	}
	if ref := ResolveProject(c, b, nil); ref.Placeholder != "[cline-cloud]" || ref.Note != NoteRepositoryNotReported {
		t.Fatalf("a session without a repository goes to the placeholder: %+v", ref)
	}
	if ref := ResolveProject(c, a, nil); ref.Remote != "github.com/acme/widget" {
		t.Fatalf("repoContext names the project: %+v", ref)
	}
	if s := Surface(c, a.ID); len(s) != 1 || s[0].SurfaceHost != SurfaceHostClineCloud || s[0].Surface != "" {
		t.Fatalf("surface %+v", s)
	}
	if e := Execution(a.ID, a); e.ExecutionLocation != models.ExecutionVendorCloud || e.VendorSessionRef != "task-synth-0001" {
		t.Fatalf("execution %+v", e)
	}
	// A projected VS Code task row stamped with the same vendor reference
	// is the row the pull merges into (CA-D12).
	byRef := func(ref string) (string, bool) { return "projected-row", ref == "task-synth-0001" }
	if id, m := ResolveSessionID(a, byRef); id != "projected-row" || m != MatchVendorRef {
		t.Fatalf("merge %s %s", id, m)
	}
	if id, m := ResolveSessionID(a, nil); id != a.ID || m != MatchNativeID {
		t.Fatalf("native id %s %s", id, m)
	}
}

// TestClineHandoffIsAUserFork: lineage from metadata.handoff.sourceSessionId
// is a user fork (forked_from_id, thread_source user), never a subagent,
// and the pending link survives its checkpoint cursor.
func TestClineHandoffIsAUserFork(t *testing.T) {
	l := ChildLink{Parent: "1793351400123", Child: "ses-synth0001", Fork: true}
	lin, ok := ChildLineage(l)
	if !ok || lin.SessionID != "ses-synth0001" || lin.ForkedFromID != "1793351400123" || lin.ParentThreadID != "" ||
		lin.ThreadSource != ThreadSourceUser {
		t.Fatalf("fork lineage %+v %v", lin, ok)
	}
	if back := LinkFromCursor(l.Child, LinkCursor(l)); back != l {
		t.Fatalf("fork cursor round trip %+v", back)
	}
	sub := ChildLink{Parent: "p1", Child: "c1"}
	if back := LinkFromCursor("c1", LinkCursor(sub)); back != sub || LinkCursor(sub) != "p1" {
		t.Fatalf("a subagent cursor stays the bare parent id: %+v", back)
	}
	if lin, _ := ChildLineage(sub); lin.ThreadSource != ThreadSourceSubagent || lin.ParentThreadID != "p1" {
		t.Fatalf("subagent lineage %+v", lin)
	}
}

// TestClineStatusDetail: a status read refines the lifecycle; a missing
// record (the egress's null for a 404 or 410) changes nothing; an expired
// session stays expired.
func TestClineStatusDetail(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	base := clineList(t, `{"data":[`+clineRecord("ses-synth0001", "active", "", "")+`]}`)[0]
	got, err := ApplyAPIDetail(c, DetailStatus, base, vendorFixture(t, "cline/cline.cloud.session_status/normal_page.json"))
	if err != nil || got.Lifecycle != LifecycleUnknown || got.VendorStatus != "active" {
		t.Fatalf("active status %+v %v", got, err)
	}
	failed, err := ApplyAPIDetail(c, DetailStatus, base, []byte(`{"data":{"status":"provisioning","phase":"failed"}}`))
	if err != nil || failed.Lifecycle != LifecycleFailed || failed.CompletedAt.IsZero() {
		t.Fatalf("failed phase %+v %v", failed, err)
	}
	same, err := ApplyAPIDetail(c, DetailStatus, base, []byte("null"))
	if err != nil || same.Lifecycle != base.Lifecycle || same.VendorStatus != base.VendorStatus {
		t.Fatalf("absent status %+v %v", same, err)
	}
	expired := clineList(t, `{"data":[`+clineRecord("ses-synth0001", "suspended", "", "2026-10-01T00:00:00Z")+`]}`)[0]
	still, _ := ApplyAPIDetail(c, DetailStatus, expired, []byte(`{"data":{"status":"suspended"}}`))
	if still.VendorStatus != ClineStatusExpired || still.Lifecycle != LifecycleCancelled {
		t.Fatalf("expiry wins %+v", still)
	}
}

// TestClineHistoryMapping: the archive's messages become metadata-only
// activity and its metrics one token figure and one US-dollar figure,
// mapped to one token_usage row and one ledger row.
func TestClineHistoryMapping(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	hp, err := ParseAPIHistory(c, nil, "ses-synth0001", "", vendorFixture(t, "cline/cline.cloud.session_history/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[ActivityKind]int{}
	for _, a := range hp.Activity {
		kinds[a.Kind]++
		if a.Target != "" {
			t.Fatalf("activity carries text %+v", a)
		}
	}
	if kinds[ActivityPrompt] != 1 || kinds[ActivityResponse] != 2 || kinds[ActivityToolCall] != 2 || hp.Next != "" {
		t.Fatalf("activity %v next %q", kinds, hp.Next)
	}
	at := time.Date(2026, 10, 30, 9, 12, 25, 0, time.UTC)
	// metrics.inputTokens is gross of cache reads (live check 2026-11-02):
	// the fixture reports 10200 + 10500 input with 9000 + 10200 of it cache
	// reads, so the figure lands net, 1500.
	if hp.Tokens == nil || hp.Tokens.Input != 1500 || hp.Tokens.Output != 460 || hp.Tokens.CacheRead != 19200 ||
		hp.Tokens.CacheCreation != 800 || hp.Tokens.Kind != TokenFromProviderRunTotal || !hp.Tokens.ReportedAt.Equal(at) ||
		hp.Tokens.Model != "anthropic/claude-sonnet-4.5" {
		t.Fatalf("tokens %+v", hp.Tokens)
	}
	if len(hp.Usage) != 1 || hp.Usage[0].Unit != "usd" || hp.Usage[0].Value != 0.0174 ||
		hp.Usage[0].MonetaryStatus != models.UsageMonetaryReported || hp.Usage[0].ValueType != models.UsageValueCumulative {
		t.Fatalf("usage %+v", hp.Usage)
	}
	task := Task{Connector: c.ID, ID: "ses-synth0001", UpdatedAt: at, Tokens: hp.Tokens, Usage: hp.Usage}
	tok := MapTokens(c, task, task.ID, "/r")
	if len(tok) != 1 || tok[0].Tool != models.ToolCline || tok[0].InputTokens != 1500 || tok[0].Source != models.TokenSourceSessionSummary {
		t.Fatalf("token rows %+v", tok)
	}
	led := MapLedger(c, task, task.ID, KeychainKeyAccount)
	if len(led) != 1 || led[0].Unit != "usd" || led[0].MonetaryStatus != models.UsageMonetaryReported {
		t.Fatalf("ledger %+v", led)
	}
	acts := MapActivity(c, task.ID, "/r", hp.Activity)
	if len(acts) != 5 {
		t.Fatalf("actions %d", len(acts))
	}
	// The Cline SDK's tool names classify through cline-cli's vocabulary.
	byRaw := map[string]string{}
	for _, a := range acts {
		byRaw[a.RawToolName] = a.ActionType
	}
	if byRaw["editor"] != models.ActionEditFile || byRaw["run_commands"] != models.ActionRunCommand {
		t.Fatalf("tool call actions %v", byRaw)
	}
}

// TestClineNoUsageMeansNoRow: a history whose messages report no metrics,
// and a session with no archive yet (the egress's null for a 404), land no
// token row and no ledger row: absent, never zero (CA-D11).
func TestClineNoUsageMeansNoRow(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	for name, body := range map[string]string{
		"no metrics": `{"version":1,"messages":[{"role":"user","content":"hi","ts":1793351521000},
			{"role":"assistant","content":"ok","metrics":{},"ts":1793351530000}]}`,
		"no archive": "null",
		"empty":      `{"version":1,"messages":[]}`,
	} {
		hp, err := ParseAPIHistory(c, nil, "ses-synth0001", "", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hp.Tokens != nil || len(hp.Usage) != 0 {
			t.Fatalf("%s: figures %+v %+v", name, hp.Tokens, hp.Usage)
		}
		task := Task{Connector: c.ID, ID: "ses-synth0001", UpdatedAt: time.Now(), Tokens: hp.Tokens, Usage: hp.Usage}
		if rows := MapTokens(c, task, task.ID, "/r"); len(rows) != 0 {
			t.Fatalf("%s: token rows %+v", name, rows)
		}
		if led := MapLedger(c, task, task.ID, KeychainKeyAccount); len(led) != 0 {
			t.Fatalf("%s: ledger %+v", name, led)
		}
	}
}

// TestClineRequestsAndAbsentStatuses: every request is driver-built on the
// row's own host; the status and history reads carry the row's absent
// statuses (404 and 410 mean no record), the list carries none.
func TestClineRequestsAndAbsentStatuses(t *testing.T) {
	c := mustConn(t, ConnectorClineCloud)
	list, err := APIListRequest(c, nil, time.Time{}, time.Time{}, "")
	if err != nil || list.URL != "https://api.cline.bot/api/v1/session" || list.Auth != AuthBearer || len(list.Absent) != 0 {
		t.Fatalf("list %+v %v", list, err)
	}
	id, err := APIIdentityRequest(c, nil)
	if err != nil || id.URL != list.URL || id.Op != OpIdentity {
		t.Fatalf("identity %+v %v", id, err)
	}
	st, err := APIDetailRequest(c, DetailStatus, "ses-synth0001")
	if err != nil || st.URL != "https://api.cline.bot/api/v1/session/ses-synth0001/status" || !sameInts(st.Absent, []int{404, 410}) {
		t.Fatalf("status %+v %v", st, err)
	}
	h, err := APIHistoryRequest(c, nil, "ses-synth0001", "", time.Time{}, time.Time{})
	if err != nil || h.URL != "https://api.cline.bot/api/v1/session/ses-synth0001/history" || !sameInts(h.Absent, []int{404, 410}) {
		t.Fatalf("history %+v %v", h, err)
	}
	if _, err := APIDetailRequest(c, DetailStatus, "../x"); err == nil {
		t.Fatal("a traversal id built a request")
	}
	if ident, err := ParseAPIIdentity(c, nil, vendorFixture(t, "cline/cline.cloud.sessions/normal_page.json")); err != nil ||
		ident.AccountID != KeychainKeyAccount {
		t.Fatalf("identity %+v %v", ident, err)
	}
	if _, err := ParseAPIList(c, nil, "", []byte(`{"items":[]}`)); ClassOf(err) != ErrWrongShape {
		t.Fatalf("a drifted list is wrong_shape, got %v", err)
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGroundingLevelOrdering: the coverage levels are ordered Live verified,
// Documented, Observed in vendor client undocumented; only the last needs
// a drift test and a ledger note; every connector has a known level and a
// connector without a row is Documented (CA-D17).
func TestGroundingLevelOrdering(t *testing.T) {
	want := []Grounding{GroundingVerified, GroundingDocumented, GroundingObservedUndocumented}
	levels := GroundingLevels()
	if len(levels) != len(want) {
		t.Fatalf("levels %+v", levels)
	}
	for i, g := range want {
		if levels[i].Level != g || g.Rank() != i || levels[i].Label == "" || levels[i].Meaning == "" {
			t.Errorf("row %d = %+v, want %s at rank %d", i, levels[i], g, i)
		}
		if levels[i].RequiresDriftTest != (g == GroundingObservedUndocumented) || (levels[i].Ledger != "") != levels[i].RequiresDriftTest {
			t.Errorf("%s: drift-test rule or ledger note wrong: %+v", g, levels[i])
		}
	}
	if GroundingObservedUndocumented.Label() != "Observed in vendor client, undocumented" {
		t.Fatalf("label %q", GroundingObservedUndocumented.Label())
	}
	if !(GroundingDocumented.Rank() < GroundingObservedUndocumented.Rank()) || Grounding("bogus").Rank() != len(levels) {
		t.Fatal("undocumented must rank below Documented, and an unknown level below every known one")
	}
	for _, c := range Connectors {
		if _, ok := LevelOf(c.Grounding()); !ok {
			t.Errorf("%s: unknown grounding %q", c.ID, c.Grounding())
		}
	}
	if mustConn(t, ConnectorOpenHandsCloud).Grounding() != GroundingDocumented {
		t.Error("a connector with no grounding row is Documented")
	}
	seen := map[string]bool{}
	for _, r := range connectorGroundings {
		if _, ok := ConnectorByID(r.connector); !ok || seen[r.connector] || r.evidence == "" {
			t.Errorf("grounding row %+v: unknown connector, repeated, or no evidence", r)
		}
		seen[r.connector] = true
	}
}

// TestUndocumentedConnectorsCarryDriftTests is the rule of the "Observed in
// vendor client, undocumented" level: every surface such a connector reads
// names a schema-drift test, and that test exists in its package.
func TestUndocumentedConnectorsCarryDriftTests(t *testing.T) {
	checked := 0
	for _, c := range Connectors {
		lvl, _ := LevelOf(c.Grounding())
		if !lvl.RequiresDriftTest {
			continue
		}
		surfaces := c.Surfaces()
		if len(surfaces) == 0 {
			t.Errorf("%s: at level %q but reads no declared surface", c.ID, lvl.Label)
		}
		for _, s := range surfaces {
			pkg, test, ok := DriftTest(s)
			if !ok {
				t.Errorf("%s reads %s, which has no schema-drift test", c.ID, s)
				continue
			}
			if !testExists(t, pkg, test) {
				t.Errorf("%s: drift test %s.%s does not exist", s, pkg, test)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no undocumented connector was checked (cline-cloud should be)")
	}
}

// testExists reports whether a _test.go file of the package directory
// (relative to the repository root) declares func test.
func testExists(t *testing.T, pkg, test string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", filepath.FromSlash(pkg), "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "\nfunc "+test+"(t *testing.T)") {
			return true
		}
	}
	return false
}
