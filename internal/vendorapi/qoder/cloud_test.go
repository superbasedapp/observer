package qoder

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/vendormock"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

const testCloudSession = "sess_synth0001"

var cloudParams = vendorapi.Params{ParamSessionID: testCloudSession, ParamEnvironmentID: "env_synth01"}

func cloudFixture(t *testing.T, surface vs.SurfaceID, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vendorapi", "qoder", string(surface), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cloudResp(body []byte, cursor string) vendorapi.Response {
	return vendorapi.Response{Status: 200, Origin: "https://api.qoder.com:443", Body: body, Cursor: cursor, Params: cloudParams}
}

// noLeak fails when any landing of p carries a placeholder the fixtures put
// in a member the drivers must never decode.
func noLeak(t *testing.T, p vendorapi.Page) {
	t.Helper()
	bad := []string{
		"synthetic-env-placeholder", "Synthetic system prompt", "Synthetic task title", "SYNTH-1",
		"Synthetic prompt placeholder", "Synthetic reply placeholder", "synthetic-command-placeholder",
		"synthetic output placeholder", "user@", "/repos/widget", "echo synthetic", "synthetic-env",
		"Synthetic agent name", "Synthetic agent description", "/data/workspace", "thr_synth01", "synthetic-agent",
	}
	check := func(where, v string) {
		for _, b := range bad {
			if strings.Contains(v, b) {
				t.Fatalf("%s carries %q", where, b)
			}
		}
	}
	for _, s := range p.Snapshots {
		for k, v := range s.Body {
			check("snapshot "+k, v)
		}
	}
	for _, e := range p.Audit {
		check("audit target", e.Target)
		for k, v := range e.Detail {
			check("audit "+k, v)
		}
	}
	if len(p.Content) != 0 {
		t.Fatalf("the drivers land no content, got %d items", len(p.Content))
	}
}

// TestCloudSessionsParseCorpus: one snapshot per session, a token row only
// where usage reports tokens, one cumulative credit row per session that
// reports total_credits (the live shape: credits only, no tokens), a
// repository URL with user information dropped, and nothing content-shaped
// decoded.
func TestCloudSessionsParseCorpus(t *testing.T) {
	p, err := parseCloudSessions(cloudResp(cloudFixture(t, SurfaceCloudSessions, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 3 || len(p.Usage) != 3 || p.NextCursor != "page_synth0002" {
		t.Fatalf("snapshots %d usage %d next %q", len(p.Snapshots), len(p.Usage), p.NextCursor)
	}
	noLeak(t, p)
	want := map[string]string{
		"status": "idle", "created_at": "2026-10-30T09:00:00Z", "updated_at": "2026-10-30T09:42:10Z",
		"environment_id": "env_synth01", "type": "session", "agent_id": "agent_synth01", "model": "ultimate",
		"repo_url": "https://github.com/acme/widget", "repo_type": "github_repository", "repo_branch": "main",
		"repository_count": "1", "active_seconds": "512.5", "duration_seconds": "2530",
		"model_credits": "7.66", "sandbox_runtime_credits": "0.34", "total_credits": "8",
	}
	s := p.Snapshots[0]
	if s.Class != CloudSessionClass || s.Subject != testCloudSession || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	// A git_repository resource carrying user information keeps its branch
	// and count, never its URL; a bare model string is read.
	s2 := p.Snapshots[1]
	if _, ok := s2.Body["repo_url"]; ok || s2.Body["repo_branch"] != "dev" || s2.Body["model"] != "auto" {
		t.Fatalf("second session body %+v", s2.Body)
	}
	// The live-shaped session: a github_repository resource with a null
	// checkout, model qfmodel, credits only.
	if b := p.Snapshots[2].Body; b["archived_at"] != "2026-10-29T09:00:00Z" || b["repository_count"] != "1" ||
		b["repo_url"] != "https://github.com/synth-owner/synth-repo" || b["repo_branch"] != "" || b["model"] != "qfmodel" ||
		b["total_credits"] != "0.2" || b["sandbox_runtime_credits"] != "0.02" {
		t.Fatalf("third session body %+v", b)
	}
	u := p.Usage[0]
	at := time.Date(2026, 10, 30, 9, 42, 10, 0, time.UTC)
	if u.JoinValue != testCloudSession || u.InputTokens != 41200 || u.OutputTokens != 6100 || u.CacheReadTokens != 220400 ||
		u.CacheWriteTokens != 18000 || u.ChargedUnit != "" || u.ChargedMicros != 0 || u.Model != "ultimate" ||
		!u.At.Equal(at) || u.Revision != at.Unix() || u.IdentityKind != CloudIdentityCaller ||
		u.JoinNamespace != CloudSessionUsageNamespace {
		t.Fatalf("usage %+v", u)
	}
	// One cumulative credit row per session: the total, with the model and
	// sandbox split as flags (a breakdown inside the total).
	cr := p.Usage[1]
	if cr.JoinNamespace != CloudSessionCreditsNamespace || cr.JoinValue != testCloudSession || cr.ChargedUnit != UnitCloudCredit ||
		cr.ChargedMicros != 8_000_000 || cr.Flags[FlagModelCreditsMicros] != "7660000" ||
		cr.Flags[FlagSandboxCreditsMicros] != "340000" || cr.InputTokens != 0 || !cr.At.Equal(at) {
		t.Fatalf("credit row %+v", cr)
	}
	if c3 := p.Usage[2]; c3.JoinValue != "sess_synth0003" || c3.ChargedMicros != 200_000 || c3.JoinNamespace != CloudSessionCreditsNamespace ||
		c3.Flags[FlagSandboxCreditsMicros] != "20000" {
		t.Fatalf("live-shaped credit row %+v", c3)
	}
	last, err := parseCloudSessions(cloudResp(cloudFixture(t, SurfaceCloudSessions, "last_page.json"), "page_synth0002"))
	if err != nil || last.NextCursor != "" || len(last.Snapshots) != 1 || last.Snapshots[0].Body["status"] != "rescheduling" {
		t.Fatalf("last page %+v %v", last, err)
	}
}

func TestCloudSessionRetrieveAndEnvironment(t *testing.T) {
	p, err := parseCloudSession(cloudResp(cloudFixture(t, SurfaceCloudSession, "normal_page.json"), ""))
	if err != nil || len(p.Snapshots) != 1 || len(p.Usage) != 2 || p.Snapshots[0].Subject != testCloudSession {
		t.Fatalf("retrieve %+v %v", p, err)
	}
	noLeak(t, p)
	other := cloudResp(cloudFixture(t, SurfaceCloudSession, "normal_page.json"), "")
	other.Params = vendorapi.Params{ParamSessionID: "sess_other"}
	if _, err := parseCloudSession(other); !errors.Is(err, vendorapi.ErrSchemaDrift) {
		t.Fatalf("a different session answered must be drift, got %v", err)
	}
	e, err := parseCloudEnvironment(cloudResp(cloudFixture(t, SurfaceCloudEnvironment, "normal_page.json"), ""))
	if err != nil || len(e.Snapshots) != 1 {
		t.Fatalf("environment %+v %v", e, err)
	}
	noLeak(t, e)
	if b := e.Snapshots[0].Body; e.Snapshots[0].Class != CloudEnvironmentClass || b["config_type"] != "self_hosted" ||
		b["scope"] != "personal" || len(b) != 2 {
		t.Fatalf("environment snapshot %+v", e.Snapshots[0])
	}
}

// TestCloudEventsParseCorpus: metadata-only audit rows over the live event
// sequence; no usage row at all (every credit an event carries repeats the
// session's cumulative total, which the sessions surface lands).
func TestCloudEventsParseCorpus(t *testing.T) {
	p, err := parseCloudEvents(cloudResp(cloudFixture(t, SurfaceCloudEvents, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	noLeak(t, p)
	if len(p.Audit) != 14 || p.NextCursor != "evpage_synth0002" || p.SourceRecords != 14 {
		t.Fatalf("audit %d next %q records %d", len(p.Audit), p.NextCursor, p.SourceRecords)
	}
	actions := []string{
		ActionStatusRunning, "thread_running", ActionUserMessage, "model_request_start", "agent_thinking",
		ActionToolCall, ActionToolResult, ActionToolCall, ActionAgentMessage, ActionModelRequest, "thread_idle",
		ActionUsageSnapshot, ActionTurnEnd, ActionContextCompacted,
	}
	for i, a := range actions {
		if p.Audit[i].Action != a {
			t.Errorf("event %d action %q, want %q", i, p.Audit[i].Action, a)
		}
	}
	if p.Audit[5].Target != "Bash" || p.Audit[7].Target != "search_issues" || p.Audit[7].Detail[DetailMCPServer] != "github" {
		t.Fatalf("tool calls %+v %+v", p.Audit[5], p.Audit[7])
	}
	if r := p.Audit[6].Detail; r[DetailToolUseID] != "evt_synth0002" || r[DetailIsError] != "false" {
		t.Fatalf("tool result detail %+v", r)
	}
	if p.Audit[12].Detail[DetailStopReason] != "end_turn" {
		t.Fatalf("turn end detail %+v", p.Audit[12].Detail)
	}
	if c := canaryCloudEvents(p); len(c) != 0 {
		t.Fatalf("the live event types tripped the canary: %+v", c)
	}
	if len(p.Usage) != 0 {
		t.Fatalf("events landed %d usage rows, want none", len(p.Usage))
	}
	last, err := parseCloudEvents(cloudResp(cloudFixture(t, SurfaceCloudEvents, "last_page.json"), "evpage_synth0002"))
	if err != nil || len(last.Usage) != 0 || last.NextCursor != "" || len(last.Audit) != 4 {
		t.Fatalf("last page %+v %v", last, err)
	}
}

func TestCloudEventsUnknownTypeAndMissingTime(t *testing.T) {
	body := []byte(`{"data":[{"id":"evt_x1","type":"agent.something_new","processed_at":"2026-10-30T09:00:00Z"},
		{"id":"evt_x2","type":"agent.message"}],"has_more":false,"next_page":null}`)
	p, err := parseCloudEvents(cloudResp(body, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Audit) != 1 || p.Audit[0].Action != ActionCloudOther || p.SourceRecords != 2 {
		t.Fatalf("page %+v", p)
	}
	if c := canaryCloudEvents(p); len(c) != 1 || c[0].Kind != "unknown_enum" {
		t.Fatalf("canary %+v", c)
	}
}

func TestCloudBuilders(t *testing.T) {
	r, err := buildCloudSessions(nil, vendorapi.Window{}, "")
	if err != nil || r.Path != "/api/v1/cloud/sessions" || r.Query["limit"][0] != "100" || r.Query["order"][0] != "desc" || r.Query["page"] != nil {
		t.Fatalf("sessions %+v %v", r, err)
	}
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	r, err = buildCloudEvents(cloudParams, vendorapi.Window{From: from, To: to}, "evpage_2")
	if err != nil || r.Path != "/api/v1/cloud/sessions/sess_synth0001/events" || r.Query["order"][0] != "asc" ||
		r.Query["page"][0] != "evpage_2" || r.Query["created_at[gte]"][0] != "2026-10-01T00:00:00Z" ||
		r.Query["created_at[lt]"][0] != "2026-10-02T00:00:00Z" {
		t.Fatalf("events %+v %v", r, err)
	}
	if _, err := buildCloudEvents(vendorapi.Params{ParamSessionID: "../x"}, vendorapi.Window{}, ""); err == nil {
		t.Fatal("a traversal id must be refused")
	}
	if _, err := buildCloudEvents(cloudParams, vendorapi.Window{From: from}, ""); err == nil {
		t.Fatal("a half window must be refused")
	}
	if _, err := buildCloudSessions(nil, vendorapi.Window{}, "bad cursor"); err == nil {
		t.Fatal("a cursor with a space must be refused")
	}
	r, err = buildCloudEnvironment(cloudParams, vendorapi.Window{}, "")
	if err != nil || r.Path != "/api/v1/cloud/environments/env_synth01" {
		t.Fatalf("environment %+v %v", r, err)
	}
	r, err = buildCloudSession(cloudParams, vendorapi.Window{}, "")
	if err != nil || r.Path != "/api/v1/cloud/sessions/sess_synth0001" {
		t.Fatalf("session %+v %v", r, err)
	}
}

func cloudDrivers() []vendorapi.Driver {
	return []vendorapi.Driver{CloudSessions(), CloudSession(), CloudEnvironment(), CloudEvents()}
}

// TestCloudDriverContract pins each driver to its catalog row and corpus
// ledger (no org driver-table entry: node-consumed).
func TestCloudDriverContract(t *testing.T) {
	for _, d := range cloudDrivers() {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != CloudTool || d.Auth.Scheme != vendorapi.SchemeBearer {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestCloudConformance runs the shared conformance suite against the four
// drivers through the pure adapter.
func TestCloudConformance(t *testing.T) {
	for _, d := range cloudDrivers() {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) { vendormock.RunPure(t, d, cloudParams, vendorapi.Window{}) })
	}
}
