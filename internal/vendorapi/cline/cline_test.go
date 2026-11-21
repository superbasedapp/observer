package cline

import (
	"encoding/json"
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

const testSession = "ses-synth0001"

var testParams = vendorapi.Params{ParamSessionID: testSession}

func fixtureDir(surface vs.SurfaceID) string {
	return filepath.Join("..", "..", "..", "testdata", "vendorapi", "cline", string(surface))
}

func fixture(t *testing.T, surface vs.SurfaceID, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir(surface), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resp(body []byte) vendorapi.Response {
	return vendorapi.Response{Status: 200, Origin: "https://api.cline.bot:443", Body: body, Params: testParams}
}

func isDrift(err error) bool { return err != nil && errors.Is(err, vendorapi.ErrSchemaDrift) }

// TestSessionsParseCorpus: one snapshot per record with the ids, times,
// repository, task id and handoff source; the title, sandbox URL, status
// reason, request title and cwd are never decoded.
func TestSessionsParseCorpus(t *testing.T) {
	p, err := parseSessions(resp(fixture(t, SurfaceSessions, "normal_page.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 2 || p.SourceRecords != 2 || p.NextCursor != "" {
		t.Fatalf("snapshots %d records %d next %q", len(p.Snapshots), p.SourceRecords, p.NextCursor)
	}
	want := map[string]string{
		"created_at": "2026-10-30T09:12:00Z", "updated_at": "2026-10-30T09:40:12Z", "last_activity_at": "2026-10-30T09:40:12Z",
		"status": "active", "sandbox_type": "resumable", "repo_url": "https://github.com/acme/widget", "branch": "main",
		"model_id": "anthropic/claude-sonnet-4.5", "task_id": "task-synth-0001", "provisioning_phase": "ready",
		"handoff_source_session_id": "1793351400123",
	}
	s := p.Snapshots[0]
	if s.Class != SessionClass || s.Subject != testSession || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	s2 := p.Snapshots[1]
	if s2.Body["expired_at"] != "2026-10-29T12:00:00Z" || s2.Body["status"] != "suspended" || s2.Body["repo_url"] != "" ||
		s2.Body["sandbox_type"] != "standard" || s2.Body["handoff_source_session_id"] != "" {
		t.Fatalf("second snapshot %+v", s2)
	}
	for _, sn := range p.Snapshots {
		for k, v := range sn.Body {
			if strings.Contains(v, "placeholder") || strings.Contains(v, "sandbox.invalid") || v == "/workspace" {
				t.Fatalf("a text or address field leaked: %s=%s", k, v)
			}
		}
	}
	// A null data is an empty list, as the client reads it.
	empty, err := parseSessions(resp([]byte(`{"data":null}`)))
	if err != nil || len(empty.Snapshots) != 0 {
		t.Fatalf("null data %+v %v", empty, err)
	}
}

// TestSessionStatusParseCorpus: one snapshot with status and phase; the
// status reason is never decoded; a null body (the egress's 404 or 410)
// lands nothing.
func TestSessionStatusParseCorpus(t *testing.T) {
	p, err := parseSessionStatus(resp(fixture(t, SurfaceSessionStatus, "normal_page.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatal(err)
	}
	if len(p.Snapshots) != 1 || p.Snapshots[0].Class != StatusClass || p.Snapshots[0].Subject != testSession ||
		len(p.Snapshots[0].Body) != 2 || p.Snapshots[0].Body["status"] != "active" || p.Snapshots[0].Body["phase"] != "ready" {
		t.Fatalf("status page %+v", p)
	}
	none, err := parseSessionStatus(resp([]byte("null")))
	if err != nil || none.HasActivity() {
		t.Fatalf("null body %+v %v", none, err)
	}
}

// TestSessionHistoryParseCorpus: timed prompts and responses as content
// items with no text, tool_use blocks as tool_call rows naming the tool, a
// user message of tool results is not a prompt, and the metrics summed into
// one session usage row (tokens as reported, cost in micro-dollars).
func TestSessionHistoryParseCorpus(t *testing.T) {
	p, err := parseSessionHistory(resp(fixture(t, SurfaceSessionHistory, "normal_page.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if p.SourceRecords != 5 || len(p.Content) != 3 || len(p.Audit) != 2 || len(p.Usage) != 1 {
		t.Fatalf("records %d content %d audit %d usage %d", p.SourceRecords, len(p.Content), len(p.Audit), len(p.Usage))
	}
	roles := []string{p.Content[0].Role, p.Content[1].Role, p.Content[2].Role}
	if strings.Join(roles, ",") != "prompt,response,response" || p.Content[0].ItemID != "msg-synth-0001" ||
		!p.Content[0].At.Equal(time.Date(2026, 10, 30, 9, 12, 1, 0, time.UTC)) {
		t.Fatalf("content %+v", p.Content)
	}
	for _, c := range p.Content {
		if c.Text != "" || c.SessionRef != testSession {
			t.Fatalf("content item carries text or the wrong session: %+v", c)
		}
	}
	// The Cline SDK's tool names, as the live archive carries them.
	for i, want := range []struct{ target, event string }{
		{"editor", "msg-synth-0002/toolu_synth_0001"}, {"run_commands", "msg-synth-0004/toolu_synth_0002"},
	} {
		a := p.Audit[i]
		if a.Action != "tool_call" || a.Target != want.target || a.EventID != want.event ||
			a.AgentSessionID != testSession || !a.ActorIsAgent || a.Namespace != MessageNamespace {
			t.Fatalf("tool call %d %+v", i, a)
		}
	}
	u := p.Usage[0]
	at := time.Date(2026, 10, 30, 9, 12, 25, 0, time.UTC)
	// InputTokens is the sum as reported, GROSS of cache reads (the
	// connector nets it); the fixture's two reporting messages sum to 20700
	// input with 19200 of it cache reads.
	if u.JoinValue != testSession || u.SessionRef != testSession || u.InputTokens != 20700 || u.OutputTokens != 460 ||
		u.CacheReadTokens != 19200 || u.CacheWriteTokens != 800 || u.ChargedUnit != ChargedUnitUSD ||
		u.ChargedMicros != 17_400 || !u.At.Equal(at) || u.Revision != at.Unix() || u.Model != "anthropic/claude-sonnet-4.5" ||
		u.Flags[TokensFlag] != "true" || u.Flags[InputBasisFlag] != InputBasisValue || u.Flags[ModelCountFlag] != "1" ||
		u.IdentityKind != IdentityCaller {
		t.Fatalf("usage %+v", u)
	}
	raw, _ := json.Marshal(p)
	for _, leak := range []string{"placeholder", "README", "reasoning"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("message text or tool input leaked (%s)", leak)
		}
	}
}

// TestSessionHistoryNoMetricsNoUsageRow: an archive whose messages carry no
// metrics yields no usage row (absent, never zero), and a cost-only archive
// yields a cost with no token flag.
func TestSessionHistoryNoMetricsNoUsageRow(t *testing.T) {
	plain := `{"version":1,"messages":[{"role":"user","content":"hi","ts":1793351521000},
		{"role":"assistant","content":[{"type":"text","text":"x"}],"metrics":{},"ts":1793351530000}]}`
	p, err := parseSessionHistory(resp([]byte(plain)))
	if err != nil || len(p.Usage) != 0 || len(p.Content) != 2 {
		t.Fatalf("no-metrics archive: %+v %v", p, err)
	}
	costOnly := `{"version":1,"messages":[{"role":"assistant","content":"x","metrics":{"cost":1e-7},"ts":1793351530000}]}`
	c, err := parseSessionHistory(resp([]byte(costOnly)))
	if err != nil || len(c.Usage) != 1 || c.Usage[0].Flags[TokensFlag] != "" || c.Usage[0].InputTokens != 0 ||
		c.Usage[0].ChargedUnit != ChargedUnitUSD || c.Usage[0].ChargedMicros != 0 {
		t.Fatalf("cost-only archive: %+v %v", c, err)
	}
	none, err := parseSessionHistory(resp([]byte("null")))
	if err != nil || none.HasActivity() || none.HasContent() {
		t.Fatalf("no archive: %+v %v", none, err)
	}
}

func TestBuildContract(t *testing.T) {
	list, err := buildSessions(nil, vendorapi.Window{}, "")
	if err != nil || list.Method != "GET" || list.Path != "/api/v1/session" || len(list.Query) != 0 {
		t.Fatalf("list request %+v %v", list, err)
	}
	org, err := buildSessions(vendorapi.Params{ParamOrganizationID: "org_synth1"}, vendorapi.Window{}, "")
	if err != nil || org.Query["organizationId"][0] != "org_synth1" {
		t.Fatalf("org list request %+v %v", org, err)
	}
	st, err := buildSessionStatus(testParams, vendorapi.Window{}, "")
	if err != nil || st.Path != "/api/v1/session/"+testSession+"/status" {
		t.Fatalf("status request %+v %v", st, err)
	}
	h, err := buildSessionHistory(testParams, vendorapi.Window{}, "")
	if err != nil || h.Path != "/api/v1/session/"+testSession+"/history" {
		t.Fatalf("history request %+v %v", h, err)
	}
	for name, err := range map[string]error{
		"list cursor":       errOf(buildSessions(nil, vendorapi.Window{}, "p2")),
		"list bad org":      errOf(buildSessions(vendorapi.Params{ParamOrganizationID: "../x"}, vendorapi.Window{}, "")),
		"status no id":      errOf(buildSessionStatus(nil, vendorapi.Window{}, "")),
		"status traversal":  errOf(buildSessionStatus(vendorapi.Params{ParamSessionID: "../x"}, vendorapi.Window{}, "")),
		"history no id":     errOf(buildSessionHistory(nil, vendorapi.Window{}, "")),
		"history traversal": errOf(buildSessionHistory(vendorapi.Params{ParamSessionID: "a/b"}, vendorapi.Window{}, "")),
		"history cursor":    errOf(buildSessionHistory(testParams, vendorapi.Window{}, "c")),
	} {
		if err == nil {
			t.Errorf("%s: build accepted", name)
		}
	}
}

func errOf(_ vendorapi.Request, err error) error { return err }

// expectDrift asserts every case fails as schema drift (plan 12A.5). The
// surface reads an undocumented API ("Observed in vendor client,
// undocumented"), so these cases are the early warning that the vendor
// changed a shape the driver depends on.
func expectDrift(t *testing.T, cases map[string]error) {
	t.Helper()
	for name, err := range cases {
		if !isDrift(err) {
			t.Errorf("%s: err %v, want schema drift", name, err)
		}
	}
}

// TestSchemaDriftSessions is the schema-drift test of cline.cloud.sessions.
func TestSchemaDriftSessions(t *testing.T) {
	list := func(b string) error { _, err := parseSessions(resp([]byte(b))); return err }
	wrap := func(items string) string { return `{"data":[` + items + `]}` }
	ok := `"status":"active","createdAt":"2026-10-30T09:12:00.000Z","updatedAt":"2026-10-30T09:40:12.000Z"`
	expectDrift(t, map[string]error{
		"not json":          list(`<html>`),
		"data missing":      list(`{"sessions":[]}`),
		"data object":       list(`{"data":{}}`),
		"items envelope":    list(`{"items":[]}`),
		"id missing":        list(wrap(`{` + ok + `}`)),
		"id number":         list(wrap(`{"id":7,` + ok + `}`)),
		"id unsafe":         list(wrap(`{"id":"../x",` + ok + `}`)),
		"repeated":          list(wrap(`{"id":"ses-1",` + ok + `},{"id":"ses-1",` + ok + `}`)),
		"status missing":    list(wrap(`{"id":"ses-1","createdAt":"2026-10-30T09:12:00Z","updatedAt":"2026-10-30T09:12:00Z"}`)),
		"status number":     list(wrap(`{"id":"ses-1","status":3,"createdAt":"2026-10-30T09:12:00Z","updatedAt":"2026-10-30T09:12:00Z"}`)),
		"created missing":   list(wrap(`{"id":"ses-1","status":"active","updatedAt":"2026-10-30T09:12:00Z"}`)),
		"created epoch":     list(wrap(`{"id":"ses-1","status":"active","createdAt":1793351520,"updatedAt":"2026-10-30T09:12:00Z"}`)),
		"updated bad":       list(wrap(`{"id":"ses-1","status":"active","createdAt":"2026-10-30T09:12:00Z","updatedAt":"later"}`)),
		"expired bad":       list(wrap(`{"id":"ses-1",` + ok + `,"expiredAt":"soon"}`)),
		"repoContext text":  list(wrap(`{"id":"ses-1",` + ok + `,"repoContext":"acme/widget"}`)),
		"metadata list":     list(wrap(`{"id":"ses-1",` + ok + `,"metadata":[]}`)),
		"taskId number":     list(wrap(`{"id":"ses-1",` + ok + `,"metadata":{"taskId":12}}`)),
		"handoff text":      list(wrap(`{"id":"ses-1",` + ok + `,"metadata":{"handoff":"x"}}`)),
		"task id over-long": list(wrap(`{"id":"ses-1",` + ok + `,"metadata":{"taskId":"` + strings.Repeat("t", 300) + `"}}`)),
	})
	if _, err := parseSessions(vendorapi.Response{Status: 500, Body: []byte(`{}`)}); !isDrift(err) {
		t.Errorf("non-200: %v", err)
	}
}

// TestSchemaDriftSessionStatus is the schema-drift test of
// cline.cloud.session_status.
func TestSchemaDriftSessionStatus(t *testing.T) {
	st := func(b string) error { _, err := parseSessionStatus(resp([]byte(b))); return err }
	expectDrift(t, map[string]error{
		"not json":        st(`<html>`),
		"unwrapped":       st(`{"status":"active"}`),
		"data null":       st(`{"data":null}`),
		"data list":       st(`{"data":[]}`),
		"status missing":  st(`{"data":{"phase":"ready"}}`),
		"status number":   st(`{"data":{"status":1}}`),
		"phase object":    st(`{"data":{"status":"active","phase":{}}}`),
		"another session": st(`{"data":{"sessionId":"ses-other","status":"active"}}`),
	})
	noID := resp([]byte(`{"data":{"status":"active"}}`))
	noID.Params = nil
	if _, err := parseSessionStatus(noID); !isDrift(err) {
		t.Errorf("status without a session parameter: %v", err)
	}
}

// TestSchemaDriftSessionHistory is the schema-drift test of
// cline.cloud.session_history.
func TestSchemaDriftSessionHistory(t *testing.T) {
	h := func(b string) error { _, err := parseSessionHistory(resp([]byte(b))); return err }
	msgs := func(m string) string { return `{"version":1,"messages":[` + m + `]}` }
	expectDrift(t, map[string]error{
		"not json":           h(`<html>`),
		"wrapped in data":    h(`{"data":{"version":1,"messages":[]}}`),
		"version missing":    h(`{"messages":[]}`),
		"version 2":          h(`{"version":2,"messages":[]}`),
		"version quoted":     h(`{"version":"1","messages":[]}`),
		"messages missing":   h(`{"version":1}`),
		"messages object":    h(`{"version":1,"messages":{}}`),
		"role unknown":       h(msgs(`{"role":"system","content":"x"}`)),
		"role missing":       h(msgs(`{"content":"x"}`)),
		"content missing":    h(msgs(`{"role":"user"}`)),
		"content number":     h(msgs(`{"role":"user","content":3}`)),
		"block no type":      h(msgs(`{"role":"user","content":[{"text":"x"}]}`)),
		"ts quoted":          h(msgs(`{"role":"user","content":"x","ts":"1793351521000"}`)),
		"ts negative":        h(msgs(`{"role":"user","content":"x","ts":-1}`)),
		"ts fractional":      h(msgs(`{"role":"user","content":"x","ts":1.5}`)),
		"id repeated":        h(msgs(`{"role":"user","id":"m1","content":"x"},{"role":"assistant","id":"m1","content":"y"}`)),
		"id with slash":      h(msgs(`{"role":"user","id":"a/b","content":"x"}`)),
		"tokens negative":    h(msgs(`{"role":"assistant","content":"x","metrics":{"inputTokens":-1}}`)),
		"tokens fractional":  h(msgs(`{"role":"assistant","content":"x","metrics":{"outputTokens":1.5}}`)),
		"tokens quoted":      h(msgs(`{"role":"assistant","content":"x","metrics":{"inputTokens":"10"}}`)),
		"cost negative":      h(msgs(`{"role":"assistant","content":"x","metrics":{"cost":-0.1}}`)),
		"metrics list":       h(msgs(`{"role":"assistant","content":"x","metrics":[]}`)),
		"tool call no name":  h(msgs(`{"role":"assistant","content":[{"type":"tool_use","id":"t1"}],"ts":1793351530000}`)),
		"modelInfo id typed": h(msgs(`{"role":"assistant","content":"x","modelInfo":{"id":5}}`)),
	})
	noID := resp([]byte(`{"version":1,"messages":[]}`))
	noID.Params = nil
	if _, err := parseSessionHistory(noID); !isDrift(err) {
		t.Errorf("history without a session parameter: %v", err)
	}
}

// TestFixtureSidecarsRecordSource: every fixture sidecar names the package
// version and the cline/cline commit its shape was read from (the
// undocumented-surface rule: provenance is pinned so a drift can be traced).
func TestFixtureSidecarsRecordSource(t *testing.T) {
	for _, s := range []vs.SurfaceID{SurfaceSessions, SurfaceSessionStatus, SurfaceSessionHistory} {
		names, err := filepath.Glob(filepath.Join(fixtureDir(s), "*.source.json"))
		if err != nil || len(names) == 0 {
			t.Fatalf("%s: no sidecars (%v)", s, err)
		}
		for _, n := range names {
			b, err := os.ReadFile(n)
			if err != nil {
				t.Fatal(err)
			}
			var side struct {
				Version string `json:"sdk_or_spec_version_or_commit"`
				Notes   string `json:"notes"`
			}
			if err := json.Unmarshal(b, &side); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(side.Version, "0.2.0") || !strings.Contains(side.Version, SourceCommit) ||
				!strings.Contains(side.Notes, "Observed in vendor client, undocumented") {
				t.Errorf("%s: sidecar does not record the version, the commit and the coverage level", n)
			}
		}
	}
}

// TestDriversContract pins the three drivers to their catalog rows and
// corpus ledgers (node-consumed: they have no org driver-table entry).
func TestDriversContract(t *testing.T) {
	for _, d := range []vendorapi.Driver{Sessions(), SessionStatus(), SessionHistory()} {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != Tool || d.Auth.Scheme != vendorapi.SchemeBearer {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestConformance runs the shared conformance suite against the three
// drivers through the pure adapter.
func TestConformance(t *testing.T) {
	for _, d := range []vendorapi.Driver{Sessions(), SessionStatus(), SessionHistory()} {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) { vendormock.RunPure(t, d, testParams, vendorapi.Window{}) })
	}
}
