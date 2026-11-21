package cursor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/vendormock"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

const testAgent = "bc-00000000-0000-0000-0000-000000000001"

func cloudFixture(t *testing.T, surface vs.SurfaceID, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vendorapi", "cursor", string(surface), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cloudResp(body []byte, cursor string) vendorapi.Response {
	return vendorapi.Response{
		Status: 200, Origin: "https://api.cursor.com:443", Body: body, Cursor: cursor,
		Params: vendorapi.Params{ParamAgentID: testAgent},
	}
}

// TestCloudAgentsParseCorpus: the documented List Agents example lands one
// cursor.cloud_agent snapshot keyed by the bc- id, with the next cursor.
func TestCloudAgentsParseCorpus(t *testing.T) {
	p, err := parseCloudAgents(cloudResp(cloudFixture(t, SurfaceCloudAgents, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 1 || p.NextCursor != "bc-00000000-0000-0000-0000-000000000002" {
		t.Fatalf("snapshots %d next %q", len(p.Snapshots), p.NextCursor)
	}
	s := p.Snapshots[0]
	want := map[string]string{
		"status": "ACTIVE", "created_at": "2026-04-13T18:30:00Z", "updated_at": "2026-04-13T18:45:00Z",
		"name": "Add README with setup instructions", "env_type": "cloud",
		"url":           "https://cursor.com/agents/bc-00000000-0000-0000-0000-000000000001",
		"latest_run_id": "run-00000000-0000-0000-0000-000000000001",
	}
	if s.Class != CloudAgentClass || s.Subject != testAgent || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	last, err := parseCloudAgents(cloudResp([]byte(`{"items":[]}`), "c1"))
	if err != nil || last.NextCursor != "" || len(last.Snapshots) != 0 {
		t.Fatalf("last page %+v %v", last, err)
	}
}

func TestCloudAgentRunsParseCorpus(t *testing.T) {
	p, err := parseCloudAgentRuns(cloudResp(cloudFixture(t, SurfaceCloudAgentRuns, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 1 || p.NextCursor != "" {
		t.Fatalf("snapshots %d next %q", len(p.Snapshots), p.NextCursor)
	}
	s := p.Snapshots[0]
	if s.Class != CloudAgentRunClass || s.Subject != "run-00000000-0000-0000-0000-000000000002" ||
		s.Body["agent_id"] != testAgent || s.Body["status"] != "RUNNING" || s.Body["branch"] != "cursor/add-readme-a1b2" ||
		s.Body["repo_url"] != "github.com/your-org/your-repo" || s.Body["branch_count"] != "1" ||
		s.Body["created_at"] != "2026-04-13T18:50:00Z" {
		t.Fatalf("snapshot %+v", s)
	}
}

// TestCloudAgentUsageParseCorpus: the agent total and each run land as
// token snapshots in native units; SourceRecords counts the runs.
func TestCloudAgentUsageParseCorpus(t *testing.T) {
	p, err := parseCloudAgentUsage(cloudResp(cloudFixture(t, SurfaceCloudAgentUsage, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 3 || p.SourceRecords != 2 {
		t.Fatalf("snapshots %d records %d", len(p.Snapshots), p.SourceRecords)
	}
	tot := p.Snapshots[0]
	if tot.Class != CloudAgentUsageClass || tot.Subject != testAgent || tot.Body["input"] != "12480" ||
		tot.Body["output"] != "3110" || tot.Body["cache_write"] != "18200" || tot.Body["cache_read"] != "42600" ||
		tot.Body["total"] != "76390" || tot.Body["unit"] != "tokens" || tot.Body["run_count"] != "2" {
		t.Fatalf("total %+v", tot)
	}
	r0 := p.Snapshots[1]
	if r0.Class != CloudAgentRunUsageClass || r0.Subject != "run-00000000-0000-0000-0000-000000000002" ||
		r0.Body["usage_uuid"] != "00000000-0000-0000-0000-000000000002" || r0.Body["input"] != "6320" ||
		r0.Body["agent_id"] != testAgent {
		t.Fatalf("run 0 %+v", r0)
	}
	// An absent count stays absent, never zero.
	q, err := parseCloudAgentUsage(cloudResp([]byte(`{"totalUsage":{"inputTokens":5},"runs":[]}`), ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := q.Snapshots[0].Body["output"]; ok || q.Snapshots[0].Body["input"] != "5" {
		t.Fatalf("absent count %+v", q.Snapshots[0])
	}
}

// TestCloudAgentUsageCost: the live-verified (2026-11-01) cost object on the
// agent and on each run is kept as the vendor's decimal text, one key per
// amount; an absent amount stays absent, a malformed one is drift.
func TestCloudAgentUsageCost(t *testing.T) {
	body := `{"totalUsage":{"inputTokens":10,"totalTokens":10},"cost":{"rawCostCents":14.24463,"chargedCents":0},
	 "runs":[{"id":"run-1","usageUuid":"u-1","usage":{"inputTokens":10},"cost":{"rawCostCents":6.19843,"chargedCents":0}},
	         {"id":"run-2","usage":{"inputTokens":0},"cost":{"rawCostCents":1.5}},
	         {"id":"run-3","usage":{"inputTokens":0}}]}`
	p, err := parseCloudAgentUsage(cloudResp([]byte(body), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	cases := []struct {
		snap          int
		raw, charged  string
		hasRaw, hasCh bool
	}{
		{0, "14.24463", "0", true, true},
		{1, "6.19843", "0", true, true},
		{2, "1.5", "", true, false},
		{3, "", "", false, false},
	}
	for _, tc := range cases {
		b := p.Snapshots[tc.snap].Body
		raw, okR := b["raw_cost_cents"]
		ch, okC := b["charged_cents"]
		if okR != tc.hasRaw || okC != tc.hasCh || raw != tc.raw || ch != tc.charged {
			t.Errorf("snapshot %d: %+v", tc.snap, b)
		}
	}
}

func TestCloudAgentBuildContract(t *testing.T) {
	cases := []struct {
		name   string
		build  func(vendorapi.Params, vendorapi.Window, string) (vendorapi.Request, error)
		params vendorapi.Params
		cursor string
		path   string
		query  map[string]string
	}{
		{"agents first", buildCloudAgents, nil, "", "/v1/agents", map[string]string{"limit": "100"}},
		{"agents next", buildCloudAgents, nil, "bc-x", "/v1/agents", map[string]string{"limit": "100", "cursor": "bc-x"}},
		{
			"runs", buildCloudAgentRuns,
			vendorapi.Params{ParamAgentID: testAgent},
			"", "/v1/agents/" + testAgent + "/runs",
			map[string]string{"limit": "100"},
		},
		{"usage", buildCloudAgentUsage, vendorapi.Params{ParamAgentID: testAgent}, "", "/v1/agents/" + testAgent + "/usage", nil},
	}
	for _, c := range cases {
		req, err := c.build(c.params, vendorapi.Window{}, c.cursor)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if req.Method != "GET" || req.Path != c.path || len(req.Query) != len(c.query) || req.Body != nil {
			t.Fatalf("%s: request %+v", c.name, req)
		}
		for k, v := range c.query {
			if got := req.Query[k]; len(got) != 1 || got[0] != v {
				t.Errorf("%s: query %s = %v, want %s", c.name, k, got, v)
			}
		}
	}
	refused := []struct {
		name   string
		build  func(vendorapi.Params, vendorapi.Window, string) (vendorapi.Request, error)
		params vendorapi.Params
		cursor string
	}{
		{"bad cursor", buildCloudAgents, nil, "bad cursor!"},
		{"runs without agent", buildCloudAgentRuns, nil, ""},
		{"runs path injection", buildCloudAgentRuns, vendorapi.Params{ParamAgentID: "bc-x/../../teams"}, ""},
		{"usage foreign id", buildCloudAgentUsage, vendorapi.Params{ParamAgentID: "run-1"}, ""},
		{"usage paged", buildCloudAgentUsage, vendorapi.Params{ParamAgentID: testAgent}, "x"},
	}
	for _, c := range refused {
		if _, err := c.build(c.params, vendorapi.Window{}, c.cursor); err == nil {
			t.Errorf("%s: build accepted", c.name)
		}
	}
}

// TestCloudAgentFieldPolicy (plan 12A.5): a missing required field, a wrong
// JSON type, a repeated key, a bad timestamp, a foreign agent, a negative or
// quoted count, a non-200 status and a repeating cursor fail as drift.
func TestCloudAgentFieldPolicy(t *testing.T) {
	agents := func(b, cur string) error { _, err := parseCloudAgents(cloudResp([]byte(b), cur)); return err }
	runs := func(b string) error { _, err := parseCloudAgentRuns(cloudResp([]byte(b), "")); return err }
	usage := func(b string) error { _, err := parseCloudAgentUsage(cloudResp([]byte(b), "")); return err }
	okAgent := `{"id":"bc-1","status":"ACTIVE","createdAt":"2026-04-13T18:30:00Z"}`
	okRun := `{"id":"run-1","agentId":"` + testAgent + `","status":"FINISHED","createdAt":"2026-04-13T18:30:00Z"}`
	cases := map[string]error{
		"agents container missing": agents(`{"agents":[]}`, ""),
		"agents items not array":   agents(`{"items":{}}`, ""),
		"agent id foreign":         agents(`{"items":[{"id":"x1","status":"ACTIVE","createdAt":"2026-04-13T18:30:00Z"}]}`, ""),
		"agent repeated":           agents(`{"items":[`+okAgent+`,`+okAgent+`]}`, ""),
		"agent status missing":     agents(`{"items":[{"id":"bc-1","createdAt":"2026-04-13T18:30:00Z"}]}`, ""),
		"agent bad time":           agents(`{"items":[{"id":"bc-1","status":"A","createdAt":"yesterday"}]}`, ""),
		"agent cursor repeats":     agents(`{"items":[],"nextCursor":"c1"}`, "c1"),
		"agent cursor not string":  agents(`{"items":[],"nextCursor":7}`, ""),
		"runs foreign agent":       runs(`{"items":[{"id":"run-1","agentId":"bc-2","status":"F","createdAt":"2026-04-13T18:30:00Z"}]}`),
		"runs repeated":            runs(`{"items":[` + okRun + `,` + okRun + `]}`),
		"runs missing agentId":     runs(`{"items":[{"id":"run-1","status":"F","createdAt":"2026-04-13T18:30:00Z"}]}`),
		"usage runs missing":       usage(`{"totalUsage":{}}`),
		"usage total missing":      usage(`{"runs":[]}`),
		"usage negative":           usage(`{"totalUsage":{"inputTokens":-1},"runs":[]}`),
		"usage quoted number":      usage(`{"totalUsage":{"inputTokens":"5"},"runs":[]}`),
		"usage run without usage":  usage(`{"totalUsage":{},"runs":[{"id":"run-1"}]}`),
		"usage negative cost":      usage(`{"totalUsage":{},"cost":{"rawCostCents":-1},"runs":[]}`),
		"usage quoted cost":        usage(`{"totalUsage":{},"cost":{"chargedCents":"0"},"runs":[]}`),
		"usage run cost absurd":    usage(`{"totalUsage":{},"runs":[{"id":"run-1","usage":{},"cost":{"chargedCents":1e300}}]}`),
	}
	for name, err := range cases {
		if err == nil || !errors.Is(err, vendorapi.ErrSchemaDrift) {
			t.Errorf("%s: err %v, want schema drift", name, err)
		}
	}
	if _, err := parseCloudAgents(vendorapi.Response{Status: 500, Body: []byte(`{}`)}); !errors.Is(err, vendorapi.ErrSchemaDrift) {
		t.Errorf("non-200: %v", err)
	}
}

// TestCloudAgentDriversContract pins the three drivers to their catalog rows
// and corpus ledgers (the org driver-table test does this for table entries;
// these drivers are node-consumed and are not in that table).
func TestCloudAgentDriversContract(t *testing.T) {
	for _, d := range []vendorapi.Driver{CloudAgents(), CloudAgentRuns(), CloudAgentUsage()} {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != Tool || d.Auth.Scheme != vendorapi.SchemeBasicUser || d.MaxWindow != 0 {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestCloudAgentConformance runs the shared conformance suite against each
// driver through the pure adapter.
func TestCloudAgentConformance(t *testing.T) {
	params := vendorapi.Params{ParamAgentID: testAgent}
	for _, d := range []vendorapi.Driver{CloudAgents(), CloudAgentRuns(), CloudAgentUsage()} {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) { vendormock.RunPure(t, d, params, vendorapi.Window{}) })
	}
}
