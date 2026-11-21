package warp

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

const (
	runClaude = "7c1e2a40-0000-4000-8000-000000000001"
	runCodex  = "7c1e2a40-0000-4000-8000-000000000002"
	runOz     = "7c1e2a40-0000-4000-8000-000000000003"
)

func fixture(t *testing.T, surface vs.SurfaceID, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vendorapi", "warp", string(surface), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resp(body []byte, cursor, run string) vendorapi.Response {
	return vendorapi.Response{
		Status: 200, Origin: "https://app.warp.dev:443", Body: body, Cursor: cursor,
		Params: vendorapi.Params{ParamRunID: run},
	}
}

func isDrift(err error) bool { return err != nil && errors.Is(err, vendorapi.ErrSchemaDrift) }

func usageOf(p vendorapi.Page, ns, run string) (vendorapi.UsageRow, bool) {
	for _, u := range p.Usage {
		if u.JoinNamespace == ns && u.JoinValue == run {
			return u, true
		}
	}
	return vendorapi.UsageRow{}, false
}

// TestRunsListParseCorpus: one snapshot per run with the harness (stated or
// the documented oz default), lineage and pull request; credits and USD as
// two rows, never summed together; no prompt, title or e-mail decoded.
func TestRunsListParseCorpus(t *testing.T) {
	p, err := parseRunsList(resp(fixture(t, SurfaceRunsList, "normal_page.json"), "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 3 || p.SourceRecords != 3 || p.NextCursor != "synthRunsCursor0002" || len(p.Usage) != 6 {
		t.Fatalf("snapshots %d records %d next %q usage %d", len(p.Snapshots), p.SourceRecords, p.NextCursor, len(p.Usage))
	}
	s := p.Snapshots[0]
	want := map[string]string{
		"created_at": "2026-10-30T09:00:00Z", "updated_at": "2026-10-30T09:21:40Z", "state": "succeeded",
		"started_at": "2026-10-30T09:01:05Z", "finished_at": "2026-10-30T09:21:15Z",
		"execution_location": "REMOTE", "source": "API", "conversation_id": "9a4f7c21-0000-4000-8000-0000000000c1",
		"root_run_id": runClaude, "creator_type": "user", "creator_uid": "synthUserUid0001",
		"model_id": "claude-sonnet-4-5", "environment_id": "SynthEnvironment00001a",
		"harness": "claude", "harness_source": HarnessStated,
		"pr_url": "https://github.com/acme/widget/pull/42", "pr_branch": "warp/fix-flaky-auth", "pr_count": "1",
	}
	if s.Class != RunClass || s.Subject != runClaude || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	for _, sn := range p.Snapshots {
		for k, v := range sn.Body {
			if strings.Contains(v, "Fix the flaky") || strings.Contains(v, "example.com") || strings.Contains(v, "Synthetic User") {
				t.Fatalf("content or an e-mail leaked into %s=%s", k, v)
			}
		}
	}
	cr, ok := usageOf(p, CreditsNamespace, runClaude)
	if !ok || cr.ChargedUnit != UnitCredit || cr.ChargedMicros != 54_750_000 || cr.Flags["inference_micros"] != "41500000" ||
		cr.IdentityKind != "user_uid" || cr.Identity != "synthUserUid0001" || cr.Revision != unixOf(t, s.Body["updated_at"]) {
		t.Fatalf("credits %+v", cr)
	}
	usd, ok := usageOf(p, USDNamespace, runClaude)
	if !ok || usd.ChargedUnit != UnitUSD || usd.ChargedMicros != 547_500 || usd.Model != "claude-sonnet-4-5" {
		t.Fatalf("usd %+v", usd)
	}
	codex := p.Snapshots[1]
	if codex.Body["harness"] != "codex" || codex.Body["parent_run_id"] != runClaude || codex.Body["model_id"] != "gpt-5.6" ||
		codex.Body["finished_at"] != "" || codex.Body["creator_type"] != "service_account" {
		t.Fatalf("codex snapshot %+v", codex)
	}
	if u, _ := usageOf(p, CreditsNamespace, runCodex); u.ChargedMicros != 12_000_000 || u.IdentityKind != "service_account_uid" ||
		len(u.Flags) != 1 {
		t.Fatalf("codex credits %+v", u)
	}
	oz := p.Snapshots[2]
	if oz.Body["harness"] != HarnessOz || oz.Body["harness_source"] != HarnessDefaulted || oz.Body["model_id"] != "auto" {
		t.Fatalf("oz snapshot %+v", oz)
	}
	last, err := parseRunsList(resp(fixture(t, SurfaceRunsList, "last_page.json"), "synthRunsCursor0002", ""))
	if err != nil || last.NextCursor != "" || len(last.Snapshots) != 1 || len(last.Usage) != 0 ||
		last.Snapshots[0].Body["harness"] != HarnessOz || last.Snapshots[0].Body["harness_source"] != HarnessStated {
		t.Fatalf("last page %+v %v", last, err)
	}
}

// unixOf reads a snapshot body time as unix seconds.
func unixOf(t *testing.T, v string) int64 {
	t.Helper()
	at, err := time.Parse(time.RFC3339, v)
	if err != nil {
		t.Fatal(err)
	}
	return at.Unix()
}

func TestRunDetailParseCorpus(t *testing.T) {
	p, err := parseRunDetail(resp(fixture(t, SurfaceRunDetail, "normal_page.json"), "", runClaude))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatal(err)
	}
	if len(p.Snapshots) != 1 || p.Snapshots[0].Body["worker_host"] != "warp" || p.Snapshots[0].Body["harness"] != "claude" ||
		len(p.Usage) != 2 {
		t.Fatalf("detail %+v", p)
	}
	if _, err := parseRunDetail(resp(fixture(t, SurfaceRunDetail, "normal_page.json"), "", runCodex)); !isDrift(err) {
		t.Fatalf("a detail answering another run: %v", err)
	}
}

// TestConversationParseCorpus: user and assistant text as content, actions
// and results as metadata events (never their input or output), nested
// steps walked.
func TestConversationParseCorpus(t *testing.T) {
	p, err := parseConversation(resp(fixture(t, SurfaceConversation, "normal_page.json"), "", runClaude))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Content) != 2 || len(p.Audit) != 4 || p.SourceRecords != 1 {
		t.Fatalf("content %d audit %d records %d", len(p.Content), len(p.Audit), p.SourceRecords)
	}
	if c := p.Content[0]; c.ItemID != "msg-synth-0001" || c.Role != "prompt" || c.SessionRef != runClaude ||
		!c.At.Equal(time.Date(2026, 10, 30, 9, 1, 10, 0, time.UTC)) {
		t.Fatalf("prompt %+v", c)
	}
	if c := p.Content[1]; c.Role != "response" || c.Text != "I will run the test first." {
		t.Fatalf("response %+v", c)
	}
	call, res, edit, ev := p.Audit[0], p.Audit[1], p.Audit[2], p.Audit[3]
	if call.Action != ActionToolCall || call.Target != "run_command" || call.EventID != "act-synth-0001" ||
		call.AgentSessionID != runClaude || !call.ActorIsAgent || call.Detail["category"] != "command" {
		t.Fatalf("call %+v", call)
	}
	if res.Action != ActionToolResult || res.Detail["state"] != "failed" || res.Detail["action_id"] != "act-synth-0001" || res.ActorIsAgent {
		t.Fatalf("result %+v", res)
	}
	if edit.Target != "edit_files" || ev.Action != ActionEvent || ev.Target != "context_compaction" {
		t.Fatalf("nested %+v %+v", edit, ev)
	}
	for _, e := range p.Audit {
		for k, v := range e.Detail {
			if strings.Contains(v, "go test") || strings.Contains(v, "helper_test") || k == "command" {
				t.Fatalf("an action body leaked: %s=%s", k, v)
			}
		}
	}
	// A message with no timestamp takes its step's start; with neither it
	// is not landed.
	noTime := `{"conversation_id":"c1","steps":[{"id":"s1","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],"steps":[]},
		{"id":"s2","started_at":"2026-10-30T09:00:00Z","messages":[{"role":"user","content":[{"type":"text","text":"yo"}]}],"steps":[]}]}`
	q, err := parseConversation(resp([]byte(noTime), "", runClaude))
	if err != nil || len(q.Content) != 1 || q.SourceRecords != 2 || q.Content[0].ItemID != "step:s2:0" {
		t.Fatalf("time fallback %+v %v", q, err)
	}
}

// TestHarnessUsageParseCorpus: native counters as reported (Codex input
// still includes cached input; netting is the consumer's), absent counters
// named, an unavailable read lands no usage row.
func TestHarnessUsageParseCorpus(t *testing.T) {
	p, err := parseHarnessUsage(resp(fixture(t, SurfaceHarnessUsage, "normal_page.json"), "", runClaude))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatal(err)
	}
	if len(p.Usage) != 1 || len(p.Snapshots) != 1 {
		t.Fatalf("claude %+v", p)
	}
	u := p.Usage[0]
	if u.InputTokens != 1840 || u.OutputTokens != 6120 || u.CacheReadTokens != 150200 || u.CacheWriteTokens != 21400 ||
		u.ReasoningTokens != 0 || u.Revision != 12 || u.Model != "claude-sonnet-4-5" || u.Flags[FlagCache1h] != "1400" ||
		u.Flags[FlagInputBasis] != BasisNetOfCache || u.Flags[FlagHarness] != "claude_code" || u.Flags[FlagAbsent] != "" ||
		!u.At.Equal(time.Date(2026, 10, 30, 9, 21, 10, 0, time.UTC)) {
		t.Fatalf("claude usage %+v", u)
	}
	c, err := parseHarnessUsage(resp(fixture(t, SurfaceHarnessUsage, "enum_sweep.json"), "", runCodex))
	if err != nil || len(c.Usage) != 1 {
		t.Fatalf("codex %+v %v", c, err)
	}
	cu := c.Usage[0]
	if cu.InputTokens != 64000 || cu.CacheReadTokens != 48000 || cu.OutputTokens != 3000 || cu.ReasoningTokens != 1200 ||
		cu.CacheWriteTokens != 0 || cu.Flags[FlagAbsent] != "cache_write" || cu.Flags[FlagInputBasis] != BasisIncludesCached ||
		cu.Flags[FlagOutputBasis] != BasisIncludesReasoning || cu.Flags[FlagCoverage] != "partial" || cu.Model != "" {
		t.Fatalf("codex usage %+v", cu)
	}
	n, err := parseHarnessUsage(resp(fixture(t, SurfaceHarnessUsage, "nulls_and_absent.json"), "", "7c1e2a40-0000-4000-8000-000000000004"))
	if err != nil || len(n.Usage) != 0 || len(n.Snapshots) != 1 || n.Snapshots[0].Body["available"] != "false" {
		t.Fatalf("unavailable %+v %v", n, err)
	}
	unk := `{"run_id":"r1","conversation_id":"c","available":true,"usage":{"metricsVersion":1,"harness":"CODEX","executionId":1,
		"captureSequence":1,"capturedAt":"2026-10-30T09:00:00Z","snapshot":{"coverage":{"tokenStatus":"unavailable","toolStatus":"unavailable"},
		"payload":{"usage":{"input_tokens":5}}}}}`
	if q, err := parseHarnessUsage(resp([]byte(unk), "", "r1")); err != nil || len(q.Usage) != 0 {
		t.Fatalf("tokenStatus unavailable landed usage: %+v %v", q, err)
	}
	empty := strings.Replace(unk, `"tokenStatus":"unavailable"`, `"tokenStatus":"known"`, 1)
	empty = strings.Replace(empty, `{"input_tokens":5}`, `{"input_tokens":null}`, 1)
	if q, err := parseHarnessUsage(resp([]byte(empty), "", "r1")); err != nil || len(q.Usage) != 0 {
		t.Fatalf("all-null counters landed usage: %+v %v", q, err)
	}
}

func TestBuildContract(t *testing.T) {
	from := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	w := vendorapi.Window{From: from, To: from.Add(48 * time.Hour)}
	req, err := buildRunsList(nil, w, "")
	if err != nil || req.Method != "GET" || req.Path != "/api/v1/agent/runs" || req.Query["limit"][0] != "100" ||
		req.Query["execution_location"][0] != "REMOTE" || req.Query["updated_after"][0] != "2026-10-29T00:00:00Z" ||
		req.Query["sort_by"][0] != "updated_at" || req.Query["sort_order"][0] != "desc" || req.Query["cursor"] != nil {
		t.Fatalf("list request %+v %v", req, err)
	}
	all, err := buildRunsList(nil, vendorapi.Window{}, "synthRunsCursor0002")
	if err != nil || all.Query["updated_after"] != nil || all.Query["cursor"][0] != "synthRunsCursor0002" ||
		all.Query["execution_location"][0] != "REMOTE" {
		t.Fatalf("unwindowed request %+v %v", all, err)
	}
	p := vendorapi.Params{ParamRunID: runClaude}
	for _, c := range []struct {
		build func(vendorapi.Params, vendorapi.Window, string) (vendorapi.Request, error)
		path  string
	}{{buildRunDetail, ""}, {buildConversation, "/conversation"}, {buildHarnessUsage, "/harness-usage"}} {
		build, path := c.build, c.path
		r, err := build(p, vendorapi.Window{}, "")
		if err != nil || r.Path != "/api/v1/agent/runs/"+runClaude+path || len(r.Query) != 0 {
			t.Errorf("per-run request %+v %v", r, err)
		}
	}
	for name, err := range map[string]error{
		"list half window":   errOf(buildRunsList(nil, vendorapi.Window{From: from}, "")),
		"list bad cursor":    errOf(buildRunsList(nil, vendorapi.Window{}, "bad cursor!")),
		"detail no id":       errOf(buildRunDetail(nil, vendorapi.Window{}, "")),
		"usage traversal":    errOf(buildHarnessUsage(vendorapi.Params{ParamRunID: "../x"}, vendorapi.Window{}, "")),
		"conversation slash": errOf(buildConversation(vendorapi.Params{ParamRunID: "a/b"}, vendorapi.Window{}, "")),
	} {
		if err == nil {
			t.Errorf("%s: build accepted", name)
		}
	}
}

func errOf(_ vendorapi.Request, err error) error { return err }

// TestFieldPolicyMatrix (plan 12A.5): missing required fields, wrong JSON
// types, repeated records, bad timestamps, negative or quoted amounts and a
// paging contract break fail the page as schema drift.
func TestFieldPolicyMatrix(t *testing.T) {
	list := func(b, cur string) error { _, err := parseRunsList(resp([]byte(b), cur, "")); return err }
	wrap := func(runs string) string {
		return `{"runs":[` + runs + `],"page_info":{"has_next_page":false},"as_of":"2026-10-30T09:00:00Z","team_uid":null}`
	}
	okRun := `{"run_id":"r1","state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z"}`
	withUsage := func(u string) string {
		return wrap(`{"run_id":"r1","state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z","request_usage":` + u + `}`)
	}
	conv := func(b string) error { _, err := parseConversation(resp([]byte(b), "", "r1")); return err }
	hu := func(b string) error { _, err := parseHarnessUsage(resp([]byte(b), "", "r1")); return err }
	huEnv := func(env string) string {
		return `{"run_id":"r1","conversation_id":"c","available":true,"usage":` + env + `}`
	}
	for name, err := range map[string]error{
		"runs missing":           list(`{"page_info":{"has_next_page":false}}`, ""),
		"page info missing":      list(`{"runs":[]}`, ""),
		"flag quoted":            list(`{"runs":[],"page_info":{"has_next_page":"false"}}`, ""),
		"more without cursor":    list(`{"runs":[],"page_info":{"has_next_page":true}}`, ""),
		"cursor repeats":         list(`{"runs":[],"page_info":{"has_next_page":true,"next_cursor":"c1"}}`, "c1"),
		"run id missing":         list(wrap(`{"state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z"}`), ""),
		"run repeated":           list(wrap(okRun+","+okRun), ""),
		"state missing":          list(wrap(`{"run_id":"r1","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z"}`), ""),
		"bad created":            list(wrap(`{"run_id":"r1","state":"QUEUED","created_at":"yesterday","updated_at":"2026-10-30T09:00:00Z"}`), ""),
		"bad finished":           list(wrap(`{"run_id":"r1","state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z","finished_at":7}`), ""),
		"credits negative":       list(withUsage(`{"inference_cost":-1}`), ""),
		"usd quoted":             list(withUsage(`{"inference_cost_usd":"0.1"}`), ""),
		"pr without url":         list(wrap(`{"run_id":"r1","state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:00:00Z","artifacts":[{"artifact_type":"PULL_REQUEST","data":{"branch":"b"}}]}`), ""),
		"conv steps missing":     conv(`{"conversation_id":"c1"}`),
		"conv id missing":        conv(`{"steps":[]}`),
		"step messages missing":  conv(`{"conversation_id":"c1","steps":[{"id":"s1","steps":[]}]}`),
		"message role missing":   conv(`{"conversation_id":"c1","steps":[{"id":"s1","messages":[{"content":[]}],"steps":[]}]}`),
		"block type unknown":     conv(`{"conversation_id":"c1","steps":[{"id":"s1","messages":[{"role":"user","timestamp":"2026-10-30T09:00:00Z","content":[{"type":"image"}]}],"steps":[]}]}`),
		"action without id":      conv(`{"conversation_id":"c1","steps":[{"id":"s1","messages":[{"role":"assistant","timestamp":"2026-10-30T09:00:00Z","content":[{"type":"action","name":"run_command"}]}],"steps":[]}]}`),
		"action repeated":        conv(`{"conversation_id":"c1","steps":[{"id":"s1","messages":[{"role":"assistant","timestamp":"2026-10-30T09:00:00Z","content":[{"type":"action","id":"a","name":"x"},{"type":"action","id":"a","name":"x"}]}],"steps":[]}]}`),
		"usage available absent": hu(`{"run_id":"r1","conversation_id":"c"}`),
		"usage other run":        hu(`{"run_id":"r2","conversation_id":"c","available":false}`),
		"envelope unknown":       hu(huEnv(`{"harness":"GEMINI","captureSequence":1,"capturedAt":"2026-10-30T09:00:00Z","snapshot":{"coverage":{"tokenStatus":"known"},"payload":{}}}`)),
		"counter negative":       hu(huEnv(`{"harness":"CODEX","captureSequence":1,"capturedAt":"2026-10-30T09:00:00Z","snapshot":{"coverage":{"tokenStatus":"known"},"payload":{"usage":{"input_tokens":-1}}}}`)),
		"counter fractional":     hu(huEnv(`{"harness":"CODEX","captureSequence":1,"capturedAt":"2026-10-30T09:00:00Z","snapshot":{"coverage":{"tokenStatus":"known"},"payload":{"usage":{"input_tokens":1.5}}}}`)),
		"captured at bad":        hu(huEnv(`{"harness":"CODEX","captureSequence":1,"capturedAt":"now","snapshot":{"coverage":{"tokenStatus":"known"},"payload":{}}}`)),
	} {
		if !isDrift(err) {
			t.Errorf("%s: err %v, want schema drift", name, err)
		}
	}
	if _, err := parseRunsList(vendorapi.Response{Status: 500, Body: []byte(`{}`)}); !isDrift(err) {
		t.Errorf("non-200: %v", err)
	}
	noRun := resp([]byte(`{"conversation_id":"c1","steps":[]}`), "", "")
	if _, err := parseConversation(noRun); !isDrift(err) {
		t.Errorf("conversation without a run parameter: %v", err)
	}
}

func drivers() []vendorapi.Driver {
	return []vendorapi.Driver{RunsList(), RunDetail(), RunConversation(), RunHarnessUsage()}
}

// TestDriversContract pins every driver to its catalog row and corpus
// ledgers (node-consumed: they have no org driver-table entry).
func TestDriversContract(t *testing.T) {
	for _, d := range drivers() {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Auth.Scheme != vendorapi.SchemeBearer || d.Tool != "" {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestConformance runs the shared conformance suite against every driver
// through the pure adapter.
func TestConformance(t *testing.T) {
	for _, d := range drivers() {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) {
			vendormock.RunPure(t, d, vendorapi.Params{ParamRunID: runClaude}, vendorapi.Window{})
		})
	}
}
