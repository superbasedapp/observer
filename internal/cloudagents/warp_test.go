package cloudagents

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Lane CA-V1: the warp-cloud connector over the lane's own driver fixtures
// (testdata/vendorapi/warp, built from Warp's OpenAPI at docs commit
// 4aa3f12). Documented, not live-verified (CA-D17).

const (
	warpRunClaude = "7c1e2a40-0000-4000-8000-000000000001"
	warpRunCodex  = "7c1e2a40-0000-4000-8000-000000000002"
	warpRunOz     = "7c1e2a40-0000-4000-8000-000000000003"
)

func warpList(t *testing.T) map[string]Task {
	t.Helper()
	c := mustConn(t, ConnectorWarpCloud)
	p, err := ParseAPIList(c, nil, "", vendorFixture(t, "warp/warp.agent_api.runs_list/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Cursor != "synthRunsCursor0002" {
		t.Fatalf("cursor %q", p.Cursor)
	}
	out := map[string]Task{}
	for _, task := range p.Tasks {
		out[task.ID] = task
	}
	return out
}

func TestWarpConnectorRow(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	if c.Kind != SourceAPI || c.Auth != AuthBearer || len(c.APIHosts) != 1 || c.APIHosts[0] != "app.warp.dev" ||
		c.Tool != "" || c.SurfaceHost != SurfaceHostWarpCloud || !c.ServerWindow || !c.History || c.KeyLabel == "" {
		t.Fatalf("row %+v", c)
	}
	if !strings.Contains(c.KeyLabel, "Settings > Platform > API Keys") {
		t.Errorf("key label %q does not say where the key is created", c.KeyLabel)
	}
	r, err := APIListRequest(c, nil, time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Auth != AuthBearer || !strings.HasPrefix(r.URL, "https://app.warp.dev/api/v1/agent/runs?") ||
		!strings.Contains(r.URL, "execution_location=REMOTE") || !strings.Contains(r.URL, "updated_after=2026-10-30T00%3A00%3A00Z") {
		t.Fatalf("list request %+v", r)
	}
	for kind, path := range map[string]func() (Request, error){
		"/harness-usage": func() (Request, error) { return APIDetailRequest(c, DetailHarnessUsage, warpRunClaude) },
		"/conversation": func() (Request, error) {
			return APIHistoryRequest(c, nil, warpRunClaude, "", time.Time{}, time.Time{})
		},
	} {
		req, err := path()
		if err != nil || req.URL != "https://app.warp.dev/api/v1/agent/runs/"+warpRunClaude+kind {
			t.Errorf("%s request %+v %v", kind, req, err)
		}
	}
	for _, r := range APIOps() {
		if r.Connector == ConnectorWarpCloud && strings.Contains(r.URL, "/transcript") {
			t.Fatalf("the transcript route is never fetched: %s", r.URL)
		}
	}
}

// TestWarpHarnessClaude: a Claude Code harness run lands under tool
// claude-code, its conversation id as the second reference, its pull
// request's repository as the project, credits and USD as two ledger rows.
func TestWarpHarnessClaude(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	task := warpList(t)[warpRunClaude]
	cc, ok := ForTask(c, task)
	if !ok || cc.Tool != models.ToolClaudeCode || task.Harness != "claude" {
		t.Fatalf("tool %q harness %q", cc.Tool, task.Harness)
	}
	if task.VendorRef != "9a4f7c21-0000-4000-8000-0000000000c1" || task.Lifecycle != LifecycleSucceeded ||
		task.RepoRemote != "github.com/acme/widget" || task.PullRequestNumber != 42 || task.User != "synthUserUid0001" ||
		!task.CompletedAt.Equal(time.Date(2026, 10, 30, 9, 21, 15, 0, time.UTC)) || task.ParentID != "" {
		t.Fatalf("task %+v", task)
	}
	if ex := Execution(task.ID, task); ex.ExecutionLocation != models.ExecutionVendorCloud || ex.VendorSessionRef != task.VendorRef {
		t.Fatalf("execution %+v", ex)
	}
	if s := Surface(cc, task.ID); len(s) != 1 || s[0].SurfaceHost != "warp-cloud" || s[0].Surface != "" {
		t.Fatalf("surface %+v", s)
	}
	ev := MapEvents(cc, task, task.ID, "/repo")
	if len(ev) != 2 || ev[0].Tool != models.ToolClaudeCode || ev[0].SourceFile != "cloud-agents/warp-cloud" {
		t.Fatalf("events %+v", ev)
	}
	led := MapLedger(cc, task, task.ID, KeychainKeyAccount)
	if len(led) != 2 {
		t.Fatalf("ledger %+v", led)
	}
	units := map[string]LedgerEntry{}
	for _, l := range led {
		units[l.Unit] = l
	}
	cr, usd := units["warp_credit"], units["usd"]
	if cr.Value != 54.75 || cr.MonetaryStatus != models.UsageMonetaryNone || cr.ValueType != models.UsageValueCumulative ||
		cr.MeasurementSource != models.UsageSourceProviderRunTotal || cr.IncludesChildren != nil {
		t.Fatalf("credits %+v", cr)
	}
	if usd.Value != 0.5475 || usd.MonetaryStatus != models.UsageMonetaryReported || usd.ScopeModel != "claude-sonnet-4-5" {
		t.Fatalf("usd %+v", usd)
	}
	if dl := DeliveryLinks(task); len(dl) != 1 || dl[0].Remote != "github.com/acme/widget" || dl[0].PRNumber != 42 {
		t.Fatalf("delivery %+v", dl)
	}
	// Harness usage: Claude Code counters as reported, the 1h split kept.
	got, err := ApplyAPIDetail(c, DetailHarnessUsage, task, vendorFixture(t, "warp/warp.agent_api.run_harness_usage/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := got.Tokens
	if f == nil || f.Kind != TokenFromProviderRunTotal || f.Input != 1840 || f.Output != 6120 || f.CacheRead != 150200 ||
		f.CacheCreation != 21400 || f.CacheCreation1h != 1400 || f.Reasoning != 0 || f.Model != "claude-sonnet-4-5" {
		t.Fatalf("tokens %+v", f)
	}
	tok := MapTokens(cc, got, got.ID, "/repo")
	if len(tok) != 1 || tok[0].Tool != models.ToolClaudeCode || tok[0].Source != models.TokenSourceSessionSummary ||
		tok[0].CacheCreation1hTokens != 1400 {
		t.Fatalf("token event %+v", tok)
	}
}

// TestWarpHarnessCodex: a Codex harness run lands under tool codex as a
// child of its parent run; its counters are netted the way the Codex
// adapter nets them (input less cached input, output less reasoning).
func TestWarpHarnessCodex(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	task := warpList(t)[warpRunCodex]
	cc, ok := ForTask(c, task)
	if !ok || cc.Tool != models.ToolCodex || task.Lifecycle != LifecycleRunning || !task.CompletedAt.IsZero() {
		t.Fatalf("tool %q task %+v", cc.Tool, task)
	}
	if lin, ok := ChildLineage(ChildLink{Parent: task.ParentID, Child: task.ID}); !ok || lin.ParentThreadID != warpRunClaude {
		t.Fatalf("lineage %+v %v", lin, ok)
	}
	if task.RepoRemote != "" || ResolveProject(c, task, nil).Placeholder != "[warp-cloud]" {
		t.Fatalf("a run with no pull request goes to the placeholder: %+v", task)
	}
	if len(task.Usage) != 2 {
		t.Fatalf("usage %+v", task.Usage)
	}
	got, err := ApplyAPIDetail(c, DetailHarnessUsage, task, vendorFixture(t, "warp/warp.agent_api.run_harness_usage/enum_sweep.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := got.Tokens
	if f == nil || f.Input != 16000 || f.CacheRead != 48000 || f.Output != 1800 || f.Reasoning != 1200 || f.CacheCreation != 0 {
		t.Fatalf("tokens %+v", f)
	}
}

// TestWarpHarnessOz: Warp's own oz harness (stated or the documented
// default) has no tool, so the run lands no tool rows: no events, no
// tokens, no harness-usage or history read; only its ledger rows.
func TestWarpHarnessOz(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	task := warpList(t)[warpRunOz]
	cc, ok := ForTask(c, task)
	if ok || cc.Tool != "" || task.Harness != "oz" || task.Lifecycle != LifecycleFailed {
		t.Fatalf("oz run attributed: tool %q task %+v", cc.Tool, task)
	}
	if NeedsDetail(c, task) || DetailApplies(DetailHarnessUsage, task) {
		t.Fatal("an oz run reads no harness usage")
	}
	if len(MapLedger(cc, task, task.ID, KeychainKeyAccount)) != 2 {
		t.Fatalf("an oz run's credits and USD still reach the ledger: %+v", task.Usage)
	}
	for _, h := range []string{"gemini", "pi", ""} {
		if _, ok := ForTask(c, Task{Harness: h}); ok {
			t.Errorf("harness %q has no tool row and must land no tool rows", h)
		}
	}
	if _, ok := ForTask(mustConn(t, ConnectorDevin), Task{}); !ok {
		t.Error("a fixed-tool row is always attributed")
	}
}

// TestWarpLocalRunSkipped: the list is asked for REMOTE runs, and a LOCAL
// run (executed in the user's own Warp app) is refused anyway; a run on a
// self-hosted worker is customer compute, not Warp's cloud.
func TestWarpLocalRunSkipped(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	body := `{"runs":[
		{"run_id":"local-1","state":"SUCCEEDED","execution_location":"LOCAL","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:05:00Z",
		 "agent_config":{"harness":{"type":"claude"}}},
		{"run_id":"worker-1","state":"SUCCEEDED","execution_location":"REMOTE","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:05:00Z",
		 "agent_config":{"worker_host":"my-worker-01","harness":{"type":"claude"}}},
		{"run_id":"cloud-1","state":"QUEUED","created_at":"2026-10-30T09:00:00Z","updated_at":"2026-10-30T09:05:00Z"}
	],"page_info":{"has_next_page":false},"as_of":"2026-10-30T09:06:00Z","team_uid":null}`
	p, err := ParseAPIList(c, nil, "", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Task{}
	for _, task := range p.Tasks {
		got[task.ID] = task
	}
	if _, ok := got["local-1"]; ok || len(got) != 2 {
		t.Fatalf("tasks %+v: the LOCAL run must be skipped", got)
	}
	if ex := Execution("worker-1", got["worker-1"]); ex.ExecutionLocation != models.ExecutionCustomerWorker {
		t.Fatalf("self-hosted worker %+v", ex)
	}
	if ex := Execution("cloud-1", got["cloud-1"]); ex.ExecutionLocation != models.ExecutionVendorCloud || got["cloud-1"].Harness != "oz" {
		t.Fatalf("absent location (the REMOTE filter's answer) %+v %+v", ex, got["cloud-1"])
	}
}

// TestWarpHistory: the conversation lands as metadata-only activity, an
// action's result settling its call's outcome; text is never kept.
func TestWarpHistory(t *testing.T) {
	c := mustConn(t, ConnectorWarpCloud)
	hp, err := ParseAPIHistory(c, nil, warpRunClaude, "", vendorFixture(t, "warp/warp.agent_api.run_conversation/normal_page.json"))
	if err != nil {
		t.Fatal(err)
	}
	if hp.Next != "" || len(hp.Activity) != 4 {
		t.Fatalf("history %+v", hp)
	}
	byID := map[string]Activity{}
	for _, a := range hp.Activity {
		byID[a.ID] = a
	}
	if a := byID["msg:msg-synth-0001"]; a.Kind != ActivityPrompt {
		t.Fatalf("prompt %+v", a)
	}
	run := byID["ev:act-synth-0001"]
	if run.Kind != ActivityToolCall || run.Tool != "run_command" || !run.OutcomeKnown || !run.Failed {
		t.Fatalf("failed call %+v", run)
	}
	if edit := byID["ev:act-synth-0002"]; edit.OutcomeKnown || edit.Failed {
		t.Fatalf("a call with no result stays unsettled: %+v", edit)
	}
	cc, _ := ForTask(c, Task{Harness: "claude"})
	acts := MapActivity(cc, warpRunClaude, "/repo", hp.Activity)
	for _, a := range acts {
		if a.Tool != models.ToolClaudeCode || strings.Contains(a.Target, "go test") {
			t.Fatalf("activity %+v", a)
		}
	}
	if out := MapOutcomes(cc, warpRunClaude, hp.Activity); len(out) != 1 || out[0].Success {
		t.Fatalf("outcomes %+v", out)
	}
	// The harness survives a checkpoint round trip, so a re-read without a
	// listing still knows the tool; junk is dropped.
	h := DecodeHistoryCursor(EncodeHistoryCursor(HistoryCursor{Harness: "codex", Lifecycle: "running"}))
	if h.Harness != "codex" || DecodeHistoryCursor(`{"h":"Not A Token!"}`).Harness != "" {
		t.Fatalf("cursor %+v", h)
	}
}
