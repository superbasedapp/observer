package cloudagentssvc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/qoder"
	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// qoderLocalTranscript is a SYNTHETIC qodercli transcript for the cloud
// session sess_synth0001: the shape is the adapter's CC envelope; that a
// `qodercli --remote` run writes such a file, and under which session id,
// is a live-check item (hand-back CA-V2). It is the case the fold must
// handle if it does.
const qoderLocalTranscript = `{"type":"user","uuid":"u-1","timestamp":"2026-10-30T09:00:04Z","message":{"role":"user","content":"run the tests"},"parentUuid":null,"isSidechain":false,"cwd":"/home/dev/widget","sessionId":"sess_synth0001","gitBranch":"main"}
{"type":"assistant","uuid":"u-2","timestamp":"2026-10-30T09:00:19Z","message":{"id":"chatcmpl-A","role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"Bash","input":{"command":"go test ./..."}}]},"parentUuid":"u-1","isSidechain":false,"cwd":"/home/dev/widget","sessionId":"sess_synth0001","gitBranch":"main"}
`

// ingestLocalQoder parses the synthetic transcript and a run-log segment
// with real token counts through the local qoder adapter and lands them,
// the way the watcher would.
func ingestLocalQoder(t *testing.T, st *store.Store) {
	t.Helper()
	root := t.TempDir()
	projects := filepath.Join(root, ".qoder", "projects")
	logs := filepath.Join(root, ".qoder", "logs", "sessions")
	transcript := filepath.Join(projects, "-home-dev-widget", "11111111-2222-4333-8444-555555555555.jsonl")
	segment := filepath.Join(logs, "-home-dev-widget", "sess_synth0001", "segments", "20261030-r1-p1.jsonl")
	seg, err := os.ReadFile(filepath.Join("..", "..", "testdata", "qoder", "segments-tokens.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{transcript: []byte(qoderLocalTranscript), segment: seg} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := qoder.NewWithOptions(nil, projects, logs)
	for _, path := range []string{transcript, segment} {
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Ingest(context.Background(), res.ToolEvents, res.TokenEvents, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func qoderAPI(t *testing.T, envCalls map[string]int) *fakeAPI {
	return qoderAPIWith(t, envCalls, nil)
}

// qoderAPIWith is qoderAPI with the first sessions page passed through edit
// (nil = the fixture as is), for a vendor whose figures move between passes.
func qoderAPIWith(t *testing.T, envCalls map[string]int, edit func([]byte) []byte) *fakeAPI {
	empty := []byte(`{"data":[],"has_more":false,"next_page":null}`)
	return &fakeAPI{call: func(req cloudagents.Request) ([]byte, error) {
		u := req.URL
		if !strings.HasPrefix(u, "https://api.qoder.com.cn/api/v1/cloud/") {
			t.Errorf("request off the picked region: %s", u)
		}
		switch {
		case strings.Contains(u, "/sessions?"):
			if strings.Contains(u, "page=page_synth0002") {
				return vendorFixture(t, "qoder/qoder.ca.sessions/last_page.json"), nil
			}
			b := vendorFixture(t, "qoder/qoder.ca.sessions/normal_page.json")
			if edit != nil {
				b = edit(b)
			}
			return b, nil
		case strings.Contains(u, "/environments/"):
			envCalls[u]++
			if strings.HasSuffix(u, "/env_synth01") {
				return vendorFixture(t, "qoder/qoder.ca.environment_retrieve/normal_page.json"), nil
			}
			return nil, cloudagents.NewError(cloudagents.ErrPermissionDenied, "HTTP 404")
		case strings.Contains(u, "/sessions/sess_synth0001/events?"):
			if strings.Contains(u, "page=evpage_synth0002") {
				return vendorFixture(t, "qoder/qoder.ca.session_events/last_page.json"), nil
			}
			return vendorFixture(t, "qoder/qoder.ca.session_events/normal_page.json"), nil
		case strings.Contains(u, "/events?"):
			return empty, nil
		}
		return nil, notFound(req)
	}}
}

// TestQoderCloudFoldsWithLocalTranscript: a Qoder Cloud Agents session that
// also left a local ~/.qoder transcript and run log lands as ONE session,
// and its tokens count once: the CA-D12 precedence fold keeps the per-turn
// local rows and supersedes the connector's provider run total. The pass
// also pins the region, the environment table (self_hosted =
// customer_worker, an unreadable environment = unknown, one read per
// environment per pass), the cumulative credits and idempotent re-reads.
func TestQoderCloudFoldsWithLocalTranscript(t *testing.T) {
	envCalls := map[string]int{}
	api := qoderAPI(t, envCalls)
	svc, st, database, keys, _ := newAPIService(t, api, &clock{t: t0})
	ctx := context.Background()
	ingestLocalQoder(t, st)

	// Free text and an unlisted region are refused before any call.
	for _, bad := range []map[string]string{nil, {"region": "api.qoder.com.cn"}, {"region": "eu"}} {
		if _, _, err := svc.ConnectWith(ctx, cloudagents.ConnectorQoderCloud, Credentials{Key: apiKey, Params: bad}); err == nil {
			t.Fatalf("region %v accepted", bad)
		}
	}
	if got := api.reset(); len(got) != 0 {
		t.Fatalf("calls before a valid region: %v", got)
	}
	res, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorQoderCloud, Credentials{Key: apiKey, Params: map[string]string{"region": "cn"}})
	if err != nil || av == nil || !res.OK || av.AccountID != "keychain-key@cn" {
		t.Fatalf("connect %+v %+v %v", res, av, err)
	}
	if k, _ := keys.Get(SecretName(cloudagents.ConnectorQoderCloud, av.ID)); k != apiKey {
		t.Fatalf("keychain %q", k)
	}
	sr, err := svc.SyncAccount(ctx, av.ID)
	if err != nil {
		t.Fatalf("sync %+v %v", sr, err)
	}
	if sr.Tasks != 4 {
		t.Fatalf("sync result %+v", sr)
	}

	// One session row for the id both rails report, under tool qoder.
	var n int
	var tool string
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*), MAX(tool) FROM sessions WHERE id = 'sess_synth0001'`).Scan(&n, &tool); err != nil {
		t.Fatal(err)
	}
	if n != 1 || tool != models.ToolQoder {
		t.Fatalf("sessions for sess_synth0001: %d (tool %q)", n, tool)
	}

	// Tokens: both rails' rows are kept as evidence, the fold counts one tier.
	rows, err := database.QueryContext(ctx, `SELECT source FROM token_usage WHERE session_id = 'sess_synth0001' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var turns []cloudlane.FoldTurn
	sources := map[string]int{}
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			t.Fatal(err)
		}
		sources[src]++
		turns = append(turns, cloudlane.FoldTurn{SessionID: "sess_synth0001", TokenSource: src})
	}
	_ = rows.Close()
	if sources[models.TokenSourceJSONL] == 0 || sources[models.TokenSourceSessionSummary] != 1 {
		t.Fatalf("token rows by source %v", sources)
	}
	ex, err := st.LoadSessionExecution(ctx, "sess_synth0001")
	if err != nil {
		t.Fatal(err)
	}
	offMachine := func(string) bool { return ex.ExecutionLocation != "" && ex.ExecutionLocation != models.ExecutionLocal }
	sup := cloudlane.SupersededTurns(turns, offMachine)
	counted := map[string]int{}
	for i, tr := range turns {
		if !sup[i] {
			counted[tr.TokenSource]++
		}
	}
	if counted[models.TokenSourceSessionSummary] != 0 || counted[models.TokenSourceJSONL] != sources[models.TokenSourceJSONL] {
		t.Fatalf("fold counted %v of %v (the provider total must not add to the per-turn rows)", counted, sources)
	}

	// Execution: self_hosted environment = customer_worker; the environment
	// the API would not return stays unknown; env_synth01 was read once
	// although two sessions ran in it.
	if ex.ExecutionLocation != models.ExecutionCustomerWorker {
		t.Fatalf("sess_synth0001 location %q", ex.ExecutionLocation)
	}
	if ex2, _ := st.LoadSessionExecution(ctx, "sess_synth0002"); ex2.ExecutionLocation != "" {
		t.Fatalf("sess_synth0002 location %q, want unknown", ex2.ExecutionLocation)
	}
	if ex4, _ := st.LoadSessionExecution(ctx, "sess_synth0004"); ex4.ExecutionLocation != models.ExecutionVendorCloud {
		t.Fatalf("sess_synth0004 (no environment) location %q", ex4.ExecutionLocation)
	}
	if envCalls["https://api.qoder.com.cn/api/v1/cloud/environments/env_synth01"] != 1 {
		t.Fatalf("environment reads %v", envCalls)
	}

	// Credits: one cumulative row per session that reports total_credits,
	// native unit, never summed with tokens; the events (per-request spans,
	// session.usage, the compaction) add none.
	led, err := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorQoderCloud})
	if err != nil {
		t.Fatal(err)
	}
	bySession := map[string]float64{}
	for _, e := range led {
		if e.Unit != cloudagents.UnitQoderCredit || e.MonetaryStatus != models.UsageMonetaryNone ||
			e.ValueType != models.UsageValueCumulative || e.MeasurementSource != models.UsageSourceProviderRunTotal {
			t.Fatalf("ledger row %+v", e)
		}
		bySession[e.ScopeSession] += e.Value
	}
	if len(led) != 2 || bySession["sess_synth0001"] != 8 || bySession["sess_synth0003"] != 0.2 {
		t.Fatalf("ledger %d rows, by session %v", len(led), bySession)
	}

	var host string
	_ = database.QueryRowContext(ctx, `SELECT IFNULL(surface_host, '') FROM sessions WHERE id = 'sess_synth0001'`).Scan(&host)
	t.Logf("surface_host after both rails: %q", host)

	// A second pass re-reads and lands nothing twice.
	var actions int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = 'sess_synth0001'`).Scan(&actions)
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	var actions2 int
	_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = 'sess_synth0001'`).Scan(&actions2)
	led2, _ := st.ListCloudUsage(ctx, store.CloudUsageFilter{Connector: cloudagents.ConnectorQoderCloud})
	if actions2 != actions || len(led2) != len(led) {
		t.Fatalf("re-read changed counts: actions %d -> %d, ledger %d -> %d", actions, actions2, len(led), len(led2))
	}
}

// creditRows returns the qoder-cloud ledger rows of one session.
func creditRows(t *testing.T, st *store.Store, sessionID string) []store.CloudUsageEntry {
	t.Helper()
	led, err := st.ListCloudUsage(context.Background(), store.CloudUsageFilter{Connector: cloudagents.ConnectorQoderCloud, ScopeSession: sessionID})
	if err != nil {
		t.Fatal(err)
	}
	return led
}

// liveCredits is the session total the readers see: the newest row no other
// row supersedes (cloudlane's rule for a cumulative figure).
func liveCredits(rows []store.CloudUsageEntry) (float64, int) {
	superseded := map[int64]bool{}
	for _, e := range rows {
		if e.SupersedesID != 0 {
			superseded[e.SupersedesID] = true
		}
	}
	v, live := 0.0, 0
	for _, e := range rows {
		if !superseded[e.ID] {
			v, live = e.Value, live+1
		}
	}
	return v, live
}

// TestQoderCloudRefreshesOpenSessionCredits: the live check of 2026-11-02
// showed sandbox runtime credits accruing after the last turn while the
// session's updated_at stayed put. An idle (waiting) session is re-landed on
// every pass while it is listed (its open checkpoint keeps it owed, whatever
// updated_at says), so a higher total_credits supersedes the stored figure
// and readers see the new total, with no new actions. A terminated session
// whose updated_at did not move is not re-landed: its figure stays.
func TestQoderCloudRefreshesOpenSessionCredits(t *testing.T) {
	grown := false
	api := qoderAPIWith(t, map[string]int{}, func(b []byte) []byte {
		if !grown {
			return b
		}
		out := strings.Replace(string(b), `"sandbox_runtime_credits": 0.34,
        "total_credits": 8`, `"sandbox_runtime_credits": 0.84,
        "total_credits": 8.5`, 1)
		out = strings.Replace(out, `"total_credits": 0.2`, `"total_credits": 0.3`, 1)
		if out == string(b) {
			t.Fatal("the fixture edit matched nothing")
		}
		return []byte(out)
	})
	clk := &clock{t: t0}
	svc, st, database, _, _ := newAPIService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorQoderCloud, Credentials{Key: apiKey, Params: map[string]string{"region": "cn"}})
	if err != nil || av == nil {
		t.Fatalf("connect %+v %v", av, err)
	}
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if v, live := liveCredits(creditRows(t, st, "sess_synth0001")); v != 8 || live != 1 {
		t.Fatalf("first pass sess_synth0001 credits %v (%d live rows)", v, live)
	}
	actions := func() int {
		var n int
		_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id IN ('sess_synth0001','sess_synth0003')`).Scan(&n)
		return n
	}
	before := actions()

	// The vendor's totals grow; updated_at does not move.
	grown = true
	clk.set(t0.Add(20 * time.Minute))
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	rows := creditRows(t, st, "sess_synth0001")
	if v, live := liveCredits(rows); v != 8.5 || live != 1 || len(rows) != 2 {
		t.Fatalf("second pass sess_synth0001 credits %v (%d live of %d rows)", v, live, len(rows))
	}
	if v, live := liveCredits(creditRows(t, st, "sess_synth0003")); v != 0.2 || live != 1 {
		t.Fatalf("terminated sess_synth0003 was re-landed: credits %v (%d live rows)", v, live)
	}
	if after := actions(); after != before {
		t.Fatalf("the re-land added actions: %d -> %d", before, after)
	}

	// A third pass with the same totals lands nothing new.
	clk.set(t0.Add(40 * time.Minute))
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if rows3 := creditRows(t, st, "sess_synth0001"); len(rows3) != len(rows) {
		t.Fatalf("an unchanged total landed a row: %d -> %d", len(rows), len(rows3))
	}
}
