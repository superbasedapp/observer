package cloudagentssvc

import (
	"context"
	"database/sql"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The Cursor Cloud Agents live check of 2026-11-01 (a Cursor Pro account:
// four IDLE agents, nine FINISHED or CANCELLED runs, run streams expired),
// replayed from the synthetic fixtures under testdata/cloudagents/cursor-cloud.

// liveCursorAPI answers like the live account. fail, when set, may refuse a
// request first (nil lets it through).
type liveCursorAPI struct {
	*fakeAPI
	mu      sync.Mutex
	fail    func(req cloudagents.Request) error
	streams map[string]int
	// retention is the X-Cursor-Stream-Retention-Seconds a refused stream
	// sends (0: none).
	retention int64
	// usage overrides an agent's usage document by its two-digit number.
	usage map[string][]byte
}

// Stream answers like the live account: every stream is refused as
// expired (410), with the retention header when one is set.
func (l *liveCursorAPI) Stream(ctx context.Context, req cloudagents.Request, key string, w time.Duration, on func(cloudagents.SSEEvent) bool) (cloudagents.StreamEnd, error) {
	end, err := l.fakeAPI.Stream(ctx, req, key, w, on)
	l.mu.Lock()
	end.RetentionSeconds = l.retention
	l.mu.Unlock()
	return end, err
}

func newLiveCursorAPI(t *testing.T) *liveCursorAPI {
	l := &liveCursorAPI{fakeAPI: &fakeAPI{}, streams: map[string]int{}, usage: map[string][]byte{}}
	agentN := func(u string) string {
		const p = "/v1/agents/bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a"
		i := strings.Index(u, p)
		if i < 0 || len(u) < i+len(p)+2 {
			return ""
		}
		return u[i+len(p) : i+len(p)+2]
	}
	l.call = func(req cloudagents.Request) ([]byte, error) {
		l.mu.Lock()
		fail := l.fail
		l.mu.Unlock()
		if fail != nil {
			if err := fail(req); err != nil {
				return nil, err
			}
		}
		switch {
		case strings.HasSuffix(req.URL, "/v1/me"):
			return vendorFixture(t, "cursor/cursor.cloudagent.meta/normal_page.json"), nil
		case strings.HasSuffix(req.URL, "/v1/agents?limit=100"):
			return fixture(t, "cursor-cloud/agents.json"), nil
		case strings.HasSuffix(req.URL, "/runs?limit=100"):
			return fixture(t, "cursor-cloud/runs-a"+agentN(req.URL)+".json"), nil
		case strings.HasSuffix(req.URL, "/usage"):
			l.mu.Lock()
			b, ok := l.usage[agentN(req.URL)]
			l.mu.Unlock()
			if ok {
				return b, nil
			}
			return fixture(t, "cursor-cloud/usage-a"+agentN(req.URL)+".json"), nil
		}
		return nil, notFound(req)
	}
	l.stream = func(req cloudagents.Request) ([]byte, error) {
		l.mu.Lock()
		l.streams[req.URL]++
		l.mu.Unlock()
		// Every request the plan still makes is refused as expired.
		return nil, cloudagents.NewError(cloudagents.ErrStreamExpired, "HTTP Gone")
	}
	return l
}

// liveNow is the day of the live check: every fixture run ended more than
// 24 h earlier. agentsNow sits 34 minutes after agent 1's last update:
// agents 1 and 2 (seven runs) are inside Cursor's 24 h stream retention,
// agents 3 and 4 (two runs) are past it.
var (
	liveNow   = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	agentsNow = time.Date(2026, 10, 17, 19, 47, 0, 0, time.UTC)
)

// newLiveCursorService is newAPIService over the live-shaped API.
func newLiveCursorService(t *testing.T, api *liveCursorAPI, clk *clock) (*Service, *store.Store, *sql.DB) {
	t.Helper()
	svc, st, database, _, _ := newAPIService(t, api.fakeAPI, clk)
	svc.api = api
	return svc, st, database
}

// TestCursorMultiRunAgentsAreNotLeftOpen reproduces defect 2 of the live
// check: after pass 1 two multi-run agents kept session_history checkpoints
// although every run had finished, `status` showed them OPEN and `sync`
// "still running", and they were not re-read on the next pass. Root cause:
// the per-pass stream budget (3) left runs unread, which kept the
// checkpoint; the next pass did not select such a session (it was neither
// detail-pending nor live), and an unlisted session's checkpoint was then
// rewritten from its bare list snapshot, which always reads "detail
// pending", so it flip-flopped between re-read and skipped, and every kept
// checkpoint counted as a running task.
func TestCursorMultiRunAgentsAreNotLeftOpen(t *testing.T) {
	api := newLiveCursorAPI(t)
	clk := &clock{t: agentsNow}
	svc, st, database := newLiveCursorService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}
	c, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCursorCloud)
	const runs = 9
	totalStreams := 0
	for pass := 1; ; pass++ {
		if pass > runs {
			t.Fatal("the owed sessions never drained")
		}
		res, err := svc.SyncAccount(ctx, av.ID)
		if err != nil || res.ErrorClass != "" {
			t.Fatalf("pass %d: %v %+v", pass, err, res)
		}
		if res.OpenTasks != 0 {
			t.Fatalf("pass %d: %d finished agents counted as still running", pass, res.OpenTasks)
		}
		v, err := svc.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if v.Accounts[0].OpenTasks != 0 || v.Accounts[0].Owed != res.Owed {
			t.Fatalf("pass %d: account view open %d owed %d, sync owed %d", pass, v.Accounts[0].OpenTasks, v.Accounts[0].Owed, res.Owed)
		}
		if pass > 1 && res.Streams == 0 && res.Owed > 0 {
			t.Fatalf("pass %d: %d session(s) owed but nothing was re-read", pass, res.Owed)
		}
		if res.Streams > c.MaxStreams {
			t.Fatalf("pass %d read %d streams, budget %d", pass, res.Streams, c.MaxStreams)
		}
		totalStreams += res.Streams
		open, _ := st.ListCloudSyncCheckpoints(ctx, av.ID, models.SyncStreamSessionHistory)
		for _, o := range open {
			if h := cloudagents.DecodeHistoryCursor(o.Cursor); !h.Owed() {
				t.Fatalf("pass %d: %s keeps a checkpoint owing nothing: %s", pass, o.Scope, o.Cursor)
			}
		}
		if res.Owed == 0 {
			if len(open) != 0 {
				t.Fatalf("pass %d: nothing owed, yet %d checkpoints", pass, len(open))
			}
			break
		}
		clk.set(clk.now().Add(20 * time.Minute))
	}
	// Every run inside the retention was tried exactly once (expired: a gap,
	// never retried); the two past it were never requested; all nine are
	// recorded gaps.
	const inRetention = 7
	if totalStreams != inRetention || len(api.streams) != inRetention {
		t.Fatalf("streams read %d over %d runs: %v", totalStreams, len(api.streams), api.streams)
	}
	for u, n := range api.streams {
		if n != 1 {
			t.Errorf("%s streamed %d times", u, n)
		}
	}
	v, _ := svc.Status(ctx)
	if v.Accounts[0].ActivityGaps != runs {
		t.Errorf("activity gaps %d, want %d", v.Accounts[0].ActivityGaps, runs)
	}
	// A later pass with nothing new reads only the list.
	clk.set(clk.now().Add(20 * time.Minute))
	api.reset()
	if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
		t.Fatal(err)
	}
	if calls := api.reset(); len(calls) != 1 || !strings.HasSuffix(calls[0], "/v1/agents?limit=100") {
		t.Errorf("an idle pass called %v", calls)
	}

	// Defect 3: the vendor-reported cost of every run is in the ledger,
	// two measurements per run, landed once across all those re-reads.
	rows, err := database.QueryContext(ctx, `SELECT source_record_id, unit, value, monetary_status, measurement_source, value_type, scope_run, scope_session
		FROM cloud_usage_ledger WHERE connector = ?`, cloudagents.ConnectorCursorCloud)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n, raw, charged := 0, 0.0, 0.0
	for rows.Next() {
		var id, unit, monetary, source, vt, run, sess string
		var val float64
		if err := rows.Scan(&id, &unit, &val, &monetary, &source, &vt, &run, &sess); err != nil {
			t.Fatal(err)
		}
		n++
		unattributed := strings.Contains(id, ":"+cloudagents.RevisableUnattributed+":")
		if unit != "usd" || source != models.UsageSourceProviderRunTotal || vt != models.UsageValueInterval || (run == "") != unattributed || sess == "" {
			t.Errorf("ledger row %s: %s %s %s run=%q session=%q", id, unit, source, vt, run, sess)
		}
		switch monetary {
		case models.UsageMonetaryAPIEquivalent:
			raw += val
		case models.UsageMonetaryReported:
			charged += val
		default:
			t.Errorf("ledger row %s: monetary status %s", id, monetary)
		}
	}
	// Raw: 14.24463 + 3.89843 + 0.98 + 0.43 cents (agent 3's total is 0.37
	// cents above its run, landed once as its unattributed row); charged:
	// 2.5 cents. Two rows per run plus that one.
	if n != 2*runs+1 || math.Abs(raw-0.1955306) > 1e-9 || math.Abs(charged-0.025) > 1e-12 {
		t.Errorf("ledger: %d rows, raw $%v, charged $%v", n, raw, charged)
	}
	// Token totals land as reported: no model is invented and nothing is
	// priced from tokens (Cursor reports no model per agent).
	var tokRows int
	var models_ string
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(GROUP_CONCAT(DISTINCT model), '') FROM token_usage WHERE source_file = ?`,
		cloudagents.SourceFile(cloudagents.ConnectorCursorCloud)).Scan(&tokRows, &models_); err != nil {
		t.Fatal(err)
	}
	if tokRows != 4 || models_ != "" {
		t.Errorf("token rows %d, models %q", tokRows, models_)
	}
}

// TestCursorServerErrorOnOneSessionKeepsThePass reproduces defect 1: one
// vendor 500 on one agent's usage read used to fail the whole pass as
// "unreachable". It now leaves that agent owed (detail_pending) and the pass
// goes on; the agent is read on the next pass. A 5xx on the list still fails
// the pass, as server_error (not unreachable), and keeps the coverage.
func TestCursorServerErrorOnOneSessionKeepsThePass(t *testing.T) {
	api := newLiveCursorAPI(t)
	clk := &clock{t: liveNow}
	svc, st, _, _, _ := newAPIService(t, api.fakeAPI, clk)
	ctx := context.Background()

	// The connect probe: a 500 is server_error, never unreachable.
	api.fail = func(req cloudagents.Request) error {
		if strings.HasSuffix(req.URL, "/v1/me") {
			return cloudagents.NewError(cloudagents.ErrServerError, "HTTP Internal Server Error")
		}
		return nil
	}
	pr, err := svc.TestWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || pr.OK || pr.ErrorClass != cloudagents.ErrServerError {
		t.Fatalf("probe on a 500: %v %+v", err, pr)
	}
	api.fail = nil
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		op   string // a URL suffix that answers with err
		err  cloudagents.ErrorClass
	}{
		{"usage 500", "4a02/usage", cloudagents.ErrServerError},
		{"runs 503", "4a02/runs?limit=100", cloudagents.ErrServerError},
		{"usage timeout", "4a02/usage", cloudagents.ErrTimeout},
	}
	for i, tc := range cases {
		api.mu.Lock()
		api.fail = func(req cloudagents.Request) error {
			if strings.HasSuffix(req.URL, tc.op) {
				return cloudagents.NewError(tc.err, "vendor fault")
			}
			return nil
		}
		api.mu.Unlock()
		// Force agent 2 to be read: drop its checkpoint state and move the
		// clock so each case starts from a first-pass view of it.
		if i > 0 {
			if _, err := st.DeleteCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, ""); err != nil {
				t.Fatal(err)
			}
		}
		clk.set(liveNow.Add(time.Duration(i) * time.Hour))
		res, err := svc.SyncAccount(ctx, av.ID)
		if err != nil || res.ErrorClass != "" || res.DetailPending != 1 {
			t.Fatalf("%s: the pass failed or did not owe the agent: %v %+v", tc.name, err, res)
		}
		cp, found, err := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamSessionHistory, "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a02")
		if err != nil || !found || !cloudagents.DecodeHistoryCursor(cp.Cursor).DetailPending {
			t.Fatalf("%s: agent 2 is not owed: %v %+v", tc.name, found, cp)
		}
		v, _ := svc.Status(ctx)
		if v.Accounts[0].Coverage != cloudagents.CoverageVerified || v.Accounts[0].LastError != "" {
			t.Fatalf("%s: account %+v", tc.name, v.Accounts[0])
		}
		// Next pass, the vendor answers: the owed agent is read.
		api.mu.Lock()
		api.fail = nil
		api.mu.Unlock()
		api.reset()
		clk.set(clk.now().Add(20 * time.Minute))
		res, err = svc.SyncAccount(ctx, av.ID)
		if err != nil || res.DetailPending != 0 {
			t.Fatalf("%s: next pass %v %+v", tc.name, err, res)
		}
		if !containsCall(api.reset(), "4a02/usage") {
			t.Fatalf("%s: the owed agent was not re-read", tc.name)
		}
	}

	// A 5xx on discovery fails the pass, as server_error, and a working
	// account stays Verified (transient).
	api.mu.Lock()
	api.fail = func(req cloudagents.Request) error {
		if strings.HasSuffix(req.URL, "/v1/agents?limit=100") {
			return cloudagents.NewError(cloudagents.ErrServerError, "HTTP Bad Gateway")
		}
		return nil
	}
	api.mu.Unlock()
	clk.set(clk.now().Add(20 * time.Minute))
	res, err := svc.SyncAccount(ctx, av.ID)
	if err == nil || res.ErrorClass != cloudagents.ErrServerError || res.Coverage != cloudagents.CoverageVerified {
		t.Fatalf("list 5xx: %v %+v", err, res)
	}
	// Not-signed-in on a session read still fails the pass.
	api.mu.Lock()
	api.fail = func(req cloudagents.Request) error {
		if strings.HasSuffix(req.URL, "/usage") {
			return cloudagents.NewError(cloudagents.ErrNotSignedIn, "HTTP Unauthorized")
		}
		return nil
	}
	api.mu.Unlock()
	if _, err := st.DeleteCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, ""); err != nil {
		t.Fatal(err)
	}
	clk.set(clk.now().Add(20 * time.Minute))
	if res, err := svc.SyncAccount(ctx, av.ID); err == nil || res.ErrorClass != cloudagents.ErrNotSignedIn {
		t.Fatalf("a 401 on a session read must fail the pass: %v %+v", err, res)
	}
}

// TestPassFatalTable: one case per class row.
func TestPassFatalTable(t *testing.T) {
	cases := []struct {
		class cloudagents.ErrorClass
		fatal bool
	}{
		{cloudagents.ErrNotSignedIn, true},
		{cloudagents.ErrPermissionDenied, true},
		{cloudagents.ErrRateLimited, true},
		{cloudagents.ErrUnreachable, true},
		{cloudagents.ErrServerError, false},
		{cloudagents.ErrTimeout, false},
		{cloudagents.ErrWrongShape, false},
		{cloudagents.ErrStreamExpired, false},
	}
	for _, tc := range cases {
		if got := fatalForPass(cloudagents.NewError(tc.class, "")); got != tc.fatal {
			t.Errorf("%s: fatal %v want %v", tc.class, got, tc.fatal)
		}
	}
}

// TestCursorStreamsPastRetentionAreGaps: live 2026-11-01 every stream of a
// run older than a day answered 410 (retention 86400 s), each costing a slot
// of the 3-per-pass budget and a slow round trip. A run that ended longer
// ago than the retention is now a gap without a request: one pass records
// all nine and owes nothing.
func TestCursorStreamsPastRetentionAreGaps(t *testing.T) {
	api := newLiveCursorAPI(t)
	clk := &clock{t: liveNow}
	svc, st, _ := newLiveCursorService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Streams != 0 || res.StreamGaps != 9 || res.Owed != 0 || res.OpenTasks != 0 {
		t.Fatalf("pass: %v %+v", err, res)
	}
	if len(api.streams) != 0 {
		t.Fatalf("a stream past its retention was requested: %v", api.streams)
	}
	if open, _ := st.ListCloudSyncCheckpoints(ctx, av.ID, models.SyncStreamSessionHistory); len(open) != 0 {
		t.Fatalf("checkpoints left: %+v", open)
	}
	if v, _ := svc.Status(ctx); v.Accounts[0].ActivityGaps != 9 {
		t.Errorf("activity gaps %d", v.Accounts[0].ActivityGaps)
	}
}

// TestCursorObservedRetentionIsUsed: the retention header a refused stream
// sent is kept for the account and wins over the row's 24 h default on the
// next pass.
func TestCursorObservedRetentionIsUsed(t *testing.T) {
	api := newLiveCursorAPI(t)
	api.retention = 3600
	clk := &clock{t: agentsNow}
	svc, st, _ := newLiveCursorService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}
	// Pass 1 plans with 24 h: the two runs of agents 3 and 4 are gaps, the
	// three newest runs are requested and refused with retention 3600.
	res, err := svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Streams != 3 || res.StreamGaps != 5 {
		t.Fatalf("pass 1: %v %+v", err, res)
	}
	cp, found, err := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, cloudagents.StreamRetentionScope)
	if err != nil || !found || cloudagents.DecodeStreamRetention(cp.Cursor) != 3600 {
		t.Fatalf("retention not kept: %v %v %+v", found, err, cp)
	}
	// Pass 2, 20 minutes later: the four runs still owed all ended more
	// than an hour ago, so with the observed 1 h they are gaps, not requests.
	api.reset()
	clk.set(agentsNow.Add(20 * time.Minute))
	res, err = svc.SyncAccount(ctx, av.ID)
	if err != nil || res.Streams != 0 || res.StreamGaps != 4 || res.Owed != 0 {
		t.Fatalf("pass 2: %v %+v", err, res)
	}
	if calls := api.reset(); containsCall(calls, "/stream") {
		t.Fatalf("pass 2 requested a stream: %v", calls)
	}
}

// TestCursorUnattributedCostIsRevised: the agent's cost that no run reports
// lands as one live revision per measure; a changed total supersedes it
// (never frozen by the insert-once record id), an unchanged one adds
// nothing, and a value returning to an earlier one is a new revision. The
// rows a reader keeps (not superseded) always add up to the agent's total.
func TestCursorUnattributedCostIsRevised(t *testing.T) {
	api := newLiveCursorAPI(t)
	clk := &clock{t: liveNow}
	svc, st, database := newLiveCursorService(t, api, clk)
	ctx := context.Background()
	_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
	if err != nil || av == nil {
		t.Fatal(err)
	}
	const agent3 = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a03"
	usage := func(totalCents string) []byte {
		return []byte(`{"totalUsage":{"inputTokens":2000,"outputTokens":500,"cacheWriteTokens":0,"cacheReadTokens":7900,"totalTokens":10400},"cost":{"rawCostCents":` + totalCents + `,"chargedCents":0},"runs":[
		 {"id":"run-c1000000-0000-4000-8000-0000000000c1","usageUuid":"0f1e2d3c-4b5a-4968-8776-c1c1c1c1c1c1","usage":{"inputTokens":1200},"cost":{"rawCostCents":0.61,"chargedCents":0}}]}`)
	}
	// live sums the rows a reader keeps (cloudlane drops superseded rows).
	live := func() (rows, kept int, total float64) {
		t.Helper()
		rs, err := database.QueryContext(ctx, `SELECT l.value, l.id IN (SELECT supersedes_id FROM cloud_usage_ledger WHERE supersedes_id IS NOT NULL)
			FROM cloud_usage_ledger l WHERE l.scope_session = ? AND l.monetary_status = ?`, agent3, models.UsageMonetaryAPIEquivalent)
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close()
		for rs.Next() {
			var v float64
			var superseded bool
			if err := rs.Scan(&v, &superseded); err != nil {
				t.Fatal(err)
			}
			rows++
			if !superseded {
				kept++
				total += v
			}
		}
		return rows, kept, total
	}
	steps := []struct {
		name       string
		totalCents string
		rows, kept int
		wantUSD    float64
	}{
		{"first read: total 0.98 vs run 0.61", "0.98", 2, 2, 0.0098},
		{"total grows to 1.5", "1.5", 3, 2, 0.015},
		{"unchanged", "1.5", 3, 2, 0.015},
		{"back to 0.98: a new revision", "0.98", 4, 2, 0.0098},
		{"equal to the run: the remainder goes to zero", "0.61", 5, 2, 0.0061},
	}
	for i, s := range steps {
		api.mu.Lock()
		api.usage["03"] = usage(s.totalCents)
		api.mu.Unlock()
		// Relist everything, so the finished agent is read again.
		if _, err := st.DeleteCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamDiscovery, ""); err != nil {
			t.Fatal(err)
		}
		clk.set(liveNow.Add(time.Duration(i) * time.Hour))
		if res, err := svc.SyncAccount(ctx, av.ID); err != nil || res.ErrorClass != "" {
			t.Fatalf("%s: %v %+v", s.name, err, res)
		}
		rows, kept, total := live()
		if rows != s.rows || kept != s.kept || math.Abs(total-s.wantUSD) > 1e-12 {
			t.Errorf("%s: %d rows, %d kept, $%v kept, want %d, %d, $%v", s.name, rows, kept, total, s.rows, s.kept, s.wantUSD)
		}
	}
}

// spawnStream is a finished run stream (live shape 2026-11-01, synthetic
// values) whose create_agent call reports creating child.
func spawnStream(child string) []byte {
	return []byte(`id: 1792264216000-1
event: tool_call
data: {"callId":"toolu_06|spawn","name":"create_agent","status":"running","args":{"name":"SYNTHETIC CHILD NAME","prompt":"SYNTHETIC CHILD PROMPT"}}

id: 1792264219000-2
event: tool_call
data: {"callId":"toolu_06|spawn","name":"create_agent","status":"completed","args":{"name":"SYNTHETIC CHILD NAME","prompt":"SYNTHETIC CHILD PROMPT"},"result":{"success":{"agentId":"` + child + `","message":"SYNTHETIC MESSAGE"}}}

id: 1792264221100-3
event: done
data: {}

`)
}

// TestCursorChildAgentLineage: a create_agent result names the child
// agent; once the child's session exists its parent_thread_id is the agent
// whose run created it, and the pending link is gone. A child that never
// appears is dropped after OpenSessionTTL, stamping nothing.
func TestCursorChildAgentLineage(t *testing.T) {
	const (
		parent  = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a01"
		child   = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a02"
		missing = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a99"
	)
	cases := []struct {
		name    string
		child   string
		stamped bool
	}{
		{"listed child is stamped", child, true},
		{"absent child waits, then is dropped", missing, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newLiveCursorAPI(t)
			api.stream = func(req cloudagents.Request) ([]byte, error) {
				if strings.Contains(req.URL, "/agents/"+parent+"/runs/run-a4000000-0000-4000-8000-0000000000a4/") {
					return spawnStream(tc.child), nil
				}
				return nil, cloudagents.NewError(cloudagents.ErrStreamExpired, "HTTP Gone")
			}
			clk := &clock{t: agentsNow}
			svc, st, database := newLiveCursorService(t, api, clk)
			ctx := context.Background()
			_, av, err := svc.ConnectWith(ctx, cloudagents.ConnectorCursorCloud, Credentials{Key: apiKey})
			if err != nil || av == nil {
				t.Fatal(err)
			}
			if res, err := svc.SyncAccount(ctx, av.ID); err != nil || res.ErrorClass != "" {
				t.Fatalf("sync: %v %+v", err, res)
			}
			scope := childScopePrefix + tc.child
			_, pending, err := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, scope)
			if err != nil || pending == tc.stamped {
				t.Fatalf("pending link = %v (%v), want %v", pending, err, !tc.stamped)
			}
			if tc.stamped {
				var pt, src string
				if err := database.QueryRowContext(ctx, `SELECT COALESCE(parent_thread_id,''), COALESCE(thread_source,'') FROM sessions WHERE id = ?`, child).Scan(&pt, &src); err != nil {
					t.Fatal(err)
				}
				if pt != parent || src != cloudagents.ThreadSourceSubagent {
					t.Fatalf("child lineage = %q %q", pt, src)
				}
				var other int
				_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE parent_thread_id IS NOT NULL AND parent_thread_id <> '' AND id <> ?`, child).Scan(&other)
				if other != 0 {
					t.Fatalf("%d other sessions got a parent", other)
				}
				return
			}
			// Still absent past the TTL: the link is dropped, nothing stamped.
			clk.set(agentsNow.Add(OpenSessionTTL + time.Hour))
			if _, err := svc.SyncAccount(ctx, av.ID); err != nil {
				t.Fatal(err)
			}
			if _, pending, _ := st.LoadCloudSyncCheckpoint(ctx, av.ID, models.SyncStreamLive, scope); pending {
				t.Fatal("a stale child link is kept")
			}
			var n int
			_ = database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE parent_thread_id IS NOT NULL AND parent_thread_id <> ''`).Scan(&n)
			if n != 0 {
				t.Fatalf("%d sessions stamped from a missing child", n)
			}
		})
	}
}
