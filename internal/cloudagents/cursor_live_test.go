package cloudagents

import (
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// The Cursor Cloud Agents shapes live-verified on 2026-11-01 (a Cursor Pro
// account, four agents, nine runs), replayed from the synthetic fixtures
// under testdata/cloudagents/cursor-cloud (values invented, shapes real).

const (
	liveAgent1 = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a01" // four runs, a GitHub repository
	liveAgent2 = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a02" // three runs, a Cursor-hosted scratch repository
)

// liveCursorAgent returns the listed agent with id, its runs and usage
// applied.
func liveCursorAgent(t *testing.T, id, n string) Task {
	t.Helper()
	c := mustConn(t, ConnectorCursorCloud)
	p, err := ParseAPIList(c, nil, "", fixture(t, "cursor-cloud/agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	for _, x := range p.Tasks {
		if x.ID == id {
			task = x
		}
	}
	if task.ID == "" {
		t.Fatalf("agent %s not listed", id)
	}
	if task, err = ApplyAPIDetail(c, DetailRuns, task, fixture(t, "cursor-cloud/runs-a"+n+".json")); err != nil {
		t.Fatal(err)
	}
	if task, err = ApplyAPIDetail(c, DetailUsage, task, fixture(t, "cursor-cloud/usage-a"+n+".json")); err != nil {
		t.Fatal(err)
	}
	return task
}

// TestCursorLiveListShape: the list parses, carries no cursor when it fits
// one page, is ordered by updatedAt newest first (the row declares
// NewestFirst on that basis), and every IDLE agent is unknown until its runs
// are read.
func TestCursorLiveListShape(t *testing.T) {
	c := mustConn(t, ConnectorCursorCloud)
	p, err := ParseAPIList(c, nil, "", fixture(t, "cursor-cloud/agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Tasks) != 4 || p.Cursor != "" {
		t.Fatalf("list: %d tasks, cursor %q", len(p.Tasks), p.Cursor)
	}
	for i, x := range p.Tasks {
		if x.VendorStatus != "idle" || x.Lifecycle != LifecycleUnknown || !x.DetailPending {
			t.Errorf("agent %d: %+v", i, x)
		}
		if i > 0 && x.UpdatedAt.After(p.Tasks[i-1].UpdatedAt) {
			t.Errorf("agent %d is newer than the one before it: the list is not newest first by updatedAt", i)
		}
	}
	if !c.NewestFirst {
		t.Error("cursor-cloud must declare NewestFirst (live-verified ordering)")
	}
}

// TestCursorStatusVocabulary: one row per live status. The agent's IDLE
// defers to the latest run; FINISHED and CANCELLED are the run statuses.
func TestCursorStatusVocabulary(t *testing.T) {
	c := mustConn(t, ConnectorCursorCloud)
	cases := []struct {
		status string
		want   Lifecycle
	}{
		{"IDLE", LifecycleUnknown},
		{"FINISHED", LifecycleSucceeded},
		{"CANCELLED", LifecycleCancelled},
		{"RUNNING", LifecycleRunning},
		{"CREATING", LifecycleRunning},
		{"ERROR", LifecycleFailed},
	}
	for _, tc := range cases {
		if got := c.LifecycleOf(tc.status); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.status, got, tc.want)
		}
	}
	// The IDLE agent takes its latest run's lifecycle (agent 2's latest run
	// was CANCELLED, agent 1's FINISHED).
	if a := liveCursorAgent(t, liveAgent2, "02"); a.Lifecycle != LifecycleCancelled || a.VendorStatus != "cancelled" || a.CompletedAt.IsZero() {
		t.Errorf("agent 2: %s %s %s", a.Lifecycle, a.VendorStatus, a.CompletedAt)
	}
	if a := liveCursorAgent(t, liveAgent1, "01"); a.Lifecycle != LifecycleSucceeded || len(a.Runs) != 4 {
		t.Errorf("agent 1: %s, %d runs", a.Lifecycle, len(a.Runs))
	}
}

// TestCursorLiveRepositories: a run's repoUrl carries the https scheme; a
// GitHub repository names the task's remote, a Cursor-hosted scratch
// repository (origin.cursor.com/git/<owner>/tmp-<hex>) names none, so the
// task goes to the [cursor-cloud] placeholder.
func TestCursorLiveRepositories(t *testing.T) {
	if a := liveCursorAgent(t, liveAgent1, "01"); a.RepoRemote != "github.com/acme-dev/widgets" {
		t.Errorf("agent 1 remote %q", a.RepoRemote)
	}
	if a := liveCursorAgent(t, liveAgent2, "02"); a.RepoRemote != "" {
		t.Errorf("a Cursor scratch repository named remote %q", a.RepoRemote)
	}
}

// TestCursorUsageInputIsNet pins the live finding: totalTokens equals input
// + output + cacheWrite + cacheRead exactly, so inputTokens is already net
// of cache reads and writes and is stored as reported (nothing subtracted).
func TestCursorUsageInputIsNet(t *testing.T) {
	cases := []struct {
		id, n                   string
		in, out, cr, cw, totals int64
	}{
		{liveAgent1, "01", 21200, 5092, 122368, 0, 148660},
		{liveAgent2, "02", 7500, 1650, 22000, 1200, 32350},
	}
	for _, tc := range cases {
		a := liveCursorAgent(t, tc.id, tc.n)
		f := a.Tokens
		if f == nil || f.Input != tc.in || f.Output != tc.out || f.CacheRead != tc.cr || f.CacheCreation != tc.cw {
			t.Fatalf("%s tokens %+v", tc.id, f)
		}
		if f.Input+f.Output+f.CacheRead+f.CacheCreation != tc.totals {
			t.Errorf("%s: the parts do not add up to totalTokens %d", tc.id, tc.totals)
		}
		if f.Model != "" {
			t.Errorf("%s: a model was invented: %q (Cursor reports none per agent)", tc.id, f.Model)
		}
	}
}

// TestCursorRunCosts: each finished run's rawCostCents and chargedCents land
// as two measurements in US dollars, keyed by the run's usageUuid.
func TestCursorRunCosts(t *testing.T) {
	a := liveCursorAgent(t, liveAgent2, "02")
	type key struct{ run, monetary string }
	got := map[key]UsageFigure{}
	runFigures := 0
	for _, f := range a.Usage {
		if f.Run != "" {
			got[key{f.Run, f.MonetaryStatus}] = f
			runFigures++
		}
	}
	cases := []struct {
		run, uuid string
		monetary  string
		usd       float64
	}{
		{"run-b1000000-0000-4000-8000-0000000000b1", "0f1e2d3c-4b5a-4968-8776-b1b1b1b1b1b1", models.UsageMonetaryAPIEquivalent, 0.012},
		{"run-b1000000-0000-4000-8000-0000000000b1", "0f1e2d3c-4b5a-4968-8776-b1b1b1b1b1b1", models.UsageMonetaryReported, 0},
		{"run-b2000000-0000-4000-8000-0000000000b2", "0f1e2d3c-4b5a-4968-8776-b2b2b2b2b2b2", models.UsageMonetaryAPIEquivalent, 0.025},
		{"run-b2000000-0000-4000-8000-0000000000b2", "0f1e2d3c-4b5a-4968-8776-b2b2b2b2b2b2", models.UsageMonetaryReported, 0.025},
		{"run-b3000000-0000-4000-8000-0000000000b3", "0f1e2d3c-4b5a-4968-8776-b3b3b3b3b3b3", models.UsageMonetaryAPIEquivalent, 0.0019843},
		{"run-b3000000-0000-4000-8000-0000000000b3", "0f1e2d3c-4b5a-4968-8776-b3b3b3b3b3b3", models.UsageMonetaryReported, 0},
	}
	if runFigures != len(cases) {
		t.Fatalf("%d run figures, want %d: %+v", runFigures, len(cases), a.Usage)
	}
	for _, tc := range cases {
		f, ok := got[key{tc.run, tc.monetary}]
		if !ok {
			t.Errorf("%s %s missing", tc.run, tc.monetary)
			continue
		}
		if f.RecordID != tc.uuid || f.Unit != "usd" || math.Abs(f.Value-tc.usd) > 1e-12 ||
			f.ValueType != models.UsageValueInterval || f.Source != models.UsageSourceProviderRunTotal ||
			f.IntervalStart.IsZero() || f.IntervalEnd.Before(f.IntervalStart) || !f.ReportedAt.Equal(f.IntervalEnd) {
			t.Errorf("%s %s: %+v", tc.run, tc.monetary, f)
		}
	}
	// Applying the usage read again replaces, never repeats, the figures.
	again, err := ApplyAPIDetail(mustConn(t, ConnectorCursorCloud), DetailUsage, a, fixture(t, "cursor-cloud/usage-a02.json"))
	if err != nil || len(again.Usage) != len(a.Usage) {
		t.Fatalf("re-applied usage: %v %d figures", err, len(again.Usage))
	}
}

// TestCursorRunCostRules: one case per rule of runCosts.
func TestCursorRunCostRules(t *testing.T) {
	c := mustConn(t, ConnectorCursorCloud)
	usage := []byte(`{"totalUsage":{"inputTokens":1},"cost":{"rawCostCents":3,"chargedCents":1},"runs":[
	 {"id":"run-1","usageUuid":"u-1","usage":{"inputTokens":1},"cost":{"rawCostCents":1,"chargedCents":1}},
	 {"id":"run-2","usageUuid":"u-2","usage":{"inputTokens":1},"cost":{"rawCostCents":1,"chargedCents":0}},
	 {"id":"run-3","usage":{"inputTokens":1},"cost":{"rawCostCents":1}},
	 {"id":"run-4","usageUuid":"u-4","usage":{"inputTokens":1},"cost":{"rawCostCents":1}},
	 {"id":"run-5","usageUuid":"u-5","usage":{"inputTokens":1}}]}`)
	at := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)
	task := Task{ID: "bc-1", Runs: []Run{
		{ID: "run-1", Lifecycle: LifecycleSucceeded, CreatedAt: at, UpdatedAt: at.Add(time.Minute)},
		{ID: "run-2", Lifecycle: LifecycleRunning, CreatedAt: at, UpdatedAt: at},
		{ID: "run-3", Lifecycle: LifecycleSucceeded, CreatedAt: at, UpdatedAt: at},
		{ID: "run-5", Lifecycle: LifecycleCancelled, CreatedAt: at, UpdatedAt: at},
	}}
	got, err := ApplyAPIDetail(c, DetailUsage, task, usage)
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]int{}
	for _, f := range got.Usage {
		runs[f.Run]++
	}
	cases := []struct {
		run  string
		want int
		why  string
	}{
		{"run-1", 2, "a finished run lands both amounts"},
		{"run-2", 0, "a running run's cost may still grow"},
		{"run-3", 0, "no usageUuid, no stable record id"},
		{"run-4", 0, "not in the runs read, its lifecycle is unknown"},
		{"run-5", 0, "no cost object reported"},
	}
	for _, tc := range cases {
		if runs[tc.run] != tc.want {
			t.Errorf("%s: %d figures, want %d (%s)", tc.run, runs[tc.run], tc.want, tc.why)
		}
	}
}

// TestCursorRunCostLedger: a figure with a vendor record id lands under that
// id (one row per measurement under the unique index), scoped to its run,
// whatever time it is read at.
func TestCursorRunCostLedger(t *testing.T) {
	c := mustConn(t, ConnectorCursorCloud)
	a := liveCursorAgent(t, liveAgent1, "01")
	var es []LedgerEntry
	for _, e := range MapLedger(c, a, a.ID, "user:1") {
		if !e.Revisable {
			es = append(es, e)
		}
	}
	if len(es) != 8 {
		t.Fatalf("%d ledger entries, want 8 (four runs, two amounts each)", len(es))
	}
	ids := map[string]bool{}
	var raw float64
	for _, e := range es {
		if e.ScopeRun == "" || e.ScopeSession != a.ID || e.Unit != "usd" {
			t.Errorf("entry %+v", e)
		}
		ids[e.SourceRecordID] = true
		if e.MonetaryStatus == models.UsageMonetaryAPIEquivalent {
			raw += e.Value
		}
	}
	if len(ids) != 8 || !ids["0f1e2d3c-4b5a-4968-8776-a1a1a1a1a1a1:"+models.UsageMonetaryReported] {
		t.Errorf("record ids %v", ids)
	}
	// The four runs' raw amounts add up to the agent's total (14.24463 cents).
	if math.Abs(raw-0.1424463) > 1e-9 {
		t.Errorf("raw total %v", raw)
	}
	later := a
	later.UpdatedAt = a.UpdatedAt.Add(time.Hour)
	for i, e := range MapLedger(c, later, a.ID, "user:1")[:len(es)] {
		if e.SourceRecordID != es[i].SourceRecordID {
			t.Errorf("a re-read changed a record id: %s -> %s", es[i].SourceRecordID, e.SourceRecordID)
		}
	}
}

// TestCheckpointLifecycle: one case per cursor shape.
func TestCheckpointLifecycle(t *testing.T) {
	cases := []struct {
		cursor string
		want   Lifecycle
	}{
		{EncodeHistoryCursor(HistoryCursor{Lifecycle: "succeeded"}), LifecycleSucceeded},
		{`{"s":"0001-01-01T00:00:00Z","l":"cancelled"}`, LifecycleCancelled},
		{EncodeHistoryCursor(HistoryCursor{Lifecycle: "running", StreamsOwed: true}), LifecycleRunning},
		{EncodeHistoryCursor(HistoryCursor{DetailPending: true}), LifecycleUnknown},
		{"running", LifecycleRunning},
		{"waiting", LifecycleWaiting},
		{"", LifecycleUnknown},
	}
	for _, tc := range cases {
		if got := CheckpointLifecycle(tc.cursor); got != tc.want {
			t.Errorf("%q: %s want %s", tc.cursor, got, tc.want)
		}
	}
	h := DecodeHistoryCursor(EncodeHistoryCursor(HistoryCursor{StreamsOwed: true, Lifecycle: "succeeded"}))
	if !h.StreamsOwed || !h.Owed() || (HistoryCursor{}).Owed() {
		t.Errorf("owed round trip %+v", h)
	}
}

// TestDiscoveryWantsOwedSessions: a newest-first list keeps paging past its
// window until every owed session was listed; with none owed it stops at
// the first older entry.
func TestDiscoveryWantsOwedSessions(t *testing.T) {
	c := mustConn(t, ConnectorCursorCloud)
	at := func(h int) time.Time { return time.Date(2026, 10, 17, h, 0, 0, 0, time.UTC) }
	page1 := Page{Tasks: []Task{{ID: "bc-new", UpdatedAt: at(19)}, {ID: "bc-old1", UpdatedAt: at(10)}}, Cursor: "c2"}
	page2 := Page{Tasks: []Task{{ID: "bc-old2", UpdatedAt: at(9)}}, Cursor: "c3"}
	since := at(18)
	cases := []struct {
		name      string
		want      []string
		continues bool
	}{
		{"nothing owed", nil, false},
		{"owed on page 1", []string{"bc-old1"}, false},
		{"owed on a later page", []string{"bc-old2"}, true},
		{"owed in the window", []string{"bc-new"}, false},
	}
	for _, tc := range cases {
		d := NewDiscovery(c, since)
		d.Want(tc.want)
		if got := d.Add(page1); got != tc.continues {
			t.Errorf("%s: continue = %v", tc.name, got)
			continue
		}
		if tc.continues {
			if d.Add(page2) {
				t.Errorf("%s: kept paging after the owed session was listed", tc.name)
			}
			if _, ok := d.Older("bc-old2"); !ok {
				t.Errorf("%s: the owed session is not in Older", tc.name)
			}
		}
		if d.Truncated() {
			t.Errorf("%s: a newest-first list past its window start is not truncated", tc.name)
		}
	}
}

// TestCursorUnattributedCost: live 2026-11-01 an agent's total exceeded the
// sum of its runs (by 35 to 50 percent on three of four agents). The excess
// lands as one revisable "unattributed" figure per measure, so the run rows
// plus it add up to the agent's reported total exactly once.
func TestCursorUnattributedCost(t *testing.T) {
	cases := []struct {
		name, id, n   string
		rawRem, chRem float64 // dollars
		tokens        int64   // totalTokens the token row carries
	}{
		// Agent 3: total 0.98 cents vs one run 0.61 cents.
		{"total above runs", "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a03", "03", 0.0037, 0, 10400},
		// Agent 1: total equals the sum of its runs.
		{"total equals runs", liveAgent1, "01", 0, 0, 148660},
	}
	for _, tc := range cases {
		a := liveCursorAgent(t, tc.id, tc.n)
		rem := map[string]float64{}
		for _, f := range a.Usage {
			if f.Revisable == RevisableUnattributed {
				if f.Run != "" || f.ValueType != models.UsageValueInterval || f.Unit != "usd" {
					t.Errorf("%s: %+v", tc.name, f)
				}
				rem[f.MonetaryStatus] = f.Value
			}
		}
		if math.Abs(rem[models.UsageMonetaryAPIEquivalent]-tc.rawRem) > 1e-12 || math.Abs(rem[models.UsageMonetaryReported]-tc.chRem) > 1e-12 {
			t.Errorf("%s: unattributed %v", tc.name, rem)
		}
		// The token row is the agent total, not the run sum.
		f := a.Tokens
		if f.Input+f.Output+f.CacheRead+f.CacheCreation != tc.tokens {
			t.Errorf("%s: token total %d", tc.name, f.Input+f.Output+f.CacheRead+f.CacheCreation)
		}
	}
	// A running run's cost is not landed per run yet, so it is in the
	// unattributed part until the run ends; never below zero.
	c := mustConn(t, ConnectorCursorCloud)
	at := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)
	task := Task{ID: "bc-1", CreatedAt: at, UpdatedAt: at.Add(time.Hour), Runs: []Run{
		{ID: "run-1", Lifecycle: LifecycleSucceeded, CreatedAt: at, UpdatedAt: at.Add(time.Minute)},
		{ID: "run-2", Lifecycle: LifecycleRunning, CreatedAt: at, UpdatedAt: at},
	}}
	got, err := ApplyAPIDetail(c, DetailUsage, task, []byte(`{"totalUsage":{},"cost":{"rawCostCents":5,"chargedCents":1},"runs":[
	 {"id":"run-1","usageUuid":"u-1","usage":{},"cost":{"rawCostCents":2,"chargedCents":3}},
	 {"id":"run-2","usageUuid":"u-2","usage":{},"cost":{"rawCostCents":1}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Usage {
		if f.Revisable == "" {
			continue
		}
		want := map[string]float64{models.UsageMonetaryAPIEquivalent: 0.03, models.UsageMonetaryReported: 0}[f.MonetaryStatus]
		if math.Abs(f.Value-want) > 1e-12 {
			t.Errorf("unattributed %s = %v want %v", f.MonetaryStatus, f.Value, want)
		}
	}
}

// TestResolveRevisions: one case per rule. A revisable entry becomes the next
// numbered revision superseding the newest stored one, or is dropped when
// unchanged; a first zero lands nothing; a value returning to an earlier
// one is still a new revision.
func TestResolveRevisions(t *testing.T) {
	base := "bc-1:unattributed:api_equivalent"
	entry := func(v float64) LedgerEntry {
		return LedgerEntry{SourceRecordID: base, Value: v, Revisable: true}
	}
	cases := []struct {
		name      string
		in        LedgerEntry
		prior     []PriorLedgerRow
		wantID    string
		wantSuper int64
		dropped   bool
	}{
		{"first revision", entry(0.5), nil, base + "#r1", 0, false},
		{"first revision of zero", entry(0), nil, "", 0, true},
		{"unchanged", entry(0.5), []PriorLedgerRow{{ID: 7, SourceRecordID: base + "#r1", Value: 0.5}}, "", 0, true},
		{"changed", entry(0.3), []PriorLedgerRow{{ID: 7, SourceRecordID: base + "#r1", Value: 0.5}}, base + "#r2", 7, false},
		{"back to zero", entry(0), []PriorLedgerRow{{ID: 7, SourceRecordID: base + "#r1", Value: 0.5}}, base + "#r2", 7, false},
		{"back to an earlier value", entry(0.5), []PriorLedgerRow{
			{ID: 7, SourceRecordID: base + "#r1", Value: 0.5}, {ID: 9, SourceRecordID: base + "#r2", Value: 0.3},
		}, base + "#r3", 9, false},
		{"other bases ignored", entry(0.5), []PriorLedgerRow{{ID: 3, SourceRecordID: "bc-2:unattributed:api_equivalent#r4", Value: 1}}, base + "#r1", 0, false},
	}
	for _, tc := range cases {
		out := ResolveRevisions([]LedgerEntry{tc.in, {SourceRecordID: "u-1:reported_charge", Value: 1}}, tc.prior)
		if out[len(out)-1].SourceRecordID != "u-1:reported_charge" {
			t.Errorf("%s: a final entry was not passed through", tc.name)
		}
		if tc.dropped {
			if len(out) != 1 {
				t.Errorf("%s: not dropped: %+v", tc.name, out)
			}
			continue
		}
		if len(out) != 2 || out[0].SourceRecordID != tc.wantID || out[0].SupersedesID != tc.wantSuper || out[0].Revisable {
			t.Errorf("%s: %+v", tc.name, out)
		}
	}
}

// TestStreamPlanRetention: one case per retention rule row. Live 2026-11-01
// every stream of a run older than a day answered 410 with a retention
// header of 86400 s; such a run is a gap without a request, but a run still
// going is never skipped for age.
func TestStreamPlanRetention(t *testing.T) {
	now := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	ended := func(age time.Duration) Run {
		return Run{ID: "r", Lifecycle: LifecycleSucceeded, UpdatedAt: now.Add(-age)}
	}
	cases := []struct {
		name      string
		run       Run
		cp        StreamCursor
		found     bool
		retention time.Duration
		want      StreamAction
	}{
		{"ended past retention, never read", ended(2 * day), StreamCursor{}, false, day, StreamPastRetention},
		{"cancelled past retention", Run{Lifecycle: LifecycleCancelled, UpdatedAt: now.Add(-3 * day)}, StreamCursor{}, false, day, StreamPastRetention},
		{"ended past retention, stored position", ended(2 * day), StreamCursor{State: StreamOpen, LastEventID: "6"}, true, day, StreamPastRetention},
		{"ended within retention", ended(time.Hour), StreamCursor{}, false, day, StreamFromStart},
		{"ended within retention, stored position", ended(time.Hour), StreamCursor{State: StreamOpen, LastEventID: "6"}, true, day, StreamResume},
		{"running for days is never skipped", Run{Lifecycle: LifecycleRunning, UpdatedAt: now.Add(-3 * day)}, StreamCursor{}, false, day, StreamFromStart},
		{"unknown state is never skipped", Run{Lifecycle: LifecycleUnknown, UpdatedAt: now.Add(-3 * day)}, StreamCursor{}, false, day, StreamFromStart},
		{"no end time is never skipped", Run{Lifecycle: LifecycleSucceeded}, StreamCursor{}, false, day, StreamFromStart},
		{"retention unknown", ended(30 * day), StreamCursor{}, false, 0, StreamFromStart},
		{"done stays skipped", ended(2 * day), StreamCursor{State: StreamDone}, true, day, StreamSkip},
		{"expired stays skipped", ended(2 * day), StreamCursor{State: StreamExpired}, true, day, StreamSkip},
	}
	for _, tc := range cases {
		got, rule := PlanStream(StreamPlanInput{Run: tc.run, Cursor: tc.cp, Found: tc.found, Now: now, Retention: tc.retention})
		if got != tc.want {
			t.Errorf("%s: %s (%s), want %s", tc.name, got, rule, tc.want)
		}
	}
}

// TestStreamRetentionFor: the last observed header wins, else the row's
// default (24 h on cursor-cloud), else unknown.
func TestStreamRetentionFor(t *testing.T) {
	cur := mustConn(t, ConnectorCursorCloud)
	devin := mustConn(t, ConnectorDevin)
	cases := []struct {
		name     string
		c        Connector
		observed int64
		want     time.Duration
	}{
		{"observed header", cur, 3600, time.Hour},
		{"row default", cur, 0, 24 * time.Hour},
		{"no stream row", devin, 0, 0},
	}
	for _, tc := range cases {
		if got := StreamRetentionFor(tc.c, tc.observed); got != tc.want {
			t.Errorf("%s: %s want %s", tc.name, got, tc.want)
		}
	}
	if DecodeStreamRetention(EncodeStreamRetention(86400)) != 86400 || DecodeStreamRetention("junk") != 0 {
		t.Error("retention round trip")
	}
}
