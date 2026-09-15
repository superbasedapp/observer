package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// seedProcessRun persists one process_runs row (via the real PersistRuns
// path, exactly as the production capture pipeline writes it) and returns
// the row's autoincrement id, so a test can then attach process_events to it.
func seedProcessRun(t *testing.T, s *Store, key, sessionID string, pid int, started time.Time, exited bool) int64 {
	t.Helper()
	ctx := context.Background()
	run := processobs.ProcessRun{
		ProcessKey:     key,
		BootID:         "boot-1",
		PID:            pid,
		StartTimeTicks: int64(pid) * 1000,
		ExePath:        "/usr/bin/node",
		ExeBasename:    "node",
		ExeHash:        "sha256:abc",
		CWD:            "/home/dev/proj",
		ArgvPreview:    "node server.js",
		ArgvArgc:       2,
		StartedAt:      started,
		LastSeenAt:     started,
		Attribution: processobs.Attribution{
			SessionID:  sessionID,
			Tool:       "claude-code",
			Source:     processobs.AttrBridge,
			Confidence: processobs.ConfHigh,
		},
	}
	if exited {
		run.Exited = true
		run.ExitedAt = started.Add(2 * time.Second)
		run.ExitCode = 0
		run.DurationMs = 2000
		run.CPUUserMs = 40
		run.CPUSystemMs = 10
		run.MaxRSSBytes = 1 << 20
		run.ReadBytes = 100
		run.WriteBytes = 200
	}
	if _, err := s.PersistRuns(ctx, []processobs.ProcessRun{run}); err != nil {
		t.Fatalf("seedProcessRun PersistRuns(%s): %v", key, err)
	}
	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM process_runs WHERE process_key = ?`, key).Scan(&id); err != nil {
		t.Fatalf("seedProcessRun lookup id(%s): %v", key, err)
	}
	return id
}

// seedProcessEvents inserts n bare process_events rows against a run id, only
// for exercising the per-run COUNT(*) this query surfaces — target/details
// content is irrelevant to SelectSessionProcessRows, which never selects it.
func seedProcessEvents(t *testing.T, s *Store, runID int64, processKey, sessionID string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO process_events (process_run_id, process_key, timestamp, event_type, session_id)
			VALUES (?, ?, ?, 'network_connect', ?)`,
			runID, processKey, timestamp(time.Now().UTC()), sessionID); err != nil {
			t.Fatalf("seedProcessEvents[%d]: %v", i, err)
		}
	}
}

func TestSelectSessionProcessRows_FieldsAndEventCount(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	parentID := seedProcessRun(t, s, "proc-parent", sessionID, 100, now.Add(-time.Minute), false)
	_ = parentID
	childID := seedProcessRun(t, s, "proc-child", sessionID, 101, now.Add(-30*time.Second), true)
	seedProcessEvents(t, s, childID, "proc-child", sessionID, 3)

	got, err := s.SelectSessionProcessRows(context.Background())
	if err != nil {
		t.Fatalf("SelectSessionProcessRows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}

	byKey := map[string]int{}
	for i, r := range got {
		byKey[r.RunKey] = i
	}
	child := got[byKey["proc-child"]]
	if child.SessionID != sessionID {
		t.Errorf("child.SessionID = %q, want %q", child.SessionID, sessionID)
	}
	if child.PID != 101 {
		t.Errorf("child.PID = %d, want 101", child.PID)
	}
	if child.ExePath != "/usr/bin/node" || child.ExeBasename != "node" || child.ExeHash != "sha256:abc" {
		t.Errorf("child exe fields = %+v, want /usr/bin/node node sha256:abc", child)
	}
	if child.CWD != "/home/dev/proj" || child.ArgvPreview != "node server.js" || child.ArgvArgc != 2 {
		t.Errorf("child command fields = %+v", child)
	}
	if child.AttributionSource != string(processobs.AttrBridge) || child.AttributionConfidence != string(processobs.ConfHigh) {
		t.Errorf("child attribution = %q/%q, want bridge/high", child.AttributionSource, child.AttributionConfidence)
	}
	if !child.Exited || child.EndedAt == "" {
		t.Errorf("child.Exited/EndedAt = %v/%q, want exited with an EndedAt", child.Exited, child.EndedAt)
	}
	if child.DurationMs != 2000 || child.CPUUserMs != 40 || child.CPUSystemMs != 10 {
		t.Errorf("child timing/cpu = %+v", child)
	}
	if child.MaxRSSBytes != 1<<20 || child.ReadBytes != 100 || child.WriteBytes != 200 {
		t.Errorf("child resource metrics = %+v", child)
	}
	if child.EventCount != 3 {
		t.Errorf("child.EventCount = %d, want 3", child.EventCount)
	}
	if child.Tool != "claude-code" {
		t.Errorf("child.Tool = %q, want claude-code", child.Tool)
	}

	parent := got[byKey["proc-parent"]]
	if parent.Exited {
		t.Errorf("parent.Exited = true, want false (still running)")
	}
	if parent.EventCount != 0 {
		t.Errorf("parent.EventCount = %d, want 0 (no events seeded)", parent.EventCount)
	}
}

// TestSelectSessionProcessRows_ExcludesUnattributedAndOldRuns pins two
// exclusions: a run with no session_id never crosses the wire (it can't be
// scoped to a session detail view), and a run outside the recompute window is
// dropped even though it has a session.
func TestSelectSessionProcessRows_ExcludesUnattributedAndOldRuns(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	seedProcessRun(t, s, "proc-unattributed", "", 200, now, false)
	seedProcessRun(t, s, "proc-old", sessionID, 201, now.AddDate(0, 0, -30), false)
	seedProcessRun(t, s, "proc-current", sessionID, 202, now, false)

	got, err := s.SelectSessionProcessRows(context.Background())
	if err != nil {
		t.Fatalf("SelectSessionProcessRows: %v", err)
	}
	if len(got) != 1 || got[0].RunKey != "proc-current" {
		t.Fatalf("got = %+v, want exactly [proc-current]", got)
	}
}

// TestSelectSessionProcessRows_MetricsMessageIDAndSampleCap pins the W-A
// additions to the wire row: working_set_bytes / thread_count surface as
// captured, message_id is resolved from the correlated action's
// actions.message_id (process_runs has no message_id column of its own), and
// the high-volume metric_samples_json ring is capped to the most-recent
// sessionProcessMetricSampleCap samples under the byte ceiling.
func TestSelectSessionProcessRows_MetricsMessageIDAndSampleCap(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, projectID := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	// An action carrying a message id, so the run correlated to it (by
	// action_id) resolves MessageID through the actions.message_id join.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO actions (session_id, project_id, timestamp, tool, action_type, message_id, success, source_file, source_event_id)
		 VALUES (?, ?, ?, 'claude-code', 'run_command', 'msg_abc123', 1, 'p.jsonl', 'ev-mid')`,
		sessionID, projectID, timestamp(now))
	if err != nil {
		t.Fatalf("insert correlated action: %v", err)
	}
	actionID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}

	// 61 samples: one over the cap, so the wire keeps the last 60.
	samples := make([]processobs.MetricSample, 0, 61)
	for i := 0; i < 61; i++ {
		samples = append(samples, processobs.MetricSample{
			T: now.Add(time.Duration(i) * time.Second), CPUMs: int64(i), WorkingSet: int64(i) * 1024,
		})
	}
	run := processobs.ProcessRun{
		ProcessKey: "proc-metrics", BootID: "boot-1", PID: 500, StartTimeTicks: 500000,
		ExePath: "/usr/bin/node", ExeBasename: "node", ArgvPreview: "node x.js", ArgvArgc: 2,
		StartedAt: now, LastSeenAt: now,
		WorkingSetBytes: 5 << 20, ThreadCount: 12,
		MetricSamples: samples,
		Attribution: processobs.Attribution{
			SessionID: sessionID, Tool: "claude-code",
			Source: processobs.AttrBridge, Confidence: processobs.ConfHigh,
			ActionID: &actionID,
		},
	}
	if _, err := s.PersistRuns(ctx, []processobs.ProcessRun{run}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	got, err := s.SelectSessionProcessRows(ctx)
	if err != nil {
		t.Fatalf("SelectSessionProcessRows: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	r := got[0]
	if r.WorkingSetBytes != 5<<20 {
		t.Errorf("WorkingSetBytes = %d, want %d", r.WorkingSetBytes, 5<<20)
	}
	if r.ThreadCount != 12 {
		t.Errorf("ThreadCount = %d, want 12", r.ThreadCount)
	}
	if r.MessageID != "msg_abc123" {
		t.Errorf("MessageID = %q, want msg_abc123 (resolved via actions.message_id by action_id)", r.MessageID)
	}

	var kept []processobs.MetricSample
	if err := json.Unmarshal([]byte(r.MetricSamplesJSON), &kept); err != nil {
		t.Fatalf("MetricSamplesJSON not a valid JSON array: %v (%q)", err, r.MetricSamplesJSON)
	}
	if len(kept) != sessionProcessMetricSampleCap {
		t.Errorf("kept %d samples, want the cap %d", len(kept), sessionProcessMetricSampleCap)
	}
	if len(r.MetricSamplesJSON) > sessionProcessMetricSamplesMaxBytes {
		t.Errorf("MetricSamplesJSON = %d bytes, exceeds ceiling %d", len(r.MetricSamplesJSON), sessionProcessMetricSamplesMaxBytes)
	}
	// The freshest sample (CPUMs=60) is kept, the oldest (CPUMs=0) dropped.
	if kept[len(kept)-1].CPUMs != 60 {
		t.Errorf("last kept sample CPUMs = %d, want 60 (freshest retained)", kept[len(kept)-1].CPUMs)
	}
	if kept[0].CPUMs != 1 {
		t.Errorf("first kept sample CPUMs = %d, want 1 (sample 0 dropped by the cap)", kept[0].CPUMs)
	}
}

// TestCapMetricSamples pins capMetricSamples in isolation: an empty or
// non-array input drops to "", an under-cap array is preserved, an over-cap
// array is trimmed to the freshest sessionProcessMetricSampleCap, and an array
// that stays over the byte ceiling after trimming is dropped whole.
func TestCapMetricSamples(t *testing.T) {
	t.Parallel()

	jsonArray := func(n int, elem func(i int) string) string {
		var b strings.Builder
		b.WriteByte('[')
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(elem(i))
		}
		b.WriteByte(']')
		return b.String()
	}

	if got := capMetricSamples(""); got != "" {
		t.Errorf("empty input: got %q, want \"\"", got)
	}
	if got := capMetricSamples("{not json"); got != "" {
		t.Errorf("garbage input: got %q, want \"\"", got)
	}
	if got := capMetricSamples(`{"t":1}`); got != "" {
		t.Errorf("object (not array): got %q, want \"\"", got)
	}

	// Under the cap: element count preserved.
	under := jsonArray(10, func(i int) string { return fmt.Sprintf(`{"t":%d}`, i) })
	var got10 []json.RawMessage
	if err := json.Unmarshal([]byte(capMetricSamples(under)), &got10); err != nil {
		t.Fatalf("under-cap output invalid: %v", err)
	}
	if len(got10) != 10 {
		t.Errorf("under-cap kept %d, want 10", len(got10))
	}

	// Over the cap (small elements): trimmed to the freshest cap.
	over := jsonArray(sessionProcessMetricSampleCap+25, func(i int) string { return fmt.Sprintf(`{"t":%d}`, i) })
	var gotCap []json.RawMessage
	if err := json.Unmarshal([]byte(capMetricSamples(over)), &gotCap); err != nil {
		t.Fatalf("over-cap output invalid: %v", err)
	}
	if len(gotCap) != sessionProcessMetricSampleCap {
		t.Errorf("over-cap kept %d, want %d", len(gotCap), sessionProcessMetricSampleCap)
	}

	// Over the byte ceiling even after trimming to the cap: dropped whole.
	big := strings.Repeat("A", 300)
	huge := jsonArray(sessionProcessMetricSampleCap, func(int) string { return fmt.Sprintf(`{"t":%q}`, big) })
	if len(huge) <= sessionProcessMetricSamplesMaxBytes {
		t.Fatalf("test fixture too small (%d bytes) to exceed the ceiling", len(huge))
	}
	if got := capMetricSamples(huge); got != "" {
		t.Errorf("over-ceiling input: got %d bytes, want \"\" (dropped whole)", len(got))
	}
}

// TestSelectSessionProcessRows_NoRuns returns an empty (never nil) slice.
func TestSelectSessionProcessRows_NoRuns(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	got, err := s.SelectSessionProcessRows(context.Background())
	if err != nil {
		t.Fatalf("SelectSessionProcessRows: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got = %v, want empty non-nil slice", got)
	}
}

// TestSelectSessionProcessRows_QueryPlan pins the PLAN, not just the result.
// The 2026-08-26 audit fix is entirely about which index the planner picks —
// the rows returned are unchanged — so a correctness test alone cannot detect
// a regression that silently restores the full-table aggregate or the
// window-wide sort. This asserts the plan of the exact production query
// string (sessionProcessRowsQuery) after the real migration path has run.
//
// Note SQLite is queried with NO statistics: nothing in this repo runs
// ANALYZE, so the planner uses default estimates and these choices are the
// ones production sees too.
func TestSelectSessionProcessRows_QueryPlan(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	rows, err := s.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+sessionProcessRowsQuery,
		timestamp(time.Now().UTC().AddDate(0, 0, -sessionProcessWindowDays)), sessionProcessRunCap)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("empty query plan")
	}
	joined := strings.Join(plan, "\n")

	// Both migration-090 indexes must actually be chosen. Naming them (rather
	// than asserting "some index") is the point: idx_process_runs_session is
	// also a plausible pick and is precisely the one that costs the sort.
	for _, want := range []string{
		"idx_process_runs_session_started_desc",
		"idx_process_events_run",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan does not use %s\nplan:\n%s", want, joined)
		}
	}

	// The event count must be an indexed seek, never a scan of process_events
	// and never a materialized whole-table GROUP BY (the pre-090 shape).
	if strings.Contains(joined, "SCAN process_events") {
		t.Errorf("plan scans process_events; want a covering-index seek\nplan:\n%s", joined)
	}
	if strings.Contains(joined, "USE TEMP B-TREE FOR GROUP BY") {
		t.Errorf("plan re-introduced the whole-table GROUP BY aggregate\nplan:\n%s", joined)
	}
	// Those two markers alone are NOT sufficient, which is worth stating
	// because it is counter-intuitive: once idx_process_events_run exists,
	// the OLD pre-aggregated `LEFT JOIN (... GROUP BY process_run_id)` shape
	// no longer scans or temp-b-trees either — it degrades to
	//
	//   MATERIALIZE agg
	//   SEARCH process_events USING COVERING INDEX idx_process_events_run (process_run_id>?)
	//
	// i.e. an index RANGE scan building an aggregate over every attributed
	// event in the table, then a join. That still costs work proportional to
	// the whole table rather than to the ~cap survivors, so it is a real
	// regression the index alone does not prevent. MATERIALIZE is the marker
	// that separates the two, and the equality (`=?`) vs range (`>?`)
	// constraint is the second: a per-survivor seek binds process_run_id, a
	// whole-relation aggregate cannot.
	if strings.Contains(joined, "MATERIALIZE") {
		t.Errorf("plan materializes a whole-relation aggregate; want per-survivor seeks\nplan:\n%s", joined)
	}
	if !strings.Contains(joined, "CORRELATED SCALAR SUBQUERY") {
		t.Errorf("event count is not a correlated per-row subquery\nplan:\n%s", joined)
	}
	if !strings.Contains(joined, "idx_process_events_run (process_run_id=?)") {
		t.Errorf("event-count index lookup is not an equality seek on process_run_id\nplan:\n%s", joined)
	}

	// The window must not sort. "LAST TERM OF ORDER BY" is the exact marker
	// SQLite emits when it can serve session_id from the index but has to
	// sort started_at itself — i.e. an external sort over the whole 7-day
	// window, BEFORE the cap can discard from it.
	if strings.Contains(joined, "USE TEMP B-TREE FOR LAST TERM OF ORDER BY") {
		t.Errorf("plan sorts the full window before the cap applies\nplan:\n%s", joined)
	}

	// A single temp b-tree remains, on the OUTER ORDER BY: SQLite cannot
	// carry sort order out of a co-routine CTE. It is bounded by the post-cap
	// survivors (cap x sessions), not by the window, so it is accepted — the
	// sibling network read has the same residual. Asserted rather than
	// ignored so that if a future SQLite/CTE-materialization change removes
	// it, this test tells us instead of silently passing.
	if got := strings.Count(joined, "USE TEMP B-TREE FOR ORDER BY"); got != 1 {
		t.Errorf("USE TEMP B-TREE FOR ORDER BY count = %d, want exactly 1 (the bounded outer sort)\nplan:\n%s", got, joined)
	}

	t.Logf("query plan:\n%s", joined)
}

// seedSession inserts an additional sessions row so a test can prove the
// per-session cap partitions rather than truncating globally. process_runs
// .session_id is FK-enforced, so the row must exist first.
func seedSession(t *testing.T, s *Store, sessionID string, projectID int64) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sessionID, projectID, "claude-code", timestamp(time.Now().UTC())); err != nil {
		t.Fatalf("seedSession(%s): %v", sessionID, err)
	}
}

// TestSelectSessionProcessRows_CapsPerSessionMostRecent pins the SQL cap
// pushdown (ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY started_at
// DESC) filtered rn <= sessionProcessRunCap, migration 090) against the
// Go-side cap loop it replaced. The pushdown is only a safe swap if it is
// ARITHMETICALLY identical, so each case asserts one property of that
// identity rather than just the row count.
func TestSelectSessionProcessRows_CapsPerSessionMostRecent(t *testing.T) {
	t.Parallel()

	// Seeds shared by every case: session A is over-cap by 5, session B is
	// well under it, and the boundary runs of A carry distinguishable event
	// counts so the correlated COUNT(*) can be checked on survivors.
	//
	// A's runs are named proc-a-000 (oldest) .. proc-a-204 (newest); with
	// cap=200 the survivors are exactly proc-a-005..proc-a-204, so
	// proc-a-004 is the last EXCLUDED row and proc-a-005 the first INCLUDED
	// one — the boundary pair.
	const (
		sessA    = "sess-proc-1" // the session mustProjectAndSession creates
		sessB    = "sess-proc-2"
		overBy   = 5
		bUnder   = 3
		firstIn  = overBy     // proc-a-005
		lastOut  = overBy - 1 // proc-a-004
		aEventsN = 7
	)
	totalA := sessionProcessRunCap + overBy

	setup := func(t *testing.T) []orgcontract.SessionProcessRow {
		t.Helper()
		s, _ := newTestStore(t)
		_, projectID := mustProjectAndSession(t, s)
		seedSession(t, s, sessB, projectID)
		now := time.Now().UTC()

		for i := 0; i < totalA; i++ {
			// Oldest first: i=0 started longest ago, i=totalA-1 most recently.
			// Minutes keep every run inside the 7-day window (204 min < 7d).
			started := now.Add(-time.Duration(totalA-i) * time.Minute)
			id := seedProcessRun(t, s, fmt.Sprintf("proc-a-%03d", i), sessA, 300+i, started, false)
			switch i {
			case firstIn, totalA - 1:
				// Events on the first surviving run and the newest run: the
				// count must reach the caller for rows the cap KEEPS.
				seedProcessEvents(t, s, id, fmt.Sprintf("proc-a-%03d", i), sessA, aEventsN)
			case lastOut:
				// Events on a run the cap DROPS. These must not be counted
				// against any surviving row (they share no run id), and the
				// row itself must not appear.
				seedProcessEvents(t, s, id, fmt.Sprintf("proc-a-%03d", i), sessA, 99)
			}
		}
		// Session B: far under the cap, must be untouched by A's overflow.
		for i := 0; i < bUnder; i++ {
			seedProcessRun(t, s, fmt.Sprintf("proc-b-%03d", i), sessB, 900+i,
				now.Add(-time.Duration(i+1)*time.Minute), false)
		}
		// An A run outside the trailing window: excluded by the WHERE, and
		// therefore never eligible to consume one of A's 200 cap slots.
		seedProcessRun(t, s, "proc-a-ancient", sessA, 800,
			now.AddDate(0, 0, -sessionProcessWindowDays-1), false)

		got, err := s.SelectSessionProcessRows(context.Background())
		if err != nil {
			t.Fatalf("SelectSessionProcessRows: %v", err)
		}
		return got
	}

	index := func(rows []orgcontract.SessionProcessRow) map[string]orgcontract.SessionProcessRow {
		m := make(map[string]orgcontract.SessionProcessRow, len(rows))
		for _, r := range rows {
			m[r.RunKey] = r
		}
		return m
	}

	tests := []struct {
		name  string
		check func(t *testing.T, rows []orgcontract.SessionProcessRow)
	}{
		{
			// The cap partitions per session: A contributes exactly the cap,
			// B contributes all of its (under-cap) runs. A global LIMIT or a
			// shared counter would fail this.
			name: "per-session partition, not a global limit",
			check: func(t *testing.T, rows []orgcontract.SessionProcessRow) {
				perSession := map[string]int{}
				for _, r := range rows {
					perSession[r.SessionID]++
				}
				if perSession[sessA] != sessionProcessRunCap {
					t.Errorf("session A rows = %d, want cap %d", perSession[sessA], sessionProcessRunCap)
				}
				if perSession[sessB] != bUnder {
					t.Errorf("session B rows = %d, want %d (an under-cap session is unaffected by A's overflow)", perSession[sessB], bUnder)
				}
				if want := sessionProcessRunCap + bUnder; len(rows) != want {
					t.Errorf("total rows = %d, want %d", len(rows), want)
				}
			},
		},
		{
			// The exact boundary: proc-a-004 out, proc-a-005 in. An off-by-one
			// in the rn <= ? filter moves exactly this pair.
			name: "boundary run inclusion/exclusion by started_at",
			check: func(t *testing.T, rows []orgcontract.SessionProcessRow) {
				byKey := index(rows)
				inKey := fmt.Sprintf("proc-a-%03d", firstIn)
				outKey := fmt.Sprintf("proc-a-%03d", lastOut)
				if _, ok := byKey[inKey]; !ok {
					t.Errorf("%s missing: it is the %dth-most-recent run and must be the LAST one kept", inKey, sessionProcessRunCap)
				}
				if _, ok := byKey[outKey]; ok {
					t.Errorf("%s present: it is the %dst-most-recent run and must be the FIRST one dropped", outKey, sessionProcessRunCap+1)
				}
				// Everything older than the boundary is gone too.
				for i := 0; i < lastOut; i++ {
					if _, ok := byKey[fmt.Sprintf("proc-a-%03d", i)]; ok {
						t.Errorf("cap kept run proc-a-%03d, older than the excluded boundary", i)
					}
				}
				if _, ok := byKey[fmt.Sprintf("proc-a-%03d", totalA-1)]; !ok {
					t.Errorf("cap dropped the most recent run, want it kept")
				}
			},
		},
		{
			// The trailing window is applied BEFORE the cap: an out-of-window
			// run is absent and did not consume a cap slot (proven by A still
			// contributing a full cap's worth above).
			name: "trailing window excludes old runs",
			check: func(t *testing.T, rows []orgcontract.SessionProcessRow) {
				if _, ok := index(rows)["proc-a-ancient"]; ok {
					t.Errorf("proc-a-ancient present: a run older than %dd must be excluded", sessionProcessWindowDays)
				}
			},
		},
		{
			// The correlated COUNT(*) must resolve for surviving rows, and
			// must stay 0 for runs with no events — the count moved from a
			// pre-aggregated LEFT JOIN to a per-survivor subquery, so a wrong
			// correlation key would show up as a shifted or zeroed count.
			name: "event counts correct on surviving rows",
			check: func(t *testing.T, rows []orgcontract.SessionProcessRow) {
				byKey := index(rows)
				for _, key := range []string{
					fmt.Sprintf("proc-a-%03d", firstIn),
					fmt.Sprintf("proc-a-%03d", totalA-1),
				} {
					if got := byKey[key].EventCount; got != aEventsN {
						t.Errorf("%s EventCount = %d, want %d", key, got, aEventsN)
					}
				}
				// A surviving run that was seeded no events counts 0 — not
				// the dropped run's 99, and not another run's 7.
				noEvents := fmt.Sprintf("proc-a-%03d", firstIn+1)
				if got := byKey[noEvents].EventCount; got != 0 {
					t.Errorf("%s EventCount = %d, want 0 (no events seeded for it)", noEvents, got)
				}
				for i := 0; i < bUnder; i++ {
					key := fmt.Sprintf("proc-b-%03d", i)
					if got := byKey[key].EventCount; got != 0 {
						t.Errorf("%s EventCount = %d, want 0", key, got)
					}
				}
			},
		},
		{
			// Output order survives the CTE: session_id ascending, and within
			// a session started_at strictly descending.
			name: "ordering preserved: session_id asc, started_at desc",
			check: func(t *testing.T, rows []orgcontract.SessionProcessRow) {
				for i := 1; i < len(rows); i++ {
					prev, cur := rows[i-1], rows[i]
					switch {
					case cur.SessionID < prev.SessionID:
						t.Fatalf("row %d session_id %q sorts before row %d's %q; want session_id ascending",
							i, cur.SessionID, i-1, prev.SessionID)
					case cur.SessionID == prev.SessionID && cur.StartedAt > prev.StartedAt:
						t.Fatalf("row %d started_at %q is newer than row %d's %q within session %q; want started_at descending",
							i, cur.StartedAt, i-1, prev.StartedAt, cur.SessionID)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.check(t, setup(t))
		})
	}
}
