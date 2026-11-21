package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// TestProcessMetricRunColsAreMetricOnly pins the bounded read: the metrics
// seam decodes the ring and the lifecycle facts, never the heavy or sensitive
// columns of a process row.
func TestProcessMetricRunColsAreMetricOnly(t *testing.T) {
	t.Parallel()
	for _, col := range []string{
		"argv_preview", "argv_hash", "env_posture_json", "exe_path", "exe_basename",
		"cwd", "username", "cgroup_hash", "container_id", "namespace", "seccomp",
		"capabilities", "apparmor", "selinux", "attribution", "action_id", "tool",
	} {
		if strings.Contains(processMetricRunCols, col) {
			t.Errorf("processMetricRunCols selects %q; the metrics read must stay metric-only", col)
		}
	}
	for _, col := range []string{"process_key", "started_at", "exited_at", "last_seen_at", "metric_samples_json"} {
		if !strings.Contains(processMetricRunCols, col) {
			t.Errorf("processMetricRunCols lost %q", col)
		}
	}
}

// TestProcessMetricsForSession walks the incremental read through one
// session: a full first read with its settled mark, tail-only reads while the
// mark holds (and the cutoff advancing as rows age), and a full read again
// whenever the settled rows change under the mark.
func TestProcessMetricsForSession(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	t0 := t0Proc()

	ids := map[string]int64{}
	persist := func(key string, startOff, seenOff time.Duration, samples int) {
		t.Helper()
		r := quietRun(key, sess, pid, 2000+len(ids), t0.Add(startOff))
		r.LastSeenAt = t0.Add(seenOff)
		for i := range samples {
			r.MetricSamples = append(r.MetricSamples, procmodel.MetricSample{
				T: t0.Add(startOff + time.Duration(i)*2*time.Second), CPUMs: int64(i) * 100, WorkingSet: 1 << 20,
			})
		}
		if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{r}); err != nil {
			t.Fatalf("PersistRuns %s: %v", key, err)
		}
		var id int64
		if err := db.QueryRowContext(ctx, `SELECT id FROM process_runs WHERE process_key = ?`, key).Scan(&id); err != nil {
			t.Fatalf("id of %s: %v", key, err)
		}
		ids[key] = id
	}
	// Three old ring rows, two recent ones, one recent row with no ring.
	persist("old-a", 0, time.Minute, 3)
	persist("old-b", time.Second, time.Minute, 1)
	persist("old-c", 2*time.Second, time.Minute, 2)
	persist("new-a", time.Hour, time.Hour, 2)
	persist("new-b", time.Hour+time.Second, time.Hour, 3)
	persist("bare", time.Hour+2*time.Second, time.Hour, 0)

	idSum := func(keys ...string) int64 {
		var n int64
		for _, k := range keys {
			n += ids[k]
		}
		return n
	}

	var mark *ProcessMetricsSettled
	for _, step := range []struct {
		name     string
		mutate   func()
		useMark  bool
		full     bool
		total    int64
		runs     string // process keys returned, in order
		settled  string // the returned keys flagged Settled
		markRows int64
		markKeys []string
	}{
		{
			name: "first read is full and settles the old rows",
			full: true, total: 6,
			runs: "old-a old-b old-c new-a new-b ", settled: "old-a old-b old-c ",
			markRows: 3, markKeys: []string{"old-a", "old-b", "old-c"},
		},
		{
			name: "an unchanged mark reads only the tail", useMark: true,
			total: 6, runs: "new-a new-b ", settled: "",
			markRows: 3, markKeys: []string{"old-a", "old-b", "old-c"},
		},
		{
			name:    "the cutoff advances as the tail ages",
			mutate:  func() { persist("newer", 2*time.Hour, 2*time.Hour, 2) },
			useMark: true, total: 7,
			runs: "new-a new-b newer ", settled: "new-a new-b ",
			markRows: 5, markKeys: []string{"old-a", "old-b", "old-c", "new-a", "new-b"},
		},
		{
			name: "the advanced mark reads only the newest tail", useMark: true,
			total: 7, runs: "newer ", settled: "",
			markRows: 5, markKeys: []string{"old-a", "old-b", "old-c", "new-a", "new-b"},
		},
		{
			name:    "a settled row seen again falls back to a full read",
			mutate:  func() { persist("old-b", time.Second, 2*time.Hour, 1) },
			useMark: true, full: true, total: 7,
			runs: "old-a old-b old-c new-a new-b newer ", settled: "old-a old-c new-a new-b ",
			markRows: 4, markKeys: []string{"old-a", "old-c", "new-a", "new-b"},
		},
		{
			name: "a settled row deleted falls back to a full read",
			mutate: func() {
				if _, err := db.ExecContext(ctx, `DELETE FROM process_runs WHERE process_key = 'old-a'`); err != nil {
					t.Fatalf("delete: %v", err)
				}
			},
			useMark: true, full: true, total: 6,
			runs: "old-b old-c new-a new-b newer ", settled: "old-c new-a new-b ",
			markRows: 3, markKeys: []string{"old-c", "new-a", "new-b"},
		},
		{
			name:    "an old row attached late falls back to a full read",
			mutate:  func() { persist("late", 3*time.Second, time.Minute, 2) },
			useMark: true, full: true, total: 7,
			runs: "old-b old-c late new-a new-b newer ", settled: "old-c late new-a new-b ",
			markRows: 4, markKeys: []string{"old-c", "late", "new-a", "new-b"},
		},
	} {
		if step.mutate != nil {
			step.mutate()
		}
		q := ProcessMetricsQuery{SettleAge: 10 * time.Minute}
		if step.useMark {
			q.Known = mark
		}
		res, err := s.ProcessMetricsForSession(ctx, sess, q)
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		var runs, settled string
		for _, r := range res.Runs {
			runs += r.ProcessKey + " "
			if r.Settled {
				settled += r.ProcessKey + " "
			}
			if len(r.Samples) == 0 {
				t.Errorf("%s: %s returned with no samples (ring-less rows must be skipped)", step.name, r.ProcessKey)
			}
		}
		if res.Full != step.full || res.Total != step.total || runs != step.runs || settled != step.settled {
			t.Errorf("%s: full=%v total=%d runs=%q settled=%q, want full=%v total=%d runs=%q settled=%q",
				step.name, res.Full, res.Total, runs, settled, step.full, step.total, step.runs, step.settled)
		}
		if res.Settled.Rows != step.markRows || res.Settled.IDSum != idSum(step.markKeys...) {
			t.Errorf("%s: mark rows/idsum = %d/%d, want %d/%d",
				step.name, res.Settled.Rows, res.Settled.IDSum, step.markRows, idSum(step.markKeys...))
		}
		m := res.Settled
		mark = &m
	}
}

// TestProcessMetricsForSessionEmpty: an unknown session reads as empty, and
// no age settles nothing.
func TestProcessMetricsForSessionEmpty(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	res, err := s.ProcessMetricsForSession(context.Background(), "nope", ProcessMetricsQuery{})
	if err != nil {
		t.Fatalf("ProcessMetricsForSession: %v", err)
	}
	if !res.Full || res.Total != 0 || len(res.Runs) != 0 || res.Settled != (ProcessMetricsSettled{}) {
		t.Errorf("empty session = %+v, want a full empty read with a zero mark", res)
	}
}
