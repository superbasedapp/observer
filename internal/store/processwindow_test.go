package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// seedWindowRuns stores n exited runs of one session, one per second from
// t0Proc, every one a child of the first.
func seedWindowRuns(t *testing.T, s *Store, sess string, pid int64, n int) {
	t.Helper()
	var runs []procmodel.ProcessRun
	for i := range n {
		r := quietRun(fmt.Sprintf("w-%02d", i), sess, pid, 1000+i, t0Proc().Add(time.Duration(i)*time.Second))
		if i > 0 {
			r.ParentProcessKey = "w-00"
		}
		runs = append(runs, r)
	}
	if _, err := s.PersistRuns(context.Background(), runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
}

func windowKeys(rows []ProcessRunRow) string {
	out := ""
	for _, r := range rows {
		out += r.ProcessKey[2:] + " "
	}
	return out
}

// TestProcessRunsWindowForSession pins the windowed tree read (plan §9.3):
// newest rows by default, oldest first, the limit cap, To inclusive of its
// second, From, Since, and the truncated flag.
func TestProcessRunsWindowForSession(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	seedWindowRuns(t, s, sess, pid, 10)
	at := func(i int) time.Time { return t0Proc().Add(time.Duration(i) * time.Second) }

	for _, tc := range []struct {
		name      string
		w         ProcessRunWindow
		want      string
		truncated bool
	}{
		{"default is everything when small", ProcessRunWindow{}, "00 01 02 03 04 05 06 07 08 09 ", false},
		{"limit keeps the newest", ProcessRunWindow{Limit: 3}, "07 08 09 ", true},
		{"to is inclusive and pages earlier", ProcessRunWindow{Limit: 3, To: at(5)}, "03 04 05 ", true},
		{"to at the start ends paging", ProcessRunWindow{Limit: 3, To: at(1)}, "00 01 ", false},
		{"from excludes older rows", ProcessRunWindow{From: at(8)}, "08 09 ", true},
		{"from at the first row", ProcessRunWindow{From: at(0), To: at(2)}, "00 01 02 ", false},
		{"since polls recent rows", ProcessRunWindow{Since: at(9)}, "09 ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := s.ProcessRunsWindowForSession(ctx, sess, tc.w)
			if err != nil {
				t.Fatal(err)
			}
			if got := windowKeys(res.Rows); got != tc.want || res.Truncated != tc.truncated {
				t.Fatalf("rows %q truncated %v, want %q truncated %v", got, res.Truncated, tc.want, tc.truncated)
			}
		})
	}
	if got := (ProcessRunWindow{Limit: 50000}).Normalized().Limit; got != ProcessWindowMaxLimit {
		t.Fatalf("limit cap = %d", got)
	}
	if got := (ProcessRunWindow{}).Normalized().Limit; got != ProcessWindowDefaultLimit {
		t.Fatalf("default limit = %d", got)
	}

	rows, maxID, err := s.ProcessSessionRowMark(ctx, sess)
	if err != nil || rows != 10 || maxID == 0 {
		t.Fatalf("row mark %d %d %v", rows, maxID, err)
	}
	if m, err := s.ProcessSessionRecentMark(ctx, sess, 0); err != nil || m.LastSeen == "" || m.Exited != 0 {
		t.Fatalf("recent mark %+v %v", m, err)
	}
}

// TestProcessFindingsForSessionWindow: findings come from the window's rows
// only.
func TestProcessFindingsForSessionWindow(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	old := quietRun("f-old", sess, pid, 10, t0Proc())
	old.ExePath = "/tmp/payload"
	recent := quietRun("f-new", sess, pid, 11, t0Proc().Add(time.Hour))
	if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{old, recent}); err != nil {
		t.Fatal(err)
	}
	all, err := s.ProcessFindingsForSessionWindow(ctx, sess, ProcessRunWindow{})
	if err != nil || len(all) != 1 || all[0].ProcessKey != "f-old" {
		t.Fatalf("all findings %+v %v", all, err)
	}
	recentOnly, err := s.ProcessFindingsForSessionWindow(ctx, sess, ProcessRunWindow{Limit: 1})
	if err != nil || len(recentOnly) != 0 {
		t.Fatalf("windowed findings %+v %v", recentOnly, err)
	}
}

// TestProcessServiceRootsForSession: a service root with its kept rows and
// its rollups summed; exemplars are not services.
func TestProcessServiceRootsForSession(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	root := quietRun("svc", sess, pid, 50, t0Proc())
	root.CaptureClass, root.ServiceRootKey, root.CPUUserMs = "service_root", "svc", 10
	var runs []procmodel.ProcessRun
	runs = append(runs, root)
	for i := range 2 {
		r := quietRun(fmt.Sprintf("svc-%d", i), sess, pid, 60+i, t0Proc().Add(time.Duration(i+1)*time.Second))
		r.ParentProcessKey, r.CaptureClass, r.ServiceRootKey, r.CPUUserMs, r.MaxRSSBytes = "svc", "service", "svc", 5, 700
		runs = append(runs, r)
	}
	plain := quietRun("plain", sess, pid, 70, t0Proc())
	plain.CaptureClass = "exemplar"
	runs = append(runs, plain)
	last := t0Proc().Add(10 * time.Minute)
	delta := proccapture.Delta{Rollups: []proccapture.Rollup{{
		Key: proccapture.GroupKey{
			SessionID: sess, BucketStart: proccapture.BucketStart(last, time.Minute), Kind: proccapture.GroupService,
			ParentProcessKey: "svc", ServiceRootKey: "svc", ExeBasename: "docker.exe", ArgvTemplateHash: "h",
		},
		Count: 40, CPUSumMs: 100, PeakRSSBytes: 900, FirstSeen: last, LastSeen: last,
	}}}
	if _, err := s.PersistCapture(ctx, runs, delta); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProcessServiceRootsForSession(ctx, sess, 0)
	if err != nil || len(got) != 1 {
		t.Fatalf("roots %+v %v", got, err)
	}
	r := got[0]
	if r.RootKey != "svc" || r.Kept != 2 || r.RolledUp != 40 || r.CPUSumMs != 120 || r.PeakRSSBytes != 900 || !r.LastSeen.Equal(last) {
		t.Fatalf("root %+v", r)
	}
}

// compactionFixture stores a legacy (pre-budget) session: a seed root, one
// tool-call shell, n short successful git children, one failed child and one
// child running from /tmp (a finding).
func compactionFixture(t *testing.T, s *Store, sess string, pid int64, n int) {
	t.Helper()
	at := func(ms int) time.Time { return t0Proc().Add(time.Duration(ms) * time.Millisecond) }
	mk := func(key, parent, exe string, i int) procmodel.ProcessRun {
		r := quietRun(key, sess, pid, 2000+i, at(i*50))
		r.ParentProcessKey, r.ExeBasename, r.ArgvPreview = parent, exe, exe+" status"
		r.Exited, r.DurationMs, r.LastSeenAt, r.ExitedAt = true, 40, at(i*50+40), at(i*50+40)
		if parent != "" {
			r.Attribution.Source = procmodel.AttrInherited
		}
		return r
	}
	runs := []procmodel.ProcessRun{mk("c-root", "", "claude", 0), mk("c-sh", "c-root", "bash", 1)}
	for i := range n {
		runs = append(runs, mk(fmt.Sprintf("c-git-%03d", i), "c-sh", "git", i+2))
	}
	failed := mk("c-failed", "c-sh", "git", n+2)
	failed.ExitCode = 1
	finding := mk("c-tmp", "c-sh", "payload", n+3)
	finding.ExePath = "/tmp/payload"
	runs = append(runs, failed, finding)
	if _, err := s.PersistRuns(context.Background(), runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
}

func activityMark(t *testing.T, s *Store, sess string) ProcessCompactionMark {
	t.Helper()
	acts, err := s.ProcessSessionActivities(context.Background(), sess, 0)
	if err != nil || len(acts) != 1 {
		t.Fatalf("activities %+v %v", acts, err)
	}
	return acts[0].CompactionMark()
}

// TestCompactionMarkIgnoresServiceRows pins what a service subtree does to the
// watermark: a service row sighted or added after planning cancels nothing,
// while one of the session's own rows being sighted still does.
func TestCompactionMarkIgnoresServiceRows(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	compactionFixture(t, s, sess, pid, 120)
	svc := func(key string, pidN int, seen time.Time) procmodel.ProcessRun {
		r := quietRun(key, sess, pid, pidN, t0Proc())
		r.CaptureClass, r.ServiceRootKey, r.LastSeenAt = "service", "svc", seen
		return r
	}
	if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{svc("svc-a", 900, t0Proc().Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	mark := activityMark(t, s, sess)
	acts, err := s.ProcessSessionActivities(ctx, sess, 0)
	if err != nil || len(acts) != 1 {
		t.Fatalf("activities %+v %v", acts, err)
	}
	if acts[0].Rows != acts[0].OwnRows+1 {
		t.Fatalf("Rows %d, OwnRows %d: the service row must count in one only", acts[0].Rows, acts[0].OwnRows)
	}
	if !acts[0].LastActivity().Before(t0Proc().Add(time.Hour)) {
		t.Fatalf("a service sighting counted as activity: %s", acts[0].LastActivity())
	}

	if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{
		svc("svc-a", 900, t0Proc().Add(2*time.Hour)), svc("svc-b", 901, t0Proc().Add(2*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
	if got := activityMark(t, s, sess); got != mark {
		t.Fatalf("service rows moved the mark: %+v -> %+v", mark, got)
	}

	rows, err := s.LoadSessionCaptureRows(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	cfg := proccapture.DefaultConfig()
	cfg.PerToolCall = 20
	p, err := proccapture.PlanCompaction(sess, rows, proccapture.Stats{}, false, cfg)
	if err != nil || len(p.Delete) == 0 {
		t.Fatalf("plan %+v %v", p, err)
	}
	own := quietRun("c-root", sess, pid, 2000, t0Proc())
	own.LastSeenAt = t0Proc().Add(3 * time.Hour)
	if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{own}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompactProcessSession(ctx, p, mark); !errors.Is(err, ErrProcessCompactionStale) {
		t.Fatalf("an own row sighted after planning: err = %v", err)
	}
	if _, err := s.CompactProcessSession(ctx, p, activityMark(t, s, sess)); err != nil {
		t.Fatalf("compaction under a live service: %v", err)
	}
}

// TestCompactProcessSession pins the copy-then-delete compaction: the over
// budget rows become rollups and are deleted, the failure and the finding
// survive, the stats row satisfies the count invariant, a second compaction
// is a no-op, and a stale watermark writes nothing.
func TestCompactProcessSession(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	compactionFixture(t, s, sess, pid, 120)
	cfg := proccapture.DefaultConfig()
	cfg.PerToolCall = 20

	plan := func() proccapture.CompactionPlan {
		rows, err := s.LoadSessionCaptureRows(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		st, ok, err := s.ProcessCaptureStatsForSession(ctx, sess)
		if err != nil {
			t.Fatal(err)
		}
		p, err := proccapture.PlanCompaction(sess, rows, st, ok, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	// A stale watermark (a row arrived after planning) writes nothing.
	p := plan()
	if len(p.Delete) == 0 {
		t.Fatal("expected rows to compact")
	}
	mark := activityMark(t, s, sess)
	stale := mark
	stale.Rows++
	if _, err := s.CompactProcessSession(ctx, p, stale); !errors.Is(err, ErrProcessCompactionStale) {
		t.Fatalf("stale compaction err = %v", err)
	}
	if _, ok, _ := s.ProcessCaptureStatsForSession(ctx, sess); ok {
		t.Fatal("a stale compaction wrote stats")
	}

	res, err := s.CompactProcessSession(ctx, p, mark)
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != int64(len(p.Delete)) {
		t.Fatalf("deleted %d, planned %d", res.Deleted, len(p.Delete))
	}
	runs, err := s.ProcessRunsForSession(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]ProcessRunRow{}
	for _, r := range runs {
		have[r.ProcessKey] = r
		if r.CaptureClass == "" {
			t.Fatalf("kept legacy row %s was not stamped", r.ProcessKey)
		}
	}
	for _, k := range []string{"c-root", "c-sh", "c-failed", "c-tmp"} {
		if _, ok := have[k]; !ok {
			t.Fatalf("protected row %s was compacted away", k)
		}
	}
	st, ok, err := s.ProcessCaptureStatsForSession(ctx, sess)
	if err != nil || !ok {
		t.Fatalf("stats %v %v", ok, err)
	}
	if st.Observed != int64(p.Rows) || st.Observed != st.Accounted() {
		t.Fatalf("stats %+v: observed must equal the %d stored rows and the accounted total", st, p.Rows)
	}
	if st.Kept+st.ServiceKept != int64(len(runs)) {
		t.Fatalf("stats kept %d+%d, rows left %d", st.Kept, st.ServiceKept, len(runs))
	}
	rollups, err := s.ProcessRollupsForSession(ctx, sess, 0)
	if err != nil {
		t.Fatal(err)
	}
	var rolled int64
	for _, r := range rollups {
		rolled += r.Count
	}
	if rolled != st.Folded+st.RolledUp+st.ServiceRolledUp {
		t.Fatalf("rollups %d, stats %+v", rolled, st)
	}

	again := plan()
	if !again.Empty() {
		t.Fatalf("second compaction is not a no-op: delete %d updates %d delta %+v", len(again.Delete), len(again.Updates), again.StatsDelta)
	}
}

// quietRun is execRun with the effective uid equal to the real one, so the
// run fires no privileged-exec finding (execRun leaves euid 0).
func quietRun(key, sess string, projectID int64, pid int, started time.Time) procmodel.ProcessRun {
	r := execRun(key, sess, projectID, pid, started)
	r.EUID = r.UID
	return r
}
