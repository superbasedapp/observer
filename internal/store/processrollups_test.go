package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// TestPersistCaptureRollupsStatsAndFolds pins the one-transaction capture
// write: the exemplar row with its capture columns, the fold increment on
// it, rollup increments that ADD (including the NULL-session machine
// rollup), stats increments, and the read helpers.
func TestPersistCaptureRollupsStatsAndFolds(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)

	parent := execRun("key-parent", sess, pid, 200, t0Proc())
	parent.CaptureClass = string(proccapture.ClassServiceRoot)
	parent.ServiceRootKey = "key-parent"
	bucket := proccapture.BucketStart(t0Proc(), time.Minute)
	key := proccapture.GroupKey{
		SessionID: sess, BucketStart: bucket, Kind: proccapture.GroupService,
		ParentProcessKey: "key-parent", ServiceRootKey: "key-parent", ExeBasename: "docker.exe", ArgvTemplateHash: "h1",
	}
	machine := proccapture.GroupKey{BucketStart: bucket, Kind: proccapture.GroupUnattributed, ExeBasename: "git", ArgvTemplateHash: "h2"}
	delta := proccapture.Delta{
		Rollups: []proccapture.Rollup{
			{
				Key: key, Count: 3, FailedCount: 1, DurationSumMs: 30, DurationMaxMs: 20, CPUSumMs: 9, PeakRSSBytes: 100,
				FirstSeen: t0Proc(), LastSeen: t0Proc().Add(time.Second), ExampleArgvPreview: "docker.exe stats", ExampleProcessKey: "k1",
			},
			{Key: machine, Count: 2, FirstSeen: t0Proc(), LastSeen: t0Proc()},
		},
		Stats: map[string]proccapture.Stats{sess: {Observed: 5, ServiceKept: 1, ServiceRolledUp: 3, Folded: 1}},
		Folds: map[string]int64{"key-parent": 1},
	}
	if _, err := s.PersistCapture(ctx, []procmodel.ProcessRun{parent}, delta); err != nil {
		t.Fatalf("PersistCapture: %v", err)
	}
	// A second flush adds to the same groups (both the session group and the
	// NULL-session machine group) and re-persists the parent without
	// resetting its fold count.
	delta2 := proccapture.Delta{
		Rollups: []proccapture.Rollup{
			{Key: key, Count: 2, DurationSumMs: 10, DurationMaxMs: 50, PeakRSSBytes: 50, FirstSeen: t0Proc().Add(-time.Second), LastSeen: t0Proc().Add(5 * time.Second)},
			{Key: machine, Count: 1, FirstSeen: t0Proc(), LastSeen: t0Proc()},
		},
		Stats: map[string]proccapture.Stats{sess: {Observed: 2, ServiceRolledUp: 2}},
		Folds: map[string]int64{"key-parent": 2, "key-missing": 1},
	}
	if _, err := s.PersistCapture(ctx, []procmodel.ProcessRun{parent}, delta2); err != nil {
		t.Fatalf("PersistCapture 2: %v", err)
	}

	runs, err := s.ProcessRunsForSession(ctx, sess)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs %v %v", runs, err)
	}
	if r := runs[0]; r.CaptureClass != "service_root" || r.ServiceRootKey != "key-parent" || r.FoldCount != 3 {
		t.Fatalf("capture columns %+v", r)
	}

	rs, err := s.ProcessRollupsForSession(ctx, sess, 0)
	if err != nil || len(rs) != 1 {
		t.Fatalf("rollups %v %v", rs, err)
	}
	if r := rs[0]; r.Count != 5 || r.FailedCount != 1 || r.DurationSumMs != 40 || r.DurationMaxMs != 50 || r.CPUSumMs != 9 ||
		r.PeakRSSBytes != 100 || !r.FirstSeen.Equal(t0Proc().Add(-time.Second)) || !r.LastSeen.Equal(t0Proc().Add(5*time.Second)) ||
		r.ExampleArgvPreview != "docker.exe stats" || r.GroupKind != "service" {
		t.Fatalf("summed rollup %+v", r)
	}
	ms, err := s.ProcessRollupsForSession(ctx, "", 0)
	if err != nil || len(ms) != 1 || ms[0].Count != 3 {
		t.Fatalf("machine rollup %+v %v", ms, err)
	}
	bs, err := s.ProcessRollupBucketsForSession(ctx, sess, time.Time{}, time.Time{}, 0)
	if err != nil || len(bs) != 1 || !bs[0].BucketStart.Equal(bucket) {
		t.Fatalf("buckets %+v %v", bs, err)
	}

	st, ok, err := s.ProcessCaptureStatsForSession(ctx, sess)
	if err != nil || !ok {
		t.Fatalf("stats %v %v", ok, err)
	}
	if st.Observed != 7 || st.ServiceRolledUp != 5 || st.Observed != st.Accounted() {
		t.Fatalf("stats %+v", st)
	}
	if _, ok, _ := s.ProcessCaptureStatsForSession(ctx, "legacy"); ok {
		t.Fatal("a session with no stats row must read as legacy")
	}
}

// TestApplyUnattributedPolicy pins the unattributed policy: one capped batch
// of session-less rows older than pending_hours becomes the machine rollup
// and is deleted; younger rows and attributed rows stay; drop mode writes no
// rollup.
func TestApplyUnattributedPolicy(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	now := time.Now().UTC()

	var runs []procmodel.ProcessRun
	for i := range 5 {
		r := execRun("old-"+string(rune('a'+i)), "", 0, 300+i, now.Add(-48*time.Hour))
		r.Attribution = procmodel.Attribution{Source: procmodel.AttrNone, Confidence: procmodel.ConfNone}
		runs = append(runs, r)
	}
	young := execRun("young", "", 0, 400, now.Add(-time.Hour))
	young.Attribution = procmodel.Attribution{Source: procmodel.AttrNone, Confidence: procmodel.ConfNone}
	runs = append(runs, young, execRun("attributed-old", sess, pid, 401, now.Add(-48*time.Hour)))
	if _, err := s.PersistRuns(ctx, runs); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := proccapture.DefaultConfig()
	res, err := s.ApplyUnattributedPolicy(ctx, cfg, now, 3)
	if err != nil || res.RowsProcessed != 3 || res.RollupGroups == 0 {
		t.Fatalf("first batch %+v %v", res, err)
	}
	res, err = s.ApplyUnattributedPolicy(ctx, cfg, now, 3)
	if err != nil || res.RowsProcessed != 2 {
		t.Fatalf("second batch %+v %v", res, err)
	}
	if n, _ := s.CountProcessRuns(ctx); n != 2 {
		t.Fatalf("remaining runs %d, want young + attributed", n)
	}
	ms, err := s.ProcessRollupsForSession(ctx, "", 0)
	if err != nil || len(ms) != 1 || ms[0].Count != 5 || ms[0].GroupKind != "unattributed" {
		t.Fatalf("machine rollup %+v %v", ms, err)
	}
	st, ok, _ := s.ProcessCaptureStatsForSession(ctx, "")
	if !ok || st.RolledUp != 5 || st.Observed != st.Accounted() {
		t.Fatalf("machine stats %+v", st)
	}

	// Drop mode deletes without a rollup.
	cfg.UnattributedMode = proccapture.UnattributedDrop
	cfg.PendingHours = 0
	if res, _ := s.ApplyUnattributedPolicy(ctx, cfg, now, 0); res.RowsProcessed != 0 {
		t.Fatal("pending_hours 0 must be a no-op")
	}
	cfg.PendingHours = 0
	cfg.PendingHours = 1
	res, err = s.ApplyUnattributedPolicy(ctx, cfg, now.Add(2*time.Hour), 0)
	if err != nil || res.RowsProcessed != 1 || res.RollupGroups != 0 {
		t.Fatalf("drop %+v %v", res, err)
	}
	st, _, _ = s.ProcessCaptureStatsForSession(ctx, "")
	if st.Dropped != 1 || st.Observed != st.Accounted() {
		t.Fatalf("machine stats after drop %+v", st)
	}
}

// TestLoadCaptureHistoryAndPrune pins the estimate loader and the capture
// prune.
func TestLoadCaptureHistoryAndPrune(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	now := time.Now().UTC()
	parent := execRun("p", sess, pid, 500, now.Add(-time.Hour))
	child := execRun("c", sess, pid, 501, now.Add(-time.Hour+time.Second))
	child.ParentProcessKey = "p"
	child.ExeBasename = "conhost.exe"
	child.Exited, child.ExitedAt, child.ExitCode, child.DurationMs = true, now, 1, 1500
	old := execRun("old", sess, pid, 502, now.Add(-30*24*time.Hour))
	if _, err := s.PersistRuns(ctx, []procmodel.ProcessRun{parent, child, old}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h, err := s.LoadCaptureHistory(ctx, time.Time{}, 0)
	if err != nil || len(h) != 2 {
		t.Fatalf("history %d %v", len(h), err)
	}
	if h[0].ProcessKey != "p" || h[1].ParentExeBasename != "bash" || !h[1].Failed || !h[1].Ended ||
		h[1].AliveFor != 1500*time.Millisecond || h[1].StoredBytes == 0 {
		t.Fatalf("facts %+v", h)
	}
	if lim, _ := s.LoadCaptureHistory(ctx, time.Time{}, 1); len(lim) != 1 || lim[0].ProcessKey != "c" {
		t.Fatalf("limit keeps the newest: %+v", lim)
	}

	// Prune: an old bucket and a stale stats row go, fresh ones stay.
	oldKey := proccapture.GroupKey{SessionID: sess, BucketStart: now.Add(-40 * 24 * time.Hour), Kind: proccapture.GroupBudget}
	newKey := proccapture.GroupKey{SessionID: sess, BucketStart: now, Kind: proccapture.GroupBudget}
	if _, err := s.PersistCapture(ctx, nil, proccapture.Delta{
		Rollups: []proccapture.Rollup{{Key: oldKey, Count: 1}, {Key: newKey, Count: 1}},
		Stats:   map[string]proccapture.Stats{sess: {Observed: 1, Kept: 1}},
	}); err != nil {
		t.Fatalf("seed rollups: %v", err)
	}
	if n, err := s.PruneProcessCaptureRows(ctx, 0); err != nil || n != 0 {
		t.Fatalf("disabled prune %d %v", n, err)
	}
	n, err := s.PruneProcessCaptureRows(ctx, 30)
	if err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
	if _, ok, _ := s.ProcessCaptureStatsForSession(ctx, sess); !ok {
		t.Fatal("a fresh stats row was pruned")
	}
}
