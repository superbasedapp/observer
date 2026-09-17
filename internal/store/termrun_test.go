package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func openTermRunTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "termrun_test.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database), ctx
}

func TestTerminalRunRoundTrip(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	launched := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	run := TerminalRun{
		RunID:                "run-abc",
		Tool:                 "claude-code",
		Kind:                 "handoff",
		SourceSessionID:      "sess-source",
		ProjectRootHash:      "deadbeef",
		CorrelationTokenHash: "cafef00d",
		LaunchedAt:           launched,
	}
	if err := st.InsertTerminalRun(ctx, run); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}

	got, ok, err := st.LoadTerminalRun(ctx, "run-abc")
	if err != nil || !ok {
		t.Fatalf("LoadTerminalRun ok=%v err=%v", ok, err)
	}
	if got.Tool != "claude-code" || got.Kind != "handoff" || got.SourceSessionID != "sess-source" {
		t.Errorf("run = %+v", got)
	}
	if got.ProjectRootHash != "deadbeef" || got.CorrelationTokenHash != "cafef00d" {
		t.Errorf("hashes not round-tripped: %+v", got)
	}
	if !got.LaunchedAt.Equal(launched) {
		t.Errorf("launchedAt = %v, want %v", got.LaunchedAt, launched)
	}
	if got.EndedAt != nil || got.ExitCode != nil {
		t.Errorf("fresh run must have nil ended_at/exit_code, got %+v", got)
	}

	// End the run.
	ended := launched.Add(5 * time.Minute)
	if err := st.EndTerminalRun(ctx, "run-abc", ended, 0, EndReasonChildExit); err != nil {
		t.Fatalf("EndTerminalRun: %v", err)
	}
	got2, _, err := st.LoadTerminalRun(ctx, "run-abc")
	if err != nil {
		t.Fatalf("LoadTerminalRun after end: %v", err)
	}
	if got2.EndedAt == nil || !got2.EndedAt.Equal(ended) {
		t.Errorf("endedAt = %v, want %v", got2.EndedAt, ended)
	}
	if got2.ExitCode == nil || *got2.ExitCode != 0 {
		t.Errorf("exitCode = %v, want 0", got2.ExitCode)
	}
	if got2.EndReason != EndReasonChildExit {
		t.Errorf("endReason = %q, want %q", got2.EndReason, EndReasonChildExit)
	}
}

// TestLiveRunForSession pins the durable double-spawn AUTHORITY (round-5 finding
// 1): the query reports a conflict for a LIVE (ended_at NULL) run correlated to a
// session at or above the confidence gate, and abstains for an ended run, a
// below-gate weak correlation, and an uncorrelated session — kind-agnostically.
func TestLiveRunForSession(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	ended := time.Now().UTC()

	mk := func(id, kind string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: id, Tool: "claude-code", Kind: kind}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	correlate := func(id, sess string, conf float64, src string) {
		if err := st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: id, SessionID: sess, Confidence: conf, Source: src}); err != nil {
			t.Fatalf("correlate %s: %v", id, err)
		}
	}

	// (1) live + strongly correlated → a conflict. kind='resume' proves the query
	//     is kind-agnostic (a dashboard resume is not KindAttach).
	mk("live", "resume")
	correlate("live", "sess-live", 0.95, "oob")
	// (2) correlated but the run ENDED → not a live conflict.
	mk("ended", "attach")
	if err := st.EndTerminalRun(ctx, "ended", ended, 0, EndReasonChildExit); err != nil {
		t.Fatalf("end: %v", err)
	}
	correlate("ended", "sess-ended", 0.95, "oob")
	// (3) live but only WEAKLY correlated (below the gate) → abstain.
	mk("weak", "attach")
	correlate("weak", "sess-weak", 0.40, "heuristic")

	cases := []struct {
		session string
		want    bool
	}{
		{"sess-live", true},   // live + established correlation
		{"sess-ended", false}, // correlated but the run ended
		{"sess-weak", false},  // live but below the confidence gate
		{"sess-none", false},  // nothing correlated at all
		{"", false},           // empty session id is never a conflict
	}
	for _, tc := range cases {
		got, err := st.LiveRunForSession(ctx, tc.session, 0.50)
		if err != nil {
			t.Fatalf("LiveRunForSession(%q): %v", tc.session, err)
		}
		if got != tc.want {
			t.Errorf("LiveRunForSession(%q) = %v, want %v", tc.session, got, tc.want)
		}
	}
}

// TestLiveRunForSessionExcluding pins the review finding-1 fix (self-blocking
// authority): the durable authority must NOT count a conclusively-dead orphan
// (end_reason 'resumed'/'daemon_shutdown', ended_at NULL) as live, and must
// exclude the caller-supplied predecessor run ids — so a crash-orphan auto-resume
// never self-blocks on its own predecessor — while a GENUINELY distinct live run
// for the same session still conflicts.
func TestLiveRunForSessionExcluding(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	mk := func(id, kind, reason string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: id, Tool: "claude-code", Kind: kind}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		if reason != "" {
			// Stamp the durable reason WITHOUT setting ended_at (mirrors the
			// shutdown/resumed sweeps: reason changes, ended_at stays NULL).
			if _, err := st.db.ExecContext(ctx,
				`UPDATE terminal_run SET end_reason = ? WHERE run_id = ?`, reason, id); err != nil {
				t.Fatalf("stamp %s: %v", id, err)
			}
		}
	}
	correlate := func(id, sess string) {
		if err := st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: id, SessionID: sess, Confidence: 0.95, Source: "oob"}); err != nil {
			t.Fatalf("correlate %s: %v", id, err)
		}
	}

	// (t3) A lone already-superseded orphan: end_reason='resumed', ended_at NULL,
	// correlated. It must NOT be a conflict (dead state).
	mk("resumed-orphan", "attach", EndReasonResumed)
	correlate("resumed-orphan", "sess-resumed")
	// A lone shutdown orphan (daemon_shutdown, ended_at NULL) is likewise dead.
	mk("shutdown-orphan", "attach", EndReasonDaemonShutdown)
	correlate("shutdown-orphan", "sess-shutdown")

	// A crash orphan (end_reason='', ended_at NULL), correlated — the predecessor
	// rediscovery offers for auto-resume. With NO exclusion it looks live (SQL
	// cannot tell it from a real live run); excluding its run id retires it.
	mk("crash-orphan", "attach", "")
	correlate("crash-orphan", "sess-crash")

	// A genuinely distinct live run for the SAME session as the crash orphan (a
	// dashboard run): end_reason='', ended_at NULL, NOT a predecessor. It must
	// still conflict even when the crash orphan is excluded.
	mk("dash-live", "resume", "")
	correlate("dash-live", "sess-crash")

	cases := []struct {
		name    string
		session string
		exclude []string
		want    bool
	}{
		{"resumed orphan alone → no conflict", "sess-resumed", nil, false},
		{"shutdown orphan alone → no conflict", "sess-shutdown", nil, false},
		{"crash orphan excluded → no self-block", "sess-crash", []string{"crash-orphan", "dash-live"}, false},
		{"crash orphan excluded but distinct live run remains → conflict", "sess-crash", []string{"crash-orphan"}, true},
		{"no exclusion, live run present → conflict", "sess-crash", nil, true},
	}
	for _, tc := range cases {
		got, err := st.LiveRunForSessionExcluding(ctx, tc.session, 0.50, tc.exclude)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestEndReasonGuardedAndSweeps pins the H2 end-reason semantics: EndTerminalRun
// never downgrades an existing reason, the graceful-shutdown sweep stamps only
// live attach runs, and the resumed-supersede targets a session's orphan(s).
func TestEndReasonGuardedAndSweeps(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	mk := func(id string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID: id, Tool: "claude-code", Kind: "attach", LaunchedAt: base,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// live1: live attach run correlated to a session (shutdown orphan candidate).
	mk("live1")
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "live1", SessionID: "sess-1", Confidence: 0.95, Source: "oob", ObservedAt: base,
	}); err != nil {
		t.Fatalf("correlate: %v", err)
	}
	// exited1: already recorded a natural child exit.
	mk("exited1")
	if err := st.EndTerminalRun(ctx, "exited1", base.Add(time.Minute), 0, EndReasonChildExit); err != nil {
		t.Fatalf("end exited1: %v", err)
	}

	// Shutdown sweep: only live1 gets stamped (exited1 already ended).
	n, err := st.StampLiveAttachRunsShutdown(ctx)
	if err != nil {
		t.Fatalf("StampLiveAttachRunsShutdown: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept %d rows, want 1 (only the live attach run)", n)
	}
	r, _, _ := st.LoadTerminalRun(ctx, "live1")
	if r.EndReason != EndReasonDaemonShutdown {
		t.Fatalf("live1 end_reason = %q, want daemon_shutdown", r.EndReason)
	}
	if r.EndedAt != nil {
		t.Fatalf("shutdown stamp must NOT set ended_at, got %v", r.EndedAt)
	}

	// A racing natural OnExit now records ended_at but MUST NOT downgrade the
	// daemon_shutdown reason (guarded update).
	if err := st.EndTerminalRun(ctx, "live1", base.Add(2*time.Minute), 0, EndReasonChildExit); err != nil {
		t.Fatalf("racing end: %v", err)
	}
	r, _, _ = st.LoadTerminalRun(ctx, "live1")
	if r.EndReason != EndReasonDaemonShutdown {
		t.Fatalf("racing OnExit downgraded reason to %q — must stay daemon_shutdown", r.EndReason)
	}
	if r.EndedAt == nil {
		t.Fatal("racing OnExit must still record ended_at")
	}

	// A FRESH replacement run correlates to the SAME session via OOB (as the
	// codex resume announce does immediately) BEFORE the supersede stamp runs.
	// This is the wrong-run-supersede race: a by-session stamp would wrongly
	// mark this live row 'resumed'. StampResumedByRunID targets the predecessor
	// by exact id, so this new run must be LEFT untouched.
	mk("new1")
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "new1", SessionID: "sess-1", Confidence: 0.95, Source: "oob", ObservedAt: base,
	}); err != nil {
		t.Fatalf("correlate new1: %v", err)
	}

	// Supersede by RUN ID: stamps the predecessor live1 (daemon_shutdown →
	// resumed) and NOTHING else.
	if err := st.StampResumedByRunID(ctx, "live1"); err != nil {
		t.Fatalf("StampResumedByRunID: %v", err)
	}
	r, _, _ = st.LoadTerminalRun(ctx, "live1")
	if r.EndReason != EndReasonResumed {
		t.Fatalf("after supersede live1 end_reason = %q, want resumed", r.EndReason)
	}
	// The concurrently-correlated fresh run must NOT have been stamped — its
	// live row stays end_reason='' so the shutdown sweep + its own restart offer
	// still apply.
	rn, _, _ := st.LoadTerminalRun(ctx, "new1")
	if rn.EndReason != "" {
		t.Fatalf("fresh replacement run end_reason = %q, want '' (must not be superseded)", rn.EndReason)
	}
}

// TestStampLiveNonAttachRunsShutdown pins the FIX-2 sibling sweep: a live
// non-attach run (resume/fresh/handoff) is stamped 'daemon_shutdown' at graceful
// shutdown so the runs-history view stops showing it as live (the 2026-07-20
// orphaned resume-kind run), while the attach sweep stays DISJOINT (kind) and the
// attach resume-offer inputs are provably untouched.
func TestStampLiveNonAttachRunsShutdown(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 15, 24, 33, 0, time.UTC)

	mk := func(id, kind string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID: id, Tool: "claude-code", Kind: kind, LaunchedAt: base,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// A live attach run correlated to a session (offer candidate), a live
	// resume-kind run (the orphan), and an already-exited resume run.
	mk("attach-live", "attach")
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "attach-live", SessionID: "sess-A", Confidence: 0.95, Source: "oob", ObservedAt: base,
	}); err != nil {
		t.Fatalf("correlate: %v", err)
	}
	mk("resume-live", "resume")
	mk("fresh-live", "fresh")
	mk("resume-done", "resume")
	if err := st.EndTerminalRun(ctx, "resume-done", base.Add(time.Minute), 0, EndReasonChildExit); err != nil {
		t.Fatalf("end resume-done: %v", err)
	}

	// The attach sweep must NOT touch the non-attach kinds (disjoint by kind).
	nAttach, err := st.StampLiveAttachRunsShutdown(ctx)
	if err != nil {
		t.Fatalf("StampLiveAttachRunsShutdown: %v", err)
	}
	if nAttach != 1 {
		t.Fatalf("attach sweep stamped %d rows, want 1 (only the attach run)", nAttach)
	}
	if r, _, _ := st.LoadTerminalRun(ctx, "resume-live"); r.EndReason != "" {
		t.Fatalf("attach sweep leaked onto resume-live: end_reason=%q, want '' (disjoint by kind)", r.EndReason)
	}

	// The sibling sweep stamps exactly the two live NON-attach runs.
	nNon, err := st.StampLiveNonAttachRunsShutdown(ctx)
	if err != nil {
		t.Fatalf("StampLiveNonAttachRunsShutdown: %v", err)
	}
	if nNon != 2 {
		t.Fatalf("non-attach sweep stamped %d rows, want 2 (resume-live + fresh-live)", nNon)
	}
	for _, id := range []string{"resume-live", "fresh-live"} {
		r, _, _ := st.LoadTerminalRun(ctx, id)
		if r.EndReason != EndReasonDaemonShutdown {
			t.Fatalf("%s end_reason = %q, want daemon_shutdown", id, r.EndReason)
		}
		// Finding 4: the non-attach sweep MUST set ended_at so
		// /api/terminal/runs (running == ended_at==nil) stops rendering the dead
		// run as live — that was the exact bug this sweep was meant to fix.
		if r.EndedAt == nil {
			t.Fatalf("%s: sibling sweep must SET ended_at (running-view fix), got nil", id)
		}
	}
	// The already-exited resume run keeps its child_exit reason (excluded).
	if r, _, _ := st.LoadTerminalRun(ctx, "resume-done"); r.EndReason != EndReasonChildExit {
		t.Fatalf("resume-done end_reason = %q, want child_exit (already ended, excluded)", r.EndReason)
	}
	// Offerability of the attach run is UNCHANGED: it carries the same
	// daemon_shutdown reason it would have without the sibling sweep, so the
	// kind='attach'-scoped resume-offer path still classifies it resumable.
	if r, _, _ := st.LoadTerminalRun(ctx, "attach-live"); r.EndReason != EndReasonDaemonShutdown {
		t.Fatalf("attach-live end_reason = %q, want daemon_shutdown (offer path untouched)", r.EndReason)
	} else if r.EndedAt != nil {
		// The attach sweep MUST leave ended_at NULL — the resume-offer path keys
		// daemon-death orphan detection off it. The non-attach sweep setting
		// ended_at must not have leaked onto the attach kind.
		t.Fatalf("attach-live ended_at = %v, want nil (attach sweep leaves ended_at NULL for the resume-offer flow)", r.EndedAt)
	}
	// Idempotent: a second sibling sweep stamps nothing.
	if n, err := st.StampLiveNonAttachRunsShutdown(ctx); err != nil || n != 0 {
		t.Fatalf("second sibling sweep n=%d err=%v, want 0,nil (idempotent)", n, err)
	}
}

// TestStampResumedByRunIDs is the round-4 multi-orphan supersede: a single
// successful auto-resume stamps EVERY eligible predecessor orphan of the session
// (historical duplicates / prior stamp failures), not just the newest, applying
// StampResumedByRunID's guarded per-id semantics so a child_exit row is left
// untouched.
func TestStampResumedByRunIDs(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

	mk := func(id string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID: id, Tool: "claude-code", Kind: "attach", LaunchedAt: base,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	// Two eligible crash orphans (reason '') for one session, plus a natural
	// child-exit that must be left untouched by the guarded stamp.
	mk("orphan-new")
	mk("orphan-old")
	mk("done")
	if err := st.EndTerminalRun(ctx, "done", base.Add(time.Minute), 0, EndReasonChildExit); err != nil {
		t.Fatalf("end done: %v", err)
	}

	// Stamp all three ids in one call (as the supersede does for the session's
	// predecessor list); "done" is included to prove the guard leaves it alone.
	if err := st.StampResumedByRunIDs(ctx, []string{"orphan-new", "orphan-old", "done"}); err != nil {
		t.Fatalf("StampResumedByRunIDs: %v", err)
	}
	for _, id := range []string{"orphan-new", "orphan-old"} {
		r, _, _ := st.LoadTerminalRun(ctx, id)
		if r.EndReason != EndReasonResumed {
			t.Fatalf("%s end_reason = %q, want resumed", id, r.EndReason)
		}
	}
	r, _, _ := st.LoadTerminalRun(ctx, "done")
	if r.EndReason != EndReasonChildExit {
		t.Fatalf("done end_reason = %q, want child_exit (guarded, untouched)", r.EndReason)
	}
	// Empty input is a no-op (not an error).
	if err := st.StampResumedByRunIDs(ctx, nil); err != nil {
		t.Fatalf("empty StampResumedByRunIDs: %v", err)
	}
}

func TestListTerminalRuns(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	base := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	// Three runs, launched oldest→newest so ORDER BY DESC is observable.
	for i, id := range []string{"run-old", "run-mid", "run-new"} {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID:      id,
			Tool:       "claude-code",
			Kind:       "fresh",
			LaunchedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("InsertTerminalRun %s: %v", id, err)
		}
	}
	// Correlate run-mid with two sessions; the stronger one must win.
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: "run-mid", SessionID: "sess-weak", Confidence: 0.4, Source: "heuristic"}); err != nil {
		t.Fatalf("UpsertCorrelation weak: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: "run-mid", SessionID: "sess-strong", Confidence: 0.9, Source: "oob"}); err != nil {
		t.Fatalf("UpsertCorrelation strong: %v", err)
	}

	got, err := st.ListTerminalRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListTerminalRuns: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 runs, got %d", len(got))
	}
	// Newest first.
	if got[0].RunID != "run-new" || got[2].RunID != "run-old" {
		t.Errorf("order = %s..%s, want run-new..run-old", got[0].RunID, got[2].RunID)
	}
	// run-mid folds in the strongest correlation.
	var mid *TerminalRunSummary
	for i := range got {
		if got[i].RunID == "run-mid" {
			mid = &got[i]
		}
	}
	if mid == nil {
		t.Fatal("run-mid missing")
	}
	if mid.BestSessionID != "sess-strong" || mid.BestConfidence != 0.9 {
		t.Errorf("best correlation = %q/%v, want sess-strong/0.9", mid.BestSessionID, mid.BestConfidence)
	}
	// A run with no correlation reports an empty session.
	for _, r := range got {
		if r.RunID == "run-new" && (r.BestSessionID != "" || r.BestConfidence != 0) {
			t.Errorf("run-new should have no correlation, got %q/%v", r.BestSessionID, r.BestConfidence)
		}
	}

	// Limit is honored.
	limited, err := st.ListTerminalRuns(ctx, 1)
	if err != nil {
		t.Fatalf("ListTerminalRuns limit: %v", err)
	}
	if len(limited) != 1 || limited[0].RunID != "run-new" {
		t.Errorf("limit 1 = %+v, want [run-new]", limited)
	}
}

// TestSessionLinkedToAnyRun pins the discovery sweep's pre-link re-check:
// unlinked → false; linked at/above minConfidence → true (whether the run is
// still live or has since ended); linked only below minConfidence → false;
// the confidence boundary is inclusive (>=); and an empty session id always
// short-circuits to false.
func TestSessionLinkedToAnyRun(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	mk := func(id string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: id, Tool: "claude-code", Kind: "attach"}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	correlate := func(id, sess string, conf float64) {
		if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
			RunID: id, SessionID: sess, Confidence: conf, Source: "oob",
		}); err != nil {
			t.Fatalf("correlate %s: %v", id, err)
		}
	}

	mk("run-strong")
	correlate("run-strong", "sess-strong", 0.75)

	mk("run-weak")
	correlate("run-weak", "sess-weak", 0.40)

	mk("run-boundary")
	correlate("run-boundary", "sess-boundary", 0.50)

	mk("run-ended")
	correlate("run-ended", "sess-ended", 0.90)
	if err := st.EndTerminalRun(ctx, "run-ended", time.Now().UTC(), 0, EndReasonChildExit); err != nil {
		t.Fatalf("EndTerminalRun: %v", err)
	}

	cases := []struct {
		name    string
		session string
		want    bool
	}{
		{"unlinked session → false", "sess-none", false},
		{"linked at 0.75 → true", "sess-strong", true},
		{"linked only at 0.40 with minConfidence 0.50 → false", "sess-weak", false},
		{"linked at exactly 0.50 → true (boundary inclusive)", "sess-boundary", true},
		{"linked to an ENDED run still counts → true", "sess-ended", true},
		{"empty session id → false", "", false},
	}
	for _, tc := range cases {
		got, err := st.SessionLinkedToAnyRun(ctx, tc.session, 0.50)
		if err != nil {
			t.Fatalf("%s: SessionLinkedToAnyRun(%q): %v", tc.name, tc.session, err)
		}
		if got != tc.want {
			t.Errorf("%s: SessionLinkedToAnyRun(%q) = %v, want %v", tc.name, tc.session, got, tc.want)
		}
	}
}

func TestLoadTerminalRunAbsent(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	_, ok, err := st.LoadTerminalRun(ctx, "nope")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for absent run")
	}
}

func TestUpsertCorrelationKeepsStrongest(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: "run-1", Tool: "codex", Kind: "fresh"}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}

	// Weak heuristic first.
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "run-1", SessionID: "sess-x", Confidence: 0.40, Source: "heuristic",
	}); err != nil {
		t.Fatalf("upsert heuristic: %v", err)
	}
	// Strong OOB upgrades it.
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "run-1", SessionID: "sess-x", Confidence: 0.95, Source: "oob",
	}); err != nil {
		t.Fatalf("upsert oob: %v", err)
	}
	// A later weak heuristic must NOT downgrade.
	if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
		RunID: "run-1", SessionID: "sess-x", Confidence: 0.40, Source: "heuristic",
	}); err != nil {
		t.Fatalf("upsert heuristic 2: %v", err)
	}

	corrs, err := st.LoadCorrelations(ctx, "run-1")
	if err != nil {
		t.Fatalf("LoadCorrelations: %v", err)
	}
	if len(corrs) != 1 {
		t.Fatalf("expected 1 correlation (unique per run,session), got %d", len(corrs))
	}
	if corrs[0].Confidence != 0.95 || corrs[0].Source != "oob" {
		t.Errorf("correlation = %+v, want confidence=0.95 source=oob", corrs[0])
	}
}

func TestResolveRunForSession(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	for _, r := range []string{"run-a", "run-b"} {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: r, Tool: "claude-code", Kind: "fresh"}); err != nil {
			t.Fatalf("InsertTerminalRun %s: %v", r, err)
		}
	}
	// Two runs both claim sess-shared; the stronger wins the reverse lookup.
	_ = st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: "run-a", SessionID: "sess-shared", Confidence: 0.40, Source: "heuristic"})
	_ = st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: "run-b", SessionID: "sess-shared", Confidence: 0.95, Source: "oob"})

	runID, conf, ok, err := st.ResolveRunForSession(ctx, "sess-shared")
	if err != nil || !ok {
		t.Fatalf("ResolveRunForSession ok=%v err=%v", ok, err)
	}
	if runID != "run-b" || conf != 0.95 {
		t.Errorf("resolved = (%q, %v), want (run-b, 0.95)", runID, conf)
	}

	// Absent session → ok=false.
	_, _, ok, err = st.ResolveRunForSession(ctx, "sess-none")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for uncorrelated session")
	}
}

// seedTermRunProject is the modelvalue_test.go-style project-seed helper
// (UpsertProject) for the discovery-sweep tests below.
func seedTermRunProject(t *testing.T, st *Store, ctx context.Context, root string) int64 {
	t.Helper()
	id, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatalf("UpsertProject(%s): %v", root, err)
	}
	return id
}

// seedTermRunSession is the modelvalue_test.go-style session-seed helper
// (UpsertSession) for the discovery-sweep tests below.
func seedTermRunSession(t *testing.T, st *Store, ctx context.Context, id string, projectID int64, tool string, started time.Time) {
	t.Helper()
	if err := st.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: projectID, Tool: tool, StartedAt: started,
	}); err != nil {
		t.Fatalf("UpsertSession(%s): %v", id, err)
	}
}

// TestListLiveUncorrelatedRuns pins the discovery sweep's work-list query: a
// live run with no correlation is included; an ended run, an end_reason'd
// run (daemon_shutdown / resumed), and a run whose correlation already
// clears minConfidence are all excluded; a run whose only correlation sits
// BELOW minConfidence is still included (it needs the sweep). Field
// round-tripping (Tool/Kind/SourceSessionID/LaunchedAt) is pinned on the one
// included row that carries non-default values.
func TestListLiveUncorrelatedRuns(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	mk := func(id, kind, source string) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID: id, Tool: "claude-code", Kind: kind, SourceSessionID: source, LaunchedAt: base,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	correlate := func(id, sess string, conf float64) {
		if err := st.UpsertCorrelation(ctx, TerminalCorrelation{
			RunID: id, SessionID: sess, Confidence: conf, Source: "oob",
		}); err != nil {
			t.Fatalf("correlate %s: %v", id, err)
		}
	}

	mk("live-uncorrelated", "handoff", "src-1") // included
	mk("ended-run", "attach", "")
	if err := st.EndTerminalRun(ctx, "ended-run", base.Add(time.Minute), 0, EndReasonChildExit); err != nil {
		t.Fatalf("EndTerminalRun: %v", err)
	}
	mk("shutdown-run", "attach", "")
	if _, err := st.db.ExecContext(ctx, `UPDATE terminal_run SET end_reason = ? WHERE run_id = ?`, EndReasonDaemonShutdown, "shutdown-run"); err != nil {
		t.Fatalf("stamp shutdown-run: %v", err)
	}
	mk("resumed-run", "attach", "")
	if _, err := st.db.ExecContext(ctx, `UPDATE terminal_run SET end_reason = ? WHERE run_id = ?`, EndReasonResumed, "resumed-run"); err != nil {
		t.Fatalf("stamp resumed-run: %v", err)
	}
	mk("strong-corr-run", "attach", "")
	correlate("strong-corr-run", "sess-strong", 0.75)
	mk("weak-corr-run", "attach", "")
	correlate("weak-corr-run", "sess-weak", 0.40)

	got, err := st.ListLiveUncorrelatedRuns(ctx, 0.50, 50)
	if err != nil {
		t.Fatalf("ListLiveUncorrelatedRuns: %v", err)
	}
	byID := map[string]UncorrelatedTerminalRun{}
	for _, u := range got {
		byID[u.RunID] = u
	}
	for _, want := range []string{"live-uncorrelated", "weak-corr-run"} {
		if _, ok := byID[want]; !ok {
			t.Errorf("expected %q in result, got %+v", want, got)
		}
	}
	for _, notWant := range []string{"ended-run", "shutdown-run", "resumed-run", "strong-corr-run"} {
		if _, ok := byID[notWant]; ok {
			t.Errorf("did not expect %q in result, got %+v", notWant, got)
		}
	}

	live := byID["live-uncorrelated"]
	if live.Tool != "claude-code" || live.Kind != "handoff" || live.SourceSessionID != "src-1" {
		t.Errorf("live-uncorrelated fields = %+v", live)
	}
	if !live.LaunchedAt.Equal(base) {
		t.Errorf("LaunchedAt = %v, want %v", live.LaunchedAt, base)
	}
}

// TestListLiveUncorrelatedRunsOrderingAndLimit pins the newest-first
// ordering and the limit clamp.
func TestListLiveUncorrelatedRunsOrderingAndLimit(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	for i, id := range []string{"run-old", "run-mid", "run-new"} {
		if err := st.InsertTerminalRun(ctx, TerminalRun{
			RunID: id, Tool: "claude-code", Kind: "fresh", LaunchedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	got, err := st.ListLiveUncorrelatedRuns(ctx, 0.50, 50)
	if err != nil {
		t.Fatalf("ListLiveUncorrelatedRuns: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 runs, got %d (%+v)", len(got), got)
	}
	if got[0].RunID != "run-new" || got[1].RunID != "run-mid" || got[2].RunID != "run-old" {
		t.Errorf("order = %s,%s,%s, want run-new,run-mid,run-old", got[0].RunID, got[1].RunID, got[2].RunID)
	}
	if !got[0].LaunchedAt.Equal(base.Add(2 * time.Minute)) {
		t.Errorf("run-new LaunchedAt = %v, want %v", got[0].LaunchedAt, base.Add(2*time.Minute))
	}

	limited, err := st.ListLiveUncorrelatedRuns(ctx, 0.50, 1)
	if err != nil {
		t.Fatalf("ListLiveUncorrelatedRuns limit=1: %v", err)
	}
	if len(limited) != 1 || limited[0].RunID != "run-new" {
		t.Errorf("limit=1 = %+v, want [run-new]", limited)
	}
}

// TestCandidateSessionsForTerminalRun pins the discovery sweep's per-run
// candidate query: tool filter, gitRoot-or-rawDir project matching (with the
// project filter MANDATORY — a session in a different project never
// matches, even with matching tool/time), the after boundary (>= is
// inclusive), excludeSessionID, exclusion of sessions already linked at or
// above minConfidence (while a below-gate link still leaves a session
// eligible), and ASC ordering + limit (with the id tie-break for equal
// started_at).
func TestCandidateSessionsForTerminalRun(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	base := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	pA := seedTermRunProject(t, st, ctx, "/repo/a")
	pRaw := seedTermRunProject(t, st, ctx, "/repo/raw-only")
	pOther := seedTermRunProject(t, st, ctx, "/repo/other")

	seedTermRunSession(t, st, ctx, "sess-match", pA, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-wrong-tool", pA, "codex", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-raw-match", pRaw, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-other-project", pOther, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-before", pA, "claude-code", base.Add(-time.Minute))
	seedTermRunSession(t, st, ctx, "sess-at-after", pA, "claude-code", base)
	seedTermRunSession(t, st, ctx, "sess-exclude-me", pA, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-linked-strong", pA, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-linked-weak", pA, "claude-code", base.Add(time.Hour))
	seedTermRunSession(t, st, ctx, "sess-ord-1", pA, "claude-code", base.Add(2*time.Hour))
	seedTermRunSession(t, st, ctx, "sess-ord-2", pA, "claude-code", base.Add(3*time.Hour))
	seedTermRunSession(t, st, ctx, "sess-ord-3", pA, "claude-code", base.Add(4*time.Hour))

	correlateSession := func(runID, sess string, conf float64) {
		if err := st.InsertTerminalRun(ctx, TerminalRun{RunID: runID, Tool: "claude-code", Kind: "attach", LaunchedAt: base}); err != nil {
			t.Fatalf("insert %s: %v", runID, err)
		}
		if err := st.UpsertCorrelation(ctx, TerminalCorrelation{RunID: runID, SessionID: sess, Confidence: conf, Source: "oob"}); err != nil {
			t.Fatalf("correlate %s: %v", runID, err)
		}
	}
	correlateSession("run-corr-strong", "sess-linked-strong", 0.75)
	correlateSession("run-corr-weak", "sess-linked-weak", 0.40)

	// A wide forward ceiling so every seeded session (up to base+4h) is inside
	// the window — the forward bound itself is pinned by the dedicated boundary
	// test below.
	until := base.Add(24 * time.Hour)

	// Call A: gitRoot matches project A; rawDir deliberately matches nothing.
	got, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/a", "/repo/nonexistent-raw", base, until, "sess-exclude-me", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun: %v", err)
	}
	byID := map[string]DiscoveryCandidateSession{}
	for _, c := range got {
		byID[c.SessionID] = c
	}
	for _, want := range []string{"sess-match", "sess-at-after", "sess-linked-weak", "sess-ord-1", "sess-ord-2", "sess-ord-3"} {
		if _, ok := byID[want]; !ok {
			t.Errorf("expected %q in result, got %+v", want, got)
		}
	}
	for _, notWant := range []string{"sess-wrong-tool", "sess-raw-match", "sess-other-project", "sess-before", "sess-exclude-me", "sess-linked-strong"} {
		if _, ok := byID[notWant]; ok {
			t.Errorf("did not expect %q in result, got %+v", notWant, got)
		}
	}
	if len(got) != 6 {
		t.Errorf("want 6 candidates, got %d (%+v)", len(got), got)
	}
	// ASC ordering: non-decreasing started_at across the returned slice.
	for i := 1; i < len(got); i++ {
		if got[i].StartedAt.Before(got[i-1].StartedAt) {
			t.Fatalf("candidates not ASC-ordered at index %d: %+v", i, got)
		}
	}
	if !byID["sess-at-after"].StartedAt.Equal(base) {
		t.Errorf("sess-at-after StartedAt = %v, want %v", byID["sess-at-after"].StartedAt, base)
	}

	// Call B: rawDir matches project raw-only; gitRoot deliberately matches
	// nothing — only sess-raw-match should surface.
	rawGot, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/nonexistent-git", "/repo/raw-only", base, until, "", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun (rawDir): %v", err)
	}
	if len(rawGot) != 1 || rawGot[0].SessionID != "sess-raw-match" {
		t.Errorf("rawDir match = %+v, want [sess-raw-match]", rawGot)
	}

	// Call C: limit=2 exercises the ASC + id tie-break ordering explicitly.
	// sess-at-after (base) sorts first; among the base+1h ties,
	// "sess-linked-weak" < "sess-match" lexicographically, so it sorts next.
	limited, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/a", "/repo/nonexistent-raw", base, until, "sess-exclude-me", 0.50, 2)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun limit=2: %v", err)
	}
	if len(limited) != 2 || limited[0].SessionID != "sess-at-after" || limited[1].SessionID != "sess-linked-weak" {
		t.Errorf("limit=2 = %+v, want [sess-at-after sess-linked-weak]", limited)
	}
}

// TestCandidateSessionsForTerminalRunMixedTimestampFormats pins the
// julianday()-bridging behavior the query relies on: one session's
// started_at is written in RFC3339Nano (with a fractional second, the shape
// UpsertSession/`timestamp()` produce) and another is written as plain
// RFC3339 (no fraction, an older/foreign shape) via a raw insert — both must
// compare correctly against the `after` boundary, and both must parse back
// into an accurate time.Time.
func TestCandidateSessionsForTerminalRunMixedTimestampFormats(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	after := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	projectID := seedTermRunProject(t, st, ctx, "/repo/mixed")

	// RFC3339Nano with a fractional second, at after+500ms.
	nanoStarted := after.Add(500 * time.Millisecond)
	seedTermRunSession(t, st, ctx, "sess-mixed-nano", projectID, "claude-code", nanoStarted)

	// Plain RFC3339 (no fraction), written directly at exactly `after` — the
	// boundary case, and a shape UpsertSession itself never produces.
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"sess-mixed-plain", projectID, "claude-code", "2026-07-20T09:00:00Z"); err != nil {
		t.Fatalf("seed sess-mixed-plain: %v", err)
	}
	// Plain RFC3339, one second BEFORE `after` — must be excluded.
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		"sess-mixed-before", projectID, "claude-code", "2026-07-20T08:59:59Z"); err != nil {
		t.Fatalf("seed sess-mixed-before: %v", err)
	}

	got, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/mixed", "/repo/nonexistent-raw", after, after.Add(24*time.Hour), "", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun: %v", err)
	}
	byID := map[string]DiscoveryCandidateSession{}
	for _, c := range got {
		byID[c.SessionID] = c
	}
	if _, ok := byID["sess-mixed-before"]; ok {
		t.Errorf("sess-mixed-before (before the after boundary) must be excluded, got %+v", got)
	}
	plain, ok := byID["sess-mixed-plain"]
	if !ok {
		t.Fatalf("sess-mixed-plain (exactly at the after boundary) must be included, got %+v", got)
	}
	if !plain.StartedAt.Equal(after) {
		t.Errorf("sess-mixed-plain StartedAt = %v, want %v", plain.StartedAt, after)
	}
	nano, ok := byID["sess-mixed-nano"]
	if !ok {
		t.Fatalf("sess-mixed-nano must be included, got %+v", got)
	}
	if !nano.StartedAt.Equal(nanoStarted) {
		t.Errorf("sess-mixed-nano StartedAt = %v, want %v", nano.StartedAt, nanoStarted)
	}
}

// TestCandidateSessionsForTerminalRunFractionalBoundary pins the julianday()
// fix (adversarial-review P1): datetime() DISCARDS fractional seconds, so a
// session up to ~1s BEFORE `after` with a fractional-second stamp could slip
// through once both truncated to the same whole second — confirmed:
// datetime('...01.100Z') >= datetime('...01.900Z') is true because both
// truncate to :01. julianday() returns a float that preserves subsecond
// precision, so the same comparison now correctly excludes it.
func TestCandidateSessionsForTerminalRunFractionalBoundary(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	projectID := seedTermRunProject(t, st, ctx, "/repo/frac")

	// `after` carries a fractional second so the truncation bug is
	// exercisable.
	after := time.Date(2026, 7, 20, 10, 0, 1, 900_000_000, time.UTC) // 10:00:01.900Z

	rawSession := func(id, started string) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
			id, projectID, "claude-code", started); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	// 800ms BEFORE `after`, but datetime() truncates both to the same whole
	// second (:01) — exactly the shape that let a session slip through
	// pre-fix. Must be EXCLUDED.
	rawSession("sess-frac-before", "2026-07-20T10:00:01.100Z")
	// 100ms AFTER `after`. Must be INCLUDED.
	rawSession("sess-frac-after", "2026-07-20T10:00:02.000Z")
	// Exactly AT `after` (same instant, same fraction) — >= must stay
	// inclusive under julianday too. Must be INCLUDED.
	rawSession("sess-frac-exact", "2026-07-20T10:00:01.900Z")

	got, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/frac", "/repo/nonexistent-raw", after, after.Add(24*time.Hour), "", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun: %v", err)
	}
	byID := map[string]DiscoveryCandidateSession{}
	for _, c := range got {
		byID[c.SessionID] = c
	}
	if _, ok := byID["sess-frac-before"]; ok {
		t.Errorf("sess-frac-before (800ms before `after`, same whole second under datetime() truncation) must be EXCLUDED, got %+v", got)
	}
	if _, ok := byID["sess-frac-after"]; !ok {
		t.Errorf("sess-frac-after (100ms after `after`) must be INCLUDED, got %+v", got)
	}
	if _, ok := byID["sess-frac-exact"]; !ok {
		t.Errorf("sess-frac-exact (exactly at the boundary) must be INCLUDED (>= preserved), got %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("want 2 candidates, got %d (%+v)", len(got), got)
	}
}

// TestCandidateSessionsForTerminalRunChronologicalOrdering pins the
// julianday() ordering fix (adversarial-review P2): raw-text ORDER BY is not
// chronological across mixed stamp formats — '2026-07-20 10:00:00' sorts
// BEFORE '2026-07-20T08:00:00Z' as text (because ' ' 0x20 < 'T' 0x54), even
// though 08:00 is chronologically earlier. julianday() orders by actual
// instant regardless of format, and LIMIT truncation must keep the
// chronologically-oldest rows (ASC = oldest-first, this query's contract).
func TestCandidateSessionsForTerminalRunChronologicalOrdering(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	projectID := seedTermRunProject(t, st, ctx, "/repo/chrono")
	after := time.Date(2026, 7, 20, 7, 0, 0, 0, time.UTC)

	rawSession := func(id, started string) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
			id, projectID, "claude-code", started); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	// Chronological order is earliest->latest: sess-early (08:00, RFC3339) <
	// sess-mid (09:00.5, RFC3339Nano) < sess-late (10:00, SQLite-default —
	// sorts BEFORE sess-early as raw text because ' ' < 'T'). Inserted out of
	// chronological order deliberately.
	rawSession("sess-late", "2026-07-20 10:00:00")
	rawSession("sess-early", "2026-07-20T08:00:00Z")
	rawSession("sess-mid", "2026-07-20T09:00:00.500000000Z")

	got, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/chrono", "/repo/nonexistent-raw", after, after.Add(24*time.Hour), "", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 candidates, got %d (%+v)", len(got), got)
	}
	if got[0].SessionID != "sess-early" || got[1].SessionID != "sess-mid" || got[2].SessionID != "sess-late" {
		t.Errorf("order = %s,%s,%s, want sess-early,sess-mid,sess-late (chronological)", got[0].SessionID, got[1].SessionID, got[2].SessionID)
	}

	// LIMIT=2 must keep the chronologically-oldest two, not whatever raw
	// text order would pick (which would keep sess-late + sess-early).
	limited, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/chrono", "/repo/nonexistent-raw", after, after.Add(24*time.Hour), "", 0.50, 2)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun limit=2: %v", err)
	}
	if len(limited) != 2 || limited[0].SessionID != "sess-early" || limited[1].SessionID != "sess-mid" {
		t.Errorf("limit=2 = %+v, want [sess-early sess-mid]", limited)
	}
}

// TestCandidateSessionsForTerminalRunForwardBound pins the forward ceiling
// (Fix 1): the window is [after, until] inclusive, so a session started
// exactly AT `until` is INCLUDED (<=), one 1s past `until` is EXCLUDED, and a
// fractional-second stamp just past `until` is EXCLUDED (julianday() preserves
// subsecond precision on the ceiling exactly as it does on the floor).
func TestCandidateSessionsForTerminalRunForwardBound(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)
	projectID := seedTermRunProject(t, st, ctx, "/repo/fwd")

	after := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	until := after.Add(30 * time.Minute) // 09:30:00.000Z ceiling

	rawSession := func(id, started string) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
			id, projectID, "claude-code", started); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	// Exactly AT `until` — inclusive (<=), must be INCLUDED.
	rawSession("sess-at-until", "2026-07-20T09:30:00Z")
	// 1s PAST `until` — must be EXCLUDED.
	rawSession("sess-past-until", "2026-07-20T09:30:01Z")
	// Fractional-second stamp just past `until` (100ms) — must be EXCLUDED;
	// julianday() must not truncate it back onto the boundary second.
	rawSession("sess-frac-past-until", "2026-07-20T09:30:00.100Z")
	// A well-inside session as a positive control.
	rawSession("sess-inside", "2026-07-20T09:15:00Z")

	got, err := st.CandidateSessionsForTerminalRun(ctx, "claude-code", "/repo/fwd", "/repo/nonexistent-raw", after, until, "", 0.50, 50)
	if err != nil {
		t.Fatalf("CandidateSessionsForTerminalRun: %v", err)
	}
	byID := map[string]DiscoveryCandidateSession{}
	for _, c := range got {
		byID[c.SessionID] = c
	}
	if _, ok := byID["sess-at-until"]; !ok {
		t.Errorf("sess-at-until (exactly at the until ceiling) must be INCLUDED (<=), got %+v", got)
	}
	if _, ok := byID["sess-past-until"]; ok {
		t.Errorf("sess-past-until (1s past the ceiling) must be EXCLUDED, got %+v", got)
	}
	if _, ok := byID["sess-frac-past-until"]; ok {
		t.Errorf("sess-frac-past-until (100ms past the ceiling) must be EXCLUDED, got %+v", got)
	}
	if _, ok := byID["sess-inside"]; !ok {
		t.Errorf("sess-inside (well within the window) must be INCLUDED, got %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("want 2 candidates (sess-inside, sess-at-until), got %d (%+v)", len(got), got)
	}
}

// TestListLiveUncorrelatedRunsChronologicalOrdering pins the julianday()
// ordering fix (adversarial-review P2) on the DESC (newest-first) side:
// mixed launched_at formats must sort by actual instant, not raw text, and
// LIMIT truncation must keep the chronologically-newest rows.
func TestListLiveUncorrelatedRunsChronologicalOrdering(t *testing.T) {
	t.Parallel()
	st, ctx := openTermRunTestStore(t)

	rawRun := func(id, launched string) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx,
			`INSERT INTO terminal_run
			   (run_id, tool, kind, source_session_id, project_root_hash,
			    correlation_token_hash, launched_at, ended_at, exit_code)
			 VALUES (?, 'claude-code', 'fresh', '', '', '', ?, NULL, NULL)`,
			id, launched); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	// Chronological order oldest->newest: run-early (08:00) < run-mid
	// (09:00.5) < run-late (10:00, SQLite-default — sorts BEFORE run-early as
	// raw text because ' ' < 'T'). Inserted out of chronological order
	// deliberately.
	rawRun("run-late", "2026-07-20 10:00:00")
	rawRun("run-early", "2026-07-20T08:00:00Z")
	rawRun("run-mid", "2026-07-20T09:00:00.500000000Z")

	got, err := st.ListLiveUncorrelatedRuns(ctx, 0.50, 50)
	if err != nil {
		t.Fatalf("ListLiveUncorrelatedRuns: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 runs, got %d (%+v)", len(got), got)
	}
	// DESC (newest-first): run-late, run-mid, run-early.
	if got[0].RunID != "run-late" || got[1].RunID != "run-mid" || got[2].RunID != "run-early" {
		t.Errorf("order = %s,%s,%s, want run-late,run-mid,run-early (chronological, newest-first)", got[0].RunID, got[1].RunID, got[2].RunID)
	}

	// LIMIT=2 must keep the chronologically-newest two.
	limited, err := st.ListLiveUncorrelatedRuns(ctx, 0.50, 2)
	if err != nil {
		t.Fatalf("ListLiveUncorrelatedRuns limit=2: %v", err)
	}
	if len(limited) != 2 || limited[0].RunID != "run-late" || limited[1].RunID != "run-mid" {
		t.Errorf("limit=2 = %+v, want [run-late run-mid]", limited)
	}
}
