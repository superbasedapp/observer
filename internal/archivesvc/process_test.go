package archivesvc_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivestore"
	"github.com/marmutapp/superbased-observer/internal/archivesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// timeNowDay is today's UTC calendar day, the boundary the staleness selector
// must never cross.
func timeNowDay() string { return time.Now().UTC().Format("2006-01-02") }

// processRig is the Bucket B counterpart of rig: a real hot DB and a real
// archive file, wired through the process mover.
type processRig struct {
	*rig
	pmover *archivesvc.ProcessMover
}

func newProcessRig(t *testing.T) *processRig {
	t.Helper()
	r := newRig(t)
	return &processRig{
		rig: r,
		pmover: &archivesvc.ProcessMover{
			Hot:       r.store,
			Cold:      r.cold,
			BatchRows: 2,
		},
	}
}

// seedProcessWindow writes a structurally complete day of process capture:
// runs, events, and the network bodies that hang off those events.
//
// The bodies matter most. They are the dominant byte contributor in Bucket B
// (§2.2), they carry no session_id and no clock of their own — they are reached
// only through their parent event — and they are the rows most likely to be
// stranded by a sloppy predicate. Seeding them is what makes the tests below
// able to notice.
func seedProcessWindow(t *testing.T, hot *sql.DB, day, sessionID string, runs int) {
	t.Helper()
	ctx := context.Background()
	// process_runs.session_id is a real FK, so the session has to exist for
	// the seed to be a faithful stand-in for captured data.
	if _, err := hot.ExecContext(ctx,
		`INSERT OR IGNORE INTO projects (id, root_path, name, created_at)
		 VALUES (1, '/repo', 'repo', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := hot.ExecContext(ctx,
		`INSERT OR IGNORE INTO sessions (id, project_id, tool, started_at)
		 VALUES (?, 1, 'claude-code', ?)`, sessionID, day+"T00:00:00.000000000Z"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	for i := 0; i < runs; i++ {
		ts := fmt.Sprintf("%sT0%d:00:00.000000000Z", day, i%10)
		res, err := hot.ExecContext(ctx,
			`INSERT INTO process_runs (process_key, pid, ppid, session_id, tool,
			   attribution_source, attribution_confidence, exe_path, exe_basename, cwd,
			   argv_preview, started_at, last_seen_at, exited_at, exit_code, duration_ms)
			 VALUES (?,?,?,?,'claude-code','hook','high',?,?,?,?,?,?,?,0,120)`,
			fmt.Sprintf("%s-key-%d", day, i), 1000+i, 1, sessionID,
			"/usr/bin/tool", "tool", "/repo", "tool --run "+day, ts, ts, ts)
		if err != nil {
			t.Fatalf("seed run: %v", err)
		}
		runID, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("run id: %v", err)
		}
		eres, err := hot.ExecContext(ctx,
			`INSERT INTO process_events (process_run_id, process_key, timestamp, event_type,
			   session_id, tool, target_kind, target, target_hash, severity, details_json)
			 VALUES (?,?,?,'network_connect',?,'claude-code','host',?,?,'info','{"capture_source":"proxy"}')`,
			runID, fmt.Sprintf("%s-key-%d", day, i), ts, sessionID,
			fmt.Sprintf("api%d.example.com", i), fmt.Sprintf("hash-%d", i))
		if err != nil {
			t.Fatalf("seed event: %v", err)
		}
		eventID, err := eres.LastInsertId()
		if err != nil {
			t.Fatalf("event id: %v", err)
		}
		if _, err := hot.ExecContext(ctx,
			`INSERT INTO process_network_bodies (process_event_id, capture_source, method, url,
			   host, status_code, duration_ms, request_body, request_body_bytes,
			   response_body, response_body_bytes, response_content_type, created_at)
			 VALUES (?,'proxy','POST',?,?,200,42,?,17,?,23,'application/json',?)`,
			eventID, fmt.Sprintf("https://api%d.example.com/v1/x", i),
			fmt.Sprintf("api%d.example.com", i),
			`{"req":`+fmt.Sprint(i)+`}`, `{"resp":`+fmt.Sprint(i)+`}`, ts); err != nil {
			t.Fatalf("seed body: %v", err)
		}
	}
}

func hotProcessCounts(t *testing.T, hot *sql.DB, day string) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := map[string]int{}
	q := map[string]string{
		"process_runs":   `SELECT COUNT(*) FROM process_runs WHERE started_at >= ? AND started_at < ?`,
		"process_events": `SELECT COUNT(*) FROM process_events WHERE timestamp >= ? AND timestamp < ?`,
		"process_network_bodies": `SELECT COUNT(*) FROM process_network_bodies WHERE process_event_id IN
			(SELECT id FROM process_events WHERE timestamp >= ? AND timestamp < ?)`,
	}
	lo, hi := archive.Window{Day: day}.Bounds()
	for table, sqlText := range q {
		var n int
		if err := hot.QueryRowContext(ctx, sqlText, lo, hi).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

func coldProcessCounts(t *testing.T, cold *archivestore.Store, day string) map[string]int {
	t.Helper()
	ctx := context.Background()
	lo, hi := archive.Window{Day: day}.Bounds()
	out := map[string]int{}
	q := map[string]string{
		"process_runs":   `SELECT COUNT(*) FROM archive_process_runs WHERE started_at >= ? AND started_at < ?`,
		"process_events": `SELECT COUNT(*) FROM archive_process_events WHERE timestamp >= ? AND timestamp < ?`,
		"process_network_bodies": `SELECT COUNT(*) FROM archive_process_network_bodies WHERE process_event_id IN
			(SELECT id FROM archive_process_events WHERE timestamp >= ? AND timestamp < ?)`,
	}
	for table, sqlText := range q {
		var n int
		if err := cold.DB().QueryRowContext(ctx, sqlText, lo, hi).Scan(&n); err != nil {
			t.Fatalf("count cold %s: %v", table, err)
		}
		out[table] = n
	}
	return out
}

// TestGateP3ArchivedWindowIsByteIdenticalOnReadBack is the first half of gate
// P3: every archived row comes back out of cold storage exactly as it went in.
//
// It compares the FULL ROW CONTENT, not counts. Bucket B has 94 columns across
// three tables and no regeneration fallback, so "the right number of rows, some
// of them subtly wrong" is the failure that actually threatens it — a body
// whose response text was truncated, an exit code that came back as text
// instead of an integer, a NULL that turned into an empty string.
func TestGateP3ArchivedWindowIsByteIdenticalOnReadBack(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-05"
	const session = "sess-gate-p3"
	seedProcessWindow(t, r.hot, day, session, 3)

	w := archive.Window{Day: day}
	before, err := r.store.ProcessWindowDigest(ctx, w, 2)
	if err != nil {
		t.Fatalf("hot digest: %v", err)
	}
	if before.Empty() {
		t.Fatal("seeded window digested empty — the gate would pass vacuously")
	}
	hotBefore := hotProcessCounts(t, r.hot, day)
	for table, n := range hotBefore {
		if n == 0 {
			t.Fatalf("seed produced no %s rows — the gate would not cover that table", table)
		}
	}

	out, err := r.pmover.ArchiveProcessWindow(ctx, w)
	if err != nil {
		t.Fatalf("archive window: %v", err)
	}
	if out.Result != archivesvc.ResultArchived {
		t.Fatalf("result = %v, want archived", out.Result)
	}

	// Hot is empty, cold holds exactly what hot held.
	for table, n := range hotProcessCounts(t, r.hot, day) {
		if n != 0 {
			t.Errorf("after archive, hot %s still holds %d rows", table, n)
		}
	}
	coldAfter := coldProcessCounts(t, r.cold, day)
	for table, n := range hotBefore {
		if coldAfter[table] != n {
			t.Errorf("%s: hot had %d rows, cold holds %d", table, n, coldAfter[table])
		}
	}

	// THE GATE: the cold copy digests identically to what the hot rows did.
	after, err := r.cold.ProcessWindowDigest(ctx, w, 2)
	if err != nil {
		t.Fatalf("cold digest: %v", err)
	}
	if err := archive.VerifyWindow(before, after); err != nil {
		t.Fatalf("archived window is NOT byte-identical on read-back: %v", err)
	}

	marker, found, err := r.store.ProcessArchivedWindow(ctx, day)
	if err != nil || !found {
		t.Fatalf("marker missing after archive (found=%v err=%v)", found, err)
	}
	if marker.RowsArchived() != out.RowsArchived {
		t.Errorf("marker records %d rows, mover reported %d", marker.RowsArchived(), out.RowsArchived)
	}
}

// TestGateP3CorruptedColdCopyIsCaughtBeforeTheHotDelete is the SECOND half of
// gate P3, and the mandatory mutation proof for the only-copy bucket.
//
// A cold copy that silently loses rows must be caught by verification BEFORE
// anything hot is deleted. If verification is ever weakened, this is the test
// that fails — and it fails by naming the surviving hot rows, because for this
// bucket "the hot rows survived" IS the property under test.
func TestGateP3CorruptedColdCopyIsCaughtBeforeTheHotDelete(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-06"
	seedProcessWindow(t, r.hot, day, "sess-corrupt", 3)
	before := hotProcessCounts(t, r.hot, day)

	mover := &archivesvc.ProcessMover{
		Hot:       r.store,
		Cold:      &lossyProcessCold{Store: r.cold, dropFrom: "process_network_bodies"},
		BatchRows: 2,
	}
	out, err := mover.ArchiveProcessWindow(ctx, archive.Window{Day: day})
	if err == nil {
		t.Fatal("a lossy cold copy was ACCEPTED — verification is not gating the delete " +
			"on the only-copy bucket")
	}
	if out.Result == archivesvc.ResultArchived {
		t.Fatalf("result = archived despite a verification error: %v", err)
	}
	for table, n := range hotProcessCounts(t, r.hot, day) {
		if n != before[table] {
			t.Errorf("hot %s went from %d to %d rows after a FAILED archive — "+
				"unrecoverable process capture was deleted behind a broken verification",
				table, before[table], n)
		}
	}
	if _, found, _ := r.store.ProcessArchivedWindow(ctx, day); found {
		t.Error("a marker was written for a window that was never successfully archived")
	}
}

// lossyProcessCold silently drops one row from every batch of one table,
// standing in for a partially-durable write. A write that ERRORS is easy to
// handle correctly by accident; the interesting failure is a copy that succeeds
// and is wrong.
type lossyProcessCold struct {
	*archivestore.Store
	dropFrom string
}

func (c *lossyProcessCold) WriteRows(ctx context.Context, b archive.RowBatch) error {
	if b.Table == c.dropFrom && len(b.Vals) > 0 {
		b.Vals = b.Vals[:len(b.Vals)-1]
	}
	return c.Store.WriteRows(ctx, b)
}

// TestProcessArchiveIsRerunnableAfterAPartialCopy pins invariant 4 on Bucket B:
// a pass that dies mid-copy and re-runs must converge, not duplicate.
func TestProcessArchiveIsRerunnableAfterAPartialCopy(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-07"
	seedProcessWindow(t, r.hot, day, "sess-rerun", 3)
	w := archive.Window{Day: day}

	// A crashed first attempt: rows land cold, nothing is deleted hot.
	tee := archive.NewWindowTeeSink(r.cold)
	if err := r.store.ProcessExportWindow(ctx, w, 2, tee); err != nil {
		t.Fatalf("simulate partial copy: %v", err)
	}
	if coldProcessCounts(t, r.cold, day)["process_runs"] == 0 {
		t.Fatal("partial copy wrote nothing — this test would be vacuous")
	}
	// ...and then the hot window SHRANK before the retry. This is what makes
	// the cold pre-clear load-bearing rather than decorative: an upsert alone
	// would leave the vanished run behind as an orphan, and the read-back
	// digest would disagree with the hot digest forever, wedging the window.
	if _, err := r.hot.ExecContext(ctx,
		`DELETE FROM process_network_bodies WHERE process_event_id IN
		   (SELECT id FROM process_events WHERE process_key = ?)`,
		fmt.Sprintf("%s-key-2", day)); err != nil {
		t.Fatalf("shrink hot bodies: %v", err)
	}
	if _, err := r.hot.ExecContext(ctx,
		`DELETE FROM process_events WHERE process_key = ?`, fmt.Sprintf("%s-key-2", day)); err != nil {
		t.Fatalf("shrink hot events: %v", err)
	}
	if _, err := r.hot.ExecContext(ctx,
		`DELETE FROM process_runs WHERE process_key = ?`, fmt.Sprintf("%s-key-2", day)); err != nil {
		t.Fatalf("shrink hot runs: %v", err)
	}

	out, err := r.pmover.ArchiveProcessWindow(ctx, w)
	if err != nil {
		t.Fatalf("re-run archive: %v", err)
	}
	if out.Result != archivesvc.ResultArchived {
		t.Fatalf("result = %v, want archived", out.Result)
	}
	cold := coldProcessCounts(t, r.cold, day)
	if cold["process_runs"] != 2 || cold["process_events"] != 2 || cold["process_network_bodies"] != 2 {
		t.Errorf("re-copy over a stale cold copy left orphans or duplicates: %v "+
			"(want 2 of each — the shrunken hot window)", cold)
	}
}

// TestProcessArchiveCancelsOnConcurrentCapture pins invariant 5 for Bucket B.
//
// The interesting case is NOT a new row — it is an UPDATE. store.PersistRuns
// upserts on process_key, refreshing last_seen_at and the exit columns of a
// process that started days ago and is still alive, so a guard built from a row
// count and a MAX(id) would report "unchanged" while the row's contents moved
// on, and the delete would destroy the original of a stale snapshot.
func TestProcessArchiveCancelsOnConcurrentCapture(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-08"
	seedProcessWindow(t, r.hot, day, "sess-race", 2)
	w := archive.Window{Day: day}

	mover := &archivesvc.ProcessMover{
		Hot:       &mutatingProcessHot{store: r.store, hot: r.hot, t: t, day: day},
		Cold:      r.cold,
		BatchRows: 2,
	}
	out, err := mover.ArchiveProcessWindow(ctx, w)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.Result != archivesvc.ResultChanged {
		t.Fatalf("result = %v, want changed — a run mutated between the copy and the "+
			"delete and the move went ahead anyway", out.Result)
	}
	if n := hotProcessCounts(t, r.hot, day)["process_runs"]; n != 2 {
		t.Errorf("hot process_runs = %d, want 2 — a cancelled move still deleted rows", n)
	}
	if _, found, _ := r.store.ProcessArchivedWindow(ctx, day); found {
		t.Error("a cancelled move wrote a marker")
	}
}

// mutatingProcessHot refreshes a run's last_seen_at after the copy, standing in
// for live capture touching a still-running process.
type mutatingProcessHot struct {
	store *store.Store
	hot   *sql.DB
	t     *testing.T
	day   string
	fired bool
}

func (h *mutatingProcessHot) ProcessStaleWindows(ctx context.Context, d, m int) ([]archive.WindowCandidate, error) {
	return h.store.ProcessStaleWindows(ctx, d, m)
}

func (h *mutatingProcessHot) ProcessWindowShape(ctx context.Context, w archive.Window) (archive.WindowShape, error) {
	return h.store.ProcessWindowShape(ctx, w)
}

func (h *mutatingProcessHot) ProcessArchiveComplete(ctx context.Context, c archive.WindowCompletion) error {
	return h.store.ProcessArchiveComplete(ctx, c)
}

func (h *mutatingProcessHot) DeleteProcessArchivedWindow(ctx context.Context, day string) error {
	return h.store.DeleteProcessArchivedWindow(ctx, day)
}

func (h *mutatingProcessHot) ProcessExportWindow(ctx context.Context, w archive.Window, batchRows int, sink archive.WindowSink) error {
	if err := h.store.ProcessExportWindow(ctx, w, batchRows, sink); err != nil {
		return err
	}
	if !h.fired && w.Day == h.day {
		h.fired = true
		if _, err := h.hot.ExecContext(ctx,
			`UPDATE process_runs SET last_seen_at = ? WHERE started_at >= ? AND started_at < ?`,
			h.day+"T23:59:59.000000000Z", h.day, h.day+"z"); err != nil {
			h.t.Fatalf("simulate live capture: %v", err)
		}
	}
	return nil
}

// TestProcessDirectReadServesAnArchivedSession pins P3.5: after a window is
// archived, its session's process trail is still answerable — from the archive
// file, with NO write-back into the hot database.
func TestProcessDirectReadServesAnArchivedSession(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-09"
	const session = "sess-direct-read"
	seedProcessWindow(t, r.hot, day, session, 3)
	if _, err := r.pmover.ArchiveProcessWindow(ctx, archive.Window{Day: day}); err != nil {
		t.Fatalf("archive: %v", err)
	}

	has, err := r.cold.HasArchivedSessionProcesses(ctx, session)
	if err != nil {
		t.Fatalf("HasArchivedSessionProcesses: %v", err)
	}
	if !has {
		t.Fatal("the archive does not admit holding the archived session's processes")
	}

	sink := archive.NewWindowDigestSink()
	if err := r.cold.ProcessRunsForSession(ctx, session, 2, sink); err != nil {
		t.Fatalf("direct read: %v", err)
	}
	if got := sink.Digest().Rows("process_runs"); got != 3 {
		t.Errorf("direct read returned %d runs, want 3", got)
	}

	// NO WRITE-BACK. Re-growing the hot database on a read is the exact thing
	// this arc exists to stop, so the read path must leave it untouched.
	if n := hotProcessCounts(t, r.hot, day)["process_runs"]; n != 0 {
		t.Errorf("the direct read wrote %d rows back into the hot database", n)
	}
}

// TestProcessColdExpiryDropsRowsAndMarkerTogether pins P3.6's honesty rule: a
// marker must never outlive the data it promises.
func TestProcessColdExpiryDropsRowsAndMarkerTogether(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-10"
	seedProcessWindow(t, r.hot, day, "sess-expire", 2)
	if _, err := r.pmover.ArchiveProcessWindow(ctx, archive.Window{Day: day}); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if _, found, _ := r.store.ProcessArchivedWindow(ctx, day); !found {
		t.Fatal("no marker to expire")
	}

	// A retention horizon that has long since passed for this window.
	n, err := r.pmover.ExpireProcessWindows(ctx, 1, 10)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d windows, want 1", n)
	}
	if c := coldProcessCounts(t, r.cold, day); c["process_runs"] != 0 || c["process_events"] != 0 || c["process_network_bodies"] != 0 {
		t.Errorf("cold rows survived expiry: %v", c)
	}
	if _, found, _ := r.store.ProcessArchivedWindow(ctx, day); found {
		t.Error("the marker outlived its data — it now promises capture that no longer exists")
	}
}

// TestProcessStaleWindowsNeverOffersToday pins the first of the two guards
// standing between the sweep and live capture.
func TestProcessStaleWindowsNeverOffersToday(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	today := timeNowDay()
	seedProcessWindow(t, r.hot, today, "sess-today", 2)
	seedProcessWindow(t, r.hot, "2020-01-01", "sess-ancient", 2)

	got, err := r.store.ProcessStaleWindows(ctx, 14, 10)
	if err != nil {
		t.Fatalf("ProcessStaleWindows: %v", err)
	}
	for _, c := range got {
		if c.Window.Day == today {
			t.Fatalf("today's window (%s) was offered for archival — live capture is being moved", today)
		}
	}
	var sawAncient bool
	for _, c := range got {
		if c.Window.Day == "2020-01-01" {
			sawAncient = true
		}
	}
	if !sawAncient {
		t.Error("an ancient window was not offered — the selector is not finding stale capture")
	}
}

// TestGateP3TruncatedBodyIsCaughtWithTheRowCountIntACT is the second mutation
// fixture for the only-copy bucket: a cold copy with the RIGHT NUMBER of rows
// whose content is subtly wrong.
//
// It is the realistic corruption for Bucket B. process_network_bodies carries
// captured request/response excerpts, and the plausible failure is not a lost
// row but a truncated body — a copy that counts correctly and reads wrong. Only
// the checksum half of the digest can see it, so this test is what fails if
// that half is ever disabled.
func TestGateP3TruncatedBodyIsCaughtWithTheRowCountIntact(t *testing.T) {
	ctx := context.Background()
	r := newProcessRig(t)
	const day = "2026-01-11"
	seedProcessWindow(t, r.hot, day, "sess-truncate", 3)
	before := hotProcessCounts(t, r.hot, day)

	mover := &archivesvc.ProcessMover{
		Hot:       r.store,
		Cold:      &truncatingProcessCold{Store: r.cold},
		BatchRows: 2,
	}
	out, err := mover.ArchiveProcessWindow(ctx, archive.Window{Day: day})
	if err == nil {
		t.Fatal("a cold copy with the same row count but truncated bodies verified — " +
			"the checksum half of the digest is not load-bearing")
	}
	if out.Result == archivesvc.ResultArchived {
		t.Fatalf("result = archived despite a verification error: %v", err)
	}
	for table, n := range hotProcessCounts(t, r.hot, day) {
		if n != before[table] {
			t.Errorf("hot %s went from %d to %d after a FAILED archive", table, before[table], n)
		}
	}
}

// truncatingProcessCold shortens every response body it writes, keeping the row
// count exactly right.
type truncatingProcessCold struct {
	*archivestore.Store
}

func (c *truncatingProcessCold) WriteRows(ctx context.Context, b archive.RowBatch) error {
	if b.Table == "process_network_bodies" {
		idx := -1
		for i, col := range b.Cols {
			if col == "response_body" {
				idx = i
			}
		}
		if idx >= 0 {
			for _, row := range b.Vals {
				if s, ok := row[idx].(string); ok && len(s) > 1 {
					row[idx] = s[:len(s)-1]
				}
			}
		}
	}
	return c.Store.WriteRows(ctx, b)
}
