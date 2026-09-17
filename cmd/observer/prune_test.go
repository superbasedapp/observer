package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRunRetentionPrunesHandoffRows is the WIRING proof for the P4 handoff
// retention sweep: it exercises the runRetention orchestration path (not
// just store.PruneHandoffRows) and asserts an over-horizon handoffs row is
// pruned while a fresh one survives — guarding against the historical
// "prune func shipped but never wired" regression.
func TestRunRetentionPrunesHandoffRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prune.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	s := store.New(database)

	oldID, err := s.InsertHandoff(ctx, store.HandoffRecord{
		SourceSessionID: "sess-old", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "distilled_tail", Delivery: "file",
	})
	if err != nil {
		t.Fatalf("InsertHandoff(old): %v", err)
	}
	freshID, err := s.InsertHandoff(ctx, store.HandoffRecord{
		SourceSessionID: "sess-fresh", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "distilled_tail", Delivery: "file",
	})
	if err != nil {
		t.Fatalf("InsertHandoff(fresh): %v", err)
	}

	// Backdate the old row past the default 180-day horizon.
	old := time.Now().UTC().Add(-200 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx,
		`UPDATE handoffs SET created_at = ? WHERE id = ?`, old, oldID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	cfg := config.Default()
	cfg.Observer.DBPath = path
	if cfg.Handoff.RetentionDays != 180 {
		t.Fatalf("default handoff retention = %d, want 180", cfg.Handoff.RetentionDays)
	}

	res, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention: %v", err)
	}
	if res.HandoffRowsDeleted != 1 {
		t.Errorf("HandoffRowsDeleted = %d, want 1", res.HandoffRowsDeleted)
	}

	got, err := s.ListHandoffs(ctx, 10)
	if err != nil {
		t.Fatalf("ListHandoffs: %v", err)
	}
	if len(got) != 1 || got[0].ID != freshID {
		t.Fatalf("after prune got %d rows (want 1, the fresh row id=%d)", len(got), freshID)
	}

	// Second run within the same horizon is a clean no-op (idempotent).
	res2, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention(2): %v", err)
	}
	if res2.HandoffRowsDeleted != 0 {
		t.Errorf("second run HandoffRowsDeleted = %d, want 0", res2.HandoffRowsDeleted)
	}
}

// TestRunRetentionPrunesCodeIntelProjects is the WIRING proof for the
// Ticket-B codeintel retention sweep (docs/plans/claude-code-hook-stall-
// ticket-and-db-prune-plan-2026-07-12.md): it exercises the runRetention
// orchestration path (not just store.CodeIntelPruneStaleProjects) and
// asserts a project whose last index pass is older than the default
// [codeintel].retention_days is deleted while a freshly indexed one
// survives — guarding against the historical "prune func shipped but
// never wired" regression.
func TestRunRetentionPrunesCodeIntelProjects(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prune-codeintel.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	now := time.Now().Unix()
	const day = int64(24 * 60 * 60)
	seed := func(project string, indexedAt int64) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status, indexed_at)
			 VALUES(?, ?, 'go', 'indexed', ?)`,
			project, project+"/a.go", indexedAt); err != nil {
			t.Fatalf("seed %s: %v", project, err)
		}
	}
	seed("/repo/stale", now-200*day)
	seed("/repo/fresh", now-5*day)

	cfg := config.Default()
	cfg.Observer.DBPath = path
	if cfg.CodeIntel.RetentionDays != 90 {
		t.Fatalf("default codeintel retention = %d, want 90", cfg.CodeIntel.RetentionDays)
	}

	res, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention: %v", err)
	}
	if res.CodeIntelProjectsDeleted != 1 {
		t.Errorf("CodeIntelProjectsDeleted = %d, want 1", res.CodeIntelProjectsDeleted)
	}

	remaining, err := store.New(database).CodeIntelListProjects(ctx)
	if err != nil {
		t.Fatalf("CodeIntelListProjects: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != "/repo/fresh" {
		t.Fatalf("after prune remaining projects = %v, want [/repo/fresh]", remaining)
	}

	// Second run within the same horizon is a clean no-op (idempotent).
	res2, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention(2): %v", err)
	}
	if res2.CodeIntelProjectsDeleted != 0 {
		t.Errorf("second run CodeIntelProjectsDeleted = %d, want 0", res2.CodeIntelProjectsDeleted)
	}
}

// mbBytes builds a byte count from a MB figure for readable fixtures.
func mbBytes(m int64) int64 { return m * 1024 * 1024 }

// TestPrintPruneReclamation verifies the `observer prune` before/after
// reporting: per-category reclamation lines (codeintel / process), the WAL
// checkpoint line, and the two-step "run --vacuum" hint when pages are on the
// freelist rather than returned to the OS.
func TestPrintPruneReclamation(t *testing.T) {
	before := db.StorageReport{
		TotalBytes: mbBytes(9500),
		Tables: []db.StorageTable{
			{Name: "codeintel_embeddings", Bytes: mbBytes(1650)},
			{Name: "codeintel_nodes", Bytes: mbBytes(200)},
			{Name: "process_runs", Bytes: mbBytes(1770)},
			{Name: "process_network_bodies", Bytes: mbBytes(389)},
			{Name: "actions", Bytes: mbBytes(946)},
		},
	}
	after := db.StorageReport{
		TotalBytes:       mbBytes(9500), // unchanged without VACUUM
		ReclaimableBytes: mbBytes(4000), // now on the freelist
		Tables: []db.StorageTable{
			{Name: "codeintel_embeddings", Bytes: mbBytes(4)},
			{Name: "codeintel_nodes", Bytes: mbBytes(1)},
			{Name: "process_runs", Bytes: mbBytes(120)},
			{Name: "process_network_bodies", Bytes: mbBytes(10)},
			{Name: "actions", Bytes: mbBytes(946)}, // protected by keep-floor
		},
	}

	var buf bytes.Buffer
	printPruneReclamation(&buf, before, after, mbBytes(1800), 0, true, false)
	out := buf.String()

	for _, want := range []string{
		"WAL checkpoint: truncated 1800.0 MB",
		"codeintel stale projects:",
		"process observability:",
		"top tables reclaimed:",
		"main DB file: 9500.0 MB → 9500.0 MB",
		"observer prune --vacuum",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	// actions were NOT reclaimed (keep-floor) — must not appear as a freed
	// category line.
	if strings.Contains(out, "actions:") {
		t.Errorf("actions should not be reported as reclaimed (keep-floor):\n%s", out)
	}
}

// TestPrintPruneReclamationVacuumed checks the post-VACUUM message path: the
// file shrank, so no "run --vacuum" hint and no freelist framing.
func TestPrintPruneReclamationVacuumed(t *testing.T) {
	before := db.StorageReport{TotalBytes: mbBytes(9500), Tables: []db.StorageTable{{Name: "codeintel_embeddings", Bytes: mbBytes(1650)}}}
	after := db.StorageReport{TotalBytes: mbBytes(5800), Tables: []db.StorageTable{{Name: "codeintel_embeddings", Bytes: mbBytes(4)}}}

	var buf bytes.Buffer
	printPruneReclamation(&buf, before, after, mbBytes(1800), 0, true, true)
	out := buf.String()

	if !strings.Contains(out, "returned to the OS by VACUUM") {
		t.Errorf("expected VACUUM message, got:\n%s", out)
	}
	if strings.Contains(out, "observer prune --vacuum") {
		t.Errorf("should not suggest --vacuum after a vacuum ran:\n%s", out)
	}
}

// TestPrintPruneReclamationNoBreakdown covers --breakdown=false: only the WAL
// line prints, no dbstat categories.
func TestPrintPruneReclamationNoBreakdown(t *testing.T) {
	var buf bytes.Buffer
	printPruneReclamation(&buf, db.StorageReport{}, db.StorageReport{}, mbBytes(1800), 0, false, false)
	out := buf.String()
	if !strings.Contains(out, "WAL checkpoint: truncated") {
		t.Errorf("expected WAL line, got: %q", out)
	}
	if strings.Contains(out, "reclaimed by category") {
		t.Errorf("category breakdown printed despite breakdown=false:\n%s", out)
	}
}

// TestPruneReclaimCategoryGroupBytes verifies prefix vs explicit-name folding.
func TestPruneReclaimCategoryGroupBytes(t *testing.T) {
	byName := map[string]int64{
		"codeintel_embeddings":   100,
		"codeintel_nodes":        50,
		"process_runs":           30,
		"process_network_bodies": 20,
		"unrelated":              999,
	}
	ci := pruneReclaimCategory{prefix: "codeintel_"}
	if got := ci.groupBytes(byName); got != 150 {
		t.Errorf("codeintel prefix group = %d, want 150", got)
	}
	proc := pruneReclaimCategory{names: []string{"process_runs", "process_network_bodies", "process_events"}}
	if got := proc.groupBytes(byName); got != 50 {
		t.Errorf("process name group = %d, want 50", got)
	}
}

// TestRunRetentionArchivesCodeIntelProjectsWhenEnabled is the WIRING proof for
// the [archive] sweep: the SAME staleness horizon that deletes today must
// instead MOVE the project to ~/.observer/archive.db when the block is on.
//
// It asserts both halves of that sentence, because either alone is a bug: the
// hot rows are gone AND the project is recorded on the marker, so the operator
// can tell "archived" from "never indexed" — and the delete counter stays at
// zero, so the two fates never get conflated in the report.
func TestRunRetentionArchivesCodeIntelProjectsWhenEnabled(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "prune-archive.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	now := time.Now().Unix()
	const day = int64(24 * 60 * 60)
	seedFile := func(project string, indexedAt int64) {
		t.Helper()
		if _, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status, indexed_at)
			 VALUES(?, ?, 'go', 'indexed', ?)`,
			project, project+"/a.go", indexedAt); err != nil {
			t.Fatalf("seed %s: %v", project, err)
		}
	}
	seedFile("/repo/stale", now-200*day)
	seedFile("/repo/fresh", now-5*day)

	cfg := config.Default()
	cfg.Observer.DBPath = path
	cfg.Archive.Enabled = true
	cfg.Archive.Path = filepath.Join(dir, "archive.db")

	res, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention: %v", err)
	}
	if res.CodeIntelProjectsArchived != 1 {
		t.Errorf("CodeIntelProjectsArchived = %d, want 1", res.CodeIntelProjectsArchived)
	}
	if res.CodeIntelProjectsDeleted != 0 {
		t.Errorf("CodeIntelProjectsDeleted = %d — the archive sweep must not also report deletions",
			res.CodeIntelProjectsDeleted)
	}
	if res.CodeIntelRowsArchived <= 0 {
		t.Error("CodeIntelRowsArchived was not reported")
	}

	s := store.New(database)
	remaining, err := s.CodeIntelListProjects(ctx)
	if err != nil {
		t.Fatalf("CodeIntelListProjects: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != "/repo/fresh" {
		t.Fatalf("after archive remaining projects = %v, want [/repo/fresh]", remaining)
	}
	marker, found, err := s.CodeIntelArchivedProject(ctx, "/repo/stale")
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	if !found {
		t.Fatal("no marker for the archived project — it is now indistinguishable from never-indexed")
	}
	if marker.RowsArchived != res.CodeIntelRowsArchived {
		t.Errorf("marker rows %d != reported rows %d", marker.RowsArchived, res.CodeIntelRowsArchived)
	}
	if _, err := os.Stat(cfg.Archive.Path); err != nil {
		t.Fatalf("archive database was not created at %s: %v", cfg.Archive.Path, err)
	}

	// Second pass is a clean no-op: the project is no longer stale-eligible
	// because its rows are gone from codeintel_files entirely.
	res2, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention(2): %v", err)
	}
	if res2.CodeIntelProjectsArchived != 0 {
		t.Errorf("second pass archived %d projects, want 0", res2.CodeIntelProjectsArchived)
	}
}

// TestRunRetentionArchiveSweepFailsOpenToSkip pins the one-directional
// fail-open: when the archive database cannot be opened, the codeintel sweep
// is SKIPPED, never downgraded to the delete path. An operator who asked for
// archival and got deletion because a file was momentarily unavailable would
// have lost data to the option meant to stop losing it.
func TestRunRetentionArchiveSweepFailsOpenToSkip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "prune-archive-fail.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	now := time.Now().Unix()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO codeintel_files(project, path, lang, status, indexed_at)
		 VALUES('/repo/stale', '/repo/stale/a.go', 'go', 'indexed', ?)`,
		now-200*24*60*60); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A directory where the archive file should be: Open must fail.
	badPath := filepath.Join(dir, "archive.db")
	if err := os.MkdirAll(badPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cfg := config.Default()
	cfg.Observer.DBPath = path
	cfg.Archive.Enabled = true
	cfg.Archive.Path = badPath

	res, err := runRetention(ctx, cfg, database)
	if err != nil {
		t.Fatalf("runRetention must fail open, got error: %v", err)
	}
	if res.CodeIntelProjectsArchived != 0 || res.CodeIntelProjectsDeleted != 0 {
		t.Fatalf("archived/deleted = %d/%d, want 0/0 — the sweep must be skipped, not downgraded to a delete",
			res.CodeIntelProjectsArchived, res.CodeIntelProjectsDeleted)
	}
	remaining, err := store.New(database).CodeIntelListProjects(ctx)
	if err != nil {
		t.Fatalf("CodeIntelListProjects: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("the stale project was removed despite the skipped sweep: %v", remaining)
	}
}
