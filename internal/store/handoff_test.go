package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// handoffTranscript is the seeded session's transcript path, absolute on this
// OS: a Windows daemon stores C:\ paths, and the source-file filter must keep
// them (it once matched only a leading "/").
func handoffTranscript() string {
	p := filepath.FromSlash("/home/u/.claude/projects/x/hs-1.jsonl")
	if runtime.GOOS == "windows" {
		p = `C:` + p
	}
	return p
}

func seedHandoffSession(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mustExec(`INSERT INTO projects (id, root_path, created_at) VALUES (7, '/home/u/proj', ?)`, timestamp(time.Now()))
	mustExec(`INSERT INTO sessions (id, project_id, tool, model, git_branch, started_at) VALUES ('hs-1', 7, 'claude-code', '', 'main', '2026-07-03T10:00:00Z')`)
	mustExec(`INSERT INTO token_usage (session_id, tool, model, input_tokens, output_tokens, timestamp, source, source_file)
	          VALUES ('hs-1', 'claude-code', 'opus-4-8', 100, 50, '2026-07-03T10:01:00Z', 'transcript', ?)`, handoffTranscript())
	acts := []struct {
		typ, target, errMsg string
		success             int
		ts                  string
	}{
		{models.ActionEditFile, "internal/a.go", "", 1, "2026-07-03T10:02:00Z"},
		{models.ActionReadFile, "internal/a.go", "", 1, "2026-07-03T10:01:30Z"},
		{models.ActionRunCommand, "go test ./...", "exit 1", 0, "2026-07-03T10:03:00Z"},
		{models.ActionRunCommand, "go test ./...", "", 1, "2026-07-03T10:04:00Z"},
		{models.ActionEditFile, "internal/broken.go", "syntax error", 0, "2026-07-03T10:05:00Z"},
	}
	for _, a := range acts {
		mustExec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, error_message, tool, source_file)
		          VALUES ('hs-1', 7, ?, ?, ?, ?, ?, 'claude-code', 'claude-code:hook')`,
			a.ts, a.typ, a.target, a.success, a.errMsg)
	}
}

func TestLoadHandoffSubstrate(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	sub, err := s.LoadHandoffSubstrate(context.Background(), "hs-1")
	if err != nil {
		t.Fatalf("LoadHandoffSubstrate: %v", err)
	}
	if sub.ProjectRoot != "/home/u/proj" || sub.Session.Tool != "claude-code" {
		t.Errorf("session/root = %q/%q", sub.Session.Tool, sub.ProjectRoot)
	}
	if sub.Session.Model != "opus-4-8" {
		t.Errorf("model fallback from token_usage failed: %q", sub.Session.Model)
	}
	// The `<tool>:hook` sentinel must be filtered (D-P0.1); the real path kept.
	if len(sub.SourceFiles) != 1 || sub.SourceFiles[0] != handoffTranscript() {
		t.Errorf("source files = %v", sub.SourceFiles)
	}
	if len(sub.Files) != 2 || sub.Files[0].Path != "internal/a.go" || sub.Files[0].Edits != 1 || sub.Files[0].Reads != 1 {
		t.Errorf("files = %+v", sub.Files)
	}
	if len(sub.Commands) != 1 || !sub.Commands[0].LastOK || sub.Commands[0].Runs != 2 {
		t.Errorf("commands (last run succeeded) = %+v", sub.Commands)
	}
	// broken.go failed with no later success → unresolved; the command
	// target recovered → excluded.
	if len(sub.Errors) != 1 || sub.Errors[0].Target != "internal/broken.go" {
		t.Errorf("errors = %+v", sub.Errors)
	}

	if _, err := s.LoadHandoffSubstrate(context.Background(), "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("missing session must return sql.ErrNoRows, got %v", err)
	}
}

func TestInsertAndListHandoffs(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	id, err := s.InsertHandoff(context.Background(), HandoffRecord{
		SourceSessionID:  "hs-1",
		SourceTool:       "claude-code",
		TargetTool:       "codex",
		CarryMode:        "distilled_tail",
		ForkKind:         "message_index",
		ForkMessageIndex: 4,
		ForkMessageTime:  time.Date(2026, 7, 3, 10, 2, 0, 0, time.UTC),
		ForkAnchorHash:   "abc",
		RequestedIndex:   5,
		DocTokenEstimate: 3000,
		EstimateJSON:     `{"rows":[]}`,
		Delivery:         "inject_file",
		DeliveryRef:      "/home/u/proj/HANDOFF-x.md",
		ShortID:          "abcd1234",
	})
	if err != nil || id == 0 {
		t.Fatalf("InsertHandoff: id=%d err=%v", id, err)
	}
	got, err := s.ListHandoffs(context.Background(), 5)
	if err != nil || len(got) != 1 {
		t.Fatalf("ListHandoffs: %v (%d rows)", err, len(got))
	}
	r := got[0]
	if r.TargetTool != "codex" || r.ForkMessageIndex != 4 || r.RequestedIndex != 5 || r.Delivery != "inject_file" {
		t.Errorf("row = %+v", r)
	}
	if r.ShortID != "abcd1234" {
		t.Errorf("ShortID = %q, want abcd1234", r.ShortID)
	}
	if r.ForkMessageTime.IsZero() || r.CreatedAt.IsZero() {
		t.Errorf("timestamps must round-trip: %+v", r)
	}
}

func TestPruneHandoffRowsAndNoop(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	oldID, err := s.InsertHandoff(ctx, HandoffRecord{
		SourceSessionID: "s-old", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "distilled_tail", Delivery: "file",
	})
	if err != nil {
		t.Fatalf("InsertHandoff(old): %v", err)
	}
	if _, err := s.InsertHandoff(ctx, HandoffRecord{
		SourceSessionID: "s-fresh", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "distilled_tail", Delivery: "file",
	}); err != nil {
		t.Fatalf("InsertHandoff(fresh): %v", err)
	}
	// Backdate the old row 200 days.
	old := time.Now().UTC().Add(-200 * 24 * time.Hour).Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `UPDATE handoffs SET created_at = ? WHERE id = ?`, old, oldID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// retentionDays <= 0 is a clean keep-forever no-op.
	if n, err := s.PruneHandoffRows(ctx, 0); err != nil || n != 0 {
		t.Fatalf("disabled prune = %d, %v; want 0", n, err)
	}

	n, err := s.PruneHandoffRows(ctx, 180)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d, want 1", n)
	}
	got, _ := s.ListHandoffs(ctx, 10)
	if len(got) != 1 || got[0].SourceSessionID != "s-fresh" {
		t.Errorf("remaining = %+v, want only s-fresh", got)
	}

	// Second run within the same horizon is idempotent.
	if n, err := s.PruneHandoffRows(ctx, 180); err != nil || n != 0 {
		t.Errorf("second prune = %d, %v; want 0", n, err)
	}
}

func TestLinkTargetSessionAndUnlinkedListing(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	ctx := context.Background()

	created := time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)
	mustInsert := func(rec HandoffRecord) int64 {
		t.Helper()
		id, err := s.InsertHandoff(ctx, rec)
		if err != nil {
			t.Fatalf("InsertHandoff: %v", err)
		}
		// Backdate created_at deterministically so the window filter is testable.
		if _, err := s.db.ExecContext(ctx, `UPDATE handoffs SET created_at = ? WHERE id = ?`,
			timestamp(created), id); err != nil {
			t.Fatalf("backdate: %v", err)
		}
		return id
	}
	// A delivered, unlinked, in-window handoff.
	id1 := mustInsert(HandoffRecord{
		SourceSessionID: "hs-1", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "distilled_tail", ForkKind: "last", Delivery: "file",
		DeliveryRef: "/home/u/proj/HANDOFF-abcd1234.md", ProjectRoot: "/home/u/proj",
	})
	// A dry-run row must never appear in the unlinked work list.
	mustInsert(HandoffRecord{
		SourceSessionID: "hs-1", SourceTool: "claude-code", TargetTool: "codex",
		CarryMode: "metadata", ForkKind: "last", Delivery: "dry_run",
	})

	unlinked, err := s.ListUnlinkedHandoffs(ctx, created.Add(-time.Hour))
	if err != nil {
		t.Fatalf("ListUnlinkedHandoffs: %v", err)
	}
	if len(unlinked) != 1 || unlinked[0].ID != id1 {
		t.Fatalf("unlinked = %+v, want just id %d", unlinked, id1)
	}
	if unlinked[0].ProjectRoot != "/home/u/proj" || unlinked[0].DeliveryRef == "" {
		t.Errorf("linker needs project_root + delivery_ref: %+v", unlinked[0])
	}

	// Out-of-window rows are excluded.
	if late, _ := s.ListUnlinkedHandoffs(ctx, created.Add(time.Hour)); len(late) != 0 {
		t.Errorf("out-of-window handoff must not list: %+v", late)
	}

	// Guarded link: stamps once, never overwrites.
	if err := s.LinkTargetSession(ctx, id1, "target-sess-A"); err != nil {
		t.Fatalf("LinkTargetSession: %v", err)
	}
	if err := s.LinkTargetSession(ctx, id1, "target-sess-B"); err != nil {
		t.Fatalf("LinkTargetSession (second): %v", err)
	}
	rows, _ := s.ListHandoffs(ctx, 5)
	var linked string
	for _, r := range rows {
		if r.ID == id1 {
			linked = r.TargetSessionID
		}
	}
	if linked != "target-sess-A" {
		t.Errorf("target_session_id = %q, want target-sess-A (write-once guard)", linked)
	}
	// Now linked → drops out of the unlinked list.
	if u2, _ := s.ListUnlinkedHandoffs(ctx, created.Add(-time.Hour)); len(u2) != 0 {
		t.Errorf("linked handoff must leave the unlinked list: %+v", u2)
	}
}

func TestCandidateTargetSessions(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	ctx := context.Background()
	// Two codex sessions in /home/u/proj after the handoff, one before, one
	// in another project.
	seed := func(id, tool, root, started string) {
		var pid int64 = 7
		if root != "/home/u/proj" {
			pid = 8
			s.db.ExecContext(ctx, `INSERT OR IGNORE INTO projects (id, root_path, created_at) VALUES (8, ?, ?)`, root, timestamp(time.Now()))
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
			id, pid, tool, started); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}
	after := time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC)
	seed("cx-early", "codex", "/home/u/proj", "2026-07-04T08:00:00Z")  // before → excluded
	seed("cx-1", "codex", "/home/u/proj", "2026-07-04T09:30:00Z")      // in
	seed("cx-2", "codex", "/home/u/proj", "2026-07-04T10:30:00Z")      // in
	seed("cx-other", "codex", "/home/u/other", "2026-07-04T09:30:00Z") // wrong project

	// Record a source_file for cx-1 (plus a duplicate + a NULL) so the
	// hint attach returns the single distinct path.
	for _, sf := range []any{"/mnt/c/opencode.db", "/mnt/c/opencode.db", nil} {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, tool, action_type, source_file, timestamp)
			 VALUES ('cx-1', 7, 'codex', 'read_file', ?, ?)`,
			sf, timestamp(time.Now())); err != nil {
			t.Fatalf("seed action: %v", err)
		}
	}

	got, err := s.CandidateTargetSessions(ctx, "codex", "/home/u/proj", after, 10)
	if err != nil {
		t.Fatalf("CandidateTargetSessions: %v", err)
	}
	if len(got) != 2 || got[0].SessionID != "cx-1" || got[1].SessionID != "cx-2" {
		t.Fatalf("candidates = %+v, want cx-1 then cx-2 (oldest-first)", got)
	}
	if len(got[0].Hints) != 1 || got[0].Hints[0] != "/mnt/c/opencode.db" {
		t.Errorf("cx-1 hints = %v, want [/mnt/c/opencode.db]", got[0].Hints)
	}
	if len(got[1].Hints) != 0 {
		t.Errorf("cx-2 hints = %v, want none", got[1].Hints)
	}
	// Empty project root drops the project filter (any project).
	anyProj, _ := s.CandidateTargetSessions(ctx, "codex", "", after, 10)
	if len(anyProj) != 3 {
		t.Errorf("empty project filter must span projects: got %d", len(anyProj))
	}
}

func TestClaimArmedHandoffHook(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	ctx := context.Background()
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

	arm := func(target, root string, expires time.Time, delivery, ref string) {
		t.Helper()
		if _, err := s.InsertHandoff(ctx, HandoffRecord{
			SourceSessionID: "hs-1", SourceTool: "claude-code", TargetTool: target,
			CarryMode: "distilled_tail", ForkKind: "last", Delivery: delivery,
			DeliveryRef: ref, ProjectRoot: root, HookExpiresAt: expires,
		}); err != nil {
			t.Fatalf("arm: %v", err)
		}
	}

	// A live armed hook for claude-code in /home/u/proj.
	arm("claude-code", "/home/u/proj", now.Add(4*time.Hour), "hook", "/home/u/proj/HANDOFF-live.md")
	// An expired one (must never fire).
	arm("claude-code", "/home/u/proj", now.Add(-time.Minute), "hook", "/home/u/proj/HANDOFF-stale.md")
	// A file-delivery row (not a hook lane).
	arm("claude-code", "/home/u/proj", time.Time{}, "file", "/home/u/proj/HANDOFF-file.md")
	// A hook for a different project.
	arm("claude-code", "/home/u/other", now.Add(4*time.Hour), "hook", "/home/u/other/HANDOFF-x.md")

	// Wrong project → no claim.
	if _, ok, err := s.ClaimArmedHandoffHook(ctx, "claude-code", "/home/u/nope", now); err != nil || ok {
		t.Fatalf("wrong project must not claim: ok=%v err=%v", ok, err)
	}
	// Wrong target tool → no claim.
	if _, ok, err := s.ClaimArmedHandoffHook(ctx, "codex", "/home/u/proj", now); err != nil || ok {
		t.Fatalf("wrong tool must not claim: ok=%v err=%v", ok, err)
	}

	// The live, matching hook fires once.
	path, ok, err := s.ClaimArmedHandoffHook(ctx, "claude-code", "/home/u/proj", now)
	if err != nil || !ok {
		t.Fatalf("expected a claim: ok=%v err=%v", ok, err)
	}
	if path != "/home/u/proj/HANDOFF-live.md" {
		t.Errorf("claimed wrong doc: %q (expired/file rows must be excluded)", path)
	}

	// One-shot: a second claim finds nothing (the live row is delivered).
	if _, ok, err := s.ClaimArmedHandoffHook(ctx, "claude-code", "/home/u/proj", now); err != nil || ok {
		t.Fatalf("second claim must be a no-op (one-shot): ok=%v err=%v", ok, err)
	}
}

// TestLoadHandoffSubstrateRefusesNetworkPaths pins ledger CLOUDSESS-12 on
// the handoff reader: a stored source_file naming a UNC share, a device or
// an extended-length path is never handed to a reader that opens it
// (handoffsvc, the MCP get_session_message tool), on any OS, while the
// session's real transcript path is kept.
func TestLoadHandoffSubstrateRefusesNetworkPaths(t *testing.T) {
	s, _ := newTestStore(t)
	seedHandoffSession(t, s)
	for i, p := range []string{
		`\attacker.example@SSL\share\a.jsonl`,
		"//attacker.example/share/a.jsonl",
		`\?\C:\Users\me\a.jsonl`,
		`\.\pipe\a.jsonl`,
	} {
		if _, err := s.db.Exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, target, success, tool, source_file, source_event_id)
		          VALUES ('hs-1', 7, '2026-07-03T10:06:00Z', ?, 'x', 1, 'claude-code', ?, ?)`,
			models.ActionReadFile, p, fmt.Sprintf("unc-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	sub, err := s.LoadHandoffSubstrate(context.Background(), "hs-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.SourceFiles) != 1 || sub.SourceFiles[0] != handoffTranscript() {
		t.Fatalf("source files = %v, want only the local transcript", sub.SourceFiles)
	}
}
