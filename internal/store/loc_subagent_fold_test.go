package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSubagentChildFoldsIntoParentAsSidechain pins the lineage-fold path
// (Item 1.0 / D3): a sub-agent that runs in its OWN session (opencode /
// openclaw / codex / devin / a claude-code dedicated-file child with a
// session row) is linked to its parent by parent_thread_id + thread_source
// 'subagent'. The parent's card must show that child's edits as SIDECHAIN,
// while the child's OWN card stays honest — its edits are its main line.
func TestSubagentChildFoldsIntoParentAsSidechain(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("p1", "/repo", "/repo/main.go", models.ActionEditFile,
			`{"file_path":"/repo/main.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev-main", false),
		locEvent("c1", "/repo", "/repo/sub.go", models.ActionEditFile,
			`{"file_path":"/repo/sub.go","old_string":"b := 1","new_string":"b := 2\nc := 3"}`,
			"ev-child", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// Link c1 as a sub-agent of p1 (the lineage every separate-session
	// sub-agent adapter records).
	if _, err := s.SetSessionLineage(ctx, models.SessionLineage{
		SessionID: "c1", ParentThreadID: "p1", ThreadSource: "subagent",
	}); err != nil {
		t.Fatalf("SetSessionLineage: %v", err)
	}

	parent, err := s.LoadSessionLOC(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	var main, side loc.Stats
	for _, b := range parent.Buckets {
		if b.Sidechain {
			side.Add(b.Stats)
		} else {
			main.Add(b.Stats)
		}
	}
	if main.ModifiedCode != 1 || main.AddedCode != 0 {
		t.Errorf("parent main = %+v, want 1 modified (its own edit)", main)
	}
	if side.ModifiedCode != 1 || side.AddedCode != 1 {
		t.Errorf("parent sidechain = %+v, want the child's 1 modified + 1 added folded in", side)
	}
	if parent.Files != 2 {
		t.Errorf("parent files = %d, want 2 (own + folded child)", parent.Files)
	}

	// The child's OWN card must NOT relabel its work as sidechain — from the
	// child's vantage its edit is main-line. This is why the split is derived
	// at parent read time and never stored on the child's rows.
	child, err := s.LoadSessionLOC(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	var childMain loc.Stats
	for _, b := range child.Buckets {
		if b.Sidechain {
			t.Errorf("child card bucket %+v is sidechain — a sub-agent's own card must read main-line", b)
		}
		childMain.Add(b.Stats)
	}
	if childMain.ModifiedCode != 1 || childMain.AddedCode != 1 {
		t.Errorf("child own card = %+v, want 1 modified + 1 added on the main line", childMain)
	}
}

// TestSubagentOrphanFoldsViaAgentIDConvention pins the LIKE-fold path: a
// claude-code dedicated-file child whose session row was never stamped with
// lineage still folds into the parent through the `<parent>:agent:<id>` id
// convention. SubagentChildIDs returns nothing here (no thread_source), so
// only the id-prefix LIKE can produce the fold.
func TestSubagentOrphanFoldsViaAgentIDConvention(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	child := "p2:agent:aa11bb22cc33dd44e"
	events := []models.ToolEvent{
		locEvent("p2", "/repo", "/repo/main.go", models.ActionEditFile,
			`{"file_path":"/repo/main.go","old_string":"a := 1","new_string":"a := 2"}`,
			"ev-main", false),
		locEvent(child, "/repo", "/repo/child.go", models.ActionEditFile,
			`{"file_path":"/repo/child.go","old_string":"x := 1","new_string":"x := 2\ny := 9"}`,
			"ev-orphan", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// Deliberately NO SetSessionLineage: prove the id-prefix fold alone works.
	kids, err := s.SubagentChildIDs(ctx, "p2")
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 0 {
		t.Fatalf("SubagentChildIDs = %v, want none (no lineage stamped)", kids)
	}

	parent, err := s.LoadSessionLOC(ctx, "p2")
	if err != nil {
		t.Fatal(err)
	}
	var side loc.Stats
	for _, b := range parent.Buckets {
		if b.Sidechain {
			side.Add(b.Stats)
		}
	}
	if side.ModifiedCode != 1 || side.AddedCode != 1 {
		t.Errorf("parent sidechain = %+v, want the orphan child's 1 modified + 1 added", side)
	}

	// The child card, viewed directly, is honest main-line.
	c, err := s.LoadSessionLOC(ctx, child)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range c.Buckets {
		if b.Sidechain {
			t.Errorf("orphan child own card bucket %+v is sidechain, want main-line", b)
		}
	}
}

// TestParentFoldDropsChildDigestAlreadyOnParent pins the double-count guard:
// when a parent inline-sidechain edit and a folded child edit describe the
// SAME change to the same file (identical file_path_hash + input_digest),
// only one is counted — the guard drops the folded child duplicate.
func TestParentFoldDropsChildDigestAlreadyOnParent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	raw := `{"file_path":"/repo/x.go","old_string":"a := 1","new_string":"a := 2"}`
	events := []models.ToolEvent{
		// The parent already carries this change as an inline sidechain edit.
		locEvent("p3", "/repo", "/repo/x.go", models.ActionEditFile, raw, "ev-parent", true),
		// The folded child carries a byte-identical duplicate of it.
		locEvent("p3:agent:dead0beef0000cafe", "/repo", "/repo/x.go", models.ActionEditFile, raw, "ev-childdup", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	parent, err := s.LoadSessionLOC(ctx, "p3")
	if err != nil {
		t.Fatal(err)
	}
	var side loc.Stats
	for _, b := range parent.Buckets {
		side.Add(b.Stats) // both the inline-sidechain and any folded child land in sidechain
	}
	if side.ModifiedCode != 1 {
		t.Errorf("sidechain modified = %d, want 1 (the child duplicate must not double-count)", side.ModifiedCode)
	}
	if parent.Files != 1 {
		t.Errorf("parent files = %d, want 1 (same file, de-duplicated)", parent.Files)
	}
}

// TestSubagentChildIDs pins the lineage read helper: it returns a parent's
// thread_source='subagent' children and never the parent itself, and is
// empty for a session with no sub-agents.
func TestSubagentChildIDs(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	events := []models.ToolEvent{
		locEvent("par", "/repo", "/repo/a.go", models.ActionEditFile,
			`{"file_path":"/repo/a.go","old_string":"a := 1","new_string":"a := 2"}`, "e0", false),
		locEvent("kidA", "/repo", "/repo/b.go", models.ActionEditFile,
			`{"file_path":"/repo/b.go","old_string":"b := 1","new_string":"b := 2"}`, "e1", false),
		locEvent("kidB", "/repo", "/repo/c.go", models.ActionEditFile,
			`{"file_path":"/repo/c.go","old_string":"c := 1","new_string":"c := 2"}`, "e2", false),
	}
	if _, err := s.Ingest(ctx, events, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	for _, kid := range []string{"kidA", "kidB"} {
		if _, err := s.SetSessionLineage(ctx, models.SessionLineage{
			SessionID: kid, ParentThreadID: "par", ThreadSource: "subagent",
		}); err != nil {
			t.Fatalf("SetSessionLineage %s: %v", kid, err)
		}
	}

	got, err := s.SubagentChildIDs(ctx, "par")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"kidA": true, "kidB": true}
	if len(got) != 2 {
		t.Fatalf("SubagentChildIDs = %v, want kidA + kidB", got)
	}
	for _, id := range got {
		if !want[id] {
			t.Errorf("unexpected child id %q", id)
		}
	}
	if none, err := s.SubagentChildIDs(ctx, "kidA"); err != nil || len(none) != 0 {
		t.Errorf("SubagentChildIDs(kidA) = %v, %v; want empty (a leaf has no sub-agents)", none, err)
	}
}
