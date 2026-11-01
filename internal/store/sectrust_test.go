package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSecTrustAcceptFlow: a recorded item is not accepted; an accept
// records who and when and makes the digest accepted for that project only;
// recording again keeps the accept; a revoke clears it and keeps the row.
func TestSecTrustAcceptFlow(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	const p1, p2 = "proj-one-hash", "proj-two-hash"
	item := SecTrustItem{
		ContentHash: "sha256:aa", Scope: "project_shared", PathClass: "structured",
		RelPath: ".mcp.json", ItemKey: "mcpServers.fs", ReasonCode: "mcp_server_command",
	}
	if err := s.RecordSecTrustItems(ctx, p1, []SecTrustItem{item}, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.AcceptedSecTrustDigests(ctx, p1); len(got) != 0 {
		t.Fatalf("recorded item already accepted: %v", got)
	}
	if _, err := s.AcceptSecTrustItems(ctx, p1, []SecTrustItem{item}, "", now); err == nil {
		t.Fatal("an accept without who was stored")
	}
	if n, err := s.AcceptSecTrustItems(ctx, p1, []SecTrustItem{item}, "cli:dev", now.Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("accept: %d %v", n, err)
	}
	if err := s.RecordSecTrustItems(ctx, p1, []SecTrustItem{item}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.AcceptedSecTrustDigests(ctx, p1)
	if err != nil || !got[item.ContentHash] {
		t.Fatalf("accepted digests %v %v", got, err)
	}
	if other, _ := s.AcceptedSecTrustDigests(ctx, p2); len(other) != 0 {
		t.Fatalf("an accept leaked to another project: %v", other)
	}
	recs, err := s.ListSecTrustItems(ctx, p1)
	if err != nil || len(recs) != 1 {
		t.Fatalf("list %v %v", recs, err)
	}
	r := recs[0]
	if !r.Accepted() || r.AcceptedBy != "cli:dev" || !r.AcceptedAt.Equal(now.Add(time.Minute)) ||
		!r.FirstSeenAt.Equal(now) || !r.LastSeenAt.Equal(now.Add(2*time.Minute)) || r.ItemKey != "mcpServers.fs" {
		t.Fatalf("record %+v", r)
	}
	if ok, err := s.RevokeSecTrustAccept(ctx, p1, item.ContentHash); err != nil || !ok {
		t.Fatalf("revoke %v %v", ok, err)
	}
	if got, _ := s.AcceptedSecTrustDigests(ctx, p1); len(got) != 0 {
		t.Fatalf("revoked digest still accepted: %v", got)
	}
	if recs, _ := s.ListSecTrustItems(ctx, p1); len(recs) != 1 || recs[0].Accepted() {
		t.Fatalf("revoke removed or kept the record wrongly: %+v", recs)
	}
}

// TestSecTrustRefusesBadInput: no project and a non-digest are refused.
func TestSecTrustRefusesBadInput(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.RecordSecTrustItems(ctx, "", []SecTrustItem{{ContentHash: "sha256:aa"}}, now); err == nil {
		t.Error("no project hash accepted")
	}
	if err := s.RecordSecTrustItems(ctx, "p", []SecTrustItem{{ContentHash: "md5:aa"}}, now); err == nil {
		t.Error("a non-sha256 digest accepted")
	}
}

// TestSecConfigFilesSnapshot: a project has no snapshot until one is
// stored; a replace swaps the whole snapshot; projects stay apart.
func TestSecConfigFilesSnapshot(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if _, ok, err := s.LoadSecConfigFiles(ctx, "p1"); err != nil || ok {
		t.Fatalf("fresh project: ok %v err %v", ok, err)
	}
	first := []SecConfigFile{{RelPath: ".mcp.json", PathClass: "structured", SHA256: "aa", Size: 2}, {RelPath: "CLAUDE.md", PathClass: "prose", SHA256: "bb", Size: 4}}
	if err := s.ReplaceSecConfigFiles(ctx, "p1", first, now); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadSecConfigFiles(ctx, "p1")
	if err != nil || !ok || len(got) != 2 || got[0] != first[0] {
		t.Fatalf("loaded %+v %v %v", got, ok, err)
	}
	if err := s.ReplaceSecConfigFiles(ctx, "p1", first[:1], now); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.LoadSecConfigFiles(ctx, "p1"); len(got) != 1 {
		t.Fatalf("after replace %+v", got)
	}
	if _, ok, _ := s.LoadSecConfigFiles(ctx, "p2"); ok {
		t.Fatal("projects share a snapshot")
	}
	if err := s.ReplaceSecConfigFiles(ctx, "p2", nil, now); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := s.LoadSecConfigFiles(ctx, "p2"); err != nil || !ok || len(got) != 0 {
		t.Fatalf("an empty snapshot: %+v %v %v", got, ok, err)
	}
	if err := s.ReplaceSecConfigFiles(ctx, "", first, now); err == nil {
		t.Fatal("a snapshot without a project was stored")
	}
}

// TestLatestAgentWriteTo: the newest agent write to the file since the
// given time, or none.
func TestLatestAgentWriteTo(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, ok, err := s.LatestAgentWriteTo(ctx, []string{"/r/.mcp.json"}, time.Time{}); err != nil || ok {
		t.Fatalf("no actions: ok %v err %v", ok, err)
	}
	if _, ok, err := s.LatestAgentWriteTo(ctx, nil, time.Time{}); err != nil || ok {
		t.Fatalf("no targets: ok %v err %v", ok, err)
	}
	ts := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ev := func(id, typ, target string) models.ToolEvent {
		return models.ToolEvent{
			SessionID: "s1", ProjectRoot: "/r", Timestamp: ts, Tool: models.ToolClaudeCode,
			SourceFile: "/t.jsonl", SourceEventID: id, ActionType: typ, Target: target, Success: true,
		}
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		ev("a", models.ActionReadFile, "/r/.mcp.json"),
		ev("b", models.ActionEditFile, "/r/.mcp.json"),
	}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	a, ok, err := s.LatestAgentWriteTo(ctx, []string{"/r/.mcp.json", ".mcp.json"}, ts.Add(-time.Minute))
	if err != nil || !ok || a.SessionID != "s1" || a.ActionID == 0 {
		t.Fatalf("the edit: %+v %v %v", a, ok, err)
	}
	if _, ok, _ := s.LatestAgentWriteTo(ctx, []string{"/r/.mcp.json"}, ts.Add(time.Minute)); ok {
		t.Fatal("an edit before the snapshot was attributed")
	}
}

// TestAgentFileWritesAfter: the change feed returns write and edit actions
// above the watermark, oldest first, with their project root, and the
// watermark starts at the newest action.
func TestAgentFileWritesAfter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if id, err := s.LatestActionID(ctx); err != nil || id != 0 {
		t.Fatalf("empty: %d %v", id, err)
	}
	ts := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ev := func(id, typ, target string) models.ToolEvent {
		return models.ToolEvent{
			SessionID: "s1", ProjectRoot: "/r", Timestamp: ts, Tool: models.ToolClaudeCode,
			SourceFile: "/t.jsonl", SourceEventID: id, ActionType: typ, Target: target, Success: true,
		}
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		ev("a", models.ActionWriteFile, "/r/.mcp.json"),
	}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	mark, err := s.LatestActionID(ctx)
	if err != nil || mark == 0 {
		t.Fatalf("watermark: %d %v", mark, err)
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{
		ev("b", models.ActionReadFile, "/r/.mcp.json"),
		ev("c", models.ActionEditFile, ".claude/settings.json"),
		ev("d", models.ActionWriteFile, "/r/AGENTS.md"),
	}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.AgentFileWritesAfter(ctx, mark, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Target != ".claude/settings.json" || got[1].Target != "/r/AGENTS.md" ||
		got[0].ProjectRoot == "" || got[0].ActionID <= mark || got[1].ActionID <= got[0].ActionID {
		t.Fatalf("feed: %+v", got)
	}
	if one, _ := s.AgentFileWritesAfter(ctx, mark, 1); len(one) != 1 {
		t.Fatalf("limit: %+v", one)
	}
}
