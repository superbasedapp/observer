package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
)

const (
	skTestMD   = ".claude/skills/deploy/SKILL.md"
	skTestBlob = "aaaaaaaa11111111111111111111111111111111"
	skTestSHA  = "1111111111111111111111111111111111111111"
)

func TestInsertSkillSnapshotIsIdempotentAndDedupesSets(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	members := []SkillSnapshotMember{{
		Scope: "project", RelPath: skTestMD, DirKey: ".claude/skills/deploy", Name: "deploy",
		State: "present", ContentHash: "c1", BlobOID: skTestBlob, SizeBytes: 12,
	}}
	for i, snap := range []SkillSnapshot{
		{SessionID: "s1", Tool: "claude-code", Event: "session_start", Source: "startup", ObservedAt: at, Complete: true, HomeResolved: true, Members: members},
		{SessionID: "s1", Tool: "claude-code", Event: "session_start", Source: "startup", ObservedAt: at, Complete: true, HomeResolved: true, Members: members}, // re-fired hook
		{SessionID: "s2", Tool: "claude-code", Event: "session_start", Source: "startup", ObservedAt: at.Add(time.Hour), Complete: true, HomeResolved: true, Members: members},
	} {
		if err := s.InsertSkillSnapshot(ctx, snap); err != nil {
			t.Fatalf("InsertSkillSnapshot #%d: %v", i, err)
		}
	}
	var snaps, mems int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM session_skill_snapshots`).Scan(&snaps); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM skill_snapshot_members`).Scan(&mems); err != nil {
		t.Fatal(err)
	}
	if snaps != 2 || mems != 1 {
		t.Errorf("snapshots=%d members=%d, want 2 snapshots (re-fire ignored) sharing 1 member row", snaps, mems)
	}
	var stored string
	if err := database.QueryRowContext(ctx, `SELECT observed_at FROM session_skill_snapshots WHERE session_id='s1'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "2026-09-23T10:00:00.000000000Z" {
		t.Errorf("observed_at = %q, want the fixed-width layout", stored)
	}
	if err := s.InsertSkillSnapshot(ctx, SkillSnapshot{Event: "session_start"}); err == nil {
		t.Error("empty session id accepted")
	}
}

func TestSkillGitWriters(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	root := "/repo/skills"
	projectID, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []string{".claude/skills"}
	base := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

	if ok, err := s.ProjectHasSkillSignal(ctx, projectID, root, prefixes); err != nil || ok {
		t.Fatalf("ProjectHasSkillSignal on a bare project = %v, %v; want false", ok, err)
	}

	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		{
			SHA: skTestSHA, CommittedAt: base, AuthoredAt: base, Subject: "add skill",
			Files: []commitlog.CommitFile{{RelPath: skTestMD, PathHash: "h1"}, {RelPath: "src/a.go", PathHash: "h2"}},
		},
		{
			SHA: "2222222222222222222222222222222222222222", CommittedAt: base.Add(time.Hour), AuthoredAt: base, Subject: "code only",
			Files: []commitlog.CommitFile{{RelPath: "src/a.go", PathHash: "h2"}},
		},
	}, base); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.ProjectHasSkillSignal(ctx, projectID, root, prefixes); err != nil || !ok {
		t.Fatalf("ProjectHasSkillSignal with a committed skill path = %v, %v; want true", ok, err)
	}

	moves := []HeadMoveRow{
		{MovedAt: base.Add(2 * time.Hour), SHA: "3333333333333333333333333333333333333333", Kind: "checkout"},
		{MovedAt: base, SHA: skTestSHA, Kind: "commit"},
	}
	if n, seen, err := s.InsertHeadMoves(ctx, projectID, moves); err != nil || n != 2 || seen {
		t.Fatalf("InsertHeadMoves first = %d,%v,%v; want 2,false,nil", n, seen, err)
	}
	if n, seen, err := s.InsertHeadMoves(ctx, projectID, moves[:1]); err != nil || n != 0 || !seen {
		t.Fatalf("InsertHeadMoves replay = %d,%v,%v; want 0,true,nil", n, seen, err)
	}

	cands, err := s.SkillTreeCandidates(ctx, projectID, prefixes, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 2 || cands[0] != "3333333333333333333333333333333333333333" || cands[1] != skTestSHA {
		t.Fatalf("candidates = %v, want [head-move sha, skill commit] newest first (code-only commit excluded)", cands)
	}
	if err := s.SaveSkillTree(ctx, projectID, skTestSHA, "ok",
		[]SkillTreeFileRow{{RelPath: skTestMD, Mode: "100644", BlobOID: skTestBlob}}, base); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSkillTree(ctx, projectID, "3333333333333333333333333333333333333333", "missing", nil, base); err != nil {
		t.Fatal(err)
	}
	// A memoised tree is immutable: a second save is a no-op.
	if err := s.SaveSkillTree(ctx, projectID, skTestSHA, "ok", []SkillTreeFileRow{{RelPath: "x", BlobOID: "y"}}, base); err != nil {
		t.Fatal(err)
	}
	var files int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_skill_tree_files`).Scan(&files); err != nil {
		t.Fatal(err)
	}
	if files != 1 {
		t.Errorf("tree files = %d, want 1 (immutable memo)", files)
	}
	if cands, _ := s.SkillTreeCandidates(ctx, projectID, prefixes, 10); len(cands) != 0 {
		t.Errorf("candidates after memo = %v, want none", cands)
	}
	if known, err := s.SkillTreeKnown(ctx, projectID, skTestSHA); err != nil || !known {
		t.Errorf("SkillTreeKnown = %v, %v", known, err)
	}

	if err := s.ReplaceSkillWorktree(ctx, projectID, []SkillWorktreeRow{{RelPath: skTestMD, State: "modified"}, {RelPath: "b", State: "untracked"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceSkillWorktree(ctx, projectID, []SkillWorktreeRow{{RelPath: skTestMD, State: "modified"}}); err != nil {
		t.Fatal(err)
	}
	var wt int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_skill_worktree`).Scan(&wt); err != nil {
		t.Fatal(err)
	}
	if wt != 1 {
		t.Errorf("worktree rows = %d, want 1 (replaced whole)", wt)
	}

	want := SkillScanState{
		ProjectID: projectID, LastScanAt: base, HeadSHA: skTestSHA, ReflogSince: base, ProbedAt: base,
		IgnoreCase: true, IgnoreCaseKnown: true, ShallowKnown: true, ObjectFormat: "sha1", LastError: "", ConsecutiveFailures: 0,
	}
	if err := s.SetSkillScanState(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.SkillScanStateFor(ctx, projectID)
	if err != nil || !ok || got != want {
		t.Errorf("SkillScanStateFor = %+v,%v,%v; want %+v", got, ok, err, want)
	}
	// An unknown probe round-trips as unknown (-1), never as false.
	want.IgnoreCase, want.IgnoreCaseKnown, want.ShallowKnown = false, false, false
	if err := s.SetSkillScanState(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.SkillScanStateFor(ctx, projectID); got != want {
		t.Errorf("unknown probes round-trip = %+v, want %+v", got, want)
	}
	in, err := s.LoadSkillHistoryInput(ctx, projectID, root, base, base.Add(time.Hour), prefixes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(in.Git.ProbeUnknown, ",") != "ignorecase,shallow" {
		t.Errorf("ProbeUnknown = %v, want [ignorecase shallow]", in.Git.ProbeUnknown)
	}
}

// TestHeadMoveSequenceAndSameSecondTimeline pins the two same-second
// orderings the store supplies: reflog entries sharing one second get a
// sequence from the reflog's own (newest-first) order, stable across
// captures; commits sharing one committer second come back parent-first
// in the scanner's order, with their ancestry loaded.
func TestHeadMoveSequenceAndSameSecondTimeline(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := "/repo/seq"
	projectID, err := s.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	sec := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	shaStart, shaPick, shaFinish := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	// A rebase: start, pick, finish in one second; the reflog lists them
	// newest first. The first capture only saw two of them.
	if _, _, err := s.InsertHeadMoves(ctx, projectID, []HeadMoveRow{
		{MovedAt: sec, SHA: shaPick, Kind: "rebase"}, {MovedAt: sec, SHA: shaStart, Kind: "rebase"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.InsertHeadMoves(ctx, projectID, []HeadMoveRow{
		{MovedAt: sec, SHA: shaFinish, Kind: "rebase"}, {MovedAt: sec, SHA: shaPick, Kind: "rebase"}, {MovedAt: sec, SHA: shaStart, Kind: "rebase"},
	}); err != nil {
		t.Fatal(err)
	}
	moves, err := s.loadHeadMoves(ctx, projectID)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, m := range moves {
		order = append(order, m.SHA[:1])
	}
	if strings.Join(order, "") != "321" { // newest first
		t.Errorf("same-second reflog order = %v, want finish, pick, start", order)
	}
	if newest, ok, err := s.NewestHeadMove(ctx, projectID); err != nil || !ok || !newest.Equal(sec) {
		t.Errorf("NewestHeadMove = %v,%v,%v", newest, ok, err)
	}

	// Commits: parent (adds the skill) and child (edits it) share one
	// committer second; a code-only commit between them shares it too.
	parent, mid, child := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{
		{SHA: child, Parents: []string{mid}, CommittedAt: sec, AuthoredAt: sec, Files: []commitlog.CommitFile{{RelPath: skTestMD, PathHash: "h"}}},
		{SHA: mid, Parents: []string{parent}, CommittedAt: sec, AuthoredAt: sec, Files: []commitlog.CommitFile{{RelPath: "src/a.go", PathHash: "h2"}}},
		{SHA: parent, CommittedAt: sec, AuthoredAt: sec, Files: []commitlog.CommitFile{{RelPath: skTestMD, PathHash: "h"}}},
	}, sec); err != nil {
		t.Fatal(err)
	}
	tl, truncated, err := s.loadSkillTimeline(ctx, projectID, []string{".claude/skills"})
	if err != nil || truncated {
		t.Fatalf("loadSkillTimeline: %v truncated=%v", err, truncated)
	}
	if len(tl) != 2 || tl[0].SHA != parent || tl[1].SHA != child || len(tl[1].Parents) != 1 || tl[1].Parents[0] != mid {
		t.Errorf("timeline = %+v, want parent then child, with parents", tl)
	}
	anc, err := s.loadSameSecondAncestry(ctx, projectID, tl)
	if err != nil {
		t.Fatal(err)
	}
	if len(anc) != 3 || anc[mid][0] != parent {
		t.Errorf("ancestry = %v, want all three same-second commits incl. the code-only one", anc)
	}
}

// TestLoadSkillHistoryInputFeedsBuild runs the whole read seam against a
// seeded store and hands the result to skillhistory.Build: one session
// whose hook snapshot saw the committed version, and one Skill-tool
// invocation joined to its PostToolUse snapshot by tool_use_id.
func TestLoadSkillHistoryInputFeedsBuild(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	if _, err := s.Ingest(ctx, []models.ToolEvent{
		{
			SessionID: "sess1", ProjectRoot: root, Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
			Target: "a.go", SourceFile: "/t.jsonl", SourceEventID: "e0", Timestamp: start, Success: true,
		},
		{
			SessionID: "sess1", ProjectRoot: root, Tool: models.ToolClaudeCode, ActionType: models.ActionSkillInvoke,
			RawToolName: "Skill", Target: "deploy", SourceFile: "/t.jsonl", SourceEventID: "toolu_1",
			Timestamp: start.Add(time.Minute), Success: true,
		},
	}, nil, IngestOptions{}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	projectID, err := s.ProjectIDForRoot(ctx, root)
	if err != nil || projectID == 0 {
		t.Fatalf("ProjectIDForRoot: %d %v", projectID, err)
	}
	if _, err := s.UpsertGuidanceScan(ctx, root, []guidance.File{{
		Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
		RelPath: skTestMD, AbsPath: root + "/" + skTestMD, Name: "deploy", ContentHash: "c1",
	}}, start); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertCommits(ctx, projectID, []commitlog.Commit{{
		SHA: skTestSHA, CommittedAt: start.Add(-time.Hour),
		AuthoredAt: start.Add(-time.Hour), Subject: "add deploy", Files: []commitlog.CommitFile{{RelPath: skTestMD, PathHash: "h"}},
	}}, start); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSkillTree(ctx, projectID, skTestSHA, "ok", []SkillTreeFileRow{{RelPath: skTestMD, Mode: "100644", BlobOID: skTestBlob}}, start); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.InsertHeadMoves(ctx, projectID, []HeadMoveRow{{MovedAt: start.Add(-time.Hour), SHA: skTestSHA, Kind: "commit"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSkillScanState(ctx, SkillScanState{ProjectID: projectID, LastScanAt: start, HeadSHA: skTestSHA, ReflogSince: start.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mem := []SkillSnapshotMember{{Scope: "project", RelPath: skTestMD, DirKey: ".claude/skills/deploy", Name: "deploy", State: "present", BlobOID: skTestBlob}}
	if err := s.InsertSkillSnapshot(ctx, SkillSnapshot{
		SessionID: "sess1", Tool: "claude-code", Event: "session_start",
		Source: "startup", ObservedAt: start, Complete: true, HomeResolved: true, Members: mem,
	}); err != nil {
		t.Fatal(err)
	}
	// The invocation snapshot is keyed by the HOOK's session id; the join
	// is by tool_use_id, so a different session id must not matter.
	if err := s.InsertSkillSnapshot(ctx, SkillSnapshot{
		SessionID: "hook-parent", Tool: "claude-code", Event: "skill_invoke",
		ToolUseID: "toolu_1", InvokedName: "deploy", ObservedAt: start.Add(time.Minute), Complete: true, HomeResolved: true, Members: mem,
	}); err != nil {
		t.Fatal(err)
	}

	in, err := s.LoadSkillHistoryInput(ctx, projectID, root, start.Add(-24*time.Hour), time.Now().UTC().Add(time.Hour),
		skillhistory.Pathspecs(guidance.Rules()))
	if err != nil {
		t.Fatalf("LoadSkillHistoryInput: %v", err)
	}
	if len(in.Inventory) != 1 || len(in.Timeline) != 1 || len(in.Trees) != 1 || len(in.HeadMoves) != 1 ||
		len(in.Sessions) != 1 || len(in.Invocations) != 1 || len(in.Snapshots) != 2 || !in.Git.Scanned {
		t.Fatalf("input = inv%d tl%d trees%d moves%d sess%d invs%d snaps%d git=%+v",
			len(in.Inventory), len(in.Timeline), len(in.Trees), len(in.HeadMoves),
			len(in.Sessions), len(in.Invocations), len(in.Snapshots), in.Git)
	}
	if in.Invocations[0].ToolUseID != "toolu_1" || in.Invocations[0].Name != "deploy" {
		t.Errorf("invocation = %+v, want toolu_1/deploy", in.Invocations[0])
	}

	in.Rules = guidance.Rules()
	in.SnapshotEmitters = map[string]bool{"claude-code": true}
	in.InvocationMeasurable = map[string]bool{"claude-code": true}
	r := skillhistory.Build(in)
	if len(r.Spans) != 1 || r.Spans[0].Observed.State != skillhistory.ObsObserved || r.Spans[0].Observed.Version != "aaaaaaaa" ||
		r.Spans[0].Head.State != skillhistory.HeadCommitted {
		t.Fatalf("spans = %+v, want one observed+committed span at aaaaaaaa", r.Spans)
	}
	if len(r.Cells) != 1 || len(r.Cells[0].Invoked) != 1 || r.Cells[0].Invoked[0].Version != "aaaaaaaa" {
		t.Errorf("cells = %+v, want the invocation resolved to aaaaaaaa", r.Cells)
	}
	if sk := r.Skills[0]; sk.Current.InGit != skillhistory.GitCommitted || len(sk.Commits) != 1 || sk.Commits[0].Subject != "add deploy" {
		t.Errorf("skill = %+v", sk)
	}
}
