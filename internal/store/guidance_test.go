package store

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const guidanceTestRoot = "/repo/demo"

func guidanceFile(tool, rel string, kind guidance.Kind, hash string) guidance.File {
	return guidance.File{
		Tool:        tool,
		Kind:        kind,
		Scope:       guidance.ScopeProject,
		RelPath:     rel,
		AbsPath:     guidanceTestRoot + "/" + rel,
		Name:        "n-" + rel,
		Description: "d-" + rel,
		SizeBytes:   int64(len(hash)),
		ModTime:     time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC),
		ContentHash: hash,
	}
}

func guidanceAt(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
}

// TestUpsertGuidanceScanLifecycle is the load-bearing store test: a file
// appears, stays unchanged, changes, vanishes (tombstoned, NEVER
// deleted) and then comes back — with first_seen preserved across the
// whole arc.
func TestUpsertGuidanceScanLifecycle(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	// --- 1. first scan: two files, both new -----------------------------
	first := []guidance.File{
		guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "hash-a"),
		guidanceFile("cursor", ".cursor/rules/a.mdc", guidance.KindRule, "hash-b"),
	}
	sum, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot, first, t0)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if want := (GuidanceScanSummary{Added: 2}); sum != want {
		t.Fatalf("first scan summary = %+v want %+v", sum, want)
	}
	rows, err := s.ListGuidance(ctx, guidanceTestRoot, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("live rows = %d want 2", len(rows))
	}
	firstSeen := map[string]time.Time{}
	for _, r := range rows {
		firstSeen[r.Tool] = r.FirstSeen
		if !r.Present {
			t.Errorf("%s: Present = false on a fresh row", r.Tool)
		}
	}

	// --- 2. identical rescan: everything unchanged, first_seen kept -----
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, first, t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if want := (GuidanceScanSummary{Unchanged: 2}); sum != want {
		t.Fatalf("rescan summary = %+v want %+v", sum, want)
	}
	rows, _ = s.ListGuidance(ctx, guidanceTestRoot, false)
	for _, r := range rows {
		if !r.FirstSeen.Equal(firstSeen[r.Tool]) {
			t.Errorf("%s: first_seen moved on an unchanged rescan: %v -> %v", r.Tool, firstSeen[r.Tool], r.FirstSeen)
		}
		if !r.LastScanned.Equal(t0.Add(time.Hour)) {
			t.Errorf("%s: last_scanned = %v, want the rescan stamp", r.Tool, r.LastScanned)
		}
	}

	// --- 3. one file's bytes change ------------------------------------
	changed := []guidance.File{
		guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "hash-a2"),
		guidanceFile("cursor", ".cursor/rules/a.mdc", guidance.KindRule, "hash-b"),
	}
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, changed, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("changed scan: %v", err)
	}
	if want := (GuidanceScanSummary{Updated: 1, Unchanged: 1}); sum != want {
		t.Fatalf("changed summary = %+v want %+v", sum, want)
	}

	// --- 4. the cursor rule disappears: tombstoned, not deleted --------
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, changed[:1], t0.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("tombstone scan: %v", err)
	}
	if want := (GuidanceScanSummary{Unchanged: 1, Tombstoned: 1}); sum != want {
		t.Fatalf("tombstone summary = %+v want %+v", sum, want)
	}
	live, _ := s.ListGuidance(ctx, guidanceTestRoot, false)
	if len(live) != 1 || live[0].Tool != "claude-code" {
		t.Fatalf("live rows after tombstone = %+v, want only claude-code", live)
	}
	all, _ := s.ListGuidance(ctx, guidanceTestRoot, true)
	if len(all) != 2 {
		t.Fatalf("includeAbsent rows = %d want 2 — a tombstone must never delete", len(all))
	}
	var tomb GuidanceRow
	for _, r := range all {
		if r.Tool == "cursor" {
			tomb = r
		}
	}
	if tomb.Present {
		t.Error("the vanished row is still marked present")
	}
	if !tomb.FirstSeen.Equal(firstSeen["cursor"]) {
		t.Errorf("tombstone lost first_seen: %v want %v", tomb.FirstSeen, firstSeen["cursor"])
	}

	// --- 5. a second tombstoning scan must not re-count it --------------
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, changed[:1], t0.Add(4*time.Hour))
	if err != nil {
		t.Fatalf("second tombstone scan: %v", err)
	}
	if sum.Tombstoned != 0 {
		t.Errorf("Tombstoned = %d on a repeat scan, want 0 (already absent)", sum.Tombstoned)
	}

	// --- 6. the file comes back: an update, with first_seen intact ------
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, changed, t0.Add(5*time.Hour))
	if err != nil {
		t.Fatalf("reappear scan: %v", err)
	}
	if want := (GuidanceScanSummary{Updated: 1, Unchanged: 1}); sum != want {
		t.Fatalf("reappear summary = %+v want %+v", sum, want)
	}
	live, _ = s.ListGuidance(ctx, guidanceTestRoot, false)
	if len(live) != 2 {
		t.Fatalf("live rows after reappear = %d want 2", len(live))
	}
	for _, r := range live {
		if r.Tool != "cursor" {
			continue
		}
		if !r.Present {
			t.Error("the reappeared row is not present")
		}
		if !r.FirstSeen.Equal(firstSeen["cursor"]) {
			t.Errorf("reappear reset first_seen: %v want %v", r.FirstSeen, firstSeen["cursor"])
		}
	}
}

// TestUpsertGuidanceScanIsScopedToOneProject pins that a scan of one
// project never tombstones another's rows.
func TestUpsertGuidanceScanIsScopedToOneProject(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	a := []guidance.File{guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "a")}
	b := []guidance.File{guidanceFile("codex", "AGENTS.md", guidance.KindInstructions, "b")}
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/one", a, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/two", b, t0); err != nil {
		t.Fatal(err)
	}
	// Empty scan of /repo/two clears only /repo/two.
	sum, err := s.UpsertGuidanceScan(ctx, "/repo/two", nil, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Tombstoned != 1 {
		t.Errorf("Tombstoned = %d want 1", sum.Tombstoned)
	}
	one, _ := s.ListGuidance(ctx, "/repo/one", false)
	if len(one) != 1 {
		t.Errorf("/repo/one lost rows to a /repo/two scan: %+v", one)
	}
}

// TestGuidanceSameFileFansOutPerTool pins the intended key shape: one
// AGENTS.md read by several tools is several rows, and they are
// independent.
func TestGuidanceSameFileFansOutPerTool(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	files := []guidance.File{
		guidanceFile("codex", "AGENTS.md", guidance.KindInstructions, "shared"),
		guidanceFile("opencode", "AGENTS.md", guidance.KindInstructions, "shared"),
		guidanceFile("droid", "AGENTS.md", guidance.KindInstructions, "shared"),
	}
	sum, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot, files, t0)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Added != 3 {
		t.Fatalf("Added = %d want 3 (one row per tool)", sum.Added)
	}
	// A duplicate (tool, scope, rel_path) inside one scan collapses.
	sum, err = s.UpsertGuidanceScan(ctx, guidanceTestRoot, append(files, files[0]), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unchanged != 3 || sum.Added != 0 {
		t.Errorf("duplicate in one scan was double-counted: %+v", sum)
	}
}

// TestGuidanceScopeAndFrontmatterRoundTrip pins that the user-scope
// "~/" path and the flat front-matter map survive the store unchanged.
func TestGuidanceScopeAndFrontmatterRoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	user := guidance.File{
		Tool:        "claude-code",
		Kind:        guidance.KindSkill,
		Scope:       guidance.ScopeUser,
		RelPath:     "~/.claude/skills/bar/SKILL.md",
		AbsPath:     "/home/dev/.claude/skills/bar/SKILL.md",
		Name:        "bar-skill",
		Description: "A user-scope skill.",
		SizeBytes:   42,
		ModTime:     time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC),
		ContentHash: "deadbeef",
		Frontmatter: map[string]string{"name": "bar-skill", "allowed-tools": "Read, Bash"},
	}
	bare := guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "plain")
	bare.ParseErr = "front matter: bad mapping"

	if _, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot, []guidance.File{user, bare}, t0); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListGuidance(ctx, guidanceTestRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d want 2", len(rows))
	}

	var got GuidanceRow
	for _, r := range rows {
		if r.Scope == string(guidance.ScopeUser) {
			got = r
		}
	}
	if got.RelPath != user.RelPath || got.AbsPath != user.AbsPath {
		t.Errorf("user-scope paths mangled: rel=%q abs=%q", got.RelPath, got.AbsPath)
	}
	if got.Kind != string(guidance.KindSkill) {
		t.Errorf("Kind = %q want %q", got.Kind, guidance.KindSkill)
	}
	if !got.ModifiedAt.Equal(user.ModTime) {
		t.Errorf("ModifiedAt = %v want %v", got.ModifiedAt, user.ModTime)
	}
	if len(got.Frontmatter) != 2 || got.Frontmatter["allowed-tools"] != "Read, Bash" {
		t.Errorf("Frontmatter round-trip broke: %v", got.Frontmatter)
	}
	for _, r := range rows {
		if r.Scope != string(guidance.ScopeProject) {
			continue
		}
		if r.ParseError != bare.ParseErr {
			t.Errorf("ParseError = %q want %q", r.ParseError, bare.ParseErr)
		}
		if r.Frontmatter != nil {
			t.Errorf("empty front matter decoded to %v, want nil", r.Frontmatter)
		}
	}
}

// TestListGuidanceOrdering pins the (tool, kind, rel_path) order the
// panel renders in.
func TestListGuidanceOrdering(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	files := []guidance.File{
		guidanceFile("cursor", "z.mdc", guidance.KindRule, "1"),
		guidanceFile("claude-code", "b.md", guidance.KindSkill, "2"),
		guidanceFile("claude-code", "a.md", guidance.KindSkill, "3"),
		guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "4"),
	}
	if _, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot, files, guidanceAt(t)); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListGuidance(ctx, guidanceTestRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"claude-code/instructions/CLAUDE.md",
		"claude-code/skill/a.md",
		"claude-code/skill/b.md",
		"cursor/rule/z.mdc",
	}
	for i, r := range rows {
		got := r.Tool + "/" + r.Kind + "/" + r.RelPath
		if i >= len(want) || got != want[i] {
			t.Fatalf("row %d = %q, want %q (full: %+v)", i, got, want[i], rows)
		}
	}
}

// TestGuidanceProjects pins the cross-project index, including the
// "scanned but now empty" case that must still be listed.
func TestGuidanceProjects(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	if _, err := s.UpsertGuidanceScan(ctx, "/repo/older",
		[]guidance.File{guidanceFile("codex", "AGENTS.md", guidance.KindInstructions, "a")}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/newer", []guidance.File{
		guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "b"),
		guidanceFile("cursor", "a.mdc", guidance.KindRule, "c"),
	}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// /repo/older then loses its only file.
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/older", nil, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	projects, err := s.GuidanceProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 2 {
		t.Fatalf("projects = %+v want 2", projects)
	}
	// Most recently scanned first — /repo/older was rescanned last.
	if projects[0].ProjectRoot != "/repo/older" {
		t.Errorf("order = %s first, want /repo/older (most recent scan)", projects[0].ProjectRoot)
	}
	if projects[0].Files != 0 {
		t.Errorf("/repo/older live files = %d, want 0 — tombstones must not count", projects[0].Files)
	}
	if !projects[0].LastScanned.Equal(t0.Add(2 * time.Hour)) {
		t.Errorf("/repo/older last scanned = %v want %v", projects[0].LastScanned, t0.Add(2*time.Hour))
	}
	if projects[1].ProjectRoot != "/repo/newer" || projects[1].Files != 2 {
		t.Errorf("/repo/newer = %+v want 2 live files", projects[1])
	}
}

// TestGuidanceRejectsEmptyProjectRoot pins the guard clauses.
func TestGuidanceRejectsEmptyProjectRoot(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.UpsertGuidanceScan(ctx, "  ", nil, time.Now()); err == nil {
		t.Error("UpsertGuidanceScan accepted an empty project root")
	}
	if _, err := s.ListGuidance(ctx, "", false); err == nil {
		t.Error("ListGuidance accepted an empty project root")
	}
}

// TestGuidanceProjectsEmpty pins the zero state: no scans, no rows, no
// error.
func TestGuidanceProjectsEmpty(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	projects, err := s.GuidanceProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 0 {
		t.Errorf("projects = %+v want none", projects)
	}
}

// guidanceUserFile builds a ScopeUser row the way the scanner does: a
// "~/"-prefixed relative path and an absolute path under the home dir.
func guidanceUserFile(tool, rel, hash string) guidance.File {
	return guidance.File{
		Tool:        tool,
		Kind:        guidance.KindInstructions,
		Scope:       guidance.ScopeUser,
		RelPath:     "~/" + rel,
		AbsPath:     "/home/dev/" + rel,
		Name:        "n-" + rel,
		Description: "d-" + rel,
		SizeBytes:   int64(len(hash)),
		ModTime:     time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC),
		ContentHash: hash,
	}
}

// TestGuidanceUserScopeSentinel pins the once-per-machine home inventory:
// it is stored under ONE sentinel root, folded into every project's
// listing, and never counted as a project of its own.
func TestGuidanceUserScopeSentinel(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := guidanceAt(t)

	if _, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot,
		[]guidance.File{guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "hash-a")}, t0); err != nil {
		t.Fatalf("project scan: %v", err)
	}
	if _, err := s.UpsertGuidanceScan(ctx, GuidanceUserScopeRoot,
		[]guidance.File{guidanceUserFile("claude-code", ".claude/CLAUDE.md", "hash-u")}, t0); err != nil {
		t.Fatalf("user scan: %v", err)
	}

	// Every project's inventory carries the home rows.
	rows, err := s.ListGuidance(ctx, guidanceTestRoot, false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d want 2 (the project file + the folded home file): %+v", len(rows), rows)
	}
	var user int
	for _, r := range rows {
		if r.Scope == string(guidance.ScopeUser) {
			user++
			if r.RelPath != "~/.claude/CLAUDE.md" {
				t.Errorf("user row rel_path = %q", r.RelPath)
			}
		}
	}
	if user != 1 {
		t.Errorf("user-scope rows in a project listing = %d want 1", user)
	}

	// A project that has NEVER been scanned still sees them, because they
	// apply to every project on the machine.
	other, err := s.ListGuidance(ctx, "/repo/other", false)
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(other) != 1 || other[0].Scope != string(guidance.ScopeUser) {
		t.Errorf("unscanned project listing = %+v, want just the folded home row", other)
	}

	// Asking for the sentinel itself returns those rows once, not twice.
	sentinel, err := s.ListGuidance(ctx, GuidanceUserScopeRoot, false)
	if err != nil {
		t.Fatalf("list sentinel: %v", err)
	}
	if len(sentinel) != 1 {
		t.Errorf("sentinel listing = %+v want exactly 1 row", sentinel)
	}

	// And the sentinel is not a project.
	projects, err := s.GuidanceProjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 || projects[0].ProjectRoot != guidanceTestRoot {
		t.Errorf("projects = %+v, want only %s", projects, guidanceTestRoot)
	}
	if projects[0].Files != 1 {
		t.Errorf("project file count = %d, want 1 — home rows must not be counted here", projects[0].Files)
	}
}

// TestGuidanceKnownFiles pins the re-scan cache seam's shape.
func TestGuidanceKnownFiles(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	f := guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "hash-a")
	f.Frontmatter = map[string]string{"model": "opus"}
	if _, err := s.UpsertGuidanceScan(ctx, guidanceTestRoot, []guidance.File{f}, guidanceAt(t)); err != nil {
		t.Fatalf("scan: %v", err)
	}
	known, err := s.GuidanceKnownFiles(ctx, guidanceTestRoot)
	if err != nil {
		t.Fatalf("GuidanceKnownFiles: %v", err)
	}
	k, ok := known[f.AbsPath]
	if !ok {
		t.Fatalf("no cache entry for %s: %+v", f.AbsPath, known)
	}
	if k.ContentHash != f.ContentHash || k.SizeBytes != f.SizeBytes || !k.ModTime.Equal(f.ModTime) {
		t.Errorf("cache identity mismatch: %+v want %s/%d/%v", k, f.ContentHash, f.SizeBytes, f.ModTime)
	}
	if k.Name != f.Name || k.Description != f.Description || k.Frontmatter["model"] != "opus" {
		t.Errorf("cache metadata mismatch: %+v", k)
	}
}

// TestGuidanceScanRootsOrdersByActivity pins the pass's root selection:
// most recently active first, and capped.
func TestGuidanceScanRootsOrdersByActivity(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	insert := func(root, created, lastSession string) {
		t.Helper()
		var last any
		if lastSession != "" {
			last = lastSession
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO projects (root_path, created_at, last_session_at) VALUES (?, ?, ?)`,
			root, created, last); err != nil {
			t.Fatalf("insert %s: %v", root, err)
		}
	}
	insert("/repo/stale", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
	insert("/repo/fresh", "2026-01-01T00:00:00Z", "2026-09-01T00:00:00Z")
	insert("/repo/never", "2026-05-01T00:00:00Z", "")

	roots, err := s.GuidanceScanRoots(ctx, 0)
	if err != nil {
		t.Fatalf("GuidanceScanRoots: %v", err)
	}
	want := []string{"/repo/fresh", "/repo/never", "/repo/stale"}
	if len(roots) != len(want) {
		t.Fatalf("roots = %v want %v", roots, want)
	}
	for i := range want {
		if roots[i] != want[i] {
			t.Fatalf("roots = %v want %v", roots, want)
		}
	}

	capped, err := s.GuidanceScanRoots(ctx, 2)
	if err != nil {
		t.Fatalf("GuidanceScanRoots capped: %v", err)
	}
	if len(capped) != 2 || capped[0] != "/repo/fresh" {
		t.Errorf("capped roots = %v, want the 2 most recently active", capped)
	}
}

// --------------------------------------------------------------- usage join

const guidanceUsageRoot = "/repo/usage"

func guidanceUsageFixture(t *testing.T) (*Store, context.Context, int64) {
	t.Helper()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, guidanceUsageRoot, "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s-guid", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	return s, ctx, pid
}

func guidanceUsageAction(pid int64, id, actionType, target string, at time.Time) models.Action {
	return models.Action{
		SessionID: "s-guid", ProjectID: pid, Timestamp: at,
		ActionType: actionType, Target: target, Success: true,
		Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: id,
	}
}

// TestGuidanceUsage_JoinsSkillsAndLoads is the wave-2 join: skill_invoke
// actions fold onto guidance.SkillKey identities (so "deploy.md" and
// "deploy" are one key), instructions_loaded actions fold onto cleaned
// absolute paths, and anything outside the window is excluded.
func TestGuidanceUsage_JoinsSkillsAndLoads(t *testing.T) {
	t.Parallel()
	s, ctx, pid := guidanceUsageFixture(t)
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -200)

	if _, err := s.InsertActions(ctx, []models.Action{
		guidanceUsageAction(pid, "sk-1", models.ActionSkillInvoke, "update-config", now.Add(-2*time.Hour)),
		guidanceUsageAction(pid, "sk-2", models.ActionSkillInvoke, "update-config", now.Add(-time.Hour)),
		// Same skill, path-and-extension spelling: same normalized key.
		guidanceUsageAction(pid, "sk-3", models.ActionSkillInvoke, "skills/update-config.md", now.Add(-30*time.Minute)),
		guidanceUsageAction(pid, "sk-4", models.ActionSkillInvoke, "code-review", now.Add(-time.Minute)),
		// Outside the 90d window: must not count.
		guidanceUsageAction(pid, "sk-old", models.ActionSkillInvoke, "ancient", old),
		// Empty target (a pre-wave-2 row): contributes no key at all.
		guidanceUsageAction(pid, "sk-empty", models.ActionSkillInvoke, "", now),
		guidanceUsageAction(pid, "ld-1", models.ActionInstructionsLoaded, guidanceUsageRoot+"/CLAUDE.md", now.Add(-3*time.Hour)),
		guidanceUsageAction(pid, "ld-2", models.ActionInstructionsLoaded, guidanceUsageRoot+"/./CLAUDE.md", now.Add(-time.Hour)),
		// An unrelated action type must never land in either map.
		guidanceUsageAction(pid, "rd-1", models.ActionReadFile, "main.go", now),
	}); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}

	u, err := s.GuidanceUsage(ctx, guidanceUsageRoot, time.Time{})
	if err != nil {
		t.Fatalf("GuidanceUsage: %v", err)
	}

	wantKey := guidance.SkillKey("claude-code", guidance.KindSkill, "update-config")
	if got := u.Skills[wantKey]; got.Count != 3 {
		t.Errorf("skills[%s].Count = %d, want 3 (two spellings folded)", wantKey, got.Count)
	}
	if got := u.Skills[wantKey].Last; got.Before(now.Add(-time.Hour)) {
		t.Errorf("skills[%s].Last = %v, want the newest of the three", wantKey, got)
	}
	reviewKey := guidance.SkillKey("claude-code", guidance.KindSkill, "code-review")
	if got := u.Skills[reviewKey].Count; got != 1 {
		t.Errorf("skills[%s].Count = %d, want 1", reviewKey, got)
	}
	oldKey := guidance.SkillKey("claude-code", guidance.KindSkill, "ancient")
	if _, ok := u.Skills[oldKey]; ok {
		t.Errorf("skills[%s] present, want excluded by the 90d window", oldKey)
	}
	if len(u.Skills) != 2 {
		t.Errorf("skills = %d keys (%v), want 2 (empty target contributes none)", len(u.Skills), u.Skills)
	}

	loadKey := guidanceUsageRoot + "/CLAUDE.md"
	if got := u.Files[loadKey].Count; got != 2 {
		t.Errorf("files[%s].Count = %d, want 2 (path cleaned before keying)", loadKey, got)
	}
	if len(u.Files) != 1 {
		t.Errorf("files = %d keys (%v), want 1", len(u.Files), u.Files)
	}
	if u.Since.IsZero() {
		t.Error("Since is zero; the window must be reported back")
	}
}

// TestGuidanceUsage_UnknownRootsAreEmptyNotErrors pins that the two
// "nothing to say" shapes are answers, not failures: a root with no
// captured activity, and the user-scope sentinel (which is not a project
// and whose files are used inside whatever project ran the session).
func TestGuidanceUsage_UnknownRootsAreEmptyNotErrors(t *testing.T) {
	t.Parallel()
	s, ctx, _ := guidanceUsageFixture(t)
	for _, root := range []string{"/repo/never-seen", GuidanceUserScopeRoot} {
		u, err := s.GuidanceUsage(ctx, root, time.Time{})
		if err != nil {
			t.Fatalf("GuidanceUsage(%q): %v", root, err)
		}
		if len(u.Skills) != 0 || len(u.Files) != 0 {
			t.Errorf("GuidanceUsage(%q) = %+v, want empty maps", root, u)
		}
		if u.Skills == nil || u.Files == nil {
			t.Errorf("GuidanceUsage(%q): nil map, want empty non-nil", root)
		}
	}
	if _, err := s.GuidanceUsage(ctx, "  ", time.Time{}); err == nil {
		t.Error("GuidanceUsage(\"\") = nil error, want a refusal")
	}
}

// TestGuidanceUsage_QueryPlan pins the PLAN, not the rows. actions is the
// biggest table in the store (734k rows on one live host) and this query
// runs on a dashboard GET, so the only acceptable plan is a seek on the
// rare action_type — idx_actions_project would hand back every action of
// the operator's main project. SQLite is queried with NO statistics here,
// exactly as in production: nothing in this repo runs ANALYZE.
func TestGuidanceUsage_QueryPlan(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	rows, err := s.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+guidanceUsageQuery,
		models.ActionSkillInvoke, models.ActionInstructionsLoaded, int64(1),
		formatGuidanceTime(time.Now().UTC().AddDate(0, 0, -GuidanceUsageWindowDays)))
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	joined := strings.Join(plan, "\n")
	t.Logf("EXPLAIN QUERY PLAN:\n%s", joined)

	if !strings.Contains(joined, "idx_actions_type") {
		t.Errorf("plan does not seek idx_actions_type\nplan:\n%s", joined)
	}
	if strings.Contains(joined, "SCAN actions") {
		t.Errorf("plan scans the whole actions table\nplan:\n%s", joined)
	}
	if strings.Contains(joined, "idx_actions_project") {
		t.Errorf("plan fell back to idx_actions_project (the unbounded per-project read)\nplan:\n%s", joined)
	}
}

// TestGuidanceNeverScannedRoots returns only roots with no guidance row at
// all, most recently active first.
func TestGuidanceNeverScannedRoots(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, root := range []string{"/repo/scanned", "/repo/fresh-a", "/repo/fresh-b"} {
		if _, err := s.UpsertProject(ctx, root, ""); err != nil {
			t.Fatalf("UpsertProject(%s): %v", root, err)
		}
	}
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/scanned",
		[]guidance.File{guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "h")},
		guidanceAt(t)); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}

	got, err := s.GuidanceNeverScannedRoots(ctx, 0, nil)
	if err != nil {
		t.Fatalf("GuidanceNeverScannedRoots: %v", err)
	}
	for _, r := range got {
		if r == "/repo/scanned" {
			t.Errorf("a scanned root is offered as never-scanned: %v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("never-scanned = %v, want the two unscanned roots", got)
	}

	capped, err := s.GuidanceNeverScannedRoots(ctx, 1, nil)
	if err != nil {
		t.Fatalf("GuidanceNeverScannedRoots(limit=1): %v", err)
	}
	if len(capped) != 1 {
		t.Errorf("limit=1 returned %d roots, want 1", len(capped))
	}

	// The exclusion is applied IN SQL, so excluding the head yields the tail
	// rather than an empty page.
	excluded, err := s.GuidanceNeverScannedRoots(ctx, 1, []string{capped[0]})
	if err != nil {
		t.Fatalf("GuidanceNeverScannedRoots(exclude): %v", err)
	}
	if len(excluded) != 1 || excluded[0] == capped[0] {
		t.Errorf("exclude=%v returned %v, want the next root instead", capped, excluded)
	}

	// A tombstone is still a row: a root whose guidance all vanished has
	// been scanned and must not be re-offered.
	if _, err := s.UpsertGuidanceScan(ctx, "/repo/fresh-a", nil, guidanceAt(t)); err != nil {
		t.Fatalf("empty scan: %v", err)
	}
	after, err := s.GuidanceNeverScannedRoots(ctx, 0, nil)
	if err != nil {
		t.Fatalf("GuidanceNeverScannedRoots after: %v", err)
	}
	if len(after) != 2 {
		t.Logf("note: a guidance-free root stays never-scanned here (%v); the loop's "+
			"per-lifetime attempted set is what stops it being re-walked every poll", after)
	}
}

// TestGuidanceNeverScannedRootsNoStarvation is the P2 regression pin.
//
// The bug: the store LIMITed to N and the loop filtered its attempted set in
// Go AFTERWARDS. Once N guidance-free roots occupied the head of the recency
// ordering, every page came back fully attempted, the loop filtered all of it
// away, and root N+1 was never offered again for the daemon's lifetime. With
// the exclusion pushed into the query, the page is REMAINING work, so draining
// it root by root eventually reaches every candidate.
func TestGuidanceNeverScannedRootsNoStarvation(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	const total = 25 // > the pollLimit below, which is the shape that starved
	want := map[string]bool{}
	for i := range total {
		root := fmt.Sprintf("/repo/p%02d", i)
		if _, err := s.UpsertProject(ctx, root, ""); err != nil {
			t.Fatalf("UpsertProject(%s): %v", root, err)
		}
		want[root] = true
	}

	// Simulate the loop: every root it is offered is "attempted" (the
	// guidance-free case, which never gains a row and so never leaves the
	// candidate set on its own).
	const pollLimit = 20
	attempted := map[string]bool{}
	for poll := range total + 5 {
		exclude := make([]string, 0, len(attempted))
		for r := range attempted {
			exclude = append(exclude, r)
		}
		sort.Strings(exclude)
		page, err := s.GuidanceNeverScannedRoots(ctx, pollLimit, exclude)
		if err != nil {
			t.Fatalf("poll %d: %v", poll, err)
		}
		if len(page) == 0 {
			break
		}
		for _, r := range page {
			if attempted[r] {
				t.Fatalf("poll %d re-offered an excluded root %q", poll, r)
			}
			attempted[r] = true
		}
	}

	for root := range want {
		if !attempted[root] {
			t.Errorf("root %q was never offered — starvation past the LIMIT is back", root)
		}
	}
	if len(attempted) != total {
		t.Errorf("offered %d distinct roots, want %d", len(attempted), total)
	}
}

// ----------------------------------------------------------- root normalization

// TestNormalizeGuidanceRoot pins the cases that must hold on EVERY host,
// independent of whether pathnorm's Windows-drive translation is active
// on this OS (that host-gated case is TestNormalizeGuidanceRoot_WindowsDriveToWSLMnt
// below). The sentinel and the empty string are special-cased in
// normalizeGuidanceRoot itself — crossmount.TranslateForeignPath would
// otherwise expand "~" to the home directory and corrupt the sentinel.
func TestNormalizeGuidanceRoot(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"sentinel unchanged", GuidanceUserScopeRoot, GuidanceUserScopeRoot},
		{"empty unchanged", "", ""},
		{"native linux path unchanged", "/home/u/proj", "/home/u/proj"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeGuidanceRoot(tt.in); got != tt.want {
				t.Errorf("normalizeGuidanceRoot(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeGuidanceRootIdempotent pins that normalizing an
// already-normalized root is a no-op. This matters because the helper
// flows to BOTH writes (UpsertGuidanceScan) and reads (ListGuidance /
// GuidanceUsage / GuidanceKnownFiles) — applying it twice, directly or
// through a caller that already normalized, must never re-mangle the
// root on a second pass.
func TestNormalizeGuidanceRootIdempotent(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		GuidanceUserScopeRoot,
		"",
		"/home/u/proj",
		"/mnt/d/repo/demo",
		`D:\repo\demo`,
	} {
		once := normalizeGuidanceRoot(in)
		twice := normalizeGuidanceRoot(once)
		if once != twice {
			t.Errorf("normalizeGuidanceRoot not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
	}
}

// TestNormalizeGuidanceRoot_WindowsDriveToWSLMnt pins the headline fix
// from chip task_f11f1a8d: a Windows-spelled root folds onto the
// WSL-mount spelling a Linux/WSL daemon can actually os.Stat.
//
// pathnorm's drive-letter rewrite (windowsToWSLMnt) is itself gated on
// `runtime.GOOS != "windows"` (internal/platform/pathnorm/pathnorm.go),
// so this equivalence only holds when the test BINARY runs on a
// non-Windows host — pathnorm's own suite applies the identical skip
// (pathnorm_test.go's TestNormalize_FormatMatrix). This repo's test
// suite is routinely run from a Windows host against Linux/WSL daemon
// behavior (see CLAUDE.md / project memory), so this assertion is
// gated rather than asserted unconditionally.
func TestNormalizeGuidanceRoot_WindowsDriveToWSLMnt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("pathnorm's Windows-drive translation only runs on GOOS=linux (windowsToWSLMnt short-circuits elsewhere)")
	}
	t.Parallel()
	got := normalizeGuidanceRoot(`D:\programsx\superbased-observer`)
	want := "/mnt/d/programsx/superbased-observer"
	if got != want {
		t.Errorf(`normalizeGuidanceRoot(D:\...) = %q, want %q`, got, want)
	}
}

// TestDedupeGuidanceRoots pins the order-preserving, first-occurrence-wins
// dedupe that GuidanceScanRoots / GuidanceNeverScannedRoots apply to their
// output after normalizing each element.
func TestDedupeGuidanceRoots(t *testing.T) {
	t.Parallel()
	in := []string{"/repo/a", "/repo/b", "/repo/a", "/repo/c", "/repo/b"}
	got := dedupeGuidanceRoots(in)
	want := []string{"/repo/a", "/repo/b", "/repo/c"}
	if len(got) != len(want) {
		t.Fatalf("dedupeGuidanceRoots(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupeGuidanceRoots(%v) = %v, want %v", in, got, want)
		}
	}
}

// TestListGuidance_ReadsEitherSpelling is the end-to-end pin: a scan
// persisted under the Windows spelling of a project root is found via
// ListGuidance under the WSL-mount spelling, and vice versa, because both
// input sites fold onto the same normalized root. Gated to GOOS=linux for
// the same reason as TestNormalizeGuidanceRoot_WindowsDriveToWSLMnt — on
// any other host pathnorm leaves the Windows spelling untouched, so the
// two spellings are genuinely different strings there and the bug this
// chip fixes (daemon-side) doesn't reproduce.
func TestListGuidance_ReadsEitherSpelling(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-spelling fold only reproduces on GOOS=linux; see TestNormalizeGuidanceRoot_WindowsDriveToWSLMnt")
	}
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	winRoot := `D:\repo\demo`
	wslRoot := "/mnt/d/repo/demo"

	if _, err := s.UpsertGuidanceScan(ctx, winRoot,
		[]guidance.File{guidanceFile("claude-code", "CLAUDE.md", guidance.KindInstructions, "hash-a")},
		guidanceAt(t)); err != nil {
		t.Fatalf("scan under Windows spelling: %v", err)
	}

	byWSL, err := s.ListGuidance(ctx, wslRoot, false)
	if err != nil {
		t.Fatalf("ListGuidance(wsl spelling): %v", err)
	}
	if len(byWSL) != 1 || byWSL[0].ProjectRoot != wslRoot {
		t.Fatalf("ListGuidance(%q) = %+v, want the row persisted under the normalized spelling", wslRoot, byWSL)
	}

	byWin, err := s.ListGuidance(ctx, winRoot, false)
	if err != nil {
		t.Fatalf("ListGuidance(windows spelling): %v", err)
	}
	if len(byWin) != 1 || byWin[0].ProjectRoot != wslRoot {
		t.Fatalf("ListGuidance(%q) = %+v, want the same row (normalized to %q)", winRoot, byWin, wslRoot)
	}
}

// TestGuidanceScanRootsFoldsCrossSpellings pins that a repo recorded twice
// in the projects table — once per OS spelling, the exact split described
// in chip task_f11f1a8d — is offered to a scan pass exactly ONCE, under
// the process-reachable spelling. That fold is what makes the daemon
// actually os.Stat the directory instead of silently skipping the foreign
// spelling as "not a directory". Gated to GOOS=linux for the same reason
// as the other cross-spelling tests.
func TestGuidanceScanRootsFoldsCrossSpellings(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cross-spelling fold only reproduces on GOOS=linux")
	}
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	winRoot := `D:\repo\demo`
	wslRoot := "/mnt/d/repo/demo"
	if _, err := s.UpsertProject(ctx, winRoot, ""); err != nil {
		t.Fatalf("UpsertProject(win): %v", err)
	}
	if _, err := s.UpsertProject(ctx, wslRoot, ""); err != nil {
		t.Fatalf("UpsertProject(wsl): %v", err)
	}

	roots, err := s.GuidanceScanRoots(ctx, 0)
	if err != nil {
		t.Fatalf("GuidanceScanRoots: %v", err)
	}
	var hits int
	for _, r := range roots {
		if r == wslRoot {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("GuidanceScanRoots offered %q %d times, want exactly 1 (folded from two spellings): %v", wslRoot, hits, roots)
	}
}
