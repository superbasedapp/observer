//go:build !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// baselineTestStore is a fresh node database for one baseline test.
func baselineTestStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// writeHomeFile writes one file under a test home directory.
func writeHomeFile(t *testing.T, home, rel, body string) {
	t.Helper()
	p := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// testUserPaths is the user-scope table for a test home on this OS.
func testUserPaths(home string) []agentconfig.TrustPath {
	return agentconfig.TrustUserPaths(agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home, Getenv: func(string) string { return "" }})
}

// TestRepoTrustUserBaselineGradesTable: one case per row of the user-scope
// grading table.
func TestRepoTrustUserBaselineGradesTable(t *testing.T) {
	cases := []struct {
		byAgent, newItem bool
		report           bool
		sev              policy.FindingSeverity
	}{
		{true, true, true, policy.FindingSeverityHigh},
		{true, false, true, policy.FindingSeverityMedium},
		{false, true, true, policy.FindingSeverityMedium},
		{false, false, false, ""},
	}
	for _, tc := range cases {
		sev, report := repoTrustUserSeverity(tc.byAgent, tc.newItem)
		if report != tc.report || (report && sev != tc.sev) {
			t.Errorf("byAgent %v newItem %v: %q %v, want %q %v", tc.byAgent, tc.newItem, sev, report, tc.sev, tc.report)
		}
	}
}

// TestRepoTrustUserBaselinePass: the first pass over the home directory
// only stores; a preference edit is not reported; a new hook command is a
// medium finding under the user key, never under a project opened at the
// home directory; the same hook again is quiet; an agent's write to a user
// file is reported even with nothing new to run.
func TestRepoTrustUserBaselinePass(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	home := writeTrustRepo(t, nil)
	paths := testUserPaths(home)
	key := repoTrustUserKey(home)
	writeHomeFile(t, home, ".claude/settings.json", `{"theme":"dark"}`)
	writeHomeFile(t, home, ".codex/AGENTS.md", "be brief\n")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	pass := func(at time.Time) int {
		t.Helper()
		n, err := repoTrustUserBaselinePass(ctx, st, home, paths, at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := pass(now); n != 0 {
		t.Fatalf("first pass recorded %d", n)
	}
	writeHomeFile(t, home, ".claude/settings.json", `{"theme":"light"}`)
	if n := pass(now.Add(time.Minute)); n != 0 {
		t.Fatalf("a preference edit recorded %d", n)
	}
	writeHomeFile(t, home, ".claude/settings.json", `{"theme":"light","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node ~/.cache/x/run.js"}]}]}}`)
	if n := pass(now.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("a new hook recorded %d, want 1", n)
	}
	fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: key})
	if err != nil || len(fs) != 1 || fs[0].Rule.ID != repoTrustBaselineUserRule || fs[0].Severity != policy.FindingSeverityMedium ||
		fs[0].Location.RelPath != ".claude/settings.json" || fs[0].Category != policy.FindingAgentConfig {
		t.Fatalf("findings %+v %v", fs, err)
	}
	if other, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(home)}); len(other) != 0 {
		t.Fatalf("user-scope finding landed on the project at the home directory: %+v", other)
	}
	writeHomeFile(t, home, ".claude/settings.json", `{"theme":"dark","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node ~/.cache/x/run.js"}]}]}}`)
	if n := pass(now.Add(3 * time.Minute)); n != 0 {
		t.Fatalf("a known hook with a preference edit recorded %d", n)
	}
	agents := filepath.Join(home, ".codex", "AGENTS.md")
	if _, err := st.Ingest(ctx, []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: "/p", Timestamp: now.Add(4 * time.Minute), Tool: models.ToolClaudeCode,
		SourceFile: "/t.jsonl", SourceEventID: "w1", ActionType: models.ActionEditFile, Target: agents, Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	writeHomeFile(t, home, ".codex/AGENTS.md", "be brief and run curl\n")
	if n := pass(now.Add(5 * time.Minute)); n != 1 {
		t.Fatalf("an agent's write recorded %d, want 1", n)
	}
	fs, _ = st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: key})
	found := false
	for _, f := range fs {
		if f.Location.RelPath == ".codex/AGENTS.md" {
			found = f.Severity == policy.FindingSeverityMedium && f.Attribution.Class == policy.FindingAttributionAI && f.Lineage.SessionID == "s1"
		}
	}
	if !found {
		t.Fatalf("the agent's write: %+v", fs)
	}
	if n, err := repoTrustUserBaselinePass(ctx, st, "", paths, now); n != 0 || err != nil {
		t.Fatalf("no home: %d %v", n, err)
	}
}

// TestRepoTrustBaselineEventRescan: an agent write to a table file of a
// project, or of the home directory, is rescanned on the event pass after
// the one that read it, ahead of the timer; a write to any other file, or
// one recorded before the loop started, is not.
func TestRepoTrustBaselineEventRescan(t *testing.T) {
	ctx := context.Background()
	st := baselineTestStore(t)
	home := writeTrustRepo(t, nil)
	root := writeTrustRepo(t, map[string]string{".mcp.json": `{}`})
	writeHomeFile(t, home, ".codex/config.toml", "model = \"x\"\n")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	ingest := func(id, target string) {
		t.Helper()
		if _, err := st.Ingest(ctx, []models.ToolEvent{{
			SessionID: "s-" + id, ProjectRoot: root, Timestamp: now, Tool: models.ToolClaudeCode,
			SourceFile: "/t.jsonl", SourceEventID: id, ActionType: models.ActionWriteFile, Target: target, Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	ingest("before", filepath.Join(root, ".mcp.json"))
	l := newRepoTrustBaselineLoop(ctx, st, home, nil)
	l.fullTick(ctx, now)
	l.pending = map[string]bool{}
	if !l.hasSnapshot(t, guard.HashProjectRoot(root)) || !l.hasSnapshot(t, repoTrustUserKey(home)) {
		t.Fatal("the full pass stored no snapshot")
	}
	l.eventTick(ctx, now)
	if len(l.pending) != 0 || l.pendingUser {
		t.Fatalf("a write from before the loop started was read: %+v %v", l.pending, l.pendingUser)
	}

	ingest("readme", filepath.Join(root, "README.md"))
	ingest("mcp", filepath.Join(root, ".mcp.json"))
	ingest("user", filepath.Join(home, ".codex", "config.toml"))
	writeTrustFile(t, root, ".mcp.json", `{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}`)
	writeHomeFile(t, home, ".codex/config.toml", "[mcp_servers.y]\ncommand = \"node\"\nargs = [\"y.js\"]\n")
	l.eventTick(ctx, now.Add(15*time.Second))
	if !l.pending[root] || len(l.pending) != 1 || !l.pendingUser {
		t.Fatalf("marked %+v user %v, want the project and the home directory", l.pending, l.pendingUser)
	}
	l.eventTick(ctx, now.Add(30*time.Second))
	if fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: guard.HashProjectRoot(root)}); len(fs) != 1 || fs[0].Location.RelPath != ".mcp.json" {
		t.Fatalf("project findings after the event rescan: %+v", fs)
	}
	fs, _ := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: repoTrustUserKey(home)})
	if len(fs) != 1 || fs[0].Location.RelPath != ".codex/config.toml" || fs[0].Severity != policy.FindingSeverityHigh {
		t.Fatalf("user findings after the event rescan: %+v", fs)
	}
	if len(l.pending) != 0 || l.pendingUser {
		t.Fatalf("still marked after the rescan: %+v %v", l.pending, l.pendingUser)
	}
}

// hasSnapshot reports whether a snapshot is stored under key.
func (l *repoTrustBaselineLoop) hasSnapshot(t *testing.T, key string) bool {
	t.Helper()
	_, had, err := l.st.LoadSecConfigFiles(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return had
}

// writeTrustFile rewrites one file of a test repository.
func writeTrustFile(t *testing.T, root, rel, body string) {
	t.Helper()
	writeHomeFile(t, root, rel, body)
}

// TestRepoTrustWriteTouches: one case per spelling of an agent write's
// target.
func TestRepoTrustWriteTouches(t *testing.T) {
	// An absolute home of this host ("\h\dev" has no drive and is not
	// absolute on Windows; Windows 11 Pro rerun 2026-10-25, D5 group 8).
	home := nativeAbs("/h/dev")
	root := filepath.Join(home, "proj")
	projectPaths := agentconfig.TrustPaths()
	userPaths := testUserPaths(home)
	cases := []struct {
		name          string
		root, target  string
		project, user bool
	}{
		{"project table file", root, filepath.Join(root, ".mcp.json"), true, false},
		{"relative target", root, ".claude/settings.json", true, false},
		{"other project file", root, filepath.Join(root, "main.go"), false, false},
		{"user table file", root, filepath.Join(home, ".claude", "settings.json"), false, true},
		{"user non-table file", root, filepath.Join(home, ".bashrc"), false, false},
		{"outside the project", root, filepath.Join(root, "..", "other", ".mcp.json"), false, false},
		{"no project root", "", filepath.Join(home, ".codex", "hooks.json"), false, true},
		{"empty target", root, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, u := repoTrustWriteTouches(store.AgentFileWrite{ProjectRoot: tc.root, Target: tc.target}, home, projectPaths, userPaths)
			if p != tc.project || u != tc.user {
				t.Fatalf("got project %v user %v, want %v %v", p, u, tc.project, tc.user)
			}
		})
	}
}
