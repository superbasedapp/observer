package dashboard

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSkillHistoryLeavesExistingEndpointsByteIdentical pins S10-SKILLS
// ruling R6: the skills-history arc adds its own endpoint
// (/api/project/{id}/skills) and seven node-local tables, and NOTHING
// already served changes shape or content because of them. It renders
// GET /api/project/{id} and GET /api/projects/guidance for a project
// that carries a skill in its guidance inventory, then plants rows in all
// seven skill-history tables (migration 135) and renders both again: the
// bodies must be byte-identical. A regression that threads skill history
// into the detail summary or the guidance inventory fails here.
func TestSkillHistoryLeavesExistingEndpointsByteIdentical(t *testing.T) {
	s, root, projectID, _, _ := seedProjectsFixture(t)
	ctx := context.Background()
	st := store.New(s.opts.DB)

	scanned := time.Now().UTC().Add(-time.Hour)
	if _, err := st.UpsertGuidanceScan(ctx, root, []guidance.File{{
		Tool: "claude-code", Kind: guidance.KindSkill, Scope: guidance.ScopeProject,
		RelPath: ".claude/skills/deploy/SKILL.md", AbsPath: root + "/.claude/skills/deploy/SKILL.md",
		Name: "deploy", Description: "ship it", SizeBytes: 12, ModTime: scanned,
		ContentHash: "aaaa",
	}}, scanned); err != nil {
		t.Fatalf("UpsertGuidanceScan: %v", err)
	}

	render := func(path string) []byte {
		t.Helper()
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d body=%s", path, rr.Code, rr.Body.String())
		}
		return append([]byte(nil), rr.Body.Bytes()...)
	}
	detailPath := "/api/project/" + itoa64(projectID)
	guidancePath := "/api/projects/guidance?root=" + url.QueryEscape(root)

	beforeDetail := render(detailPath)
	beforeGuidance := render(guidancePath)

	const ts = "2026-09-23T00:00:00.000000000Z"
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO skill_snapshot_members (set_hash, scope, rel_path, dir_key, name, state, content_hash, blob_oid)
		  VALUES ('set1', 'project', '.claude/skills/deploy/SKILL.md', '.claude/skills/deploy', 'deploy', 'present', 'aaaa', 'b1')`, nil},
		{`INSERT INTO session_skill_snapshots (session_id, tool, event, source, observed_at, set_hash)
		  VALUES ('sess1', 'claude-code', 'session_start', 'startup', ?, 'set1')`, []any{ts}},
		{`INSERT INTO project_head_moves (project_id, moved_at, sha, kind) VALUES (?, ?, 'sha1', 'commit')`, []any{projectID, ts}},
		{`INSERT INTO project_skill_trees (project_id, sha, state, resolved_at) VALUES (?, 'sha1', 'ok', ?)`, []any{projectID, ts}},
		{`INSERT INTO project_skill_tree_files (project_id, sha, rel_path, mode, blob_oid)
		  VALUES (?, 'sha1', '.claude/skills/deploy/SKILL.md', '100644', 'b1')`, []any{projectID}},
		{`INSERT INTO project_skill_worktree (project_id, rel_path, state) VALUES (?, '.claude/skills/deploy/SKILL.md', 'modified')`, []any{projectID}},
		{`INSERT INTO project_skill_scan (project_id, last_scan_at, reflog_since) VALUES (?, ?, ?)`, []any{projectID, ts, ts}},
	} {
		if _, err := s.opts.DB.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed skill history: %v\n%s", err, q.sql)
		}
	}

	if after := render(detailPath); !bytes.Equal(beforeDetail, after) {
		t.Errorf("GET %s changed after seeding skill history:\nbefore=%s\nafter =%s", detailPath, beforeDetail, after)
	}
	// usage_since is "now minus the usage window", recomputed per request, so
	// two renders a second apart differ there without anything having changed
	// (CI flake 2026-09-30: 10:27:36 vs 10:27:37). Compare everything else.
	if after := render(guidancePath); !bytes.Equal(stripUsageSince(beforeGuidance), stripUsageSince(after)) {
		t.Errorf("GET %s changed after seeding skill history:\nbefore=%s\nafter =%s", guidancePath, beforeGuidance, after)
	}
}

// usageSinceField matches the clock-derived usage_since member of a guidance body.
var usageSinceField = regexp.MustCompile(`"usage_since":"[^"]*"`)

// stripUsageSince blanks usage_since so a byte comparison ignores the clock.
func stripUsageSince(b []byte) []byte {
	return usageSinceField.ReplaceAll(b, []byte(`"usage_since":""`))
}
