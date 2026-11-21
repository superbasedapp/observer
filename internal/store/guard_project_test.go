package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestResolveDraftProject pins draftProjectRules (GRANT-20), one row per case.
func TestResolveDraftProject(t *testing.T) {
	t.Parallel()
	session := draftProject{hash: "h-session", root: "/home/u"}
	cases := []struct {
		name    string
		event   draftProject
		session draftProject
		want    draftProject
	}{
		{name: "event recorded the gate's project", event: draftProject{hash: "h-repo", root: "/home/u/repo"}, session: session, want: draftProject{hash: "h-repo", root: "/home/u/repo"}},
		{name: "event hash without its root never borrows the session's root", event: draftProject{hash: "h-repo"}, session: session, want: draftProject{hash: "h-repo"}},
		{name: "pre-253 row falls back to the session", session: session, want: session},
		{name: "a root alone is not a recorded project", event: draftProject{root: "/home/u/repo"}, session: session, want: session},
		{name: "nothing known", want: draftProject{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveDraftProject(tc.event, tc.session); got != tc.want {
				t.Errorf("resolveDraftProject = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestGuardEventRequestDraftUsesTheGateProject is the GRANT-20 fix end to
// end through the one writer: a session that started in /home/u ran a call
// in /home/u/repo. The verdict persisted through PersistGuardVerdicts carries
// the project the gate matched, the request drafted from the row (by event
// and by rule) is scoped on it, a row with no recorded project (an older row)
// still drafts on the session's project, the chain still verifies, and
// neither column reaches the org push.
func TestGuardEventRequestDraftUsesTheGateProject(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	const sessionRoot, repo = "/home/u", "/home/u/repo"
	pid, err := s.UpsertProject(ctx, sessionRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sNew", "sOld"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', '2026-11-13T00:00:00Z')`, id, pid); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)
	verdict := func(session string, gp guard.GrantProject) guard.ActionVerdict {
		return guard.ActionVerdict{
			Input:        guard.ActionInput{SessionID: session, Tool: "claude-code", ActionType: "run_command", Target: "git commit -m x", Timestamp: at},
			Kind:         policy.KindShellExec,
			Category:     "vcs",
			Verdict:      policy.Verdict{RuleID: "S-793", Decision: policy.DecisionAsk, Severity: policy.SeverityHigh, Source: policy.SourceBuiltin},
			Enforced:     true,
			GrantProject: gp,
		}
	}
	gate := guard.GrantProject{Root: repo, Hash: guard.HashProjectRoot(repo)}
	if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{verdict("sNew", gate), verdict("sOld", guard.GrantProject{})}); err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	rows, err := s.LoadRecentGuardEvents(ctx, at.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		ids[r.SessionID] = r.ID
		want := ""
		if r.SessionID == "sNew" {
			want = gate.Hash
		}
		if r.ProjectRootHash != want {
			t.Errorf("%s loaded project_root_hash = %q, want %q", r.SessionID, r.ProjectRootHash, want)
		}
	}
	var nulls int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_events WHERE session_id = 'sOld' AND project_root_hash IS NULL AND project_root IS NULL`).Scan(&nulls); err != nil || nulls != 1 {
		t.Errorf("the unrecorded row stores NULLs: count %d err %v", nulls, err)
	}

	sessionHash := guard.HashProjectRoot(sessionRoot)
	cases := []struct {
		name               string
		draft              func() (string, string, error)
		wantHash, wantRoot string
	}{
		{name: "by event: the gate's project", draft: draftByEvent(ctx, s, ids["sNew"]), wantHash: gate.Hash, wantRoot: repo},
		{name: "by event: an unrecorded row takes the session's project", draft: draftByEvent(ctx, s, ids["sOld"]), wantHash: sessionHash, wantRoot: sessionRoot},
		{name: "by rule: the newest event's gate project", draft: draftByRule(ctx, s, "S-793", "sNew"), wantHash: gate.Hash, wantRoot: repo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, root, err := tc.draft()
			if err != nil {
				t.Fatal(err)
			}
			if h != tc.wantHash || root != tc.wantRoot {
				t.Errorf("draft project = (%q, %q), want (%q, %q)", h, root, tc.wantHash, tc.wantRoot)
			}
		})
	}

	if rep, err := s.VerifyGuardChain(ctx); err != nil || !rep.OK {
		t.Errorf("chain after the new columns: %+v, %v", rep, err)
	}
	for _, share := range []ShareOptions{{}, {FullContent: true}} {
		batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@acme.example", share, ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(batch.GuardEvents)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), repo) || strings.Contains(string(raw), gate.Hash) {
			t.Errorf("guard_events push (full_content=%v) carries the node-local project columns: %s", share.FullContent, raw)
		}
	}
}

func draftByEvent(ctx context.Context, s *Store, id int64) func() (string, string, error) {
	return func() (string, string, error) {
		d, ok, err := s.GuardEventRequestDraft(ctx, id)
		if err != nil || !ok {
			return "", "", err
		}
		return d.Payload.ProjectRootHash, d.Context.ProjectRoot, nil
	}
}

func draftByRule(ctx context.Context, s *Store, rule, session string) func() (string, string, error) {
	return func() (string, string, error) {
		d, err := s.GuardRuleRequestDraft(ctx, rule, session)
		if err != nil {
			return "", "", err
		}
		return d.Payload.ProjectRootHash, d.Context.ProjectRoot, nil
	}
}
