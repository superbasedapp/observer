package diag

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestCheckHookLiveness drives the doctor row over a real store: OK on an
// empty node, then a warning naming the silent desktop surface of Claude
// Code once a CLI session's hooks are proven live and a desktop session
// shows none, with the route the hooks saw and no env value.
func TestCheckHookLiveness(t *testing.T) {
	database := diagTestDB(t)
	ctx := context.Background()
	home := t.TempDir()
	now := time.Now().UTC()
	if c := checkHookLiveness(ctx, database, home, home, nil, now, nil); c.Name != "hooks.liveness" || c.Status != StatusOK {
		t.Fatalf("empty node: %+v", c)
	}
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?)`, now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	started := now.Add(-time.Hour)
	for _, s := range []struct{ id, surface string }{{"cli-1", "cli"}, {"desk-1", "desktop"}} {
		if _, err := database.Exec(`INSERT INTO sessions (id, project_id, tool, started_at, surface) VALUES (?, 1, ?, ?, ?)`,
			s.id, models.ToolClaudeCode, started.Format(time.RFC3339Nano), s.surface); err != nil {
			t.Fatal(err)
		}
	}
	st := store.New(database)
	if err := st.UpsertHookActivity(ctx, []store.HookActivityRow{
		{
			Tool: models.ToolClaudeCode, Event: "PreToolUse", SessionID: "cli-1", Count: 3, FirstAt: started.Add(-time.Minute), LastAt: started.Add(time.Minute),
			EnvClasses: map[string]string{"ANTHROPIC_BASE_URL": hookliveness.ClassLoopback},
		},
		{Tool: models.ToolClaudeCode, Event: "Stop", Count: 1, FirstAt: started, LastAt: started},
	}); err != nil {
		t.Fatal(err)
	}
	c := checkHookLiveness(ctx, database, home, home, nil, now, nil)
	if c.Status != StatusWarn || !strings.Contains(c.Message, "1 tool(s) captured sessions whose hooks did not fire") {
		t.Fatalf("check %+v", c)
	}
	joined := strings.Join(c.Details, "\n")
	for _, want := range []string{
		"claude-code: hooks_silent_on_surface",
		"silent surface(s): desktop",
		"e.g. session desk-1",
		"1 call(s) without a session id",
		"seen: PreToolUse",
		"route seen by hooks: ANTHROPIC_BASE_URL loopback=1",
		"never proves a session's hooks ran",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("details missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "8820") || strings.Contains(joined, "http") {
		t.Errorf("details carry an env value:\n%s", joined)
	}
	tools, err := HookSilentTools(ctx, st, now)
	if err != nil || len(tools) != 1 || tools[0] != models.ToolClaudeCode {
		t.Fatalf("HookSilentTools = %v err %v", tools, err)
	}
}

// TestHookLivenessReasonsCoverEveryReportedRule: every rule a verdict can
// render has its sentence.
func TestHookLivenessReasonsCoverEveryReportedRule(t *testing.T) {
	for _, r := range []hookliveness.Rule{
		hookliveness.RuleDisabledSwitch, hookliveness.RuleNotYetObserved, hookliveness.RuleNeverSeen,
		hookliveness.RuleNoSessionKey, hookliveness.RuleUnattributedOnly, hookliveness.RuleSessionIDsUnjoined,
		hookliveness.RuleSilentOnSurface, hookliveness.RuleSilentSomeSessions, hookliveness.RuleOK,
	} {
		if hookLivenessReasons[r] == "" {
			t.Errorf("rule %s has no rendered reason", r)
		}
	}
}
