package main

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHookVerdictRecordsTheGateProject is GRANT-20 through the real Claude
// Code PreToolUse receiver: the session started in a parent folder (its
// project is that folder), the call runs in a repository below it with a
// cwd-only payload. The guard_events row the hook writes carries the
// repository the gate matched grants on, and the request drafted from that
// row is scoped on it, so the grant it yields matches the next call.
func TestHookVerdictRecordsTheGateProject(t *testing.T) {
	root, cwd := projectHookRepo(t, "https://github.com/acme/widget.git")
	cp, dbPath := approvalHookNode(t)
	ctx := context.Background()
	d, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st := store.New(d)
	parent := filepath.Dir(root)
	pid, err := st.UpsertProject(ctx, parent, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	body := `{"session_id":"s1","cwd":` + strconv.Quote(filepath.ToSlash(cwd)) + `,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf ~/"}}`
	h := newFailureHarness(t, hookFailurePlan{})
	var errBuf strings.Builder
	handleClaudeCodePreTool(strings.NewReader(body), &h.stdout, &errBuf, "claude-code:pre-tool", cp)
	if out := h.stdout.String(); !toolGateBlockWords.MatchString(out) {
		t.Fatalf("reply %q (stderr %s), want a block", out, errBuf.String())
	}

	var id int64
	var hash, rawRoot string
	if err := d.QueryRowContext(ctx, `SELECT id, COALESCE(project_root_hash,''), COALESCE(project_root,'') FROM guard_events WHERE session_id = 's1' ORDER BY id DESC LIMIT 1`).
		Scan(&id, &hash, &rawRoot); err != nil {
		t.Fatalf("no guard_events row from the hook: %v (stderr %s)", err, errBuf.String())
	}
	if hash != guard.HashProjectRoot(root) || rawRoot != root {
		t.Errorf("row project = (%q, %q), want the repository %q (the session's project is %q)", hash, rawRoot, root, parent)
	}
	draft, ok, err := st.GuardEventRequestDraft(ctx, id)
	if err != nil || !ok {
		t.Fatalf("draft: ok=%v err=%v", ok, err)
	}
	if draft.Payload.ProjectRootHash != guard.HashProjectRoot(root) || draft.Context.ProjectRoot != root {
		t.Errorf("draft project = (%q, %q), want the repository %q", draft.Payload.ProjectRootHash, draft.Context.ProjectRoot, root)
	}
}
