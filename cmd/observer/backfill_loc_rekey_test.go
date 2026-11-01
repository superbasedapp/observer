package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestBackfillLOCRekeyCommand (SHR-8, lane SHR-FOLLOWUPS): `observer
// backfill --loc-rekey` is a dry run by default (counts, writes nothing),
// --apply moves the row, a second --apply moves nothing, and --dry-run is
// refused (the pass has its own dry run).
func TestBackfillLOCRekeyCommand(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	ctx := context.Background()
	gitRun := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	repo, _ := filepath.EvalSymlinks(t.TempDir())
	gitRun(repo, "init")
	gitRun(repo, "checkout", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.go"), []byte("package a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(repo, "add", "-A")
	gitRun(repo, "commit", "-m", "init")
	wt := filepath.Join(repo, ".worktrees", "x")
	gitRun(repo, "worktree", "add", "-b", "x", wt)

	root := t.TempDir()
	dbPath := filepath.Join(root, "obs.db")
	cfgPath := filepath.Join(root, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("[observer]\ndb_path = %q\n", dbPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(wt, "a.go")
	ev := models.ToolEvent{
		SessionID: "s1", ProjectRoot: repo, Target: path, ActionType: models.ActionEditFile,
		RawToolInput: fmt.Sprintf(`{"file_path":%q,"old_string":"a","new_string":"b"}`, path),
		RawToolName:  "Edit", Tool: models.ToolClaudeCode, SourceFile: "/tmp/s.jsonl", SourceEventID: "e1",
		Timestamp: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Success: true,
	}
	if _, err := store.New(database).Ingest(ctx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	legacy := loc.PathHash(repo, path)
	if _, err := database.ExecContext(ctx, `UPDATE file_changes SET file_path_hash = ?`, legacy); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	run := func(args ...string) (string, error) {
		var out strings.Builder
		cmd := newBackfillCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--config", cfgPath))
		err := cmd.Execute()
		return out.String(), err
	}
	report := func(args ...string) store.RekeyLOCTable {
		t.Helper()
		out, err := run(append(args, "--loc-rekey", "--json")...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		var r struct {
			LOCRekey store.RekeyLOCResult `json:"loc_rekey"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return r.LOCRekey.Tables["file_changes"]
	}
	if got := report(); got.Rekeyed != 1 || got.AlreadyKeyed != 0 {
		t.Fatalf("dry run: %+v", got)
	}
	if got := report(); got.Rekeyed != 1 {
		t.Fatalf("the dry run wrote: %+v", got)
	}
	if got := report("--apply"); got.Rekeyed != 1 {
		t.Fatalf("apply: %+v", got)
	}
	if got := report("--apply"); got.Rekeyed != 0 || got.AlreadyKeyed != 1 {
		t.Fatalf("second apply: %+v", got)
	}
	if out, err := run("--loc-rekey"); err != nil || !strings.Contains(out, "dry run") || !strings.Contains(out, "file_changes: 0 rekeyed, 1 already keyed") {
		t.Fatalf("text report: %v\n%s", err, out)
	}
	if _, err := run("--loc-rekey", "--dry-run"); err == nil || !strings.Contains(err.Error(), "--apply") {
		t.Fatalf("--dry-run with --loc-rekey: %v", err)
	}
}
