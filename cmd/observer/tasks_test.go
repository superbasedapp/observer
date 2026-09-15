package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// seedTasksCorpus writes a temp DB with one claude-code session carrying
// a TodoWrite lifecycle (one completed task, one still pending), runs
// BackfillTaskItems to populate task_items/task_transitions, and
// returns a config.toml path pointing at it.
func seedTasksCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "o.db")
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/tasks-cli', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('sTasksCLI', 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	insertAction := func(offsetMin int, input, srcEventID string) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_name, raw_tool_input, source_file, source_event_id)
			 VALUES ('sTasksCLI', ?, ?, 'todo_update', 'claude-code', 'TodoWrite', ?, 'f.jsonl', ?)`,
			projectID, base.Add(time.Duration(offsetMin)*time.Minute).Format(time.RFC3339Nano), input, srcEventID); err != nil {
			t.Fatal(err)
		}
	}
	insertAction(0, `{"todos":[{"content":"Fix the bug","status":"pending"}]}`, "e0")
	insertAction(1, `{"todos":[{"content":"Fix the bug","status":"in_progress"}]}`, "e1")
	insertAction(5, `{"todos":[{"content":"Fix the bug","status":"completed"}]}`, "e2")
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
		 VALUES ('sTasksCLI', ?, 'claude-code', 'claude-opus-4-8', 1000, 500, 'watcher', 'f.jsonl', 'tok0')`,
		base.Add(2*time.Minute).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	st := store.New(database)
	if _, err := st.BackfillTaskItems(ctx, 0); err != nil {
		t.Fatalf("BackfillTaskItems: %v", err)
	}
	database.Close()

	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = "+fmt.Sprintf("%q", dbPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestTasksCmd_SessionJSON(t *testing.T) {
	cfgPath := seedTasksCorpus(t)

	cmd := newTasksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sTasksCLI", "--config", cfgPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v — output: %s", err, out.String())
	}

	var rep taskreport.SessionTaskReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v — body %s", err, out.String())
	}
	if !rep.HasTasks || len(rep.Items) != 1 {
		t.Fatalf("rep = %+v", rep)
	}
	if rep.Items[0].Status != "completed" {
		t.Errorf("item status = %q, want completed", rep.Items[0].Status)
	}
}

func TestTasksCmd_SessionTable(t *testing.T) {
	cfgPath := seedTasksCorpus(t)

	cmd := newTasksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sTasksCLI", "--config", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v — output: %s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("Fix the bug")) {
		t.Errorf("table output missing task content, got: %s", out.String())
	}
}

func TestTasksCmd_Rollup(t *testing.T) {
	cfgPath := seedTasksCorpus(t)

	cmd := newTasksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--rollup", "--config", cfgPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v — output: %s", err, out.String())
	}

	var rep taskreport.TaskRollup
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v — body %s", err, out.String())
	}
	if rep.SessionsWithTasks != 1 {
		t.Errorf("sessions_with_tasks = %d, want 1", rep.SessionsWithTasks)
	}
	if len(rep.ByTool) != 1 || rep.ByTool[0].Tool != "claude-code" {
		t.Errorf("by_tool = %+v", rep.ByTool)
	}
}

func TestTasksCmd_DisabledByConfig(t *testing.T) {
	cfgPath := seedTasksCorpus(t)
	// Overwrite with an explicit [tasks].enabled = false — seedTasksCorpus's
	// config.toml has no [tasks] section at all, which partial-merges to
	// the Enabled=true default (CLAUDE.md's "default-on" posture), so this
	// needs an explicit override to exercise the disabled path.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(data, []byte("\n[tasks]\nenabled = false\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newTasksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sTasksCLI", "--config", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v — output: %s", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("disabled")) {
		t.Errorf("expected a '[tasks] disabled' message, got: %s", out.String())
	}
}

func TestTasksCmd_MissingSessionIDWithoutRollup(t *testing.T) {
	cfgPath := seedTasksCorpus(t)

	cmd := newTasksCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--config", cfgPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when no session id is given and --rollup is not set")
	}
}
