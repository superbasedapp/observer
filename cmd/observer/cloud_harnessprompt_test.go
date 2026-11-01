//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// harnessFixturePrompts is the T-966 fixture: the shapes the first live cloud
// test uploaded as the developer's words (a Claude Code background task
// notification carrying a local path and a request id, another agent's
// hand-back, a system reminder) around two real prompts.
var harnessFixturePrompts = []string{
	"<task-notification>\n<task-id>b7d1f0</task-id>\n<output-file>/home/dev/private-client/tasks/b7d1f0.output</output-file>\n<status>completed</status>\n<summary>request_id req_01HZX9SECRET finished</summary>\n</task-notification>",
	"Refactor the retry loop so it backs off exponentially.",
	"<agent-message from=\"lead\">\n[lane hand-back] see /home/dev/private-client/notes.md\n</agent-message>",
	"<system-reminder>The user opened /home/dev/private-client/main.go</system-reminder>",
	"Now add a test for the jitter.",
}

// seedHarnessPromptSession inserts one personal session whose user_prompt rows
// are harnessFixturePrompts, plus one edit, so the mix has a non-prompt kind.
func seedHarnessPromptSession(t *testing.T, dbPath, sessionID string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-10-23T00:00:00Z') RETURNING id`,
		"/tmp/cloud-harness/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-sonnet-5', '2026-10-23T10:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	insert := func(i int, kind, target string) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', 1, ?, 'claude-code:hook', ?)`,
			sessionID, projectID, base.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano),
			kind, target, sessionID+"-"+string(rune('a'+i))); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
	for i, p := range harnessFixturePrompts {
		insert(i, "user_prompt", p)
	}
	insert(len(harnessFixturePrompts), "edit_file", "/tmp/cloud-harness/retry.go")
}

// TestCloudEnvelopeSkipsHarnessPrompts pins T-966 end to end: a message the
// harness wrote on the user's channel is never excerpted as the developer's
// words, never counted as a user_prompt in the activity mix, and never sampled
// as one; its local paths and request id never reach the upload bytes.
func TestCloudEnvelopeSkipsHarnessPrompts(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedHarnessPromptSession(t, dbPath, "harness1")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	for _, purpose := range []cloudcontract.Purpose{
		cloudcontract.PurposeContextEnrichment,
		cloudcontract.PurposeStructuralInsights,
	} {
		t.Run(string(purpose), func(t *testing.T) {
			res, err := buildCloudEnvelope(context.Background(), st, "harness1", purpose, nil)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			env := res.Envelope
			if len(env.Context) == 0 || env.Context[0].Source != cloudevidence.SourceFirstUserPrompt ||
				!strings.HasPrefix(env.Context[0].Text, "Refactor the retry loop") {
				t.Fatalf("first excerpt = %+v, want the first REAL prompt", env.Context)
			}
			for _, c := range env.Context {
				if c.Source == cloudevidence.SourceFirstUserPrompt || c.Source == cloudevidence.SourceUserPrompt {
					if !strings.HasPrefix(c.Text, "Refactor") && !strings.HasPrefix(c.Text, "Now add a test") {
						t.Errorf("a harness message was excerpted as the user's words: %q", c.Text)
					}
				}
			}
			body := string(res.Bytes)
			for _, forbidden := range []string{
				"task-notification", "agent-message", "system-reminder",
				"req_01HZX9SECRET", "private-client",
			} {
				if strings.Contains(body, forbidden) {
					t.Errorf("upload bytes carry %q", forbidden)
				}
			}
			mix := map[string]int{}
			for _, e := range env.ActivityMix {
				mix[e.Key] = e.Count
			}
			want := map[string]int{"user_prompt": 2, "task_event": 1, "agent_message": 1, "prompt_context": 1, "edit_file": 1}
			for k, v := range want {
				if mix[k] != v {
					t.Errorf("activity_mix[%s] = %d, want %d (mix %+v)", k, mix[k], v, env.ActivityMix)
				}
			}
			prompts := 0
			for _, a := range env.Actions {
				if a.Kind == "user_prompt" {
					prompts++
				}
			}
			if prompts != 2 {
				t.Errorf("sampled %d user_prompt actions, want the 2 real ones", prompts)
			}
		})
	}
}
