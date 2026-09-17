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
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// seedPredictCorpus writes a temp DB with one cached claude-code session
// (token rows + user_prompt boundaries) and a config.toml pointing at it.
// Returns the config path.
func seedPredictCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "o.db")
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-cli', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('sCLI', 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	for i, off := range []int{0, 30, 60} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id)
			 VALUES ('sCLI', ?, ?, 'user_prompt', 'claude-code', 'f', ?)`,
			projectID, base.Add(time.Duration(off)*time.Minute).Format(time.RFC3339Nano),
			fmt.Sprintf("up-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	turns := []struct {
		min, out int
	}{{2, 100}, {5, 800}, {9, 1600}, {32, 400}, {40, 1200}, {62, 300}, {70, 900}}
	for i, tr := range turns {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, source, reliability, source_file, source_event_id)
			 VALUES ('sCLI', ?, 'claude-code', 'claude-opus-4-8', 200000, ?, 200000, 'proxy', 'high', 'f', ?)`,
			base.Add(time.Duration(tr.min)*time.Minute).Format(time.RFC3339Nano), tr.out, fmt.Sprintf("tu-%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = "+fmt.Sprintf("%q", dbPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestPredictCmd_JSON(t *testing.T) {
	cfgPath := seedPredictCorpus(t)

	cmd := newPredictCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"sCLI", "--config", cfgPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("predict: %v\n%s", err, out.String())
	}
	var got struct {
		Estimate struct {
			HasEstimate bool   `json:"has_estimate"`
			TurnsTier   string `json:"turns_tier"`
			Mid         struct {
				MessageUSD float64 `json:"message_usd"`
			} `json:"mid"`
		} `json:"estimate"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out.String())
	}
	if !got.Estimate.HasEstimate {
		t.Fatal("expected an estimate")
	}
	if got.Estimate.TurnsTier != "observed" {
		t.Errorf("turns tier = %q, want observed", got.Estimate.TurnsTier)
	}
	if got.Estimate.Mid.MessageUSD <= 0 {
		t.Errorf("mid message cost should be positive, got %f", got.Estimate.Mid.MessageUSD)
	}
}

func TestPredictCmd_NoModelErrors(t *testing.T) {
	cfgPath := seedPredictCorpus(t)
	// A session id that doesn't exist → load error.
	cmd := newPredictCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"nonexistent", "--config", cfgPath})
	if err := cmd.Execute(); err == nil {
		t.Errorf("expected an error for a nonexistent session, got: %s", out.String())
	}
}
