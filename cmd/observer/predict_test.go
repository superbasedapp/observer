package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// seedPredictCorpusCursor mirrors seedPredictCorpus but for a "cursor"
// session — internal/integration's registry carries an AUDITED negative
// finding for cursor (no local usage-limit signal can ever exist), so
// `observer predict` must render "not visible for cursor: <reason>"
// instead of the ladder's misleading "route through the proxy" hint.
func seedPredictCorpusCursor(t *testing.T) string {
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
		`INSERT INTO projects (root_path, created_at) VALUES ('/tmp/pred-cursor', '2026-06-09T00:00:00Z') RETURNING id`).
		Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at)
		 VALUES ('sCursor', 'cursor', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z')`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, source, reliability, source_file, source_event_id)
		 VALUES ('sCursor', '2026-06-09T00:05:00Z', 'cursor', 'claude-opus-4-8', 1200, 300, 0, 'jsonl', 'approximate', 'r.jsonl', 'tk:sCursor:L1')`); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = "+fmt.Sprintf("%q", dbPath)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestPredictCmd_NoSourceTool(t *testing.T) {
	cfgPath := seedPredictCorpusCursor(t)

	t.Run("json", func(t *testing.T) {
		cmd := newPredictCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"sCursor", "--config", cfgPath, "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("predict: %v\n%s", err, out.String())
		}
		var got struct {
			Limit struct {
				NoSource   bool   `json:"no_source"`
				SourceNote string `json:"source_note"`
				NeedsProxy bool   `json:"needs_proxy"`
			} `json:"limit"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v\n%s", err, out.String())
		}
		if !got.Limit.NoSource {
			t.Error("limit.no_source = false, want true")
		}
		if got.Limit.SourceNote == "" {
			t.Error("limit.source_note is empty")
		}
		if got.Limit.NeedsProxy {
			t.Error("limit.needs_proxy = true at the same time as no_source — must never both be true")
		}
	})

	t.Run("table", func(t *testing.T) {
		cmd := newPredictCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"sCursor", "--config", cfgPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("predict: %v\n%s", err, out.String())
		}
		text := out.String()
		if !strings.Contains(text, "not visible for cursor:") {
			t.Errorf("table output missing the honest not-visible line, got:\n%s", text)
		}
		if strings.Contains(text, "route this client through the observer proxy") {
			t.Errorf("table output still renders the misleading proxy hint for cursor, got:\n%s", text)
		}
	})
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
