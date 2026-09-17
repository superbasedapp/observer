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
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedRoutingSimCorpus writes a temp config + DB holding one session
// with three opus read-only proxy turns, and returns the config path.
func seedRoutingSimCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("[observer]\ndb_path = %q\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	projectID, err := st.UpsertProject(ctx, "/repo/sim", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	now := time.Now().UTC()
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sess-sim", ProjectID: projectID, Tool: "claude-code", StartedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(-90+i*30) * time.Minute)
		if _, err := st.InsertAPITurn(ctx, models.APITurn{
			SessionID: "sess-sim", ProjectID: projectID, Provider: "anthropic",
			Model: "claude-opus-4-8", RequestID: fmt.Sprintf("req-%d", i),
			Timestamp:   ts,
			InputTokens: 50_000, OutputTokens: 2_000,
			MessageCount: 6, ToolUseCount: 3,
			TotalResponseMS: 1500, HTTPStatus: 200, CostUSD: 0.30,
		}); err != nil {
			t.Fatalf("InsertAPITurn %d: %v", i, err)
		}
		if _, err := st.InsertActions(ctx, []models.Action{{
			SessionID: "sess-sim", ProjectID: projectID, Tool: "claude-code",
			Timestamp: ts.Add(-time.Minute), ActionType: models.ActionReadFile,
			Target: "main.go", Success: true,
			SourceFile: "sim.jsonl", SourceEventID: fmt.Sprintf("a-%d", i),
		}}); err != nil {
			t.Fatalf("InsertActions %d: %v", i, err)
		}
	}
	return cfgPath
}

// runRoutingSimulate executes the subcommand and decodes its JSON.
func runRoutingSimulate(t *testing.T, cfgPath, policy string) routing.SimReport {
	t.Helper()
	cmd := newRoutingCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"simulate", "--config", cfgPath, "--policy", policy, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("routing simulate: %v\n%s", err, out.String())
	}
	var rep routing.SimReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out.String())
	}
	return rep
}

// TestRoutingSimulate_EndToEnd replays a seeded corpus under "frugal"
// and pins the headline counters: every opus read-only turn outside the
// stickiness floor would reroute to the haiku representative, with
// positive savings and quality-risk flags (no parity evidence at n=3).
func TestRoutingSimulate_EndToEnd(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)
	rep := runRoutingSimulate(t, cfgPath, "frugal")

	if rep.PolicyName != "frugal" || rep.EstimateVersion == "" || rep.PolicyHash == "" {
		t.Errorf("attribution = %+v", rep)
	}
	if rep.TurnsEvaluated != 3 {
		t.Errorf("evaluated = %d, want 3", rep.TurnsEvaluated)
	}
	// Turn 1 reroutes; turns 2–3 hold (frugal stickiness floor 3).
	if rep.WouldReroute != 1 {
		t.Errorf("would reroute = %d, want 1; %+v", rep.WouldReroute, rep)
	}
	if rep.EstSavingsUSD <= 0 {
		t.Errorf("savings = %v, want positive", rep.EstSavingsUSD)
	}
	if len(rep.ByMove) != 1 || rep.ByMove[0].To != "claude-haiku-4-5" {
		t.Errorf("moves = %+v", rep.ByMove)
	}
	// n=3 is far below the parity floor — the reroute must be flagged.
	if rep.QualityRiskFlags != 1 {
		t.Errorf("quality risks = %d, want 1", rep.QualityRiskFlags)
	}
}

// TestRoutingSimulate_Deterministic pins §R18.1: two runs over the same
// data + policy yield identical reports.
func TestRoutingSimulate_Deterministic(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)
	first := runRoutingSimulate(t, cfgPath, "value")
	second := runRoutingSimulate(t, cfgPath, "value")
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic replay:\n%s\nvs\n%s", a, b)
	}
}

// TestRoutingSimulate_UnknownPolicy pins the error path.
func TestRoutingSimulate_UnknownPolicy(t *testing.T) {
	cfgPath := seedRoutingSimCorpus(t)
	cmd := newRoutingCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"simulate", "--config", cfgPath, "--policy", "nonsense"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown policy template")
	}
}
