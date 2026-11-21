package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/predict"
)

// withProjectionBudgets adds a node [guard.budget] cap and an org window the
// daemon wrote in its own zone to the predict corpus, so the projection has
// two budgets in force.
func withProjectionBudgets(t *testing.T, cfgPath string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(raw, []byte("\n[guard.budget]\ndaily_usd = 50.0\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	cp, ok := predict.CalendarBounds("monthly", "America/Los_Angeles", time.Now())
	if !ok {
		t.Fatal("calendar")
	}
	dbPath := filepath.Join(filepath.Dir(cfgPath), "o.db")
	if err := budgetwarnfile.Write(budgetwarnfile.StatusPath(dbPath), budgetwarnfile.File{
		WrittenAt: time.Now(),
		Windows: []budgetwarnfile.Window{{
			Window: "monthly", Unit: "tokens", Period: cp.Key, Timezone: "America/Los_Angeles",
			Cap: 1_000_000, Spent: 900_000, Scope: "team:core", Enforcement: "hard",
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func runPredictCmd(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newPredictCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("predict: %v\n%s", err, out.String())
	}
	return out.String()
}

// TestPredictCmd_ProjectionJSON pins the additive --json shape: the existing
// keys stay, "projection" carries the API's limits / budgets arrays.
func TestPredictCmd_ProjectionJSON(t *testing.T) {
	cfgPath := seedPredictCorpus(t)
	withProjectionBudgets(t, cfgPath)
	out := runPredictCmd(t, "sCLI", "--config", cfgPath, "--json")
	var got struct {
		SessionID  string          `json:"session_id"`
		Estimate   json.RawMessage `json:"estimate"`
		Projection *struct {
			Limits  []predict.Projection `json:"limits"`
			Budgets []predict.Projection `json:"budgets"`
		} `json:"projection"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if got.SessionID != "sCLI" || len(got.Estimate) == 0 || got.Projection == nil {
		t.Fatalf("existing keys and projection: %s", out)
	}
	if got.Projection.Limits == nil || len(got.Projection.Budgets) != 2 {
		t.Fatalf("limits %v budgets %+v", got.Projection.Limits, got.Projection.Budgets)
	}
	org := got.Projection.Budgets[0]
	if org.Origin != "org" || org.Unit != "tokens" || org.LeftTokens == nil || *org.LeftTokens != 100_000 {
		t.Errorf("org budget %+v", org)
	}
	for _, n := range org.Notes {
		if n == predict.NoteTimezoneAssumed {
			t.Errorf("a zoned org window must not carry the UTC assumption: %v", org.Notes)
		}
	}
	if got.Projection.Budgets[1].Origin != "node" || got.Projection.Budgets[1].Key != "daily" {
		t.Errorf("node budget %+v", got.Projection.Budgets[1])
	}
}

// TestPredictCmd_ProjectionTable pins the human block: a line per budget,
// tightest first, with the facts the projection carries.
func TestPredictCmd_ProjectionTable(t *testing.T) {
	cfgPath := seedPredictCorpus(t)
	t.Run("no budget", func(t *testing.T) {
		out := runPredictCmd(t, "sCLI", "--config", cfgPath)
		if !strings.Contains(out, "Run-out projection:") || !strings.Contains(out, "no limit reading and no budget in force.") {
			t.Errorf("missing the empty projection block:\n%s", out)
		}
	})
	t.Run("budgets", func(t *testing.T) {
		withProjectionBudgets(t, cfgPath)
		out := runPredictCmd(t, "sCLI", "--config", cfgPath)
		at := strings.Index(out, "Run-out projection:")
		if at < 0 {
			t.Fatalf("no projection block:\n%s", out)
		}
		block := out[at:]
		org := strings.Index(block, "org monthly budget (team:core, hard): 90% used, 10% left · 100.0K tokens left · resets in ")
		node := strings.Index(block, "node daily budget (soft): 0% used, 100% left · $50.00 left · resets in ")
		if org < 0 || node < 0 || org > node {
			t.Fatalf("budget lines missing or out of order:\n%s", block)
		}
		if !strings.Contains(block, "notes: the spend includes your other machines") {
			t.Errorf("org note missing:\n%s", block)
		}
		if strings.Contains(block, "UTC is assumed") {
			t.Errorf("a zoned org window must not say UTC is assumed:\n%s", block)
		}
	})
}
