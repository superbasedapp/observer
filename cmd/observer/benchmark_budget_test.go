package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBenchmarkManagedBudgetRefusesEveryDriverAndScorer(t *testing.T) {
	t.Parallel()
	configPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	for name, driver := range budgetControlledBenchmarkDrivers("missing-observer", "isolated.db", configPath) {
		t.Run(name, func(t *testing.T) {
			_, err := driver.Drive(t.Context(), DriveRequest{ProxyURL: "http://127.0.0.1:9999"})
			if !errors.Is(err, errBudgetLaunchUncontrolled) {
				t.Fatalf("driver was reached before managed admission: %v", err)
			}
		})
	}
	scorer := budgetControlledBenchmarkScorer{configPath: configPath}
	if _, err := scorer.Score(context.Background(), scoreInput{}); !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("judge was reached before managed admission: %v", err)
	}
}

func TestBenchmarkManagedBudgetRefusesBeforeEphemeralDaemon(t *testing.T) {
	t.Parallel()
	configPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")
	specPath := filepath.Join(t.TempDir(), "spec.toml")
	spec := `name = "budget-admission"
repeats = 1
[budget]
max_total_usd = 100.0
max_cell_usd = 1.0
[[tasks]]
id = "one"
prompt = "Do not run"
repo = "https://example.invalid/repo"
[tasks.success]
scorer = "contains_all"
values = ["OK"]
[[configs]]
id = "claude"
harness = "claude-code"
model = "claude-sonnet-4"
`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newBenchmarkRunCmd()
	cmd.SetArgs([]string{"--config", configPath, "--confirm-spend", "--ephemeral-daemon", specPath})
	if err := cmd.Execute(); !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("managed benchmark did not refuse before isolated setup: %v", err)
	}
}
