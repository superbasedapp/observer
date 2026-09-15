package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestManagedBudgetLaunchRejectsUnboundOrStaleExplicitNone proves that a
// legacy or differently-enrolled cache row cannot turn a managed hard-budget
// launch into an apparently unbudgeted direct vendor process.
func TestManagedBudgetLaunchRejectsUnboundOrStaleExplicitNone(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		encode func(t *testing.T, doc orgcontract.BudgetPolicyDoc) string
	}{
		{
			name: "legacy unbound row",
			encode: func(t *testing.T, doc orgcontract.BudgetPolicyDoc) string {
				raw, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			},
		},
		{
			name: "stale enrollment binding",
			encode: func(t *testing.T, doc orgcontract.BudgetPolicyDoc) string {
				raw, err := json.Marshal(struct {
					Format   int                         `json:"format"`
					Binding  string                      `json:"binding"`
					Document orgcontract.BudgetPolicyDoc `json:"document"`
				}{Format: 1, Binding: "old-enrollment-epoch", Document: doc})
				if err != nil {
					t.Fatal(err)
				}
				return string(raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, false, "enforce")
			ctx := context.Background()
			database, err := db.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatalf("reopen database: %v", err)
			}
			doc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{
				Version: 7, ResolvedScope: "none",
			}}
			if _, err := database.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 7, etag = '"legacy"', org_key_fingerprint = 'legacy-key',
       body_json = ?, fetched_at = '2026-09-14T01:00:00Z'
 WHERE id = 1`, tc.encode(t, doc)); err != nil {
				_ = database.Close()
				t.Fatalf("seed cache: %v", err)
			}
			if err := database.Close(); err != nil {
				t.Fatalf("close database: %v", err)
			}

			err = enforceBudgetControlledLaunch(ctx, cfgPath, "muse",
				budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
			if !errors.Is(err, errBudgetLaunchUncontrolled) {
				t.Fatalf("direct launch error = %v, want managed hard-budget refusal", err)
			}
		})
	}
}

// TestManagedBudgetStatusRejectsUnboundCache keeps the CLI's managed posture
// honest as well: an explicit-none body from a legacy or stale enrollment is
// unverified, so it cannot be rewritten into the reassuring cached label.
func TestManagedBudgetStatusRejectsUnboundCache(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		stale bool
	}{
		{name: "legacy unbound"},
		{name: "stale binding", stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			_, dbPath := writeManagedBudgetLaunchFixture(t, false, "enforce")
			database, err := db.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatalf("reopen database: %v", err)
			}
			doc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{
				Version: 8, ResolvedScope: "none",
			}}
			var body any = doc
			if tc.stale {
				body = struct {
					Format   int                         `json:"format"`
					Binding  string                      `json:"binding"`
					Document orgcontract.BudgetPolicyDoc `json:"document"`
				}{Format: 1, Binding: "old-enrollment-epoch", Document: doc}
			}
			raw, err := json.Marshal(body)
			if err != nil {
				_ = database.Close()
				t.Fatalf("marshal cache: %v", err)
			}
			if _, err := database.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 8, etag = '"legacy"', org_key_fingerprint = 'legacy-key',
       body_json = ?, fetched_at = '2026-09-14T01:00:00Z'
 WHERE id = 1`, string(raw)); err != nil {
				_ = database.Close()
				t.Fatalf("seed cache: %v", err)
			}

			cfg := config.Config{Guard: config.GuardConfig{
				Enabled: true, Mode: "enforce",
				Budget: config.GuardBudgetConfig{FromOrg: true},
			}}
			line := guardBudgetPostureLineWithGrant(ctx, cfg, database, true)
			if err := database.Close(); err != nil {
				t.Fatalf("close database: %v", err)
			}
			for _, want := range []string{
				"budget_required=true",
				"fetch_state=" + orgcontract.BudgetFetchUnverified,
			} {
				if !strings.Contains(line, want) {
					t.Errorf("managed status line missing %q: %s", want, line)
				}
			}
			if strings.Contains(line, "fetch_state=cached") {
				t.Fatalf("managed stale cache was reported as cached: %s", line)
			}
		})
	}
}
