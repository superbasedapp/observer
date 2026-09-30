package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// storedTokenDims is the projection the reconcile tests compare.
type storedTokenDims struct {
	rel                        string
	in, out, cr, cc, reasoning int64
	cc1h                       sql.NullInt64
	cost                       float64
	model                      string
}

func loadTokenDims(t *testing.T, database *sql.DB, src, eventID string) storedTokenDims {
	t.Helper()
	var d storedTokenDims
	if err := database.QueryRow(`SELECT COALESCE(reliability,''), input_tokens, output_tokens, cache_read_tokens,
		cache_creation_tokens, reasoning_tokens, cache_creation_1h_tokens, estimated_cost_usd, COALESCE(model,'')
		FROM token_usage WHERE source_file = ? AND source_event_id = ?`, src, eventID).
		Scan(&d.rel, &d.in, &d.out, &d.cr, &d.cc, &d.reasoning, &d.cc1h, &d.cost, &d.model); err != nil {
		t.Fatalf("load %s/%s: %v", src, eventID, err)
	}
	return d
}

// seedReconcileSession creates the project + session token rows reference.
func seedReconcileSession(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo/reconcile", "")
	if err != nil {
		t.Fatal(err)
	}
	sess := models.Session{ID: id, ProjectID: pid, Tool: models.ToolCrush, StartedAt: time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)}
	if err := s.UpsertSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
}

// TestTokenReliabilityReconcileTable pins every row of tokenReliabilityRules
// through the REAL InsertTokenEvents upsert against a real node DB, plus the
// regressions the MAX-reliant adapters depend on (they all re-emit one
// constant tier, so row 1 must leave them exactly as before).
func TestTokenReliabilityReconcileTable(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ev := func(tool, rel string, in, out, cr, cc int64, cc1h, reasoning int64, cost float64) models.TokenEvent {
		return models.TokenEvent{
			SessionID: "s1", Tool: tool, Model: "m-1", Timestamp: now,
			InputTokens: in, OutputTokens: out, CacheReadTokens: cr, CacheCreationTokens: cc,
			CacheCreation1hTokens: cc1h, ReasoningTokens: reasoning, EstimatedCostUSD: cost,
			Source: models.TokenSourceJSONL, Reliability: rel,
		}
	}
	const (
		appr = models.ReliabilityApproximate
		acc  = models.ReliabilityAccurate
		unr  = models.ReliabilityUnreliable
		unk  = models.ReliabilityUnknown
	)
	cases := []struct {
		name     string
		rule     string // the table row expected to decide (for the name check)
		emits    []models.TokenEvent
		want     storedTokenDims
		wantCC1h bool // cache_creation_1h expected non-NULL
	}{
		{
			name: "row1 same measured tier: MAX counts, tier kept", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, appr, 100, 10, 0, 0, 0, 0, 0.01),
				ev(models.ToolCrush, appr, 150, 5, 0, 0, 0, 0, 0.02),
			},
			want: storedTokenDims{rel: appr, in: 150, out: 10, cost: 0.02, model: "m-1"},
		},
		{
			name: "row1 same unknown tier: counts stay zero, cost grows", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0.01),
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0.03),
			},
			want: storedTokenDims{rel: unk, cost: 0.03, model: "m-1"},
		},
		{
			name: "row2 unknown promoted to approximate: counts lifted", rule: "unknown promoted by a measured tier: adopt, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0.002),
				ev(models.ToolCrush, appr, 800, 7, 0, 0, 0, 0, 0.003),
			},
			want: storedTokenDims{rel: appr, in: 800, out: 7, cost: 0.003, model: "m-1"},
		},
		{
			name: "row2 unknown promoted to accurate", rule: "unknown promoted by a measured tier: adopt, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0),
				ev(models.ToolCrush, acc, 50, 60, 70, 80, 9, 11, 0.5),
			},
			want: storedTokenDims{rel: acc, in: 50, out: 60, cr: 70, cc: 80, cc1h: sql.NullInt64{Int64: 9, Valid: true}, reasoning: 11, cost: 0.5, model: "m-1"}, wantCC1h: true,
		},
		{
			name: "row3 approximate demoted by all-zero unknown: counts replaced", rule: "measured demoted by an all-zero unknown restatement: adopt, replace counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, appr, 21749, 5, 3, 4, 2, 6, 0.054),
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0.1),
			},
			want: storedTokenDims{rel: unk, cost: 0.1, model: "m-1"},
		},
		{
			name: "row3 demotion keeps the larger stored cost (cost rule unchanged)", rule: "measured demoted by an all-zero unknown restatement: adopt, replace counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, acc, 10, 10, 0, 0, 0, 0, 0.5),
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0.1),
			},
			want: storedTokenDims{rel: unk, cost: 0.5, model: "m-1"},
		},
		{
			name: "row3 demotion wins over the copilot input carve-out", rule: "measured demoted by an all-zero unknown restatement: adopt, replace counts",
			emits: []models.TokenEvent{
				ev(models.ToolCopilotCLI, appr, 1000, 20, 0, 0, 0, 0, 0),
				ev(models.ToolCopilotCLI, unk, 0, 0, 0, 0, 0, 0, 0),
			},
			want: storedTokenDims{rel: unk, model: "m-1"},
		},
		{
			name: "row4 two different measured tiers: first tier stands, MAX", rule: "any other change: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, appr, 100, 10, 0, 0, 0, 0, 0),
				ev(models.ToolCrush, unr, 90, 20, 0, 0, 0, 0, 0),
			},
			want: storedTokenDims{rel: appr, in: 100, out: 20, model: "m-1"},
		},
		{
			name: "row4 unknown emission that still carries counts changes nothing", rule: "any other change: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, appr, 100, 10, 0, 0, 0, 0, 0),
				ev(models.ToolCrush, unk, 5, 0, 0, 0, 0, 0, 0),
			},
			want: storedTokenDims{rel: appr, in: 100, out: 10, model: "m-1"},
		},
		{
			name: "row4 empty stored tier is not demoted", rule: "any other change: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCrush, "", 100, 10, 0, 0, 0, 0, 0),
				ev(models.ToolCrush, unk, 0, 0, 0, 0, 0, 0, 0),
			},
			want: storedTokenDims{rel: "", in: 100, out: 10, model: "m-1"},
		},
		// --- regressions: the MAX-reliant adapters (row 1) ---
		{
			name: "regression primeagent child fold: second emit larger -> MAX", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolPrimeAgent, appr, 1200, 300, 5000, 100, 0, 0, 0),
				ev(models.ToolPrimeAgent, appr, 1900, 520, 8000, 160, 0, 0, 0),
			},
			want: storedTokenDims{rel: appr, in: 1900, out: 520, cr: 8000, cc: 160, model: "m-1"},
		},
		{
			name: "regression session-cumulative row grows, a partial re-parse cannot lower it", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolGoose, appr, 1000, 100, 0, 0, 0, 0, 0.01),
				ev(models.ToolGoose, appr, 2500, 400, 0, 0, 0, 0, 0.04),
				ev(models.ToolGoose, appr, 800, 90, 0, 0, 0, 0, 0.005),
			},
			want: storedTokenDims{rel: appr, in: 2500, out: 400, cost: 0.04, model: "m-1"},
		},
		{
			name: "regression openclaw duplicate emit is a no-op", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolOpenClaw, acc, 300, 40, 900, 0, 0, 0, 0),
				ev(models.ToolOpenClaw, acc, 300, 40, 900, 0, 0, 0, 0),
			},
			want: storedTokenDims{rel: acc, in: 300, out: 40, cr: 900, model: "m-1"},
		},
		{
			name: "regression copilot input carve-out still corrects input DOWN", rule: "same tier: keep, MAX counts",
			emits: []models.TokenEvent{
				ev(models.ToolCopilotCLI, appr, 1000, 20, 0, 0, 0, 0, 0),
				ev(models.ToolCopilotCLI, appr, 600, 20, 0, 400, 0, 0, 0),
			},
			want: storedTokenDims{rel: appr, in: 600, out: 20, cc: 400, model: "m-1"},
		},
	}
	ruleNames := map[string]bool{}
	for _, r := range tokenReliabilityRules {
		ruleNames[r.name] = true
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !ruleNames[tc.rule] {
				t.Fatalf("case names rule %q, which is not a row of tokenReliabilityRules", tc.rule)
			}
			ctx := context.Background()
			s, database := newTestStore(t)
			seedReconcileSession(t, s, "s1")
			src := "/src/reconcile-" + string(rune('a'+i))
			for j, e := range tc.emits {
				e.SourceFile, e.SourceEventID = src, "evt-1"
				if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{e}); err != nil {
					t.Fatalf("emit %d: %v", j, err)
				}
			}
			got := loadTokenDims(t, database, src, "evt-1")
			if got.cc1h.Valid != tc.wantCC1h {
				t.Errorf("cache_creation_1h valid = %v, want %v", got.cc1h.Valid, tc.wantCC1h)
			}
			want := tc.want
			want.cc1h = got.cc1h
			if tc.wantCC1h && got.cc1h != tc.want.cc1h {
				t.Errorf("cache_creation_1h = %+v, want %+v", got.cc1h, tc.want.cc1h)
			}
			if got != want {
				t.Errorf("stored = %+v\nwant     %+v", got, want)
			}
		})
	}
}

// TestTokenReliabilityTableShape pins the table's order and that its last
// row is the catch-all, and that the rendered statement carries no
// unfilled placeholder.
func TestTokenReliabilityTableShape(t *testing.T) {
	want := []string{
		"same tier: keep, MAX counts",
		"unknown promoted by a measured tier: adopt, MAX counts",
		"measured demoted by an all-zero unknown restatement: adopt, replace counts",
		"any other change: keep, MAX counts",
	}
	if len(tokenReliabilityRules) != len(want) {
		t.Fatalf("table has %d rows, want %d", len(tokenReliabilityRules), len(want))
	}
	for i, r := range tokenReliabilityRules {
		if r.name != want[i] {
			t.Errorf("row %d = %q, want %q", i, r.name, want[i])
		}
	}
	if last := tokenReliabilityRules[len(tokenReliabilityRules)-1]; last.when != "1" {
		t.Errorf("last row must be the catch-all, got when=%q", last.when)
	}
	out := renderTokenUpsertSQL("a {{replace_counts}} b {{reliability}}")
	if strings.Contains(out, "{{") {
		t.Errorf("unfilled placeholder in %q", out)
	}
}

// TestTokenReliabilityDemotionRequeuesForOrg pins the org-propagation half:
// an in-place demotion changes reliability + counts, which agent migration
// 140's trigger watches, so an already-shipped row is queued for re-send
// (the org applies a newer node revision wholesale, replacing counts).
func TestTokenReliabilityDemotionRequeuesForOrg(t *testing.T) {
	ctx := context.Background()
	s, database := newTestStore(t)
	seedReconcileSession(t, s, "s")
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	e := models.TokenEvent{
		SourceFile: "/src/q", SourceEventID: "tokens:s", SessionID: "s", Tool: models.ToolCrush, Model: "m",
		Timestamp: now, InputTokens: 900, OutputTokens: 9, EstimatedCostUSD: 0.01,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
	}
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{e}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO schema_meta (key, value) VALUES ('org_push_floor_token_usage', '0')`); err != nil {
		t.Fatal(err)
	}
	queued := func() int {
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'token_usage'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Same tier, identical emit: nothing changes, nothing queued.
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{e}); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 0 {
		t.Fatalf("identical re-emit queued %d rows, want 0", n)
	}
	e.InputTokens, e.OutputTokens, e.EstimatedCostUSD, e.Reliability = 0, 0, 0.02, models.ReliabilityUnknown
	if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{e}); err != nil {
		t.Fatal(err)
	}
	if n := queued(); n != 1 {
		t.Fatalf("demotion queued %d rows, want 1", n)
	}
	if got := loadTokenDims(t, database, "/src/q", "tokens:s"); got.rel != models.ReliabilityUnknown || got.in != 0 || got.out != 0 || got.cost != 0.02 {
		t.Errorf("stored = %+v, want unknown 0/0 $0.02", got)
	}
}
