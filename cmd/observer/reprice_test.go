package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/reprice"
	"github.com/marmutapp/superbased-observer/internal/repricesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestRepriceOptsResolve(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		o       repriceOpts
		want    repriceMode
		wantErr string
	}{
		{"default is a dry run", repriceOpts{}, repriceModePlan, ""},
		{"dry run with a window", repriceOpts{since: "30d", until: "2026-09-28", model: "m"}, repriceModePlan, ""},
		{"apply", repriceOpts{apply: true, since: "2026-09-01T00:00:00Z"}, repriceModeApply, ""},
		{"revert", repriceOpts{revert: 4}, repriceModeRevert, ""},
		{"list", repriceOpts{list: true}, repriceModeList, ""},
		{"apply and list", repriceOpts{apply: true, list: true}, 0, "mutually exclusive"},
		{"apply and revert", repriceOpts{apply: true, revert: 2}, 0, "mutually exclusive"},
		{"negative revert", repriceOpts{revert: -1}, 0, "positive run id"},
		{"revert with a window", repriceOpts{revert: 2, since: "7d"}, 0, "dry run or --apply only"},
		{"bad since", repriceOpts{since: "last week"}, 0, "not YYYY-MM-DD"},
		{"bad until", repriceOpts{apply: true, until: "2026-02-30"}, 0, "not YYYY-MM-DD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.o.resolve(now)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %v %v, want %v", got, err, tc.want)
			}
		})
	}
}

// TestRepriceCmdRejectsBadFlagsBeforeTouchingTheDB drives the cobra command
// itself: a conflicting flag set fails before any config or DB is opened (the
// config path points nowhere).
func TestRepriceCmdRejectsBadFlagsBeforeTouchingTheDB(t *testing.T) {
	for _, args := range [][]string{
		{"--apply", "--list"},
		{"--since", "yesterday"},
		{"--revert", "3", "--model", "m"},
	} {
		cmd := newRepriceCmd()
		cmd.SetArgs(append(args, "--config", filepath.Join(t.TempDir(), "missing", "config.toml")))
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil || !strings.HasPrefix(err.Error(), "observer reprice:") {
			t.Fatalf("%v: err %v", args, err)
		}
	}
}

func repriceTestDB(t *testing.T) (*sql.DB, *store.Store) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "reprice.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	pid, err := st.UpsertProject(ctx, "/tmp/reprice-cmd", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s1', ?, 'claude-code', '2026-01-01T00:00:00Z')`, pid); err != nil {
		t.Fatal(err)
	}
	return database, st
}

func insertReprTurn(t *testing.T, database *sql.DB, ts, model string, input int64, cost any) int64 {
	t.Helper()
	res, err := database.Exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd, source)
		VALUES ('s1', ?, 'anthropic', ?, ?, 0, ?, 'proxy')`, ts, model, input, cost)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func reprCost(t *testing.T, database *sql.DB, id int64) *float64 {
	t.Helper()
	var c sql.NullFloat64
	if err := database.QueryRow(`SELECT cost_usd FROM api_turns WHERE id = ?`, id).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if !c.Valid {
		return nil
	}
	return &c.Float64
}

// TestRepriceDatedPricesAcrossABoundary is the end-to-end correctness pin: a
// REAL cost engine carrying a dated org price history (cost.WithOrgRows +
// History, the org / feed rail's shape) prices each stored row at the rate in
// force at ITS OWN timestamp, through the real price adapter, service and
// store. A row before the first period has no rate and keeps its stored cost.
func TestRepriceDatedPricesAcrossABoundary(t *testing.T) {
	database, st := repriceTestDB(t)
	ctx := context.Background()
	period := func(from string, in float64) cost.OrgPrice {
		return cost.OrgPrice{
			Model: "zz-reprice", EffectiveFrom: from,
			Pricing: cost.Pricing{Input: in, Output: in * 2}, Set: cost.OrgPriceSet{Input: true, Output: true},
		}
	}
	p0, p1 := period("2026-01-01T00:00:00Z", 1), period("2026-06-01T00:00:00Z", 3)
	top := p1
	top.History = []cost.OrgPrice{p0, p1}
	e := cost.NewEngine(config.IntelligenceConfig{}, cost.WithOrgRows(func() (cost.OrgRows, bool) {
		return cost.OrgRows{Rows: []cost.OrgPrice{top}, Version: 7}, true
	}))
	if w := e.PricingWarnings(); len(w) != 0 {
		t.Fatalf("pricing warnings %v", w)
	}

	before := insertReprTurn(t, database, "2025-12-31T23:59:59Z", "zz-reprice", 1_000_000, 42.0)
	early := insertReprTurn(t, database, "2026-03-01T10:00:00Z", "zz-reprice", 1_000_000, 9.0)
	boundary := insertReprTurn(t, database, "2026-06-01T00:00:00Z", "zz-reprice", 1_000_000, 9.0)
	late := insertReprTurn(t, database, "2026-07-01T10:00:00Z", "zz-reprice", 1_000_000, nil)

	svc := repricesvc.New(st, enginePriceFunc(e), func(context.Context) repricesvc.PricingInfo {
		return repricesvc.PricingInfo{Source: repricesvc.PricingSourceOrg, Version: e.OrgPricingVersion()}
	}, nil)
	plan, err := svc.Plan(ctx, repricesvc.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Changed != 3 || plan.Summary.Filled != 1 || plan.Summary.Skipped[reprice.ReasonNoPrice] != 1 {
		t.Fatalf("plan %+v", plan.Summary)
	}
	run, err := svc.Apply(ctx, repricesvc.Request{Actor: "t", Digest: plan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if run.PricingSource != "org" || run.PricingVersion != 7 || run.Changed != 3 {
		t.Fatalf("run %+v", run)
	}
	for _, tc := range []struct {
		name string
		id   int64
		want float64
	}{
		{"before the history keeps its stored cost", before, 42.0},
		{"first period", early, 1.0},
		{"the boundary instant is the second period", boundary, 3.0},
		{"second period, filled from unpriced", late, 3.0},
	} {
		got := reprCost(t, database, tc.id)
		if got == nil || math.Abs(*got-tc.want) > 1e-9 {
			t.Errorf("%s: cost %v, want %v", tc.name, got, tc.want)
		}
	}
	// The same engine answers "unchanged" for every row now: idempotent.
	again, err := svc.Plan(ctx, repricesvc.Filter{})
	if err != nil || again.Summary.Changed != 0 {
		t.Fatalf("second plan %+v %v", again.Summary, err)
	}
}

func TestEnginePriceFuncFastTierAndWebSearch(t *testing.T) {
	e := cost.NewEngine(config.IntelligenceConfig{})
	price := enginePriceFunc(e)
	at := time.Now().UTC()
	std := price("claude-opus-5", at, reprice.Tokens{Input: 1_000_000})
	fast := price("claude-opus-5", at, reprice.Tokens{Input: 1_000_000, Fast: true})
	if !std.OK || !std.FastTier || math.Abs(fast.USD-2*std.USD) > 1e-9 {
		t.Fatalf("std %+v fast %+v", std, fast)
	}
	ws := price("claude-opus-5", at, reprice.Tokens{Input: 1_000_000, WebSearchRequests: 10})
	if ws.USD <= std.USD {
		t.Fatalf("web search requests were not priced: %v vs %v", ws.USD, std.USD)
	}
	if q := price("no-such-model-zz", at, reprice.Tokens{Input: 1}); q.OK {
		t.Fatalf("unknown model priced: %+v", q)
	}
	// An all-zero rate set is "no rate", never a $0 re-price.
	if q := price("some-open-model:free", at, reprice.Tokens{Input: 1}); q.OK {
		t.Fatalf("an all-zero rate set quoted: %+v", q)
	}
}

func TestRepricePricingInfo(t *testing.T) {
	database, _ := repriceTestDB(t)
	ctx := context.Background()
	seed := cost.NewEngine(config.IntelligenceConfig{})
	if got := repricePricingInfo(ctx, config.Config{}, database, seed); got.Source != "seed" || got.Version != 0 || got.Description != "the built-in rate table" {
		t.Fatalf("standalone seed %+v", got)
	}
	feed := cost.NewEngine(config.IntelligenceConfig{}, cost.WithOrgRows(func() (cost.OrgRows, bool) {
		return cost.OrgRows{Rows: []cost.OrgPrice{{
			Model: "zz-feed", Pricing: cost.Pricing{Input: 1, Output: 2},
			Set: cost.OrgPriceSet{Input: true, Output: true},
		}}, Version: 4}, true
	}))
	if got := repricePricingInfo(ctx, config.Config{}, database, feed); got.Source != "feed" || got.Version != 4 || !strings.Contains(got.Description, "public price feed v4") {
		t.Fatalf("standalone feed %+v", got)
	}
	if _, err := database.Exec(`INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		VALUES (1, 'o', 'Org', 'https://org.example', 'u', 'u@example.com', '2026-08-15T00:00:00Z', 'k')`); err != nil {
		t.Fatal(err)
	}
	// Enrolled: the description is `observer guard status`'s own sentence.
	got := repricePricingInfo(ctx, config.Config{}, database, seed)
	if got.Source != "seed" || got.Description != guardPricingLine(ctx, config.Config{}, database) {
		t.Fatalf("enrolled seed %+v", got)
	}
}

// fakeRepriceRunner feeds runReprice canned answers.
type fakeRepriceRunner struct{ plan repricesvc.Plan }

func (f fakeRepriceRunner) Plan(context.Context, repricesvc.Filter) (repricesvc.Plan, error) {
	return f.plan, nil
}

func (f fakeRepriceRunner) Apply(context.Context, repricesvc.Request) (store.RepriceRun, error) {
	return store.RepriceRun{ID: 3, Kind: "apply", Status: "applied", Changed: 2, DeltaUSD: 0.5}, nil
}

func (f fakeRepriceRunner) Revert(context.Context, int64, string) (store.RepriceRun, error) {
	return store.RepriceRun{ID: 4, Kind: "revert", RevertsRun: 3, Status: "applied"}, nil
}

func (f fakeRepriceRunner) Runs(context.Context, int) ([]store.RepriceRun, error) {
	return []store.RepriceRun{{ID: 3, Kind: "apply", Status: "applied"}}, nil
}

func TestRunRepriceOutputIsHonestAndDashFree(t *testing.T) {
	plan := repricesvc.Plan{
		Pricing: repricesvc.PricingInfo{Source: "seed", Description: "the built-in rate table"},
		Summary: reprice.Summary{
			Scanned: 5, Changed: 2, Filled: 1, OldUSD: 1, NewUSD: 1.5,
			Skipped: map[reprice.Reason]int{reprice.ReasonSourceReported: 3},
			Models:  []reprice.ModelSummary{{Model: "m", Changed: 2, OldUSD: 1, NewUSD: 1.5}},
		},
		Org: repricesvc.OrgNote{Note: "This node is not enrolled in an org, so re-priced costs stay on this machine."},
	}
	for _, mode := range []repriceMode{repriceModePlan, repriceModeApply, repriceModeRevert, repriceModeList} {
		var out bytes.Buffer
		if err := runReprice(context.Background(), &out, fakeRepriceRunner{plan: plan}, mode, repriceOpts{revert: 3}, "t"); err != nil {
			t.Fatalf("mode %v: %v", mode, err)
		}
		s := out.String()
		if strings.ContainsRune(s, '\u2014') {
			t.Fatalf("mode %v: em-dash in output:\n%s", mode, s)
		}
		switch mode {
		case repriceModePlan:
			for _, want := range []string{"dry run, nothing written", "source_reported", "kept as stated", "--apply", "Not re-priced"} {
				if !strings.Contains(s, want) {
					t.Fatalf("plan output lacks %q:\n%s", want, s)
				}
			}
		case repriceModeApply:
			if !strings.Contains(s, "Applied run #3") || !strings.Contains(s, "--revert 3") {
				t.Fatalf("apply output:\n%s", s)
			}
		}
	}
}

// TestRepriceCLIApplyHonoursPricingPin pins review finding 5 on the CLI path:
// `observer reprice --apply` goes through the same service the Settings card
// uses, composed by newRepriceService with a governance provider, so the
// org's pin on the pricing Settings section refuses it with nothing written;
// the CLI's own provider (repriceCLIGovernance, the verified on-disk LKG) is
// dormant on a node with no grant, and the apply then proceeds.
func TestRepriceCLIApplyHonoursPricingPin(t *testing.T) {
	database, st := repriceTestDB(t)
	ctx := context.Background()
	insertReprTurn(t, database, "2026-09-02T10:00:00Z", "claude-opus-4-1", 1_000_000, 999.0)
	cfg := config.Config{}
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "unused.db")

	pinned := func(context.Context) govern.Effective {
		return govern.Effective{Active: true, OrgName: "Acme", ReadOnlySettings: []string{repricesvc.SettingsSection}}
	}
	svc := newRepriceService(ctx, cfg, database, slog.Default(), pinned)
	var out bytes.Buffer
	err := runReprice(ctx, &out, svc, repriceModeApply, repriceOpts{apply: true}, "cli:t")
	if !errors.Is(err, repricesvc.ErrGovernanceRefused) || !strings.Contains(err.Error(), "Acme") {
		t.Fatalf("pinned CLI apply = %v, want the pricing pin refusal", err)
	}
	if runs, _ := st.ListRepriceRuns(ctx, 10); len(runs) != 0 {
		t.Fatalf("a pinned CLI apply wrote a run: %+v", runs)
	}
	if c := reprCost(t, database, 1); c == nil || *c != 999.0 {
		t.Fatalf("a pinned CLI apply changed a row: %v", c)
	}

	// The CLI's own provider on an ungranted node is dormant: the apply runs.
	cliGov := repriceCLIGovernance(ctx, cfg, database, slog.Default())
	if eff := cliGov(ctx); eff.Active {
		t.Fatalf("an ungranted node resolved an active posture: %+v", eff)
	}
	svc = newRepriceService(ctx, cfg, database, slog.Default(), cliGov)
	out.Reset()
	if err := runReprice(ctx, &out, svc, repriceModeApply, repriceOpts{apply: true}, "cli:t"); err != nil {
		t.Fatalf("ungoverned CLI apply: %v\n%s", err, out.String())
	}
	if runs, _ := st.ListRepriceRuns(ctx, 10); len(runs) != 1 || runs[0].Changed != 1 {
		t.Fatalf("ungoverned CLI apply runs %+v", runs)
	}
}
