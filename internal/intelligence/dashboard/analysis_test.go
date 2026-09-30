package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// headlineResponse mirrors the v1.4.50 JSON shape /api/analysis/headline
// returns. Kept private to the test so the public JSON contract can stay
// flexible without breaking external callers.
type headlineResponse struct {
	Days   int `json:"days"`
	Period struct {
		CostUSD              float64 `json:"cost_usd"`
		PriorCostUSD         float64 `json:"prior_cost_usd"`
		PriorIsZero          bool    `json:"prior_is_zero"`
		DeltaPct             float64 `json:"delta_pct"`
		RecordedCostSharePct float64 `json:"recorded_cost_share_pct"`
	} `json:"period"`
	Month struct {
		ToDateUSD            float64 `json:"to_date_usd"`
		ProjectionUSD        float64 `json:"projection_usd"`
		PriorMonthSameDayUSD float64 `json:"prior_month_same_day_usd"`
		PriorMonthIsZero     bool    `json:"prior_month_is_zero"`
		VsPriorMonthPct      float64 `json:"vs_prior_month_pct"`
		BudgetUSD            float64 `json:"budget_usd"`
		BudgetPct            float64 `json:"budget_pct"`
		DaysElapsed          int     `json:"days_elapsed"`
		DaysInMonth          int     `json:"days_in_month"`
	} `json:"month"`
	OutputRate struct {
		OutputTokens   int64   `json:"output_tokens"`
		RatePerMillion float64 `json:"rate_per_million"`
	} `json:"output_rate"`
	CacheSavings struct {
		USD             float64 `json:"usd"`
		CacheReadTokens int64   `json:"cache_read_tokens"`
	} `json:"cache_savings"`
	Cache struct {
		ReadTokens  int64   `json:"read_tokens"`
		WriteTokens int64   `json:"write_tokens"`
		Efficacy    float64 `json:"efficacy"`
	} `json:"cache"`
	HighContext struct {
		TurnsOver100k   int64   `json:"turns_over_100k"`
		TurnsOver200k   int64   `json:"turns_over_200k"`
		CostOver100kUSD float64 `json:"cost_over_100k_usd"`
		CostOver200kUSD float64 `json:"cost_over_200k_usd"`
		LCEligibleTurns int64   `json:"lc_eligible_turns"`
		LCSurchargeUSD  float64 `json:"lc_surcharge_usd"`
	} `json:"high_context"`
	PerTurn struct {
		Count   int     `json:"count"`
		MeanUSD float64 `json:"mean_usd"`
		P95USD  float64 `json:"p95_usd"`
	} `json:"per_turn"`
	BurnRate struct {
		ActiveHours    int     `json:"active_hours"`
		CostPerHourUSD float64 `json:"cost_per_hour_usd"`
	} `json:"burn_rate"`
	TopModel struct {
		Key              string  `json:"key"`
		CostUSD          float64 `json:"cost_usd"`
		ConcentrationPct float64 `json:"concentration_pct"`
	} `json:"top_model"`
	Waste struct {
		USD                   float64 `json:"usd"`
		Tokens                int64   `json:"tokens"`
		BlendedRatePerMillion float64 `json:"blended_rate_per_million"`
	} `json:"waste"`
}

func openHeadline(t *testing.T, server *Server, days int) headlineResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/analysis/headline?days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/headline: %d body=%s", rr.Code, rr.Body.String())
	}
	var got headlineResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestAnalysisHeadline_EmptyDB returns zeros for every metric without
// erroring. The handler must tolerate a fresh install with no api_turns
// or token_usage rows.
func TestAnalysisHeadline_EmptyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, s, 30)
	if got.Period.CostUSD != 0 || got.Period.PriorCostUSD != 0 {
		t.Errorf("empty DB cost: %+v", got.Period)
	}
	if !got.Period.PriorIsZero {
		t.Errorf("empty DB should report prior_is_zero=true")
	}
	if got.HighContext.TurnsOver100k != 0 || got.HighContext.TurnsOver200k != 0 ||
		got.HighContext.LCSurchargeUSD != 0 {
		t.Errorf("empty DB high_context: %+v", got.HighContext)
	}
	if got.Cache.Efficacy != 0 {
		t.Errorf("empty DB cache efficacy: %v", got.Cache.Efficacy)
	}
	if got.OutputRate.RatePerMillion != 0 || got.CacheSavings.USD != 0 ||
		got.PerTurn.Count != 0 || got.BurnRate.ActiveHours != 0 {
		t.Errorf("empty DB new tiles non-zero: outRate=%v cacheSave=%+v perTurn=%+v burn=%+v",
			got.OutputRate, got.CacheSavings, got.PerTurn, got.BurnRate)
	}
	if got.TopModel.Key != "" || got.TopModel.CostUSD != 0 {
		t.Errorf("empty DB top_model non-zero: %+v", got.TopModel)
	}
	if got.Days != 30 {
		t.Errorf("days echo: got %d want 30", got.Days)
	}
}

// TestAnalysisHeadline_PeriodVsPrior splits one batch of turns across
// the current and prior windows to verify period-over-period
// accounting. Each turn is small enough to stay below the LC threshold
// so cost computes at standard rates.
func TestAnalysisHeadline_PeriodVsPrior(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sX",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// One turn 1 day ago (in current 7d window).
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sX", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 10_000,
		Timestamp: now.Add(-24 * time.Hour), RequestID: "msg_p_1",
	}); err != nil {
		t.Fatal(err)
	}
	// Two turns 10 days ago (in prior 7d window: [-14, -7] days from now).
	for i := 0; i < 2; i++ {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sX", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 10_000,
			Timestamp: now.Add(-10 * 24 * time.Hour),
			RequestID: "msg_q_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)

	// Sonnet 4.6 standard: input $3/M, output $15/M. Each turn:
	//   50K × $3 + 10K × $15 / 1M = 0.15 + 0.15 = 0.30
	const perTurn = 0.30
	wantPeriod := perTurn    // 1 turn in current period
	wantPrior := perTurn * 2 // 2 turns in prior period
	if approx(got.Period.CostUSD, wantPeriod) != true {
		t.Errorf("period cost: got %v want %v", got.Period.CostUSD, wantPeriod)
	}
	if approx(got.Period.PriorCostUSD, wantPrior) != true {
		t.Errorf("prior cost: got %v want %v", got.Period.PriorCostUSD, wantPrior)
	}
	if got.Period.PriorIsZero {
		t.Errorf("prior_is_zero must be false when prior had turns")
	}
	// delta = (period - prior) / prior * 100 = (0.30 - 0.60) / 0.60 = -50%
	if got.Period.DeltaPct < -50.5 || got.Period.DeltaPct > -49.5 {
		t.Errorf("delta_pct: got %v want ≈ -50", got.Period.DeltaPct)
	}
}

// TestAnalysisHeadline_HighContextAndLCSurcharge pins the dual signal
// for the v1.4.50 high_context tile. One Sonnet 4 turn at 100K (under
// the 200K LC threshold) and one at 250K (LC kicks in). Verifies:
//
//   - turns_over_100k counts both; turns_over_200k counts only the 250K
//   - cost_over_200k_usd attributes the 250K turn's full cost
//   - lc_eligible_turns / lc_surcharge_usd match the LC-only turn (the
//     surcharge attribution survived the v1.4.49→v1.4.50 transition for
//     LC-eligible models)
func TestAnalysisHeadline_HighContextAndLCSurcharge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sLC",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	// Sub-threshold turn — should NOT add to surcharge.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sLC", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-20250514", InputTokens: 100_000, OutputTokens: 5_000,
		Timestamp: now.Add(-2 * 24 * time.Hour), RequestID: "msg_lc_under",
	}); err != nil {
		t.Fatal(err)
	}
	// Over-threshold turn (250K) — LC pricing kicks in. Standard cost:
	//   250K × $3 + 5K × $15 / 1M = 0.75 + 0.075 = 0.825
	// LC cost: 250K × $6 + 5K × $22.50 / 1M = 1.50 + 0.1125 = 1.6125
	// Surcharge = 1.6125 - 0.825 = 0.7875
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sLC", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-20250514", InputTokens: 250_000, OutputTokens: 5_000,
		Timestamp: now.Add(-1 * 24 * time.Hour), RequestID: "msg_lc_over",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	// High-context counts: 100K turn is NOT >100K (strict), 250K is.
	// (Threshold check is `> 100_000`, not `>= 100_000`.)
	if got.HighContext.TurnsOver100k != 1 {
		t.Errorf("turns_over_100k: got %d want 1", got.HighContext.TurnsOver100k)
	}
	if got.HighContext.TurnsOver200k != 1 {
		t.Errorf("turns_over_200k: got %d want 1", got.HighContext.TurnsOver200k)
	}
	// cost_over_200k_usd = LC-tier cost of the 250K turn = 1.6125
	if !approx(got.HighContext.CostOver200kUSD, 1.6125) {
		t.Errorf("cost_over_200k_usd: got %v want 1.6125", got.HighContext.CostOver200kUSD)
	}
	// LC-eligible: 1 (Sonnet 4 has LC tier defined). Surcharge:
	// 1.6125 (LC) − 0.825 (standard) = 0.7875.
	if got.HighContext.LCEligibleTurns != 1 {
		t.Errorf("lc_eligible_turns: got %d want 1", got.HighContext.LCEligibleTurns)
	}
	const wantSurcharge = 0.7875
	if !approx(got.HighContext.LCSurchargeUSD, wantSurcharge) {
		t.Errorf("lc_surcharge_usd: got %v want %v", got.HighContext.LCSurchargeUSD, wantSurcharge)
	}
}

// TestAnalysisHeadline_HighContextOpusModelAgnostic — the v1.4.50 fix:
// when the user's only model is Opus (no LC tier in pricing), high-
// context turns >100K and >200K still show their counts and cost
// attribution, but LC surcharge stays $0 (correct — Opus has no LC tier).
// Previously the LC tile showed always-$0 with no high-context signal,
// hiding 18k+ heavy turns on real Opus-heavy installs.
func TestAnalysisHeadline_HighContextOpusModelAgnostic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sOpus",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Opus 4.7 turn at 300K prompt window (200K cache_read + 100K input).
	// Crosses BOTH high-context thresholds but has no LC tier so no
	// surcharge attribution.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sOpus", Provider: models.ProviderAnthropic,
		Model:       "claude-opus-4-7",
		InputTokens: 100_000, CacheReadTokens: 200_000, OutputTokens: 10_000,
		Timestamp: now.Add(-1 * 24 * time.Hour), RequestID: "msg_opus_300k",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.HighContext.TurnsOver100k != 1 || got.HighContext.TurnsOver200k != 1 {
		t.Errorf("opus high-context counts: 100k=%d 200k=%d want 1/1",
			got.HighContext.TurnsOver100k, got.HighContext.TurnsOver200k)
	}
	if got.HighContext.LCEligibleTurns != 0 {
		t.Errorf("opus has no LC tier, lc_eligible_turns must be 0: got %d", got.HighContext.LCEligibleTurns)
	}
	if got.HighContext.LCSurchargeUSD != 0 {
		t.Errorf("opus has no LC tier, lc_surcharge_usd must be 0: got %v", got.HighContext.LCSurchargeUSD)
	}
	// cost_over_200k_usd should be > 0 — Opus 4.7 priced at standard rate.
	// 100K input × $5 + 200K cache_read × $0.50 + 10K output × $25 = $0.50 + $0.10 + $0.25 = $0.85
	if !approx(got.HighContext.CostOver200kUSD, 0.85) {
		t.Errorf("cost_over_200k_usd: got %v want 0.85", got.HighContext.CostOver200kUSD)
	}
}

// TestAnalysisHeadline_CacheEfficacy verifies cache_read / (cache_read +
// cache_creation) over the current period.
func TestAnalysisHeadline_CacheEfficacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sCache",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCache", Provider: models.ProviderAnthropic,
		Model:           "claude-sonnet-4-6",
		CacheReadTokens: 800_000, CacheCreationTokens: 200_000,
		Timestamp: now.Add(-2 * 24 * time.Hour), RequestID: "msg_cache_1",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	// 800K / (800K + 200K) = 0.80
	if got.Cache.Efficacy < 0.799 || got.Cache.Efficacy > 0.801 {
		t.Errorf("cache efficacy: got %v want 0.80", got.Cache.Efficacy)
	}
	if got.Cache.ReadTokens != 800_000 || got.Cache.WriteTokens != 200_000 {
		t.Errorf("cache tokens: read=%d write=%d", got.Cache.ReadTokens, got.Cache.WriteTokens)
	}
}

// TestAnalysisHeadline_BudgetTile pins MTD + projection + budget %
// computation when MonthlyBudgetUSD is set on the server options.
func TestAnalysisHeadline_BudgetTile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sB",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sB", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, OutputTokens: 20_000,
		Timestamp: monthStart.Add(time.Hour), RequestID: "msg_b_1",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path, MonthlyBudgetUSD: 100})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 30)
	// MTD cost: 100K × $3 + 20K × $15 / 1M = 0.30 + 0.30 = 0.60
	if !approx(got.Month.ToDateUSD, 0.60) {
		t.Errorf("MTD: got %v want 0.60", got.Month.ToDateUSD)
	}
	if got.Month.BudgetUSD != 100 {
		t.Errorf("budget echo: got %v want 100", got.Month.BudgetUSD)
	}
	// budget_pct = MTD / budget * 100 = 0.60%
	if got.Month.BudgetPct < 0.59 || got.Month.BudgetPct > 0.61 {
		t.Errorf("budget pct: got %v want ≈ 0.60", got.Month.BudgetPct)
	}
	if got.Month.DaysInMonth < 28 || got.Month.DaysInMonth > 31 {
		t.Errorf("days_in_month sanity: %v", got.Month.DaysInMonth)
	}
}

// TestAnalysisHeadline_OutputRate pins $/M output (replacement for the
// retired Effective rate). One Sonnet 4.6 turn: 10K output × $15/M =
// $0.15. Output-only rate = $0.15 × 1M / 10K = $15/M (matches Sonnet 4.6
// output rate exactly, confirming the cache_write isn't muddying the
// denominator as it did pre-v1.4.50).
func TestAnalysisHeadline_OutputRate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sOut",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Pure-output turn (no input, no cache writes) so the rate isolates
	// to the output_rate denominator.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sOut", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", OutputTokens: 10_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_out",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.OutputRate.OutputTokens != 10_000 {
		t.Errorf("output_tokens: got %d want 10000", got.OutputRate.OutputTokens)
	}
	// $0.15 × 1M / 10K = $15.00/M — pinned exact since pricing is deterministic.
	if !approx(got.OutputRate.RatePerMillion, 15.0) {
		t.Errorf("rate_per_million: got %v want 15.00", got.OutputRate.RatePerMillion)
	}
}

// TestAnalysisHeadline_CacheSavings pins the counterfactual cache savings
// math. Sonnet 4.6 turn with 100K cache_read tokens. Actual cost:
//
//	100K × $0.30/M (cache_read rate) = $0.030
//
// Counterfactual (cache_read priced as raw input):
//
//	100K × $3.00/M (input rate) = $0.300
//
// Savings = $0.300 - $0.030 = $0.27.
func TestAnalysisHeadline_CacheSavings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sCS",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCS", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", CacheReadTokens: 100_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_cs",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.CacheSavings.CacheReadTokens != 100_000 {
		t.Errorf("cache_read_tokens: got %d want 100000", got.CacheSavings.CacheReadTokens)
	}
	if !approx(got.CacheSavings.USD, 0.27) {
		t.Errorf("cache_savings.usd: got %v want 0.27", got.CacheSavings.USD)
	}
}

// TestAnalysisHeadline_CacheSavingsRecordedRows pins the 2026-07-30 fix
// for the "recorded > 0 suppresses cache_savings" bug: before the fix,
// any turn with a proxy/JSONL-populated cost_usd set rowAltCost ==
// rowCost, so `rowAltCost > rowCost` could never fire and the turn
// contributed exactly $0 to cache_savings regardless of how much
// cache_read traffic it carried — a ~3× understatement on a real
// corpus where proxy-recorded turns are the majority of spend.
//
// Three cases, table-driven:
//
//   - "recorded_priced": a proxy-recorded turn (cost_usd set to an
//     arbitrary $5.00 — deliberately NOT the value the pricing table
//     would compute, to prove the recorded total is preserved as
//     ground truth) on a model the pricing table knows. Must now
//     contribute the same $0.27 delta as the non-recorded case
//     (100K cache_read tokens on claude-sonnet-4-6: 100K × ($3 input
//     − $0.30 cache_read)/1M = $0.27), AND period cost_usd must still
//     equal the recorded $5.00 exactly (never overridden by a modeled
//     figure).
//   - "recorded_unpriced": a proxy-recorded turn on a model with NO
//     pricing-table entry. Must contribute exactly $0 — honesty
//     requirement: never invent a counterfactual without a pricing
//     basis.
//   - "unrecorded_logtier": a non-recorded (token_usage / log-tier)
//     turn with identical cache_read tokens on the same priced model.
//     Already worked before the fix; pinned here to prove the fix left
//     this path unchanged.
func TestAnalysisHeadline_CacheSavingsRecordedRows(t *testing.T) {
	cases := []struct {
		name           string
		model          string
		recordedCost   float64 // 0 means "insert via token_usage, unrecorded"
		wantSavingsUSD float64
		wantPeriodCost float64 // 0 => don't assert (log-tier path computes its own)
	}{
		{
			name:           "recorded_priced",
			model:          "claude-sonnet-4-6",
			recordedCost:   5.00,
			wantSavingsUSD: 0.27,
			wantPeriodCost: 5.00,
		},
		{
			name:           "recorded_unpriced",
			model:          "some-bogus-model-xyz",
			recordedCost:   5.00,
			wantSavingsUSD: 0,
			wantPeriodCost: 5.00,
		},
		{
			name:           "unrecorded_logtier",
			model:          "claude-sonnet-4-6",
			recordedCost:   0,
			wantSavingsUSD: 0.27,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "d.db")
			database, err := openTestDB(context.Background(), db.Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { database.Close() })
			st := store.New(database)
			root := t.TempDir()
			if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
				SourceFile: "f", SourceEventID: "e1", SessionID: "sCSR",
				ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
				Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
				Target: "a.go", Success: true,
			}}, nil, store.IngestOptions{}); err != nil {
				t.Fatal(err)
			}

			if tc.recordedCost > 0 {
				if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
					SessionID: "sCSR", Provider: models.ProviderAnthropic,
					Model: tc.model, CacheReadTokens: 100_000,
					Timestamp: time.Now().UTC().Add(-24 * time.Hour),
					RequestID: "msg_csr_" + tc.name,
					CostUSD:   tc.recordedCost,
				}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := st.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SourceFile: "f.jsonl", SourceEventID: "e_csr_" + tc.name,
					SessionID: "sCSR", ProjectRoot: root,
					Timestamp: time.Now().UTC().Add(-24 * time.Hour),
					Tool:      models.ToolClaudeCode, Model: tc.model,
					CacheReadTokens: 100_000,
					Source:          models.TokenSourceJSONL, Reliability: models.ReliabilityApproximate,
				}}); err != nil {
					t.Fatal(err)
				}
			}

			server, err := New(Options{DB: database, DBPath: path})
			if err != nil {
				t.Fatal(err)
			}
			got := openHeadline(t, server, 7)
			if got.CacheSavings.CacheReadTokens != 100_000 {
				t.Errorf("cache_read_tokens: got %d want 100000", got.CacheSavings.CacheReadTokens)
			}
			if !approx(got.CacheSavings.USD, tc.wantSavingsUSD) {
				t.Errorf("cache_savings.usd: got %v want %v", got.CacheSavings.USD, tc.wantSavingsUSD)
			}
			if tc.wantPeriodCost > 0 && !approx(got.Period.CostUSD, tc.wantPeriodCost) {
				t.Errorf("period.cost_usd: got %v want %v (recorded total must be preserved)",
					got.Period.CostUSD, tc.wantPeriodCost)
			}
		})
	}
}

// TestAnalysisHeadline_LCSurchargeClampedToRecorded is the F5 regression
// test (2026-07-30 adversarial review). A recorded row's rowStdCost =
// recorded - (computedCost - computedStd) had no lower bound: when the
// pricing table's modeled LC delta exceeds the row's own recorded
// (authoritative) cost, rowStdCost went negative and the LC surcharge
// tile reported a surcharge larger than the entire recorded spend — an
// impossible number.
//
// One claude-sonnet-4-20250514 turn (Sonnet 4 with the 200K LC tier):
// recorded=$0.10 (proxy ground truth, deliberately tiny — e.g. a
// discounted lane), 1,000,000 input tokens (well over the 200K LC
// threshold). Modeled LC delta at the pricing table's rates:
// computedStd = 1,000,000 × $3/M = $3.00, computedCost (LC) =
// 1,000,000 × $6/M = $6.00, delta = $3.00 — 30× the recorded cost.
// The fix clamps the applied delta at `recorded`, so:
//   - lc_surcharge_usd must be AT MOST $0.10 (never $3.00)
//   - period.cost_usd (rowCost = recorded, untouched) stays $0.10
//   - the clamp forces rowStdCost = recorded - min(delta, recorded) = 0,
//     which is still >= 0 — the invariant under test.
func TestAnalysisHeadline_LCSurchargeClampedToRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sClamp",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sClamp", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-20250514", InputTokens: 1_000_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour),
		RequestID: "msg_clamp_lc", CostUSD: 0.10,
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	const recorded = 0.10
	if got.HighContext.LCSurchargeUSD > recorded+1e-9 {
		t.Errorf("lc_surcharge_usd: got %v, must be clamped to at most the recorded cost %v",
			got.HighContext.LCSurchargeUSD, recorded)
	}
	if !approx(got.HighContext.LCSurchargeUSD, recorded) {
		t.Errorf("lc_surcharge_usd: got %v want %v (clamped to the full recorded amount since the modeled delta $3.00 exceeds it)",
			got.HighContext.LCSurchargeUSD, recorded)
	}
	if !approx(got.Period.CostUSD, recorded) {
		t.Errorf("period.cost_usd must stay the recorded ground truth: got %v want %v",
			got.Period.CostUSD, recorded)
	}
}

// TestAnalysisHeadline_CacheSavingsFastTierPricedAtFastRate is the F6
// regression test (2026-07-30 adversarial review) for
// handleAnalysisHeadline. The headline query didn't select api_turns.fast
// / token_usage.fast, so bundle.Fast was always false and cost.Compute
// priced every counterfactual delta at standard rates — undercounting a
// fast-tier turn's cache-savings delta by the FastMultiplier.
//
// One recorded claude-opus-4-8 turn (FastMultiplier=2), Fast=true,
// 100,000 cache_read tokens, recorded cost $5.00 (ground truth,
// unrelated to the counterfactual — only the delta matters here):
//   - actual  = cache_read 100K × $0.50/M × fast(2)  = $0.10
//   - alt     = input      100K × $5.00/M × fast(2)  = $1.00
//   - delta   = alt - actual                          = $0.90
//
// Pre-fix (Fast always scanned as false) the same shapes price at
// standard (non-fast) rates: actual=$0.05, alt=$0.50, delta=$0.45 — half
// the correct value. cache_savings.usd must reflect the fast-priced
// $0.90 delta, not the standard-priced $0.45.
func TestAnalysisHeadline_CacheSavingsFastTierPricedAtFastRate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sFastCS",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sFastCS", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-8", CacheReadTokens: 100_000, Fast: true,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour),
		RequestID: "msg_fast_cs", CostUSD: 5.00,
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	const wantSavings = 0.90
	if !approx(got.CacheSavings.USD, wantSavings) {
		t.Errorf("cache_savings.usd: got %v want %v (fast-tier delta undercounted if bundle.Fast wasn't scanned)",
			got.CacheSavings.USD, wantSavings)
	}
}

// TestAnalysisHeadline_PerTurnDistribution pins mean + p95 across a
// known cost distribution. Sample size is N=10 so the impl's
// p95Idx = int(0.95*10 + 0.5) - 1 = 9 lands cleanly on the outlier
// at sorted[9].
//   - 9 cheap Sonnet-4.6 turns at $0.090 each (5K input + 5K output)
//   - 1 outlier at $0.900 (50K input + 50K output)
//   - mean = (9 × 0.090 + 0.900) / 10 = 0.171
//   - p95 = sorted[9] = $0.900 (the outlier)
func TestAnalysisHeadline_PerTurnDistribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sPT",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 9; i++ {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sPT", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 5_000, OutputTokens: 5_000,
			Timestamp: now.Add(-24 * time.Hour), RequestID: "msg_pt_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sPT", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 50_000,
		Timestamp: now.Add(-24 * time.Hour), RequestID: "msg_pt_big",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.PerTurn.Count != 10 {
		t.Errorf("per_turn.count: got %d want 10", got.PerTurn.Count)
	}
	if !approx(got.PerTurn.MeanUSD, 0.171) {
		t.Errorf("per_turn.mean_usd: got %v want 0.171", got.PerTurn.MeanUSD)
	}
	if !approx(got.PerTurn.P95USD, 0.90) {
		t.Errorf("per_turn.p95_usd: got %v want 0.90 (the outlier)", got.PerTurn.P95USD)
	}
}

// TestAnalysisHeadline_BurnRate pins active-hour distinct bucketing.
// Three turns spread across two distinct (date, hour) buckets → 2 active hours.
// Period cost / 2 = $/hour.
func TestAnalysisHeadline_BurnRate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sBR",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Use a known anchor time so the hour buckets are deterministic.
	hourA := time.Now().UTC().Add(-2 * 24 * time.Hour).Truncate(time.Hour)
	hourB := hourA.Add(1 * time.Hour)
	// Two turns in hourA, one turn in hourB → 2 distinct buckets.
	for i, ts := range []time.Time{hourA, hourA.Add(15 * time.Minute), hourB} {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sBR", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 10_000, OutputTokens: 5_000,
			Timestamp: ts, RequestID: "msg_br_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.BurnRate.ActiveHours != 2 {
		t.Errorf("active_hours: got %d want 2 (hourA shared by two turns + hourB)",
			got.BurnRate.ActiveHours)
	}
	// 3 turns × 10K input × $3/M + 3 × 5K output × $15/M = $0.09 + $0.225 = $0.315
	// $/hour = 0.315 / 2 = $0.1575
	if !approx(got.BurnRate.CostPerHourUSD, 0.1575) {
		t.Errorf("cost_per_hour_usd: got %v want 0.1575", got.BurnRate.CostPerHourUSD)
	}
}

// TestAnalysisHeadline_TopModel pins concentration % math. Sonnet at
// $0.30 + Opus at $0.70 → top = Opus, concentration = 70%.
func TestAnalysisHeadline_TopModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sTM",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Sonnet: 50K × $3 + 10K × $15 / 1M = 0.15 + 0.15 = $0.30
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sTM", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 10_000,
		Timestamp: now.Add(-24 * time.Hour), RequestID: "msg_tm_s",
	}); err != nil {
		t.Fatal(err)
	}
	// Opus 4-7: 100K × $5 + 8K × $25 / 1M = 0.50 + 0.20 = $0.70
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sTM", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 100_000, OutputTokens: 8_000,
		Timestamp: now.Add(-24 * time.Hour), RequestID: "msg_tm_o",
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	if got.TopModel.Key != "claude-opus-4-7" {
		t.Errorf("top_model.key: got %q want claude-opus-4-7", got.TopModel.Key)
	}
	if !approx(got.TopModel.CostUSD, 0.70) {
		t.Errorf("top_model.cost_usd: got %v want 0.70", got.TopModel.CostUSD)
	}
	// Period = 0.30 + 0.70 = 1.00; concentration = 70 / 100 = 70%.
	if got.TopModel.ConcentrationPct < 69.5 || got.TopModel.ConcentrationPct > 70.5 {
		t.Errorf("top_model.concentration_pct: got %v want ≈ 70.0", got.TopModel.ConcentrationPct)
	}
}

// TestAnalysisHeadline_PriorMonthSameDay covers the month-over-month
// comparison: a turn this calendar month + a turn at the same day-of-
// month in the prior calendar month. The vs_prior_month_pct delta
// surfaces the change between them.
//
// Skipped when the current day is too early in the month to construct
// a meaningful "prior month same day" range — the comparison window
// degenerates to [prior_month_start, prior_month_start + ε], which
// won't reliably overlap with seeded data.
func TestAnalysisHeadline_PriorMonthSameDay(t *testing.T) {
	now := time.Now().UTC()
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	if now.Sub(monthStart) < 36*time.Hour {
		t.Skip("current calendar day too close to month-start for a meaningful prior-month comparison")
	}

	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sPM",
		ProjectRoot: root, Timestamp: now.Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// MTD turn: 12 hours after month start.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sPM", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, OutputTokens: 20_000,
		Timestamp: monthStart.Add(12 * time.Hour), RequestID: "msg_mtd",
	}); err != nil {
		t.Fatal(err)
	}
	// Prior-month turn: 12 hours into the prior calendar month (inside
	// the [prior_month_start, prior_month_start + (now - month_start))
	// window the handler computes).
	priorMonthStart := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sPM", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 10_000,
		Timestamp: priorMonthStart.Add(12 * time.Hour), RequestID: "msg_pm",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	// days=60 to ensure both turns fall inside the headline's main scan window.
	got := openHeadline(t, server, 60)
	// MTD: 100K × $3 + 20K × $15 / 1M = 0.30 + 0.30 = 0.60
	if !approx(got.Month.ToDateUSD, 0.60) {
		t.Errorf("mtd: got %v want 0.60", got.Month.ToDateUSD)
	}
	// Prior-month-same-day: 50K × $3 + 10K × $15 / 1M = 0.15 + 0.15 = 0.30
	if !approx(got.Month.PriorMonthSameDayUSD, 0.30) {
		t.Errorf("prior_month_same_day_usd: got %v want 0.30", got.Month.PriorMonthSameDayUSD)
	}
	if got.Month.PriorMonthIsZero {
		t.Errorf("prior_month_is_zero must be false when prior had turns")
	}
	// vs_prior_month_pct = (0.60 - 0.30) / 0.30 × 100 = +100%
	if got.Month.VsPriorMonthPct < 99.5 || got.Month.VsPriorMonthPct > 100.5 {
		t.Errorf("vs_prior_month_pct: got %v want ≈ +100", got.Month.VsPriorMonthPct)
	}
}

// TestAnalysisHeadline_PriorMonthShorterThanCurrentDay pins the
// 2026-05-31 regression: when "today" is past the prior month's last
// day, the [priorMonthStart, priorMonthStart+(now-monthStart)) window
// overflows past first-of-current-month and double-counts MTD turns
// in the prior-month baseline. The fix clamps the window's upper
// bound to monthStart. This test runs under a pinned clock so it
// fails on every day of every month if the clamp regresses, instead
// of only fortuitously exposing the bug on the last day of a month
// with a shorter prior month (like real CI did 2026-05-31).
func TestAnalysisHeadline_PriorMonthShorterThanCurrentDay(t *testing.T) {
	// Pin "now" to 2026-05-31 14:00 UTC. monthStart=May 1, prior=Apr 1.
	// (now - monthStart) ≈ 30d 14h; Apr 1 + that = May 1 14h — i.e.
	// the buggy window would extend into May and include MTD seeds.
	pinned := time.Date(2026, 5, 31, 14, 0, 0, 0, time.UTC)

	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sPMS",
		ProjectRoot: root, Timestamp: pinned.Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	// MTD seed: May 1 08:00 — early in the current month, inside the
	// buggy window's overflow [May 1 00:00, May 1 14:00) so that any
	// window leak past monthStart would catch it.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sPMS", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, OutputTokens: 20_000,
		Timestamp: time.Date(2026, 5, 1, 8, 0, 0, 0, time.UTC), RequestID: "msg_mtd",
	}); err != nil {
		t.Fatal(err)
	}
	// Prior-month seed: April 15 12:00 — solidly inside prior month.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sPMS", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 50_000, OutputTokens: 10_000,
		Timestamp: time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC), RequestID: "msg_pm",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return pinned }

	// days=60 to cover both seeds in the headline's main period.
	got := openHeadline(t, server, 60)
	// MTD: 100K × $3 + 20K × $15 / 1M = 0.30 + 0.30 = 0.60
	if !approx(got.Month.ToDateUSD, 0.60) {
		t.Errorf("mtd: got %v want 0.60", got.Month.ToDateUSD)
	}
	// Prior-month-same-day: ONLY the April seed should count
	// (50K × $3 + 10K × $15 / 1M = 0.30). If the May MTD seed leaks
	// in (pre-clamp behaviour), this would be 0.30 + 0.60 = 0.90.
	if !approx(got.Month.PriorMonthSameDayUSD, 0.30) {
		t.Errorf("prior_month_same_day_usd: got %v want 0.30 (window must clamp at monthStart)", got.Month.PriorMonthSameDayUSD)
	}
	// vs_prior_month_pct = (0.60 - 0.30) / 0.30 × 100 = +100%
	if got.Month.VsPriorMonthPct < 99.5 || got.Month.VsPriorMonthPct > 100.5 {
		t.Errorf("vs_prior_month_pct: got %v want ≈ +100", got.Month.VsPriorMonthPct)
	}
}

// TestAnalysisHeadline_RecordedCostShare pins the B3 disclosure. A turn
// with recorded cost_usd > 0 contributes 100% of period cost; the
// recorded_cost_share_pct should reflect that.
func TestAnalysisHeadline_RecordedCostShare(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sRC",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Turn with recorded cost_usd = $0.50 (proxy populated).
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sRC", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", InputTokens: 100_000, OutputTokens: 20_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_rc_recorded",
		CostUSD: 0.50,
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 7)
	// 100% of period cost comes from a recorded row.
	if got.Period.RecordedCostSharePct < 99.5 || got.Period.RecordedCostSharePct > 100.5 {
		t.Errorf("recorded_cost_share_pct: got %v want ≈ 100", got.Period.RecordedCostSharePct)
	}
}

// TestAnalysisHeadline_NoBudgetSetHidesPct when MonthlyBudgetUSD is zero,
// budget_pct stays zero so the JS knows to render only the projection.
func TestAnalysisHeadline_NoBudgetSetHidesPct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openHeadline(t, server, 30)
	if got.Month.BudgetUSD != 0 || got.Month.BudgetPct != 0 {
		t.Errorf("no budget should yield zeros: %+v", got.Month)
	}
}

func approx(got, want float64) bool {
	d := got - want
	return d < 1e-6 && d > -1e-6
}

// routingResponse mirrors /api/analysis/routing-suggestions.
type routingResponse struct {
	Days        int     `json:"days"`
	TotalSaving float64 `json:"total_savings_usd"`
	Suggestions []struct {
		SessionID        string   `json:"session_id"`
		CurrentModel     string   `json:"current_model"`
		SuggestedModel   string   `json:"suggested_model"`
		CurrentCostUSD   float64  `json:"current_cost_usd"`
		SuggestedCostUSD float64  `json:"suggested_cost_usd"`
		SavingsUSD       float64  `json:"savings_usd"`
		Reasons          []string `json:"reasons"`
	} `json:"suggestions"`
}

func openRouting(t *testing.T, server *Server, days int) routingResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/routing-suggestions?days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/routing-suggestions: %d body=%s", rr.Code, rr.Body.String())
	}
	var got routingResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisRoutingSuggestions_TrivialOpusFlagged: a single-turn
// Opus session with small prompt + low output gets flagged with a
// Sonnet 4.6 alternative. The savings reflect the 5× rate gap
// between Opus 4.7 ($5/$25) and Sonnet 4.6 ($3/$15).
func TestAnalysisRoutingSuggestions_TrivialOpusFlagged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sTrivial",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sTrivial", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 20_000, OutputTokens: 3_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_t",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openRouting(t, server, 7)
	if len(got.Suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(got.Suggestions))
	}
	s := got.Suggestions[0]
	if s.SessionID != "sTrivial" || s.CurrentModel != "claude-opus-4-7" {
		t.Errorf("session/model: %+v", s)
	}
	if s.SuggestedModel != "claude-sonnet-4-6" {
		t.Errorf("suggested model: got %q want claude-sonnet-4-6", s.SuggestedModel)
	}
	// Opus 4.7: 20K × $5 + 3K × $25 / 1M = 0.100 + 0.075 = 0.175
	// Sonnet 4.6: 20K × $3 + 3K × $15 / 1M = 0.060 + 0.045 = 0.105
	// Savings = 0.07 — clears the 0.05 floor.
	if !approx(s.SavingsUSD, 0.07) {
		t.Errorf("savings: got %v want 0.07", s.SavingsUSD)
	}
	if !approx(s.CurrentCostUSD, 0.175) {
		t.Errorf("current cost: got %v want 0.175", s.CurrentCostUSD)
	}
}

// TestAnalysisRoutingSuggestions_HeavyOpusSkipped: an Opus session
// with a large prompt or LC-tier turn is NOT flagged — heavy work
// could legitimately need Opus. Two sessions; both should fail the
// trivial filter, neither should appear in the suggestions list.
func TestAnalysisRoutingSuggestions_HeavyOpusSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()

	// Heavy-prompt Opus — 200K input. Should be skipped.
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "eH", SessionID: "sHeavy",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sHeavy", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 200_000, OutputTokens: 1_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_h",
	}); err != nil {
		t.Fatal(err)
	}

	// High-output Opus — 10K output. Should be skipped (output >= 5K).
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "eO", SessionID: "sHighOutput",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "b.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sHighOutput", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 10_000, OutputTokens: 10_000,
		Timestamp: time.Now().UTC().Add(-24 * time.Hour), RequestID: "msg_o",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openRouting(t, server, 7)
	for _, s := range got.Suggestions {
		if s.SessionID == "sHeavy" || s.SessionID == "sHighOutput" {
			t.Errorf("expected skip but got suggestion for %s: %+v", s.SessionID, s)
		}
	}
}

// TestAnalysisRoutingSuggestions_MixedModelSkipped: a session that
// mixed Opus and Sonnet is intentional routing — leave it alone.
func TestAnalysisRoutingSuggestions_MixedModelSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "eM", SessionID: "sMixed",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	for i, model := range []string{"claude-opus-4-7", "claude-sonnet-4-6"} {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sMixed", Provider: models.ProviderAnthropic,
			Model: model, InputTokens: 5_000, OutputTokens: 1_000,
			Timestamp: time.Now().UTC().Add(-time.Duration(i+1) * 24 * time.Hour),
			RequestID: "msg_m_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openRouting(t, server, 7)
	for _, s := range got.Suggestions {
		if s.SessionID == "sMixed" {
			t.Errorf("mixed-model session should NOT be flagged: %+v", s)
		}
	}
}

// TestAnalysisRoutingSuggestions_EmptyDB returns an empty list, not 500.
func TestAnalysisRoutingSuggestions_EmptyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openRouting(t, server, 30)
	if len(got.Suggestions) != 0 || got.TotalSaving != 0 {
		t.Errorf("empty DB: %+v", got)
	}
}

// TestAnalysisRoutingSuggestions_DatedPricingLadder pins the recorded →
// dated → undated ladder in handleAnalysisRoutingSuggestions's per-row
// pricing: a recorded turn wins verbatim, an unrecorded turn before the
// synthetic boundary prices at the OLD dated rate, and one after prices
// at the NEW/current rate — folded into the flagged session's
// CurrentCostUSD (and therefore its SavingsUSD against the forward-
// looking Sonnet-4.6 projection, which correctly stays undated).
func TestAnalysisRoutingSuggestions_DatedPricingLadder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	boundary := now.Add(-36 * time.Hour)

	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e_ladder_r", SessionID: "sLadderRoute",
		ProjectRoot: root, Timestamp: now.Add(-3 * 24 * time.Hour), Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "x.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	insertTurn := func(ts time.Time, usd float64, reqID string) {
		t.Helper()
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sLadderRoute", Provider: models.ProviderAnthropic,
			Model: ladderOpusModel, InputTokens: ladderTrivialBundle.Input, OutputTokens: ladderTrivialBundle.Output,
			Timestamp: ts, RequestID: reqID, CostUSD: usd,
		}); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn(now.Add(-2*24*time.Hour), 0.5, "msg_route_recorded")    // recorded — must win verbatim
	insertTurn(now.Add(-2*24*time.Hour-time.Hour), 0, "msg_route_old") // before boundary — OLD dated rate
	insertTurn(now.Add(-time.Hour), 0, "msg_route_new")                // after boundary — NEW/current rate

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	server.opts.CostEngine = newLadderTestEngine(t, boundary)

	got := openRouting(t, server, 30)
	if len(got.Suggestions) != 1 || got.Suggestions[0].SessionID != "sLadderRoute" {
		t.Fatalf("suggestions: got %+v", got.Suggestions)
	}
	s := got.Suggestions[0]
	wantCurrent := 0.5 + ladderOldTrivialCost + ladderNewTrivialCost
	if diff := s.CurrentCostUSD - wantCurrent; diff > 0.001 || diff < -0.001 {
		t.Errorf("current_cost_usd: got %f want %f (recorded=0.5 old=%.3f new=%.3f)",
			s.CurrentCostUSD, wantCurrent, ladderOldTrivialCost, ladderNewTrivialCost)
	}
}

// trendResponse mirrors /api/analysis/trend's JSON shape for tests.
type trendResponse struct {
	Metric string `json:"metric"`
	Dim    string `json:"dim"`
	Bucket string `json:"bucket"`
	Days   int    `json:"days"`
	Series []struct {
		Bucket      string  `json:"bucket"`
		Key         string  `json:"key"`
		TotalTokens int64   `json:"total_tokens"`
		CostUSD     float64 `json:"cost_usd"`
		TurnCount   int     `json:"turn_count"`
	} `json:"series"`
}

func openTrend(t *testing.T, server *Server, dim string, days int) trendResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/trend?dim="+dim+"&days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/trend?dim=%s: %d body=%s", dim, rr.Code, rr.Body.String())
	}
	var got trendResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisTrend_EmptyAndUnknownDim verifies the empty-DB path
// returns an empty series, and that an invalid dim is rejected.
func TestAnalysisTrend_EmptyAndUnknownDim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openTrend(t, server, "model", 30)
	if got.Dim != "model" || got.Days != 30 {
		t.Errorf("echo: dim=%q days=%d", got.Dim, got.Days)
	}
	if len(got.Series) != 0 {
		t.Errorf("empty DB series: got %d points", len(got.Series))
	}

	// Unknown dim → 400.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/analysis/trend?dim=invalid", nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Errorf("unknown dim: got %d want 400", rr.Code)
	}
}

// TestAnalysisTrend_GroupsByDimension seeds turns from two projects
// running two tools across two days, then verifies each dimension
// rolls up correctly. The dim toggle on the page rides this contract.
func TestAnalysisTrend_GroupsByDimension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)

	now := time.Now().UTC()
	day1 := now.Add(-2 * 24 * time.Hour)
	day2 := now.Add(-1 * 24 * time.Hour)
	repoA := t.TempDir()
	repoB := t.TempDir()

	// Two sessions, different projects, different tools. Token counts
	// kept small so cost stays at standard rates (no LC dispatch).
	for _, ev := range []struct {
		sid, eid, ts string
		root         string
		tool         string
	}{
		{"sA", "eA", day1.Format(time.RFC3339Nano), repoA, models.ToolClaudeCode},
		{"sB", "eB", day2.Format(time.RFC3339Nano), repoB, models.ToolCodex},
	} {
		ts, _ := time.Parse(time.RFC3339Nano, ev.ts)
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: "f", SourceEventID: ev.eid, SessionID: ev.sid,
			ProjectRoot: ev.root, Timestamp: ts, Tool: ev.tool,
			ActionType: models.ActionReadFile, Target: "x.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	// Two proxy turns, one per session. 10K input + 5K output × Sonnet
	// 4.6 = $0.10 each. Different days, different (project, tool).
	// Look up each session's project_id so the api_turns row joins back
	// to a project root_path — without it the GroupByDayProject rollup
	// groups everything under "<no-project>".
	projectIDFor := func(sessionID string) int64 {
		var pid int64
		if err := database.QueryRow(
			`SELECT project_id FROM sessions WHERE id = ?`, sessionID,
		).Scan(&pid); err != nil {
			t.Fatalf("project_id for %s: %v", sessionID, err)
		}
		return pid
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", ProjectID: projectIDFor("sA"),
		Provider: models.ProviderAnthropic,
		Model:    "claude-sonnet-4-6", InputTokens: 10_000, OutputTokens: 5_000,
		Timestamp: day1, RequestID: "msg_A",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sB", ProjectID: projectIDFor("sB"),
		Provider: models.ProviderOpenAI,
		Model:    "gpt-5.1", InputTokens: 10_000, OutputTokens: 5_000,
		Timestamp: day2, RequestID: "msg_B",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}

	// dim=model → 2 series points (one per model, on different days).
	got := openTrend(t, server, "model", 7)
	if len(got.Series) != 2 {
		t.Fatalf("model series: got %d want 2", len(got.Series))
	}
	models := map[string]bool{}
	for _, p := range got.Series {
		models[p.Key] = true
	}
	if !models["claude-sonnet-4-6"] || !models["gpt-5.1"] {
		t.Errorf("model keys: got %v want claude-sonnet-4-6 + gpt-5.1", models)
	}

	// dim=project → 2 series points (one per project root).
	got = openTrend(t, server, "project", 7)
	if len(got.Series) != 2 {
		t.Fatalf("project series: got %d want 2 (one per project)", len(got.Series))
	}
	projects := map[string]bool{}
	for _, p := range got.Series {
		projects[p.Key] = true
	}
	if !projects[repoA] || !projects[repoB] {
		t.Errorf("project keys: got %v want %s + %s", projects, repoA, repoB)
	}

	// dim=tool → 2 series points (claude-code + codex).
	got = openTrend(t, server, "tool", 7)
	if len(got.Series) != 2 {
		t.Fatalf("tool series: got %d want 2 (one per tool)", len(got.Series))
	}
	tools := map[string]bool{}
	for _, p := range got.Series {
		tools[p.Key] = true
	}
	if !tools["claude-code"] || !tools["codex"] {
		t.Errorf("tool keys: got %v want claude-code + codex", tools)
	}
}

// moversResponse mirrors /api/analysis/movers's JSON for tests.
type moversResponse struct {
	Dim         string         `json:"dim"`
	Days        int            `json:"days"`
	Increases   []moverEntry   `json:"increases"`
	Decreases   []moverEntry   `json:"decreases"`
	NewEntrants []entrantEntry `json:"new_entrants"`
}
type moverEntry struct {
	Key        string  `json:"key"`
	PriorUSD   float64 `json:"prior_usd"`
	CurrentUSD float64 `json:"current_usd"`
	DeltaUSD   float64 `json:"delta_usd"`
	DeltaPct   float64 `json:"delta_pct"`
}
type entrantEntry struct {
	Key        string  `json:"key"`
	CurrentUSD float64 `json:"current_usd"`
}

func openMovers(t *testing.T, server *Server, dim string, days int) moversResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/movers?dim="+dim+"&days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/movers?dim=%s: %d body=%s", dim, rr.Code, rr.Body.String())
	}
	var got moversResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisMovers_PeriodOverPeriod pins the diff math: a model whose
// cost rises gets surfaced in increases; one that falls in decreases;
// one new this period in new_entrants; one only in prior period appears
// as a -100% mover with current=0.
func TestAnalysisMovers_PeriodOverPeriod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sM",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	priorTs := now.Add(-10 * 24 * time.Hour)
	currentTs := now.Add(-1 * 24 * time.Hour)

	type fix struct {
		ts      time.Time
		model   string
		in, out int64
		reqID   string
	}
	for i, f := range []fix{
		// "rising" — prior $0.30, current $0.60 → +$0.30
		{priorTs, "claude-sonnet-4-6", 50_000, 10_000, "msg_rise_p"},
		{currentTs, "claude-sonnet-4-6", 100_000, 20_000, "msg_rise_c"},
		// "falling" — prior $0.60, current $0.30 → -$0.30
		{priorTs, "claude-haiku-4-5", 200_000, 100_000, "msg_fall_p"},  // 200K×$1 + 100K×$5 = 0.20+0.50=0.70
		{currentTs, "claude-haiku-4-5", 100_000, 50_000, "msg_fall_c"}, // 0.10+0.25=0.35
		// "new entrant" — only in current period
		{currentTs, "gpt-5.1", 50_000, 10_000, "msg_new_c"},
		// "departed" — only in prior period
		{priorTs, "claude-opus-4-7", 10_000, 1_000, "msg_dep_p"},
	} {
		_ = i
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sM", Provider: models.ProviderAnthropic,
			Model: f.model, InputTokens: f.in, OutputTokens: f.out,
			Timestamp: f.ts, RequestID: f.reqID,
		}); err != nil {
			t.Fatal(err)
		}
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openMovers(t, server, "model", 7)

	// Increases: should include claude-sonnet-4-6 (Δ +0.30).
	foundRise := false
	for _, m := range got.Increases {
		if m.Key == "claude-sonnet-4-6" {
			foundRise = true
			if !approx(m.DeltaUSD, 0.30) {
				t.Errorf("rise delta: got %v want 0.30", m.DeltaUSD)
			}
		}
	}
	if !foundRise {
		t.Errorf("increases missing claude-sonnet-4-6: %+v", got.Increases)
	}

	// Decreases: should include claude-haiku-4-5 (Δ -0.35) AND
	// claude-opus-4-7 (the departed model — current=0, delta=-prior).
	foundFall, foundDep := false, false
	for _, m := range got.Decreases {
		if m.Key == "claude-haiku-4-5" {
			foundFall = true
		}
		if m.Key == "claude-opus-4-7" {
			foundDep = true
			if m.CurrentUSD != 0 || m.DeltaPct != -100 {
				t.Errorf("departed model: got %+v want current=0 deltaPct=-100", m)
			}
		}
	}
	if !foundFall {
		t.Errorf("decreases missing claude-haiku-4-5: %+v", got.Decreases)
	}
	if !foundDep {
		t.Errorf("decreases missing claude-opus-4-7 (departed): %+v", got.Decreases)
	}

	// New entrants: gpt-5.1 only.
	if len(got.NewEntrants) != 1 || got.NewEntrants[0].Key != "gpt-5.1" {
		t.Errorf("new entrants: got %+v want [gpt-5.1]", got.NewEntrants)
	}
}

// TestAnalysisMovers_EmptyAndUnknownDim handles fresh DB + invalid dim.
func TestAnalysisMovers_EmptyAndUnknownDim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openMovers(t, server, "model", 30)
	if len(got.Increases) != 0 || len(got.Decreases) != 0 || len(got.NewEntrants) != 0 {
		t.Errorf("empty DB movers: %+v", got)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/analysis/movers?dim=invalid", nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Errorf("unknown dim: got %d want 400", rr.Code)
	}
}

// topSessionsResponse mirrors /api/analysis/top-sessions's JSON for tests.
type topSessionsResponse struct {
	Days     int `json:"days"`
	Limit    int `json:"limit"`
	Sessions []struct {
		ID        string   `json:"id"`
		Tool      string   `json:"tool"`
		Models    []string `json:"models"`
		Turns     int      `json:"turns"`
		MaxPrompt int64    `json:"max_prompt_tokens"`
		LCTurns   int      `json:"lc_turn_count"`
		CostUSD   float64  `json:"cost_usd"`
		Badges    []string `json:"badges"`
	} `json:"sessions"`
}

func openTopSessions(t *testing.T, server *Server, days, limit int) topSessionsResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/top-sessions?days="+itoa(days)+"&limit="+itoa(limit), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/top-sessions: %d body=%s", rr.Code, rr.Body.String())
	}
	var got topSessionsResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisTopSessions_RankingAndBadges sets up four sessions with
// distinct cost profiles and verifies (a) cost-ordering, (b) badge
// attribution, (c) tool/started_at enrichment from the sessions table.
func TestAnalysisTopSessions_RankingAndBadges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()

	// Each session needs an action row so it lands in the sessions
	// table; that's where tool / started_at come from for enrichment.
	seedSession := func(sid, tool string, ts time.Time) {
		t.Helper()
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e_" + sid, SessionID: sid,
			ProjectRoot: root, Timestamp: ts, Tool: tool,
			ActionType: models.ActionReadFile, Target: "x.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
	}

	// Session A — Opus, big single turn, $4.00 → top of the list,
	// badges: opus, large_prompt (250K > 100K).
	seedSession("sA", models.ToolClaudeCode, now.Add(-2*24*time.Hour))
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sA", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", InputTokens: 250_000, OutputTokens: 100_000,
		Timestamp: now.Add(-2 * 24 * time.Hour), RequestID: "msg_A",
	}); err != nil {
		t.Fatal(err)
	}

	// Session B — Sonnet 4 LC tier turn (250K) → cost $1.6125,
	// badges: lc_tier, large_prompt.
	seedSession("sB", models.ToolClaudeCode, now.Add(-1*24*time.Hour))
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sB", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-20250514", InputTokens: 250_000, OutputTokens: 5_000,
		Timestamp: now.Add(-1 * 24 * time.Hour), RequestID: "msg_B",
	}); err != nil {
		t.Fatal(err)
	}

	// Session C — many small Sonnet 4.6 turns (35 turns) → many_turns badge.
	seedSession("sC", models.ToolCodex, now.Add(-3*24*time.Hour))
	for i := 0; i < 35; i++ {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sC", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 5_000, OutputTokens: 1_000,
			Timestamp: now.Add(-3 * 24 * time.Hour),
			RequestID: "msg_C_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Session D — small, no badges. Should rank last.
	seedSession("sD", models.ToolClaudeCode, now.Add(-4*24*time.Hour))
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sD", Provider: models.ProviderAnthropic,
		Model: "claude-haiku-4-5", InputTokens: 1_000, OutputTokens: 500,
		Timestamp: now.Add(-4 * 24 * time.Hour), RequestID: "msg_D",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openTopSessions(t, server, 7, 10)
	if len(got.Sessions) != 4 {
		t.Fatalf("session count: got %d want 4", len(got.Sessions))
	}

	// Cost ranking: A > B > C > D.
	if got.Sessions[0].ID != "sA" {
		t.Errorf("rank 1: got %q want sA", got.Sessions[0].ID)
	}
	if got.Sessions[1].ID != "sB" {
		t.Errorf("rank 2: got %q want sB", got.Sessions[1].ID)
	}
	if got.Sessions[3].ID != "sD" {
		t.Errorf("rank last: got %q want sD", got.Sessions[3].ID)
	}

	// Badges per session.
	badgeOf := func(sid string) []string {
		for _, s := range got.Sessions {
			if s.ID == sid {
				return s.Badges
			}
		}
		return nil
	}
	hasBadge := func(badges []string, want string) bool {
		for _, b := range badges {
			if b == want {
				return true
			}
		}
		return false
	}

	bA := badgeOf("sA")
	if !hasBadge(bA, "opus") || !hasBadge(bA, "large_prompt") {
		t.Errorf("sA badges: got %v want opus + large_prompt", bA)
	}
	bB := badgeOf("sB")
	if !hasBadge(bB, "lc_tier") || !hasBadge(bB, "large_prompt") {
		t.Errorf("sB badges: got %v want lc_tier + large_prompt", bB)
	}
	bC := badgeOf("sC")
	if !hasBadge(bC, "many_turns") {
		t.Errorf("sC badges: got %v want many_turns", bC)
	}
	if hasBadge(bC, "opus") {
		t.Errorf("sC must NOT have opus badge: %v", bC)
	}
	bD := badgeOf("sD")
	if len(bD) != 0 {
		t.Errorf("sD should have no badges: got %v", bD)
	}

	// Tool enrichment.
	for _, s := range got.Sessions {
		if s.ID == "sC" && s.Tool != models.ToolCodex {
			t.Errorf("sC tool: got %q want codex", s.Tool)
		}
		if s.ID == "sA" && s.Tool != models.ToolClaudeCode {
			t.Errorf("sA tool: got %q want claude-code", s.Tool)
		}
	}
}

// TestAnalysisTopSessions_DatedPricingLadder pins the recorded → dated
// → undated ladder in handleAnalysisTopSessions's per-row pricing: a
// recorded turn wins verbatim, an unrecorded turn before the synthetic
// boundary prices at the OLD dated rate, and one after prices at the
// NEW/current rate — folded into one session's CostUSD.
func TestAnalysisTopSessions_DatedPricingLadder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	now := time.Now().UTC()
	boundary := now.Add(-36 * time.Hour)

	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e_ladder", SessionID: "sLadder",
		ProjectRoot: root, Timestamp: now.Add(-3 * 24 * time.Hour), Tool: models.ToolClaudeCode,
		ActionType: models.ActionReadFile, Target: "x.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	insertTurn := func(ts time.Time, usd float64, reqID string) {
		t.Helper()
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sLadder", Provider: models.ProviderAnthropic,
			Model: ladderModel, InputTokens: ladderBundle.Input, OutputTokens: ladderBundle.Output,
			Timestamp: ts, RequestID: reqID, CostUSD: usd,
		}); err != nil {
			t.Fatal(err)
		}
	}
	insertTurn(now.Add(-2*24*time.Hour), 9.99, "msg_ladder_recorded")   // recorded — must win verbatim
	insertTurn(now.Add(-2*24*time.Hour-time.Hour), 0, "msg_ladder_old") // before boundary — OLD dated rate
	insertTurn(now.Add(-time.Hour), 0, "msg_ladder_new")                // after boundary — NEW/current rate

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	server.opts.CostEngine = newLadderTestEngine(t, boundary)

	got := openTopSessions(t, server, 30, 10)
	if len(got.Sessions) != 1 || got.Sessions[0].ID != "sLadder" {
		t.Fatalf("sessions: got %+v", got.Sessions)
	}
	want := 9.99 + ladderOldCost + ladderNewCost
	if diff := got.Sessions[0].CostUSD - want; diff > 0.001 || diff < -0.001 {
		t.Errorf("cost_usd: got %f want %f (recorded=9.99 old=%.2f new=%.2f)",
			got.Sessions[0].CostUSD, want, ladderOldCost, ladderNewCost)
	}
}

// TestAnalysisTopSessions_LimitAndEmpty pins the limit param and the
// empty-DB path.
func TestAnalysisTopSessions_LimitAndEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openTopSessions(t, server, 30, 5)
	if got.Limit != 5 || len(got.Sessions) != 0 {
		t.Errorf("empty DB: got limit=%d sessions=%d", got.Limit, len(got.Sessions))
	}
}

// costByHourResponse mirrors /api/analysis/cost-by-hour for tests.
type costByHourResponse struct {
	Days     int    `json:"days"`
	Timezone string `json:"timezone"`
	Buckets  []struct {
		Hour      int     `json:"hour"`
		CostUSD   float64 `json:"cost_usd"`
		TurnCount int     `json:"turn_count"`
	} `json:"buckets"`
}

func openCostByHour(t *testing.T, server *Server, days int) costByHourResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/cost-by-hour?days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/cost-by-hour: %d body=%s", rr.Code, rr.Body.String())
	}
	var got costByHourResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisCostByHour_EmptyAlwaysReturns24Buckets — empty DB still
// returns the full 0..23 bucket scaffold with zero cost; chart code can
// assume the array length is 24.
func TestAnalysisCostByHour_EmptyAlwaysReturns24Buckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openCostByHour(t, server, 30)
	if got.Timezone != "UTC" {
		t.Errorf("timezone: got %q want UTC", got.Timezone)
	}
	if len(got.Buckets) != 24 {
		t.Fatalf("buckets length: got %d want 24", len(got.Buckets))
	}
	for i, b := range got.Buckets {
		if b.Hour != i {
			t.Errorf("bucket %d: hour=%d want %d", i, b.Hour, i)
		}
		if b.CostUSD != 0 || b.TurnCount != 0 {
			t.Errorf("bucket %d non-zero on empty DB: %+v", i, b)
		}
	}
}

// TestAnalysisCostByHour_BucketsByUTCHour seeds three turns at known
// UTC hours and verifies the bucket attribution + cost math.
func TestAnalysisCostByHour_BucketsByUTCHour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sCBH",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Yesterday at 03:00 + 03:30 UTC (same hour bucket) + 14:00 UTC.
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	h03 := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 3, 0, 0, 0, time.UTC)
	h14 := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 14, 0, 0, 0, time.UTC)
	for i, ts := range []time.Time{h03, h03.Add(30 * time.Minute), h14} {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sCBH", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: 10_000, OutputTokens: 5_000,
			Timestamp: ts, RequestID: "msg_cbh_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openCostByHour(t, server, 7)
	// hour=3 has 2 turns × ($0.030 input + $0.075 output) = 2 × $0.105 = $0.21
	if got.Buckets[3].TurnCount != 2 {
		t.Errorf("hour 3 turns: got %d want 2", got.Buckets[3].TurnCount)
	}
	if !approx(got.Buckets[3].CostUSD, 0.21) {
		t.Errorf("hour 3 cost: got %v want 0.21", got.Buckets[3].CostUSD)
	}
	// hour=14 has 1 turn × $0.105 = $0.105
	if got.Buckets[14].TurnCount != 1 {
		t.Errorf("hour 14 turns: got %d want 1", got.Buckets[14].TurnCount)
	}
	if !approx(got.Buckets[14].CostUSD, 0.105) {
		t.Errorf("hour 14 cost: got %v want 0.105", got.Buckets[14].CostUSD)
	}
	// All other buckets must be zero.
	for i, b := range got.Buckets {
		if i == 3 || i == 14 {
			continue
		}
		if b.CostUSD != 0 || b.TurnCount != 0 {
			t.Errorf("bucket %d should be zero, got %+v", i, b)
		}
	}
}

// cacheSavingsTrendResponse mirrors /api/analysis/cache-savings-trend.
type cacheSavingsTrendResponse struct {
	Days   int `json:"days"`
	Points []struct {
		Day             string  `json:"day"`
		SavingsUSD      float64 `json:"savings_usd"`
		CacheReadTokens int64   `json:"cache_read_tokens"`
	} `json:"points"`
}

func openCacheSavingsTrend(t *testing.T, server *Server, days int) cacheSavingsTrendResponse {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/api/analysis/cache-savings-trend?gran=1d&days="+itoa(days), nil)
	server.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /api/analysis/cache-savings-trend: %d body=%s", rr.Code, rr.Body.String())
	}
	var got cacheSavingsTrendResponse
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// TestAnalysisCacheSavingsTrend_EmptyReturnsNoPoints — empty DB is a
// zero-filled all-zero series, not an error.
func TestAnalysisCacheSavingsTrend_EmptyReturnsNoPoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openCacheSavingsTrend(t, server, 30)
	// The grid is zero-filled (30-31 day buckets), every one of them zero.
	if n := len(got.Points); n < 30 || n > 31 {
		t.Errorf("empty DB points: got %d want the 30-31 day zero-filled grid", n)
	}
	for _, p := range got.Points {
		if p.SavingsUSD != 0 || p.CacheReadTokens != 0 {
			t.Errorf("empty DB point %s is non-zero: %+v", p.Day, p)
		}
	}
}

// TestAnalysisCacheSavingsTrend_DailySavingsAttribution pins the
// counterfactual savings math per day. Two Sonnet 4.6 turns on the same
// day with 100K cache_read each → savings = 2 × $0.27 = $0.54.
// A separate Opus 4.7 turn next day with 50K cache_read at the Opus
// rates (input $5/M, cache_read $0.50/M) → savings = 50K × ($5 − $0.50)/M = $0.225.
//
// A fourth turn on day B is proxy-recorded (CostUSD set) on Sonnet 4.6
// with 1M cache_read tokens. Post-2026-07-30 fix, a recorded row still
// contributes its priced counterfactual delta — 1,000,000 × ($3 −
// $0.30)/1M = $2.70 — because the pricing table gives a basis to
// decompose it even though the proxy's own total is opaque; only rows
// on models with NO pricing entry are excluded. Day B total is
// therefore 0.225 + 2.70 = 2.925, and day B's cache_read_tokens
// includes the recorded row's 1M (50,000 + 1,000,000 = 1,050,000).
func TestAnalysisCacheSavingsTrend_DailySavingsAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sCST",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Anchor at noon UTC of each day so adding intra-day offsets
	// (e.g. +1h, +2h) can't cross midnight into the wrong calendar
	// day. Without the Truncate, this test fires false-positives
	// when the wall clock is within an hour of UTC midnight: dayA.Add(1h)
	// then lands on day B's calendar and one Sonnet turn's $0.27
	// savings get attributed to the wrong day. Verified 2026-05-19
	// at 23:14 UTC where this exact failure mode hit CI.
	dayA := time.Now().UTC().Add(-3 * 24 * time.Hour).Truncate(24 * time.Hour).Add(12 * time.Hour)
	dayB := time.Now().UTC().Add(-2 * 24 * time.Hour).Truncate(24 * time.Hour).Add(12 * time.Hour)
	for i := 0; i < 2; i++ {
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "sCST", Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", CacheReadTokens: 100_000,
			Timestamp: dayA.Add(time.Duration(i) * time.Hour),
			RequestID: "msg_cst_a_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCST", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-7", CacheReadTokens: 50_000,
		Timestamp: dayB, RequestID: "msg_cst_b",
	}); err != nil {
		t.Fatal(err)
	}
	// Recorded-cost row — now DOES contribute its priced counterfactual
	// delta (see the fix note above); the proxy's own $0.05 total is not
	// used for the savings math, only as the "this row is recorded"
	// signal that no longer suppresses attribution.
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sCST", Provider: models.ProviderAnthropic,
		Model: "claude-sonnet-4-6", CacheReadTokens: 1_000_000,
		Timestamp: dayB.Add(2 * time.Hour), RequestID: "msg_cst_recorded",
		CostUSD: 0.05,
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openCacheSavingsTrend(t, server, 7)
	byDay := map[string]float64{}
	tokenByDay := map[string]int64{}
	for _, p := range got.Points {
		byDay[p.Day] += p.SavingsUSD
		tokenByDay[p.Day] += p.CacheReadTokens
	}
	dayAKey := dayA.Format("2006-01-02")
	dayBKey := dayB.Format("2006-01-02")
	if !approx(byDay[dayAKey], 0.54) {
		t.Errorf("day A savings: got %v want 0.54", byDay[dayAKey])
	}
	if !approx(byDay[dayBKey], 2.925) {
		t.Errorf("day B savings: got %v want 2.925 (0.225 opus + 2.70 recorded-row delta)", byDay[dayBKey])
	}
	if tokenByDay[dayBKey] != 1_050_000 {
		t.Errorf("day B cache_read_tokens (recorded row now included): got %d want 1050000",
			tokenByDay[dayBKey])
	}
}

// TestAnalysisCacheSavingsTrend_FastTierPricedAtFastRate is the F6
// regression test (2026-07-30 adversarial review) for
// handleAnalysisCacheSavingsTrend. Same defect as the headline tile: the
// query didn't select the fast column, so every counterfactual delta
// priced at standard rates regardless of the turn's actual fast-tier
// status.
//
// One claude-opus-4-8 turn (FastMultiplier=2), Fast=true, 100,000
// cache_read tokens:
//   - actual = 100K × $0.50/M cache_read × fast(2) = $0.10
//   - alt    = 100K × $5.00/M input      × fast(2) = $1.00
//   - delta  = $0.90
//
// Pre-fix (fast never scanned) the same shapes price at standard rates:
// actual=$0.05, alt=$0.50, delta=$0.45 — half the correct value.
func TestAnalysisCacheSavingsTrend_FastTierPricedAtFastRate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "sFastCST",
		ProjectRoot: root, Timestamp: time.Now().UTC().Add(-time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Add(-24 * time.Hour).Truncate(24 * time.Hour).Add(12 * time.Hour)
	if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
		SessionID: "sFastCST", Provider: models.ProviderAnthropic,
		Model: "claude-opus-4-8", CacheReadTokens: 100_000, Fast: true,
		Timestamp: day, RequestID: "msg_fast_cst",
	}); err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openCacheSavingsTrend(t, server, 7)
	dayKey := day.Format("2006-01-02")
	var savings float64
	for _, p := range got.Points {
		if p.Day == dayKey {
			savings = p.SavingsUSD
		}
	}
	const wantSavings = 0.90
	if !approx(savings, wantSavings) {
		t.Errorf("day savings: got %v want %v (fast-tier delta undercounted if fast wasn't scanned)",
			savings, wantSavings)
	}
}

// TestAnalysisTrend_ChronologicalOrder pins the rendering contract:
// chart axes read left-to-right by day. Cost engine returns rows by
// cost DESC so the handler must re-sort before serializing.
func TestAnalysisTrend_ChronologicalOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	root := t.TempDir()

	now := time.Now().UTC()
	// Three days, smallest cost first chronologically (so the
	// cost-DESC default would put it last in the wire).
	for i, in := range []int64{1_000, 100_000, 10_000} {
		ts := now.Add(-time.Duration(3-i) * 24 * time.Hour)
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e" + itoa(i), SessionID: "s" + itoa(i),
			ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
			ActionType: models.ActionReadFile, Target: "x.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InsertAPITurn(context.Background(), models.APITurn{
			SessionID: "s" + itoa(i), Provider: models.ProviderAnthropic,
			Model: "claude-sonnet-4-6", InputTokens: in,
			Timestamp: ts, RequestID: "msg_" + itoa(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	server, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	got := openTrend(t, server, "model", 7)
	for i := 1; i < len(got.Series); i++ {
		if got.Series[i].Bucket < got.Series[i-1].Bucket {
			t.Errorf("series not chronological at %d: %s < %s",
				i, got.Series[i].Bucket, got.Series[i-1].Bucket)
		}
	}
}
