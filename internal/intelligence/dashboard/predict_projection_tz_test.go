package dashboard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/predict"
)

func projTZ(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, time.UTC)
}

// TestHandleSessionPredict_OrgBudgetInItsOwnZone is the handler end to end:
// an org window the daemon wrote with its zone is bucketed in that zone and
// carries no "timezone assumed" note; one from an older daemon still does.
func TestHandleSessionPredict_OrgBudgetInItsOwnZone(t *testing.T) {
	t.Parallel()
	database, cleanup := openForecastTestDB(t)
	defer cleanup()
	seedPredictSession(t, database, "sTZ", "claude-opus-4-8")
	now := projTZ(2026, 11, 11, 6, 0) // 22:00 on Nov 10 in Los Angeles
	seedRecentUsage(t, database, "sTZ", now)

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := budgetwarnfile.Write(budgetwarnfile.StatusPath(dbPath), budgetwarnfile.File{
		WrittenAt: now,
		Windows: []budgetwarnfile.Window{
			{Window: "daily", Unit: "usd", Period: "2026-11-10", Timezone: "America/Los_Angeles", Cap: 20, Spent: 10, Scope: "team:west", Enforcement: "hard"},
			{Window: "monthly", Unit: "tokens", Period: "2026-11", Cap: 1_000_000, Spent: 1000, Scope: "org", Enforcement: "soft"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv := &Server{opts: Options{DB: database, CostEngine: newForecastTestEngine(t), ConfigPath: cfgPath}, now: func() time.Time { return now }}
	resp, _ := getPredict(t, srv, "sTZ")
	var daily, monthly *predict.Projection
	for i := range resp.Projection.Budgets {
		switch resp.Projection.Budgets[i].Key {
		case "daily":
			daily = &resp.Projection.Budgets[i]
		case "monthly":
			monthly = &resp.Projection.Budgets[i]
		}
	}
	if daily == nil || monthly == nil {
		t.Fatalf("budgets %+v", resp.Projection.Budgets)
	}
	if daily.WindowStartUnix == nil || *daily.WindowStartUnix != projTZ(2026, 11, 10, 8, 0).Unix() ||
		daily.ResetsAtUnix == nil || *daily.ResetsAtUnix != projTZ(2026, 11, 11, 8, 0).Unix() {
		t.Fatalf("daily window %v .. %v, want the Los Angeles day", daily.WindowStartUnix, daily.ResetsAtUnix)
	}
	for _, n := range daily.Notes {
		if n == predict.NoteTimezoneAssumed {
			t.Errorf("a zoned window must not say its zone was assumed: %v", daily.Notes)
		}
	}
	assumed := false
	for _, n := range monthly.Notes {
		assumed = assumed || n == predict.NoteTimezoneAssumed
	}
	if !assumed {
		t.Errorf("a window from an older daemon keeps the assumption note: %v", monthly.Notes)
	}
}
