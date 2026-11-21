package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// TestPlanFromTemplateReproducesTheV5Rows pins the projection to cloud
// migration 0079's two v5 rows, column by column: generating them from the
// catalog changes no production row.
func TestPlanFromTemplateReproducesTheV5Rows(t *testing.T) {
	t.Parallel()
	const haiku = "session_enrichment.claude-haiku-5-5.v1"
	want := []Plan{
		{
			Name: PlanFree, Version: 5, Label: "Signed-in Free", DailyCap: 100, MonthlyCap: 3000, ConcurrencyCap: 2,
			BudgetPool: FreeBudgetPool, DigestWeekly: false, ResultsRetentionDays: 30, RouteID: haiku, EnrichmentTier: "free",
		},
		{
			Name: PlanPlusBeta, Version: 5, Label: "Plus", DailyCap: 500, MonthlyCap: 15000, ConcurrencyCap: 4,
			BudgetPool: "plus_beta", DigestWeekly: true, ResultsRetentionDays: 365, RouteID: haiku, EnrichmentTier: "paid",
		},
	}
	got, err := GeneratedPlans()
	if err != nil {
		t.Fatalf("GeneratedPlans: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("GeneratedPlans = %d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v\nwant     %+v", i, got[i], want[i])
		}
	}
}

// TestPlanFromTemplateRefusals: one row per projection refusal.
func TestPlanFromTemplateRefusals(t *testing.T) {
	t.Parallel()
	free, ok := entitlements.Plan(PlanFree, DefaultFreePlanVersion)
	if !ok {
		t.Fatal("no free template")
	}
	team, _ := entitlements.Plan("team", 0)
	for _, tc := range []struct {
		name string
		mut  func(b *entitlements.Body)
		want string
	}{
		{name: "another kind", mut: func(b *entitlements.Body) { *b = team }, want: "only account templates"},
		{name: "a missing cap", mut: func(b *entitlements.Body) { delete(b.Caps, entitlements.CapEnrichmentDaily) }, want: "daily_cap: the template sets no"},
		{name: "an Unlimited cap", mut: func(b *entitlements.Body) { b.Caps[entitlements.CapEnrichmentConcurrency] = entitlements.Unlimited }, want: "concurrency_cap"},
		{name: "a missing budget pool", mut: func(b *entitlements.Body) { delete(b.Terms, entitlements.TermEnrichmentBudgetPool) }, want: "budget_pool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := free.Normalized()
			tc.mut(&b)
			_, err := PlanFromTemplate(b)
			if !errors.Is(err, ErrPlanDrift) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PlanFromTemplate = %v, want %q", err, tc.want)
			}
		})
	}
	noRoute := free.Normalized()
	delete(noRoute.Terms, entitlements.TermEnrichmentRoute)
	if p, err := PlanFromTemplate(noRoute); err != nil || p.RouteID != "" {
		t.Fatalf("an optional term left out = %+v, %v", p, err)
	}
}

// TestTheStoreConstantsAreTheCatalogs: the plan constants this package
// branches on are the catalog's names and the account floor's version, so a
// catalog bump that forgets DefaultFreePlanVersion fails here.
func TestTheStoreConstantsAreTheCatalogs(t *testing.T) {
	t.Parallel()
	floor, ok := entitlements.Floor(entitlements.KindAccount)
	if !ok {
		t.Fatal("no account floor")
	}
	if floor.Plan.Name != PlanFree || floor.Plan.Version != DefaultFreePlanVersion {
		t.Errorf("account floor = %s v%d, want %s v%d", floor.Plan.Name, floor.Plan.Version, PlanFree, DefaultFreePlanVersion)
	}
	if floor.Terms[entitlements.TermEnrichmentBudgetPool] != FreeBudgetPool {
		t.Errorf("floor budget pool = %q, want %q", floor.Terms[entitlements.TermEnrichmentBudgetPool], FreeBudgetPool)
	}
	if _, ok := entitlements.Plan(PlanPlusBeta, 0); !ok {
		t.Errorf("%s is not a catalog plan", PlanPlusBeta)
	}
}

// TestPlansAreWrittenOnlyByTheGenerator is the structural half of "plans
// written only by the generator" (plan 07 M7b.1): no production Go file of
// the cloud service but plangen.go inserts into plans, and no cloud
// migration after 0084 does (0084's trigger is the database half).
func TestPlansAreWrittenOnlyByTheGenerator(t *testing.T) {
	t.Parallel()
	insert := regexp.MustCompile(`(?i)insert\s+into\s+plans\b`)
	for _, root := range []string{"..", filepath.Join("..", "..", "..", "cmd", "observer-cloud")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.Base(path) == "plangen.go" && filepath.Base(filepath.Dir(path)) == "store" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if insert.Match(b) {
				t.Errorf("%s inserts into plans: add a catalog row to internal/entitlements instead", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	dir := filepath.Join("..", "db", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		n, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || n <= 84 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if insert.Match(b) {
			t.Errorf("cloud migration %s inserts into plans: plans are generated from internal/entitlements", e.Name())
		}
	}
}
