package planlimits

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// webVocab reads the dashboard's Plans & limits vocabulary: plans.ts plus the
// per-lane source word files in plansSources/.
func webVocab(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("..", "..", "web", "src", "lib")
	raw, err := os.ReadFile(filepath.Join(dir, "plans.ts"))
	if err != nil {
		t.Skipf("web source not present: %v", err)
	}
	var b strings.Builder
	b.Write(raw)
	files, _ := filepath.Glob(filepath.Join(dir, "plansSources", "*.ts"))
	for _, f := range files {
		more, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("\n")
		b.Write(more)
	}
	return b.String()
}

// TestWebVocabCoversTheRegistry pins that the dashboard's vocabulary
// (web/src/lib/plans.ts and plansSources/) names every code this package can
// send: a provider, source, status, source kind, unit, gap, shows code,
// coverage, auth method, secret or parameter the page would otherwise render
// raw. The server sends codes; the page owns the words.
func TestWebVocabCoversTheRegistry(t *testing.T) {
	src := webVocab(t)
	has := func(id string) bool {
		return strings.Contains(src, `"`+id+`"`) || strings.Contains(src, "\n  "+id+":")
	}
	var want []string
	for _, p := range Providers {
		want = append(want, p.ID)
	}
	for _, s := range Sources {
		want = append(want, s.ID)
		for _, sp := range s.Secrets {
			want = append(want, sp.Key)
		}
		for _, pp := range s.Params {
			want = append(want, pp.Key)
			want = append(want, pp.Choices...)
		}
	}
	for _, k := range AllKinds() {
		want = append(want, string(k))
	}
	for _, u := range AllUnits() {
		want = append(want, string(u))
	}
	want = append(want, AllGaps()...)
	want = append(want, AllShows()...)
	for _, c := range AllCoverages() {
		want = append(want, string(c))
	}
	for _, a := range AllAuthMethods() {
		want = append(want, string(a))
	}
	want = append(want, GroupPlans, GroupBalance, GroupUsage)
	want = append(want, StatusOK, StatusThrottled, StatusPlanOnly, StatusUnmetered, StatusBilledElse,
		StatusAuthNeeded, StatusError, StatusEndpointGone, StatusStale, StatusNotOptedIn, StatusSkipped,
		HealthWaiting,
		ScopeBound, ScopeNoSession, ScopeNoObservation, ScopeConflict, ScopeExplicit)
	for _, id := range want {
		if !has(id) {
			t.Errorf("web/src/lib/plans.ts (or plansSources/) has no words for %q", id)
		}
	}
}
