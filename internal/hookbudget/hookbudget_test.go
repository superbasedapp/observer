package hookbudget

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the harness core as pure: it measures
// nothing that needs a database, the network or a child process.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") && p != "github.com/marmutapp/superbased-observer/internal/hookctx" {
				return "hookbudget may import only internal/hookctx"
			}
			return ""
		},
		Reason: "hookbudget is the harness's pure core",
	})
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestSummarize(t *testing.T) {
	hundred := make([]time.Duration, 100)
	for i := range hundred {
		hundred[i] = ms(100 - i) // reverse order: Summarize sorts a copy
	}
	cases := []struct {
		name string
		in   []time.Duration
		want Stats
	}{
		{"empty", nil, Stats{}},
		{"one", []time.Duration{ms(3)}, Stats{N: 1, Min: ms(3), P50: ms(3), P95: ms(3), P99: ms(3), Max: ms(3)}},
		{"two", []time.Duration{ms(9), ms(1)}, Stats{N: 2, Min: ms(1), P50: ms(1), P95: ms(9), P99: ms(9), Max: ms(9)}},
		{"hundred", hundred, Stats{N: 100, Min: ms(1), P50: ms(50), P95: ms(95), P99: ms(99), Max: ms(100)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]time.Duration(nil), tc.in...)
			if got := Summarize(tc.in); got != tc.want {
				t.Errorf("Summarize = %+v, want %+v", got, tc.want)
			}
			for i := range before {
				if before[i] != tc.in[i] {
					t.Fatal("Summarize modified its input")
				}
			}
		})
	}
}

func TestJudge(t *testing.T) {
	sidecar, _ := Lookup(Sidecar)
	cold, _ := Lookup(HookCold)
	cases := []struct {
		name string
		b    Budget
		s    Stats
		want Verdict
	}{
		{"no samples", sidecar, Stats{}, VerdictNotBuilt},
		{"no target", cold, Stats{N: 3, P99: time.Second}, VerdictMeasured},
		{"within", sidecar, Stats{N: 3, P99: ms(2)}, VerdictWithin},
		{"over", sidecar, Stats{N: 3, P99: ms(2) + 1}, VerdictOver},
	}
	for _, tc := range cases {
		if got := Judge(tc.b, tc.s); got != tc.want {
			t.Errorf("%s: Judge = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestBudgetTable pins the targets to the plan: the three hook-side
// security budgets of sections 4.7 and 4.8, the relay slot, and unique ids.
func TestBudgetTable(t *testing.T) {
	want := map[ID]time.Duration{
		HookCold: 0, HookWarm: 0, Seam: 0, SeamProviders: 0,
		Sidecar: 2 * time.Millisecond, Detectors: 5 * time.Millisecond, QuickScan: 2 * time.Second, Relay: 0,
		Feedback:     50 * time.Millisecond,
		ProjectMatch: 2 * time.Millisecond,
	}
	seen := map[ID]bool{}
	for _, b := range Budgets {
		if seen[b.ID] {
			t.Errorf("duplicate budget %s", b.ID)
		}
		seen[b.ID] = true
		w, ok := want[b.ID]
		if !ok {
			t.Errorf("unexpected budget %s", b.ID)
			continue
		}
		if b.P99 != w {
			t.Errorf("%s target = %v, want %v", b.ID, b.P99, w)
		}
		if b.Source == "" || b.Note == "" || b.Kind == "" {
			t.Errorf("%s lacks a source, note or kind", b.ID)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("budget table has %d rows, want %d", len(seen), len(want))
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup found an unknown id")
	}
}

func TestReportRendering(t *testing.T) {
	r := NewReport("linux/amd64", "unit test", map[ID][]time.Duration{
		HookWarm: {ms(90), ms(95)},
		Seam:     {time.Microsecond},
		Sidecar:  {ms(3)},
	})
	verdicts := map[ID]Verdict{}
	for _, row := range r.Rows {
		verdicts[row.Budget.ID] = row.Verdict
	}
	if verdicts[HookCold] != VerdictNotBuilt || verdicts[HookWarm] != VerdictMeasured ||
		verdicts[Sidecar] != VerdictOver || verdicts[Relay] != VerdictNotBuilt {
		t.Errorf("verdicts = %v", verdicts)
	}
	var text bytes.Buffer
	if err := r.Text(&text); err != nil {
		t.Fatal(err)
	}
	for _, b := range Budgets {
		if !strings.Contains(text.String(), string(b.ID)) {
			t.Errorf("text report lacks %s:\n%s", b.ID, text.String())
		}
	}
	var js bytes.Buffer
	if err := r.JSON(&js); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Platform string
		Rows     []struct {
			ID      ID
			N       int
			Verdict Verdict
		}
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back.Platform != "linux/amd64" || len(back.Rows) != len(Budgets) {
		t.Errorf("JSON report = %s (%v)", js.String(), err)
	}
}

// seamCeiling is the always-on ceiling for the seam's own cost, checked at
// p95 in every test run (CI included). It is half the smallest hook-side
// added-work budget (the 2 ms sidecar budget, security plan 6.4): the seam
// must never be what spends a budget. The measured cost is a few
// microseconds without providers and a few tens of microseconds with
// three no-op providers under the race detector, so the ceiling leaves
// more than a hundredfold headroom; p95 rather than p99 keeps a single
// garbage-collection or scheduler pause on a busy CI runner from failing
// it. Real numbers are reported, not asserted (docs/hook-budget-harness.md).
const seamCeiling = time.Millisecond

func TestSeamCostUnderCeiling(t *testing.T) {
	for _, tc := range []struct {
		id      ID
		samples func(int) []time.Duration
	}{
		{Seam, SeamSamples},
		{SeamProviders, SeamProviderSamples},
	} {
		s := Summarize(tc.samples(1000))
		t.Logf("%s: n=%d p50=%v p95=%v p99=%v max=%v", tc.id, s.N, s.P50, s.P95, s.P99, s.Max)
		if s.P95 > seamCeiling {
			t.Errorf("%s p95 = %v, over the %v ceiling (half the smallest added-work budget)", tc.id, s.P95, seamCeiling)
		}
	}
}

func BenchmarkSeam(b *testing.B) {
	for b.Loop() {
		SeamSamples(1)
	}
}

func BenchmarkSeamProviders(b *testing.B) {
	for b.Loop() {
		SeamProviderSamples(1)
	}
}
