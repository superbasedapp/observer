package orgcontract

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

// TestEveryCaptureRiskLabelIsPrioritized pins the T-873 priority table:
// every classified capture-risk label (TestEveryCaptureRiskLabelIsClassified
// pins that the class table covers every CaptureRisk* constant) has exactly
// one priority row, so a new label is placed deliberately.
func TestEveryCaptureRiskLabelIsPrioritized(t *testing.T) {
	seen := map[string]bool{}
	for _, label := range captureRiskPriority {
		if seen[label] {
			t.Errorf("%q has two priority rows", label)
		}
		seen[label] = true
		if _, ok := captureRiskClasses[label]; !ok {
			t.Errorf("%q is prioritized but not classified", label)
		}
	}
	for label := range captureRiskClasses {
		if !seen[label] {
			t.Errorf("%q has no row in captureRiskPriority", label)
		}
	}
}

// TestCaptureRiskItemLessFollowsThePriorityTable walks the table: one case per
// row, each ranked before the next, and a label with no row first (the loud
// side). Within one label the key decides.
func TestCaptureRiskItemLessFollowsThePriorityTable(t *testing.T) {
	for i := 0; i+1 < len(captureRiskPriority); i++ {
		hi, lo := captureRiskPriority[i], captureRiskPriority[i+1]
		t.Run(hi+" before "+lo, func(t *testing.T) {
			// The tool names are chosen so key order alone would invert them.
			a := CaptureRiskItem{Risk: hi, Tool: "zz"}
			b := CaptureRiskItem{Risk: lo, Tool: "aa"}
			if !CaptureRiskItemLess(a, b) || CaptureRiskItemLess(b, a) {
				t.Fatalf("want %s ranked before %s", hi, lo)
			}
		})
	}
	future := CaptureRiskItem{Risk: "some_future_label"}
	if !CaptureRiskItemLess(future, CaptureRiskItem{Risk: captureRiskPriority[0]}) {
		t.Error("a label with no row must sort first")
	}
	a := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "codex"}
	b := CaptureRiskItem{Risk: CaptureRiskHookRepaired, Tool: "cursor"}
	if !CaptureRiskItemLess(a, b) || CaptureRiskItemLess(b, a) {
		t.Error("within one label the key must decide")
	}
}

// e1Items replays the 2026-10-17 re-test's E1 report: 21 standing binary
// mismatches, 14 repaired hooks, 6 registration errors and 8 changed hook
// files, 49 located risks against a bound of 32.
func e1Items() []CaptureRiskItem {
	var out []CaptureRiskItem
	add := func(risk string, n int, prefix string) {
		for i := 0; i < n; i++ {
			tool := prefix + string(rune('a'+i))
			out = append(out, CaptureRiskItem{Risk: risk, Tool: tool, File: "~/." + tool + "/hooks.json"})
		}
	}
	add(CaptureRiskHookBinaryMismatch, 21, "a")
	add(CaptureRiskHookRepaired, 14, "r")
	add(CaptureRiskHookRegistrationError, 6, "x")
	add(CaptureRiskHookConfigChanged, 8, "c")
	return out
}

// TestNormalizeKeepsTheMostActionableItems is T-873: the bound keeps every
// registration error and repair (key order used to keep the binary
// mismatches, which sort first by name), reports how many it left out, and
// gives the same answer whatever order the items arrive in.
func TestNormalizeKeepsTheMostActionableItems(t *testing.T) {
	in := e1Items()
	got, omitted := NormalizeCaptureRiskItemsCounted(in)
	if len(got) != maxCaptureRiskItems {
		t.Fatalf("kept %d items, want %d", len(got), maxCaptureRiskItems)
	}
	if omitted != len(in)-maxCaptureRiskItems {
		t.Fatalf("omitted = %d, want %d", omitted, len(in)-maxCaptureRiskItems)
	}
	count := map[string]int{}
	for _, it := range got {
		count[it.Risk]++
	}
	want := map[string]int{
		CaptureRiskHookRegistrationError: 6,
		CaptureRiskHookRepaired:          14,
		CaptureRiskHookConfigChanged:     8,
		CaptureRiskHookBinaryMismatch:    4,
	}
	if !reflect.DeepEqual(count, want) {
		t.Fatalf("kept per label %v, want %v", count, want)
	}
	for i := 0; i+1 < len(got); i++ {
		if !CaptureRiskItemLess(got[i], got[i+1]) {
			t.Fatalf("items %d and %d out of order: %v, %v", i, i+1, got[i], got[i+1])
		}
	}
	r := rand.New(rand.NewSource(873))
	for n := 0; n < 5; n++ {
		shuffled := append([]CaptureRiskItem(nil), in...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, o := NormalizeCaptureRiskItemsCounted(shuffled)
		if !reflect.DeepEqual(again, got) || o != omitted {
			t.Fatal("the result depends on the input order")
		}
	}
	if _, o := NormalizeCaptureRiskItemsCounted(got); o != 0 {
		t.Fatalf("re-normalizing a bounded list omitted %d more", o)
	}
}

// TestNormalizeLabelsCarriesTheOmittedCount: the node's count survives the
// server's re-normalization, a further cut adds to it, a hostile count is
// floored and bounded, and an unsupported check version carries nothing.
func TestNormalizeLabelsCarriesTheOmittedCount(t *testing.T) {
	cases := []struct {
		name    string
		in      ManagedIntegrityReport
		want    int
		noItems bool
	}{
		{"node count kept", ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, CaptureRiskItems: e1Items()[:10], CaptureRiskItemsOmitted: 5}, 5, false},
		{"server cut added", ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, CaptureRiskItems: e1Items(), CaptureRiskItemsOmitted: 5}, 5 + 49 - maxCaptureRiskItems, false},
		{"negative read as zero", ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, CaptureRiskItemsOmitted: -7}, 0, false},
		{"bounded", ManagedIntegrityReport{CaptureCheckVersion: ManagedCaptureCheckVersion, CaptureRiskItemsOmitted: 1 << 30}, maxCaptureRiskItemsOmitted, false},
		{"unsupported version", ManagedIntegrityReport{CaptureCheckVersion: 99, CaptureRiskItems: e1Items(), CaptureRiskItemsOmitted: 5}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.NormalizeLabels()
			if got.CaptureRiskItemsOmitted != tc.want {
				t.Fatalf("omitted = %d, want %d", got.CaptureRiskItemsOmitted, tc.want)
			}
			if tc.noItems && got.CaptureRiskItems != nil {
				t.Fatalf("items kept on an unsupported version: %v", got.CaptureRiskItems)
			}
			if again := got.NormalizeLabels(); again.CaptureRiskItemsOmitted != got.CaptureRiskItemsOmitted {
				t.Fatalf("a second normalize changed the count: %d -> %d", got.CaptureRiskItemsOmitted, again.CaptureRiskItemsOmitted)
			}
		})
	}
}

// TestDeriveChangesRanksWithinOneReport: when more items appear at once than
// the change list holds, the most actionable are the ones named.
func TestDeriveChangesRanksWithinOneReport(t *testing.T) {
	prior := ManagedIntegrityDetail{CaptureCheckVersion: 1, CaptureRiskItems: []CaptureRiskItem{{Risk: CaptureRiskHookConfigChanged, Tool: "seed"}}}
	items, _ := NormalizeCaptureRiskItemsCounted(e1Items())
	changes := DeriveCaptureRiskChanges(prior, true, nil, items, time.Date(2026, 10, 17, 9, 50, 0, 0, time.UTC))
	if len(changes) != maxCaptureRiskChanges {
		t.Fatalf("got %d changes, want %d", len(changes), maxCaptureRiskChanges)
	}
	for _, c := range changes {
		if c.Risk != CaptureRiskHookRegistrationError && c.Risk != CaptureRiskHookRepaired {
			t.Fatalf("change %v kept ahead of a registration error or a repair", c.CaptureRiskItem)
		}
	}
}
