package secassess

import (
	"fmt"
	"reflect"
	"testing"
)

// TestDefaultRetestIDs (N-21): the default choice of a retest is the findings the
// replay can send in full, in the model's order, at most the bound; a finding
// with a hidden value is left for the developer to choose.
func TestDefaultRetestIDs(t *testing.T) {
	f := func(id string, hidden bool) RetestFinding { return RetestFinding{ID: id, Hidden: hidden} }
	many := func(prefix string, n int, hidden bool) []RetestFinding {
		var out []RetestFinding
		for i := 1; i <= n; i++ {
			out = append(out, f(fmt.Sprintf("%s-%d", prefix, i), hidden))
		}
		return out
	}
	cases := []struct {
		name string
		in   []RetestFinding
		max  int
		want []string
	}{
		{"none offered", nil, 8, nil},
		{"nothing is hidden: the first ones, in order", []RetestFinding{f("A", false), f("B", false), f("C", false)}, 8, []string{"A", "B", "C"}},
		{"a hidden one in front is skipped, not counted", []RetestFinding{f("A", true), f("B", false), f("C", true), f("D", false)}, 8, []string{"B", "D"}},
		{"the bound counts only the ones chosen", append(many("H", 5, true), many("P", 10, false)...), 8, []string{"P-1", "P-2", "P-3", "P-4", "P-5", "P-6", "P-7", "P-8"}},
		{"every finding hidden: none is chosen", many("H", 4, true), 8, nil},
		{"a bound of zero chooses none", many("P", 3, false), 0, nil},
		{"a smaller bound", many("P", 5, false), 2, []string{"P-1", "P-2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DefaultRetestIDs(c.in, c.max)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("DefaultRetestIDs = %v, want %v", got, c.want)
			}
		})
	}
	// The input is not changed.
	in := []RetestFinding{f("A", true), f("B", false)}
	DefaultRetestIDs(in, 8)
	if in[0].ID != "A" || !in[0].Hidden {
		t.Errorf("the input was changed: %+v", in)
	}
}
