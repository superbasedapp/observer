package sandboxselect

import (
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

var hostNS = []string{"mnt:[4026531840]", "pid:[4026531836]", "net:[4026531992]", "user:[4026531837]"}

// Mutation proof (7): fed truncated or reshaped read-back output, the
// re-check yields built_below_plan, never the planned value.
func TestRecheckBwrap(t *testing.T) {
	private := []string{"mnt:[4026532001]", "pid:[4026532002]", "net:[4026532003]", "user:[4026532004]"}
	shared := []string{"mnt:[4026532001]", "pid:[4026532002]", "net:[4026531992]"}
	for _, tc := range []struct {
		name  string
		plan  PlannedBwrap
		child []string
		host  []string
		ok    bool
	}{
		{"private network as planned", PlannedBwrap{PrivateNet: true}, private, hostNS, true},
		{"host tier shares the network", PlannedBwrap{}, shared, hostNS, true},
		{"private planned, shared built", PlannedBwrap{PrivateNet: true}, shared, hostNS, false},
		{"truncated child", PlannedBwrap{}, []string{"mnt:[4026532001]", "pid:[40265"}, hostNS, false},
		{"missing net", PlannedBwrap{}, []string{"mnt:[4026532001]", "pid:[4026532002]"}, hostNS, false},
		{"reshaped line", PlannedBwrap{}, []string{"mnt -> 4026532001", "pid:[4026532002]", "net:[1]"}, hostNS, false},
		{"duplicate namespace", PlannedBwrap{}, append([]string{"net:[2]"}, private...), hostNS, false},
		{"shares the host pid namespace", PlannedBwrap{}, []string{"mnt:[4026532001]", "pid:[4026531836]", "net:[4026532003]"}, hostNS, false},
		{"empty host read-back", PlannedBwrap{}, private, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RecheckBwrap(tc.plan, tc.host, tc.child)
			if got.OK != tc.ok {
				t.Fatalf("got %+v, want ok %v", got, tc.ok)
			}
			if !tc.ok && (got.Verdict != VerdictBuiltBelowPlan || got.Class != vocab.ClassNone) {
				t.Fatalf("a failed re-check must be built_below_plan at class none: %+v", got)
			}
			if tc.ok && got.Class != vocab.ClassProcess {
				t.Fatalf("class %s", got.Class)
			}
		})
	}
}
