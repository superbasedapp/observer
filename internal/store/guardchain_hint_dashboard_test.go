package store

import (
	"strings"
	"testing"
)

// TestGuardChainRepairHintNamesBothSurfaces pins the dashboard CLI parity
// rule for the chain hint (plan docs/plans/dashboard-cli-parity-plan-
// 2026-11-06.md, B-G8): the CLI and the dashboard both show it, so every
// hint names the dashboard control first and keeps the CLI verbs it repairs
// with.
func TestGuardChainRepairHintNamesBothSurfaces(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		report GuardChainReport
		verbs  []string
	}{
		{"pruned action ids", GuardChainReport{ActionlessRewritten: 2}, []string{"repair-anchors", "--apply"}},
		{"deleted rows", GuardChainReport{Breaks: map[string]int{guardBreakLink: 1}}, []string{"dedup-events", "relink-gaps", "--apply"}},
	}
	for _, tc := range cases {
		hint := GuardChainRepairHint(tc.report)
		dash := strings.Index(hint, "Security > Coverage")
		if dash < 0 || !strings.Contains(hint, "Repair audit chain") {
			t.Errorf("%s: the hint does not name the dashboard control: %q", tc.name, hint)
			continue
		}
		for _, v := range tc.verbs {
			at := strings.Index(hint, v)
			if at < 0 || at < dash {
				t.Errorf("%s: %q missing or before the dashboard control: %q", tc.name, v, hint)
			}
		}
	}
}
