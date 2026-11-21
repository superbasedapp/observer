package sandboxnet

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestRefusalRulesMatchVocab pins the gateway's closed refusal rules equal,
// in order, to the core copy in internal/sandboxvocab that the org-wire
// refusal counts clamp on (audit CG-15). A rule added here and not there
// would count as "not recorded" on the org.
func TestRefusalRulesMatchVocab(t *testing.T) {
	t.Parallel()
	got := sandboxvocab.EgressRefusalRules()
	if len(got) != len(RefusalRules) {
		t.Fatalf("sandboxvocab has %d refusal rules, sandboxnet has %d", len(got), len(RefusalRules))
	}
	for i, r := range RefusalRules {
		if string(got[i]) != string(r) {
			t.Errorf("rule %d: sandboxvocab %q, sandboxnet %q", i, got[i], r)
		}
		if !got[i].Valid() {
			t.Errorf("rule %q is not Valid in sandboxvocab", got[i])
		}
	}
	if sandboxvocab.EgressRefusalRule("not-a-rule").Valid() {
		t.Error("an unknown rule is Valid")
	}
}
