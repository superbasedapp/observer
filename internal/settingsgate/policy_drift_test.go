package settingsgate

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestPolicyCoversEveryApprovalFamily keeps guard R-165 meaningful (D19): an
// agent that cannot get a key applied through set_setting must not be able
// to write it with `observer config set` or PUT /api/config/keys either.
func TestPolicyCoversEveryApprovalFamily(t *testing.T) {
	for _, p := range Prefixes() {
		if !policy.SelfLoweringConfigKey(p) || !policy.SelfLoweringConfigKey(p+".x") {
			t.Errorf("approval family %q is not an R-165 self-lowering key in internal/policy (add it to settingsApprovalPrefixes)", p)
		}
	}
}

// TestPolicyCoversEveryProposedLeaf is the R-B07 predicate test: every key
// set_setting turns into a proposal (a D19 family or a sensitive-tier leaf)
// is an R-165 self-approval for an agent's shell, so `observer config set
// <key> --yes` cannot do what MCP may only propose. The one escape is a
// subtree another guard rule owns (policy.SensitiveKeysOwnedElsewhere).
func TestPolicyCoversEveryProposedLeaf(t *testing.T) {
	ownedElsewhere := func(path string) bool {
		for _, p := range policy.SensitiveKeysOwnedElsewhere() {
			if path == p || strings.HasPrefix(path, p+".") {
				return true
			}
		}
		return false
	}
	for _, l := range configschema.Leaves() {
		d := Decide(l.Path, "x", nil)
		if d.Verdict != Propose || ownedElsewhere(l.Path) {
			continue
		}
		if !policy.SelfLoweringConfigKey(l.Path) {
			t.Errorf("%s is proposed over MCP (%s) but `observer config set` of it is not R-165: add it to internal/policy sensitiveConfigKeys", l.Path, d.Category)
		}
	}
}

// TestSensitiveMirrorHasNoStaleEntry: each internal/policy sensitiveConfigKeys
// entry is still a sensitive-tier leaf, so the mirror does not keep denying a
// key the schema relaxed.
func TestSensitiveMirrorHasNoStaleEntry(t *testing.T) {
	for _, k := range policy.SensitiveConfigKeys() {
		c := configschema.CheckKey(k, nil)
		if !c.Found || c.Leaf.Path != k || !c.NeedsConfirm {
			t.Errorf("internal/policy sensitiveConfigKeys names %q, which is not a sensitive-tier leaf (remove it)", k)
		}
	}
}
