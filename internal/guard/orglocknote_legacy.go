package guard

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Read-time explanation of the org-lock note on verdict rows written before
// orgLockCause (round-3 finding). A guard_events row keeps the reason text
// of its decision time, and the audit chain hashes that text, so a stored row
// is never rewritten. Rows written before 2026-11-10 carry the generic note
// "[org_locked: an org policy locks <id>; ...]", which on a managed node
// named a policy the organization never wrote (the commit gate S-791 to
// S-794 is a node pack rule). A read surface instead renders the cause the
// row's own stored fields can establish, and keeps the stored text beside
// it.
//
// What the stored verdict source establishes (policy.Engine stamps the
// source of the last layer that touched the rule; any override sets it):
//
//	stored source           | the cause it proves
//	------------------------|-------------------------------------------------
//	org, org_budget         | the organization's policy defined or overrode the
//	                        | rule (its bundle, or its policy for the project)
//	builtin, pack:<name>    | no layer touched the rule, so the organization's
//	                        | policy did not name it: the lock was a managed
//	                        | node's (or a bundle that could not be verified)
//	anything else, or empty | not established (a lower layer may have touched
//	                        | a rule the org also names): the stored text stays
//
// Rows written since carry a cause-specific note (orgLockedNotes) and are
// returned unchanged.

// legacyOrgLockedNote is the generic note orgLockedNote wrote before the
// cause was named (and still writes for an unknown cause).
func legacyOrgLockedNote(ruleID string) string {
	return " [org_locked: an org policy locks " + ruleID + "; the local approval was ignored]"
}

// legacyOrgLockRows is the table above, walked top down; a source ending in
// ":" matches as a prefix.
var legacyOrgLockRows = []struct {
	sources []string
	note    string // %s is the rule id
}{
	{
		[]string{policy.SourceOrg, policy.SourceOrgBudget},
		" [org_locked: the organization's policy names %s; the local approval was ignored]",
	},
	{
		[]string{policy.SourceBuiltin, "pack:"},
		" [org_locked: the organization's guard bundle does not name %s; the organization's lock covered every rule on this node when this ran (a managed node, or a bundle that could not be verified), so the local approval was ignored, and only an org grant (request access) or the org marking the rule overridable lifts it]",
	},
}

// ExplainLegacyOrgLockedReason returns reason with a pre-cause generic
// org-lock note replaced by the cause the stored verdict source establishes
// (the table above), and changed=true; any other reason, or a source that
// establishes no cause, is returned unchanged. It never touches what is
// stored: callers show the result and keep reason itself available.
func ExplainLegacyOrgLockedReason(reason, ruleID, source string) (explained string, changed bool) {
	if ruleID == "" {
		return reason, false
	}
	legacy := legacyOrgLockedNote(ruleID)
	if !strings.Contains(reason, legacy) {
		return reason, false
	}
	for _, row := range legacyOrgLockRows {
		for _, s := range row.sources {
			if source == s || (strings.HasSuffix(s, ":") && strings.HasPrefix(source, s)) {
				return strings.Replace(reason, legacy, fmt.Sprintf(row.note, ruleID), 1), true
			}
		}
	}
	return reason, false
}
