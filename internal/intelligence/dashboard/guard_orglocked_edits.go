package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The org-lock save gate (round-3 finding): on a node where the organization
// sets a rule (an org-layer rule it did not mark overridable, or any rule its
// lock reaches here, every rule on a managed node), the dashboard offers no
// local Disable or Override for it, and the three save paths that could
// write one refuse it, 422 with the problems listed and nothing written:
//
//	save path                               | what it checks
//	----------------------------------------|---------------------------------
//	PUT /api/guard/policy (user layer)      | [[override]] targets added
//	PUT /api/guard/policy/project (trusted) | [[override]] targets and disable ids added
//	PUT /api/config/section/guard           | [guard.rules] disable ids added
//
// Only ids the save ADDS are checked (against the file or config on disk),
// so a file that already carried an entry, written before the org's policy
// reached the node, can still be saved with its other edits; the guard
// itself keeps such an entry from relaxing the org's rule.

// guardOrgLockedEdits returns one problem per id in added that the
// organization sets on this node; what names the edit ("disable",
// "override"). The posture is the one the approvals POST and the rule
// listing read (orgOverrides, guardRuleOrgLock).
func (s *Server) guardOrgLockedEdits(ctx context.Context, what string, added []string) []string {
	if len(added) == 0 {
		return nil
	}
	posture := s.orgOverrides(ctx)
	org := map[string]policy.RuleInfo{}
	if g := s.listingGuard(ctx); g != nil {
		for _, r := range g.RuleListing() {
			if r.Source == policy.SourceOrg {
				org[r.ID] = r
			}
		}
	}
	var problems []string
	for _, id := range added {
		info, ok := org[id]
		if !ok {
			info = policy.RuleInfo{ID: id}
		}
		if _, locked := guardRuleOrgLock(info, posture); locked {
			problems = append(problems, fmt.Sprintf("%s %s: set by your organization on this machine, so it cannot be changed here (ask for an exception on Requests)", what, id))
		}
	}
	return problems
}

// addedIDs is the ids in next that prev does not carry, in next's order,
// each once.
func addedIDs(prev, next []string) []string {
	var out []string
	for _, id := range next {
		if id != "" && !slices.Contains(prev, id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// policyFileRefs is the override and disable ids of the policy file at path
// (empty when it is missing or does not parse).
func policyFileRefs(path string) (overrides, disabled []string) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	ov, _, dis, _ := guard.PolicyRuleRefs(raw)
	return ov, dis
}

// policyEditOrgLockProblems is the org-lock gate for a policy file save:
// the override (and disable) ids content adds over the file at path.
func (s *Server) policyEditOrgLockProblems(ctx context.Context, path string, content []byte) []string {
	newOv, _, newDis, err := guard.PolicyRuleRefs(content)
	if err != nil {
		return nil // Lint reports the parse error.
	}
	oldOv, oldDis := policyFileRefs(path)
	problems := s.guardOrgLockedEdits(ctx, "override", addedIDs(oldOv, newOv))
	return append(problems, s.guardOrgLockedEdits(ctx, "disable", addedIDs(oldDis, newDis))...)
}

// writeOrgLockRefusal answers a save the org-lock gate refused.
func writeOrgLockRefusal(w http.ResponseWriter, problems []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{"saved": false, "problems": problems})
}
