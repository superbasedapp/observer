package secassess

import (
	"strconv"
	"strings"
)

// grants.go reads the node's verified org grants for a held run (plan section
// 13.6): whether the grant the org issued is narrower than the ask. Coverage
// itself ("is this already granted") is the access-grant package's own answer
// (accessgrant.CoveredBy, reached through the Requests seam); this only
// explains a grant for the rule that did not cover it.

// GrantFact is one honoured org grant as the held run reads it.
type GrantFact struct {
	ID              int64
	Type            string
	Effect          string
	RuleID          string
	Lane            string
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	MaxUses         int64
	ExpiresAtNs     int64
	Honoured        bool
}

// NarrowerGrant is a grant for the rule that does not cover the ask.
type NarrowerGrant struct {
	ID  int64
	Why string
}

const (
	grantTypeExemption = "guard_exemption"
	grantEffectExempt  = "exempt"
)

// FindNarrower returns the lowest-id honoured exemption grant that names the
// rule but does not give what the run needs (an exempt grant for every command
// of the project on the tool lane for at least minWindowNs), with the reason in
// words. found is false when no honoured grant names the rule at all.
func FindNarrower(rule, projectHash string, nowNs, minWindowNs int64, grants []GrantFact) (NarrowerGrant, bool) {
	var best NarrowerGrant
	found := false
	for _, g := range grants {
		if !g.Honoured || g.Type != grantTypeExemption || g.RuleID != rule {
			continue
		}
		why := narrowerWhy(g, projectHash, nowNs, minWindowNs)
		if why == "" {
			why = "it does not cover everything the request asked for"
		}
		if !found || g.ID < best.ID {
			best, found = NarrowerGrant{ID: g.ID, Why: why}, true
		}
	}
	return best, found
}

func narrowerWhy(g GrantFact, projectHash string, nowNs, minWindowNs int64) string {
	switch {
	case g.Effect != grantEffectExempt:
		return "it softens the rule to an ask, which does nothing for a rule that already asks"
	case g.ProjectRootHash != "" && g.ProjectRootHash != projectHash:
		return "it is for another project"
	case g.Lane != "" && g.Lane != "all" && g.Lane != "tool":
		return "it is for the " + strings.TrimSpace(g.Lane) + " lane, not the tool lane"
	case g.CommandClass != "" || g.OperandHash != "":
		return "it is limited to one command"
	case g.MaxUses > 0:
		return "it is limited to " + strconv.FormatInt(g.MaxUses, 10) + " uses"
	case g.ExpiresAtNs != 0 && g.ExpiresAtNs-nowNs < minWindowNs:
		return "it ends too soon to be worth starting a run"
	}
	return ""
}
