package guard

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// Project family sections, the node's read (security plan section 7.11
// "Family bodies (security.scanning sections) merge with their per-field
// raise-only operators", lane sec-p3): READ ACCESSORS ONLY. A family section
// rides the per-project envelope the project layer loads (orgproject.go), so
// it is loaded next to the rules: the same decision (projectmatch.Decide over
// the cached mapping and the daemon's match record, a linked worktree keyed
// by its main repository), the same envelope reader (delivered, else
// resolved) and the same check against the composed bundle in force. What
// the members MEAN is the family's own merge (internal/policyfam/
// securityscanning, called by the cmd layer); nothing here interprets a body.

// ProjectFamilyLoad is what applies to one directory.
type ProjectFamilyLoad struct {
	// InForce: the org layer in force carries the project audience (a v3
	// delivery). False: no project section can apply anywhere on this node.
	InForce bool
	// State is the directory's project match (projectmatch.StateMatched,
	// StateUnmatched or StateUnknown; "" when not InForce).
	State string
	// Reason is projectmatch's reason for an unknown state, when it has one.
	Reason string
	// Projects are the matched projects, sorted by id, each with the family
	// members its envelope carries.
	Projects []ProjectFamilySet
}

// ProjectFamilySet is one matched project's family sections.
type ProjectFamilySet struct {
	OrgProjectID string
	// Members are the envelope's family members (every family), in the
	// envelope's order (family, then sequence).
	Members []orgcontract.ProjectFamilyMember
	// Unavailable: the project matched but its envelope is missing, does
	// not decode or does not verify, so its sections are unknown here.
	Unavailable bool
}

// OrgProjectFamilies resolves which org projects apply to projectRoot and
// reads each matched project's verified envelope's family members. An empty
// projectRoot, a node with no v3 delivery, or a lazy base that dropped the
// org layer answers InForce=false.
func (g *Guard) OrgProjectFamilies(projectRoot string) ProjectFamilyLoad {
	es := g.set.Load()
	if !es.orgLayerReported() {
		return ProjectFamilyLoad{}
	}
	dec, composed, key, ok := g.orgProjectDecision(es, projectRoot)
	if !ok {
		return ProjectFamilyLoad{}
	}
	out := ProjectFamilyLoad{InForce: true, State: dec.State, Reason: dec.Reason}
	if dec.State != projectmatch.StateMatched {
		return out
	}
	ids := append([]string(nil), dec.IDs...)
	sort.Strings(ids)
	for _, id := range ids {
		set := ProjectFamilySet{OrgProjectID: id}
		if env, st := g.envelopeOf(id, composed, key); st == envelopeVerified {
			set.Members = env.Families
		} else {
			set.Unavailable = true
		}
		out.Projects = append(out.Projects, set)
	}
	return out
}
