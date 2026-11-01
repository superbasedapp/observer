package orgcontract

import "strings"

// Per-section project policy status on the policy-ack rail (security plan
// section 7.11 "policy status and ack or NACK are reported per project
// section", lane sec-p2b): the gen5 guard-row field
// PolicyStateRow.ProjectSectionStatus.
//
// One entry per project in the signed mapping the node holds (the projects
// whose sections reach this member and that have a mapped repository), each
// an org project id the org itself minted and signed to this node, plus a
// closed status. No path, no directory, no repository identity and no rule
// text crosses the wire: which directory matched stays on the node.

// Project section statuses (ProjectSectionState.Status).
const (
	// ProjectSectionApplied: a directory on this node matched the project in
	// the signed mapping (the daemon's current match record) and the
	// project's envelope verifies against the composed bundle in force.
	ProjectSectionApplied = "applied"
	// ProjectSectionNotMatched: the mapping is current and no directory on
	// this node matched the project; the org, team and member layers apply
	// there. Not a fault: the developer has not worked in that project here.
	ProjectSectionNotMatched = "not_matched"
	// ProjectSectionUnknown: the node cannot say: the mapping is missing,
	// of another delivery or past its offline lifetime, or a matched
	// project's envelope does not verify.
	ProjectSectionUnknown = "unknown"
	// ProjectSectionNotDelivered: the project is in the signed mapping but
	// its envelope never arrived (the server could not compose it, or the
	// fetch has not landed yet).
	ProjectSectionNotDelivered = "not_delivered"
)

// projectSectionStatuses is the closed vocabulary, each with whether it
// acknowledges the section (ACK) or not (NACK).
var projectSectionStatuses = map[string]bool{
	ProjectSectionApplied:      true,
	ProjectSectionNotMatched:   true,
	ProjectSectionUnknown:      false,
	ProjectSectionNotDelivered: false,
}

// ProjectSectionStatusKnown reports whether s is in the closed vocabulary.
func ProjectSectionStatusKnown(s string) bool {
	_, ok := projectSectionStatuses[s]
	return ok
}

// ProjectSectionAcked reports whether a status acknowledges its section: the
// node holds the section and applies it wherever it matched (applied,
// not_matched). unknown and not_delivered are NACKs; an unknown value is a
// NACK too.
func ProjectSectionAcked(s string) bool { return projectSectionStatuses[s] }

// MaxProjectIDLen bounds one org project id on this field (org ids are short
// random hex; the bound only refuses junk).
const MaxProjectIDLen = 128

// ProjectSectionState is one project section's status on one node.
type ProjectSectionState struct {
	OrgProjectID string `json:"org_project_id"`
	Status       string `json:"status"`
}

// ValidProjectSectionStatus checks a reported list: at most
// MaxProjectMappingProjects entries, each a non-empty, bounded,
// printable-ASCII project id with no whitespace, listed once, and a status in
// the closed vocabulary. A nil or empty list is valid (nothing reported).
func ValidProjectSectionStatus(list []ProjectSectionState) bool {
	if len(list) > MaxProjectMappingProjects {
		return false
	}
	seen := map[string]bool{}
	for _, e := range list {
		id := e.OrgProjectID
		if id == "" || len(id) > MaxProjectIDLen || seen[id] || !ProjectSectionStatusKnown(e.Status) {
			return false
		}
		if strings.IndexFunc(id, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
			return false
		}
		seen[id] = true
	}
	return true
}
