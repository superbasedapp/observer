package dashapi

// ProjectPolicyLine is GET /api/terminal/project-policy's answer (security
// plan section 7.11 hard case "New Terminal shows project policy: not
// matched", lane sec-p2b): whether the organization's project rules apply to
// one directory on this node, read from the daemon's match record (P1's core
// match file) and the org-signed mapping. Shown is false when the node holds
// no project delivery (no org published a project-scoped guard bundle for
// this member), so an existing install never sees the line.
type ProjectPolicyLine struct {
	Shown bool `json:"shown"`
	// State is ProjectPolicyMatched, ProjectPolicyNotMatched or
	// ProjectPolicyUnknown ("" when Shown is false).
	State string `json:"state,omitempty"`
	// Projects is how many org projects the directory matched (State
	// ProjectPolicyMatched only).
	Projects int `json:"projects,omitempty"`
}

// Project policy line states (ProjectPolicyLine.State).
const (
	// ProjectPolicyMatched: the directory matched at least one org project;
	// its project rules apply there on top of the org, team and member
	// rules.
	ProjectPolicyMatched = "matched"
	// ProjectPolicyNotMatched: the mapping is current and the directory
	// matched no project; the org, team and member rules apply.
	ProjectPolicyNotMatched = "not_matched"
	// ProjectPolicyUnknown: the node holds a project delivery but its
	// mapping is missing or out of date, so the project layer is unknown.
	ProjectPolicyUnknown = "unknown"
)
