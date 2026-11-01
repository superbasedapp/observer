package dashapi

import "context"

// SecurityOrgShare is what the node shares with its organization about code
// security right now (security plan 7.12, lane SEC-E3), as the daemon
// resolved it: the share level (off, posture or findings), whether an org
// security floor is in force, and whether the node is org-managed (a
// managed node ships paths and a masked excerpt with each finding).
type SecurityOrgShare struct {
	Level         string
	FloorsInForce bool
	Managed       bool
}

// SecurityOrgShareFunc reads it; ok is false when the daemon has not
// resolved it (a standalone dashboard), and the notice then stays hidden.
// Wired from cmd/observer/security_orgnotice_dash.go; nil hides the notice.
type SecurityOrgShareFunc func(ctx context.Context) (share SecurityOrgShare, ok bool)
