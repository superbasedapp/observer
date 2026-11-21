package staffauth

import (
	"fmt"
	"strings"
	"time"
)

// Role is a staff member's console role. The vocabulary is closed and
// mirrors the CHECK on staff_users.staff_role (cloud migration 0069).
type Role string

// The three staff roles, least to most privileged.
const (
	// RoleSupport reads: the action log, the availability inputs, the org
	// registry.
	RoleSupport Role = "support"
	// RoleOps also changes platform state: the availability inputs.
	RoleOps Role = "ops"
	// RoleAdmin holds everything ops holds; it is the role the operator
	// enrols the first staff member with.
	RoleAdmin Role = "admin"
)

// KnownRoles lists every role, in privilege order. A test compares it with
// the database CHECK.
var KnownRoles = []Role{RoleSupport, RoleOps, RoleAdmin}

// ParseRole returns the role named s, or an error naming the vocabulary.
func ParseRole(s string) (Role, error) {
	for _, r := range KnownRoles {
		if string(r) == s {
			return r, nil
		}
	}
	names := make([]string, len(KnownRoles))
	for i, r := range KnownRoles {
		names[i] = string(r)
	}
	return "", fmt.Errorf("staffauth.ParseRole: %q is not a staff role (want one of %s)", s, strings.Join(names, ", "))
}

// Action is one thing a signed-in staff member can ask the console to do.
type Action string

// The staff actions the console serves today.
const (
	// ActionReadSelf is GET /staff/api/me.
	ActionReadSelf Action = "self.read"
	// ActionSignOut is POST /staff/auth/logout.
	ActionSignOut Action = "session.end"
	// ActionReadLog is GET /staff/api/log.
	ActionReadLog Action = "log.read"
	// ActionReadAvailability is GET /staff/api/availability.
	ActionReadAvailability Action = "availability.read"
	// ActionWriteAvailability is PUT or DELETE
	// /staff/api/availability/{section}/{key}.
	ActionWriteAvailability Action = "availability.write"
	// ActionSupportSignIn is GET /staff/oauth2/authorize: signing in to a
	// tenant org as support (managed-SaaS M7a.2). The issuer adds the
	// support claim only through it, and only for a session whose passkey
	// assertion is fresh (design m6.0 4.9); whether the org lets the staff
	// member in is the tenant's own grant, which the console cannot see.
	ActionSupportSignIn Action = "support.signin"
	// ActionReadDeletions is GET /staff/api/deletions: the org deletions and
	// account deletion follow-ups (ids, steps, times, enum reasons; no
	// subject, no name), managed-SaaS M6.9 / M7a.1.
	ActionReadDeletions Action = "deletions.read"
	// ActionReadTeamAllowlist is GET /staff/api/team-allowlist: the team
	// create allow-list (cloud 0130, until GO-3).
	ActionReadTeamAllowlist Action = "team_allowlist.read"
	// ActionWriteTeamAllowlist is POST /staff/api/team-allowlist and DELETE
	// /staff/api/team-allowlist/{id}.
	ActionWriteTeamAllowlist Action = "team_allowlist.write"
	// ActionReadOrgs is GET /staff/api/orgs and GET /staff/api/orgs/{id}:
	// the org registry, plan grant history, usage, the issued entitlements
	// document, lifecycle intents and deletion state, through the staff
	// definers of cloud migration 0133 (registry and control-plane facts
	// only, no tenant data). Also GET /staff/api/availability/document (the
	// issued envelope) rides ActionReadAvailability, not this row.
	ActionReadOrgs Action = "orgs.read"
)

// FreshAssertionWindow is how old a session's WebAuthn assertion may be for
// an action that requires a fresh one (design 4.9: "an assertion older than
// 15 minutes is required again for any mutation").
const FreshAssertionWindow = 15 * time.Minute

// actionRule is one row of the authorization table.
type actionRule struct {
	action Action
	// roles may perform the action.
	roles []Role
	// fresh requires the session's assertion to be at most
	// FreshAssertionWindow old.
	fresh bool
}

// actionRules is THE staff authorization table, one row per action. Every
// mutation is fresh; reads are not.
var actionRules = []actionRule{
	{action: ActionReadSelf, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionSignOut, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionReadLog, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionReadAvailability, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionWriteAvailability, roles: []Role{RoleOps, RoleAdmin}, fresh: true},
	{action: ActionSupportSignIn, roles: []Role{RoleSupport, RoleOps, RoleAdmin}, fresh: true},
	{action: ActionReadDeletions, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionReadTeamAllowlist, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
	{action: ActionWriteTeamAllowlist, roles: []Role{RoleOps, RoleAdmin}, fresh: true},
	{action: ActionReadOrgs, roles: []Role{RoleSupport, RoleOps, RoleAdmin}},
}

// Decision is Authorize's verdict. Code is empty when Allowed, else one of
// the Code* constants, which the API returns as its error code.
type Decision struct {
	Allowed bool
	Code    string
}

// Refusal codes.
const (
	// CodeUnknownAction: the action has no row (a programming error; fail
	// closed).
	CodeUnknownAction = "unknown_action"
	// CodeForbiddenRole: the staff role may not perform the action.
	CodeForbiddenRole = "forbidden_role"
	// CodeReauthRequired: the action needs a WebAuthn assertion newer than
	// FreshAssertionWindow.
	CodeReauthRequired = "reauth_required"
)

// Authorize decides whether a staff member with role, whose session's last
// WebAuthn assertion was at assertedAt, may perform action at now. It walks
// actionRules top down; an action with no row is refused.
func Authorize(role Role, action Action, assertedAt, now time.Time) Decision {
	for _, r := range actionRules {
		if r.action != action {
			continue
		}
		permitted := false
		for _, allowed := range r.roles {
			permitted = permitted || allowed == role
		}
		if !permitted {
			return Decision{Code: CodeForbiddenRole}
		}
		if r.fresh && (assertedAt.IsZero() || now.Sub(assertedAt) > FreshAssertionWindow) {
			return Decision{Code: CodeReauthRequired}
		}
		return Decision{Allowed: true}
	}
	return Decision{Code: CodeUnknownAction}
}

// Capability is what a role may do with one action, without a session clock:
// whether the role is permitted at all, and whether the action also needs an
// assertion within FreshAssertionWindow. The staff UI reads it to hide the
// controls a role cannot use; Authorize stays the only gate.
type Capability struct {
	Action    Action `json:"action"`
	Permitted bool   `json:"permitted"`
	Fresh     bool   `json:"fresh"`
}

// Capabilities returns role's Capability for every action of the table, in
// table order.
func Capabilities(role Role) []Capability {
	out := make([]Capability, 0, len(actionRules))
	for _, r := range actionRules {
		c := Capability{Action: r.action, Fresh: r.fresh}
		for _, allowed := range r.roles {
			c.Permitted = c.Permitted || allowed == role
		}
		out = append(out, c)
	}
	return out
}
