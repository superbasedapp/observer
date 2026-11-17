package portalmfa

import (
	"strings"
	"time"
)

// --- the routes a pending session may reach ----------------------------------

// pendingRoute is one row of the pending-session allow table.
type pendingRoute struct {
	method string
	path   string
	// prefix makes the row a prefix match.
	prefix bool
}

// pendingRoutes are the portal routes a session whose second factor is
// pending may reach: what the second-factor page needs (the session
// bootstrap, the auth configuration, the second-factor status, the passkey
// assertion, a recovery code) and sign-out. Every other portal route answers
// 403 second_factor_required.
var pendingRoutes = []pendingRoute{
	{method: "GET", path: "/portal/api/session"},
	{method: "GET", path: "/portal/api/mfa"},
	{method: "POST", path: "/portal/api/mfa/assert/begin"},
	{method: "POST", path: "/portal/api/mfa/assert/finish"},
	{method: "POST", path: "/portal/api/mfa/recover"},
	{method: "POST", path: "/portal/auth/logout"},
}

// AllowedWhilePending reports whether a session with a pending second factor
// may reach method path.
func AllowedWhilePending(method, path string) bool {
	if method == "HEAD" {
		method = "GET"
	}
	for _, r := range pendingRoutes {
		if r.method != method {
			continue
		}
		if r.path == path || (r.prefix && strings.HasPrefix(path, r.path)) {
			return true
		}
	}
	return false
}

// --- what a session may do ------------------------------------------------------

// Action is one second-factor management action.
type Action string

// The actions.
const (
	// ActionEnrol registers a passkey.
	ActionEnrol Action = "enrol"
	// ActionManage removes a passkey or mints new recovery codes.
	ActionManage Action = "manage"
	// ActionOrgPolicy changes an org's "require a second factor" setting.
	ActionOrgPolicy Action = "org_policy"
	// ActionApproveDevice approves a new device for an account that holds a
	// passkey (FR-6): the approving session must have signed in with a passkey.
	ActionApproveDevice Action = "approve_device"
)

// Facts is what a decision reads.
type Facts struct {
	Session SessionState
	// ActivePasskeys is the account's unrevoked passkey count.
	ActivePasskeys int
	// AuthTime is the session's fresh primary sign-in time (zero: unknown).
	AuthTime time.Time
	Now      time.Time
}

// Refusal codes, returned as the API's error code.
const (
	// CodeSecondFactorRequired: use a passkey (or a recovery code) first.
	CodeSecondFactorRequired = "second_factor_required"
	// CodeReauthRequired: sign in again (fresh) before adding the first
	// passkey.
	CodeReauthRequired = "reauth_required"
	// CodePasskeyLimit: MaxActivePasskeys reached.
	CodePasskeyLimit = "passkey_limit"
	// CodePasskeySignInRequired: this change needs a passkey sign-in in
	// this session (a recovery code is not enough).
	CodePasskeySignInRequired = "passkey_signin_required"
)

// actionRule is one row of the action table: when refuse is true for the
// facts, the action is refused with code.
type actionRule struct {
	id     string
	action Action
	refuse func(f Facts) bool
	code   string
}

// actionRules is THE second-factor action table, walked top down; the first
// refusing row for the action decides, and no refusing row allows it.
var actionRules = []actionRule{
	// Another passkey on an enrolled account: prove an existing factor first,
	// so a stolen primary sign-in cannot add the thief's authenticator.
	{
		id: "enrol-needs-second-factor", action: ActionEnrol, code: CodeSecondFactorRequired,
		refuse: func(f Facts) bool { return f.Session.Enrolled && f.Session.Method == MethodNone },
	},
	// The first passkey: only a fresh primary sign-in proves the owner.
	{
		id: "first-enrol-needs-fresh-signin", action: ActionEnrol, code: CodeReauthRequired,
		refuse: func(f Facts) bool {
			return !f.Session.Enrolled && (f.AuthTime.IsZero() || f.Now.Sub(f.AuthTime) > FreshEnrolWindow || f.AuthTime.After(f.Now.Add(time.Minute)))
		},
	},
	{
		id: "enrol-cap", action: ActionEnrol, code: CodePasskeyLimit,
		refuse: func(f Facts) bool { return f.ActivePasskeys >= MaxActivePasskeys },
	},
	// Removing a passkey or minting codes: the session has used its second
	// factor (a recovery code counts: it is how a person who lost a key
	// removes it).
	{
		id: "manage-needs-second-factor", action: ActionManage, code: CodeSecondFactorRequired,
		refuse: func(f Facts) bool { return !f.Session.Enrolled || f.Session.Method == MethodNone },
	},
	// An org's requirement (either way): the changer signed in with a
	// passkey in this session, so turning it on cannot lock them out and
	// turning it off is not open to a stolen primary sign-in.
	{
		id: "org-policy-needs-passkey", action: ActionOrgPolicy, code: CodePasskeySignInRequired,
		refuse: func(f Facts) bool { return !f.Session.Enrolled || f.Session.Method != MethodPasskey },
	},
	// A new device of an enrolled account: only a passkey sign-in in this
	// session may approve it (a recovery code or a primary sign-in alone may not).
	{
		id: "approve-device-needs-passkey", action: ActionApproveDevice, code: CodePasskeySignInRequired,
		refuse: func(f Facts) bool { return !f.Session.Enrolled || f.Session.Method != MethodPasskey },
	},
}

// Decide applies the action table: "" when allowed, else the refusal code.
func Decide(a Action, f Facts) (code, ruleID string) {
	for _, r := range actionRules {
		if r.action == a && r.refuse(f) {
			return r.code, r.id
		}
	}
	return "", ""
}

// --- what the platform issuer may do --------------------------------------------

// IssueVerdict is the issuer's second-factor verdict for an authorize.
type IssueVerdict int

// The verdicts.
const (
	// IssueAllowed: issue the code (with the session's amr).
	IssueAllowed IssueVerdict = iota + 1
	// IssueSecondFactor: send the browser to the portal's second-factor
	// page first (or answer interaction_required to prompt=none).
	IssueSecondFactor
)

// IssueFacts is what the issuer's decision reads.
type IssueFacts struct {
	// Pending: the account has a passkey and this session has not used it.
	Pending bool
	// MultiFactor: the session carries a multi-factor amr.
	MultiFactor bool
	// OrgRequires: the org requires a second factor of every member.
	OrgRequires bool
}

// issueRule is one row of the issuer table.
type issueRule struct {
	id      string
	match   func(f IssueFacts) bool
	verdict IssueVerdict
}

// issueRules is THE issuer second-factor table, walked top down.
var issueRules = []issueRule{
	// An enrolled account's session that skipped its passkey never reaches a
	// tenant: otherwise a stolen primary sign-in would.
	{id: "account-second-factor-pending", match: func(f IssueFacts) bool { return f.Pending }, verdict: IssueSecondFactor},
	{id: "org-requires-second-factor", match: func(f IssueFacts) bool { return f.OrgRequires && !f.MultiFactor }, verdict: IssueSecondFactor},
	{id: "allowed", match: func(IssueFacts) bool { return true }, verdict: IssueAllowed},
}

// IssueRule applies the issuer table.
func IssueRule(f IssueFacts) (IssueVerdict, string) {
	for _, r := range issueRules {
		if r.match(f) {
			return r.verdict, r.id
		}
	}
	return IssueSecondFactor, "no-row"
}
