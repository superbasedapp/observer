package openshellorg

// probe.go is the org-hosted row's local probe ladder (g1-design.md section
// 3.5, lane G4): rows R0 to R3 with R2b, all local, never a network call
// (invariant I6). Rows R4 to R8 need the org server and the front, so they
// run only at launch or on an explicit check, and their last result is
// cached and shown beside the probe's verdict. Walked top-down; the first
// failing row decides (CLAUDE.md module rule 5).

// The local probe verdicts.
const (
	VerdictNotOffered         = "org_gateway_not_offered"
	VerdictComponentInactive  = "component_inactive"
	VerdictNotInBackends      = "not_in_backends"
	VerdictUnsupportedPlatfm  = "unsupported_platform"
	VerdictCustodyNotOffered  = "custody_not_offered"
	VerdictHomeRelayMissing   = "home_relay_unavailable"
	VerdictLaptopRelayNoOptIn = string(ReasonLaptopRelayNotOptedIn)
	VerdictLaptopRelayForbid  = string(ReasonLaptopRelayForbidden)
	VerdictSigninRequired     = string(ReasonSigninRequired)
	VerdictSigninExpired      = string(ReasonSigninExpired)
)

// ProbeFacts are the local facts the ladder reads.
type ProbeFacts struct {
	// Offered: the node holds a verified, in-force org_openshell field (R0).
	Offered bool
	// SandboxAuthorityMissing: the node is a managed enrolment whose grant
	// does not hold enforce.sandbox, so no sandbox body applies (R0's own
	// reason; FX1 item 7, live finding F-B2).
	SandboxAuthorityMissing bool
	// ComponentActive and Listed: the row's component is active and the row
	// is in [terminal.sandbox].backends or the org's managed list (R1).
	ComponentActive, Listed bool
	// PlatformOK: the daemon is Linux or WSL2 (R2).
	PlatformOK bool
	// Custody is the node's [terminal.sandbox.hosted].key_custody ("" is the
	// default, home_relay); HomeRelayOK: a key the proxy adds is configured
	// (R2).
	Custody     string
	HomeRelayOK bool
	// LaptopRelay is the member's opt-in; OrgLaptopRelay is the org's
	// allowed or forbidden (R2b).
	LaptopRelay    bool
	OrgLaptopRelay LaptopRelay
	// SignedIn: a grant marker exists for this org origin and member;
	// SignInExpired: past its recorded expiry (R3).
	SignedIn, SignInExpired bool
}

// ProbeRow is one row of the ladder.
type ProbeRow struct {
	ID      string
	Verdict string
	Fails   func(ProbeFacts) bool
	Why     string
}

// ProbeLadder is the ladder, in order.
var ProbeLadder = []ProbeRow{
	{
		"R0", VerdictNotOffered, func(f ProbeFacts) bool { return !f.Offered && f.SandboxAuthorityMissing },
		"sandbox body not applied: this enrolment does not hold enforce.sandbox; ask your organization's admin for a managed enrolment token that grants it, then enrol again (`observer org enroll`)",
	},
	{"R0", VerdictNotOffered, func(f ProbeFacts) bool { return !f.Offered }, "offered only by an organization that runs an org-hosted gateway; none is published to this machine"},
	{"R1", VerdictComponentInactive, func(f ProbeFacts) bool { return !f.ComponentActive }, "the terminals.sandbox.openshell-org component is not active"},
	{"R1", VerdictNotInBackends, func(f ProbeFacts) bool { return !f.Listed }, "openshell-org is not in [terminal.sandbox].backends or your organization's managed list"},
	{"R2", VerdictUnsupportedPlatfm, func(f ProbeFacts) bool { return !f.PlatformOK }, "the org-hosted row's host side runs on a Linux or WSL2 daemon only"},
	{
		"R2", VerdictCustodyNotOffered, func(f ProbeFacts) bool { return f.Custody != "" && f.Custody != "home_relay" },
		"[terminal.sandbox.hosted].key_custody is set to an in-box custody; the org-hosted row keeps every model key on this laptop (home_relay only)",
	},
	{"R2", VerdictHomeRelayMissing, func(f ProbeFacts) bool { return !f.HomeRelayOK }, "no key the proxy adds itself is configured (a key stored for credential injection with `observer sandbox credentials add <provider>`, or the org AI gateway route; a routing key pool does not serve home_relay), so home_relay cannot serve the box"},
	{"R2b", VerdictLaptopRelayForbid, func(f ProbeFacts) bool { return f.OrgLaptopRelay == LaptopRelayForbidden }, "your organization does not allow org sandbox runs through a laptop, and this release has no other model route"},
	{"R2b", VerdictLaptopRelayNoOptIn, func(f ProbeFacts) bool { return !f.LaptopRelay }, "opt in to running org sandboxes through this laptop first (`observer sandbox org-shell opt-in`, or Settings)"},
	{"R3", VerdictSigninRequired, func(f ProbeFacts) bool { return !f.SignedIn }, "sign in to your organization's sandboxes first (`observer sandbox org-shell login`)"},
	{"R3", VerdictSigninExpired, func(f ProbeFacts) bool { return f.SignInExpired }, "your sign-in to your organization's sandboxes has expired (`observer sandbox org-shell login`)"},
}

// Probe walks the ladder and returns the first failing row ("" verdict when
// every local row passes).
func Probe(f ProbeFacts) (row, verdict, why string) {
	for _, r := range ProbeLadder {
		if r.Fails(f) {
			return r.ID, r.Verdict, r.Why
		}
	}
	return "", "", ""
}
