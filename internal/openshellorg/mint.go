package openshellorg

import (
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// Purpose is a run token's purpose (section 5.4).
type Purpose string

// The closed purposes.
const (
	PurposeProbe    Purpose = "probe"
	PurposeCreate   Purpose = "create"
	PurposeAttach   Purpose = "attach"
	PurposeReturn   Purpose = "return"
	PurposeTeardown Purpose = "teardown"
	PurposeResume   Purpose = "resume"
)

// AllPurposes is the closed set.
func AllPurposes() []Purpose {
	return []Purpose{PurposeProbe, PurposeCreate, PurposeAttach, PurposeReturn, PurposeTeardown, PurposeResume}
}

// Valid reports whether p is a member of the closed set.
func (p Purpose) Valid() bool {
	for _, k := range AllPurposes() {
		if k == p {
			return true
		}
	}
	return false
}

// Tier is an egress tier this row offers (section 6.1).
type Tier string

// The row's tiers.
const (
	TierNone      Tier = "none"
	TierProxyOnly Tier = "proxy_only"
	TierInternet  Tier = "internet"
)

// Source is a workspace source this row accepts (section 4.1).
type Source string

// The row's sources.
const (
	SourceCloneLocal  Source = "clone-local"
	SourceCloneRemote Source = "clone-remote"
)

// LaptopRelay is the org's laptop_relay setting (section 3.7).
type LaptopRelay string

// The closed laptop_relay values.
const (
	LaptopRelayAllowed   LaptopRelay = "allowed"
	LaptopRelayForbidden LaptopRelay = "forbidden"
)

// DrainState is the org's drain state (section 7.4).
type DrainState string

// The closed drain states.
const (
	DrainActive   DrainState = "active"
	DrainDraining DrainState = "draining"
	DrainBlocked  DrainState = "drain_blocked"
	DrainDrained  DrainState = "drained"
)

// Valid reports whether d is a member of the closed set.
func (d DrainState) Valid() bool {
	return d == DrainActive || d == DrainDraining || d == DrainBlocked || d == DrainDrained
}

// MintRequest is the node's signed mint body (section 5.4). Every field the
// compile uses travels here, so the org's compile works from signed inputs
// (G1-R1).
type MintRequest struct {
	GrantHandle            string   `json:"grant_handle"`
	RunID                  string   `json:"run_id"`
	Purpose                Purpose  `json:"purpose"`
	TS                     int64    `json:"ts"`
	Tier                   Tier     `json:"tier,omitempty"`
	Source                 Source   `json:"source,omitempty"`
	CloneURL               string   `json:"clone_url,omitempty"`
	NodeEgressAllowHosts   []string `json:"node_egress_allow_hosts,omitempty"`
	NodeRemoteAllowedHosts []string `json:"node_remote_allowed_hosts,omitempty"`
	SpecPreviewDigest      string   `json:"spec_preview_digest,omitempty"`
	LaptopRelay            bool     `json:"laptop_relay"`
	// BoxRunID names the held box, for resume only.
	BoxRunID string `json:"box_run_id,omitempty"`
}

// GitProviderRow is one git_providers row (section 4.3).
type GitProviderRow struct {
	Repository      string   `json:"repository"`
	ProviderProfile string   `json:"provider_profile"`
	AllowedTeams    []string `json:"allowed_teams,omitempty"`
	AllowedMembers  []string `json:"allowed_members,omitempty"`
}

// Allows reports whether the member, or one of the member's teams, is on
// the row. Empty lists allow nobody (G1-R8).
func (g GitProviderRow) Allows(memberID string, teams []string) bool {
	for _, m := range g.AllowedMembers {
		if m == memberID {
			return true
		}
	}
	for _, t := range g.AllowedTeams {
		for _, mt := range teams {
			if t == mt {
				return true
			}
		}
	}
	return false
}

// OrgValues are the org's settings the mint narrows the node's inputs
// against (sections 2.5, 4.3 and 6.1). RemoteAllowedHosts and
// AllowRemoteClone are the managed body's existing fields.
type OrgValues struct {
	Tiers              []Tier
	EgressAllowHosts   []string
	AllowCIDRs         []string
	BlockedCIDRs       []string
	RemoteAllowedHosts []string
	AllowRemoteClone   bool
	GitProviders       []GitProviderRow
	LaptopRelay        LaptopRelay
	HoldPolicy         HoldPolicy
	ReturnToNode       bool
	// HostAddrs are the sandbox host's own address entries as the gateway
	// sync last recorded them (the configured sandbox_host_addrs). An
	// internet run compiles them through HostAddrsOf.
	HostAddrs []string
	// HostAddrsKnown says HostAddrs was read: the reader is wired and found
	// the sync's row (RC1-A1). An internet create or resume whose list is
	// not known is refused, never compiled with no host carve-out.
	HostAddrsKnown bool
}

// SyncFacts is the gateway sync's last soundness row (T8).
type SyncFacts struct {
	Present   bool
	Sound     bool
	CheckedAt time.Time
	Interval  time.Duration
	// ProfilesKnown says the last sync read the gateway's provider
	// profiles; ProviderProfiles are their ids (FX3 item 4).
	ProfilesKnown    bool
	ProviderProfiles []string
}

// MissingProfile reports whether a git_providers row names a provider
// profile the gateway does not have, as the last sync read it (false when
// the list is not known, or the row names none).
func (s SyncFacts) MissingProfile(profile string) bool {
	return s.ProfilesKnown && profile != "" && !slices.Contains(s.ProviderProfiles, profile)
}

// MintFacts are every input of the mint table, loaded by the store seam and
// the route before the walk. The walk itself does no I/O.
type MintFacts struct {
	// ProofOK is the T0 verdict the route computed: the agent-key signature
	// over NodeMessage verified, fresh and not replayed.
	ProofOK bool
	// Enabled is [openshell].enabled; Compiled is the component in the image.
	Enabled  bool
	Compiled bool
	Drain    DrainState
	// Managed is membertenancy's managed verdict for the enrolment.
	Managed bool
	Grant   GrantFacts
	Member  MemberNow
	// MemberTeams are the member's team ids (for the git_providers rows).
	MemberTeams []string
	// NodeID is the enrolment's node id the request came from.
	NodeID  string
	Request MintRequest
	Org     OrgValues
	// Box is the ledger row: by run id for create, by the active run id for
	// attach, return and teardown, by box_run_id for resume.
	Box    BoxFacts
	Quotas Quotas
	Usage  Usage
	Sync   SyncFacts
	// RecompiledDigest is today's compile of a held box's recorded inputs
	// (resume only).
	RecompiledDigest string
	Now              time.Time
}

// MintAction is what the mint does on allow.
type MintAction string

// The mint actions.
const (
	// MintActionToken answers a token and records nothing on the ledger
	// beyond the jti (probe, attach, teardown).
	MintActionToken MintAction = "token"
	// MintActionReserve records a new ledger row in state minted with the
	// org-compiled spec and reserves the quota (create).
	MintActionReserve MintAction = "reserve"
	// MintActionReuse answers a fresh token for an existing minted
	// reservation (an idempotent create retry, T6).
	MintActionReuse MintAction = "reuse"
	// MintActionRecordReturn answers a token and sets return_minted_at.
	MintActionRecordReturn MintAction = "record_return"
	// MintActionResume moves a held box to resuming (T7r).
	MintActionResume MintAction = "resume"
	// MintActionResumeReuse answers a fresh token for an existing resuming
	// box with the same new run id.
	MintActionResumeReuse MintAction = "resume_reuse"
)

// Narrowed are the effective inputs T5b leaves for the compile.
type Narrowed struct {
	Tier        Tier
	Source      Source
	EgressHosts []string
	CloneHosts  []string
	CloneURL    string
	// GitProvider is the git_providers row of the clone, nil without one.
	GitProvider *GitProviderRow
}

// MintDecision is the walk's answer.
type MintDecision struct {
	Allow  bool
	Rule   string
	Reason Reason
	Action MintAction
	Inputs Narrowed
}

// mintRule is one row of the mint table.
type mintRule struct {
	ID string
	// Purposes the row applies to; empty means every purpose.
	Purposes []Purpose
	Check    func(f *MintFacts, d *MintDecision) Reason
}

func (r mintRule) applies(p Purpose) bool {
	if len(r.Purposes) == 0 {
		return true
	}
	for _, k := range r.Purposes {
		if k == p {
			return true
		}
	}
	return false
}

// mintTable is the closed rule table of section 5.4, walked top-down; the
// first refusal wins. T6 and T7r also choose the action.
var mintTable = []mintRule{
	{ID: "T0", Check: func(f *MintFacts, _ *MintDecision) Reason {
		if !f.ProofOK || !f.Request.Purpose.Valid() || !SafeID(f.Request.RunID) {
			return ReasonProofInvalid
		}
		return ReasonNone
	}},
	{ID: "T1", Check: func(f *MintFacts, _ *MintDecision) Reason {
		switch {
		case !f.Enabled || !f.Compiled:
			return ReasonOff
		case f.Drain != DrainActive:
			return ReasonDraining
		}
		return ReasonNone
	}},
	{ID: "T2", Check: func(f *MintFacts, _ *MintDecision) Reason {
		if !f.Managed {
			return ReasonNodeNotManaged
		}
		return ReasonNone
	}},
	{ID: "T3-T4", Check: func(f *MintFacts, _ *MintDecision) Reason {
		_, r := CheckGrant(f.Grant, f.Member, f.Now)
		return r
	}},
	{ID: "T5", Check: func(f *MintFacts, _ *MintDecision) Reason {
		if !f.Member.Active || !f.Member.Allowed {
			return ReasonMemberNotAllowed
		}
		return ReasonNone
	}},
	{ID: "T5b", Purposes: []Purpose{PurposeCreate, PurposeResume}, Check: checkNarrowing},
	{ID: "T6", Purposes: []Purpose{PurposeCreate}, Check: checkCreate},
	{ID: "T7", Purposes: []Purpose{PurposeAttach, PurposeReturn, PurposeTeardown}, Check: checkRunOwned},
	{ID: "T7x", Purposes: []Purpose{PurposeReturn, PurposeTeardown}, Check: checkReturnPolicy},
	{ID: "T7r", Purposes: []Purpose{PurposeResume}, Check: func(f *MintFacts, d *MintDecision) Reason {
		act, r := CheckResume(ResumeFacts{
			Box: f.Box, MemberID: f.Member.ID, NewRunID: f.Request.RunID,
			Quotas: f.Quotas, Usage: f.Usage, RecompiledDigest: f.RecompiledDigest, Now: f.Now,
		})
		if r != ReasonNone {
			return r
		}
		d.Action = MintActionResume
		if act == ResumeReuse {
			d.Action = MintActionResumeReuse
		}
		return ReasonNone
	}},
	{ID: "T7h", Check: func(f *MintFacts, _ *MintDecision) Reason {
		switch {
		case f.Org.LaptopRelay != LaptopRelayAllowed:
			return ReasonLaptopRelayForbidden
		case !f.Request.LaptopRelay:
			return ReasonLaptopRelayNotOptedIn
		}
		return ReasonNone
	}},
	{ID: "T8", Check: func(f *MintFacts, _ *MintDecision) Reason {
		switch {
		case !f.Sync.Present:
			return ReasonGatewayStateStale
		case f.Sync.Interval <= 0 || f.Now.Sub(f.Sync.CheckedAt) > 3*f.Sync.Interval:
			return ReasonGatewayStateStale
		case !f.Sync.Sound:
			return ReasonGatewayUnsound
		}
		return ReasonNone
	}},
}

// MintRuleIDs lists the table's rule ids in walk order.
func MintRuleIDs() []string {
	out := make([]string, 0, len(mintTable))
	for _, r := range mintTable {
		out = append(out, r.ID)
	}
	return out
}

// DecideMint walks the mint table. On allow the decision carries the action
// and, for create and resume, the narrowed inputs of T5b.
func DecideMint(f MintFacts) MintDecision {
	d := MintDecision{Action: MintActionToken}
	if f.Request.Purpose == PurposeReturn {
		d.Action = MintActionRecordReturn
	}
	for _, r := range mintTable {
		if !r.applies(f.Request.Purpose) {
			continue
		}
		if reason := r.Check(&f, &d); reason != ReasonNone {
			return MintDecision{Rule: r.ID, Reason: reason}
		}
	}
	d.Allow = true
	return d
}

func containsTier(ts []Tier, t Tier) bool {
	for _, k := range ts {
		if k == t {
			return true
		}
	}
	return false
}

// narrowHosts intersects the node's list with the org's, case-insensitive,
// and answers the org list when the node's is empty. The result is never
// wider than the org's list.
func narrowHosts(org, node []string) []string {
	if len(node) == 0 {
		return append([]string(nil), org...)
	}
	var out []string
	for _, n := range node {
		for _, o := range org {
			if strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(o)) {
				out = append(out, strings.ToLower(strings.TrimSpace(o)))
				break
			}
		}
	}
	return out
}

// checkNarrowing is T5b: every node input only narrows the org's values.
func checkNarrowing(f *MintFacts, d *MintDecision) Reason {
	n, r := NarrowInputs(*f)
	if r != ReasonNone {
		return r
	}
	d.Inputs = n
	return ReasonNone
}

// hostAddrRows is the internet tier's host-address check, walked top-down
// (RC1-A1, A2): every row is fail-closed, because the list is a deny-side
// input the gateway does not report.
var hostAddrRows = []struct {
	refuse func(OrgValues) bool
	reason Reason
}{
	// No sync row, or no reader wired: the list is not known.
	{func(o OrgValues) bool { return !o.HostAddrsKnown }, ReasonGatewayStateStale},
	// The org listed none.
	{func(o OrgValues) bool { return len(o.HostAddrs) == 0 }, ReasonHostAddrsMissing},
	// An entry the compile cannot take.
	{func(o OrgValues) bool { _, r := HostAddrsOf(o.HostAddrs); return r != ReasonNone }, ReasonHostAddrsInvalid},
}

// checkHostAddrs walks hostAddrRows: the first refusing row's reason.
func checkHostAddrs(o OrgValues) Reason {
	for _, row := range hostAddrRows {
		if row.refuse(o) {
			return row.reason
		}
	}
	return ReasonNone
}

// NarrowInputs is T5b's computation on its own: the narrowed inputs, or the
// refusal. The mint calls it before the walk for a resume, to recompile the
// held box's spec under today's org values (T7r's input), so the walk runs
// once with the recompiled digest (G2-A1).
func NarrowInputs(f MintFacts) (Narrowed, Reason) {
	req := f.Request
	if !containsTier(f.Org.Tiers, req.Tier) {
		return Narrowed{}, ReasonInputWidensOrg
	}
	switch req.Source {
	case SourceCloneLocal:
	case SourceCloneRemote:
		if !f.Org.AllowRemoteClone {
			return Narrowed{}, ReasonInputWidensOrg
		}
	default:
		return Narrowed{}, ReasonInputWidensOrg
	}
	n := Narrowed{
		Tier: req.Tier, Source: req.Source,
		EgressHosts: narrowHosts(f.Org.EgressAllowHosts, req.NodeEgressAllowHosts),
	}
	if req.Tier == TierInternet && len(f.Org.BlockedCIDRs) == 0 {
		return Narrowed{}, ReasonBlockedCIDRsMissing
	}
	if req.Tier == TierInternet {
		if r := checkHostAddrs(f.Org); r != ReasonNone {
			return Narrowed{}, r
		}
	}
	if req.Source == SourceCloneRemote {
		if req.Tier != TierInternet {
			return Narrowed{}, ReasonRemoteCloneNeedsEgress
		}
		if len(f.Org.RemoteAllowedHosts) == 0 {
			return Narrowed{}, ReasonRemoteCloneHostsMissing
		}
		n.CloneHosts = narrowHosts(f.Org.RemoteAllowedHosts, req.NodeRemoteAllowedHosts)
		if len(n.CloneHosts) == 0 {
			return Narrowed{}, ReasonRemoteCloneHostsDisjoint
		}
		if workspace.ValidateRemoteURL(req.CloneURL, n.CloneHosts) != nil {
			return Narrowed{}, ReasonCloneURLInvalid
		}
		norm := NormalizeRepository(req.CloneURL)
		if norm == "" {
			return Narrowed{}, ReasonCloneURLInvalid
		}
		n.CloneURL = req.CloneURL
		for i := range f.Org.GitProviders {
			row := f.Org.GitProviders[i]
			if NormalizeRepository(row.Repository) != norm {
				continue
			}
			if !row.Allows(f.Member.ID, f.MemberTeams) {
				return Narrowed{}, ReasonCloneRepositoryNotAllowed
			}
			if f.Sync.MissingProfile(row.ProviderProfile) {
				// The gateway has no profile to make the repository's
				// provider from (OpenShell 0.1.6 ships no `git` one): refused
				// at the mint, before a box exists, never left to the clone's
				// provider_not_ready (FX3 item 4).
				return Narrowed{}, ReasonGitProfileMissing
			}
			n.GitProvider = &row
			break
		}
	} else if req.CloneURL != "" {
		return Narrowed{}, ReasonInputWidensOrg
	}
	return n, ReasonNone
}

// checkCreate is T6: idempotent per run id, else one more box within quota.
func checkCreate(f *MintFacts, d *MintDecision) Reason {
	if f.Box.Found {
		switch {
		case f.Box.MemberID != f.Member.ID:
			return ReasonRunNotYours
		case f.Box.State == BoxMinted:
			d.Action = MintActionReuse
			return ReasonNone
		}
		return ReasonRunExists
	}
	if r := CheckCreateQuota(f.Quotas, f.Usage); r != ReasonNone {
		return r
	}
	d.Action = MintActionReserve
	return ReasonNone
}

// checkRunOwned is T7: the box exists, is the member's and the requesting
// node's, the run id is its active run id, and it is not ended, reaped or
// held.
func checkRunOwned(f *MintFacts, _ *MintDecision) Reason {
	b := f.Box
	switch {
	case !b.Found || b.State.Terminal():
		return ReasonRunUnknown
	case b.MemberID != f.Member.ID || b.NodeID != f.NodeID || b.ActiveRunID != f.Request.RunID:
		return ReasonRunNotYours
	case b.State == BoxHolding || b.State == BoxHeld || b.State == BoxCollectFailed:
		return ReasonRunHeld
	}
	return ReasonNone
}

// checkReturnPolicy is T7x: the run's recorded return_to_node decides.
func checkReturnPolicy(f *MintFacts, _ *MintDecision) Reason {
	switch f.Request.Purpose {
	case PurposeReturn:
		if !f.Box.ReturnToNode {
			return ReasonReturnWithheld
		}
	case PurposeTeardown:
		if !f.Box.ReturnToNode && f.Box.ReturnedAt.IsZero() {
			return ReasonTeardownNeedsCollect
		}
	}
	return ReasonNone
}
