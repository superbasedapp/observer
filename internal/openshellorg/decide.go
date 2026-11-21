package openshellorg

import "time"

// The api role's side of the front's internal decision API (g1-design.md
// sections 7.6 and 7.7). The front evaluates the request-shape rows of its
// admit table itself (lane G3's admit.go); every check that needs the
// ledger, the grant or the member is answered here, never by state the front
// keeps. DecideCall is row F0 (the per-call check, repeated every 30 s on an
// open stream) followed by the ledger parts of rows F1 to F7.

// RPC names the call the front asks about. The OpenShell method names are
// used as they are; RPCClone is the front's bracketed clone (row F4a), an
// ExecSandbox whose request equals the run's recorded clone argv.
type RPC string

// The RPCs the decide table knows.
const (
	RPCHealth          RPC = "Health"
	RPCCreateSandbox   RPC = "CreateSandbox"
	RPCGetSandbox      RPC = "GetSandbox"
	RPCGetPolicyStatus RPC = "GetSandboxPolicyStatus"
	RPCGetSandboxLogs  RPC = "GetSandboxLogs"
	RPCWatchSandbox    RPC = "WatchSandbox"
	RPCClone           RPC = "Clone"
	RPCExecSandbox     RPC = "ExecSandbox"
	RPCExecInteractive RPC = "ExecSandboxInteractive"
	RPCDeleteSandbox   RPC = "DeleteSandbox"
)

// maxRunMinutesUnlimited is a MaxRunMinutes that sets no cap (tests only;
// the config always carries one).
const maxRunMinutesUnlimited = 0

// CallFacts are the inputs of one decide call, loaded by openshellctl.
type CallFacts struct {
	RPC RPC
	// TokenOK is the run token's verdict (issuer, audience, lifetime).
	TokenOK bool
	Purpose Purpose
	// RunID and BoxRunID are the token's sbo_run and sbo_box.
	RunID    string
	BoxRunID string
	MemberID string
	// BoxName is the name the node asked for; RecordedBoxName the ledger's.
	BoxName         string
	RecordedBoxName string
	Enabled         bool
	Drain           DrainState
	Grant           GrantFacts
	Member          MemberNow
	Box             BoxFacts
	// CreatedAt, ClonedAt and the provider stamps are the ledger's.
	CreatedAt          time.Time
	CloneArgv          bool
	HasProvider        bool
	ClonedAt           time.Time
	ProviderReadyAt    time.Time
	ProviderDetachedAt time.Time
	MaxRunMinutes      int
	Quotas             Quotas
	Usage              Usage
	Now                time.Time
}

// CallAction is what an allowed call carries back to the front.
type CallAction string

// The call actions.
const (
	// CallForward forwards the call with names forced.
	CallForward CallAction = "forward"
	// CallCreate creates the recorded spec.
	CallCreate CallAction = "create"
	// CallCloneBracket runs the bracketed clone of section 4.3.
	CallCloneBracket CallAction = "clone"
	// CallDelete deletes the box (row F6).
	CallDelete CallAction = "delete"
	// CallHealth answers the health call; no member token is needed.
	CallHealth CallAction = "health"
)

// callRow is one row of the call table.
type callRow struct {
	ID       string
	RPCs     []RPC
	Purposes []Purpose
	Check    func(f CallFacts) Reason
	Action   CallAction
}

func callBoxNamed(f CallFacts) Reason {
	if f.BoxName != f.RecordedBoxName {
		return ReasonRunNotYours
	}
	return ReasonNone
}

func callRunning(f CallFacts) Reason {
	if r := callBoxNamed(f); r != ReasonNone {
		return r
	}
	if f.Box.State != BoxCreated {
		return ReasonRunUnknown
	}
	if f.MaxRunMinutes > maxRunMinutesUnlimited && !f.CreatedAt.IsZero() &&
		f.Now.Sub(f.CreatedAt) > time.Duration(f.MaxRunMinutes)*time.Minute {
		return ReasonRunUnknown
	}
	return ReasonNone
}

// callTable is the ledger half of the admit table, walked top-down after F0;
// an RPC no row names is refused rpc_not_allowed (row F7).
var callTable = []callRow{
	{ID: "F1", RPCs: []RPC{RPCHealth}, Action: CallHealth, Check: func(CallFacts) Reason { return ReasonNone }},
	{ID: "F2", RPCs: []RPC{RPCCreateSandbox}, Purposes: []Purpose{PurposeCreate}, Action: CallCreate, Check: func(f CallFacts) Reason {
		if f.Box.State != BoxMinted {
			return ReasonRunUnknown
		}
		if f.Usage.MemberLive > f.Quotas.MaxConcurrentPerMember || f.Usage.OrgLive > f.Quotas.MaxConcurrentOrg {
			return ReasonQuotaConcurrent
		}
		return callBoxNamed(f)
	}},
	{
		ID: "F3", RPCs: []RPC{RPCGetSandbox, RPCGetPolicyStatus, RPCGetSandboxLogs, RPCWatchSandbox}, Action: CallForward,
		Check: callBoxNamed,
	},
	{ID: "F4a", RPCs: []RPC{RPCClone}, Purposes: []Purpose{PurposeCreate}, Action: CallCloneBracket, Check: func(f CallFacts) Reason {
		if r := callRunning(f); r != ReasonNone {
			return r
		}
		if !f.CloneArgv || !f.ClonedAt.IsZero() || !f.ProviderDetachedAt.IsZero() {
			return ReasonRPCNotAllowed
		}
		return ReasonNone
	}},
	{
		ID: "F4", RPCs: []RPC{RPCExecSandbox, RPCExecInteractive}, Purposes: []Purpose{PurposeCreate, PurposeAttach, PurposeReturn},
		Action: CallForward, Check: func(f CallFacts) Reason {
			if r := callRunning(f); r != ReasonNone {
				return r
			}
			// No exec of any kind while the repository provider is
			// attached; a clone-remote run execs only after its clone.
			if !f.ProviderReadyAt.IsZero() && f.ProviderDetachedAt.IsZero() {
				return ReasonRPCNotAllowed
			}
			if f.CloneArgv && f.ClonedAt.IsZero() && f.ProviderDetachedAt.IsZero() {
				return ReasonRPCNotAllowed
			}
			return ReasonNone
		},
	},
	{ID: "F6", RPCs: []RPC{RPCDeleteSandbox}, Purposes: []Purpose{PurposeTeardown}, Action: CallDelete, Check: func(f CallFacts) Reason {
		if r := callBoxNamed(f); r != ReasonNone {
			return r
		}
		if !f.Box.ReturnToNode && f.Box.ReturnedAt.IsZero() {
			return ReasonTeardownNeedsCollect
		}
		return ReasonNone
	}},
}

func hasRPC(list []RPC, r RPC) bool {
	for _, k := range list {
		if k == r {
			return true
		}
	}
	return false
}

func hasPurpose(list []Purpose, p Purpose) bool {
	if len(list) == 0 {
		return true
	}
	for _, k := range list {
		if k == p {
			return true
		}
	}
	return false
}

// DecideCall answers one decide call: row F0 (the token, the grant, the
// member, the drain state; the health call needs the token only), then the
// first call row naming the RPC. It answers the deciding row, the action and
// the reason; an RPC no row names, or a purpose the row does not allow, is
// rpc_not_allowed.
func DecideCall(f CallFacts) (rule string, act CallAction, r Reason) {
	if !f.TokenOK {
		return "F0", "", ReasonRunTokenInvalid
	}
	if f.RPC != RPCHealth {
		switch {
		case !f.Enabled:
			return "F0", "", ReasonOff
		case f.Drain != DrainActive:
			return "F0", "", ReasonDraining
		}
		if _, gr := CheckGrant(f.Grant, f.Member, f.Now); gr != ReasonNone {
			return "F0", "", gr
		}
		if !f.Member.Active || !f.Member.Allowed {
			return "F0", "", ReasonMemberNotAllowed
		}
		switch {
		case !f.Box.Found || f.Box.State.Terminal():
			return "F0", "", ReasonRunUnknown
		case f.Box.MemberID != f.MemberID || f.Box.ActiveRunID != f.RunID || f.Box.RunID != f.BoxRunID:
			return "F0", "", ReasonRunNotYours
		case f.Box.State == BoxHolding || f.Box.State == BoxHeld || f.Box.State == BoxCollectFailed || f.Box.State == BoxResuming:
			// A held box takes no calls through the front (section 3.6).
			return "F0", "", ReasonRunHeld
		}
	}
	for _, row := range callTable {
		if !hasRPC(row.RPCs, f.RPC) {
			continue
		}
		if !hasPurpose(row.Purposes, f.Purpose) {
			return row.ID, "", ReasonRPCNotAllowed
		}
		if reason := row.Check(f); reason != ReasonNone {
			return row.ID, "", reason
		}
		return row.ID, row.Action, ReasonNone
	}
	return "F7", "", ReasonRPCNotAllowed
}

// FrontEvent is an event the front reports (section 7.7).
type FrontEvent string

// The closed front events.
const (
	EventCreated          FrontEvent = "created"
	EventCloned           FrontEvent = "cloned"
	EventProviderDetached FrontEvent = "provider_detached"
	EventDisconnected     FrontEvent = "disconnected"
	EventEnding           FrontEvent = "ending"
	// EventCreateRefused is the front's report that the gateway refused the
	// create itself (a definitive refusal, F-L3R-4): no box exists, so the
	// row ends never_created and its reservation is released at once
	// rather than held until the reaper's R5.
	EventCreateRefused FrontEvent = "create_refused"
)

// eventRow is one row of the event table: the state the row must be in for
// the event to be the next legal move, whether only a create token may post
// it, and whether the per-call grant and member checks (row F0) apply.
// ending and disconnected stay open to a revoked member's token: they only
// move a box towards held or ended (G2-A9).
type eventRow struct {
	Event      FrontEvent
	From       []BoxState
	CreateOnly bool
	NeedsF0    bool
}

// eventTable is the event transition table; anything else is
// illegal_transition. The column stamps (cloned, provider_detached) are
// guarded again by the store's compare-and-set.
var eventTable = []eventRow{
	{EventCreated, []BoxState{BoxMinted}, true, true},
	{EventCloned, []BoxState{BoxCreated}, true, true},
	{EventProviderDetached, []BoxState{BoxCreated}, true, true},
	{EventDisconnected, []BoxState{BoxCreated}, false, false},
	{EventEnding, []BoxState{BoxCreated}, false, false},
	// create_refused needs no F0: a member revoked between the mint and the
	// create still ends the row, it never holds a box.
	{EventCreateRefused, []BoxState{BoxMinted}, true, false},
}

// CheckEventCall is the event route's whole decision: the token's purpose
// (a create token for created, cloned and provider_detached), then the
// per-call check's verdict f0 (ReasonNone when the grant and member still
// hold) where the row needs it, then the state move.
func CheckEventCall(ev FrontEvent, s BoxState, p Purpose, f0 Reason) Reason {
	for _, row := range eventTable {
		if row.Event != ev {
			continue
		}
		if row.CreateOnly && p != PurposeCreate {
			return ReasonRPCNotAllowed
		}
		if row.NeedsF0 && f0 != ReasonNone {
			return f0
		}
		return CheckEvent(ev, s)
	}
	return ReasonIllegalTransition
}

// CheckEvent reports whether ev is a legal next move of a row in state s.
func CheckEvent(ev FrontEvent, s BoxState) Reason {
	for _, row := range eventTable {
		if row.Event != ev {
			continue
		}
		for _, from := range row.From {
			if from == s {
				return ReasonNone
			}
		}
		return ReasonIllegalTransition
	}
	return ReasonIllegalTransition
}
