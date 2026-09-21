package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// P0-6 effective-policy-state reporter wiring (docs/plans/
// plane-a-p0-6-effective-policy-state-plan.md §4.3). This file owns the FOUR
// injected point readers, the independent-reporter goroutine (startup +
// heartbeat + on-change), and the Notifier.
//
// The start.go wiring HAS SHIPPED: `observer start` constructs the reporter
// and registers the outcome sinks whenever [org_client.share].policy_state
// is on. (An earlier revision of this comment said that edit was deferred
// behind the D1 gate while start.go was an uncommitted carve-out; it is
// not, and a stale "this is not wired yet" note beside wired code is how the
// next reader concludes a live reporting path is dead.) Everything here is
// still DORMANT on a node that has not opted in: with no sinks registered,
// the orgclient loops behave exactly as before (nil-sink no-op, R6-1).

// policyStatePoster is the sender seam (satisfied by *orgclient.Client). An
// interface so the reporter unit-tests with a fake poster, no live daemon.
type policyStatePoster interface {
	PostPolicyState(ctx context.Context, report orgcontract.PolicyStateReport) error
	// ManagedMachineIdentity returns this host's org-salted machine
	// fingerprint when enrolled under managed tenancy, "" otherwise
	// (fail-open — see *orgclient.Client.ManagedMachineIdentity). The
	// generation-ladder report() calls this once per report() invocation
	// to stamp the gen2 send; a gen1-projected send always sends "".
	ManagedMachineIdentity(ctx context.Context) string
}

// policyStateNotifier is the on-change seam (§4.3 / R2-B7): a buffered-size-1
// poke channel. Poke() does a NONBLOCKING send, so multiple pokes during an
// in-flight report coalesce to exactly one follow-up.
type policyStateNotifier struct {
	poke chan struct{}
}

func newPolicyStateNotifier() *policyStateNotifier {
	return &policyStateNotifier{poke: make(chan struct{}, 1)}
}

// Poke schedules one coalesced follow-up report. Nonblocking + nil-safe.
func (n *policyStateNotifier) Poke() {
	if n == nil {
		return
	}
	select {
	case n.poke <- struct{}{}:
	default:
	}
}

// guardRunning is the guard org-layer running identity read TOGETHER from
// Guard.PolicyStates() (R2-B2 — version + hash never re-derived separately from
// the dedup-prone guard_policy_state row).
type guardRunning struct {
	RunningVersion int64
	EffectiveHash  string
	Mode           string
}

// --- point readers (the injected I/O boundary) ----------------------------

// newGuardPointReader builds the guard PointReader (§4.3). cachedVersion reads
// the verified bundle-cache envelope Version (B9); running reads the live
// Guard.PolicyStates() org entry (0 + empty when the org layer is ABSENT,
// R3-B2); lastFetch is the reporter's in-memory typed last-fetch slot (the only
// source of delivered_unaccepted / stale_lkg). HasOrgRail is always true.
func newGuardPointReader(
	cachedVersion func() (int64, error),
	running func() guardRunning,
	lastFetch func() orgclient.GuardFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		cached, err := cachedVersion()
		if err != nil {
			return policystate.PointFacts{}, fmt.Errorf("guard cached version: %w", err)
		}
		r := running()
		o := lastFetch()
		return policystate.PointFacts{
			CachedAcceptedVersion: cached,
			RunningVersion:        r.RunningVersion,
			EffectiveHash:         r.EffectiveHash,
			LatestFetchRejected:   o.RejectCode != "",
			RejectedVersion:       o.Version,
			RejectCode:            string(o.RejectCode),
			Unreachable:           o.Unreachable,
			EnforceMode:           r.Mode,
			HasOrgRail:            true,
			LastSeen:              now(),
		}, nil
	}
}

// newRouterPointReader builds the router PointReader (§4.3). cachedVersion
// reads store.GetOrgRoutingPolicy; the RoutingStateHandle supplies the running
// version + org-layer hash + mode; lastFetch is the routing last-fetch slot. A
// nil handle means routing is off → HasOrgRail=false → none/no_policy.
func newRouterPointReader(
	handle *RoutingStateHandle,
	cachedVersion func(ctx context.Context) (int64, error),
	lastFetch func() orgclient.RoutingFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(ctx context.Context) (policystate.PointFacts, error) {
		cached, err := cachedVersion(ctx)
		if err != nil {
			return policystate.PointFacts{}, fmt.Errorf("router cached version: %w", err)
		}
		o := lastFetch()
		f := policystate.PointFacts{
			CachedAcceptedVersion: cached,
			LatestFetchRejected:   o.RejectCode != "",
			RejectedVersion:       o.Version,
			RejectCode:            string(o.RejectCode),
			Unreachable:           o.Unreachable,
			EnforceMode:           "off",
			LastSeen:              now(),
		}
		if handle != nil {
			f.HasOrgRail = true
			// ONE atomic load of the whole triple (P0-7 SHOULD-FIX 4) so a
			// reload between accessors cannot yield a mixed report.
			if v, hash, mode, ok := handle.Snapshot(); ok {
				f.RunningVersion = v
				f.EffectiveHash = hash
				f.EnforceMode = mode
			}
		}
		return f, nil
	}
}

// newAdmitterPointReader / newEgressPointReader build the two proxy-family
// point readers (§4.3 + P0-5 §7.1/§7.3). They read the obs handle's live
// Org/Local layers + the reporter's per-family last-fetch slot.
//
// HasOrgRail is true exactly when a verified org-published policy is
// installed (already revalidated against the live enrolment identity by
// PolicyStateFacts). LOCKED (plan §4.3 fork 1): when HasOrgRail, wire
// EffectiveHash is the signed BodyHash — Spec.Hash is an internal cache
// key only and must never appear on the org-rail wire. Local rows still
// carry Spec.Hash as EffectiveHash (local_effective discriminator).
// A nil handle yields the zero facts → no_policy (the method is nil-safe).
func newAdmitterPointReader(
	handle *obsAdmissionHandle,
	lastFetch func() orgclient.PolicyResourceFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(ctx context.Context) (policystate.PointFacts, error) {
		facts := handle.PolicyStateFacts(ctx)
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		f := policystate.PointFacts{
			EnforceMode:         facts.AdmitterMode,
			HasOrgRail:          facts.AdmitterHasOrgRail,
			InertReason:         facts.AdmitterInertReason,
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     o.Version,
			Unreachable:         o.Unreachable,
		}
		if facts.AdmitterHasOrgRail {
			// PublishOrgAdmission only ever installs a layer right after
			// its version durably commits (no separate accept-then-later-
			// reload lag for this rail), so cached==running always.
			f.CachedAcceptedVersion = facts.AdmitterOrgVersion
			f.RunningVersion = facts.AdmitterOrgVersion
			f.EffectiveHash = facts.AdmitterBodyHash // org-rail identity = BodyHash
		} else {
			f.EffectiveHash = facts.AdmitterHash // local Spec.Hash
		}
		return f, nil
	}
}

func newEgressPointReader(
	handle *obsAdmissionHandle,
	lastFetch func() orgclient.PolicyResourceFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(ctx context.Context) (policystate.PointFacts, error) {
		facts := handle.PolicyStateFacts(ctx)
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		f := policystate.PointFacts{
			EnforceMode:         facts.EgressMode,
			HasOrgRail:          facts.EgressHasOrgRail,
			InertReason:         facts.EgressInertReason,
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     o.Version,
			Unreachable:         o.Unreachable,
		}
		if facts.EgressHasOrgRail {
			f.CachedAcceptedVersion = facts.EgressOrgVersion
			f.RunningVersion = facts.EgressOrgVersion
			f.EffectiveHash = facts.EgressBodyHash
		} else {
			f.EffectiveHash = facts.EgressHash
		}
		return f, nil
	}
}

// newGatewayPointReader builds the gateway.providers PointReader (v2,
// docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.2). Its
// facts come from the install seam (*gatewayProvidersHandle), which is both
// the only SetLaneTable caller and the only holder of the accepted org
// resource's identity; the LOCAL hash inside Facts() is a live read of the
// running lane table.
//
// Mode is a PROJECTION, not a body field: gateway.providers bodies carry no
// mode at all (policyfam.SpecRequestsEnforceMode's gateway arm: "there is no
// 'observe' posture for a lane table"). enforce = some table is routing,
// observe = an org table was accepted but is NOT routing (which is also what
// the server's accepted_inert ⇒ observe rule requires), off = nothing is
// routing.
//
// Reject precedence mirrors admitter/egress: the fetch-outcome slot (a
// DELIVERY failure — signature, key pin, replay, selectors) wins over a local
// install failure, because a delivery failure is strictly upstream of it and
// is the more actionable of the two. Both resolve to delivered_unaccepted.
func newGatewayPointReader(
	gw *gatewayProvidersHandle,
	lastFetch func() orgclient.PolicyResourceFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		g := gw.Facts()
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		rejectedVersion := o.Version
		if reject == "" && g.ApplyRejectCode != "" {
			// The proxy refused a delivered lane table (a reserved lane id, an
			// unparseable base URL, an auto_default_lane naming nothing):
			// a runtime realization failure, which §7.2 classes as
			// capability_mismatch. The previous table is still routing, so
			// running stays where it was.
			reject = g.ApplyRejectCode
			rejectedVersion = g.ApplyFailedVersion
		}
		f := policystate.PointFacts{
			HasOrgRail:          g.HasOrgRail,
			InertReason:         g.InertReason,
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     rejectedVersion,
			Unreachable:         o.Unreachable,
		}
		switch {
		case g.HasOrgRail && g.InertReason != "":
			// Accepted, durably committed, deliberately NOT routing.
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "observe"
		case g.HasOrgRail:
			// The lane table is hot-swapped, so an accepted version is a
			// running version — cached==running always, and pending_restart
			// is unreachable FOR THE GATEWAY.PROVIDERS POINT by construction.
			//
			// That is a property of THIS point, not a general one. The
			// node.governance point reaches pending_restart as of Phase 1b
			// (see newNodeGovernancePointReader): its `pinned` directive
			// class is restart-bound for the daemon's own subsystems,
			// because start.go reads config once.
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "enforce"
		case g.LocalHash != "":
			// The node's own [proxy.upstreams] are routing.
			f.EffectiveHash = g.LocalHash
			f.EnforceMode = "enforce"
		default:
			f.EnforceMode = "off"
		}
		return f, nil
	}
}

// newNodeFeaturesPointReader builds the node.features PointReader (org-parity
// W5.1). Its facts come from the nodeFeaturesHandle install seam — the only
// holder of the accepted spec's identity — via Facts(), never from a live
// read of the compiled *nodefeatures.PolicySpec itself (the reader has no
// business knowing the family's own decoded shape; that stays behind
// nodeFeaturesHandle.Allowed/TerminalAllowed).
//
// Mode is a PROJECTION exactly as for gateway.providers/node.governance: the
// node.features body carries no mode field, because a feature is either
// governing this node's enforcement seams right now or it isn't. enforce =
// the spec is installed and every gated seam consults it; observe = a body
// was accepted but is inert (not preauthorized — every seam stays fail-open,
// which is also what the server's accepted_inert => observe rule requires);
// off = no org rail at all (an ungoverned/solo node — there is no local
// overlay to fall back to, so this is always no_policy, never
// local_effective, matching node.governance's same reasoning).
//
// pending_restart is unreachable today: nodeFeaturesHandle.Facts() is read
// live at the moment of each enforcement seam (terminal launch, remote arm/
// pair, routing apply, patterns write), never cached into a restart-bound
// process-startup snapshot the way node.governance's pinned config is.
func newNodeFeaturesPointReader(
	nf *nodeFeaturesHandle,
	lastFetch func() orgclient.PolicyResourceFetchOutcome,
	now func() time.Time,
) policystate.PointReader {
	return func(context.Context) (policystate.PointFacts, error) {
		g := nf.Facts()
		o := orgclient.PolicyResourceFetchOutcome{}
		if lastFetch != nil {
			o = lastFetch()
		}
		reject := wirePolicyResourceRejectReason(o.RejectCode)
		f := policystate.PointFacts{
			HasOrgRail:          g.HasOrgRail,
			InertReason:         g.InertReason,
			LastSeen:            now(),
			LatestFetchRejected: reject != "",
			RejectCode:          reject,
			RejectedVersion:     o.Version,
			Unreachable:         o.Unreachable,
		}
		switch {
		case g.HasOrgRail && !g.InEffect:
			// Accepted, durably committed, deliberately NOT governing (the
			// preauthorization gate rejected it) — every seam stays fail-open.
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "observe"
		case g.HasOrgRail:
			f.CachedAcceptedVersion = g.Version
			f.RunningVersion = g.Version
			f.EffectiveHash = g.BodyHash
			f.EnforceMode = "enforce"
		default:
			// No org rail. There is no local feature-governance overlay — a
			// solo node's features are simply ungoverned — so this is always
			// no_policy, never local_effective.
			f.EnforceMode = "off"
		}
		return f, nil
	}
}

// wirePolicyResourceRejectReason maps an orgclient PolicyResourceRejectCode
// onto the closed orgcontract Reason enum the PolicyAck server allowlist
// accepts for delivered_unaccepted (plan §7.1/§7.2). Codes with no wire
// pairing (identity_changed — ClearOrg, not a delivered reject; empty)
// return "" so LatestFetchRejected stays false.
func wirePolicyResourceRejectReason(code orgclient.PolicyResourceRejectCode) string {
	switch code {
	case orgclient.PRRejectSigInvalid:
		return orgcontract.ReasonSigInvalid
	case orgclient.PRRejectKeyPinMismatch:
		return orgcontract.ReasonKeyPinMismatch
	case orgclient.PRRejectCapabilityMismatch,
		orgclient.PRRejectClosedEnvelope,
		orgclient.PRRejectDecodeFailed:
		// Closed-envelope / decode failures are compile/runtime capability
		// class failures (§7.4) → capability_mismatch, not accepted_inert.
		return orgcontract.ReasonCapabilityMismatch
	case orgclient.PRRejectSelectorMismatch:
		// P0-10 Phase B targeting corroboration: the signed selectors
		// contradict this node's configured [org_client.policy] attributes.
		// MUST land in the same commit as the server-side allow-list entry
		// (internal/orgserver/api/policystate.go) — an agent emitting a reason
		// a server does not allow 400s the WHOLE policy-state snapshot, not
		// just this row.
		return orgcontract.ReasonSelectorMismatch
	case orgclient.PRRejectFamilyNotAccepted:
		// gen2 P4-2: the resource verified but this node's
		// [org_client.policy].accept_families does not list the family — it
		// was never installed at all, which is a DIFFERENT fact than a
		// capability-shape mismatch on a family the node DID accept. Pairs
		// only with PRDeliveredUnaccepted (see acceptPolicyResourceGates),
		// so this is a delivered_unaccepted row, never accepted_inert.
		return orgcontract.ReasonFamilyNotAccepted
	case orgclient.PRRejectVersionDowngrade:
		return orgcontract.ReasonVersionDowngrade
	case orgclient.PRRejectVersionReplay:
		return orgcontract.ReasonVersionReplay
	default:
		return ""
	}
}

// --- daemon-side source helpers (constructed from start.go) ----------------

// guardCachedVersionFromFile reads the verified bundle-cache envelope Version
// (B9). An empty cache path or a MISSING file is the legitimate first-install
// "no cached accepted bundle yet" state → (0, nil). A file that exists but
// cannot be read (a non-not-exist error) or does not parse as JSON is a genuine
// error → (0, err), so the reader errors, Assemble omits the guard point, and
// the reporter skips the short snapshot rather than fabricating a version-0 row
// (§4.1/§4.3).
func guardCachedVersionFromFile(cachePath string) func() (int64, error) {
	return func() (int64, error) {
		if cachePath == "" {
			return 0, nil
		}
		raw, err := os.ReadFile(cachePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return 0, nil
			}
			return 0, err
		}
		var env struct {
			Version int64 `json:"version"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return 0, err
		}
		return env.Version, nil
	}
}

// guardRunningFromGuard reads the live Guard.PolicyStates() org-layer entry
// (version + hash TOGETHER, R2-B2). Absent org layer (first install /
// not-yet-loaded / rejected) → 0 + empty hash (R3-B2). Guard mode comes from
// the whole-guard mode (guard is always enforceIntent; mode is wire display).
func guardRunningFromGuard(g *guard.Guard) func() guardRunning {
	return func() guardRunning {
		if g == nil {
			return guardRunning{}
		}
		out := guardRunning{Mode: string(g.Mode())}
		for _, st := range g.PolicyStates() {
			if st.Layer == "org" {
				out.RunningVersion, _ = strconv.ParseInt(st.Version, 10, 64)
				out.EffectiveHash = st.ContentHash
				break
			}
		}
		return out
	}
}

// routerCachedVersionFromStore reads the cached org routing-policy version via
// the store seam. A genuine store/DB error propagates as (0, err) so the reader
// errors and Assemble omits the router point (§4.1/§4.3); !ok (no policy
// cached) is the legitimate version-0 state → (0, nil).
func routerCachedVersionFromStore(st *store.Store) func(ctx context.Context) (int64, error) {
	return func(ctx context.Context) (int64, error) {
		row, ok, err := st.GetOrgRoutingPolicy(ctx)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, nil
		}
		return row.Version, nil
	}
}

// policyStateSeqPath resolves the 0600 monotonic-counter sidecar location
// (§2.2): beside the org bundle cache when set, else beside the observer DB so
// a path always exists.
func policyStateSeqPath(cfg config.Config) string {
	if p := orgBundleCachePath(cfg); p != "" {
		return filepath.Join(filepath.Dir(p), "policy-state-seq")
	}
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "policy-state-seq")
}

// --- the reporter ----------------------------------------------------------

// policyStateReporter owns the two typed last-fetch slots, the four readers,
// the ReportSeq source, and the nonblocking single-flight report(). It is the
// daemon-lifetime object; the guard/routing outcome sinks (recordGuard /
// recordRouting) are the callbacks start.go registers on the orgclient.
type policyStateReporter struct {
	poster       policyStatePoster
	readers      map[string]policystate.PointReader
	seq          *orgclient.ReportSeqCounter
	agentVersion string
	enabled      bool
	logger       *slog.Logger
	notifier     *policyStateNotifier

	// ngov is the node.governance handle, consulted (W-9, raise added §5.3) so
	// an org "policy_state" share directive can LOWER this channel off even
	// though [org_client.share].policy_state is configured true locally, or —
	// on a managed node granted extract.policy_state — RAISE it on even
	// though the local config left it false. nil in the raw
	// newPolicyStateReporter test constructor (report() falls back to
	// r.enabled unchanged in that case) — only buildPolicyStateReporter,
	// which owns a live handle, populates it.
	ngov *nodeGovernanceHandle

	mu           sync.Mutex
	lastGuard    orgclient.GuardFetchOutcome
	lastRouting  orgclient.RoutingFetchOutcome
	lastAdmitter orgclient.PolicyResourceFetchOutcome
	lastEgress   orgclient.PolicyResourceFetchOutcome
	lastGateway  orgclient.PolicyResourceFetchOutcome
	lastGovern   orgclient.PolicyResourceFetchOutcome
	lastFeatures orgclient.PolicyResourceFetchOutcome

	running     atomic.Bool // single-flight guard for report()
	unsupported atomic.Bool // 404/405 latch (S8)
	// latched / latchDepth implement the OPTIONAL-POINT LADDER probe
	// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §3.8,
	// adversarial review A11; generalizing
	// docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §3.2).
	//
	// An older server 400s a snapshot carrying an optional point it does not
	// know. The FIRST such rejection is answered by re-POSTing with the
	// NEWEST optional point dropped, then the next, down to core-only; the
	// reporter latches at the highest depth that was ACCEPTED, which no other
	// failure mode produces. probed makes the whole ladder run at most once
	// per daemon lifetime (bounded at len(OptionalPoints)+1 extra requests).
	//
	// The depth is the count of OptionalPoints (in generation order) that are
	// still sent, so depth==len(OptionalPoints) is "everything" and depth==0
	// is core-only. This is what stops a v3 agent against a v2 server from
	// silently dropping the gateway row the server would have accepted.
	//
	// All three are in-memory, so a server UPGRADE is picked up on the node's
	// next restart — the same re-probe posture as the 404 unsupported latch.
	latched    atomic.Bool
	latchDepth atomic.Int32
	probed     atomic.Bool

	// latchGen1 records WHICH generation the latched depth was accepted at
	// (the generation ladder, gen2 P4-2/W-4). true once any gen1-projected
	// send has been accepted — including the very first ladder rung, since
	// the ladder loop only ever walks gen1-projected rows (see report()). It
	// is meaningless while !latched and is never read there.
	latchGen1 atomic.Bool

	// liveCaps resolves the node's advertised capability-token list at report
	// time (PolicyStateReport.LiveCapabilities, Plane B §3, Sol S3; P6b) — the
	// SAME nodeLiveCapabilities(admission) function
	// PolicyResourceOptions.LiveCapabilities is built from (policyresource_wire.go),
	// so the mode-capability token a gateway.providers body is gated on and
	// the one the server records via planebmode.RecordCapabilityAck never
	// drift apart. Resolved as a closure (not a snapshot) so a judge that is
	// wired/unwired after this reporter is constructed is reflected on the
	// very next report. nil in the raw newPolicyStateReporter test
	// constructor — only buildPolicyStateReporter, which owns a live
	// admission handle, sets it; a nil liveCaps yields an empty
	// LiveCapabilities list, matching a pre-P6 agent (omitempty).
	liveCaps func() []string
}

// newPolicyStateReporter constructs a reporter over injected dependencies (so
// it unit-tests without start.go or a live daemon). readers must be the four
// (point → reader) entries; enabled gates the whole channel
// ([org_client.share].policy_state).
func newPolicyStateReporter(
	poster policyStatePoster,
	readers map[string]policystate.PointReader,
	seq *orgclient.ReportSeqCounter,
	agentVersion string,
	enabled bool,
	logger *slog.Logger,
) *policyStateReporter {
	if logger == nil {
		logger = slog.Default()
	}
	return &policyStateReporter{
		poster:       poster,
		readers:      readers,
		seq:          seq,
		agentVersion: agentVersion,
		enabled:      enabled,
		logger:       logger,
		notifier:     newPolicyStateNotifier(),
	}
}

// recordGuard is the guard outcome sink (start.go registers it via
// SetGuardOutcomeSink). It applies the §2.5c Reached-based overwrite discipline
// then pokes. NONBLOCKING — it never calls report (that would let a slow POST
// delay the poll loops, R2-S4).
func (r *policyStateReporter) recordGuard(o orgclient.GuardFetchOutcome) {
	r.mu.Lock()
	r.lastGuard = mergeGuardOutcome(r.lastGuard, o)
	r.mu.Unlock()
	r.notifier.Poke()
}

// recordRouting is the routing outcome sink (SetRoutingOutcomeSink). Same
// overwrite discipline + poke.
func (r *policyStateReporter) recordRouting(o orgclient.RoutingFetchOutcome) {
	r.mu.Lock()
	r.lastRouting = mergeRoutingOutcome(r.lastRouting, o)
	r.mu.Unlock()
	r.notifier.Poke()
}

func (r *policyStateReporter) guardSlot() orgclient.GuardFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastGuard
}

func (r *policyStateReporter) routingSlot() orgclient.RoutingFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastRouting
}

// recordPolicyResource is the P0-5 policy-resource outcome sink (start.go
// hands it to runPolicyResourcePoller). Per-family slots feed the
// admitter/egress PointReaders' LatestFetchRejected/Unreachable fields;
// apply-then-poke ordering is owned by the poller (plan §6.6).
func (r *policyStateReporter) recordPolicyResource(family string, o orgclient.PolicyResourceFetchOutcome) {
	r.mu.Lock()
	switch family {
	case policyfam.FamilyAdmissionInput:
		r.lastAdmitter = mergePolicyResourceOutcome(r.lastAdmitter, o)
	case policyfam.FamilyEgressGuardrail:
		r.lastEgress = mergePolicyResourceOutcome(r.lastEgress, o)
	case policyfam.FamilyGatewayProviders:
		r.lastGateway = mergePolicyResourceOutcome(r.lastGateway, o)
	case policyfam.FamilyNodeGovernance:
		r.lastGovern = mergePolicyResourceOutcome(r.lastGovern, o)
	case policyfam.FamilyNodeFeatures:
		r.lastFeatures = mergePolicyResourceOutcome(r.lastFeatures, o)
	}
	r.mu.Unlock()
	r.notifier.Poke()
}

func (r *policyStateReporter) admitterSlot() orgclient.PolicyResourceFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastAdmitter
}

func (r *policyStateReporter) egressSlot() orgclient.PolicyResourceFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastEgress
}

func (r *policyStateReporter) gatewaySlot() orgclient.PolicyResourceFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastGateway
}

func (r *policyStateReporter) governanceSlot() orgclient.PolicyResourceFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastGovern
}

func (r *policyStateReporter) featuresSlot() orgclient.PolicyResourceFetchOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastFeatures
}

// mergePolicyResourceOutcome mirrors mergeRoutingOutcome for the P0-5
// policy-resource rail: RejectCode (not OK) is the delivered-reject
// discriminator; Unreachable sets transport-only stale_lkg; a local
// Indeterminate leaves the prior slot alone.
func mergePolicyResourceOutcome(prev, o orgclient.PolicyResourceFetchOutcome) orgclient.PolicyResourceFetchOutcome {
	switch {
	case o.Cleared:
		// Codex SF4: ErrNotEnrolled — drop stale reject/unreachable state.
		return orgclient.PolicyResourceFetchOutcome{}
	case o.Indeterminate && !o.Reached:
		return prev
	case o.Unreachable:
		return orgclient.PolicyResourceFetchOutcome{Unreachable: true}
	case o.RejectCode != "":
		return orgclient.PolicyResourceFetchOutcome{Reached: true, RejectCode: o.RejectCode, Version: o.Version}
	default:
		return orgclient.PolicyResourceFetchOutcome{OK: o.OK, Reached: true, Version: o.Version}
	}
}

// mergeGuardOutcome applies the §2.5c/R4-B4/R5-B3 overwrite discipline for the
// guard slot. The discriminator is Reached, not the coarse outcome type:
//   - a local pre-wire Indeterminate (Reached:false) LEAVES the prior slot;
//   - a transport Unreachable (Reached:false) SETS Unreachable;
//   - a delivered gate Reject (non-empty RejectCode, Reached:true) stores the
//     reject; the discriminator is the RejectCode, NOT OK — a guard delivered
//     rejection happens to carry OK=true, but the routing classifier emits its
//     gate rejects with OK=false, so keying on OK would DROP a routing reject
//     (see mergeRoutingOutcome). Guard rejects keep the OK:true stamp because a
//     delivered rejection is a successful poll of a rejected artifact;
//   - any other Reached:true cycle (accept / AuthFailed / reached-Indeterminate)
//     stores a NEUTRAL reached outcome — clearing a prior Unreachable AND a
//     prior reject, so the point falls back to its cache/running truth and
//     never keeps reporting stale_lkg after reachability is proven.
func mergeGuardOutcome(prev, o orgclient.GuardFetchOutcome) orgclient.GuardFetchOutcome {
	switch {
	case o.Indeterminate && !o.Reached:
		return prev
	case o.Unreachable:
		return orgclient.GuardFetchOutcome{Unreachable: true}
	case o.RejectCode != "":
		return orgclient.GuardFetchOutcome{OK: true, Reached: true, RejectCode: o.RejectCode, Version: o.Version}
	default:
		return orgclient.GuardFetchOutcome{OK: o.OK, Reached: true, Version: o.Version}
	}
}

// mergeRoutingOutcome is the routing-slot twin of mergeGuardOutcome (§2.5b/c).
// The routing classifier (classifyRoutingFetch) emits a gate rejection as
// {RejectCode, Reached:true} with OK=false, so the reject case keys on a
// non-empty RejectCode (a delivered rejection regardless of OK) — keying on OK
// would drop it and make delivered_unaccepted unreachable. A routing reject is
// not an OK, so no OK:true stamp is stored; Reached:true still clears a prior
// Unreachable.
func mergeRoutingOutcome(prev, o orgclient.RoutingFetchOutcome) orgclient.RoutingFetchOutcome {
	switch {
	case o.Indeterminate && !o.Reached:
		return prev
	case o.Unreachable:
		return orgclient.RoutingFetchOutcome{Unreachable: true}
	case o.RejectCode != "":
		return orgclient.RoutingFetchOutcome{Reached: true, RejectCode: o.RejectCode, Version: o.Version}
	default:
		return orgclient.RoutingFetchOutcome{OK: o.OK, Reached: true, Version: o.Version}
	}
}

// report assembles a full snapshot and POSTs it — nonblocking single-flight
// (§4.3). It POSTs ONLY a COMPLETE snapshot (one row per registered reader);
// a short snapshot (a reader errored) is logged-and-skipped (R3-S2).
// ReportSeq is sourced from the restart-safe counter and persisted BEFORE the
// POST — a persistence failure skips the POST (§2.2). A 404/405 latches the
// channel off for the daemon lifetime (S8); a 400 on the FIRST attempt
// triggers the v2 core-only probe (§3.2). It honors ctx (a cancel abandons
// the in-flight POST) and never propagates an error (P1 posture).
// report() implements a two-axis compat ladder: GENERATION (gen2 full-fidelity
// rows carrying the top-level MachineIdentity + the node.governance row's
// AcceptedAuthority/ExtractionEffective/DroppedClasses, vs. gen1 — those four
// fields stripped/remapped by projectGen1) crossed with the pre-existing
// optional-POINT depth ladder. The combined walk is strictly linear:
//
//	[gen2 @ full depth, gen1 @ full depth, gen1 @ depth-1, ..., gen1 @ 0]
//
// gen2 is attempted ONLY at full depth, never at a reduced depth. This is not
// a simplification that loses coverage: the gen2 fields exist ONLY on the
// node.governance row (P4-2), which is registered unconditionally and is
// itself the LAST entry in policystate.OptionalPoints, so gen2 content is
// present in a snapshot if and only if that snapshot is at full depth. And no
// server can be "new enough to understand a reduced-but-nonzero optional-point
// set, yet too old for gen2": gen2 ships in the same release as every
// optional point this build knows about, so a server old enough to reject any
// gen2 field is old enough to reject SOME optional point too — which the
// gen1-at-full-depth rung already probes for. Once gen2-at-full is rejected,
// every later rung in the ladder (including the depth walk) is gen1-projected
// for the rest of the daemon's lifetime; only depth is still open to probe.
// effectiveEnabled resolves whether this report() call should run at all
// (W-9, extended by the Plane B dual-mode gateway / RBAC-IA design,
// 2026-08-29 §5.3 scope item 3): the configured [org_client.share].policy_state
// value (r.enabled), LOWERED by a live "policy_state" node.governance share
// directive, then — for a MANAGED node that was granted the dedicated
// extract.policy_state authority — RAISED by the same directive. It reuses
// govern.Effective.LowerBool/RaiseBool — the SAME merge primitives the push
// seam and the Privacy card both use — rather than hand-rolling the algebra
// here, mirroring cmd/observer/governance_wire.go's lowerShareOptions'
// lower-then-conditionally-raise shape exactly.
//
// "policy_state" USED TO be one of W-8's two conscious extraction-tier
// exemptions (no GrantsXxxExtraction token mapped to it), meaning an org
// directive could only ever turn this channel OFF, never ON. That exemption
// is now closed: internal/govern's AuthorityExtractPolicyState /
// Effective.GrantsPolicyStateExtraction (a STRICT token — the extract.managed
// umbrella alone does not satisfy it) let an org explicitly authorize a node
// to report richer effective-policy-state detail even when the node's own
// local config left it off. The raise is gated on
// govern.ExtractionAuthorized(eff, "policy_state") — the single per-tier gate
// internal/govern/sharetiers.go owns — exactly like every other tier
// lowerShareOptions raises, so this reporting channel and the push seam can
// never disagree about which raises are actually live.
//
// r.ngov==nil (the raw newPolicyStateReporter test constructor, or a daemon
// build that never wired node.governance) falls back to r.enabled unchanged
// — the same fail-open posture every other org-directive consumer in this
// codebase uses when its handle is absent.
func (r *policyStateReporter) effectiveEnabled(ctx context.Context) bool {
	if r.ngov == nil {
		return r.enabled
	}
	eff := r.ngov.Effective(ctx)
	out := eff.LowerBool("policy_state", r.enabled)
	if govern.ExtractionAuthorized(eff, "policy_state") {
		out = eff.RaiseBool("policy_state", out)
	}
	return out
}

func (r *policyStateReporter) report(ctx context.Context) {
	if r == nil || r.unsupported.Load() {
		return
	}
	if !r.effectiveEnabled(ctx) {
		return
	}
	if !r.running.CompareAndSwap(false, true) {
		return // a report is already in flight; the buffered poke coalesces
	}
	defer r.running.Store(false)

	rows, err := policystate.Assemble(ctx, r.readers)
	if err != nil {
		r.logger.Warn("policystate: reader errors during assemble", "err", err)
	}
	// Completeness is measured against the READERS registered on this daemon,
	// not a frozen literal: a v1 reporter registers four, a v2 reporter five.
	if len(rows) != len(r.readers) {
		r.logger.Warn("policystate: incomplete snapshot; skipping POST (retry next heartbeat)",
			"rows", len(rows), "want", len(r.readers))
		return
	}
	gen1Full := projectGen1(rows)

	if r.latched.Load() {
		depth := int(r.latchDepth.Load())
		if r.latchGen1.Load() {
			r.post(ctx, rowsAtDepth(gen1Full, depth), "")
		} else {
			// Defensive / should be unreachable via this function: every
			// latching branch below sets latchGen1 together with latched, so
			// a gen2 latch can only arise from a future code path that sets
			// latched some other way. Falls back to the live identity + full
			// rows rather than silently downgrading.
			r.post(ctx, rowsAtDepth(rows, depth), r.poster.ManagedMachineIdentity(ctx))
		}
		return
	}

	mid := r.poster.ManagedMachineIdentity(ctx)
	if outcome := r.post(ctx, rows, mid); outcome != postRejected {
		return
	}
	// The full gen2 snapshot was REFUSED (400). Probe ONCE per daemon
	// lifetime: first gen1-at-full-depth (unless this snapshot carries no
	// gen2 content to strip in the first place — skipGen1Probe — in which
	// case that rung would be a byte-identical repeat of the send that was
	// just rejected, so it is skipped straight into the existing
	// optional-point depth ladder, now walked over gen1-projected rows), then
	// the depth ladder, newest optional point first, latching at the highest
	// rung accepted. A rejection that survives all the way to gen1-depth-0 is
	// NOT latched: it was about something else (a genuinely malformed core
	// row), and latching would hide a real bug behind a compat story.
	if !r.probed.CompareAndSwap(false, true) {
		return
	}
	skipGen1Probe := mid == "" && rowsEqualContent(rows, gen1Full)
	if !skipGen1Probe {
		if r.post(ctx, gen1Full, "") == postOK {
			r.latched.Store(true)
			r.latchGen1.Store(true)
			r.latchDepth.Store(int32(len(policystate.OptionalPoints)))
			r.logger.Info("policystate: server rejected the gen2 snapshot but accepted the gen1 projection — older server, dropping gen2 fields for this daemon lifetime")
			return
		}
	}
	for depth := len(policystate.OptionalPoints) - 1; depth >= 0; depth-- {
		candidate := rowsAtDepth(gen1Full, depth)
		if len(candidate) == len(gen1Full) {
			continue // this snapshot carries no row at that depth to drop
		}
		if r.post(ctx, candidate, "") != postOK {
			continue
		}
		r.latched.Store(true)
		r.latchGen1.Store(true)
		r.latchDepth.Store(int32(depth))
		dropped := policystate.OptionalPoints[depth:]
		r.logger.Info("policystate: server rejected the full snapshot but accepted a narrower one — older server, dropping the newest optional points for this daemon lifetime",
			"dropped_points", dropped, "sent_rows", len(candidate), "full_rows", len(rows))
		return
	}
}

// projectGen1 returns a copy of rows with every gen2-only field cleared: the
// three node.governance row fields (meaningless, and 400-rejected by the
// server, on any row that isn't family="node.governance" — but cleared
// unconditionally here since only that row ever carries them) and the two
// gen2 Reason values remapped to their nearest gen1 equivalent, so a gen1
// server sees exactly the reason vocabulary it already understands:
//   - ReasonFamilyNotAccepted (the resource verified but the family isn't in
//     accept_families) folds into ReasonCapabilityMismatch, the closest gen1
//     reason for "this node did not install what was delivered".
//   - ReasonSidecarUnwritable (the governance sidecar file could not be
//     written) folds into ReasonNotPreauthorized, the gen1 reason
//     newNodeGovernancePointReader used for every accepted-but-inert case
//     before gen2 gave sidecar-unwritable its own identity.
//
// It does not mutate rows — the caller may still need the gen2-full slice for
// the (rare) latchGen1==false defensive path in report().
func projectGen1(rows []orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow {
	out := make([]orgcontract.PolicyStateRow, len(rows))
	for i, row := range rows {
		row.AcceptedAuthority = nil
		row.ExtractionEffective = nil
		row.DroppedClasses = nil
		// Track C item 3 rides the SAME gen2 latch: a pre-gen2 server
		// validates the row against a closed field set and 400s the whole
		// report on an unknown key, so the gen1 projection must strip this
		// too. (In practice a gen1 server also ignores unknown JSON keys,
		// but the projection's contract is "emit exactly the gen1 shape".)
		row.EffectivePins = nil
		switch row.Reason {
		case orgcontract.ReasonFamilyNotAccepted:
			row.Reason = orgcontract.ReasonCapabilityMismatch
		case orgcontract.ReasonSidecarUnwritable:
			row.Reason = orgcontract.ReasonNotPreauthorized
		}
		out[i] = row
	}
	return out
}

// rowsEqualContent reports whether a and b carry identical rows in the same
// order — used to detect a snapshot that has no gen2 content to strip (a pre-
// gen2 reader set, or a gen2 node.governance row that happens to carry no
// gen2 fields this cycle) so report() can skip a byte-identical repeat POST.
func rowsEqualContent(a, b []orgcontract.PolicyStateRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// postOutcome is the classified result of one policy-ack POST. It exists so
// report()'s ladder logic reads on OUTCOME rather than on a bare bool, which
// is what made an earlier draft latch on a FAILED probe. postRejected is
// deliberately distinguished from postFailed: only a server REJECTION (400)
// can mean "this server does not know that point", whereas a transport
// failure mid-ladder must never be mistaken for one — that mistake would
// permanently narrow a healthy node's reporting after one flaky POST.
type postOutcome int

const (
	// postFailed — the POST did not land (transport, auth, 404 latch, or a
	// seq-persist failure that skipped the send).
	postFailed postOutcome = iota
	// postOK — the server accepted the snapshot.
	postOK
	// postRejected — the server answered 400: it refused the snapshot's
	// shape. The caller decides whether that warrants the ladder probe.
	postRejected
)

// post draws a fresh ReportSeq and POSTs one snapshot, returning the
// classified outcome. machineIdentity rides the top-level
// PolicyStateReport.MachineIdentity field (W-4) — the caller passes the live
// ManagedMachineIdentity() value only on the gen2-at-full-depth attempt, and
// "" on every gen1-projected attempt (see report()).
//
// Each POST draws its OWN seq. Reusing one would be wrong: the server's
// upsert predicate is `excluded.report_seq > policy_state.report_seq`, so a
// same-seq retry against an existing row would be silently discarded. A
// skipped seq value is harmless — gaps already occur on any failed POST.
func (r *policyStateReporter) post(ctx context.Context, rows []orgcontract.PolicyStateRow, machineIdentity string) postOutcome {
	seq, err := r.seq.Next()
	if err != nil {
		r.logger.Warn("policystate: report_seq persist failed; skipping POST", "err", err)
		return postFailed
	}
	var liveCaps []string
	if r.liveCaps != nil {
		liveCaps = r.liveCaps()
	}
	rep := orgcontract.PolicyStateReport{
		AgentVersion:     r.agentVersion,
		ReportSeq:        seq,
		Rows:             rows,
		MachineIdentity:  machineIdentity,
		LiveCapabilities: liveCaps,
	}
	perr := r.poster.PostPolicyState(ctx, rep)
	switch {
	case perr == nil:
		return postOK
	case errors.Is(perr, orgclient.ErrPolicyAckUnsupported):
		r.unsupported.Store(true)
		r.logger.Info("policystate: policy-ack endpoint unsupported (pre-P0-6 server) — latching off for daemon lifetime")
		return postFailed
	case errors.Is(perr, orgclient.ErrPolicyAckRejected):
		return postRejected
	default:
		r.logger.Warn("policystate: post failed", "err", perr)
		return postFailed
	}
}

// rowsAtDepth filters a snapshot down to the CORE rows plus the first
// `depth` OPTIONAL points in generation order — the exact set a server of
// that generation validates as complete. depth==0 is core-only (a v1
// server); depth==len(policystate.OptionalPoints) is everything.
//
// Order within the result is the caller's; the server's row-set guard is
// set-based either way.
func rowsAtDepth(rows []orgcontract.PolicyStateRow, depth int) []orgcontract.PolicyStateRow {
	if depth < 0 {
		depth = 0
	}
	if depth > len(policystate.OptionalPoints) {
		depth = len(policystate.OptionalPoints)
	}
	keep := make(map[string]bool, depth)
	for _, p := range policystate.OptionalPoints[:depth] {
		keep[p] = true
	}
	out := make([]orgcontract.PolicyStateRow, 0, len(rows))
	for i := range rows {
		p := rows[i].EnforcementPoint
		if policystate.IsCorePoint(p) || keep[p] {
			out = append(out, rows[i])
		}
	}
	return out
}

// run is the independent-reporter goroutine body (§4.3): one startup emit, then
// a heartbeat ticker + coalesced on-change pokes, until ctx is done. It never
// returns a non-nil error (P1). start.go launches this in a g.Go, gated by
// [org_client.share].policy_state (belt-and-suspenders: report() is also
// enabled-gated).
func (r *policyStateReporter) run(ctx context.Context, heartbeat time.Duration) error {
	if r == nil || !r.enabled {
		return nil
	}
	if heartbeat <= 0 {
		heartbeat = time.Duration(config.DefaultPolicyStateHeartbeatSeconds) * time.Second
	}
	r.report(ctx) // startup emit
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.report(ctx)
		case <-r.notifier.poke:
			r.report(ctx)
		}
	}
}

// buildPolicyStateReporter wires the reporter from the daemon's live
// dependencies (§4.3). It is the SINGLE assembly call the deferred start.go
// edit makes (D1); it constructs all four readers, the ReportSeq counter, and
// the enabled gate from config. The routingHandle comes from wireRouting via
// buildProxy (threaded through the gated start.go edit — see the proxy.go
// TODO). Returns a reporter whose sinks (recordGuard/recordRouting) start.go
// registers on the orgclient before launching r.run.
func buildPolicyStateReporter(
	poster policyStatePoster,
	g *guard.Guard,
	st *store.Store,
	admission *obsAdmissionHandle,
	routingHandle *RoutingStateHandle,
	gw *gatewayProvidersHandle,
	ngov *nodeGovernanceHandle,
	nf *nodeFeaturesHandle,
	cfg config.Config,
	agentVersion string,
	logger *slog.Logger,
) *policyStateReporter {
	now := time.Now
	seq := orgclient.NewReportSeqCounter(policyStateSeqPath(cfg))
	rep := &policyStateReporter{
		poster:       poster,
		seq:          seq,
		agentVersion: agentVersion,
		enabled:      cfg.OrgClient.Share.PolicyState,
		logger:       logger,
		notifier:     newPolicyStateNotifier(),
		ngov:         ngov,
	}
	if rep.logger == nil {
		rep.logger = slog.Default()
	}
	// liveCaps mirrors PolicyResourceOptions.LiveCapabilities (§ nodeLiveCapabilities
	// in policyresource_wire.go): the admission-derived judge capability plus
	// the node's static mode-capability token. Resolved as a closure over
	// `admission` so a runtime judge wiring change reaches the very next
	// report.
	rep.liveCaps = func() []string { return nodeLiveCapabilities(admission) }
	rep.readers = map[string]policystate.PointReader{
		policystate.PointGuard: newGuardPointReader(
			guardCachedVersionFromFile(orgBundleCachePath(cfg)),
			guardRunningFromGuard(g),
			rep.guardSlot,
			now,
		),
		policystate.PointRouter: newRouterPointReader(
			routingHandle,
			routerCachedVersionFromStore(st),
			rep.routingSlot,
			now,
		),
		policystate.PointProxyAdmitter: newAdmitterPointReader(admission, rep.admitterSlot, now),
		policystate.PointProxyEgress:   newEgressPointReader(admission, rep.egressSlot, now),
		// v2: the gateway.providers row is registered UNCONDITIONALLY, even
		// when gw is nil. An omitted row is indistinguishable from a pre-v2
		// agent, whereas an explicit none/no_policy row is the honest
		// statement "nothing is routing here", which is a fact worth
		// reporting (spec §2.2).
		policystate.PointProxyGateway: newGatewayPointReader(gw, rep.gatewaySlot, now),
		// v3 (admin-controlled Plane B): registered UNCONDITIONALLY too,
		// including when no grant exists. An OMITTED row is indistinguishable
		// from an older agent, whereas an explicit none/no_policy row is the
		// honest statement "this node is not governed" — which is exactly the
		// fact an admin looking at fleet state needs, and the reason the
		// review's grant-implies-new-server coupling was dropped in favour of
		// the optional-point ladder.
		policystate.PointNodeDashboard: newNodeGovernancePointReader(ngov, rep.governanceSlot, now),
		// v4 (org-parity W5.1): registered UNCONDITIONALLY, including when
		// no node.features policy exists — the same optional-point ladder
		// reasoning as the other two: an omitted row is indistinguishable
		// from an older agent, an explicit none/no_policy row is the honest
		// "this node's terminals/remote/routing-apply/patterns-write are
		// ungoverned" fact.
		policystate.PointNodeFeatures: newNodeFeaturesPointReader(nf, rep.featuresSlot, now),
	}
	return rep
}

// policyStateHeartbeat resolves the configured reporter heartbeat, defaulted.
func policyStateHeartbeat(cfg config.Config) time.Duration {
	secs := cfg.OrgClient.PolicyStateHeartbeatSeconds
	if secs <= 0 {
		secs = config.DefaultPolicyStateHeartbeatSeconds
	}
	return time.Duration(secs) * time.Second
}
