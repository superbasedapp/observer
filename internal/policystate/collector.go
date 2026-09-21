// Package policystate is the pure-logic collector for the Plane-A P0-6
// "effective policy state" reverse channel
// (docs/plans/plane-a-p0-6-effective-policy-state-plan.md §4.1). It turns a
// per-enforcement-point PointFacts snapshot into one frozen
// orgcontract.PolicyStateRow via the §3.2 ordered decision table, and
// assembles a full four-point snapshot from injected readers.
//
// Discipline (CLAUDE.md §1 / spec §24.1): NO SQL, NO HTTP, NO fsnotify. All
// I/O is injected at the boundary (the readers in cmd/observer/policystate_wire.go
// and the store seams); this package is table-driven pure logic, pinned free of
// forbidden imports by imports_test.go.
package policystate

import (
	"context"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Enforcement-point identifiers (§2.4). The four CORE points a full snapshot
// always carries, plus the v2 gateway point
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.1).
const (
	PointGuard         = "guard"
	PointRouter        = "router"
	PointProxyAdmitter = "proxy-admitter"
	PointProxyEgress   = "proxy-egress"
	// PointProxyGateway is the gateway.providers lane-table point (v2). It is
	// named proxy-gateway, not gateway, for two reasons: the lane table is
	// enforced by internal/proxy in the same request path as the other two
	// proxy-* points, and a bare "gateway" would collide with the Plane-A
	// deployment ROLE of that name (docs/plane-a/ ADR-0002).
	PointProxyGateway = "proxy-gateway"
	// PointNodeDashboard is the v3 node.governance point (admin-controlled
	// Plane B, docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §3.8).
	// It reports what the node's OWN dashboard surface is doing under org
	// governance — the enforcement point is the node dashboard's route
	// guard plus its SPA, which is why it is named for the surface and not
	// for a proxy lane.
	PointNodeDashboard = "node-dashboard"
	// PointNodeFeatures is the v4 node.features point (org-parity W5.1: an
	// org-governed feature enable/disable + limits gate consulted at four
	// dashboard enforcement seams — terminal launch, remote arm/pair,
	// routing apply, patterns write). Named for the family it reports,
	// exactly like node-dashboard is named for its own surface.
	PointNodeFeatures = "node-features"
)

// Family identifiers (§2.4). One family per enforcement point.
const (
	FamilyGuardCoding         = "guard.coding"
	FamilyRoutingOptimization = "routing.optimization"
	FamilyAdmissionInput      = "admission.input"
	FamilyEgressGuardrail     = "egress.routing_guardrail"
	// FamilyGatewayProviders is the dashboard-managed proxy lane table
	// (v2). Same literal as policyfam.FamilyGatewayProviders, duplicated
	// here for the same dependency-graph reason the other two proxy
	// families are (policystate is a REPORTING concern; policyfam is a
	// compile/dispatch concern).
	FamilyGatewayProviders = "gateway.providers"
	// FamilyNodeGovernance is the admin-controlled Plane-B node governance
	// family (v3). Same literal as policyfam.FamilyNodeGovernance,
	// duplicated for the same dependency-graph reason as the others.
	FamilyNodeGovernance = "node.governance"
	// FamilyNodeFeatures is the org-parity W5.1 node feature-governance
	// family (v4). Same literal as policyfam.FamilyNodeFeatures / policyfam/
	// nodefeatures's own package, duplicated for the same dependency-graph
	// reason as the others.
	FamilyNodeFeatures = "node.features"
)

// PointFacts is the resolved input for ONE enforcement point (§4.1). The split
// (R2-B5) keeps the CACHED/RUNNING group (verified cache + live engine)
// separate from the LATEST-FETCH group (the reporter's in-memory typed
// outcome), so the ambiguous "accepted" bool never conflates the two.
type PointFacts struct {
	// --- CACHED / RUNNING (verified cache + live engine) ---
	// CachedAcceptedVersion is the last version that passed the acceptance
	// gate and entered the node's verified cache (guard: bundle-cache envelope
	// Version; router: org_routing_policies Version). 0 when nothing accepted.
	CachedAcceptedVersion int64
	// RunningVersion is the version EFFECTIVE in the live decision path. 0 =
	// nothing running (first install / org layer not-yet-loaded / disabled).
	RunningVersion int64
	// EffectiveHash is the per-point running identity. For ORG-RAIL points
	// (guard/router) it is "" when RunningVersion==0 (R3-B2/R5-B2). For LOCAL
	// points (admitter/egress) it is a live 64-hex hash at version 0
	// (local_effective), "" when the feature is off (R5-B1).
	EffectiveHash string

	// --- LATEST-FETCH outcome (reporter in-memory, NOT the cache) ---
	// LatestFetchRejected is true when the most recent decisive poll delivered
	// a bundle that failed a gate (RejectCode set). Sourced from the reporter's
	// typed last-fetch slot, never the cache.
	LatestFetchRejected bool
	// RejectedVersion is the version the control plane last served that failed
	// a gate (may be above OR below RunningVersion — a downgrade reject, R3-B3).
	RejectedVersion int64
	// RejectCode is the typed gate-rejection reason (§2.5), "" when not
	// rejected. Maps 1:1 onto the wire Reason for a delivered_unaccepted row
	// — including the P0-10 Phase B orgcontract.ReasonSelectorMismatch, the
	// org/agent targeting disagreement
	// (docs/plans/policy-targeting-rollback-design-2026-08-13.md §2), which
	// the reader boundary supplies for the admitter/egress points only
	// (never router, whose delivered_unaccepted set is key-pin/sig only).
	RejectCode string
	// Unreachable is TRUE only on a retained decisive TRANSPORT outcome
	// (transport/5xx). AuthFailed/Indeterminate NEVER set this, and a later
	// reached outcome clears it (R2-B4/R3-B5/R4-B4) — so it is transport-only
	// by construction at the reader boundary.
	Unreachable bool

	// --- context ---
	// EnforceMode is the point's mode: off|observe|enforce (advise->observe is
	// normalized inside Resolve).
	EnforceMode string
	// HasOrgRail is true when a verified org-published layer is installed for
	// this point (guard/router always-capable; proxy-admitter/proxy-egress
	// after Plane-A P0-5 Phase W when an Org layer is live). Local-only
	// points report false and take the local_effective/no_policy paths.
	HasOrgRail bool
	// InertReason is the plan §6.4/§7.1 preauthorization (or other) inert
	// reason on an installed Org layer (e.g. "not_preauthorized"). Empty
	// when the layer is fully enforceable or no Org layer is installed.
	// Drives accepted_inert/not_preauthorized for admitter/egress (and any
	// future org-rail family that uses the same gate).
	InertReason string
	// LastSeen is the point's liveness instant at report time (RFC3339 on wire).
	LastSeen time.Time

	// --- gen2 (P4-2), meaningful ONLY when point == PointNodeDashboard ---
	// The server 400s a report that populates any of these three on a row
	// for a different point/family, so Resolve gates copying them onto the
	// wire row to the node-dashboard point alone; a reader for any other
	// point may leave them zero-valued without consequence.

	// AcceptedAuthority is govern.HonoredAuthority(grant): the grant's own
	// authority tokens, honoured (a Managed-only token is stripped unless
	// the node's consent mode allows it). Says nothing about whether any of
	// it currently raises anything on THIS delivered body — see
	// ExtractionEffective for that.
	AcceptedAuthority []string
	// ExtractionEffective is govern.ExtractionTokensInForce(eff,
	// AcceptedAuthority): the subset of AcceptedAuthority that both is an
	// extraction authority and currently gates a live raise under the
	// node's resolved govern.Effective — the honest "what is this grant's
	// extraction authority actually DOING right now" list.
	ExtractionEffective []string
	// DroppedClasses maps a govern directive class name (sections/pinned/
	// share/features) to the wire reason it was not applied, translated
	// from govern.Effective.Dropped through the closed gen2 vocabulary
	// (orgcontract.ReasonNotPreauthorized / ReasonSidecarUnwritable). Nil
	// when nothing was dropped.
	DroppedClasses map[string]string
	// EffectivePins is the Track C item 3 map: the effective value, on this
	// machine right now, of every pinnable config key whose value may cross
	// the wire (internal/policyfam/nodegov.ReportableKeys). Keys are dotted
	// config paths; values are closed spellings. Nil on a node with nothing
	// to report. See orgcontract.PolicyStateRow.EffectivePins.
	EffectivePins map[string]string
}

// PointReader resolves the live PointFacts for one enforcement point. It is the
// injected I/O boundary — the pure collector never reads a cache, DB, or wire.
type PointReader func(ctx context.Context) (PointFacts, error)

// resolveCtx is the pre-computed input a decision-table row matches against.
type resolveCtx struct {
	f             PointFacts
	point         string
	enforceIntent bool
}

// resolveRule is one row of the §3.2 ordered decision table. The table is
// walked top-down, first-match-wins (CLAUDE.md §5 — data table, not an
// if/else-if ladder).
type resolveRule struct {
	status  string
	reason  func(f PointFacts) string
	match   func(c resolveCtx) bool
	desired func(f PointFacts) int64
	running func(f PointFacts) int64
	hash    func(f PointFacts) string
}

// --- wire-field extractors (shared by table rows) ---

func cachedVersion(f PointFacts) int64  { return f.CachedAcceptedVersion }
func runningVersion(f PointFacts) int64 { return f.RunningVersion }
func zeroVersion(PointFacts) int64      { return 0 }

// orgRailHash carries the org-rail running hash ONLY when a version is running
// (R3-B2): RunningVersion==0 ⇒ empty hash, for any status. This is the encoding
// the server value-guard requires for org-rail points.
func orgRailHash(f PointFacts) string {
	if f.RunningVersion > 0 {
		return f.EffectiveHash
	}
	return ""
}

// localHash carries a local point's live 64-hex effective hash verbatim (R4-B1
// — the "version 0 ⇒ empty hash" rule is org-rail-only).
func localHash(f PointFacts) string { return f.EffectiveHash }

func emptyHash(PointFacts) string { return "" }

func constReason(r string) func(PointFacts) string { return func(PointFacts) string { return r } }

// mapRejectReason maps a typed RejectCode onto the wire Reason (§3.2 map()) —
// the codes are 1:1 with the reason enum, so a new gate rejection (e.g.
// P0-10's selector_mismatch) reaches delivered_unaccepted through row 1 with
// no change here: the translation from a rail's own reject-code type onto
// this closed enum happens ONCE, at the reader boundary
// (cmd/observer/policystate_wire.go's wire*RejectReason mappers).
func mapRejectReason(f PointFacts) string { return f.RejectCode }

// resolveTable is the frozen ordered decision table (P0-6 §3.2 + P0-5 §7.1
// widening). Rows 1-9, first-match-wins. P0-5 added row 4 (org preauth inert
// → accepted_inert/not_preauthorized) and relaxed row 6 (effective) so an
// authorized Org layer reports effective even when its Spec mode is
// observe/advise — inertness is ONLY the preauthorization gate, not mode.
var resolveTable = []resolveRule{
	{ // 1 — a delivered bundle/resource failed a gate (from the in-memory last-fetch).
		status:  orgcontract.StatusDeliveredUnaccepted,
		reason:  mapRejectReason,
		match:   func(c resolveCtx) bool { return c.f.LatestFetchRejected && c.f.RejectCode != "" },
		desired: func(f PointFacts) int64 { return f.RejectedVersion },
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 2 — running an LKG while the control plane is (transport) unreachable.
		status:  orgcontract.StatusStaleLKG,
		reason:  constReason(orgcontract.ReasonControlPlaneUnreachable),
		match:   func(c resolveCtx) bool { return c.f.Unreachable && c.f.RunningVersion > 0 },
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 3 — accepted into cache but the live engine lags (restart pending).
		status: orgcontract.StatusPendingRestart,
		reason: constReason(orgcontract.ReasonRestartRequired),
		match: func(c resolveCtx) bool {
			return c.f.HasOrgRail && c.f.CachedAcceptedVersion > 0 &&
				c.f.RunningVersion < c.f.CachedAcceptedVersion && c.enforceIntent
		},
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 4 — Org installed and inert for preauthorization (P0-5 §7.1).
		status: orgcontract.StatusAcceptedInert,
		reason: func(f PointFacts) string {
			if f.InertReason != "" {
				return f.InertReason
			}
			return orgcontract.ReasonNotPreauthorized
		},
		match: func(c resolveCtx) bool {
			return c.f.HasOrgRail && c.f.CachedAcceptedVersion > 0 &&
				c.f.RunningVersion == c.f.CachedAcceptedVersion && c.f.InertReason != ""
		},
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 5 — router accepted a policy but runs it inert (observe/advise mode).
		status: orgcontract.StatusAcceptedInert,
		reason: constReason(orgcontract.ReasonModeObserve),
		match: func(c resolveCtx) bool {
			return c.f.HasOrgRail && c.f.CachedAcceptedVersion > 0 &&
				c.point == PointRouter && !c.enforceIntent
		},
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 6 — Org installed, running equals cached, and not inert (P0-5 §7.1).
		// Unlike the P0-6-only effective row, this does NOT require
		// enforceIntent: an authorized Org observe/advise Spec is still
		// "effective" org state (the evaluation gate, not a Spec mutation).
		status: orgcontract.StatusEffective,
		reason: constReason(orgcontract.ReasonOK),
		match: func(c resolveCtx) bool {
			return c.f.HasOrgRail && c.f.CachedAcceptedVersion > 0 &&
				c.f.RunningVersion == c.f.CachedAcceptedVersion && c.f.InertReason == ""
		},
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 7 — running AHEAD of the cache: an inconsistent observation.
		status:  orgcontract.StatusNone,
		reason:  constReason(orgcontract.ReasonInconsistentObservation),
		match:   func(c resolveCtx) bool { return c.f.HasOrgRail && c.f.RunningVersion > c.f.CachedAcceptedVersion },
		desired: cachedVersion,
		running: runningVersion,
		hash:    orgRailHash,
	},
	{ // 8 — a LOCAL point running a locally-configured effective policy (R4-B1).
		status:  orgcontract.StatusNone,
		reason:  constReason(orgcontract.ReasonLocalEffective),
		match:   func(c resolveCtx) bool { return !c.f.HasOrgRail && c.f.EffectiveHash != "" },
		desired: zeroVersion,
		running: zeroVersion,
		hash:    localHash,
	},
	{ // 9 — fallthrough: no org rail + no live hash, or org rail w/o an accepted policy.
		status:  orgcontract.StatusNone,
		reason:  constReason(orgcontract.ReasonNoPolicy),
		match:   func(resolveCtx) bool { return true },
		desired: zeroVersion,
		running: zeroVersion,
		hash:    emptyHash,
	},
}

// Resolve maps one point's PointFacts to a frozen PolicyStateRow via the §3.2
// ordered decision table (first-match-wins). RestartRequired is computed
// structurally, independent of the winning row (§3.2). Attribution is left
// empty on the wire (server-stamped, R2-S2).
func Resolve(point, family string, f PointFacts) orgcontract.PolicyStateRow {
	mode := NormalizeMode(f.EnforceMode)
	c := resolveCtx{
		f:             f,
		point:         point,
		enforceIntent: point == PointGuard || mode == "enforce",
	}
	row := orgcontract.PolicyStateRow{
		Family:           family,
		EnforcementPoint: point,
		Mode:             mode,
		// RestartRequired is derived from the CACHED version, never the wire's
		// DesiredVersion — it may hold under accepted_inert / stale_lkg /
		// delivered_unaccepted as well as always under pending_restart (§3.2).
		RestartRequired: f.HasOrgRail && f.CachedAcceptedVersion > 0 && f.RunningVersion < f.CachedAcceptedVersion,
		LastSeen:        f.LastSeen.UTC().Format(time.RFC3339),
	}
	// gen2 (P4-2, extended by Track C item 3): these fields are meaningful only on the
	// node-dashboard row — the server 400s a report that populates them on
	// any other family/point, so the copy is gated here, in the one place
	// every point's row is built, rather than trusted to every PointReader.
	if point == PointNodeDashboard {
		row.AcceptedAuthority = f.AcceptedAuthority
		row.ExtractionEffective = f.ExtractionEffective
		row.DroppedClasses = f.DroppedClasses
		row.EffectivePins = f.EffectivePins
	}
	for _, rule := range resolveTable {
		if rule.match(c) {
			row.Status = rule.status
			row.Reason = rule.reason(f)
			row.DesiredVersion = rule.desired(f)
			row.RunningVersion = rule.running(f)
			row.EffectiveHash = rule.hash(f)
			return row
		}
	}
	// Unreachable: row 8 matches unconditionally. Kept for total-function
	// safety.
	row.Status = orgcontract.StatusNone
	row.Reason = orgcontract.ReasonNoPolicy
	return row
}

// NormalizeMode folds the wire mode into the closed enum off|observe|enforce
// (S3: advise->observe). An unknown/empty mode collapses to "off" so the
// collector never emits a mode the server value-guard rejects.
func NormalizeMode(m string) string {
	switch m {
	case "enforce":
		return "enforce"
	case "observe":
		return "observe"
	case "advise":
		return "observe"
	default:
		return "off"
	}
}

// pointFamily pairs each enforcement point with its family (§2.4).
var pointFamily = map[string]string{
	PointGuard:         FamilyGuardCoding,
	PointRouter:        FamilyRoutingOptimization,
	PointProxyAdmitter: FamilyAdmissionInput,
	PointProxyEgress:   FamilyEgressGuardrail,
	PointProxyGateway:  FamilyGatewayProviders,
	PointNodeDashboard: FamilyNodeGovernance,
	PointNodeFeatures:  FamilyNodeFeatures,
}

// CorePoints is the v1 (four-point) subset of the snapshot — the row set a
// pre-v2 server validates as EXACTLY complete. The reporter falls back to
// these when a probe proves it is talking to a v1 server
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §3.2).
// Order is irrelevant (the server row-set guard is set-based), but it is
// kept stable for readable test diffs.
var CorePoints = []string{PointGuard, PointRouter, PointProxyAdmitter, PointProxyEgress}

// IsCorePoint reports whether point is one of the four v1 core points.
func IsCorePoint(point string) bool {
	for _, p := range CorePoints {
		if p == point {
			return true
		}
	}
	return false
}

// OptionalPoints is the OPTIONAL points in GENERATION ORDER — oldest server
// generation first. It is the ladder the reporter walks when a server
// refuses a full snapshot (admin-controlled Plane B spec §3.8, adversarial
// review A11): drop the NEWEST optional point, retry, then the next, down to
// core-only, and latch at the highest depth that was accepted.
//
// The all-or-nothing core-only latch this replaced had a real regression in
// it: a v3 agent talking to a v2 server (which accepts proxy-gateway but not
// node-dashboard) got one 400 and fell all the way back to the four core
// rows, silently switching OFF gateway effective-state reporting that the
// server would happily have taken.
//
// ORDER IS THE CONTRACT: append new optional points, never insert.
var OptionalPoints = []string{PointProxyGateway, PointNodeDashboard, PointNodeFeatures}

// IsOptionalPoint reports whether point is an optional (post-v1) point.
func IsOptionalPoint(point string) bool {
	for _, p := range OptionalPoints {
		if p == point {
			return true
		}
	}
	return false
}

// Assemble resolves every reader into a PolicyStateRow. For a reader ERROR it
// OMITS that point's row (never synthesizes `none`, S10/R3-S2), emits the
// healthy rows, and returns the joined errors — it NEVER fails the whole
// snapshot for one reader. The REPORTER decides POST-vs-skip on the returned
// row count (a short snapshot is logged-and-skipped upstream). The family for
// each point is resolved from the §2.4 mapping; an unknown point key is
// skipped with an error.
func Assemble(ctx context.Context, readers map[string]PointReader) ([]orgcontract.PolicyStateRow, error) {
	rows := make([]orgcontract.PolicyStateRow, 0, len(readers))
	var errs []error
	for point, reader := range readers {
		family, ok := pointFamily[point]
		if !ok {
			errs = append(errs, errors.New("policystate.Assemble: unknown enforcement point "+point))
			continue
		}
		if reader == nil {
			errs = append(errs, errors.New("policystate.Assemble: nil reader for "+point))
			continue
		}
		f, err := reader(ctx)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rows = append(rows, Resolve(point, family, f))
	}
	return rows, errors.Join(errs...)
}
