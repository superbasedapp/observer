package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/providers"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Plane-A P0-5 Phase W: v1 unified-policy-resource orchestration at the
// cmd/observer layer (plan docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md
// §6.5/§6.6/§6.9/§6.10, §8 items 4-5). This file owns:
//
//   - policyResourceCacheDir / policyResourceOptionsFor: the shared knobs
//     both the LKG loader below and the steady-state poller
//     (runPolicyResourcePoller) build orgclient.PolicyResourceOptions from.
//   - loadPolicyResourceLKG: the §6.5 recovery matrix, run ONCE,
//     SYNCHRONOUSLY, before start.go binds the proxy listener.
//   - runPolicyResourcePoller: the §6.6/§6.9 steady-state poll-and-apply
//     loop, started only AFTER the listener binds.
//
// Neither function imports internal/obs — they speak to the shared
// admission service ONLY through *obsAdmissionHandle's PublishOrg*/
// ClearOrg* methods (obs_wire.go), preserving the reverse-import boundary
// (tests/invariant/obs_boundary_test.go: only obs_wire.go may import
// internal/obs).

// policyResourceCacheDir resolves the base directory for the §6.2
// generation-scoped policy-resource cache tree
// (<dir>/<org_key>/<generation>/<family>.json), mirroring
// policyStateSeqPath's convention (policystate_wire.go): beside the guard
// org-bundle cache when one is configured, else beside the observer DB.
func policyResourceCacheDir(cfg config.Config) string {
	if p := orgBundleCachePath(cfg); p != "" {
		return filepath.Join(filepath.Dir(p), "policy-resource")
	}
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "policy-resource")
}

// policyResourceOptionsFor builds the orgclient.PolicyResourceOptions both
// the LKG loader and the poller share: the cache dir and the operator's
// accept/preauthorize lists (plan §6.4). liveCaps is the closed set of
// policy-resource capability tokens this node's LIVE runtime advertises (plan
// §6.6) — resolved by the CALLER from the admission service (a plain string
// slice, never an obs type, so this untagged file stays clear of the obs
// reverse-import boundary). A body whose RequiredCapabilities is not a subset
// of liveCaps fails closed with capability_mismatch; a nil/empty liveCaps
// therefore keeps the strict fail-closed default for a node with no matching
// live capability (e.g. no judge wired, or the no_obs build).
// NodeAttrs carries the operator's locally-configured targeting attributes
// (P0-10 Phase B) so both the live accept path and the LKG path corroborate
// a signed selector predicate against the SAME attributes — an LKG install
// must never resurrect an envelope the live path would now reject.
func policyResourceOptionsFor(cfg config.Config, liveCaps []string) orgclient.PolicyResourceOptions {
	return orgclient.PolicyResourceOptions{
		CacheDir:            policyResourceCacheDir(cfg),
		AcceptFamilies:      cfg.OrgClient.Policy.AcceptFamilies,
		PreauthorizeEnforce: cfg.OrgClient.Policy.PreauthorizeEnforce,
		NodeAttrs:           policyResourceNodeAttrs(cfg),
		LiveCapabilities:    liveCaps,
	}
}

// nodeLiveCapabilities composes the FULL capability-token list this node
// advertises to the acceptance path: the admission-handle-derived judge
// capability (handle.LiveCapabilities(), honest — "judge" only when a judge
// client is actually wired) plus the node's static mode-capability token
// (orgcontract.ModeCapabilityToken(providers.SupportedModeSchemaVersion),
// capabilities.go / Plane B dual-mode gateway design 2026-08-29 §3, Sol S3).
// The mode token is unconditional (not gated on the admission service, and
// present even in the no_obs build / nil handle): every build of this binary
// ships the dual-mode gateway enforcement point in-process, so it can always
// honor a gateway.providers body up to that schema version. Callers that also
// need the same list for PolicyStateReport.LiveCapabilities (the policy-ack
// report) go through this same function so the two never drift — see
// buildPolicyStateReporter in policystate_wire.go.
func nodeLiveCapabilities(handle *obsAdmissionHandle) []string {
	caps := handle.LiveCapabilities()
	if tok := orgcontract.ModeCapabilityToken(providers.SupportedModeSchemaVersion); tok != "" {
		caps = append(caps, tok)
	}
	return caps
}

// policyResourceNodeAttrs maps [org_client.policy]'s node attribute knobs
// onto the shared contract's Selectors shape. Corroboration only — these are
// never presented to the server as an authorization claim (the server binds
// attributes to the verified identity; design §2).
func policyResourceNodeAttrs(cfg config.Config) orgcontract.Selectors {
	return orgcontract.Selectors{
		Workspace:   cfg.OrgClient.Policy.NodeWorkspace,
		Environment: cfg.OrgClient.Policy.NodeEnvironment,
		Service:     cfg.OrgClient.Policy.NodeService,
	}
}

// gatewayProvidersHandle is the SEPARATE, admission-independent install
// seam for the gateway.providers family (Phase 3,
// docs/plans/gateway-config-plane-spec-2026-08-15.md). Applying a remote
// lane table mutates internal/proxy.Proxy's live routing table directly —
// there is no obs/admission service involved at all, unlike
// admission.input and egress.routing_guardrail, which install onto the
// shared obs.AdmissionService's Org layer via *obsAdmissionHandle.
//
// A nil *gatewayProvidersHandle (or a nil apply/clear field) means this
// node has nowhere to apply a lane table — Apply/Clear are then no-ops, so
// publishPolicyResourceResult/clearOrgLayer never need to special-case "not
// wired on this build" beyond calling through this handle, exactly
// mirroring *obsAdmissionHandle's own nil-safe methods.
// It is ALSO the truth source for the P0-6 gateway.providers effective-state
// row (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.2):
// the org-rail IDENTITY (accepted version + signed BodyHash + inert reason)
// exists nowhere else in the process, because internal/proxy neither knows
// nor should know it. The LOCAL half of the report is read LIVE from
// liveLanes instead, so the common case is a genuine observation of the
// running table rather than a mirror of what we believe we installed.
//
// INVARIANT: this handle is the ONLY caller of Proxy.SetLaneTable outside
// tests (Proxy.SetUpstreams has no non-test caller at all). A second mutator
// would desynchronise the org-rail half of the report and MUST either route
// through this handle or extend it.
type gatewayProvidersHandle struct {
	// apply installs a fresh lane table (upstreams + optional default
	// lane) onto the live proxy, all-or-nothing
	// (internal/proxy.Proxy.SetLaneTable's contract). A non-nil error
	// means the CURRENT lane table is left UNCHANGED — the caller only
	// logs it, it never crashes.
	apply func(upstreams map[string]string, autoDefaultLane string) error
	// applyRoute installs a fresh lane table AND the org-gateway route
	// (mode + primary + fallbacks) as ONE atomic routing snapshot
	// (internal/proxy.Proxy.SetRoutingSnapshot, Sol S7). Set at the daemon
	// construction sites via SetRouteApply; nil on test handles and on
	// builds with no proxy wiring, in which case ApplyWithMode falls back to
	// the lane-only `apply` (org-route preserved) — a mode body then applies
	// its lanes but leaves the org-route unchanged, which is the honest
	// degraded behavior for a handle that cannot repoint the mode.
	applyRoute func(upstreams map[string]string, autoDefaultLane, mode, primary string, fallbacks []string, terminal string, custodyAck bool) error
	// clear reverts the proxy to its bootstrap ([proxy] + [proxy.org_route]
	// config.toml) lane table AND org-route — a withdrawn org policy restores
	// the operator's own configured routing, never an empty table.
	clear func()
	// liveLanes reads the CURRENTLY live lane table (Proxy.LaneTable). Only
	// the P0-6 local-row hash uses it; nil means "no live read available on
	// this node", which reports as no_policy.
	liveLanes func() (map[string]string, string)

	mu    sync.Mutex
	state gatewayProvidersState
}

// gatewayProvidersState is the org-rail half of the gateway.providers
// effective-state truth: what the org rail last INSTALLED (or failed to
// install) through this handle. The local half is never stored here — it is
// read live from liveLanes at report time.
type gatewayProvidersState struct {
	// hasOrgRail is true once an org-published lane table is installed
	// (applied or accepted-inert); false after a clear.
	hasOrgRail bool
	// version / bodyHash are the accepted org resource's identity. bodyHash
	// is the SIGNED BodyHash, never the compiled Spec.Hash — same org-rail
	// wire rule as admitter/egress.
	version  int64
	bodyHash string
	// inertReason is the §6.4 preauthorization (or other) inert reason on an
	// accepted-but-not-applied table. Empty when the table is routing.
	inertReason string
	// applyFailedVersion / applyRejectCode record a delivered version the
	// live proxy REFUSED (SetLaneTable returned an error, so the previous
	// table is still routing). Cleared by the next successful apply or
	// clear.
	applyFailedVersion int64
	applyRejectCode    string
}

// newGatewayProvidersHandle builds the daemon-lifetime install seam. All
// three closures may be nil (a node with no proxy lane wiring); every method
// is nil-safe in that case, and the P0-6 row then reports no_policy.
func newGatewayProvidersHandle(
	apply func(upstreams map[string]string, autoDefaultLane string) error,
	clear func(),
	liveLanes func() (map[string]string, string),
) *gatewayProvidersHandle {
	return &gatewayProvidersHandle{apply: apply, clear: clear, liveLanes: liveLanes}
}

// Apply installs upstreams/autoDefaultLane through the handle. Nil-safe: a
// nil handle or a nil apply field is a no-op returning nil (nothing to
// apply on this node, not a failure).
func (h *gatewayProvidersHandle) Apply(upstreams map[string]string, autoDefaultLane string) error {
	if h == nil || h.apply == nil {
		return nil
	}
	return h.apply(upstreams, autoDefaultLane)
}

// SetRouteApply binds the atomic lanes+org-route setter
// (internal/proxy.Proxy.SetRoutingSnapshot) so ApplyWithMode can install a
// gateway.providers MODE body's lanes and mode together in one generation
// (Sol S7). Called once per handle at the daemon construction sites; a nil
// handle is a no-op.
func (h *gatewayProvidersHandle) SetRouteApply(fn func(upstreams map[string]string, autoDefaultLane, mode, primary string, fallbacks []string, terminal string, custodyAck bool) error) {
	if h == nil {
		return
	}
	h.applyRoute = fn
}

// ApplyWithMode installs a compiled gateway.providers spec, honoring its
// optional mode block (P5b, Luna L14):
//
//   - a body that carries a mode block (ModeNode or ModeGateway) installs
//     lanes AND the org-route atomically via applyRoute (SetRoutingSnapshot),
//     so a mode flip is a single routing generation;
//   - a lane-only body (no mode block) installs lanes via the existing
//     apply (SetLaneTable), which PRESERVES the live org-route — so a
//     [proxy.org_route] bootstrap (or a previously-applied org mode) is not
//     clobbered by an unrelated lane publish.
//
// When applyRoute is nil (test handles / builds without proxy wiring) a mode
// body degrades to a lane-only apply; the mode is not repointed. Nil-safe.
func (h *gatewayProvidersHandle) ApplyWithMode(spec providers.PolicySpec) error {
	if h == nil {
		return nil
	}
	if spec.HasModeBlock() && h.applyRoute != nil {
		mode, primary, fallbacks := spec.OrgRoute()
		// Thread the compiled fallback-ladder terminal rung (Sol S10 / Luna
		// L16) alongside the destination so the runtime executor
		// (internal/proxy/gatewayfallback.go) reads it from the SAME routing
		// generation. TerminalPolicy / DirectFallbackCustodyAck are empty/
		// false outside Gateway Mode, so a Node-Mode body threads a no-op.
		return h.applyRoute(spec.UpstreamsAsStringMap(), spec.AutoDefaultLane, mode, primary, fallbacks, spec.TerminalPolicy, spec.DirectFallbackCustodyAck)
	}
	return h.Apply(spec.UpstreamsAsStringMap(), spec.AutoDefaultLane)
}

// Clear reverts to the bootstrap lane table through the handle and forgets
// the org-rail state, so the next report falls back to the node's own live
// lanes (local_effective) or no_policy. Nil-safe.
func (h *gatewayProvidersHandle) Clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.state = gatewayProvidersState{}
	h.mu.Unlock()
	if h.clear == nil {
		return
	}
	h.clear()
}

// recordApplied stamps a successfully-applied org lane table.
func (h *gatewayProvidersHandle) recordApplied(version int64, bodyHash string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = gatewayProvidersState{hasOrgRail: true, version: version, bodyHash: bodyHash}
}

// recordInert stamps an org lane table that was ACCEPTED but deliberately
// NOT applied (the §6.4 preauthorize_enforce gate). The proxy keeps routing
// through whatever it was routing through before.
func (h *gatewayProvidersHandle) recordInert(version int64, bodyHash, reason string) {
	if h == nil {
		return
	}
	if reason == "" {
		reason = "not_preauthorized"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state = gatewayProvidersState{hasOrgRail: true, version: version, bodyHash: bodyHash, inertReason: reason}
}

// recordApplyFailure stamps a delivered version the live proxy refused. The
// PREVIOUS org-rail identity is preserved (SetLaneTable is all-or-nothing,
// so whatever was routing still is), and the failure rides alongside it as a
// delivered_unaccepted/capability_mismatch observation.
func (h *gatewayProvidersHandle) recordApplyFailure(version int64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.state.applyFailedVersion = version
	h.state.applyRejectCode = orgcontract.ReasonCapabilityMismatch
}

// gatewayFacts is the plain snapshot the P0-6 gateway point reader consumes:
// the org-rail record plus a LIVE read of the local lane table.
type gatewayFacts struct {
	HasOrgRail  bool
	Version     int64
	BodyHash    string
	InertReason string
	// LocalHash is the content address of the live lane table, computed with
	// the SAME algorithm the family's compiler uses. Empty when no lanes are
	// live (the local_effective vs no_policy discriminator, mirroring
	// admitter/egress's hash-presence rule).
	LocalHash string
	// ApplyFailedVersion / ApplyRejectCode surface a delivered table the
	// proxy refused.
	ApplyFailedVersion int64
	ApplyRejectCode    string
}

// Facts snapshots the handle for the P0-6 reader. Nil-safe: a nil handle is
// a node with no gateway lane wiring, which reports none/no_policy.
func (h *gatewayProvidersHandle) Facts() gatewayFacts {
	if h == nil {
		return gatewayFacts{}
	}
	h.mu.Lock()
	st := h.state
	h.mu.Unlock()
	f := gatewayFacts{
		HasOrgRail:         st.hasOrgRail,
		Version:            st.version,
		BodyHash:           st.bodyHash,
		InertReason:        st.inertReason,
		ApplyFailedVersion: st.applyFailedVersion,
		ApplyRejectCode:    st.applyRejectCode,
	}
	if h.liveLanes != nil {
		if lanes, autoDefault := h.liveLanes(); len(lanes) > 0 {
			f.LocalHash = providers.HashLaneTable(lanes, autoDefault)
		}
	}
	return f
}

// applyGatewayProviders downcasts a compiled gateway.providers spec and
// applies it through gw, recording the outcome for the P0-6 reporter. A type
// mismatch — defensive; every real call site only ever passes what
// CompileFamilyBody compiled for family gateway.providers — or a nil handle
// is a silent no-op, mirroring PublishOrgAdmission/PublishOrgEgress's own
// defensive posture. An apply error is logged at Warn and never propagated:
// a bad lane table must never crash the daemon, and the previous lane table
// stays live (SetLaneTable's all-or-nothing contract).
//
// enforceAllowed is the plan §6.4 preauthorization verdict and is HONOURED
// here: an inert body is recorded but NOT applied. policyfam's
// SpecRequestsEnforceMode returns true unconditionally for this family
// precisely because "applying a remote lane table always mutates live proxy
// routing the moment it is accepted" — so a node that has not listed
// gateway.providers in [org_client.policy].preauthorize_enforce must keep
// routing through its own lanes. Before the v2 policy-state work this
// verdict was dropped on the floor and every accepted body was applied,
// which both bypassed the operator's consent gate and left no truthful
// effective-state row to report
// (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.3).
func applyGatewayProviders(gw *gatewayProvidersHandle, res orgclient.PolicyResourceResult, logger *slog.Logger) {
	p, ok := res.Spec.(providers.PolicySpec)
	if !ok {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	if !res.EnforceAllowed {
		gw.recordInert(res.Version, res.BodyHash, res.InertReason)
		logger.Info("policy resource: gateway.providers accepted but INERT — the node's own lanes keep routing",
			"version", res.Version, "reason", res.InertReason)
		return
	}
	if err := gw.ApplyWithMode(p); err != nil {
		gw.recordApplyFailure(res.Version)
		logger.Warn("policy resource: applying gateway.providers lane table failed", "err", err, "version", res.Version)
		return
	}
	gw.recordApplied(res.Version, res.BodyHash)
}

// nodeFeaturesHandle is the org-parity W5.1 install seam for the
// node.features family (docs/plans/org-parity-full-depth-plan-2026-08-24.md
// §4). Unlike gatewayProvidersHandle/nodeGovernanceHandle, it applies
// nothing onto a live subsystem — the compiled spec is only ever READ, at
// the moment of a local action, by the four dashboard enforcement seams
// (dashboard.Options.FeatureGate / TerminalFeatureGate). So this handle is
// simpler than its siblings: no apply/clear closures, just a mutex-guarded
// pointer to the latest accepted spec plus enough identity to answer the
// P0-6 policy_state effective-state row.
//
// A nil *nodeFeaturesHandle, or a handle holding no accepted (or an INERT)
// spec, means every seam fail-opens — Allowed/TerminalAllowed both defer to
// internal/policyfam/nodefeatures' own nil-spec fail-open semantics.
type nodeFeaturesHandle struct {
	mu    sync.Mutex
	state nodeFeaturesState
	// sidecarWriter, when set, materializes the resolved tools.disallow list to
	// the node-local node.features LKG sidecar (P6 item 5) so BARE CLI
	// launchers and `observer adapters` — short-lived processes with no access
	// to this in-memory handle — see the live disallow state. Called on every
	// state change (apply → the applied list; inert/clear → empty). Best-effort;
	// a nil writer is the ungoverned/solo no-op. Invoked AFTER the state mutex
	// is released so file I/O never holds the lock.
	sidecarWriter func(disallow []string)
}

// SetSidecarWriter binds the node.features LKG sidecar writer (P6 item 5).
// Called once at daemon construction; nil-safe.
func (h *nodeFeaturesHandle) SetSidecarWriter(fn func(disallow []string)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.sidecarWriter = fn
	h.mu.Unlock()
}

// emitSidecar invokes the sidecar writer (if bound) with the given disallow
// list. Read the writer under the lock, call it outside — never hold the state
// mutex across file I/O.
func (h *nodeFeaturesHandle) emitSidecar(disallow []string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	fn := h.sidecarWriter
	h.mu.Unlock()
	if fn != nil {
		fn(disallow)
	}
}

// nodeFeaturesState is the org-rail half of the node.features
// effective-state truth, mirroring gatewayProvidersState's shape.
type nodeFeaturesState struct {
	// hasOrgRail is true once an org-published node.features body is
	// accepted (applied or accepted-inert); false after a clear.
	hasOrgRail bool
	// version / bodyHash are the accepted org resource's identity. bodyHash
	// is the SIGNED BodyHash, never the compiled Spec.Hash — same org-rail
	// wire rule as every other family here.
	version  int64
	bodyHash string
	// inertReason is the §6.4 preauthorization inert reason on an
	// accepted-but-not-applied body. Empty when the body is in effect.
	inertReason string
	// spec is the compiled decision spec, nil unless the body is actually
	// in effect (hasOrgRail && inertReason == ""). A nil spec is exactly
	// nodefeatures.FeatureDecision/TerminalDecision's own fail-open input,
	// so an inert body degrades to "every seam fail-open" for free.
	spec *nodefeatures.PolicySpec
}

// newNodeFeaturesHandle builds the daemon-lifetime install seam.
func newNodeFeaturesHandle() *nodeFeaturesHandle {
	return &nodeFeaturesHandle{}
}

// Allowed implements the dashboard.Options.FeatureGate closure shape:
// (bool allowed, string reason). Nil-safe.
func (h *nodeFeaturesHandle) Allowed(feature string) (bool, string) {
	if h == nil {
		return true, ""
	}
	h.mu.Lock()
	spec := h.state.spec
	h.mu.Unlock()
	d := nodefeatures.FeatureDecision(spec, feature)
	return d.Allowed, d.Reason
}

// TerminalAllowed implements the dashboard.Options.TerminalFeatureGate
// closure shape: (bool allowed, string reason). Nil-safe.
func (h *nodeFeaturesHandle) TerminalAllowed(requestedSandbox bool) (bool, string) {
	if h == nil {
		return true, ""
	}
	h.mu.Lock()
	spec := h.state.spec
	h.mu.Unlock()
	d := nodefeatures.TerminalDecision(spec, requestedSandbox)
	return d.Allowed, d.Reason
}

// ToolAllowed evaluates the P7 gateway-arc tools disallow-list (Phase P7
// item 4 — the node-side honor path for the org_disallow enforcement
// bucket): (bool allowed, string reason). Nil-safe. tool is an
// integration-registry Capability.Tool name (e.g. "codex", "crush").
func (h *nodeFeaturesHandle) ToolAllowed(tool string) (bool, string) {
	if h == nil {
		return true, ""
	}
	h.mu.Lock()
	spec := h.state.spec
	h.mu.Unlock()
	d := nodefeatures.ToolDecision(spec, tool)
	return d.Allowed, d.Reason
}

// Clear reverts to no accepted body — every seam fail-opens. Nil-safe.
func (h *nodeFeaturesHandle) Clear() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.state = nodeFeaturesState{}
	h.mu.Unlock()
	// Cleared org rail ⇒ nothing disallowed (fail-open); refresh the sidecar so
	// a short-lived launcher never reads a stale disallow list after a withdraw.
	h.emitSidecar(nil)
}

// recordApplied stamps a body that is actually in effect.
func (h *nodeFeaturesHandle) recordApplied(version int64, bodyHash string, spec nodefeatures.PolicySpec) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.state = nodeFeaturesState{hasOrgRail: true, version: version, bodyHash: bodyHash, spec: &spec}
	h.mu.Unlock()
	h.emitSidecar(disallowKeys(spec.Tools.Disallow))
}

// recordInert stamps a body that was ACCEPTED but not applied (the §6.4
// preauthorize_enforce gate) — spec stays nil, so every seam keeps
// fail-opening exactly as if no policy existed.
func (h *nodeFeaturesHandle) recordInert(version int64, bodyHash, reason string) {
	if h == nil {
		return
	}
	if reason == "" {
		reason = "not_preauthorized"
	}
	h.mu.Lock()
	h.state = nodeFeaturesState{hasOrgRail: true, version: version, bodyHash: bodyHash, inertReason: reason}
	h.mu.Unlock()
	// An INERT body applies no disallow list (spec is nil ⇒ fail-open), so the
	// sidecar must reflect "nothing disallowed" — never the inert body's list.
	h.emitSidecar(nil)
}

// nodeFeaturesFacts is the plain snapshot the P0-6 node.features point
// reader consumes.
type nodeFeaturesFacts struct {
	HasOrgRail  bool
	Version     int64
	BodyHash    string
	InertReason string
	// InEffect is true only when the body is actually in effect (not
	// inert) — i.e. at least one seam could deny a request right now.
	InEffect bool
}

// Facts snapshots the handle for the P0-6 reader. Nil-safe.
func (h *nodeFeaturesHandle) Facts() nodeFeaturesFacts {
	if h == nil {
		return nodeFeaturesFacts{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return nodeFeaturesFacts{
		HasOrgRail:  h.state.hasOrgRail,
		Version:     h.state.version,
		BodyHash:    h.state.bodyHash,
		InertReason: h.state.inertReason,
		InEffect:    h.state.spec != nil,
	}
}

// applyNodeFeatures downcasts a compiled node.features spec and records it
// through nf, honouring the plan §6.4 preauthorization verdict exactly like
// applyGatewayProviders: an inert body is recorded (for the effective-state
// row) but never actually applied, so an unpreauthorized org body cannot
// silently start denying a dev's terminal/remote/routing-apply/
// patterns-write requests.
func applyNodeFeatures(nf *nodeFeaturesHandle, res orgclient.PolicyResourceResult, logger *slog.Logger) {
	spec, ok := res.Spec.(nodefeatures.PolicySpec)
	if !ok {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	if !res.EnforceAllowed {
		nf.recordInert(res.Version, res.BodyHash, res.InertReason)
		logger.Info("policy resource: node.features accepted but INERT — every gated seam stays fail-open",
			"version", res.Version, "reason", res.InertReason)
		return
	}
	nf.recordApplied(res.Version, res.BodyHash, spec)
	logger.Info("policy resource: node.features applied", "version", res.Version)
}

// publishPolicyResourceResult dispatches one family's fetch/LKG outcome
// onto its install seam — the ONE place both the LKG loader and the poller
// call, so the two callers can never diverge on how a PolicyResourceResult
// maps onto Publish/Apply/ClearOrg/Clear. admission.input and
// egress.routing_guardrail install through *obsAdmissionHandle (nil-safe);
// gateway.providers installs through the separate *gatewayProvidersHandle
// (also nil-safe) since it has no obs/admission counterpart at all.
func publishPolicyResourceResult(handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, family string, res orgclient.PolicyResourceResult, logger *slog.Logger) {
	switch res.Status {
	case orgclient.PRApplied, orgclient.PRAppliedInert:
		// Plan §6.10 / GWF-SF1: re-check live enrolment identity immediately
		// before Publish/Apply so a fetch paused after CAS commit cannot
		// install under a since-superseded generation. handle.OrgIdentityMatches
		// is nil-safe (returns false on a nil handle) — this is the SAME
		// identity gate for all three families, including gateway.providers,
		// even though only admission/egress publish onto *handle's own Org
		// layer.
		if !handle.OrgIdentityMatches(res.OrgKey, res.Generation) {
			return
		}
		switch family {
		case policyfam.FamilyAdmissionInput:
			handle.PublishOrgAdmission(res.OrgKey, res.Generation, res.Version, res.BodyHash, res.InertReason, res.EnforceAllowed, managedEnforceFor(ngov, family), res.Spec)
		case policyfam.FamilyEgressGuardrail:
			handle.PublishOrgEgress(res.OrgKey, res.Generation, res.Version, res.BodyHash, res.InertReason, res.EnforceAllowed, managedEnforceFor(ngov, family), res.Spec)
		case policyfam.FamilyGatewayProviders:
			applyGatewayProviders(gw, res, logger)
		case policyfam.FamilyNodeGovernance:
			// Admin-controlled Plane B: recording IS applying (the dashboard
			// route guard and the SPA both read the resolved posture), and
			// the GRANT — not this call — decides whether anything actually
			// takes effect.
			ngov.Apply(res)
		case policyfam.FamilyNodeFeatures:
			applyNodeFeatures(nf, res, logger)
		}
	case orgclient.PRNone:
		// Withdrawn (404): clear any previously-installed Org layer.
		clearOrgLayer(handle, gw, ngov, nf, family)
	case orgclient.PRRejected:
		// Plan §4.4: gate rejection keeps prior LKG — EXCEPT an identity
		// change (unenrol/re-enrol), which must ClearOrg (§6.9).
		if res.RejectCode == orgclient.PRRejectIdentityChanged {
			clearOrgLayer(handle, gw, ngov, nf, family)
		}
		// PRUnchanged / PRDeliveredUnaccepted: no Org-layer mutation.
	}
}

// clearOrgLayer clears the install seam for one family — the plan §6.9
// ErrNotEnrolled / generation-mismatch / identity-changed outcome path.
// handle.ClearOrgAdmission/ClearOrgEgress and gw.Clear are all nil-safe, so
// this never needs its own top-level nil guard: a family whose seam isn't
// wired on this node simply no-ops.
func clearOrgLayer(handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, family string) {
	switch family {
	case policyfam.FamilyAdmissionInput:
		handle.ClearOrgAdmission()
	case policyfam.FamilyEgressGuardrail:
		handle.ClearOrgEgress()
	case policyfam.FamilyGatewayProviders:
		gw.Clear()
	case policyfam.FamilyNodeGovernance:
		ngov.Clear()
	case policyfam.FamilyNodeFeatures:
		nf.Clear()
	}
}

// --- §6.6/§6.9 steady-state poller (item 5) --------------------------------

// policyResourceOutcomeSink records one family's classified fetch outcome
// into the P0-6 policy-state reporter (admitter/egress last-fetch slots).
// Nil is fine — the poller still applies/clears Org layers when the
// [org_client.share].policy_state reporter is off.
type policyResourceOutcomeSink func(family string, o orgclient.PolicyResourceFetchOutcome)

// runPolicyResourcePoller runs the plan §6.6/§6.9 steady-state poll loop for
// every v1 family, applying every outcome onto its install seam through the
// SAME publishPolicyResourceResult/clearOrgLayer dispatch the LKG loader
// (below) uses. Apply happens BEFORE the optional outcome sink poke (plan
// §6.6) so a reporter snapshot never races ahead of the live Org layer.
// Never propagates an error (P1, matching every sibling org poll loop in
// start.go) — a stuck/failing poll must never cancel the proxy, watcher, or
// dashboard. gw may be nil (gateway.providers not appliable on this node,
// e.g. the no_obs build or a node with no proxy wired) — every downstream
// call is nil-safe.
func runPolicyResourcePoller(ctx context.Context, cfg config.Config, oc *orgclient.Client, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, sink policyResourceOutcomeSink, logger *slog.Logger) {
	if oc == nil || (handle == nil && gw == nil && ngov == nil && nf == nil) {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilities(handle))
	logger.Debug("policy resource poller: starting", "families", policyfam.SupportedFamilies)
	_ = oc.PolicyResourcePollLoop(ctx, opts, func(pr orgclient.PolicyResourcePollResult) {
		switch {
		case errors.Is(pr.Err, orgclient.ErrNotEnrolled):
			// Plan §6.9 + Codex SF4: clear Org layer AND let Classify emit
			// Cleared so the outcome sink wipes stale reject/unreachable slots.
			clearOrgLayer(handle, gw, ngov, nf, pr.Family)
		case pr.Err != nil:
			// Transport/auth/indeterminate failure: leave whatever is
			// currently installed alone — a transient unreachability
			// must not tear down a still-valid Org layer. The per-Check
			// identity recheck (activeEnrolmentIdentity) is what fences
			// a layer that has ACTUALLY gone stale; this loop only acts
			// on a decisive fetch outcome. PolicyResourcePollLoop already
			// logs the failure.
		default:
			publishPolicyResourceResult(handle, gw, ngov, nf, pr.Family, pr.Result, logger)
		}
		// Apply-then-poke: classify AFTER the Org-layer mutation so the
		// reporter's next snapshot observes the post-apply state.
		if sink != nil {
			if o, ok := orgclient.ClassifyPolicyResourceFetch(pr.Result, pr.Err); ok {
				sink(pr.Family, o)
			}
		}
	})
}

// --- §6.5 LKG-before-listener (item 4) -------------------------------------

// verifiedCachedResource is one family's on-disk cache envelope, verified
// and compiled (loadPolicyResourceLKG's recovery matrix input).
type verifiedCachedResource struct {
	resource orgcontract.SignedPolicyResource
	spec     any
	digest   string
}

// verifyCachedPolicyResource reads, signature-verifies (against the pinned
// key, when one has ever been recorded), and compiles the on-disk cache
// envelope at path for one family. Any failure — missing file, bad JSON, a
// family mismatch, a bad signature, an unpinned/mismatched key, or a
// compile error — is reported as a single error so the caller's §6.5 "no
// verified cache" branch fires uniformly regardless of which gate failed: a
// corrupt or tampered local cache must never be trusted just because one
// early gate happened to pass.
// nodeAttrs are the CURRENT locally-configured targeting attributes: a
// cached envelope whose signed selectors contradict them is treated exactly
// like an unverifiable cache (design §2 "LKG" — the node's attributes
// changed, so the cached policy no longer applies to it), which sends the
// caller down matrix row 1: blank the ETag and refetch.
func verifyCachedPolicyResource(ctx context.Context, st *store.Store, orgURL, family, path string, nodeAttrs orgcontract.Selectors) (verifiedCachedResource, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return verifiedCachedResource{}, fmt.Errorf("read cache: %w", err)
	}
	var resource orgcontract.SignedPolicyResource
	if err := json.Unmarshal(raw, &resource); err != nil {
		return verifiedCachedResource{}, fmt.Errorf("decode cache: %w", err)
	}
	if resource.Family != family {
		return verifiedCachedResource{}, fmt.Errorf("cache family mismatch: got %q want %q", resource.Family, family)
	}
	// Plan §4.4 closed-envelope on every LKG path (same gates as live accept).
	if resource.ID != "default" || resource.Version <= 0 || resource.CompilerVersion != "v1" {
		return verifiedCachedResource{}, fmt.Errorf("cache closed-envelope violation: id=%q version=%d compiler=%q",
			resource.ID, resource.Version, resource.CompilerVersion)
	}
	// P0-10 Phase B: the same canonical-form gate the live accept path runs
	// (orgcontract.ValidateCanonicalSelectorsJSON), then the same targeting
	// corroboration — against CURRENT config, not whatever was configured
	// when the envelope was cached.
	selectors, selErr := orgcontract.ValidateCanonicalSelectorsJSON(resource.SelectorsJSON)
	if selErr != nil {
		return verifiedCachedResource{}, fmt.Errorf("cache closed-envelope violation: %w", selErr)
	}
	if mismatched, _ := orgcontract.CorroborateSelectors(selectors, nodeAttrs); len(mismatched) > 0 {
		return verifiedCachedResource{}, fmt.Errorf("cached envelope's selectors %s contradict this node's configured attributes on %s",
			resource.SelectorsJSON, strings.Join(mismatched, ","))
	}
	pub, err := orgcontract.VerifyPolicyResource(resource)
	if err != nil {
		return verifiedCachedResource{}, fmt.Errorf("verify signature: %w", err)
	}
	pin, perr := loadPolicyResourceKeyPin(ctx, st, orgURL)
	if perr != nil {
		return verifiedCachedResource{}, fmt.Errorf("load key pin: %w", perr)
	}
	// Codex SF2 / plan §4.4: LKG fail-closed without a recorded pin — never
	// trust a cache under TOFU-absent identity (live fetch may still TOFU).
	if pin == "" {
		return verifiedCachedResource{}, errors.New("no org policy signing key pin recorded — refuse LKG")
	}
	if pin != orgcontract.PublicKeyPinHash(pub) {
		return verifiedCachedResource{}, errors.New("cached envelope's signing key does not match the pinned key")
	}
	spec, _, cerr := policyfam.CompileFamilyBody(family, []byte(resource.Body), orgclient.DefaultMaxPolicyResourceBodyBytes)
	if cerr != nil {
		return verifiedCachedResource{}, fmt.Errorf("compile body: %w", cerr)
	}
	digest, derr := orgcontract.PolicyResourceMessageDigest(resource)
	if derr != nil {
		return verifiedCachedResource{}, fmt.Errorf("digest: %w", derr)
	}
	return verifiedCachedResource{resource: resource, spec: spec, digest: digest}, nil
}

// loadPolicyResourceKeyPin mirrors orgclient's private loadKeyPin (same
// store row: layer="org", path=orgclient.PolicyKeyPinPath(orgURL)) — a
// second, cmd-side reader is used rather than exporting orgclient's
// internal method, since this file already needs its own read-only access
// to the pin row for the LKG cache-verify path and orgclient's copy is
// wired through its unexported *Client receiver.
func loadPolicyResourceKeyPin(ctx context.Context, st *store.Store, orgURL string) (string, error) {
	states, err := st.LatestGuardPolicyStates(ctx)
	if err != nil {
		return "", err
	}
	pinPath := orgclient.PolicyKeyPinPath(orgURL)
	for _, s := range states {
		if s.Layer == "org" && s.Path == pinPath {
			return s.ContentHash, nil
		}
	}
	return "", nil
}

// policyResourceEnforceGate re-derives EnforceAllowed/InertReason (plan
// §6.4) for a cache-installed envelope the same way
// orgclient.acceptPolicyResource does for a freshly-fetched one — the
// durable state row itself carries no EnforceAllowed/InertReason column
// (only floor/last version + hashes), so the LKG install path recomputes
// it from the CURRENT [org_client.policy].preauthorize_enforce config
// every time, exactly like a live fetch would.
func policyResourceEnforceGate(family string, spec any, preauthorizeEnforce []string) (enforceAllowed bool, inertReason string) {
	if policyfam.SpecRequestsEnforceMode(family, spec) && !containsString(family, preauthorizeEnforce) {
		return false, "not_preauthorized"
	}
	return true, ""
}

// managedEnforceFor resolves the Arc 4 P3 §R23 lift for one family: true only
// when the node enrolled under Enterprise-Managed Tenancy AND the live grant
// carries that family's enforce.* authority. This is the ONE place the govern
// enforcement predicates meet the admission/egress publish path; the resolved
// bool travels onto OrgLayerMeta.ManagedEnforce so obs never imports govern.
// A nil handle (no governance) or the individual plane both yield false, so an
// unmanaged node's enforcement stays entirely node-owned ("never
// server-forced"). Only admission.input and egress.routing_guardrail have a
// managed-enforce lift here; routing is lifted separately (routing_live), and
// gateway.providers/node.governance are not §R23-gated.
func managedEnforceFor(ngov *nodeGovernanceHandle, family string) bool {
	if ngov == nil {
		return false
	}
	eff := ngov.Effective(context.Background())
	switch family {
	case policyfam.FamilyAdmissionInput:
		return eff.GrantsAdmissionEnforcement()
	case policyfam.FamilyEgressGuardrail:
		return eff.GrantsEgressEnforcement()
	}
	return false
}

func containsString(s string, set []string) bool {
	for _, v := range set {
		if v == s {
			return true
		}
	}
	return false
}

// capabilitiesSubsetLKG mirrors orgclient's RequiredCapabilities ⊆ live
// check for the LKG install path (same Gate-5 posture as live accept).
func capabilitiesSubsetLKG(required, live []string) bool {
	if len(required) == 0 {
		return true
	}
	liveSet := make(map[string]struct{}, len(live))
	for _, c := range live {
		liveSet[c] = struct{}{}
	}
	for _, c := range required {
		if _, ok := liveSet[c]; !ok {
			return false
		}
	}
	return true
}

// installPolicyResourceLKG installs an already-verified cache envelope
// (matrix rows 3/4) as the family's Org layer, after re-applying the same
// accept_families / runtime-capability gates live accept uses (plan §4.4 /
// §6.6 — LKG must not resurrect a withdrawn or unrealizable envelope).
func installPolicyResourceLKG(family, orgKey string, generation int64, opts orgclient.PolicyResourceOptions, cached verifiedCachedResource, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	if !containsString(family, opts.AcceptFamilies) {
		logger.Info("policy resource LKG: family not in accept_families — leaving uninstalled", "family", family)
		return
	}
	if adm, ok := cached.spec.(admission.PolicySpec); ok {
		if verr := admission.ValidateRuntimeCaps(adm, containsString("judge", opts.LiveCapabilities)); verr != nil {
			logger.Info("policy resource LKG: body-derived capability mismatch — leaving uninstalled",
				"family", family, "err", verr)
			return
		}
	}
	if len(cached.resource.RequiredCapabilities) > 0 && !capabilitiesSubsetLKG(cached.resource.RequiredCapabilities, opts.LiveCapabilities) {
		logger.Info("policy resource LKG: required capabilities not live — leaving uninstalled", "family", family)
		return
	}
	enforceAllowed, inertReason := policyResourceEnforceGate(family, cached.spec, opts.PreauthorizeEnforce)
	status := orgclient.PRApplied
	if !enforceAllowed {
		status = orgclient.PRAppliedInert
	}
	publishPolicyResourceResult(handle, gw, ngov, nf, family, orgclient.PolicyResourceResult{
		Status: status, Version: cached.resource.Version, EnforceAllowed: enforceAllowed,
		InertReason: inertReason, Family: family, OrgKey: orgKey, Generation: generation,
		BodyHash: cached.resource.BodyHash, Spec: cached.spec,
	}, logger)
	logger.Info("policy resource LKG: installed verified cache", "family", family,
		"version", cached.resource.Version, "enforce_allowed", enforceAllowed)
}

// repairAndInstallPolicyResourceLKG runs matrix row 4 (or the no-durable-
// floor case, which is equivalent to a floor of 0): a verified cache ahead
// of the durable floor/state — the exact window between the §6.3 cache
// fsync+rename and the DB CAS commit, e.g. a crash between the two — is
// repaired by re-running the CAS-fenced commit against the verified
// envelope's own version/hash/digest, then installed. Re-validates identity
// and the floor INSIDE the fence (a concurrent writer may have already
// caught up), matching store.WithPolicyResourceFence's own contract.
func repairAndInstallPolicyResourceLKG(ctx context.Context, st *store.Store, orgKey string, generation int64, family string, opts orgclient.PolicyResourceOptions, cached verifiedCachedResource, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	commit := store.PolicyResourceCommit{
		Generation: generation, FloorVersion: cached.resource.Version, LastVersion: cached.resource.Version,
		BodyHash: cached.resource.BodyHash, MsgDigest: cached.digest,
	}
	repaired := false
	fenceErr := st.WithPolicyResourceFence(ctx, orgKey, family, func(_ context.Context, fence store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
		if fence.Tombstoned || fence.Generation != generation {
			return nil, nil // identity changed concurrently — abort, install nothing
		}
		if fence.HasState && cached.resource.Version <= fence.FloorVersion {
			return nil, nil // a concurrent writer already caught up — nothing to repair
		}
		repaired = true
		return &commit, nil
	})
	if fenceErr != nil {
		logger.Warn("policy resource LKG: DB repair failed — leaving family uninstalled", "family", family, "err", fenceErr)
		return
	}
	if !repaired {
		// (nil, nil) abort inside the fence: identity/floor moved — do NOT
		// install the stale cache (Codex B7 / plan §6.5).
		logger.Info("policy resource LKG: repair aborted (identity/floor raced) — leaving family uninstalled", "family", family)
		return
	}
	installPolicyResourceLKG(family, orgKey, generation, opts, cached, handle, gw, ngov, nf, logger)
}

// refetchPolicyResourceLKG runs matrix rows 1/2: the on-disk cache is
// either unverifiable or behind/inconsistent with the durable floor, so it
// must never be installed as-is. The saved ETag is blanked first so the
// refetch can never short-circuit on a 304 (the whole point of this branch
// is that the local cache/DB pair is not trustworthy — a fresh signed body
// must be re-verified from scratch). A refetch failure leaves the family
// with no Org layer (Local/nil), reporting none/no_policy — never
// pending_restart.
func refetchPolicyResourceLKG(ctx context.Context, oc *orgclient.Client, st *store.Store, opts orgclient.PolicyResourceOptions, orgKey string, generation int64, family string, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	if err := st.SavePolicyResourceETag(ctx, orgKey, generation, family, ""); err != nil {
		logger.Warn("policy resource LKG: etag clear failed (refetch may still hit a stale 304)", "family", family, "err", err)
	}
	res, err := oc.FetchAndAcceptPolicyResource(ctx, family, opts)
	if err != nil {
		logger.Warn("policy resource LKG: refetch failed — booting with no Org layer for this family", "family", family, "err", err)
		clearOrgLayer(handle, gw, ngov, nf, family)
		return
	}
	publishPolicyResourceResult(handle, gw, ngov, nf, family, res, logger)
	logger.Info("policy resource LKG: refetch outcome", "family", family, "status", res.Status)
}

// loadPolicyResourceLKGFamily runs the plan §6.5 recovery matrix for ONE
// family: verify the on-disk cache, compare it against the durable
// (floor_version, msg_digest) state row, and either install it as-is,
// repair the DB and install, or force a refetch — never installing a
// cryptographically valid cache that sits below the durable replay floor.
func loadPolicyResourceLKGFamily(ctx context.Context, oc *orgclient.Client, st *store.Store, opts orgclient.PolicyResourceOptions, orgURL, orgKey string, generation int64, family string, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	cachePath := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(generation, 10), family+".json")
	cached, cacheErr := verifyCachedPolicyResource(ctx, st, orgURL, family, cachePath, opts.NodeAttrs)

	stateRow, hasState, err := st.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil {
		logger.Warn("policy resource LKG: state read failed — leaving family uninstalled", "family", family, "err", err)
		return
	}

	switch {
	case cacheErr != nil:
		// Row 1: no verified cache — force a refetch.
		refetchPolicyResourceLKG(ctx, oc, st, opts, orgKey, generation, family, handle, gw, ngov, nf, logger)
	case !hasState:
		// No durable floor at all (implicitly 0): a verified cache with
		// version > 0 is ahead of it — same repair-then-install path as
		// row 4 below.
		repairAndInstallPolicyResourceLKG(ctx, st, orgKey, generation, family, opts, cached, handle, gw, ngov, nf, logger)
	case cached.resource.Version < stateRow.FloorVersion,
		cached.resource.Version == stateRow.FloorVersion && cached.digest != stateRow.MsgDigest:
		// Row 2: cache behind the durable floor, or an equal-version
		// digest mismatch (replay/corruption) — never install; refetch.
		refetchPolicyResourceLKG(ctx, oc, st, opts, orgKey, generation, family, handle, gw, ngov, nf, logger)
	case cached.resource.Version == stateRow.FloorVersion:
		// Row 3: cache matches the durable floor exactly — install as-is,
		// but only when the state row's generation still matches the live
		// enrolment generation and the family remains accepted (plan §4.4 /
		// §6.6 — LKG must not resurrect a withdrawn accept-list entry).
		if stateRow.Generation != generation {
			logger.Warn("policy resource LKG: state generation mismatch — leaving family uninstalled", "family", family,
				"state_gen", stateRow.Generation, "live_gen", generation)
			return
		}
		installPolicyResourceLKG(family, orgKey, generation, opts, cached, handle, gw, ngov, nf, logger)
	default: // cached.resource.Version > stateRow.FloorVersion
		// Row 4: cache ahead of the durable floor — repair, then install.
		repairAndInstallPolicyResourceLKG(ctx, st, orgKey, generation, family, opts, cached, handle, gw, ngov, nf, logger)
	}
}

// loadPolicyResourceLKG runs the plan §6.5 recovery matrix for every v1
// family, synchronously, exactly once — start.go calls this BEFORE
// launching the proxy listener's goroutine, so a verified Org layer (or an
// honest none/no_policy) is in place before the first proxied request can
// ever be evaluated by Check(). Never returns an error (P1 — a wholly
// offline node, or one with no policy-resource history at all, must still
// boot cleanly): every failure downgrades to "leave this family's install
// seam uninstalled" plus a log line. gw may be nil (gateway.providers not
// appliable on this node) — the loop still runs for admission/egress in
// that case, and vice versa: a nil handle with a non-nil gw still lets
// gateway.providers load.
func loadPolicyResourceLKG(ctx context.Context, cfg config.Config, oc *orgclient.Client, st *store.Store, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	if oc == nil || (handle == nil && gw == nil && ngov == nil && nf == nil) {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return // not enrolled — nothing to load, every family stays Local/nil
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	genRow, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || genRow.Tombstoned {
		return // no live generation for this identity — nothing to load
	}
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilities(handle))
	for _, family := range policyfam.SupportedFamilies {
		loadPolicyResourceLKGFamily(ctx, oc, st, opts, enr.OrgServerURL, orgKey, genRow.Generation, family, handle, gw, ngov, nf, logger)
	}
}
