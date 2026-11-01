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
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures/lkgsidecar"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
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
		AcceptFamilies:      cfg.OrgClient.Policy.AcceptedFamilies(),
		PreauthorizeEnforce: cfg.OrgClient.Policy.PreauthorizedFamilies(),
		NodeAttrs:           policyResourceNodeAttrs(cfg),
		LiveCapabilities:    liveCaps,
		// The result-based posture gate (roadmap F0-8): each linked family's
		// own evaluator (policyfam.LinkedFamily.CheckPosture), plus, for
		// node.governance, the module posture providers of the pins it
		// carries (nodegov.CheckPinPosture, N3).
		CheckPosture: checkPolicyPosture,
	}
}

// checkPolicyPosture composes the result-based posture gate: a
// node.governance body is judged by the evaluators the modules registered
// for the pin keys it carries (nodegov.CheckPinPosture; the sandbox module's
// is cmd/observer/sandbox_posture_wire.go), every other family by its own
// linked evaluator. A family or pin set with no evaluator always passes.
func checkPolicyPosture(family string, spec any) (string, error) {
	if family == policyfam.FamilyNodeGovernance {
		s, ok := spec.(nodegov.PolicySpec)
		if !ok {
			return "", nil
		}
		return nodegov.CheckPinPosture(nodegov.SpecPins(s))
	}
	return policyfam.CheckLinkedPosture(family, spec)
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
	return nodeLiveCapabilitiesFor(handle, nil)
}

// nodeLiveCapabilitiesFor is nodeLiveCapabilities with the linked families'
// tokens limited to those whose owning module active reports active (the
// node's [components] snapshot, componentSnapshotForConfig): a deactivated
// sandbox module advertises no terminals.isolation token, so a floor body
// NACKs capability_mismatch there instead of being accepted by a module that
// does not run. A nil active keeps every token.
func nodeLiveCapabilitiesFor(handle *obsAdmissionHandle, active func(id string) bool) []string {
	caps := handle.LiveCapabilities()
	if tok := orgcontract.ModeCapabilityToken(providers.SupportedModeSchemaVersion); tok != "" {
		caps = append(caps, tok)
	}
	// Every linked family's own live tokens (roadmap F0-9), the node side of
	// the tokens the org server derives from a body (LinkedFamily legs).
	caps = append(caps, policyfam.LinkedLiveCapabilitiesActive(active)...)
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
		logger.Info("policy resource: gateway.providers accepted but INERT - the node's own lanes keep routing",
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
// (dashapi.Options.FeatureGate / TerminalFeatureGate). So this handle is
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
	sidecarWriter func(disallow []string, terminals *lkgsidecar.Terminals)
	// toolGrant answers the dashboard launch gate's tool access question
	// (request-grants G8, SetToolGrant): a verified org grant for exactly
	// this tool, counting one use. nil = no grants.
	toolGrant func(tool string) (grantID int64, ok bool)
	// featureGrant answers "does a verified feature access grant name this
	// node.features feature" (request-grants G8, SetFeatureGrant). A feature
	// grant is time-bound only, so nothing is counted. nil = no grants.
	featureGrant func(feature string) (grantID int64, ok bool)
}

// SetFeatureGrant binds the feature access grant reader (request-grants
// G8); nil-safe.
func (h *nodeFeaturesHandle) SetFeatureGrant(fn func(feature string) (int64, bool)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.featureGrant = fn
	h.mu.Unlock()
}

// grantedFeature asks the bound reader about feature (0, false when none).
func (h *nodeFeaturesHandle) grantedFeature(feature string) (int64, bool) {
	h.mu.Lock()
	fn := h.featureGrant
	h.mu.Unlock()
	if fn == nil {
		return 0, false
	}
	id, ok := fn(feature)
	return id, ok && id > 0
}

// SetToolGrant binds the tool access grant reader (request-grants G8).
// Called once at daemon construction, where the long-lived DB handle exists;
// nil-safe.
func (h *nodeFeaturesHandle) SetToolGrant(fn func(tool string) (int64, bool)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.toolGrant = fn
	h.mu.Unlock()
}

// ToolLaunchAllowed is ToolAllowed for a LAUNCH: a tool the org disallows
// still launches under a verified tool access grant for it that has a use
// left. This call only checks that a use is left and counts none; the
// launched process claims its use once (M3-10). It returns the grant id that
// let the launch through (0 = none needed or none held).
func (h *nodeFeaturesHandle) ToolLaunchAllowed(tool string) (bool, string, int64) {
	allowed, reason := h.ToolAllowed(tool)
	if allowed || h == nil {
		return allowed, reason, 0
	}
	h.mu.Lock()
	fn := h.toolGrant
	h.mu.Unlock()
	if fn == nil {
		return false, reason, 0
	}
	if id, ok := fn(tool); ok && id > 0 {
		return true, fmt.Sprintf("allowed by org grant #%d", id), id
	}
	return false, reason, 0
}

// SetSidecarWriter binds the node.features LKG sidecar writer (P6 item 5).
// Called once at daemon construction; nil-safe.
func (h *nodeFeaturesHandle) SetSidecarWriter(fn func(disallow []string, terminals *lkgsidecar.Terminals)) {
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
func (h *nodeFeaturesHandle) emitSidecar(disallow []string, terminals *lkgsidecar.Terminals) {
	if h == nil {
		return
	}
	h.mu.Lock()
	fn := h.sidecarWriter
	h.mu.Unlock()
	if fn != nil {
		fn(disallow, terminals)
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

// processNodeFeatures is the daemon's node.features handle once `observer
// start` built it; nil in every other process. A launch the daemon starts
// (termsvc's PTY entries, and the daemon-started walks of the launch gate
// table) reads the org's terminals decision from it (OSH-R-003); a
// standalone launcher reads the daemon's sidecar instead.
var processNodeFeatures atomic.Pointer[nodeFeaturesHandle]

// daemonTerminalGate is the org's terminals decision for a launch the
// daemon starts: TerminalAllowed on the daemon's handle (a nil handle, a
// daemon with no org body, still applies an isolation floor in force).
func daemonTerminalGate(requestedSandbox bool) (bool, string) {
	return processNodeFeatures.Load().TerminalAllowed(requestedSandbox)
}

// newNodeFeaturesHandle builds the daemon-lifetime install seam.
func newNodeFeaturesHandle() *nodeFeaturesHandle {
	return &nodeFeaturesHandle{}
}

// Allowed implements the dashapi.Options.FeatureGate closure shape:
// (bool allowed, string reason). Nil-safe.
func (h *nodeFeaturesHandle) Allowed(feature string) (bool, string) {
	if h == nil {
		return true, ""
	}
	h.mu.Lock()
	spec := h.state.spec
	h.mu.Unlock()
	d := nodefeatures.FeatureDecision(spec, feature)
	if !d.Allowed {
		if id, ok := h.grantedFeature(feature); ok {
			return true, fmt.Sprintf("allowed by org grant #%d", id)
		}
	}
	return d.Allowed, d.Reason
}

// TerminalAllowed implements the dashapi.Options.TerminalFeatureGate
// closure shape: (bool allowed, string reason). Nil-safe.
func (h *nodeFeaturesHandle) TerminalAllowed(requestedSandbox bool) (bool, string) {
	// An org isolation floor that implies sandbox_required (lane SBX-P1B,
	// sandbox plan v2 section 8.1) refuses an unsandboxed terminal first,
	// naming the floor; no floor in force changes nothing.
	if !requestedSandbox {
		if ok, reason := isolationFloorsAllowUnsandboxed(); !ok {
			return false, reason
		}
	}
	if h == nil {
		return true, ""
	}
	h.mu.Lock()
	spec := h.state.spec
	h.mu.Unlock()
	d := nodefeatures.TerminalDecision(spec, requestedSandbox)
	if !d.Allowed && !requestedSandbox && nodefeatures.TerminalDecision(spec, true).Allowed {
		// Refused only for want of a sandbox: on a machine that cannot run
		// one at all (SBX-P1B merge audit finding 4, plan 11.5) the reason
		// says so and names the org setting, instead of asking for a retry
		// that cannot work.
		if why := sandboxCannotRunHere(); why != "" {
			return false, sandboxCannotRunRefusal(why)
		}
	}
	if !d.Allowed && nodefeatures.TerminalDecisionEnabled(spec, true).Allowed {
		// Denied because terminals are disabled: a feature access grant
		// lifts that, and only that (the sandbox requirement stands).
		if id, ok := h.grantedFeature(nodefeatures.FeatureTerminals); ok {
			if g := nodefeatures.TerminalDecisionEnabled(spec, requestedSandbox); !g.Allowed {
				return false, g.Reason
			}
			return true, fmt.Sprintf("allowed by org grant #%d", id)
		}
	}
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
	h.emitSidecar(nil, nil)
}

// recordApplied stamps a body that is actually in effect.
func (h *nodeFeaturesHandle) recordApplied(version int64, bodyHash string, spec nodefeatures.PolicySpec) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.state = nodeFeaturesState{hasOrgRail: true, version: version, bodyHash: bodyHash, spec: &spec}
	h.mu.Unlock()
	h.emitSidecar(disallowKeys(spec.Tools.Disallow), sidecarTerminals(spec.Terminals))
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
	h.emitSidecar(nil, nil)
}

// sidecarTerminals is the sidecar's copy of a governed terminals rule (nil
// when the org does not govern terminals), so a CLI launcher's terminals
// gate decides exactly what TerminalAllowed decides here (OSH-R-003).
func sidecarTerminals(r nodefeatures.TerminalsRule) *lkgsidecar.Terminals {
	if !r.Governed {
		return nil
	}
	return &lkgsidecar.Terminals{Enabled: r.Enabled, SandboxRequired: r.SandboxRequired}
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
		logger.Info("policy resource: node.features accepted but INERT - every gated seam stays fail-open",
			"version", res.Version, "reason", res.InertReason)
		return
	}
	nf.recordApplied(res.Version, res.BodyHash, spec)
	logger.Info("policy resource: node.features applied", "version", res.Version)
}

// orgIdentityGate reports whether the node's live enrolment identity still
// equals (orgKey, generation). Production builds it from the org client
// (orgIdentityGateFor); it never depends on the Plane A admission handle, so
// every build variant (full, sbo_omit_obs, no_obs, sbo_omit_judge_client)
// installs the same org policy families (AA-67, T-673).
type orgIdentityGate func(orgKey string, generation int64) bool

// matches is the nil-safe call: a nil gate fails closed.
func (g orgIdentityGate) matches(orgKey string, generation int64) bool {
	if g == nil {
		return false
	}
	return g(orgKey, generation)
}

// orgIdentityGateFor builds the install gate from the org client: a fresh
// read of the active enrolment on every call (orgclient.PolicyIdentityMatches).
// A nil client yields a gate that always fails closed.
func orgIdentityGateFor(ctx context.Context, oc *orgclient.Client) orgIdentityGate {
	return func(orgKey string, generation int64) bool {
		return oc.PolicyIdentityMatches(ctx, orgKey, generation)
	}
}

// publishPolicyResourceResult dispatches one family's fetch/LKG outcome
// onto its install seam — the ONE place both the LKG loader and the poller
// call, so the two callers can never diverge on how a PolicyResourceResult
// maps onto Publish/Apply/ClearOrg/Clear. admission.input and
// egress.routing_guardrail install through *obsAdmissionHandle (nil-safe);
// gateway.providers installs through the separate *gatewayProvidersHandle
// (also nil-safe) since it has no obs/admission counterpart at all.
//
// It reports whether it installed res: true only for an install result that
// passed the identity gate (the poller's adopter records a layer only then).
func publishPolicyResourceResult(ident orgIdentityGate, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, family string, res orgclient.PolicyResourceResult, logger *slog.Logger) bool {
	switch policyResourceDisposition(res) {
	case prDispositionInstall:
		// Plan §6.10 / GWF-SF1: re-check live enrolment identity immediately
		// before Publish/Apply so a fetch paused after CAS commit cannot
		// install under a since-superseded generation. This is the SAME
		// identity gate for every family. It comes from the org client
		// (ident), never from the Plane A admission handle: a build without
		// obs has a nil handle, and gating on it dropped every org policy
		// family, not only the obs ones (AA-67, T-673). A nil gate fails
		// closed.
		if !ident.matches(res.OrgKey, res.Generation) {
			return false
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
		case policyfam.FamilyMCPAccess:
			// Agent Access P4 (mcprelay_wire.go): compile → swap → cache.
			// A nil process handle ([mcp_relay].enabled=false) is a no-op.
			mcpRelayPublish(res)
		case policyfam.FamilyTerminalsIsolation:
			// The sandbox module's floors (sandbox_posture_wire.go): read
			// live by every sandbox selection; a no-op in a build without
			// the module.
			isolationFloorsPublish(res)
		case policyfam.FamilySecurityScanning:
			// Lane SEC-E (security_scanning_wire.go): the floor in force,
			// read through securityFloorsApplied.
			securityScanningPublish(res, logger)
		case policyfam.FamilyNodeComponents:
			// Modular packaging P4 (components_governance.go): there is no
			// live seam. Every process that resolves component state reads
			// the verified cache this fetch just wrote; the daemon's
			// background work follows at its next start, exactly like a
			// local component change.
			if logger != nil {
				logger.Info("policy resource: node.components accepted; component state follows it on every new command and at the next daemon start",
					"version", res.Version, "inert_reason", res.InertReason)
			}
		}
		return true
	case prDispositionClear:
		clearOrgLayer(handle, gw, ngov, nf, family)
	case prDispositionKeep:
		if res.Status == orgclient.PRNone && logger != nil {
			logger.Debug("policy resource: server answered 404; keeping the installed org layer (only a signed version replaces it)",
				"family", family)
		}
	}
	return false
}

// prDisposition is what one fetch result does to a family's installed Org
// layer.
type prDisposition int

const (
	// prDispositionKeep leaves the installed layer (or its absence) alone.
	prDispositionKeep prDisposition = iota
	// prDispositionInstall publishes the verified, accepted spec.
	prDispositionInstall
	// prDispositionClear removes the installed layer.
	prDispositionClear
)

// prStatusDispositions maps a fetch status onto its install-seam effect. It
// is a table so the rule is one row per status (CLAUDE.md #5); a status
// absent from the table keeps the layer, the safe default.
//
// PRNone is KEEP (D-016, Sol A5-01): it is an unsigned 404, which a proxy
// error, a route mismatch, a downgraded server or anyone between this node
// and its org can produce, and clearing on it would silently drop an org's
// governance, admission, egress, gateway-provider, feature or MCP-access
// controls. Before this rule a 404 cleared the live layer while the durable
// cache stayed on disk, so the next daemon start re-installed it from the
// last-known-good loader anyway: the clear was neither safe nor durable. The
// org withdraws or loosens a family by publishing a newer SIGNED version.
var prStatusDispositions = map[orgclient.PolicyResourceStatus]prDisposition{
	orgclient.PRApplied:             prDispositionInstall,
	orgclient.PRAppliedInert:        prDispositionInstall,
	orgclient.PRUnchanged:           prDispositionKeep,
	orgclient.PRNone:                prDispositionKeep,
	orgclient.PRDeliveredUnaccepted: prDispositionKeep,
	// A SIGNED withdrawal addressed to this node (D-016): the one verified
	// way the org takes a layer back.
	orgclient.PRWithdrawn: prDispositionClear,
	// Plan §4.4: a gate rejection keeps the prior LKG; the identity-change
	// override is applied in policyResourceDisposition.
	orgclient.PRRejected: prDispositionKeep,
}

// policyResourceDisposition resolves one fetch result to its install-seam
// effect: the status table, plus the one reject that must clear - an
// identity change (unenrol/re-enrol), plan §6.9, which is a local fact about
// this node's enrolment rather than anything the server said.
func policyResourceDisposition(res orgclient.PolicyResourceResult) prDisposition {
	if res.Status == orgclient.PRRejected && res.RejectCode == orgclient.PRRejectIdentityChanged {
		return prDispositionClear
	}
	if d, ok := prStatusDispositions[res.Status]; ok {
		return d
	}
	return prDispositionKeep
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
	case policyfam.FamilyMCPAccess:
		mcpRelayClear()
	case policyfam.FamilyTerminalsIsolation:
		isolationFloorsClear()
	case policyfam.FamilySecurityScanning:
		securityScanningClear()
	}
}

// --- §6.6/§6.9 steady-state poller (item 5) --------------------------------

// policyResourceOutcomeSink records one family's classified fetch outcome
// into the P0-6 policy-state reporter (admitter/egress last-fetch slots).
// Nil is fine (tests, or a daemon build without the reporter) — the poller
// still applies/clears Org layers without a sink; `observer start` always
// registers one now (D-DEMO-13) and the reporter itself stays dormant until
// its channel is enabled.
type policyResourceOutcomeSink func(family string, o orgclient.PolicyResourceFetchOutcome)

// logLinkedFamilyConflicts reports, once at daemon start, every policy family
// two pair files registered (roadmap F0-9). Such a family is unlinked, so
// every body of it is refused; the log names why. It returns the list so a
// test can check it without a logger.
func logLinkedFamilyConflicts(logger *slog.Logger) []string {
	conflicts := policyfam.LinkedConflicts()
	if len(conflicts) > 0 && logger != nil {
		logger.Warn("policy families registered more than once in this build; every body of them is refused until the build is fixed",
			"families", conflicts)
	}
	return conflicts
}

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
	logLinkedFamilyConflicts(logger)
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilitiesFor(handle, componentSnapshotForConfig(cfg).ModuleActive))
	ident := orgIdentityGateFor(ctx, oc)
	adopter := newPolicyLayerAdopter()
	logger.Debug("policy resource poller: starting", "families", policyfam.SupportedFamilies)
	_ = oc.PolicyResourcePollLoop(ctx, opts, func(pr orgclient.PolicyResourcePollResult) {
		switch {
		case errors.Is(pr.Err, orgclient.ErrNotEnrolled):
			// Plan §6.9 + Codex SF4: clear Org layer AND let Classify emit
			// Cleared so the outcome sink wipes stale reject/unreachable slots.
			adopter.forget(pr.Family)
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
			adoptAndPublish(adopter, ident, handle, gw, ngov, nf, pr.Family, pr.Result, logger)
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

// policyLayerKey names one installed org layer: the enrolment identity it was
// fetched under and the exact signed version and body.
type policyLayerKey struct {
	orgKey     string
	generation int64
	version    int64
	bodyHash   string
}

func policyLayerKeyOf(res orgclient.PolicyResourceResult) policyLayerKey {
	return policyLayerKey{orgKey: res.OrgKey, generation: res.Generation, version: res.Version, bodyHash: res.BodyHash}
}

// policyLayerAdopter is the poller's record of the layer it installed per
// family (WINNODE item 1). It exists for one case: an "unchanged" fetch whose
// verified layer this daemon never installed. That happens when the daemon
// booted with no org layer (the last-known-good refetch failed: the network
// was down, or on v1.36.0 Windows every cache write failed after its rename)
// and the cache and the durable floor became consistent afterwards, written
// by another process or by an earlier poll. The status table keeps the layer
// on "unchanged", so before this the daemon stayed ungoverned until its next
// restart while a CLI reading the same cache reported the policy installed.
//
// An unchanged result is as verified as an applied one (a 304 re-runs every
// accept gate against the cache; an equal-floor 200 matched the durable
// digest), so installing it once is as safe as installing a fresh apply. The
// record is owned by one poller goroutine, so it needs no lock.
type policyLayerAdopter struct {
	installed map[string]policyLayerKey
}

func newPolicyLayerAdopter() *policyLayerAdopter {
	return &policyLayerAdopter{installed: map[string]policyLayerKey{}}
}

// resolve returns the result to publish for family. A clear forgets the
// layer, and a verified "unchanged" carrying a compiled spec this poller has
// not installed yet becomes the install it would have been as an apply
// (applied, or applied inert when enforcement is not allowed). Every other
// result passes through unchanged. An install is recorded by record, and only
// once publish reports it installed (adoptAndPublish).
func (a *policyLayerAdopter) resolve(family string, res orgclient.PolicyResourceResult) orgclient.PolicyResourceResult {
	switch policyResourceDisposition(res) {
	case prDispositionClear:
		delete(a.installed, family)
	case prDispositionKeep:
		if res.Status != orgclient.PRUnchanged || res.Spec == nil {
			return res
		}
		if held, ok := a.installed[family]; ok && held == policyLayerKeyOf(res) {
			return res
		}
		res.Status = orgclient.PRApplied
		if !res.EnforceAllowed {
			res.Status = orgclient.PRAppliedInert
		}
	}
	return res
}

// record notes that publish installed res for family.
func (a *policyLayerAdopter) record(family string, res orgclient.PolicyResourceResult) {
	a.installed[family] = policyLayerKeyOf(res)
}

// adoptAndPublish is the poller's step for one decisive fetch result: the
// adopter resolves it, publish installs it, and the adopter records the layer
// only when publish actually installed it. The identity gate is a fresh
// enrolment read on every call, so one failed read installs nothing; the
// layer stays unrecorded and the next "unchanged" poll still adopts it.
func adoptAndPublish(a *policyLayerAdopter, ident orgIdentityGate, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, family string, res orgclient.PolicyResourceResult, logger *slog.Logger) {
	res = a.resolve(family, res)
	if publishPolicyResourceResult(ident, handle, gw, ngov, nf, family, res, logger) {
		a.record(family, res)
	}
}

// forget drops family's record (the not-enrolled path clears the layer
// without a result to resolve).
func (a *policyLayerAdopter) forget(family string) {
	delete(a.installed, family)
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
	raw, err := os.ReadFile(path) //nolint:gosec // G703: false positive; every caller passes the node's own policy-resource cache file (<CacheDir>/<orgKey>/<generation>/<family>.json), and its content is signature-checked below
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
		return verifiedCachedResource{}, errors.New("no org policy signing key pin recorded - refuse LKG")
	}
	if pin != orgcontract.PublicKeyPinHash(pub) {
		return verifiedCachedResource{}, errors.New("cached envelope's signing key does not match the pinned key")
	}
	// A v2 (bound) cache must be bound to this node's current enrolment org
	// and member (C156-14). The projection target is not re-checked here: a
	// binary upgrade changes this build's target, and the cached projection
	// onto the older one is a subset this build still compiles until the
	// next fetch replaces it.
	if resource.Binding != nil {
		enr, eerr := st.LoadEnrolment(ctx)
		if eerr != nil {
			return verifiedCachedResource{}, fmt.Errorf("load enrolment: %w", eerr)
		}
		if enr == nil || resource.Binding.OrgID != enr.OrgID || resource.Binding.Subject != enr.UserID {
			return verifiedCachedResource{}, errors.New("cached envelope is bound to a different org or member than this enrolment")
		}
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
func installPolicyResourceLKG(ident orgIdentityGate, family, orgKey string, generation int64, opts orgclient.PolicyResourceOptions, cached verifiedCachedResource, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	if !containsString(family, opts.AcceptFamilies) {
		logger.Info("policy resource LKG: family not in accept_families - leaving uninstalled", "family", family)
		return
	}
	if adm, ok := cached.spec.(admission.PolicySpec); ok {
		if verr := admission.ValidateRuntimeCaps(adm, containsString("judge", opts.LiveCapabilities)); verr != nil {
			logger.Info("policy resource LKG: body-derived capability mismatch - leaving uninstalled",
				"family", family, "err", verr)
			return
		}
	}
	if len(cached.resource.RequiredCapabilities) > 0 && !capabilitiesSubsetLKG(cached.resource.RequiredCapabilities, opts.LiveCapabilities) {
		logger.Info("policy resource LKG: required capabilities not live - leaving uninstalled", "family", family)
		return
	}
	enforceAllowed, inertReason := policyResourceEnforceGate(family, cached.spec, opts.PreauthorizeEnforce)
	status := orgclient.PRApplied
	if !enforceAllowed {
		status = orgclient.PRAppliedInert
	}
	publishPolicyResourceResult(ident, handle, gw, ngov, nf, family, orgclient.PolicyResourceResult{
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
func repairAndInstallPolicyResourceLKG(ident orgIdentityGate, ctx context.Context, st *store.Store, orgKey string, generation int64, family string, opts orgclient.PolicyResourceOptions, cached verifiedCachedResource, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
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
		logger.Warn("policy resource LKG: DB repair failed - leaving family uninstalled", "family", family, "err", fenceErr)
		return
	}
	if !repaired {
		// (nil, nil) abort inside the fence: identity/floor moved — do NOT
		// install the stale cache (Codex B7 / plan §6.5).
		logger.Info("policy resource LKG: repair aborted (identity/floor raced) - leaving family uninstalled", "family", family)
		return
	}
	installPolicyResourceLKG(ident, family, orgKey, generation, opts, cached, handle, gw, ngov, nf, logger)
}

// refetchPolicyResourceLKG runs matrix rows 1/2: the on-disk cache is
// either unverifiable or behind/inconsistent with the durable floor, so it
// must never be installed as-is. The saved ETag is blanked first so the
// refetch can never short-circuit on a 304 (the whole point of this branch
// is that the local cache/DB pair is not trustworthy — a fresh signed body
// must be re-verified from scratch). A refetch failure leaves the family
// with no Org layer (Local/nil), reporting none/no_policy — never
// pending_restart.
func refetchPolicyResourceLKG(ident orgIdentityGate, ctx context.Context, oc *orgclient.Client, st *store.Store, opts orgclient.PolicyResourceOptions, orgKey string, generation int64, family string, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	if err := st.SavePolicyResourceETag(ctx, orgKey, generation, family, ""); err != nil {
		logger.Warn("policy resource LKG: etag clear failed (refetch may still hit a stale 304)", "family", family, "err", err)
	}
	res, err := oc.FetchAndAcceptPolicyResource(ctx, family, opts)
	if err != nil {
		logger.Warn("policy resource LKG: refetch failed - booting with no Org layer for this family", "family", family, "err", err)
		clearOrgLayer(handle, gw, ngov, nf, family)
		return
	}
	publishPolicyResourceResult(ident, handle, gw, ngov, nf, family, res, logger)
	logger.Info("policy resource LKG: refetch outcome", "family", family, "status", res.Status)
}

// loadPolicyResourceLKGFamily runs the plan §6.5 recovery matrix for ONE
// family: verify the on-disk cache, compare it against the durable
// (floor_version, msg_digest) state row, and either install it as-is,
// repair the DB and install, or force a refetch — never installing a
// cryptographically valid cache that sits below the durable replay floor.
func loadPolicyResourceLKGFamily(ident orgIdentityGate, ctx context.Context, oc *orgclient.Client, st *store.Store, opts orgclient.PolicyResourceOptions, orgURL, orgKey string, generation int64, family string, handle *obsAdmissionHandle, gw *gatewayProvidersHandle, ngov *nodeGovernanceHandle, nf *nodeFeaturesHandle, logger *slog.Logger) {
	cachePath := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(generation, 10), family+".json")
	cached, cacheErr := verifyCachedPolicyResource(ctx, st, orgURL, family, cachePath, opts.NodeAttrs)

	stateRow, hasState, err := st.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil {
		logger.Warn("policy resource LKG: state read failed - leaving family uninstalled", "family", family, "err", err)
		return
	}

	switch {
	case cacheErr != nil:
		// Row 1: no verified cache — force a refetch.
		refetchPolicyResourceLKG(ident, ctx, oc, st, opts, orgKey, generation, family, handle, gw, ngov, nf, logger)
	case !hasState:
		// No durable floor at all (implicitly 0): a verified cache with
		// version > 0 is ahead of it — same repair-then-install path as
		// row 4 below.
		repairAndInstallPolicyResourceLKG(ident, ctx, st, orgKey, generation, family, opts, cached, handle, gw, ngov, nf, logger)
	case cached.resource.Version < stateRow.FloorVersion,
		cached.resource.Version == stateRow.FloorVersion && cached.digest != stateRow.MsgDigest:
		// Row 2: cache behind the durable floor, or an equal-version
		// digest mismatch (replay/corruption) — never install; refetch.
		refetchPolicyResourceLKG(ident, ctx, oc, st, opts, orgKey, generation, family, handle, gw, ngov, nf, logger)
	case cached.resource.Version == stateRow.FloorVersion:
		// Row 3: cache matches the durable floor exactly — install as-is,
		// but only when the state row's generation still matches the live
		// enrolment generation and the family remains accepted (plan §4.4 /
		// §6.6 — LKG must not resurrect a withdrawn accept-list entry).
		if stateRow.Generation != generation {
			logger.Warn("policy resource LKG: state generation mismatch - leaving family uninstalled", "family", family,
				"state_gen", stateRow.Generation, "live_gen", generation)
			return
		}
		installPolicyResourceLKG(ident, family, orgKey, generation, opts, cached, handle, gw, ngov, nf, logger)
	default: // cached.resource.Version > stateRow.FloorVersion
		// Row 4: cache ahead of the durable floor — repair, then install.
		repairAndInstallPolicyResourceLKG(ident, ctx, st, orgKey, generation, family, opts, cached, handle, gw, ngov, nf, logger)
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
	// From here on this process holds the org layer in memory (the daemon,
	// or a standalone proxy): readers that a CLI must satisfy from the
	// verified cache read the installed layer instead (R-035).
	policyResourceInstalledHere.Store(true)
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
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilitiesFor(handle, componentSnapshotForConfig(cfg).ModuleActive))
	ident := orgIdentityGateFor(ctx, oc)
	for _, family := range policyfam.SupportedFamilies {
		loadPolicyResourceLKGFamily(ident, ctx, oc, st, opts, enr.OrgServerURL, orgKey, genRow.Generation, family, handle, gw, ngov, nf, logger)
	}
}

// policyResourceInstalledHere reports that this process installs the org
// policy resources itself (loadPolicyResourceLKG ran), so its in-memory org
// layer is the truth; a CLI process reads the verified cache instead
// (loadPolicyResourceFromCache).
var policyResourceInstalledHere atomic.Bool

// loadPolicyResourceFromCache is the read-only half of the LKG matrix for a
// CLI process (R-035): one family's verified cache, installed only when it
// matches the durable state exactly (row 3: same version and digest, the
// live enrolment generation) and the family is accepted, with the same
// enforce gate the daemon applies. It never repairs, refetches or writes;
// anything else is "none", as for a daemon that left the family
// uninstalled. ok reports an applied spec; inert names why it applies no
// enforcement.
func loadPolicyResourceFromCache(ctx context.Context, cfg config.Config, st *store.Store, family string) (spec any, inert string, ok bool) {
	if st == nil {
		return nil, "", false
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil, "", false
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	genRow, has, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !has || genRow.Tombstoned {
		return nil, "", false
	}
	opts := policyResourceOptionsFor(cfg, nodeLiveCapabilitiesFor(nil, componentSnapshotForConfig(cfg).ModuleActive))
	if !containsString(family, opts.AcceptFamilies) {
		return nil, "", false
	}
	cachePath := filepath.Join(opts.CacheDir, orgKey, strconv.FormatInt(genRow.Generation, 10), family+".json")
	cached, err := verifyCachedPolicyResource(ctx, st, enr.OrgServerURL, family, cachePath, opts.NodeAttrs)
	if err != nil {
		return nil, "", false
	}
	row, hasState, err := st.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil || !hasState || row.Generation != genRow.Generation ||
		cached.resource.Version != row.FloorVersion || cached.digest != row.MsgDigest {
		return nil, "", false
	}
	if len(cached.resource.RequiredCapabilities) > 0 && !capabilitiesSubsetLKG(cached.resource.RequiredCapabilities, opts.LiveCapabilities) {
		return nil, "", false
	}
	enforceAllowed, inertReason := policyResourceEnforceGate(family, cached.spec, opts.PreauthorizeEnforce)
	if !enforceAllowed && inertReason == "" {
		inertReason = "not_preauthorized"
	}
	return cached.spec, inertReason, true
}

// sandboxCannotRunRefusal is the terminal refusal on a machine where the
// organization requires a sandboxed terminal and no sandbox can run (why).
// While an isolation floor is in force a managed machine receives
// "Require a sandboxed terminal" with it (D-753 Q43), so the reason names
// both settings.
func sandboxCannotRunRefusal(why string) string {
	return "your organization requires a sandboxed terminal on this machine (\"Require a sandboxed terminal\", which an organization isolation floor sets on every managed machine), " +
		"and this machine cannot run a sandbox: " + why + "; new terminals are refused, never run without one"
}
