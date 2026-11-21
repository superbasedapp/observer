//go:build !sbo_omit_proxy_routing && !sbo_omit_capture_proxy

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/provenance"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingconfig"
	"github.com/marmutapp/superbased-observer/internal/selfobs/conformance"
	"github.com/marmutapp/superbased-observer/internal/selfobs/emit"
	"github.com/marmutapp/superbased-observer/internal/selfobs/run"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// liveRouter implements proxy.ModelRouter at the cmd boundary — the
// single place the routing engine, the store-side snapshot refresher,
// and the decision-log store seam meet (§R5). It owns the live
// session-coherence state (the Simulate sessState analog) and the
// pending-decision buffer that links decisions to api_turns rows.
//
// Hot-path contract (§R9.2): Decide reads ONLY the refresher's
// in-memory snapshot plus two map lookups under a short mutex; the
// decision-row insert happens in RecordServed on the proxy's detached
// goroutine (or via the janitor for turns that never land).
type liveRouter struct {
	// policy is the live compiled decision policy, swapped whole by the
	// P0-7 hot-reload (ReloadOrgPolicy). Decide loads a pointer-to-value
	// and dereferences, so an in-flight decision keeps its consistent
	// snapshot across a reload (routing.Decide takes Policy BY VALUE).
	policy    atomic.Pointer[routing.Policy]
	mode      string // advise | enforce (the node-LOCAL [routing].mode)
	refresher *store.RoutingRefresher
	store     *store.Store
	logger    *slog.Logger
	now       func() time.Time

	// effMode is the EFFECTIVE routing mode the hot path reads (Decide),
	// resolved from lr.mode and — for a managed node holding enforce.routing
	// (Arc 4 P3b §R23 lift) — the org body's mode. Atomic so Decide is
	// lock-free; recomputed only under reloadMu (SetManagedEnforce /
	// ReloadOrgPolicy). Nil ⇒ fall back to lr.mode (the pre-P3b behaviour).
	effMode atomic.Pointer[string]
	// managedEnforce reports, live, whether this node may honor the org
	// routing body's mode (managed tenancy + enforce.routing). Injected from
	// start.go via the RoutingStateHandle after buildProxy; nil on any node
	// with no governance handle. Read only under reloadMu.
	managedEnforce func() bool
	// orgMode is the last composed org body's [routing].mode ("" when none).
	// Written under reloadMu; the managed-enforce source for effMode.
	orgMode string

	// localSpec is the IMMUTABLE node-local routing spec captured at
	// construction (routingconfig.Spec of [routing], BEFORE any org
	// composition). ReloadOrgPolicy recomposes from it exactly as
	// wireRouting did, so a reload reproduces construction (P0-7 B5).
	localSpec routing.PolicySpec
	// handle is the P0-6/P0-7 org-layer state carrier this router
	// publishes its post-reload version/hash into (set by wireRouting).
	handle *RoutingStateHandle

	// reloadMu serializes ReloadOrgPolicy construct+publish so a
	// concurrent reload can never publish an older composed version
	// over a newer one (P0-7 BLOCKER 3; mirrors guard's B3). The
	// production caller is single-threaded (PushLoop → reload sink),
	// so this is defense + concurrency-test honesty, not a live race.
	reloadMu sync.Mutex

	mu       sync.Mutex
	sessions map[string]*liveSessionState
	pending  map[int64]pendingDecision
	nextTok  int64

	// demoted holds the calibration job's §R18.3 rule demotions (rule
	// name → reason). A demoted rule's decisions log but never apply.
	// In-memory by design: a daemon restart clears it and the next
	// calibration pass re-detects within the hour — self-healing, no
	// new table.
	demoted atomic.Pointer[map[string]string]

	// selfobs is the P1-10 decision-run emitter (cmd-injected; never
	// imported by internal/routing). Nil/Nop ⇒ no emission.
	selfobs emit.Sink
	// selfobsSampleN is routing_sample_n (0=off, 1=every, N=1-of-N).
	selfobsSampleN int
	selfobsCounter atomic.Uint64
}

// SetDemotedRules swaps the demotion set (calibration job, §R18.3).
func (lr *liveRouter) SetDemotedRules(m map[string]string) {
	lr.demoted.Store(&m)
}

// DemotedRules returns a copy of the current §R18.3 demotion set
// (rule name → reason) — the read-side surface for the dashboard's
// /api/routing/status (R2.4). A copy, so callers can never mutate the
// set the hot path reads. Empty-non-nil when nothing is demoted.
func (lr *liveRouter) DemotedRules() map[string]string {
	m := lr.demoted.Load()
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(*m))
	for k, v := range *m {
		out[k] = v
	}
	return out
}

// liveSessionState is the per-session coherence memory (§R13) plus the
// §R7.4 escalation tracker.
type liveSessionState struct {
	turnsSinceSwitch int // -1 = never switched
	lastSeen         time.Time
	// lastDownshiftAt stamps the most recent APPLIED downshift per
	// turn-kind — the escalation detector's arming state.
	lastDownshiftAt map[routing.TurnKind]time.Time
	// escalatedUntil holds active §R7.4 cooldowns per turn-kind.
	escalatedUntil map[routing.TurnKind]time.Time
}

// Escalation tuning (§R7.4). The detector arms when a downshift was
// applied within the window; a failure spike in the session's recent
// actions then escalates the kind for the cooldown. Detection v1 is
// the tool-error-spike signal; immediate-retry and user-override
// detectors are documented extensions.
const (
	escalationDetectWindow = 10 * time.Minute
	escalationCooldown     = 15 * time.Minute
	escalationFailures     = 2 // failures among the last N window actions
)

type pendingDecision struct {
	row     store.RouterDecisionRow
	created time.Time
}

// pendingJanitorAge is how long a decision waits for its turn linkage
// before flushing with a NULL api_turn_id (the turn was dropped — a
// zero-usage stream, an early return).
const pendingJanitorAge = 60 * time.Second

// liveSessionCap bounds the coherence map on long-running daemons.
const liveSessionCap = 1024

func newLiveRouter(policy routing.Policy, mode string, refresher *store.RoutingRefresher, s *store.Store, logger *slog.Logger) *liveRouter {
	lr := &liveRouter{
		mode:      mode,
		refresher: refresher,
		store:     s,
		logger:    logger,
		now:       time.Now,
		sessions:  map[string]*liveSessionState{},
		pending:   map[int64]pendingDecision{},
		selfobs:   emit.Nop(),
	}
	lr.policy.Store(&policy)
	return lr
}

// effectiveMode returns the routing mode the hot path acts on: the
// managed-enforce-resolved effMode when set, else the node-local mode.
// Lock-free (atomic load), so Decide never contends with a reload.
func (lr *liveRouter) effectiveMode() string {
	if p := lr.effMode.Load(); p != nil {
		return *p
	}
	return lr.mode
}

// recomputeEffModeLocked recomputes effMode from lr.mode and — for a managed
// node holding enforce.routing (Arc 4 P3b §R23 lift) — the last composed org
// body's mode. Caller holds reloadMu. Per the operator's Option-1 decision the
// org mode is HONORED AS AUTHORED (no coercion): "enforce" turns routing
// enforcement on, anything else leaves it advisory. A non-managed node (or one
// without the authority / without an org routing body) always resolves to the
// node-local mode, so the individual plane is untouched.
func (lr *liveRouter) recomputeEffModeLocked() {
	m := lr.mode
	if lr.managedEnforce != nil && lr.managedEnforce() && lr.orgMode != "" {
		if lr.orgMode == "enforce" {
			m = "enforce"
		} else {
			m = "advise"
		}
	}
	lr.effMode.Store(&m)
}

// SetManagedEnforce injects the managed-enforce predicate (managed tenancy +
// enforce.routing) after buildProxy (start.go, where the governance handle
// exists) and recomputes the effective mode. Serialized with ReloadOrgPolicy.
func (lr *liveRouter) SetManagedEnforce(fn func() bool) {
	lr.reloadMu.Lock()
	defer lr.reloadMu.Unlock()
	lr.managedEnforce = fn
	lr.recomputeEffModeLocked()
}

// SetSelfObs injects the P1-10 emit sink + routing sample rate (plan
// Phase B). sampleN 0 disables routing emission; 1 emits every Decide;
// N>1 emits 1-of-N. Nil sink is treated as Nop.
func (lr *liveRouter) SetSelfObs(sink emit.Sink, sampleN int) {
	if lr == nil {
		return
	}
	if sink == nil {
		sink = emit.Nop()
	}
	lr.selfobs = sink
	lr.selfobsSampleN = sampleN
}

// emitSelfObs samples and emits one routing DecisionRun (ADR-0004 /
// P1-10 Phase B). Fire-and-forget; never blocks the Decide hot path on
// network I/O beyond the sink's own async batcher.
func (lr *liveRouter) emitSelfObs(sessionID string, kind routing.TurnKind, d routing.Decision, applied bool) {
	if lr == nil || lr.selfobs == nil || lr.selfobsSampleN <= 0 {
		return
	}
	n := lr.selfobsCounter.Add(1)
	if n%uint64(lr.selfobsSampleN) != 0 {
		return
	}
	decisions := make([]string, 0, 2+len(d.ReasonCodes))
	if d.RuleName != "" {
		decisions = append(decisions, "rule:"+d.RuleName)
	}
	decisions = append(decisions, "kind:"+string(kind))
	for _, rc := range d.ReasonCodes {
		decisions = append(decisions, string(rc))
	}
	outcome := "verified"
	if !applied {
		outcome = "dismissed"
	}
	lr.selfobs.Emit(context.Background(), run.DecisionRun{
		RunID:       fmt.Sprintf("routing-%d", n),
		TraceID:     sessionID,
		Trigger:     "manual",
		Component:   conformance.ComponentRouting,
		Decisions:   decisions,
		Outcome:     outcome,
		InitiatedBy: provenance.ActorHuman,
	})
}

// ReloadOrgPolicy recomposes the org routing policy from the node-local
// cache (store.GetOrgRoutingPolicy -> routingconfig.ComposeOrgPolicy ->
// routing.Compile, EXACTLY as wireRouting does at construction) and, on
// success, atomically swaps the router's live decision policy, the
// refresher's policy (+ all its policy-derived signals), and the
// RoutingStateHandle version/hash into effect — so the very next Decide
// enforces the accepted policy and the P0-6 reporter flips the router
// point from pending_restart to effective, with NO daemon restart
// (docs/plans/plane-a-p0-7-guard-router-hotreload-plan.md §2.2/§4).
//
// It is a NO-OP-with-error on a compose/lint failure (fail-safe: the
// running policy is never downgraded by a bad reload), and a cheap
// no-op when the running version already equals the cached accepted
// version (SF7 steady-state churn guard; version is a faithful content
// proxy — the routing accept path never caches an equal-version body).
//
// Publish order is STRICT (P0-7 B4/§4.6): the refresher's complete new
// derived snapshot is published FIRST, then the live policy, then the
// RoutingStateHandle LAST — so the reporter can never observe the router
// effective at the new version while the refresher still serves the old
// version's budget/path inputs. Any failure leaves all three on the
// prior version. Safe to call concurrently with Decide on the hot path
// (every swap is an atomic store or mutex-guarded). Concurrent reloads
// are serialized by reloadMu and refuse to publish a composed version
// older than the currently-published handle version (non-regressing).
func (lr *liveRouter) ReloadOrgPolicy(ctx context.Context) error {
	orgPol, ok, err := lr.store.GetOrgRoutingPolicy(ctx)
	if err != nil {
		return fmt.Errorf("routing.ReloadOrgPolicy: cache read: %w", err)
	}
	var composedOrgVersion int64
	if ok {
		composedOrgVersion = orgPol.Version
	}

	// Serialize construct+publish (B3). The cache read above is outside
	// the lock so two reloads can observe the same cache; the
	// non-regression check below refuses the stale publisher.
	lr.reloadMu.Lock()
	defer lr.reloadMu.Unlock()

	// SF7 steady-state short-circuit: running == cached accepted version
	// means the composed content is unchanged, so there is nothing to
	// reload. Cold-recovery (running < cached — e.g. a boot that rejected
	// the cache the New-time load could not use) still falls through.
	if lr.handle != nil && lr.handle.RunningVersion() == composedOrgVersion {
		return nil
	}
	// Non-regressing publish: refuse a candidate OLDER than the
	// currently-published handle version (defensive mirror of guard's
	// regressesOrg — a stale in-flight reload that captured an older
	// cache must not overwrite a newer publication). Version 0
	// (absent cache → local-only compose) is ALSO a regression when an
	// org version is already running — the `composedOrgVersion > 0`
	// guard would otherwise let an absent-cache reload publish v0 over
	// v1 (codex re-gate B3 fold).
	if lr.handle != nil {
		running := lr.handle.RunningVersion()
		if running > 0 && composedOrgVersion < running {
			return fmt.Errorf("routing.ReloadOrgPolicy: refusing to publish org version %d over %d (non-regressing)", composedOrgVersion, running)
		}
	}

	spec := lr.localSpec
	lr.orgMode = ""
	if ok {
		composed, cerr := routingconfig.ComposeOrgPolicy(spec, orgPol.Body)
		if cerr != nil {
			return fmt.Errorf("routing.ReloadOrgPolicy: compose org policy: %w", cerr)
		}
		spec = composed
		// Arc 4 P3b: capture the org body's mode so recomputeEffModeLocked can
		// honor it on a managed node holding enforce.routing. ComposeOrgPolicy
		// itself still ignores it (§R23) — the lift lives only in effMode.
		lr.orgMode = routingconfig.OrgBodyMode(orgPol.Body)
	}
	lr.recomputeEffModeLocked()
	policy, issues := routing.Compile(spec)
	// routing.Compile never returns an error (fail-open); the promotion
	// gate is LintHasErrors (P0-7 B5) — an error-severity lint on the
	// recomposed policy is a no-op-with-error, stricter than startup
	// (which only logs) because a live downgrade is worse than staying.
	if routing.LintHasErrors(issues) {
		return fmt.Errorf("routing.ReloadOrgPolicy: recomposed policy has lint errors (version %d); keeping running policy", composedOrgVersion)
	}

	// STRICT publish order (B4/§4.6): (1) the complete derived snapshot,
	// (2) the live decision policy, (3) the RoutingStateHandle LAST.
	if err := lr.refresher.ReloadPolicy(ctx, policy); err != nil {
		return fmt.Errorf("routing.ReloadOrgPolicy: refresher reload: %w", err)
	}
	lr.policy.Store(&policy)
	effMode := lr.effectiveMode()
	if lr.handle != nil {
		next := routingState{mode: effMode}
		if composedOrgVersion > 0 {
			next.version = composedOrgVersion
			next.hash = policy.Hash()
		}
		lr.handle.store(next)
	}
	lr.logger.Info("routing: team policy hot-reloaded",
		"version", composedOrgVersion, "hash", policy.Hash(), "mode", effMode)
	return nil
}

// Decide implements proxy.ModelRouter (§R9.2).
func (lr *liveRouter) Decide(shape proxy.RouterShape, sess proxy.RouterSession) proxy.RouterVerdict {
	snap := lr.refresher.Current()
	in := routing.DecisionInput{
		Shape: routing.TurnShape{
			Model:            shape.Model,
			MessageCount:     shape.MessageCount,
			ToolUseCount:     shape.ToolUseCount,
			SystemPromptHash: shape.SystemPromptHash,
			Stream:           shape.Stream,
			Speed:            shape.Speed,
			PromptTokens:     shape.PromptTokensEstimate,
		},
		Entitlement: sess.Entitlement,
	}
	if snap != nil {
		if act, ok := snap.Sessions[sess.SessionID]; ok {
			in.Session.RecentActions = act.RecentActions
			in.Session.ActionsLagged = act.ActionsLagged
			in.Session.ClientPhase = act.ClientPhase
			in.Session.IsSidechain = act.LastSidechain
			in.Session.SessionAgeTurns = act.TurnCount
			in.Project = act.Project
			in.ScopeKeys = act.ScopeKeys
			in.PathClassHits = act.PathClassHits
			in.PathClassHitsHash = act.PathClassHitsHash
		}
		in.Session.PriorCacheReadTokens = snap.SessionCacheRead[sess.SessionID]
	}

	// The escalation tracker is keyed by turn-kind, so classify here
	// (the same pure classifier the engine runs; both see identical
	// inputs, so the kinds agree).
	kind := routing.ClassifyTurnKind(in).Kind

	lr.mu.Lock()
	state := lr.sessionStateLocked(sess.SessionID)
	in.Session.TurnsSinceSwitch = state.turnsSinceSwitch
	// §R7.4 detection: a recent applied downshift of this kind + a
	// failure spike in the action window arms the cooldown.
	if armedAt, armed := state.lastDownshiftAt[kind]; armed &&
		lr.now().Sub(armedAt) <= escalationDetectWindow &&
		failureSpike(in.Session.RecentActions) {
		state.escalatedUntil[kind] = lr.now().Add(escalationCooldown)
		delete(state.lastDownshiftAt, kind)
		lr.logger.Info("routing: escalation armed - downshifted turn-kind failing",
			"session", sess.SessionID, "kind", string(kind))
	}
	if until, active := state.escalatedUntil[kind]; active {
		if lr.now().Before(until) {
			in.Session.EscalatedKinds = append(in.Session.EscalatedKinds, kind)
		} else {
			delete(state.escalatedUntil, kind)
		}
	}
	lr.mu.Unlock()

	d := routing.Decide(*lr.policy.Load(), snap, in)

	// Effort-only decisions (§R6.5) apply without a model change —
	// the lowest-risk enforce action (zero cache loss). effectiveMode folds
	// in the Arc 4 P3b managed-enforce lift (org mode on a managed node
	// holding enforce.routing); it equals lr.mode on every other node.
	effMode := lr.effectiveMode()
	apply := effMode == "enforce" && !d.AdviseOnly && (d.Changed || d.SetEffort != "")

	// Calibration demotion (§R18.3): a rule the calibration job graded
	// as regressing logs its decision but never acts.
	if apply && d.RuleName != "" {
		if m := lr.demoted.Load(); m != nil {
			if _, isDemoted := (*m)[d.RuleName]; isDemoted {
				apply = false
				d.ReasonCodes = append(d.ReasonCodes, routing.ReasonCalibrationDemoted)
			}
		}
	}

	lr.emitSelfObs(sess.SessionID, kind, d, apply)

	lr.mu.Lock()
	// Coherence counts MODEL switches only — an applied effort-only
	// decision leaves the session's model (and its cache) untouched.
	if apply && d.Changed {
		state.turnsSinceSwitch = 0
		// Arm the §R7.4 detector: this kind just downshifted.
		state.lastDownshiftAt[d.TurnKind] = lr.now()
	} else if state.turnsSinceSwitch >= 0 {
		state.turnsSinceSwitch++
	}
	lr.nextTok++
	token := lr.nextTok
	lr.pending[token] = pendingDecision{
		row:     decisionRow(d, effMode, sess.SessionID, apply, lr.now()),
		created: lr.now(),
	}
	lr.mu.Unlock()

	v := proxy.RouterVerdict{
		SelectedModel: d.SelectedModel,
		Token:         token,
	}
	if apply {
		v.Apply = true
		v.SetEffort = d.SetEffort
	}
	if effMode == "enforce" {
		// Fallback chains (§R12.1) are an enforce-class action — a
		// fallback rewrites the model. Advise mode returns no chain.
		v.FallbackModels = d.FallbackModels
	}
	return v
}

// RecordServed implements proxy.ModelRouter: called on the proxy's
// detached insert goroutine once the turn lands. Inserts the linked
// decision row plus any janitor-expired orphans. A served model
// differing from the decision's selection means the §R12.1 fallback
// chain fired after the decision — the row is annotated with
// availability_fallback and records what actually served.
func (lr *liveRouter) RecordServed(token, apiTurnID int64, servedModel string) {
	now := lr.now()
	lr.mu.Lock()
	rows := lr.collectExpiredLocked(now)
	if pend, ok := lr.pending[token]; ok {
		delete(lr.pending, token)
		if apiTurnID > 0 {
			pend.row.APITurnID = &apiTurnID
		}
		// What we EXPECTED to serve: the selection when applied, the
		// original otherwise (advise mode / holds). Response model ids
		// often carry a -YYYYMMDD suffix the request id lacks —
		// normalized before comparing so a dated echo never
		// false-fires a fallback annotation.
		expected := pend.row.OriginalModel
		if pend.row.Applied {
			expected = pend.row.SelectedModel
		}
		if servedModel != "" && !sameModelID(servedModel, expected) {
			pend.row.SelectedModel = servedModel
			pend.row.Applied = true
			pend.row.ReasonCodes = append(pend.row.ReasonCodes, string(routing.ReasonAvailabilityFallback))
		}
		rows = append(rows, pend.row)
	}
	lr.mu.Unlock()
	lr.insertRows(rows)
}

// sessionStateLocked returns (creating if needed) the session's
// coherence state and prunes the map past its cap.
func (lr *liveRouter) sessionStateLocked(sid string) *liveSessionState {
	st, ok := lr.sessions[sid]
	if !ok {
		if len(lr.sessions) >= liveSessionCap {
			cutoff := lr.now().Add(-time.Hour)
			for k, v := range lr.sessions {
				if v.lastSeen.Before(cutoff) {
					delete(lr.sessions, k)
				}
			}
		}
		st = &liveSessionState{
			turnsSinceSwitch: -1,
			lastDownshiftAt:  map[routing.TurnKind]time.Time{},
			escalatedUntil:   map[routing.TurnKind]time.Time{},
		}
		lr.sessions[sid] = st
	}
	st.lastSeen = lr.now()
	return st
}

// failureSpike reports a §R7.4 failure signal: at least
// escalationFailures failed actions among the window's last five.
func failureSpike(window []routing.ActionSignal) bool {
	start := len(window) - 5
	if start < 0 {
		start = 0
	}
	failures := 0
	for _, a := range window[start:] {
		if !a.Success {
			failures++
		}
	}
	return failures >= escalationFailures
}

// collectExpiredLocked drains pendings past the janitor age — their
// turns never landed; the decision row persists with a NULL turn id.
func (lr *liveRouter) collectExpiredLocked(now time.Time) []store.RouterDecisionRow {
	var out []store.RouterDecisionRow
	for tok, pend := range lr.pending {
		if now.Sub(pend.created) > pendingJanitorAge {
			out = append(out, pend.row)
			delete(lr.pending, tok)
		}
	}
	return out
}

func (lr *liveRouter) insertRows(rows []store.RouterDecisionRow) {
	if len(rows) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := lr.store.InsertRouterDecisions(ctx, rows); err != nil {
		lr.logger.Warn("routing: decision row insert failed", "err", err)
	}
}

// decisionRow converts a routing.Decision into the store seam's
// SQL-shaped row — the §24.2 boundary conversion (routing types never
// cross the store seam).
func decisionRow(d routing.Decision, mode, sessionID string, applied bool, ts time.Time) store.RouterDecisionRow {
	codes := make([]string, len(d.ReasonCodes))
	for i, rc := range d.ReasonCodes {
		codes[i] = string(rc)
	}
	return store.RouterDecisionRow{
		SessionID:       sessionID,
		Timestamp:       ts,
		Mode:            mode,
		Channel:         string(routing.ChannelProxy),
		OriginalModel:   d.OriginalModel,
		SelectedModel:   d.SelectedModel,
		TurnKind:        string(d.TurnKind),
		PolicyName:      d.PolicyName,
		PolicyHash:      d.PolicyHash,
		ReasonCodes:     codes,
		EstSavingsUSD:   d.EstSavingsUSD,
		CacheForfeitUSD: d.CacheForfeitUSD,
		EstimateVersion: d.EstimateVersion,
		Applied:         applied,
	}
}

// sameModelID compares model ids ignoring case and a trailing
// -YYYYMMDD date suffix (responses echo dated SKUs for undated
// request aliases).
func sameModelID(a, b string) bool {
	return normalizeModelID(a) == normalizeModelID(b)
}

func normalizeModelID(m string) string {
	m = strings.ToLower(m)
	if len(m) > 9 && m[len(m)-9] == '-' {
		allDigits := true
		for _, c := range m[len(m)-8:] {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return m[:len(m)-9]
		}
	}
	return m
}
