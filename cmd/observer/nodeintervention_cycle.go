package main

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// nodeInterventionSource is one workload's OWN accounting-source evidence.
// The tool travels with it so the guard can scope an unpriced-usage denial to
// the tool that produced the unpriceable rows, and so a denial reason can name
// the source that could not be established.
//
// RULING 2026-09-15. A running process is stopped only on a MEASURED crossing
// of its cap, or on a STRUCTURALLY unavailable accounting source. A delayed
// tail never stops a process: the strict capture pass reads the very files the
// governed tool is writing, so it routinely defers, races or errors on the
// newest bytes, and the store's measured total (fed by the ordinary watcher
// and every earlier strict pass) already stands. Under-reading the tail by
// seconds of spend can only delay a stop, never manufacture one.
type nodeInterventionSource struct {
	// Tool is the adapter name of the governed process.
	Tool string
	// Ready is true unless this tool's accounting source is structurally
	// unavailable. It is therefore true for a tool that has honestly captured
	// nothing yet, and true for a tool whose newest tail is merely late.
	Ready bool
	// Delayed is true when the strict tail catch-up did not complete for this
	// cycle while the source itself stayed intact. It is honesty context - the
	// decision was taken on the measured total - and never denies.
	Delayed bool
	// Reason is the stable machine-readable reason behind Ready. It is
	// operator-facing context, never an admission rule.
	Reason string
}

// nodeInterventionSourceResolve resolves one workload's accounting class AND
// the operator-facing reason behind it from the cycle's inputs, top-down. One
// ordered table answers both, so the reason can never name a different
// precondition from the one the class was taken from (CLAUDE.md #5).
//
//   - No native usage for the surface is STRUCTURAL: nothing on this node can
//     read that surface's spend, so it fails closed.
//   - A source whose OWN recorded reason is structural stays structural. This
//     test precedes the staleness test on purpose: a capture result going
//     stale must never launder a recorded "this node cannot read that tool" -
//     the adapter is still unknown, still allow-filtered, still unreadable.
//   - A missing or implausibly old capture result is DELAYED, not unknown: the
//     strict pass is a tail accelerator, so a stale strict result is a stale
//     TAIL. The measured total in the store is unaffected by it.
//   - Otherwise the source's own class decides (known / delayed / unavailable).
func nodeInterventionSourceResolve(sane, nativeUsage bool, source watcher.BudgetCaptureStatus) (watcher.BudgetAccountingClass, string) {
	switch {
	case !nativeUsage:
		return watcher.BudgetAccountingUnavailable, "native_usage_unavailable"
	case source.Reason != "" && source.AccountingClass() == watcher.BudgetAccountingUnavailable:
		return watcher.BudgetAccountingUnavailable, source.AccountingReason()
	case !sane:
		return watcher.BudgetAccountingDelayed, "capture_result_unavailable"
	default:
		return source.AccountingClass(), source.AccountingReason()
	}
}

// nodeInterventionResolveSource resolves one workload's source into the shape
// the budget decision and the status report both consume.
func nodeInterventionResolveSource(tool string, sane, nativeUsage bool, source watcher.BudgetCaptureStatus) nodeInterventionSource {
	class, reason := nodeInterventionSourceResolve(sane, nativeUsage, source)
	return nodeInterventionSource{
		Tool:    tool,
		Ready:   class != watcher.BudgetAccountingUnavailable,
		Delayed: class == watcher.BudgetAccountingDelayed,
		Reason:  reason,
	}
}

// nodeInterventionCaptureMaxAge is a sanity bound, not a freshness rule. One
// capture result serves every decision of the cycle that produced it, and the
// cycle re-runs every two seconds, so the loop already bounds staleness.
// Earlier workloads in a pass can consume their whole TERM/KILL deadline; the
// five-second fence this replaced therefore turned every later workload of the
// same cycle into an "accounting unavailable" stop (accounting-readiness
// correction, 2026-09-14). The bound only rejects a result from a
// pathologically long pass, or a clock that moved backwards.
const nodeInterventionCaptureMaxAge = time.Minute

// nodeInterventionCaptureUsable reports whether a capture result taken at
// capturedAt may still decide a workload at now. A zero capture time means no
// pass ran, which is never usable.
func nodeInterventionCaptureUsable(capturedAt, now time.Time) bool {
	if capturedAt.IsZero() {
		return false
	}
	age := now.Sub(capturedAt)
	return age >= 0 && age <= nodeInterventionCaptureMaxAge
}

// nodeInterventionSessionIDLookupTimeout bounds the per-workload
// session_pid_bridge read below a busy reconcile cycle's own deadlines; it
// is a single indexed lookup by primary key, so this is a generous ceiling,
// not an expected duration.
const nodeInterventionSessionIDLookupTimeout = 2 * time.Second

// nodeInterventionWorkloadSessionID resolves the real session a matched
// process belongs to, so process-control audit rows and any session-scoped
// managed budget cap (internal/guard/interventionbudget.go's SessionID
// attribution path) can be joined back to the session that was stopped
// (P1-7). It reuses the SAME direct pid->session bridge
// (internal/store.LookupSessionPID over session_pid_bridge, migration 004,
// pid-reuse-fenced per P2-2) the SessionStart hook and the
// SessionProcessSeeds watcher-path ingest already populate for exactly this
// purpose — never a fabricated or best-guess id. A pid with no bridge row
// (an adapter that doesn't seed the bridge, a session that predates it, or
// a reused pid the fence refused) yields "" SILENTLY — that is the same
// honest "no session known" the rest of this path already treats as
// absent, never as a fabricated empty-session zero, and it is the
// overwhelmingly common case on an unmanaged/unbridged tool, so it is not
// warn-worthy. An actual lookup ERROR (a broken store, a bad query) is
// different — that is unexpected and worth a node operator's attention —
// so it is logged at WARN (still returning "": a broken session lookup
// must never fail process control itself).
func nodeInterventionWorkloadSessionID(ctx context.Context, st *store.Store, pid int, tool string) string {
	if st == nil || pid <= 0 || tool == "" {
		return ""
	}
	lookupCtx, cancel := context.WithTimeout(ctx, nodeInterventionSessionIDLookupTimeout)
	defer cancel()
	sessionID, ok, err := st.LookupSessionPID(lookupCtx, pid, tool)
	if err != nil {
		slog.Warn("node intervention: session_pid_bridge lookup failed", "tool", tool)
		return ""
	}
	if !ok {
		return ""
	}
	return sessionID
}

// reconcileNodeIntervention is the daemon's native-control cycle. The manifest
// is explicit so tests can use isolated executables and never discover or
// signal actual developer tools. The production caller supplies only the
// registry-derived installed manifest.
func reconcileNodeIntervention(ctx context.Context, st *store.Store, cfg config.Config, gd *guard.Guard, capture *watcher.Watcher, manifest intervention.InstallManifest, opts intervention.ScanOptions) (nodeInterventionStatus, []intervention.Outcome, error) {
	status := nodeInterventionStatus{
		State: "pending_control", ProcessCutoff: "unavailable", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable",
		ManifestFingerprint: intervention.InstallManifestFingerprint(manifest),
		ControlledSurfaces:  nodeInterventionControlledSurfaces(manifest),
		UnavailableSurfaces: nodeInterventionUnavailableSurfaces(manifest),
	}
	scan, err := intervention.ScanInstalledProcesses(ctx, manifest, opts)
	if err != nil {
		return status, nil, err
	}
	workloads := make([]intervention.Workload, 0, len(scan.Matches))
	toolsBySurface := make(map[string]string, len(scan.Matches))
	usageBySurface := make(map[string]bool, len(manifest.Surfaces))
	for _, surface := range manifest.Surfaces {
		usageBySurface[surface.Spec.ID] = surface.Spec.NativeUsage.Available()
	}
	toolSet := make(map[string]bool, len(scan.Matches))
	// A tool's native usage is available when ANY of its bound surfaces has
	// it. The per-SURFACE flag still decides each workload below; this
	// per-tool fold exists because the status report is keyed by tool.
	nativeByTool := make(map[string]bool, len(scan.Matches))
	for _, match := range scan.Matches {
		sessionID := nodeInterventionWorkloadSessionID(ctx, st, match.Identity.PID, match.Tool)
		workloads = append(workloads, intervention.Workload{SurfaceID: match.SurfaceID, SessionID: sessionID, Identity: match.Identity})
		toolsBySurface[match.SurfaceID] = match.Tool
		toolSet[match.Tool] = true
		nativeByTool[match.Tool] = nativeByTool[match.Tool] || usageBySurface[match.SurfaceID]
	}
	var activeTools []string
	for tool := range toolSet {
		activeTools = append(activeTools, tool)
	}
	sort.Strings(activeTools)
	status.BoundProcesses = len(workloads)
	// A surface that could not classify an observed invocation degrades ITS OWN
	// coverage only; the node's process cutoff stays whatever the rest of the
	// reconciliation earned.
	status.UnclassifiedSurfaces = append([]string(nil), scan.UnclassifiedSurfaces...)
	// Catch up the existing native parser/store path before reading the
	// budget. Source health and USD pricing availability are independent.
	var captureStatus watcher.NodeBudgetCaptureStatus
	var capturedAt time.Time
	// An explicit no-cap/soft-only policy needs no strict historical catchup.
	// The shared guard decides whether accounting is required; an unavailable
	// guard already fails closed without consulting native usage below.
	needsCapture := gd != nil && gd.CheckInterventionBudget(guard.InterventionBudgetInput{Now: time.Now().UTC()}).Required
	if capture != nil && len(activeTools) > 0 && needsCapture {
		captureCtx, captureCancel := context.WithTimeout(ctx, 20*time.Second)
		captureStatus = capture.ReconcileNodeBudgetCapture(captureCtx, activeTools)
		capturedAt = time.Now()
		captureCancel()
	}
	// The report must answer the question the DECISION answered, not the one
	// the watcher answered: a source the cycle could not use (no native usage,
	// no usable capture result) is reported the way it was decided, through
	// the same resolve function.
	reportSane := nodeInterventionCaptureUsable(capturedAt, time.Now())
	resolved := make(map[string]nodeInterventionSource, len(activeTools))
	for _, tool := range activeTools {
		resolved[tool] = nodeInterventionResolveSource(tool, reportSane, nativeByTool[tool], captureStatus.Sources[tool])
	}
	status.Capture = nodeInterventionCaptureReport(activeTools, resolved, captureStatus)
	supervisor := intervention.Supervisor{Fence: nodeInterventionSignalFence(st, gd), Revalidate: func(actionCtx context.Context, w intervention.Workload) error {
		_, err := intervention.RevalidateBinding(actionCtx, manifest, w.Identity, w.SurfaceID, opts)
		return err
	}, Decide: func(actionCtx context.Context, w intervention.Workload) (intervention.PolicyDecision, error) {
		if _, err := intervention.RevalidateBinding(actionCtx, manifest, w.Identity, w.SurfaceID, opts); err != nil {
			return intervention.PolicyDecision{}, err
		}
		now := time.Now()
		tool := toolsBySurface[w.SurfaceID]
		source := captureStatus.Sources[tool]
		sane := nodeInterventionCaptureUsable(capturedAt, now)
		// A workload is decided on ITS OWN tool's source only, and on its OWN
		// surface's native-usage capability. A STRUCTURALLY broken source for
		// tool A stops A's processes and leaves tool B's running; a merely
		// delayed tail for either stops neither, because the measured total
		// already in the store is what the cap is tested against (ruling
		// 2026-09-15).
		return nodeInterventionBudget(actionCtx, st, cfg, gd, w,
			nodeInterventionResolveSource(tool, sane, usageBySurface[w.SurfaceID], source), now.UTC())
	}}
	outcomes := supervisor.Reconcile(ctx, workloads)
	status.State, status.ProcessCutoff = "partial", "active"
	status.Reason = "verified installed processes only; native usage is delayed; shared hosts and descendants remain uncovered"
	hasTargets := false
	for _, surface := range manifest.Surfaces {
		hasTargets = hasTargets || len(surface.Targets) > 0
	}
	if !hasTargets {
		status.State, status.ProcessCutoff = "control_unavailable", "unavailable"
		status.Reason = "no installed adapter entrypoint could be bound for process control"
	}
	if !scan.Complete {
		status.ProcessCutoff = "degraded"
		status.Reason = "process inventory incomplete; unverified processes remain uncovered"
	}
	if gd == nil && len(workloads) > 0 {
		// Fail-closed is correct here, but "verified installed processes only"
		// would describe a budget decision that never happened. Name the actual
		// cause, in the report the operator reads and in the audit reason.
		status.Reason = nodeInterventionGuardUnavailableReason
	}
	for _, outcome := range outcomes {
		if outcome.Stopped {
			status.StoppedProcesses++
		}
		if outcome.Status != "allowed" && outcome.Status != "not_authorized" && !outcome.Stopped && !outcome.AlreadyExited {
			status.ProcessCutoff = "degraded"
		}
	}
	return status, outcomes, nil
}
