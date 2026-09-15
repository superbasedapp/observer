package main

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
	toolhost "github.com/marmutapp/superbased-observer/internal/toolresolve/host"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

const (
	// nodeInterventionInterval is the control cadence while this node holds
	// managed budget-enforcement authority. Governed processes must be seen
	// promptly, so this stays short.
	nodeInterventionInterval = 2 * time.Second
	// nodeInterventionIdleInterval is the cadence when the node holds no such
	// authority. `observer start` runs this loop on every node, enrolled or
	// not; a /proc walk and an atomic status write every two seconds forever is
	// unjustified cost for a node that can never stop anything
	// (accounting-readiness correction, 2026-09-14). An authority READ error
	// keeps the fast cadence: an unverified managed node must not be governed
	// more slowly because of a transient failure.
	nodeInterventionIdleInterval = 30 * time.Second
	// nodeInterventionStatusRefresh bounds how long an unchanged report may go
	// unwritten. It stays well inside readNodeInterventionStatus's freshness
	// bound for the fast cadence, so skipping identical writes can never make a
	// live controller look stale.
	nodeInterventionStatusRefresh = 10 * time.Second
)

// runNodeIntervention is the mandatory enrolled-node process controller. The
// optional observation toggle does not gate it. Normal individual nodes do
// only the enrollment read; verified managed budget authority enables target
// discovery and the shared supervisor. A backend failure is reported as
// unavailable and cannot be described as physical denial.
func runNodeIntervention(ctx context.Context, configPath string, capture *watcher.Watcher) error {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	st := store.New(database)
	logger := newLogger(cfg.Observer.LogLevel)
	controller, probeErr := intervention.Inspect(ctx, os.Getpid())
	var controlProbeAt time.Time
	var controlProbeErr error
	opts := nodeInterventionScanOptions(os.Getuid(), os.Getpid())
	var manifest intervention.InstallManifest
	var manifestAt time.Time
	var stopped int
	lastState := ""
	var writer nodeInterventionStatusWriter
	report := func(status nodeInterventionStatus) {
		status.At = time.Now().UTC()
		status.Controller = controller
		status.StoppedProcesses = stopped
		if err := writer.write(ctx, cfg.Observer.DBPath, status); err != nil && ctx.Err() == nil {
			logger.Warn("node intervention: status report unavailable")
		}
		key := status.State + "/" + status.Reason
		if key != lastState {
			logger.Info("node intervention: controller status", "state", status.State, "reason", status.Reason,
				"process_cutoff", status.ProcessCutoff, "execution_admission", status.ExecutionAdmission,
				"request_admission", status.RequestAdmission)
			lastState = key
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if probeErr != nil {
			controller, probeErr = intervention.Inspect(ctx, os.Getpid())
		}
		status := nodeInterventionStatus{State: "pending_control", ProcessCutoff: "unavailable", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable"}
		auth, err := nodeInterventionAuthority(ctx, st, opts.TargetUID, time.Now().UTC())
		switch {
		case err != nil:
			status.State, status.Reason = "control_unavailable", "managed authority could not be verified"
		case !auth.Authorized:
			status.State, status.Reason = "not_required", "no managed budget intervention authority"
		case probeErr != nil || opts.TargetUID <= 0:
			// The full parser/dashboard daemon must not acquire root privileges
			// to implement this capability. A dedicated privileged backend needs
			// a separate narrow contract on platforms that require it.
			status.State, status.Reason = "control_unavailable", "dedicated developer-user Linux controller required"
		default:
			if controlProbeAt.IsZero() || time.Since(controlProbeAt) >= time.Minute {
				controlProbeErr = probeNodeControl(ctx)
				controlProbeAt = time.Now()
			}
			if controlProbeErr != nil {
				status.State, status.Reason = "control_unavailable", "owned-child process-control self-test failed"
				break
			}
			if manifestAt.IsZero() || time.Since(manifestAt) >= 30*time.Second {
				var next intervention.InstallManifest
				next, err = intervention.RefreshInstallManifest(ctx, manifest, nodeInterventionCandidates(), opts)
				if err == nil {
					manifest = next
					manifestAt = time.Now()
				}
			}
			if err != nil {
				status.State, status.Reason = "control_unavailable", "installed adapter identity inventory failed"
				break
			}
			var outcomes []intervention.Outcome
			status, outcomes, err = reconcileNodeIntervention(ctx, st, cfg, lookupProcessGuard(cfg.Observer.DBPath), capture, manifest, opts)
			if err != nil {
				status.State, status.Reason = "control_unavailable", "process inventory failed"
			}
			if auditErr := recordNodeInterventionOutcomes(ctx, st, outcomes); auditErr != nil {
				status.ProcessCutoff = "degraded"
				status.Reason = "durable process-control audit unavailable"
				logger.Warn("node intervention: durable process-control audit unavailable")
			}
			for _, outcome := range outcomes {
				if outcome.Status == "allowed" || outcome.Status == "not_authorized" {
					continue
				}
				logger.Warn("node intervention: policy process outcome", "surface", outcome.Workload.SurfaceID,
					"pid", outcome.Workload.Identity.PID, "start_ticks", outcome.Workload.Identity.StartTicks,
					"boot_id", outcome.Workload.Identity.BootID, "rule_id", outcome.RuleID,
					"reason", outcome.Reason, "outcome", outcome.Status, "exit_observed", outcome.Stopped)
				if outcome.Stopped {
					stopped++
				}
			}
		}
		status.Authority = auth.Authority
		report(status)
		// Rest after each completed cycle. A slow source scan must not turn
		// an already-buffered ticker into continuous historical ingestion.
		delay := time.NewTimer(nodeInterventionCadence(auth.Authorized, err))
		select {
		case <-ctx.Done():
			delay.Stop()
			return nil
		case <-delay.C:
		}
	}
}

// nodeInterventionCadence is the rest between control cycles. A node that
// holds managed budget-enforcement authority - or whose authority could not be
// verified this cycle - keeps the fast cadence; a node that can never stop
// anything backs off.
func nodeInterventionCadence(authorized bool, authorityErr error) time.Duration {
	if authorityErr == nil && !authorized {
		return nodeInterventionIdleInterval
	}
	return nodeInterventionInterval
}

// nodeInterventionCandidates reuses the existing install resolver without
// executing login shells, npm, or vendor launchers. All discovered native
// path candidates are retained so a second installed version is not hidden by
// PATH precedence. The manifest builder performs the actual identity checks.
func nodeInterventionCandidates() []intervention.InstalledCandidate {
	env := toolhost.NewEnv(toolhost.Options{})
	env.LoginPath, env.NpmPrefix = nil, nil
	var interpreters []intervention.InstalledInterpreter
	for _, item := range []struct {
		kind  integration.InterpreterKind
		names []string
	}{
		{integration.InterpreterNode, []string{"node"}},
		{integration.InterpreterBun, []string{"bun"}},
		{integration.InterpreterPython, []string{"python3", "python"}},
	} {
		for _, name := range item.names {
			if path, err := exec.LookPath(name); err == nil {
				interpreters = append(interpreters, intervention.InstalledInterpreter{Kind: item.kind, Path: path})
			}
		}
	}
	var out []intervention.InstalledCandidate
	for _, surface := range integration.AllInterventionSurfaces() {
		if surface.Class != integration.SurfaceDedicatedProcess || surface.Binary == nil {
			continue
		}
		resolution := toolresolve.Resolve(*surface.Binary, env)
		seen := make(map[string]bool)
		for _, candidate := range resolution.Considered {
			if candidate.Foreign || seen[candidate.Path] {
				continue
			}
			seen[candidate.Path] = true
			out = append(out, intervention.InstalledCandidate{Tool: surface.Tool, SurfaceID: surface.ID, LauncherPath: candidate.Path, Interpreters: interpreters})
		}
	}
	return out
}

func nodeInterventionUnavailableSurfaces(manifest intervention.InstallManifest) []string {
	var out []string
	for _, surface := range manifest.Surfaces {
		if surface.State != intervention.BindingNotInstalled && (surface.State != intervention.BindingReady || !surface.Spec.NativeUsage.Available()) {
			out = append(out, surface.Spec.ID)
		}
	}
	sort.Strings(out)
	return out
}

func nodeInterventionControlledSurfaces(manifest intervention.InstallManifest) []string {
	var out []string
	for _, surface := range manifest.Surfaces {
		if surface.State != intervention.BindingReady || !surface.Spec.NativeUsage.Available() {
			continue
		}
		for _, target := range surface.Targets {
			if target.BoundProcess == nil {
				out = append(out, surface.Spec.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
