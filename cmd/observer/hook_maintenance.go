package main

import (
	"context"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// hook_maintenance.go - T-849 (node part) and the T-847 hook inputs of the
// managed-integrity probe.
//
// Before T-849 a removed or weakened hook was re-added only when the daemon
// happened to restart (`observer start` auto-registration; the 2026-10-15
// tamper audit saw an unattended-upgrade restart heal tamper c1 by accident),
// and the integrity report rode only the 900 s push. The maintenance loop
// below rides the policy-state heartbeat (about 5 minutes): it re-runs the
// SAME idempotent auto-registration (autoRegisterHooks, so the same writers,
// component gates and live gate) and then reports the managed-integrity
// probe, so a repair is both made and reported within one heartbeat.

// hookRepairTracker is the daemon-lifetime repair memory every
// auto-registration pass in this process shares (start, the post-install
// pass and the maintenance loop), so a hook removed after any of them is
// recognised as a repair, even when hook_checksums.json was deleted too.
var hookRepairTracker = &hook.RepairTracker{}

// periodicRegisterWanted is the [observer.hooks] periodic-registration
// decision, as a table: auto_register=false always wins (the developer's
// consent switch is respected); otherwise periodic_register decides, and the
// default ("managed") re-registers on a managed node only, so an individual
// node keeps the start-only behaviour it has always had.
func periodicRegisterWanted(mode string, autoRegister, managed bool) bool {
	if !autoRegister {
		return false
	}
	rows := map[string]func(managed bool) bool{
		config.HooksPeriodicRegisterAlways:  func(bool) bool { return true },
		config.HooksPeriodicRegisterOff:     func(bool) bool { return false },
		config.HooksPeriodicRegisterManaged: func(m bool) bool { return m },
	}
	decide, ok := rows[mode]
	if !ok {
		decide = rows[config.HooksPeriodicRegisterManaged]
	}
	return decide(managed)
}

// hookMaintenance is one heartbeat-driven loop: every interval it re-runs
// auto-registration when periodicRegisterWanted says so, then reports the
// managed-integrity probe on a managed node. Every dependency is injected so
// the loop is testable without a daemon.
type hookMaintenance struct {
	interval     time.Duration
	mode         string
	autoRegister bool
	managed      func(ctx context.Context) bool
	// reregister runs one auto-registration pass. managed is true on a
	// managed node, where the pass also repairs a neutralised artifact
	// Observer owns by name (T-872, hook.Options.RepairOwnedArtifacts).
	reregister func(managed bool)
	report     func(ctx context.Context)
	// routes is the lane P1 route maintenance step (route_maintenance.go):
	// on a managed node whose org needs the proxy it writes or repairs the
	// routable tools' proxy routes, and reports whether it wrote one. Nil on
	// a node without an org client, so an individual node never runs it.
	routes routeMaintenanceStep
	// waitProxy blocks until the proxy listener accepts (bounded by the
	// caller), so the start pass never writes toward a port that is not
	// bound yet. Nil skips the wait (the pass still probes health).
	waitProxy func(ctx context.Context)
}

// tick runs one maintenance step. Route maintenance runs after the hook
// pass and before the report, so a repair is made and reported in the same
// heartbeat, exactly like a hook repair.
func (m hookMaintenance) tick(ctx context.Context) {
	managed := m.managed != nil && m.managed(ctx)
	if m.reregister != nil && periodicRegisterWanted(m.mode, m.autoRegister, managed) {
		m.reregister(managed)
	}
	if m.routes != nil {
		m.routes(ctx, managed)
	}
	if managed && m.report != nil {
		m.report(ctx)
	}
}

// startRoutes is the managed START pass of route maintenance: hooks are
// registered before the proxy listens, so routes wait for the listener and
// run once as soon as it serves, then report at once when a route was
// written (instead of leaving the drift open until the first heartbeat).
func (m hookMaintenance) startRoutes(ctx context.Context) {
	if m.routes == nil {
		return
	}
	if m.waitProxy != nil {
		m.waitProxy(ctx)
	}
	if ctx.Err() != nil {
		return
	}
	managed := m.managed != nil && m.managed(ctx)
	if m.routes(ctx, managed) && managed && m.report != nil {
		m.report(ctx)
	}
}

// run runs the start route pass, then ticks every interval until ctx is
// done. The first tick waits one interval: `observer start` has just
// registered and the push loop reports at its first cycle.
func (m hookMaintenance) run(ctx context.Context) {
	m.startRoutes(ctx)
	interval := m.interval
	if interval <= 0 {
		interval = time.Duration(config.DefaultPolicyStateHeartbeatSeconds) * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

// newHookMaintenance assembles the loop for this daemon. orgManaged and
// report are nil on a node without an org client (it is never managed then).
func newHookMaintenance(cfg config.Config, cfgOK bool, configPath string, stdout, stderr io.Writer,
	orgManaged func(context.Context) bool, report func(context.Context),
) hookMaintenance {
	m := hookMaintenance{
		interval:     time.Duration(config.DefaultPolicyStateHeartbeatSeconds) * time.Second,
		mode:         config.HooksPeriodicRegisterManaged,
		autoRegister: true,
		managed:      orgManaged,
		report:       report,
	}
	promptLane := true
	if cfgOK {
		m.interval = policyStateHeartbeat(cfg)
		m.mode = cfg.Observer.Hooks.PeriodicRegister
		m.autoRegister = cfg.Observer.Hooks.AutoRegister
		promptLane = cfg.Guard.Prompt.Enabled && cfg.Guard.Prompt.HookLane
	}
	m.reregister = func(managed bool) { autoRegisterHooksPass(stdout, stderr, configPath, promptLane, managed) }
	return m
}

// probeExpectedHooks lists the hook targets this node's own auto-registration
// owns, each with a DRY RUN of that registration (hook.Registry.Probe): the
// file it owns and the events a real registration would add or rewrite. It is
// the T-847 input that makes a missing or weakened hook visible even when
// hook_checksums.json was deleted or re-baselined. It walks the same
// detection and per-target decision as autoRegisterHooks, so it dispatches on
// the registry's hook capability, never on a tool name.
func probeExpectedHooks(configPath string, promptLaneEnabled bool) []diag.ExpectedHook {
	comps := componentSnapshotFor(configPath)
	if !comps.Active("integration.hooks") {
		return nil
	}
	opts, err := autoRegisterOptions(configPath)
	if err != nil {
		return nil
	}
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		return nil
	}
	var out []diag.ExpectedHook
	for _, tool := range reg.Installed() {
		if !comps.AdapterActive(tool) || !autoRegisterDecision(tool, promptLaneEnabled) {
			continue
		}
		res := reg.Probe(tool)
		if res.Skipped || res.ConfigPath == "" {
			continue
		}
		e := diag.ExpectedHook{Tool: res.Tool, ConfigPath: res.ConfigPath}
		if res.Error == nil {
			e.Drift = hook.DriftEvents(res)
		}
		out = append(out, e)
	}
	return out
}
