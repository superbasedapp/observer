//go:build !sbo_omit_integration_shell_wrap

// shellwrap_maintenance.go: managed command wrapping (surface-gap arc
// finding CLI-1b, operator decision D6, 2026-10-25). On a managed node whose
// organization pinned shell_wrap.org_maintain, the daemon's maintenance
// heartbeat keeps the native target's wrap applied (ON) or removes the wrap
// the organization applied (OFF), through the one applier
// (internal/shellwrapsvc). An individual node never runs it: the step is
// built only with an org client and is inert unless the node is managed.

package main

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
)

// shellWrapStatus reads the native target's state through the applier (a
// seam for tests).
var shellWrapStatus = func(ctx context.Context, configPath string) (shellwrap.Status, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return shellwrap.Status{}, err
	}
	return newShellWrapService(resolved, resolveEnv).Status(ctx)
}

// shellWrapApplied reports whether the organization's wrap holds: recorded,
// on disk, in sync with the recorded choice, and that choice covers the
// organization's selection (shellwrapsvc.OrgSelectionCovered), so a
// narrower choice made before the pin is re-applied and reported missing.
func shellWrapApplied(st shellwrap.Status) bool {
	return st.Enabled && st.Active && st.InSync && shellwrapsvc.OrgSelectionCovered(st)
}

// newShellWrapMaintenance builds the step. posture is the live org posture
// (govern.Effective.ShellWrapPosture through the governance handle). The
// step returns true when it wrote, so the caller reports the
// managed-integrity probe at once.
func newShellWrapMaintenance(configPath string, posture func(context.Context) govern.ShellWrapPostureVerdict, stdout, stderr io.Writer) routeMaintenanceStep {
	var mu sync.Mutex
	lastErr := ""
	report := func(err error) {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != lastErr && msg != "" {
			fmt.Fprintf(stderr, "WARN shell-wrap maintenance: %s (the organization keeps command wrapping on for this machine; `observer shell-wrap status` shows what is applied)\n", msg)
		}
		lastErr = msg
	}
	return func(ctx context.Context, managed bool) bool {
		if !managed || ctx.Err() != nil || posture == nil {
			return false
		}
		verdict := posture(ctx)
		if verdict.Posture != govern.ShellWrapPostureMaintain && verdict.Posture != govern.ShellWrapPostureRelease {
			return false
		}
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		svc := newShellWrapService(resolved, resolveEnv)
		if verdict.Posture == govern.ShellWrapPostureRelease {
			out, released, err := svc.ReleaseOrganization(ctx)
			report(err)
			if released {
				fmt.Fprintf(stdout, "shell-wrap: your organization turned managed command wrapping off; removed the wrap it applied (%d file(s))\n", len(out.Changes))
			}
			return released
		}
		st, err := svc.Status(ctx)
		if err != nil {
			report(err)
			return false
		}
		if shellWrapApplied(st) {
			report(nil)
			return false
		}
		out, err := svc.Apply(ctx, shellwrapsvc.Request{Tools: []string{shellwrap.AllTools}, ByOrganization: true})
		report(err)
		if err != nil {
			return false
		}
		written := 0
		for _, c := range out.Changes {
			if c.Action != shellwrapsvc.ActionUnchanged {
				written++
			}
		}
		if written > 0 {
			fmt.Fprintf(stdout, "shell-wrap: your organization keeps command wrapping on for this machine; applied it (%d file(s))\n", written)
		}
		return written > 0
	}
}

// withShellWrapMaintenance runs the route step, then the shell-wrap step, on
// the same heartbeat; it reports a write when either wrote. A nil step is
// skipped.
func withShellWrapMaintenance(routes, wrap routeMaintenanceStep) routeMaintenanceStep {
	if wrap == nil {
		return routes
	}
	return func(ctx context.Context, managed bool) bool {
		wrote := false
		if routes != nil {
			wrote = routes(ctx, managed)
		}
		return wrap(ctx, managed) || wrote
	}
}

// addShellWrapPosture adds the shell_wrap_missing capture risk (CLI-1b) when
// the organization keeps command wrapping on for this node and the wrap is
// not applied, or its state cannot be read (never read as clean).
func addShellWrapPosture(ctx context.Context, v govern.ShellWrapPostureVerdict, configPath string, report *orgcontract.ManagedIntegrityReport) {
	if v.Posture != govern.ShellWrapPostureMaintain {
		return
	}
	st, err := shellWrapStatus(ctx, configPath)
	if err == nil && shellWrapApplied(st) {
		return
	}
	report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskShellWrapMissing)
}

// shellWrapOrgMaintained resolves, for the developer-facing applier (the CLI
// and the dashboard), whether this node's organization maintains the native
// wrap. It reads the config first and opens the database only on a node
// whose verified org lock records managed tenancy, so an individual node
// (and every test home) never opens one. Any read failure answers false: a
// developer is never locked into a wrap by an unreadable posture.
func shellWrapOrgMaintained(configPath string) func() bool {
	return func() bool {
		eff, ok := governanceEffectiveIfManaged(context.Background(), configPath)
		return ok && eff.ShellWrapPosture().Posture == govern.ShellWrapPostureMaintain
	}
}
