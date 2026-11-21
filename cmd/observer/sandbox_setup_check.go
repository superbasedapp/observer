//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// sandbox_setup_check.go is the ACTIVE check of sandbox setup (plan section
// 3.4, ruling R1): only on the person's click ("Check this machine", or
// `observer sandbox setup check`), the row's driver is built ephemerally over
// a config copy in which the row is listed, its component selected and the
// sandbox on; its probe runs once under a bounded context; `--version` runs
// on each resolved program; then the driver is dropped. Nothing is cached
// beyond the response and nothing runs on a timer. The click on one named
// row is the opt-in for one probe of that row (an explicit amendment of
// sandbox plan v2 section 10.1, ledger SBXSETUP-3).

// The active check's bounds.
const (
	// sandboxSetupProbeTimeout bounds the one driver probe.
	sandboxSetupProbeTimeout = 30 * time.Second
	// sandboxSetupVersionTimeout bounds one `<program> --version`.
	sandboxSetupVersionTimeout = 3 * time.Second
)

// sandboxSetupCheckConfig is cfg with row listed, its component selected and
// the sandbox enabled: the copy the ephemeral driver is built over. cfg is
// not changed (its slices are copied).
func sandboxSetupCheckConfig(cfg config.Config, backend, component string) config.Config {
	out := cfg
	sb := cfg.Terminal.Sandbox
	sb.Enabled = true
	sb.PinnedNoBackend = ""
	listed := sandboxSetupListed(cfg.Terminal.Sandbox)
	if !slices.Contains(listed, backend) {
		listed = append(listed, backend)
	}
	sb.Backends = listed
	out.Terminal.Sandbox = sb
	if component != "" {
		comps := cfg.Components
		comps.Add = append([]string(nil), comps.Add...)
		if !slices.Contains(comps.Add, component) {
			comps.Add = append(comps.Add, component)
		}
		var keep []string
		for _, r := range comps.Remove {
			// The component and every module above it must not be removed.
			if r != component && !strings.HasPrefix(component, r+".") {
				keep = append(keep, r)
			}
		}
		comps.Remove = keep
		out.Components = comps
	}
	return out
}

// sandboxSetupProbeRow builds backend's driver ephemerally over the check
// config and runs its probe once. bwrap, which has no driver registration,
// runs the shipped bwrap probe (sandbox.Probe over the runtime's own env).
// ok is false when the row has no probe in this build.
func sandboxSetupProbeRow(ctx context.Context, backend string, cfg config.Config) (sandboxselect.Probe, bool) {
	comp, inBuild := sandboxSetupComponentFor(backend)
	if !inBuild {
		return sandboxselect.Probe{}, false
	}
	full := sandboxSetupCheckConfig(cfg, backend, comp)
	obs := filepath.Dir(full.Observer.DBPath)
	bin, _ := os.Executable()
	ctx, cancel := context.WithTimeout(ctx, sandboxSetupProbeTimeout)
	defer cancel()
	rt, err := newComposedSandboxRuntime(full, full.Terminal.Sandbox, false, obs, bin, slog.Default())
	if err != nil {
		return sandboxselect.Probe{Compiled: true, Verdict: "probe_failed", Reason: err.Error()}, true
	}
	if backend == sandboxbackend.BackendBwrap {
		av := sandbox.Probe(rt.sandboxEnv(ctx))
		return sandboxselect.Probe{Compiled: true, Verdict: av.Verdict, Reason: av.Reason, Version: av.BackendVersion}, true
	}
	d, ok := rt.drivers[backend]
	if !ok {
		return sandboxselect.Probe{Compiled: true, Verdict: verdictModuleInactive, Reason: "the " + comp + " component could not be selected for the check"}, true
	}
	// The driver is local to this call: it is dropped when rt goes out of
	// scope, and nothing it probed is kept.
	return d.probe(ctx), true
}

// sandboxSetupRunVersion runs `<path> --version` under a short timeout and
// returns the first line of its output (the runtime_preflight.go pattern).
func sandboxSetupRunVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sandboxSetupVersionTimeout)
	defer cancel()
	out, err := sandboxSetupExecOutput(ctx, path, "--version")
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(out)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line, nil
}

// activeCheck runs the active check of in's row and returns the input with
// the probe and the versioned facts set. Only Check (the person's click)
// calls it.
func activeCheck(ctx context.Context, h sandboxSetupHost, si sandboxSetupInput) sandboxsetup.PlanInput {
	in := si.in
	if h.probeRow != nil {
		if p, ok := h.probeRow(ctx, in.Row.ID, si.cfg); ok {
			in.Probe = &p
		}
	}
	facts := map[string]sandboxsetup.Fact{}
	// A fact the check's engine finding can change is read again with it
	// (D-R4: a stale rootless socket file a check found silent no longer
	// makes the docker-group step not applicable).
	if in.Probe != nil {
		redo, decided := checkedFacts(h, si.cfg, in.Row, in.Records, sandboxsetup.EngineAnswerFrom(in.Probe.Verdict))
		if len(decided) > 0 {
			merged := map[string]sandboxsetup.Fact{}
			for id, f := range in.Facts {
				if !decided[id] {
					merged[id] = f
				}
			}
			for id, f := range redo {
				merged[id] = f
			}
			in.Facts = merged
		}
	}
	for id, f := range in.Facts {
		f.Checked = true
		if f.Present && f.Path != "" && h.runVersion != nil {
			if v, err := h.runVersion(ctx, f.Path); err == nil {
				f.Version = v
			}
		}
		if in.Probe != nil {
			f.Verdict = in.Probe.Verdict
		}
		facts[id] = f
	}
	in.Facts = facts
	return in
}
