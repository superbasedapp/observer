package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/feasibility/nodefeas"
)

// init_components.go is `observer init`'s side of the component gate
// (modular packaging P1, lane MP-GATE): init writes a vendor config entry
// only for an active component, so it can never re-wire what the operator
// removed. With no [components] block the binary's own base applies (every
// compiled component on an unstamped build, the distro's defaults on a
// distro build).

// initComponentGate answers "may init write this?" from one snapshot.
type initComponentGate struct {
	snap componentstate.Snapshot
}

// initGateFor resolves the gate for the config init writes against, through
// the one resolver the daemon and every gated verb use
// (componentSnapshotFor: the [components] block plus the governance
// snapshot). An empty path is the DEFAULT config (~/.observer/config.toml),
// never "everything active": before T-730 / T-742 (D-551) a bare `observer
// init` or `observer enroll --wire-clients` resolved componentstate.Legacy()
// here, so it wired adapters the operator had removed and skipped ones the
// operator had added. A config that does not load still falls back to the
// legacy snapshot inside componentSnapshotFor.
func initGateFor(configPath string) initComponentGate {
	return initComponentGate{snap: componentSnapshotFor(configPath)}
}

// initGateForHome is initGateFor for a caller that pinned the home directory
// (WireAIClientsOptions.HomeDir, interactiveInitOptions.HomeDir): with no
// config path the default config is the one under that home, so a sandboxed
// caller never reads the real user's file.
func initGateForHome(configPath, home string) initComponentGate {
	if configPath == "" && home != "" {
		configPath = filepath.Join(home, ".observer", "config.toml")
	}
	return initGateFor(configPath)
}

// allow reports whether component id is active, writing one skip line to w
// when it is not and the operator asked for that step (wanted).
func (g initComponentGate) allow(w io.Writer, wanted bool, step, id string) bool {
	if g.snap.Active(id) {
		return true
	}
	if wanted && w != nil {
		fmt.Fprintf(w, "%-12s skipped: %s\n", step, g.why(id))
	}
	return false
}

// why is the one reason an inactive component is skipped, from the
// feasibility seam (D-514): "not in this build" with the builds that have it,
// switched off, policy denied, or merely inactive.
func (g initComponentGate) why(id string) string {
	for _, v := range nodefeas.ComponentVerdicts(g.snap.Result.Decisions, g.snap.Selected) {
		if v.ID == id && !v.Feasible {
			s := v.Reason
			if v.Fix != "" {
				s += ". " + v.Fix
			}
			return s
		}
	}
	return "the " + id + " component is inactive (observer components status)"
}

// tools drops every tool whose adapter component is inactive, with one
// line per dropped tool.
func (g initComponentGate) tools(in []string, w io.Writer) []string {
	out := in[:0:0]
	for _, t := range in {
		if !g.snap.AdapterActive(t) {
			if w != nil {
				fmt.Fprintf(w, "%-12s skipped: %s\n", t, g.why(components.AdapterID(clientwire.HookTargetBase(t))))
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

// initComponentFlags are `observer init`'s component-selection flags: they
// write the [components] block through the same service the dashboard and
// `observer components select|add|remove` use, before any wiring runs.
type initComponentFlags struct {
	base    string
	with    []string
	without []string
}

func (f *initComponentFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.base, "components", "", "Component base to install with (all, minimal, developer, managed, full; see `observer components list`); written to [components] before any wiring, so init wires only active components")
	cmd.Flags().StringSliceVar(&f.with, "with", nil, "Component ids to add on top of the base (comma-separated)")
	cmd.Flags().StringSliceVar(&f.without, "without", nil, "Component ids to remove from the base (comma-separated); their wiring is removed and init does not write it")
}

func (f *initComponentFlags) set() bool {
	return f.base != "" || len(f.with) > 0 || len(f.without) > 0
}

// apply writes the selection (dry-run honoured) and prints the outcome.
// A refused id is reported and the rest still applies; an all-refused or
// no-op selection writes nothing.
func (f *initComponentFlags) apply(ctx context.Context, out io.Writer, configPath string, dryRun bool) error {
	if !f.set() {
		return nil
	}
	svc, err := newComponentsService(configPath, nil)
	if err != nil {
		return fmt.Errorf("init --components: %w", err)
	}
	ch := componentsvc.Change{Add: f.with, Remove: f.without}
	if f.base != "" {
		b := f.base
		ch.SetBase = &b
	}
	p, err := svc.Preview(ctx, ch)
	if err != nil {
		return fmt.Errorf("init --components: %w", err)
	}
	for _, r := range p.Refused {
		fmt.Fprintf(out, "components: refused: %s\n", r)
	}
	if p.NoChange {
		fmt.Fprintln(out, "components: selection unchanged")
		return nil
	}
	res, err := svc.Apply(ctx, ch, componentsvc.ApplyOptions{ExpectFingerprint: p.Fingerprint, DryRun: dryRun, Principal: "init"})
	if err != nil {
		return fmt.Errorf("init --components: %w", err)
	}
	verb := "set"
	if dryRun {
		verb = "would set"
	}
	fmt.Fprintf(out, "components: %s [components] (%d deactivated, %d activated)\n", verb, len(res.Preview.Deactivated), len(res.Preview.Activated))
	if len(res.Preview.Deactivated) > 0 {
		fmt.Fprintf(out, "components: inactive now: %s\n", strings.Join(res.Preview.Deactivated, ", "))
	}
	for _, o := range res.Teardown {
		for _, d := range o.Detail {
			fmt.Fprintf(out, "components: %s: %s\n", o.Target, d)
		}
		for _, n := range o.NeedsAttention {
			fmt.Fprintf(out, "components: %s: %s\n", o.Target, n)
		}
	}
	return nil
}
