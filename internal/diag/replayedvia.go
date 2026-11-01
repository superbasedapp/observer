package diag

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/routeattest"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// <tool>.hooks.replayed_via (surface-gap arc Wave 3, finding W-2b; gap
// review section 4.6). Some gates are reached through ANOTHER tool's hook
// registration: Cortex Code and Kimchi run Observer's Claude Code entries in
// ~/.claude/settings.json, and Grok replays them for its lifecycle events
// (integration.HookBinding.ReplayedVia). Nothing read that reliance, so a
// node where the host tool's hooks were never written (no ~/.claude, or
// Claude Code's own plugin skipped the write) looked gated while the gate
// never ran. This check walks the registry's ReplayedVia bindings, never a
// tool name: for each tool in use on this node whose wired gate rides
// another tool's registration, it asks a dry-run registration of that host
// whether Observer's hooks are in place.

// replayedViaProbe is the I/O a replayed-via check needs, injected so the
// rows are table-tested without a home directory.
type replayedViaProbe struct {
	// inUse reports whether tool shows a sign of use on this node (its
	// install directory, or captured sessions).
	inUse func(tool string) bool
	// hostRegistered reports whether Observer's hooks are registered for
	// host (covered by a plugin counts), and the config it looked at.
	hostRegistered func(host string) (configPath string, ok bool, err error)
}

// replayGate is one tool whose wired gates ride a host tool's registration.
type replayGate struct {
	tool, host string
	gates      []string
}

// replayGates walks the registry: every wired gate binding (tool gate or
// prompt gate) with a ReplayedVia host, grouped per (tool, host), sorted.
func replayGates() []replayGate {
	idx := map[[2]string]*replayGate{}
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			// A replay that only stands in for the tool's own registered
			// gate (HookSpec.ReplayFallback) does not depend on the host's
			// registration.
			if !b.Wired || b.ReplayedVia == "" || c.Hook.ReplayFallback(b) {
				continue
			}
			if b.Cap != integration.HookCapToolGate && b.Cap != integration.HookCapPromptGate {
				continue
			}
			k := [2]string{c.Tool, b.ReplayedVia}
			g := idx[k]
			if g == nil {
				g = &replayGate{tool: c.Tool, host: b.ReplayedVia}
				idx[k] = g
			}
			g.gates = append(g.gates, b.NativeEvent)
		}
	}
	out := make([]replayGate, 0, len(idx))
	for _, g := range idx {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tool != out[j].tool {
			return out[i].tool < out[j].tool
		}
		return out[i].host < out[j].host
	})
	return out
}

// replayedViaChecks renders one row per replayed gate of a tool in use: OK
// when the host's registration is in place, WARN when it is not or cannot
// be read. A tool with no sign of use gets no row (no false alarm).
func replayedViaChecks(p replayedViaProbe) []Check {
	var out []Check
	for _, g := range replayGates() {
		if p.inUse == nil || p.hostRegistered == nil || !p.inUse(g.tool) {
			continue
		}
		name := g.tool + ".hooks.replayed_via"
		display, hostDisplay := integration.DisplayName(g.tool), integration.DisplayName(g.host)
		gates := strings.Join(g.gates, ", ")
		cfg, ok, err := p.hostRegistered(g.host)
		switch {
		case err != nil:
			out = append(out, Check{
				Name: name, Status: StatusWarn,
				Message: fmt.Sprintf("%s's gates (%s) run only through Observer's %s hooks, and whether those are registered could not be read", display, gates, hostDisplay),
				Details: []string{"error: " + err.Error()},
			})
		case !ok:
			out = append(out, Check{
				Name: name, Status: StatusWarn,
				Message: fmt.Sprintf("%s is in use, but Observer's %s hooks are not registered, so %s's gates (%s) do not run", display, hostDisplay, display, gates),
				Details: []string{
					fmt.Sprintf("%s runs the hooks in %s's config; Observer writes no %s config of its own for these gates.", display, hostDisplay, display),
					fmt.Sprintf("Fix: run `observer init --%s` (or let `observer start` auto-register it) so the %s hooks exist.", g.host, hostDisplay),
					"Looked at: " + dash(cfg),
				},
			})
		default:
			out = append(out, Check{
				Name: name, Status: StatusOK,
				Message: fmt.Sprintf("%s's gates (%s) ride Observer's %s hooks, which are registered", display, gates, hostDisplay),
			})
		}
	}
	return out
}

// checkReplayedVia builds the production probe. A sandboxed run (pinned
// home) reads the pinned home only through the registry, as every other
// hook check does.
func checkReplayedVia(ctx context.Context, homeDir, binaryPath string, database *sql.DB, now time.Time) []Check {
	if binaryPath == "" {
		binaryPath = "observer"
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: binaryPath, HomeDir: homeDir, DryRun: true})
	if err != nil {
		return nil
	}
	installed := map[string]bool{}
	for _, t := range reg.Installed() {
		installed[t] = true
	}
	observed := map[string]bool{}
	if database != nil {
		if rows, err := store.New(database).RouteObservedSince(ctx, now.Add(-routeattest.ObservedWindow)); err == nil {
			for _, r := range rows {
				if r.Sessions > 0 {
					observed[r.Tool] = true
				}
			}
		}
	}
	return replayedViaChecks(replayedViaProbe{
		inUse: func(tool string) bool { return installed[tool] || observed[tool] },
		hostRegistered: func(host string) (string, bool, error) {
			res := reg.Probe(host)
			if res.Error != nil {
				return res.ConfigPath, false, res.Error
			}
			if res.Skipped {
				// A plugin carrying Observer's wiring counts; any other
				// skip means nothing is registered on this target.
				return res.ConfigPath, res.SkipKind == hook.SkipCovered, nil
			}
			return res.ConfigPath, len(res.HooksAdded) == 0 && len(res.AlreadySet) > 0, nil
		},
	})
}

// dash renders "" as "-".
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
