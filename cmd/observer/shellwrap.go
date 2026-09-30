// shellwrap.go — `observer shell-wrap status|preview|enable|disable`: the
// CLI face of the command-wrapping shell integration (backlog item 7). Typing
// a vendor command (`claude`, `codex`, `code`) runs its observer-wrapped form
// (`observer claude`, `observer ide vscode`) once enabled. The planner is
// internal/shellwrap, the applier internal/shellwrapsvc; this file only
// parses flags, wires the install probe and renders.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
	"github.com/marmutapp/superbased-observer/internal/shellwrapsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// shellWrapInstalledSeam reports whether a wrappable id's vendor command is
// installed: a [launch.tools.<id>].path override that exists, else the
// toolresolve ladder over the registry row's (or GUI row's) binary spec. The
// resolver skips command-wrapping shims (toolresolve.Env.ExcludeMarker), so a
// shim never counts as an install.
func shellWrapInstalledSeam(configPath string, env func() toolresolve.Env) func(id string) bool {
	return func(id string) bool {
		if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
			if tc, ok := cfg.Launch.Tools[id]; ok && tc.Path != "" {
				if fi, err := os.Stat(tc.Path); err == nil && !fi.IsDir() {
					return true
				}
			}
		}
		var r toolresolve.Resolution
		if c, ok := integration.For(id); ok && c.Binary != nil {
			r = toolresolve.Resolve(*c.Binary, env())
		} else if g, ok := integration.GUILaunchFor(id); ok {
			r = toolresolve.ResolveGUI(g.Spec, env())
		} else {
			return false
		}
		switch r.Verdict {
		case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
			return true
		}
		return false
	}
}

// newShellWrapService builds the one applier both the CLI and the dashboard
// seam use.
func newShellWrapService(configPath string, env func() toolresolve.Env) *shellwrapsvc.Service {
	return &shellwrapsvc.Service{
		ConfigPath: configPath,
		Installed:  shellWrapInstalledSeam(configPath, env),
	}
}

// refreshShellWrapShims is `observer start`'s one shell-wrap call site: when
// command wrapping is recorded as enabled, marked shims whose baked observer
// binary is gone (an npm reinstall under another prefix, an upgrade that moved
// it) are re-pointed at the running one; a baked binary that still exists is
// another install and is kept. It never creates a
// shim, adds a tool or edits a shell start-up file, and does nothing when
// shell-wrap is off. Fail-soft: a failure is one stderr line, never a startup
// error.
func refreshShellWrapShims(ctx context.Context, stdout, stderr io.Writer, configPath string) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "shell-wrap: shim refresh skipped: %v\n", err)
		return
	}
	out, err := newShellWrapService(resolved, resolveEnv).RefreshStale(ctx)
	for _, r := range out.Rewritten {
		fmt.Fprintf(stdout, "shell-wrap: re-pointed %s at %s (was %s)\n", r.Path, out.ObserverPath, r.OldObserverPath)
	}
	for _, r := range out.Plan.Shims {
		if r.Action == shellwrap.RefreshSkip && r.Reason == shellwrap.ReasonObserverNotRunnable {
			fmt.Fprintf(stderr, "shell-wrap: shim refresh skipped for %s (observer %q): %s\n", r.Path, out.ObserverPath, r.Reason)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "shell-wrap: shim refresh incomplete (startup continues; `observer shell-wrap enable` re-applies): %v\n", err)
	}
}

func newShellWrapCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "shell-wrap",
		Short: "Make typing a tool's command run its observer-wrapped form (claude -> observer claude)",
		Long: "Command wrapping writes small shims (one per replaced command, e.g. `claude`)\n" +
			"into ~/.observer/shims and puts that directory first on PATH through a marked,\n" +
			"removable block in your shell start-up files (bash ~/.bashrc, zsh ~/.zshrc, fish\n" +
			"conf.d, PowerShell profile). Each shim runs `observer <tool> -- <your args>`;\n" +
			"if observer is missing it runs the real command, and SBO_SHIM_BYPASS=1 always\n" +
			"runs the real command. OFF by default - nothing is written until you enable it.\n\n" +
			"What wrapping buys differs per tool and is shown honestly:\n" +
			"  routed through the observer proxy   a live turn has been proven through it\n" +
			"  wrapped, live proof owed            it injects routing, not yet proven live\n" +
			"  launches, no routing                same program; capture is unchanged\n\n" +
			"Examples:\n" +
			"    observer shell-wrap status\n" +
			"    observer shell-wrap preview claude-code codex     # show exactly what would be written\n" +
			"    observer shell-wrap enable claude-code codex\n" +
			"    observer shell-wrap enable all --shell zsh        # every installed CLI tool\n" +
			"    observer shell-wrap disable                       # restore every file byte-for-byte",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "observer config.toml path (default ~/.observer/config.toml)")
	svc := func() *shellwrapsvc.Service { return newShellWrapService(configPath, resolveEnv) }

	var statusJSON bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the wrappable commands, what is applied, and what wrapping buys per tool",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := svc().Status(cmd.Context())
			if err != nil {
				return err
			}
			if statusJSON {
				return writeShellWrapJSON(cmd.OutOrStdout(), st)
			}
			renderShellWrapStatus(cmd.OutOrStdout(), st)
			return nil
		},
	}
	status.Flags().BoolVar(&statusJSON, "json", false, "print the status as JSON")

	applyCmd := func(use, short string, forceDry bool) *cobra.Command {
		var (
			shells []string
			dryRun bool
			asJSON bool
		)
		c := &cobra.Command{
			Use:   use + " [tool-id...|all]",
			Short: short,
			RunE: func(cmd *cobra.Command, args []string) error {
				s := svc()
				tools := args
				if len(tools) == 0 {
					// Re-apply the recorded choice (e.g. after an upgrade
					// moved the observer binary).
					st, err := s.Status(cmd.Context())
					if err != nil {
						return err
					}
					for _, t := range st.Tools {
						if t.Selected {
							tools = append(tools, t.ID)
						}
					}
					if len(tools) == 0 {
						return fmt.Errorf("observer shell-wrap %s: name the tools to wrap (see `observer shell-wrap status`), or `all`", use)
					}
				}
				out, err := s.Apply(cmdContext(cmd), shellwrapsvc.Request{Tools: tools, Shells: shells, DryRun: dryRun || forceDry})
				if err != nil {
					return err
				}
				if asJSON {
					return writeShellWrapJSON(cmd.OutOrStdout(), out)
				}
				renderShellWrapOutcome(cmd.OutOrStdout(), out)
				return nil
			},
		}
		c.Flags().StringSliceVar(&shells, "shell", nil, "shell start-up files to manage: bash, zsh, fish, powershell (repeatable; default: the shells detected in use)")
		if !forceDry {
			c.Flags().BoolVar(&dryRun, "dry-run", false, "show the changes, write nothing (same as `preview`)")
		}
		c.Flags().BoolVar(&asJSON, "json", false, "print the outcome as JSON")
		return c
	}

	var disableDry, disableJSON bool
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Remove every shim and every marked block (start-up files restored byte-for-byte)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := svc().Disable(cmdContext(cmd), disableDry)
			if err != nil {
				return err
			}
			if disableJSON {
				return writeShellWrapJSON(cmd.OutOrStdout(), out)
			}
			renderShellWrapOutcome(cmd.OutOrStdout(), out)
			return nil
		},
	}
	disable.Flags().BoolVar(&disableDry, "dry-run", false, "show the changes, write nothing")
	disable.Flags().BoolVar(&disableJSON, "json", false, "print the outcome as JSON")

	cmd.AddCommand(status,
		applyCmd("preview", "Show exactly what `enable` would write, without writing anything", true),
		applyCmd("enable", "Wrap the named tools' commands (or `all` installed CLI tools)", false),
		disable,
	)
	return cmd
}

func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func writeShellWrapJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// shellWrapToolState renders one row's applied state.
func shellWrapToolState(t shellwrap.ToolStatus) string {
	switch {
	case len(t.Active) > 0 && len(t.Stale) > 0:
		return "active (stale - re-run enable)"
	case len(t.Active) > 0:
		return "active"
	case t.Selected:
		return "selected, not applied"
	}
	return "-"
}

func renderShellWrapStatus(w io.Writer, st shellwrap.Status) {
	state := "off"
	switch {
	case st.Enabled && st.InSync:
		state = "on"
	case st.Enabled:
		state = "on - files differ from the recorded choice (run `observer shell-wrap enable` to re-apply)"
	case st.Active:
		state = "off - but shims or blocks are still installed (run `observer shell-wrap disable`)"
	}
	fmt.Fprintf(w, "Command wrapping: %s\n", state)
	fmt.Fprintf(w, "Shim dir:         %s\n", st.ShimDir)
	fmt.Fprintf(w, "Shells detected:  %s\n", joinShells(st.DetectedShells, "none"))
	if len(st.RC) > 0 {
		fmt.Fprintln(w, "Start-up files:")
		for _, r := range st.RC {
			mark := "no block"
			if r.HasBlock {
				mark = "block installed"
				if r.Wanted && !r.Current {
					mark = "block outdated"
				}
			} else if r.Wanted {
				mark = "block missing"
			}
			fmt.Fprintf(w, "  %-11s %s  (%s)\n", r.Shell, r.Path, mark)
		}
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCOMMANDS\tWRAPPED AS\tSTATE\tWHAT IT BUYS")
	for _, t := range st.Tools {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.ID, strings.Join(t.Commands, ","), t.Wrapped, shellWrapToolState(t), t.HonestyText)
	}
	_ = tw.Flush()
	for _, o := range st.Orphans {
		fmt.Fprintf(w, "note: %s is a shim for %q, which is no longer wrappable here - `disable` or `enable` removes it\n", o.Path, o.ToolID)
	}
	for _, warn := range st.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
}

func joinShells(s []shellwrap.Shell, empty string) string {
	if len(s) == 0 {
		return empty
	}
	out := make([]string, len(s))
	for i, sh := range s {
		out[i] = string(sh)
	}
	return strings.Join(out, ", ")
}

func renderShellWrapOutcome(w io.Writer, out shellwrapsvc.Outcome) {
	verb := "applied"
	if out.DryRun {
		verb = "would apply (dry run)"
	}
	fmt.Fprintf(w, "observer shell-wrap: %s\n", verb)
	for _, t := range out.Plan.Tools {
		fmt.Fprintf(w, "  %s: %s -> %s  [%s]\n", t.ID, strings.Join(t.Shimmed, ","), t.Wrapped, t.HonestyText)
	}
	changes := append([]shellwrapsvc.Change(nil), out.Changes...)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].Kind > changes[j].Kind })
	for _, c := range changes {
		if c.Action == shellwrapsvc.ActionUnchanged {
			continue
		}
		label := c.Kind
		if c.Shell != "" {
			label = c.Shell
		}
		target := c.Path
		if c.Target != "" {
			target += " -> " + c.Target
		}
		fmt.Fprintf(w, "  %-7s %-10s %s\n", c.Action, label, target)
		if out.DryRun && c.Kind == "rc" && c.Detail != "" {
			for _, line := range strings.Split(c.Detail, "\n") {
				fmt.Fprintf(w, "            | %s\n", line)
			}
		}
	}
	if countChanged(out.Changes) == 0 {
		fmt.Fprintln(w, "  nothing to change")
	}
	for _, warn := range out.Plan.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	for _, n := range out.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

func countChanged(cs []shellwrapsvc.Change) int {
	n := 0
	for _, c := range cs {
		if c.Action != shellwrapsvc.ActionUnchanged {
			n++
		}
	}
	return n
}
