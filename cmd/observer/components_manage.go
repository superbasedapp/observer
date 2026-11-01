package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// components_manage.go is the write side of `observer components` (modular
// packaging P1, lane MP-GATE): status, select, add, remove, teardown and
// purge, every one through the one writer internal/componentsvc. A change
// is previewed first and applied only with --yes, so a script and a human
// see the same preview the dashboard's Settings > Components page shows.

// newComponentsService builds the production components service for a
// config path. database may be nil (purge and the audit row are then
// unavailable and say so). It is the constructor the dashboard wiring uses
// too (lane MP-DASH), so the CLI and the page share one teardown and one
// audit path.
func newComponentsService(configPath string, database *sql.DB) (*componentsvc.Service, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return nil, err
	}
	binary, err := absoluteBinaryPath()
	if err != nil {
		return nil, err
	}
	port := 8820
	if cfg, lerr := config.Load(config.LoadOptions{GlobalPath: configPath}); lerr == nil && cfg.Proxy.Port > 0 {
		port = cfg.Proxy.Port
	}
	winHomes, _, newReg := productionWindowsBrowserInputs()
	opts := componentsvc.Options{
		ConfigPath: resolved,
		Teardown: componentsvc.NewTeardown(componentsvc.TeardownOptions{
			Remove: clientwire.RemoveOptions{BinaryPath: binary, ProxyPort: port},
			BrowserHost: func(dryRun bool) componentsvc.StepOutcome {
				return removeBrowserHost(browserHostRemoveOptions{WindowsHomes: winHomes, NewRegistry: newReg}, dryRun)
			},
		}),
	}
	// Managed governance (lane MP-GOV, ledger MODPKG-7): read fresh on every
	// call, so the CLI and the dashboard refuse a narrowing change on an
	// org-managed node from the same signed inputs the daemon used.
	opts.Governed = func(ctx context.Context) componentstate.Governed {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: resolved})
		if err != nil {
			return componentstate.Governed{}
		}
		return componentGovernanceFor(ctx, cfg)
	}
	if database != nil {
		st := store.New(database)
		opts.Purge = st
		opts.Audit = func(ctx context.Context, action, detail string) {
			actx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			_ = st.InsertRemoteAudit(actx, store.RemoteAuditEvent{
				Kind: "manage", Principal: "local", Route: "components", Decision: "ok",
				Detail: strings.TrimSpace(action + " " + detail),
			})
		}
	}
	return componentsvc.New(opts)
}

// withComponentsManageVerbs adds the write verbs to the read-only
// `observer components` command.
func withComponentsManageVerbs(cmd *cobra.Command) *cobra.Command {
	cmd.AddCommand(
		newComponentsStatusCmd(),
		newComponentsChangeCmd("select", "Set the base selection: all (everything this build contains) or a distro", true),
		newComponentsChangeCmd("add", "Activate components", false),
		newComponentsChangeCmd("remove", "Make components inactive and undo what they wrote into other tools", false),
		newComponentsTeardownCmd(),
		newComponentsPurgeCmd(),
	)
	return cmd
}

func newComponentsStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show which components are active on this machine, and why",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			snap := componentSnapshotFor(configPath)
			v := componentStateView(snap)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(v)
			}
			renderComponentState(cmd.OutOrStdout(), v)
			fmt.Fprintln(cmd.OutOrStdout(), binaryInstallLine())
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the state as JSON (the shape the dashboard reads)")
	return cmd
}

// unconfiguredSelectionPhrase says what is active when no [components]
// selection is recorded (T-732, T-739, D-548). "Every component this build
// contains is active" was printed on distro and managed builds too, right
// before the list of components that were not active.
func unconfiguredSelectionPhrase(v componentstate.View) string {
	switch {
	case v.OrgManaged:
		return fmt.Sprintf("the components %s allows are active (%d of %d)", componentsOrgLabel(v.OrgName), v.ActiveCount, v.CompiledCount)
	case v.ActiveCount >= v.CompiledCount:
		return "every component this build contains is active"
	default:
		return fmt.Sprintf("this build's defaults are active (%d of %d compiled; the rest are installed and off until you turn them on)", v.ActiveCount, v.CompiledCount)
	}
}

func componentsOrgLabel(name string) string {
	if strings.TrimSpace(name) == "" {
		return "your organization"
	}
	return name
}

func renderComponentState(w io.Writer, v componentstate.View) {
	if !v.Configured {
		fmt.Fprintf(w, "No [components] selection: %s (each feature's own setting still decides whether it runs).\n", unconfiguredSelectionPhrase(v))
	} else {
		fmt.Fprintf(w, "Selection: base %s, add %v, remove %v\n", v.Base, v.Add, v.Remove)
	}
	fmt.Fprintf(w, "Build: %s, %d components compiled, %d active\n", v.BinaryDistro, v.CompiledCount, v.ActiveCount)
	for _, is := range v.Issues {
		fmt.Fprintf(w, "WARN %s\n", is)
	}
	var inactive []string
	for _, r := range v.Components {
		if r.State != components.StateActive {
			why := string(r.State)
			if r.Because != "" {
				why += " (" + string(r.Reason) + " " + r.Because + ")"
			}
			inactive = append(inactive, "  "+r.ID+": "+why)
		}
	}
	if len(inactive) > 0 {
		fmt.Fprintln(w, "Not active:")
		fmt.Fprintln(w, strings.Join(inactive, "\n"))
	}
	fmt.Fprintln(w, v.RestartNote)
}

func newComponentsChangeCmd(verb, short string, isSelect bool) *cobra.Command {
	var (
		configPath   string
		yes          bool
		skipTeardown bool
		jsonOut      bool
		endRuns      bool
	)
	use := verb + " <id>..."
	args := cobra.MinimumNArgs(1)
	if isSelect {
		use, args = verb+" <all|minimal|developer|managed|full>", cobra.ExactArgs(1)
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + ".\n\nWithout --yes this only previews: what activates, what goes inactive (with\n" +
			"the dependants that go with it), and the ordered undo of every write an\n" +
			"inactive component made into other tools' config. Data is kept; see\n" +
			"`observer components purge`.",
		Args: args,
		RunE: func(cmd *cobra.Command, a []string) error {
			var ch componentsvc.Change
			switch verb {
			case "select":
				ch.SetBase = &a[0]
			case "add":
				ch.Add = a
			case "remove":
				ch.Remove = a
			}
			return runComponentsChange(cmd, configPath, ch, yes, skipTeardown, jsonOut, endRuns)
		},
	}
	cmd.Flags().BoolVar(&endRuns, "end-sandboxed-runs", false, "When the change deactivates the sandbox (isolation, terminals.sandbox or a driver) while sandboxed runs are live, end them first")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Apply the change (without it, only preview)")
	cmd.Flags().BoolVar(&skipTeardown, "skip-teardown", false, "Write the selection but leave what inactive components wrote in place")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Print the preview or result as JSON")
	return cmd
}

func runComponentsChange(cmd *cobra.Command, configPath string, ch componentsvc.Change, yes, skipTeardown, jsonOut, endRuns bool) error {
	ctx := cmd.Context()
	var database *sql.DB
	if yes {
		if _, d, cleanup, err := loadConfigAndDB(ctx, configPath); err == nil {
			defer cleanup()
			database = d
		}
	}
	svc, err := newComponentsService(configPath, database)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if !yes {
		p, err := svc.Preview(ctx, ch)
		if err != nil {
			return err
		}
		if jsonOut {
			return writeComponentsResultJSON(out, p)
		}
		renderComponentsPreview(out, p)
		if held := liveRunHeldIDs(p.Deactivated, p.Cascade); len(held) > 0 {
			componentsLiveRunPreviewNote(ctx, out, configPath, held)
		}
		if !p.NoChange {
			fmt.Fprintln(out, "Preview only. Re-run with --yes to apply.")
		}
		return nil
	}
	// A change that deactivates the sandbox while sandboxed runs are live is
	// refused naming them, unless --end-sandboxed-runs (sandbox plan v2
	// sections 5.5 and 11.2, SBX-UPD-1).
	if p, perr := svc.Preview(ctx, ch); perr == nil {
		if held := liveRunHeldIDs(p.Deactivated, p.Cascade); len(held) > 0 {
			// The gate's lines go to stderr: with --json, stdout carries
			// only the result (SBX-UPD audit finding 4).
			if err := cliLiveRunCheck(ctx, cmd.ErrOrStderr(), liveRunTriggerDeactivation, newDaemonLiveRunsClient(configPath),
				cliLiveRunChoice{endRuns: endRuns, flagHint: "--end-sandboxed-runs (this deactivates " + strings.Join(held, ", ") + ")"}); err != nil {
				return err
			}
		}
	}
	res, err := svc.Apply(ctx, ch, componentsvc.ApplyOptions{SkipTeardown: skipTeardown, Principal: "cli"})
	if err != nil {
		return err
	}
	if jsonOut {
		return writeComponentsResultJSON(out, res)
	}
	renderComponentsPreview(out, res.Preview)
	renderTeardownOutcomes(out, res.Teardown, res.TeardownSkipped)
	if res.Wrote && res.Preview.RestartRequired {
		fmt.Fprintln(out, "Applied. "+componentstate.RestartNote)
	}
	return nil
}

// componentsLiveRunPreviewNote says, in a preview, that applying the change
// would end live sandboxed runs (only when the daemon reports some).
func componentsLiveRunPreviewNote(ctx context.Context, w io.Writer, configPath string, held []string) {
	rep, err := newDaemonLiveRunsClient(configPath).query(ctx)
	if err != nil || !rep.Answered || len(rep.Runs) == 0 {
		return
	}
	fmt.Fprintf(w, "WARN %s live (%s); deactivating %s ends them, so --yes refuses unless --end-sandboxed-runs\n",
		liveRunsAreLabel(len(rep.Runs)), describeLiveRuns(rep.Runs), strings.Join(held, ", "))
}

// liveRunHoldComponents is the dashboard's components service with the
// live-run hold (SBX-UPD-1): a change that deactivates the sandbox while
// sandboxed runs are live says so in its preview and is refused naming the
// runs; the owner ends them first (the restart dialog's "End", or each
// terminal) and applies again. With no live run it is the service itself.
type liveRunHoldComponents struct {
	*componentsvc.Service
	count func() int
	runs  func() []string
}

// withLiveRunHold wraps the dashboard's components service.
func withLiveRunHold(svc *componentsvc.Service) *liveRunHoldComponents {
	return &liveRunHoldComponents{Service: svc, count: liveSandboxedNow, runs: func() []string {
		if src := currentLiveRunSource(); src != nil {
			var out []string
			for _, r := range src.liveRuns(time.Now()) {
				out = append(out, r.Tool+" on "+r.Backend)
			}
			return out
		}
		return nil
	}}
}

// errDeactivationHeld refuses a deactivation while sandboxed runs are live.
var errDeactivationHeld = errors.New("components: the change deactivates the sandbox while sandboxed runs are live")

func (h *liveRunHoldComponents) held(p componentsvc.Preview) ([]string, int) {
	ids := liveRunHeldIDs(p.Deactivated, p.Cascade)
	if len(ids) == 0 {
		return nil, 0
	}
	return ids, h.count()
}

// Preview adds the live-run note when it applies.
func (h *liveRunHoldComponents) Preview(ctx context.Context, ch componentsvc.Change) (componentsvc.Preview, error) {
	p, err := h.Service.Preview(ctx, ch)
	if err != nil {
		return p, err
	}
	if ids, n := h.held(p); n > 0 {
		p.Issues = append(p.Issues, fmt.Sprintf("%s live (%s); deactivating %s ends them: end them first, then apply",
			liveRunsAreLabel(n), strings.Join(h.runs(), "; "), strings.Join(ids, ", ")))
	}
	return p, nil
}

// Apply refuses a held deactivation, naming the runs.
func (h *liveRunHoldComponents) Apply(ctx context.Context, ch componentsvc.Change, ao componentsvc.ApplyOptions) (componentsvc.ApplyResult, error) {
	p, err := h.Service.Preview(ctx, ch)
	if err == nil {
		if ids, n := h.held(p); n > 0 && !ao.DryRun {
			return componentsvc.ApplyResult{}, fmt.Errorf("%w: %s (%s) would end when %s goes inactive; end them first",
				errDeactivationHeld, liveRunCountLabel(n), strings.Join(h.runs(), "; "), strings.Join(ids, ", "))
		}
	}
	return h.Service.Apply(ctx, ch, ao)
}

func renderComponentsPreview(w io.Writer, p componentsvc.Preview) {
	if p.NoChange {
		fmt.Fprintln(w, "No change to the selection.")
	}
	for _, r := range p.Refused {
		fmt.Fprintf(w, "refused: %s\n", r)
	}
	if len(p.Activated) > 0 {
		fmt.Fprintf(w, "activates: %s\n", strings.Join(p.Activated, ", "))
	}
	if len(p.Deactivated) > 0 {
		fmt.Fprintf(w, "goes inactive: %s\n", strings.Join(p.Deactivated, ", "))
	}
	if len(p.Cascade) > 0 {
		fmt.Fprintf(w, "removed with them (they require a removed component): %s\n", strings.Join(p.Cascade, ", "))
	}
	for _, s := range p.Teardown {
		line := "undo " + s.Component + ": " + s.What
		if s.Command != "" {
			line += " (run `" + s.Command + "`)"
		}
		fmt.Fprintln(w, line)
	}
	for _, is := range p.Issues {
		fmt.Fprintf(w, "WARN %s\n", is)
	}
}

func renderTeardownOutcomes(w io.Writer, outs []componentsvc.StepOutcome, skipped bool) {
	if skipped {
		fmt.Fprintln(w, "teardown skipped: what the inactive components wrote is still in place (observer components teardown <id> removes it)")
	}
	for _, o := range outs {
		switch {
		case o.Error != "":
			fmt.Fprintf(w, "  %s %s: error: %s\n", o.Component, o.Target, o.Error)
		case o.Changed:
			fmt.Fprintf(w, "  %s %s: removed %s\n", o.Component, o.Target, strings.Join(o.Detail, "; "))
		}
		for _, n := range o.NeedsAttention {
			fmt.Fprintf(w, "  %s %s: needs attention: %s\n", o.Component, o.Target, n)
		}
	}
}

func newComponentsTeardownCmd() *cobra.Command {
	var (
		configPath string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "teardown <id>...",
		Short: "Undo what inactive components wrote into other tools' config (hooks, MCP entries, routes, the browser host)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, ids []string) error {
			ctx := cmd.Context()
			var database *sql.DB
			if _, d, cleanup, err := loadConfigAndDB(ctx, configPath); err == nil {
				defer cleanup()
				database = d
			}
			svc, err := newComponentsService(configPath, database)
			if err != nil {
				return err
			}
			outs, err := svc.RunTeardown(ctx, ids, dryRun)
			if err != nil {
				return err
			}
			renderTeardownOutcomes(cmd.OutOrStdout(), outs, false)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be removed without removing it")
	return cmd
}

func newComponentsPurgeCmd() *cobra.Command {
	var (
		configPath string
		confirm    string
	)
	cmd := &cobra.Command{
		Use:   "purge <id> | purge --confirm <plan-id>",
		Short: "Delete an inactive component's captured rows, previewed first (node-local; the org's copy is untouched)",
		Long: "Step 1, `observer components purge <id>`, previews: it counts the rows the\n" +
			"component captured and prints a plan id, valid for 15 minutes. Step 2,\n" +
			"`observer components purge --confirm <plan-id>`, deletes exactly those rows\n" +
			"(rows that changed since the preview are skipped and reported). A session\n" +
			"another tool's rows still use is kept. Rows already pushed to an org follow\n" +
			"the org's retention. Only components with a reviewed purge plan (today every\n" +
			"adapter) can be purged; the rest keep their data.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			ctx := cmd.Context()
			_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			svc, err := newComponentsService(configPath, database)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch {
			case confirm != "" && len(a) == 0:
				res, err := svc.PurgeExecute(ctx, confirm)
				if err != nil {
					return err
				}
				return writeComponentsResultJSON(out, res)
			case confirm == "" && len(a) == 1:
				plan, err := svc.PurgePreview(ctx, a[0])
				if err != nil {
					if errors.Is(err, store.ErrNoPurgePlan) {
						return fmt.Errorf("%s has no reviewed purge plan; its data is kept", a[0])
					}
					return err
				}
				fmt.Fprintf(out, "purge plan %s for %s (expires %s):\n", plan.ID, plan.Component, plan.ExpiresAt.Local().Format(time.Kitchen))
				candidates := []string{"actions", "token_usage", "compaction_events", "sessions"}
				for _, t := range candidates {
					if n, ok := plan.Counts[t]; ok {
						fmt.Fprintf(out, "  %-26s %d candidate rows\n", t, n)
					}
				}
				// The derived rows that go with them (ledger MODPKG-10), an
				// estimate at preview time; the result reports exact counts.
				var derived []string
				for t, n := range plan.Counts {
					if n > 0 && !slices.Contains(candidates, t) {
						derived = append(derived, t)
					}
				}
				sort.Strings(derived)
				for _, t := range derived {
					fmt.Fprintf(out, "  %-26s %d derived rows (estimate)\n", t, plan.Counts[t])
				}
				fmt.Fprintf(out, "Delete them with: observer components purge --confirm %s\n", plan.ID)
				return nil
			default:
				return errors.New("give a component id to preview, or --confirm <plan-id> to execute")
			}
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&confirm, "confirm", "", "Execute the previewed plan with this id")
	return cmd
}

func writeComponentsResultJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
