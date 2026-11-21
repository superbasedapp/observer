package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/costtext"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The CLI half of the developer cost display (D-013, T-204): an org admin
// chooses whether developers see dollar costs or only token usage, and that
// choice used to reach the dashboard, the statusline and the guard's budget
// text but not the reporting CLI (`observer cost`, `observer predict`, ...).
//
// costReportCommands is the ONE table of reporting commands whose output is
// rendered under the display. A row names a command path below the root; it
// covers that command and every subcommand under it. installCostDisplay wraps
// each covered command's run once:
//
//   - the display is resolved through store.ResolveDeveloperCostDisplay (the
//     seam GET /api/cost-display reads), once per invocation, and carried on
//     the command's context for the commands that render it natively;
//   - under token usage the command's stdout goes through costtext.NewWriter,
//     which drops dollar-keyed fields from a JSON report and hides the dollar
//     amounts in text (never converting them).
//
// A command that writes a report somewhere other than cmd.OutOrStdout() (a
// file it creates) renders the display natively and says so in its row.
// TestCostReportCommandsResolve fails when a row stops naming a command, and
// the no-bare-usd guard (no_bare_usd_test.go) fails when a file renders a
// dollar figure without being covered here or allow-listed with a reason.
var costReportCommands = []struct {
	path string
	why  string
}{
	{"cost", "per-key cost rollup; renders the token view natively (no COST column)"},
	{"chart", "terminal charts; renders the token view natively (spend drawn in tokens, no dollar fields in --json)"},
	{"predict", "next-message estimate; renders the token band natively"},
	{"advise", "avoidable-spend suggestions"},
	{"aggregate", "aggregate preview and status totals"},
	{"backfill", "maintenance summaries carry estimated cost of affected rows"},
	{"benchmark", "matrix estimates, per-cell spend, reports and exports"},
	{"cache-status", "value at risk per live cache"},
	{"handoff", "handoff option costs and next-message band"},
	{"model-value", "per-model value report"},
	{"project", "project spend, ROI and task costs"},
	{"report", "shareable spend card; refused natively in the token view"},
	{"reprice", "stored-cost re-price before / after"},
	{"routing", "routing savings, simulate and explain"},
	{"tasks", "task costs"},
	{"usage", "one-shot usage report"},
	{"verbosity", "verbosity cost estimates"},
}

// costModeKey carries the resolved display on a covered command's context.
type costModeKey struct{}

// costModeFrom returns the display installCostDisplay resolved for this
// invocation, or dollars for a command it does not cover.
func costModeFrom(ctx context.Context) string {
	if ctx != nil {
		if m, ok := ctx.Value(costModeKey{}).(string); ok && m != "" {
			return m
		}
	}
	return costtext.ModeUSD
}

// cliCostDisplayMode resolves the developer cost display for a CLI
// invocation. A machine with no database has no enrolment, so it shows
// dollars (the never-enrolled default, D-179); a database that exists but
// cannot be read shows token usage, never the dollars default. A package var
// so tests pin it.
var cliCostDisplayMode = func(cmd *cobra.Command) string {
	configPath := ""
	if f := cmd.Flags().Lookup("config"); f != nil {
		configPath = f.Value.String()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return orgcontract.DisplayCostTokens
	}
	if _, err := os.Stat(cfg.Observer.DBPath); errors.Is(err, fs.ErrNotExist) {
		return orgcontract.DisplayCostUSD
	}
	_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return orgcontract.DisplayCostTokens
	}
	defer cleanup()
	return newCostDisplayResolver(store.New(database)).Mode()
}

// installCostDisplay wraps every command costReportCommands covers.
func installCostDisplay(root *cobra.Command) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if costReportCovered(commandPathBelowRoot(c)) {
			wrapCostDisplay(c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	for _, c := range root.Commands() {
		walk(c)
	}
}

// commandPathBelowRoot is "routing savings" for `observer routing savings`.
func commandPathBelowRoot(c *cobra.Command) string {
	var parts []string
	for p := c; p != nil && p.HasParent(); p = p.Parent() {
		parts = append([]string{p.Name()}, parts...)
	}
	return strings.Join(parts, " ")
}

func costReportCovered(path string) bool {
	// The deprecated `observer observer <sub>` alias group carries the same
	// commands one level down.
	path = strings.TrimPrefix(path, "observer ")
	for _, row := range costReportCommands {
		if path == row.path || strings.HasPrefix(path, row.path+" ") {
			return true
		}
	}
	return false
}

func wrapCostDisplay(c *cobra.Command) {
	switch {
	case c.RunE != nil:
		inner := c.RunE
		c.RunE = func(cmd *cobra.Command, args []string) error {
			return runUnderCostDisplay(cmd, func() error { return inner(cmd, args) })
		}
	case c.Run != nil:
		inner := c.Run
		c.Run = nil
		c.RunE = func(cmd *cobra.Command, args []string) error {
			return runUnderCostDisplay(cmd, func() error { inner(cmd, args); return nil })
		}
	}
}

// runUnderCostDisplay resolves the display once, carries it on the context
// and, under token usage, routes stdout through costtext.NewWriter.
func runUnderCostDisplay(cmd *cobra.Command, run func() error) error {
	mode := cliCostDisplayMode(cmd)
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.SetContext(context.WithValue(ctx, costModeKey{}, mode))
	if !costtext.Tokens(mode) {
		return run()
	}
	out := cmd.OutOrStdout()
	w := costtext.NewWriter(out, mode)
	cmd.SetOut(w)
	err := run()
	cmd.SetOut(out)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return err
}

// tokenViewNote is the line a natively rendered report prints under token
// usage, so a reader knows the dollar figures were left out on purpose.
const tokenViewNote = "Costs are hidden: your organization shows token usage instead of costs on this machine."
