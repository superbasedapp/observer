package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/user"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/pricewire"
	"github.com/marmutapp/superbased-observer/internal/reprice"
	"github.com/marmutapp/superbased-observer/internal/repricesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// reprice.go is `observer reprice` - opt-in retroactive re-pricing of the
// node's stored costs (gap PRICE-REPRICE-1, docs/pricing.md "Re-pricing
// stored costs") - and the composition of the ONE repricesvc.Service the CLI
// and the dashboard's Settings card share (newRepriceService).
//
// The price side is the node's one process cost engine
// (acquireProcessCostEngine): its loader resolves internal/orgpricing.Mode
// once, so a re-price answers with exactly the precedence the proxy stamps
// with (seed -> org/feed -> local on an individual node, seed -> local -> org
// on a managed node holding enforce.budget), each row at its own timestamp.

// enginePriceFunc is the planner's price seam over the node's process
// engine: a shim over pricewire.RepricePriceFunc, the one adapter the org's
// re-price uses too.
func enginePriceFunc(e *cost.Engine) reprice.PriceFunc { return pricewire.RepricePriceFunc(e) }

// repricePricingInfo names the price table a re-price prices under. On an
// enrolled node it reuses the `observer guard status` "Pricing:" sentence
// (guardPricingLine) so the two surfaces never describe the table
// differently; a standalone node's table is the public feed when one is
// composed into the engine, else the built-in table.
func repricePricingInfo(ctx context.Context, cfg config.Config, database *sql.DB, e *cost.Engine) repricesvc.PricingInfo {
	localOverrides := len(cfg.Intelligence.Pricing.Models) > 0 || len(cfg.Intelligence.Pricing.Dated) > 0
	enr, err := store.New(database).LoadEnrolment(ctx)
	if err == nil && enr != nil {
		info := repricesvc.PricingInfo{Source: repricesvc.PricingSourceSeed, Description: guardPricingLine(ctx, cfg, database)}
		if e.HasOrgPricing() {
			info.Source, info.Version = repricesvc.PricingSourceOrg, e.OrgPricingVersion()
		}
		return info
	}
	if e.HasOrgPricing() {
		d := fmt.Sprintf("the public price feed v%d", e.OrgPricingVersion())
		if localOverrides {
			d += ", under the [intelligence.pricing] rates you set"
		}
		return repricesvc.PricingInfo{Source: repricesvc.PricingSourceFeed, Version: e.OrgPricingVersion(), Description: d}
	}
	d := "the built-in rate table"
	if localOverrides {
		d = "your own [intelligence.pricing] rates over the built-in table"
	}
	return repricesvc.PricingInfo{Source: repricesvc.PricingSourceSeed, Description: d}
}

// newRepriceService composes the one re-price service over database and the
// process cost engine. Both `observer start` / `observer dashboard` (the
// Settings card) and `observer reprice` build it here, each handing in the
// node's governance posture (the daemon's live handle, the dashboard's and
// the CLI's verified on-disk LKG), so the org's pricing pin refuses an apply
// from every caller - the check itself lives in repricesvc.Service.Apply.
// A nil governance provider is an ungoverned service.
func newRepriceService(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger, governance func(context.Context) govern.Effective) *repricesvc.Service {
	e := acquireProcessCostEngine(ctx, cfg, database, logger)
	return repricesvc.New(store.New(database), enginePriceFunc(e),
		func(ctx context.Context) repricesvc.PricingInfo { return repricePricingInfo(ctx, cfg, database, e) },
		time.Now).WithGovernance(governance)
}

// repriceCLIGovernance is the CLI's governance posture: like `observer
// dashboard`, the CLI runs no policy poller, so it installs the node.governance
// family from its verified on-disk LKG cache. Without it `observer reprice
// --apply` would be an ungoverned path around the Settings card's pin.
func repriceCLIGovernance(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) func(context.Context) govern.Effective {
	st := store.New(database)
	ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
	loadNodeGovernanceLKG(ctx, cfg, st, ngov, logger)
	return ngov.Effective
}

// repriceMode is the one action a `observer reprice` invocation takes.
type repriceMode int

const (
	repriceModePlan repriceMode = iota
	repriceModeApply
	repriceModeRevert
	repriceModeList
)

// repriceOpts are the parsed flags.
type repriceOpts struct {
	configPath string
	apply      bool
	revert     int64
	list       bool
	since      string
	until      string
	model      string
	jsonOut    bool
}

// resolve validates the flag combination and the window before anything
// touches the database.
func (o repriceOpts) resolve(now time.Time) (repriceMode, error) {
	n := 0
	mode := repriceModePlan
	if o.apply {
		n++
		mode = repriceModeApply
	}
	if o.revert != 0 {
		n++
		mode = repriceModeRevert
	}
	if o.list {
		n++
		mode = repriceModeList
	}
	if n > 1 {
		return 0, errors.New("observer reprice: --apply, --revert and --list are mutually exclusive")
	}
	if o.revert < 0 {
		return 0, errors.New("observer reprice: --revert needs a positive run id")
	}
	if (mode == repriceModeRevert || mode == repriceModeList) && (o.since != "" || o.until != "" || o.model != "") {
		return 0, errors.New("observer reprice: --since / --until / --model apply to a dry run or --apply only")
	}
	for _, b := range []string{o.since, o.until} {
		if _, err := repricesvc.ParseBound(b, now); err != nil {
			return 0, fmt.Errorf("observer reprice: %w", err)
		}
	}
	return mode, nil
}

func newRepriceCmd() *cobra.Command {
	var o repriceOpts
	cmd := &cobra.Command{
		Use:   "reprice",
		Short: "Re-price stored costs at the rate in force when each turn happened (dry run by default)",
		Long: `Re-prices the costs this node stored at capture (proxy turns and rolling-summary
calls) at the price in force AT EACH ROW'S OWN TIMESTAMP, under the price
table this node uses today (the org's rates, the public price feed, or the
built-in table, with your own [intelligence.pricing] rates where they apply).

A dry run is the default: it shows how many rows would change, the old and new
totals, and why the rest are left alone. --apply re-plans and writes; every
changed row is logged with its previous cost, and --revert <run-id> puts them
back. Nothing is re-priced automatically.

What is never re-priced:
  - a cost the capture source stated itself (native telemetry, an SDK or OTLP
    span, a tool that reports its own cost) is kept as stated;
  - a row with no rate for its model at that time stays unknown, never $0;
  - transcript rows stored at $0 are already priced at the rate in force for
    their timestamp whenever the dashboard reads them, so there is nothing
    to rewrite.

--since / --until take YYYY-MM-DD, RFC3339, or Nd (N days ago). A date in
--until covers that whole UTC day; an RFC3339 --until is exclusive. On an org-enrolled node, re-priced proxy turns are
re-sent to the org by the normal push; the output says when an
` + "`observer org resync`" + ` is also needed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := o.resolve(time.Now())
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			cfg, database, cleanup, err := loadConfigAndDB(ctx, o.configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			svc := newRepriceService(ctx, cfg, database, slog.Default(),
				repriceCLIGovernance(ctx, cfg, database, slog.Default()))
			return runReprice(ctx, cmd.OutOrStdout(), svc, mode, o, repriceCLIActor())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.configPath, "config", "", "Path to config.toml")
	f.BoolVar(&o.apply, "apply", false, "Re-plan and write the changes (prints the plan first)")
	f.Int64Var(&o.revert, "revert", 0, "Undo re-price run `id` (restores each row it changed, where nothing newer has)")
	f.BoolVar(&o.list, "list", false, "List recent re-price runs")
	f.StringVar(&o.since, "since", "", "Window start: YYYY-MM-DD, RFC3339, or Nd (default: the beginning)")
	f.StringVar(&o.until, "until", "", "Window end: YYYY-MM-DD (whole day included), RFC3339 (exclusive), or Nd (default: now)")
	f.StringVar(&o.model, "model", "", "Only rows with exactly this stored model id")
	f.BoolVar(&o.jsonOut, "json", false, "Emit JSON (the dashboard's plan / run shapes)")
	return cmd
}

// repriceCLIActor names the local user a CLI run is recorded under.
func repriceCLIActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}

// repriceRunner is the slice of the service runReprice drives.
type repriceRunner interface {
	Plan(ctx context.Context, f repricesvc.Filter) (repricesvc.Plan, error)
	Apply(ctx context.Context, req repricesvc.Request) (store.RepriceRun, error)
	Revert(ctx context.Context, runID int64, actor string) (store.RepriceRun, error)
	Runs(ctx context.Context, limit int) ([]store.RepriceRun, error)
}

// runReprice executes one mode against svc, writing to out.
func runReprice(ctx context.Context, out io.Writer, svc repriceRunner, mode repriceMode, o repriceOpts, actor string) error {
	filter := repricesvc.Filter{Since: o.since, Until: o.until, Model: o.model}
	switch mode {
	case repriceModeList:
		runs, err := svc.Runs(ctx, 20)
		if err != nil {
			return err
		}
		if o.jsonOut {
			return writeRepriceJSON(out, repricesvc.ViewRuns(runs))
		}
		printRepriceRuns(out, runs)
		return nil
	case repriceModeRevert:
		run, err := svc.Revert(ctx, o.revert, actor)
		if err != nil && run.ID == 0 {
			return err
		}
		if o.jsonOut {
			if jerr := writeRepriceJSON(out, repricesvc.ViewRun(run)); jerr != nil {
				return jerr
			}
			return err
		}
		printRepriceRevert(out, run)
		return err
	}
	plan, err := svc.Plan(ctx, filter)
	if err != nil {
		return err
	}
	if mode == repriceModePlan {
		if o.jsonOut {
			return writeRepriceJSON(out, plan.View())
		}
		printRepricePlan(out, plan, true)
		return nil
	}
	if !o.jsonOut {
		printRepricePlan(out, plan, false)
	}
	// Apply the window the plan RESOLVED, not the raw flags: "7d" re-read a
	// moment later is a different instant, and the digest would never match.
	resolvedFilter := repricesvc.Filter{Since: plan.Since, Until: plan.Until, Model: plan.Model}
	run, err := svc.Apply(ctx, repricesvc.Request{Filter: resolvedFilter, Actor: actor, Digest: plan.Digest})
	var changed *repricesvc.PlanChangedError
	if errors.As(err, &changed) {
		if o.jsonOut {
			_ = writeRepriceJSON(out, map[string]any{"error": "plan_changed", "plan": changed.Plan.View()})
		}
		return errors.New("observer reprice: prices or rows changed between the plan and the apply; nothing was written. Run it again")
	}
	if err != nil && run.ID == 0 {
		return err
	}
	if o.jsonOut {
		if jerr := writeRepriceJSON(out, map[string]any{"plan": plan.View(), "run": repricesvc.ViewRun(run)}); jerr != nil {
			return jerr
		}
		return err
	}
	printRepriceApplied(out, run, plan)
	return err
}

func writeRepriceJSON(out io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}

// repriceSkipWhy is the plain reading of every skip reason (planner and
// revert), one row per reason. A reason missing here prints bare.
var repriceSkipWhy = map[string]string{
	string(reprice.ReasonSourceReported): "the capture source stated this cost itself; kept as stated",
	string(reprice.ReasonNoModel):        "no model recorded, so no rate applies",
	string(reprice.ReasonNoTimestamp):    "the timestamp could not be read; never priced at today's rate",
	string(reprice.ReasonNoPrice):        "no rate for the model at that time; left as it was",
	string(reprice.ReasonInvalidPrice):   "the rate table gave an unusable figure; left as it was",
	string(reprice.ReasonFastUnknown):    "the fast tier is unknown for this row; left as it was",
	string(reprice.ReasonUnchanged):      "already at the price in force",
	string(reprice.ReasonRowGone):        "the row no longer exists",
	string(reprice.ReasonLaterRun):       "a later re-price run changed it since; revert that run first",
	string(reprice.ReasonChangedSince):   "a capture path rewrote its cost since; the newer figure is kept",
}

func repriceUSD(v float64) string {
	if v < 0 {
		return fmt.Sprintf("-$%.4f", -v)
	}
	return fmt.Sprintf("$%.4f", v)
}

func repriceSignedUSD(v float64) string {
	if v >= 0 {
		return "+" + repriceUSD(v)
	}
	return repriceUSD(v)
}

func repriceBound(s, empty string) string {
	if s == "" {
		return empty
	}
	return s
}

func printRepriceSkipped(out io.Writer, skipped map[string]int) {
	if len(skipped) == 0 {
		return
	}
	keys := make([]string, 0, len(skipped))
	for k := range skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(out, "Left alone:")
	for _, k := range keys {
		why := repriceSkipWhy[k]
		if why != "" {
			why = " - " + why
		}
		fmt.Fprintf(out, "  %-24s %8d%s\n", k, skipped[k], why)
	}
}

func printRepricePlan(out io.Writer, p repricesvc.Plan, dry bool) {
	title := "Re-price stored costs"
	if dry {
		title += " (dry run, nothing written)"
	}
	fmt.Fprintln(out, title)
	fmt.Fprintf(out, "Pricing:  %s\n", p.Pricing.Description)
	model := p.Model
	if model == "" {
		model = "all models"
	}
	fmt.Fprintf(out, "Window:   %s to %s, %s\n", repriceBound(p.Since, "the beginning"), repriceBound(p.Until, "now"), model)
	s := p.Summary
	tables := make([]string, 0, len(s.Tables))
	for _, t := range s.Tables {
		tables = append(tables, fmt.Sprintf("%s %d", t.Table, t.Scanned))
	}
	fmt.Fprintf(out, "Scanned:  %d row(s) (%s)\n", s.Scanned, strings.Join(tables, ", "))
	fmt.Fprintf(out, "Changes:  %d row(s), %d of them captured with no price and now priced\n", s.Changed, s.Filled)
	fmt.Fprintf(out, "Totals:   %s before, %s after, %s\n", repriceUSD(s.OldUSD), repriceUSD(s.NewUSD), repriceSignedUSD(s.DeltaUSD()))
	skipped := map[string]int{}
	for k, v := range s.Skipped {
		skipped[string(k)] = v
	}
	printRepriceSkipped(out, skipped)
	if len(s.Models) > 0 {
		fmt.Fprintln(out, "Top models by change:")
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  MODEL\tROWS\tBEFORE\tAFTER\tCHANGE")
		for i, m := range s.Models {
			if i == 10 {
				break
			}
			fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\n", m.Model, m.Changed, repriceUSD(m.OldUSD), repriceUSD(m.NewUSD), repriceSignedUSD(m.DeltaUSD()))
		}
		_ = tw.Flush()
	}
	fmt.Fprintln(out, "Not re-priced: costs a capture source stated itself are kept as stated, and")
	fmt.Fprintln(out, "  transcript rows stored at $0 are already priced at the rate in force for their")
	fmt.Fprintln(out, "  timestamp whenever the dashboard reads them.")
	fmt.Fprintf(out, "Org:      %s\n", p.Org.Note)
	if dry {
		if s.Changed == 0 {
			fmt.Fprintln(out, "Nothing to change.")
			return
		}
		fmt.Fprintln(out, "Run again with --apply to write these changes. Every change is logged and")
		fmt.Fprintln(out, "can be undone with `observer reprice --revert <run-id>`.")
	}
}

func printRepriceApplied(out io.Writer, run store.RepriceRun, p repricesvc.Plan) {
	fmt.Fprintf(out, "\nApplied run #%d (%s): %d row(s) changed, %d filled, %s before, %s after, %s.\n",
		run.ID, run.Status, run.Changed, run.Filled, repriceUSD(run.OldUSD), repriceUSD(run.NewUSD), repriceSignedUSD(run.DeltaUSD))
	if run.CASMissed > 0 {
		fmt.Fprintf(out, "%d row(s) were rewritten by a capture path after the plan and were left with the newer figure.\n", run.CASMissed)
	}
	for _, w := range run.Warnings {
		fmt.Fprintf(out, "Warning: %s\n", w)
	}
	if p.Org.Enrolled && p.Org.ResendBelowFloor > 0 {
		fmt.Fprintf(out, "Org: %s\n", p.Org.Note)
	}
	fmt.Fprintf(out, "Undo with `observer reprice --revert %d`.\n", run.ID)
}

func printRepriceRevert(out io.Writer, run store.RepriceRun) {
	fmt.Fprintf(out, "Reverted run #%d as run #%d (%s): %d row(s) restored, %s before, %s after, %s.\n",
		run.RevertsRun, run.ID, run.Status, run.Changed, repriceUSD(run.OldUSD), repriceUSD(run.NewUSD), repriceSignedUSD(run.DeltaUSD))
	printRepriceSkipped(out, run.Summary.Skipped)
	for _, w := range run.Warnings {
		fmt.Fprintf(out, "Warning: %s\n", w)
	}
}

func printRepriceRuns(out io.Writer, runs []store.RepriceRun) {
	if len(runs) == 0 {
		fmt.Fprintln(out, "No re-price runs yet. `observer reprice` shows a dry run.")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tWHEN\tSTATUS\tROWS\tCHANGE\tPRICING\tWINDOW\tACTOR")
	for _, r := range runs {
		kind := r.Kind
		if r.RevertsRun != 0 {
			kind = fmt.Sprintf("revert of #%d", r.RevertsRun)
		}
		status := r.Status
		if r.RevertedByRun != 0 {
			status = fmt.Sprintf("reverted by #%d", r.RevertedByRun)
		}
		pricing := r.PricingSource
		if r.PricingVersion != 0 {
			pricing = fmt.Sprintf("%s v%d", pricing, r.PricingVersion)
		}
		window := repriceBound(r.Since, "start") + " to " + repriceBound(r.Until, "now")
		if r.Model != "" {
			window += " (" + r.Model + ")"
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", r.ID, kind, r.CreatedAt, status, r.Changed, repriceSignedUSD(r.DeltaUSD), pricing, window, r.Actor)
	}
	_ = tw.Flush()
}
