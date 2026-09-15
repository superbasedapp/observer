package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/pricingfeedgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// pricingautosync.go is the OPT-IN background pricing-feed poller (docs/plans/
// pricing-sync-tokenomics-to-platform-plan-2026-09-11.md §C.3, D2/D3), built on
// the cloudautosync.go precedent.
//
// # Why it runs the sync ladder IN-PROCESS (finding F5)
//
// It used to spawn `observer pricing sync` as a subprocess. That kept the
// egress invariant trivially (the daemon's always-on packages linked nothing of
// the network lane) but it had a real defect: the subprocess rebuilt ITS OWN
// cost engine and exited, while the running daemon's engine reads the feed cache
// only at construction. With auto=true the daemon therefore kept stamping
// api_turns.cost_usd at the OLD feed until a restart — which the runbook forbids
// while the proxy route is live. So the synced feed never reached the running
// daemon.
//
// It now runs the SAME ladder (runPricingSync in pricing.go) in-process and, on
// an applied feed, pushes the fresh rows into the PROCESS-WIDE cost engine
// (lookupProcessCostEngine(dbPath).SetOrgRows) exactly the way orgpricing_wire.go
// does for the ORG rail. The daemon re-prices live, no restart.
//
// The egress invariant still holds. tests/invariant/pricing_feed_egress_test.go
// forbids only the always-on daemon packages (watcher / proxy / store / hook /
// orgclient) from LINKING the network lane, and requires the lane be reached
// only through internal/pricingfeedgate. This file is in cmd/observer, which is
// NOT one of those packages and which already links the gate (pricing.go); it
// reaches the network through pricingfeedgate alone and names no /client type in
// production code, so both guards stay green.
//
// It is INERT unless BOTH [pricing.feed].enabled AND [pricing.feed].auto are
// true (D3: off by default, so the node's first outbound price call is always
// operator-initiated). runPricingSync itself REFUSES on an enrolled node, so
// there is no need to re-check enrolment before calling it (we still read
// enrolment to pass the flag).
//
// WIRING: started as a fail-soft g.Go from `observer start` beside the cloud
// poller; a manual `observer pricing sync` (or an external cron/systemd timer)
// remains a valid trigger too.

// pricingAutoSyncFunc runs one poller tick. Injectable so a test drives a single
// cycle with a fake fetcher and no network, observing the process engine after.
type pricingAutoSyncFunc func(ctx context.Context, cfg config.Config, errOut io.Writer)

// runPricingAutoSyncFromConfig is the daemon entry point (a fail-soft g.Go in
// start.go). It loads config once and runs the scheduler only if the feed is
// both enabled AND auto; otherwise it returns immediately. Fail-soft: a
// config-load error is swallowed, since a background convenience must never
// break startup.
func runPricingAutoSyncFromConfig(ctx context.Context, out, errOut io.Writer, configPath string) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	runPricingAutoSync(ctx, cfg, out, errOut, func(c context.Context, cf config.Config, eo io.Writer) {
		// Production tick: the real network lane (Options.Fetcher nil) reached
		// through the gate, URL from config.
		pricingAutoSyncOnce(c, cf, pricingfeedgate.Options{}, eo)
	})
}

// runPricingAutoSync is the scheduler. Inert unless enabled AND auto; announces
// its cadence once, fires immediately, then on a ticker.
func runPricingAutoSync(ctx context.Context, cfg config.Config, out, errOut io.Writer, tick pricingAutoSyncFunc) {
	fc := cfg.Pricing.Feed
	if !fc.Enabled || !fc.Auto {
		return // opt-in only; nothing to run.
	}
	hours := fc.PollIntervalHours
	if hours <= 0 {
		hours = 24 // D2 default; never a zero-interval busy loop.
	}
	interval := time.Duration(hours) * time.Hour
	fmt.Fprintf(out, "  pricing feed auto-sync → every %s (in-process; re-prices the live daemon; standalone nodes only — refuses when enrolled)\n", interval)
	pricingAutoSyncLoop(ctx, cfg, interval, errOut, tick)
}

// pricingAutoSyncLoop fires an immediate sync, then one per interval, until the
// context is cancelled. Split out so a test can drive it at a sub-second
// interval.
func pricingAutoSyncLoop(ctx context.Context, cfg config.Config, interval time.Duration, errOut io.Writer, tick pricingAutoSyncFunc) {
	tick(ctx, cfg, errOut) // poll immediately so a freshly-enabled node does not wait a full interval.
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick(ctx, cfg, errOut)
		}
	}
}

// pricingAutoSyncOnce runs ONE in-process sync cycle: open the node db, run the
// fetch-verify-apply ladder through the egress gate, and — on an applied feed —
// push the freshly-verified rows into the PROCESS-WIDE cost engine so a running
// daemon re-prices without a restart (finding F5).
//
// opts lets a test inject a fake fetcher and a throwaway key set; production
// passes the zero value and the real network lane is built from config. The URL
// defaults from config when the caller left it empty.
//
// Every failure is a logged line, never a return: a background convenience must
// never surface an error the daemon would treat as fatal. A refusal (unreachable
// / unverified / replay) is SILENT here, exactly as the old subprocess poller
// was (the CLI exited 0 on a refusal), so a transient outage does not spam the
// log every interval.
func pricingAutoSyncOnce(ctx context.Context, cfg config.Config, opts pricingfeedgate.Options, errOut io.Writer) {
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(errOut, "pricing feed auto-sync: open db: %v\n", err)
		}
		return
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)

	enr, eerr := st.LoadEnrolment(ctx)
	if eerr != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(errOut, "pricing feed auto-sync: read enrolment: %v\n", eerr)
		}
		return
	}

	if opts.URL == "" {
		opts.URL = cfg.Pricing.Feed.URL
	}
	res, err := runPricingSync(ctx, st, enr != nil, opts)
	if ctx.Err() != nil {
		return // shutdown raced the sync; its error, if any, is shutdown noise.
	}
	if err != nil {
		fmt.Fprintf(errOut, "pricing feed auto-sync: %v\n", err)
		return
	}
	if !res.Applied {
		return // refusal / 304 / enrolled — the cache is unchanged, nothing to re-price.
	}

	// Re-price the DAEMON's live engine. lookupProcessCostEngine returns the one
	// engine buildProxy registered for this db path; a one-shot process that ran
	// this with no proxy assembled has none, and then there is simply nothing to
	// update live (the durable cache is still written, so a later start picks it
	// up). feedOrgRows re-reads exactly the bytes just persisted and projects
	// them onto the engine's input; the feed composes NON-authoritatively (false),
	// so a developer's own [intelligence.pricing] override still wins.
	engine := lookupProcessCostEngine(cfg.Observer.DBPath)
	if engine == nil {
		return
	}
	rows, ok := feedOrgRows(ctx, st, slog.Default())
	if !ok {
		return
	}
	engine.SetOrgRows(rows.Rows, rows.Version, false)
}
