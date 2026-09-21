package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgpricing"
	"github.com/marmutapp/superbased-observer/internal/pricingfeedgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// pricing.go is the `observer pricing` command family — the STANDALONE node's
// manual pricing-feed controls (docs/plans/pricing-sync-tokenomics-to-platform-
// plan-2026-09-11.md §C.3, Wave N).
//
// `observer pricing sync` is the ONE typed egress: a human (or the opt-in auto
// poller, which spawns this exact command) fetches the public feed through the
// import-isolated internal/pricingfeedgate seam, verifies it offline against the
// compiled vendor key, refuses an unsigned / mis-signed / version-regressed
// body, persists the verified envelope, and rebuilds the cost engine. It
// REFUSES on an enrolled node, where prices arrive through the org rail instead
// (§C.3/D8).
//
// `observer pricing status` reports, without touching the network, where each
// model's rate comes from (seed / feed / org / local), the applied feed version
// and when it was fetched, and a summary of the per-model economics the feed
// carried.

// pricingSyncState is the closed outcome vocabulary of one sync. It mirrors the
// org rail's PricingFetch* enum in spirit: a refusal is a state, not a crash.
const (
	pricingSyncVerified        = "verified"         // a new signed body was applied
	pricingSyncNotModified     = "not_modified"     // 304 — the applied body is current
	pricingSyncUnreachable     = "unreachable"      // transport/status/decode failure; cache kept
	pricingSyncUnverified      = "unverified"       // signature/schema/replay refusal; cache kept
	pricingSyncRefusedEnrolled = "refused_enrolled" // enrolled node — the public feed is not consulted
)

// pricingSyncResult is the structured outcome of runPricingSync, so the ladder
// is testable without a process or a terminal.
type pricingSyncResult struct {
	State       string `json:"state"`
	Applied     bool   `json:"applied"`
	FeedVersion int64  `json:"feed_version"`
	ModelCount  int    `json:"model_count"`
	Message     string `json:"message"`
}

func newPricingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pricing",
		Short: "Standalone-node public pricing-feed controls (sync / status)",
		Long: "Manages the OPT-IN public pricing feed for a STANDALONE (non-enrolled) node.\n" +
			"An org-enrolled node receives prices through its org rail and ignores the\n" +
			"public feed entirely, so `pricing sync` refuses there.\n\n" +
			"The compiled Go seed remains the last-resort fallback; the feed only\n" +
			"supersedes it at runtime, for the models it names, without a package update.",
	}
	cmd.AddCommand(newPricingSyncCmd())
	cmd.AddCommand(newPricingStatusCmd())
	return cmd
}

func newPricingSyncCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Fetch, verify, and apply the public pricing feed (standalone nodes only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			enr, eerr := st.LoadEnrolment(ctx)
			if eerr != nil {
				return fmt.Errorf("observer pricing sync: read enrolment: %w", eerr)
			}
			enrolled := enr != nil

			res, err := runPricingSync(ctx, st, enrolled, pricingfeedgate.Options{
				URL: cfg.Pricing.Feed.URL,
				// Keys zero -> the compiled vendor key set (pricingfeed.CompiledKeySet).
			})
			if err != nil {
				return err
			}
			// Apply to the process engine so a follow-up `pricing status` in this
			// same invocation (and any same-process caller) reflects the new rates.
			// A RUNNING daemon is a SEPARATE process: this call cannot reach its
			// engine. It applies the freshly-persisted feed live on its next
			// auto-sync poll (the in-process poller, when [pricing.feed].auto is
			// on — pricingautosync.go) or, failing that, on its next start from
			// the durable cache. The message below says exactly this.
			if res.Applied {
				acquireProcessCostEngine(ctx, cfg, database, slog.Default())
			}
			if jsonOut {
				body, _ := json.MarshalIndent(res, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			fmt.Fprintln(cmd.OutOrStdout(), res.Message)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the sync outcome as JSON")
	return cmd
}

// runPricingSync is the fetch-apply ladder, separated from cobra so httptest can
// drive it with an injected key set / fetcher.
//
// FAIL-OPEN on transport and trust: every non-verified path keeps the cache
// exactly as it was (only a verified, non-replay body ever calls
// store.SavePricingFeed), which is what makes "only a SIGNED body may ever
// empty this node's table" true by construction. The function never returns an
// error for a refusal — a refusal is a STATE — and returns an error only for an
// unexpected local failure (a DB write that fails after verification).
func runPricingSync(ctx context.Context, st *store.Store, enrolled bool, opts pricingfeedgate.Options) (pricingSyncResult, error) {
	if enrolled {
		return pricingSyncResult{
			State: pricingSyncRefusedEnrolled,
			Message: "this node is enrolled with an organization — prices arrive through your org rail " +
				"(GET /api/agent/pricing); the public pricing feed is not consulted (plan §C.3/D8).",
		}, nil
	}

	cache, cerr := st.LoadPricingFeed(ctx)
	if cerr != nil {
		// A corrupt cache is treated as absent: a fresh fetch can replace it.
		cache = store.PricingFeedCache{}
	}
	opts.LastDigest = cache.Digest

	res, err := pricingfeedgate.Fetch(ctx, opts)
	if err != nil {
		state := pricingSyncUnverified
		if pricingfeedgate.IsTransportError(err) {
			state = pricingSyncUnreachable
		}
		return pricingSyncResult{
			State:   state,
			Message: fmt.Sprintf("pricing feed not applied (%s): %v — keeping the previously applied prices.", state, err),
		}, nil
	}
	if res.NotModified {
		return pricingSyncResult{
			State:       pricingSyncNotModified,
			FeedVersion: cache.Version,
			Message:     fmt.Sprintf("pricing feed unchanged (feed v%d); nothing to apply.", cache.Version),
		}, nil
	}

	env := res.Envelope
	// VERSION MONOTONICITY. The signature binds FeedVersion, but binding it only
	// helps if we check it: an intermediary could replay an older correctly
	// signed body over a newer one, and every turn priced afterwards would carry
	// the wrong rate permanently. Equal is fine (a corrected-in-place rate at the
	// same version arrives as a 200 because its digest changed). Lower is ALWAYS
	// a replay — refused, cache kept.
	//
	// There is NO key-rotation exemption (finding F9). A rotation does NOT
	// restart the publisher's version lineage: during the overlap window BOTH the
	// current and previous vendor keys verify (vendorkey.go), so exempting a key
	// change would let a body signed by the old key replay an older version over
	// a newer one — exactly the hole this check closes. FeedVersion is the single
	// monotonic lineage regardless of which accepted key signed the body, and the
	// org PRICING importer has no such exemption either.
	if cache.Have && env.FeedVersion < cache.Version {
		return pricingSyncResult{
			State: pricingSyncUnverified,
			Message: fmt.Sprintf("refusing pricing feed v%d, older than the applied v%d (replay); keeping the applied prices.",
				env.FeedVersion, cache.Version),
		}, nil
	}

	// Persist the VERBATIM verified bytes (res.Raw), not a typed re-marshal of
	// env: a re-marshal drops any row field this build does not model, and the
	// reloaded feed would then fail pricingfeed.Verify on the next start and
	// revert the whole table to seed (N1 / P2-0).
	if err := st.SavePricingFeedRaw(ctx, env, res.Raw, pricingSyncVerified); err != nil {
		return pricingSyncResult{}, fmt.Errorf("observer pricing sync: persist verified feed: %w", err)
	}
	return pricingSyncResult{
		State:       pricingSyncVerified,
		Applied:     true,
		FeedVersion: env.FeedVersion,
		ModelCount:  len(env.Rows),
		// HONEST about reach (finding F5): a one-shot `observer pricing sync`
		// re-prices only ITS OWN process. A separately-running daemon applies
		// the freshly-persisted feed live on its next auto-sync poll (when the
		// in-process poller is active, i.e. [pricing.feed].auto is on), else at
		// its next start — never mid-flight from this CLI, which cannot reach
		// the daemon's engine across the process boundary.
		Message: fmt.Sprintf("applied pricing feed v%d (%d models) and persisted it; this process re-priced. "+
			"A running daemon applies it live on its next auto-sync poll when [pricing.feed].auto is on, otherwise at its next start.",
			env.FeedVersion, len(env.Rows)),
	}, nil
}

func newPricingStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the effective price source per model, feed version, and economics",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			enr, _ := st.LoadEnrolment(ctx)
			enrolled := enr != nil
			cache, _ := st.LoadPricingFeed(ctx)
			engine := acquireProcessCostEngine(ctx, cfg, database, slog.Default())

			// The org-rail half of the answer comes from the SAME resolver the
			// guard's pricing line uses, so the two surfaces cannot disagree
			// about whether this node applies its org's rates.
			orgRail, _ := orgpricing.Mode(cfg.Guard.Budget,
				budgetEnforcementGranted(ctx, cfg, database, slog.Default()))
			rep := buildPricingStatus(cfg.Pricing.Feed.Enabled, cfg.Pricing.Feed.Auto, cfg.Pricing.Feed.URL,
				cfg.Pricing.Feed.PollIntervalHours, enrolled, orgRail, cache, engine)
			if jsonOut {
				body, _ := json.MarshalIndent(rep, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			printPricingStatus(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the status as JSON")
	return cmd
}

// pricingStatusModelEconomics is the per-model economics summary line.
type pricingStatusModelEconomics struct {
	Model            string `json:"model"`
	CacheMode        string `json:"cache_mode,omitempty"`
	ReasoningBilling string `json:"reasoning_billing,omitempty"`
}

// pricingStatusReport is the `observer pricing status` payload.
type pricingStatusReport struct {
	FeedEnabled       bool   `json:"feed_enabled"`
	FeedAuto          bool   `json:"feed_auto"`
	FeedURL           string `json:"feed_url"`
	PollIntervalHours int    `json:"poll_interval_hours"`
	Enrolled          bool   `json:"enrolled"`
	FeedApplies       bool   `json:"feed_applies"`
	// OrgRailApplies is [guard.budget].from_org resolved through
	// orgpricing.Mode — the SAME resolver `observer guard status`'s pricing
	// line reads (cmd/observer/orgpricing_wire.go::guardPricingLine).
	//
	// It exists because the two surfaces disagreed: this one said "prices come
	// from the org rail" for every enrolled node, while guard status said "the
	// built-in rate table ([guard.budget].from_org is off...)" for the same
	// machine. Both cannot be true, and the second was right — an enrolled node
	// with from_org off consults NEITHER the public feed (it is enrolled) NOR
	// its org's rates (it opted out), so it prices at seed plus any local
	// override. One resolver, two surfaces.
	OrgRailApplies bool                          `json:"org_rail_applies"`
	FeedVersion    int64                         `json:"feed_version"`
	FeedFetchedAt  string                        `json:"feed_fetched_at,omitempty"`
	FeedState      string                        `json:"feed_state,omitempty"`
	ModelSources   map[string]string             `json:"model_sources"`
	Economics      []pricingStatusModelEconomics `json:"economics,omitempty"`
}

// buildPricingStatus composes the status report from config + the feed cache +
// the cost engine. The per-model `source` is the ENGINE's own resolution
// (so it cannot drift from what the next turn is priced at), with one honest
// relabel: on a standalone node a composed "org" rate IS the feed, because a
// standalone node has no org rows — the only org-shaped input it has is the
// public feed.
func buildPricingStatus(enabled, auto bool, url string, interval int, enrolled, orgRailApplies bool, cache store.PricingFeedCache, engine *cost.Engine) pricingStatusReport {
	rep := pricingStatusReport{
		FeedEnabled:       enabled,
		FeedAuto:          auto,
		FeedURL:           url,
		PollIntervalHours: interval,
		Enrolled:          enrolled,
		// orgpricing.FeedApplies, not a restatement of it: the standalone rule
		// has one owner (§C.3 / D8).
		FeedApplies:    orgpricing.FeedApplies(enrolled),
		OrgRailApplies: orgRailApplies,
		ModelSources:   map[string]string{},
	}
	if cache.Have {
		rep.FeedVersion = cache.Envelope.FeedVersion
		rep.FeedState = cache.State
		if !cache.FetchedAt.IsZero() {
			rep.FeedFetchedAt = cache.FetchedAt.UTC().Format(time.RFC3339)
		}
		models := make([]string, 0, len(cache.Envelope.Rows))
		for _, r := range cache.Envelope.Rows {
			if r.Economics == nil {
				continue
			}
			models = append(models, r.Model)
			rep.Economics = append(rep.Economics, pricingStatusModelEconomics{
				Model:            r.Model,
				CacheMode:        r.Economics.CacheMode,
				ReasoningBilling: r.Economics.ReasoningBilling,
			})
		}
		_ = models
	}

	feedActive := !enrolled && cache.Have
	if engine != nil {
		if table := engine.Table(); table != nil {
			for _, model := range table.Known() {
				_, src, ok := engine.LookupWithSource(model)
				if !ok {
					continue
				}
				rep.ModelSources[model] = pricingSourceLabel(src, feedActive)
			}
		}
	}
	return rep
}

// enrolledFeedLine renders the "applies" line for an ENROLLED node. The feed
// never applies there (orgpricing.FeedApplies); what differs is what the node
// prices from INSTEAD, and that is the org rail only when the node opted into
// it. Two rows, because the two states are different facts and the old single
// sentence asserted the wrong one for every node with from_org off.
func enrolledFeedLine(orgRailApplies bool) string {
	if orgRailApplies {
		return "no — node is enrolled; prices come from the org rail"
	}
	return "no — node is enrolled, and [guard.budget].from_org is off, so the org's " +
		"negotiated rates are not applied either; prices come from the built-in table " +
		"plus any [intelligence.pricing] override"
}

// pricingSourceLabel maps the engine's resolution onto the four-value source
// vocabulary this surface reports: seed / local / org / feed. The engine
// reports feed-composed rows as PricingSourceOrg (they ride the same OrgRows
// input), so `org` is relabelled to `feed` when the feed is the active
// org-shaped source on a standalone node.
func pricingSourceLabel(src cost.PricingSource, feedActive bool) string {
	switch src {
	case cost.PricingSourceOrg:
		if feedActive {
			return "feed"
		}
		return "org"
	case cost.PricingSourceLocal:
		return "local"
	default:
		return "seed"
	}
}

func printPricingStatus(w io.Writer, rep pricingStatusReport) {
	bw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	defer func() { _ = bw.Flush() }()
	posture := "manual only"
	switch {
	case !rep.FeedEnabled:
		posture = "off (no feed fetch; manual `observer pricing sync` still works)"
	case rep.FeedAuto:
		posture = fmt.Sprintf("auto every %dh + manual", rep.PollIntervalHours)
	}
	fmt.Fprintf(bw, "Pricing feed\t%s\n", posture)
	fmt.Fprintf(bw, "  url\t%s\n", rep.FeedURL)
	switch {
	case rep.Enrolled:
		fmt.Fprintf(bw, "  applies\t%s\n", enrolledFeedLine(rep.OrgRailApplies))
	case rep.FeedVersion > 0:
		fmt.Fprintf(bw, "  applied\tfeed v%d (fetched %s, %s)\n", rep.FeedVersion, rep.FeedFetchedAt, rep.FeedState)
	default:
		fmt.Fprintf(bw, "  applied\tnone yet — run `observer pricing sync`\n")
	}
	if len(rep.Economics) > 0 {
		fmt.Fprintln(bw, "Economics (feed-carried)")
		sort.Slice(rep.Economics, func(i, j int) bool { return rep.Economics[i].Model < rep.Economics[j].Model })
		for _, e := range rep.Economics {
			fmt.Fprintf(bw, "  %s\tcache=%s reasoning=%s\n", e.Model, pricingOrDash(e.CacheMode), pricingOrDash(e.ReasoningBilling))
		}
	}
	if len(rep.ModelSources) > 0 {
		fmt.Fprintln(bw, "Price source per model")
		keys := make([]string, 0, len(rep.ModelSources))
		for k := range rep.ModelSources {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(bw, "  %s\t%s\n", k, rep.ModelSources[k])
		}
	}
}

func pricingOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
