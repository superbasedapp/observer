package main

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgpricing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ONE PRICE ENGINE PER (PROCESS, observer.db)
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// ruling R13 / finding F3 — the processGuards and cachetrack.Engine precedent,
// applied to the price table.)
//
// THE PROBLEM. `cost.NewEngine(cfg.Intelligence)` had 38 production call
// sites. That was harmless while every one of them built the same table from
// the same compiled seed — but the moment the ORG's negotiated rates become an
// input, 38 tables means 38 answers: the proxy could stamp
// api_turns.cost_usd at the org rate while the org-push pricer stamped
// token_usage.estimated_cost_usd at list, and the node's own guard reads
// MAX(SUM(api_turns.cost_usd), SUM(token_usage.estimated_cost_usd)) — so the
// budget would be enforced against whichever of the two happened to be higher.
//
// THE SHAPE, and why it is a registry rather than a threaded parameter.
// `observer start` assembles the proxy, the watcher, the dashboard and the org
// push bundle through separate build functions, each opening its own handle
// over the SAME SQLite file; buildProxy alone already returns seven values.
// Threading an engine through all of them would touch every signature on the
// way and would still not reach `observer cost`. Keying ONE engine per
// (process, db path) is the identical problem processGuards already solved for
// the guard's daemon-wide taint state, and it makes a CLI one-shot pick up the
// same instance for free when it happens to run in the same process.
//
// WHAT IT DOES NOT DO. It does not make a HOOK process share the daemon's
// engine — hook processes are short-lived and separate by design, exactly as
// they are for the guard. They construct through the same constructor with the
// same loader, so they price the same way; they just do not share memory.

var processCostEngines = struct {
	mu sync.Mutex
	m  map[string]*cost.Engine
}{m: map[string]*cost.Engine{}}

// acquireProcessCostEngine returns the per-(process, db-path) shared cost
// engine, constructing it on first call with the org's persisted price
// document already composed in.
//
// database may be nil (a caller with no handle yet): the engine is then built
// from seed + local only, and the org rows arrive later through
// [cost.Engine.SetOrgRows] when the rail delivers. That is the fail-open
// direction and it is the honest one — an engine with no rates at all would
// price every turn at $0 and make every budget look unspent.
func acquireProcessCostEngine(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) *cost.Engine {
	key := cfg.Observer.DBPath
	processCostEngines.mu.Lock()
	defer processCostEngines.mu.Unlock()
	if e, ok := processCostEngines.m[key]; ok {
		return e
	}
	e := cost.NewEngine(cfg.Intelligence, cost.WithOrgRows(orgPricingLoader(ctx, cfg, database, logger)))
	// A DB-LESS construction is NEVER cached. Two call sites in the daemon
	// (the routing refresher and the advisor's posture read) hold a Store but
	// no *sql.DB, so they pass nil — and caching the engine they build would
	// mean whichever of them ran first permanently denied every later caller
	// the org's rates. Not caching costs one extra seed-table build in the
	// rare case they run before the proxy composes; caching would cost the
	// whole feature, silently.
	if key != "" && database != nil {
		processCostEngines.m[key] = e
	}
	return e
}

// lookupProcessCostEngine returns the already-constructed engine for a db path
// WITHOUT building one, or nil when no composition site has asked yet.
//
// It exists for the same reason lookupProcessGuard does: the org pricing
// boundary is wired AFTER buildProxy has already composed the shared engine,
// and constructing here instead would create exactly the second engine this
// registry exists to prevent.
func lookupProcessCostEngine(dbPath string) *cost.Engine {
	processCostEngines.mu.Lock()
	defer processCostEngines.mu.Unlock()
	return processCostEngines.m[dbPath]
}

// orgPricingLoader builds the one-shot loader [cost.WithOrgRows] calls at
// construction: read the node's persisted org price document and resolve the
// tenancy ladder for it.
//
// EVERY constructor gets this loader, including the standalone CLI ones, and
// that is the point of ruling N5: `observer cost` reading the same persisted
// document through the same orgpricing.Mode is what stops a developer's own
// report from disagreeing with the dashboard about what a session cost.
//
// It returns ok=false — leaving the engine on seed + local — whenever the node
// has not opted in ([guard.budget].from_org), has no handle, or has no stored
// document. None of those is an error worth failing a command over.
func orgPricingLoader(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) func() (cost.OrgRows, bool) {
	return func() (cost.OrgRows, bool) {
		if database == nil {
			return cost.OrgRows{}, false
		}
		st := store.New(database)
		// ENROLMENT decides the price source FIRST (finding F6). An org price
		// document is the ORG's; a node that is not - or no longer - enrolled
		// has no claim on it, even if a stale copy survives on disk and
		// [guard.budget].from_org is still set in TOML. (The prior order applied
		// org_pricing_cache whenever from_org && cached.Have BEFORE any
		// enrolment check, so a departed node kept pricing at the dead org's
		// rates.) Resolving this here, ONCE, is the orgpricing.Mode precedent:
		// the daemon and every CLI one-shot must agree on which source applies.
		enr, eerr := st.LoadEnrolment(ctx)
		if eerr != nil {
			// Can't tell whether we're enrolled. The safe direction is to apply
			// NEITHER source rather than risk layering a public list price onto
			// a possibly-enrolled node, or a stale org document onto a node that
			// left - seed + local, fail-open.
			if logger != nil {
				logger.Warn("pricing: enrolment unreadable; pricing from the seed table", "err", eerr)
			}
			return cost.OrgRows{}, false
		}

		if enr != nil {
			// ENROLLED (individual or managed): prices arrive through the org
			// rail ONLY, under the tenancy gate ([guard.budget].from_org via
			// orgpricing.Mode). The public feed is never consulted for an
			// enrolled node (orgpricing.FeedApplies, §C.3/D8). A node that
			// declined its org's rates (from_org=false) prices at seed+local,
			// NOT at a public list - the feed is the standalone case only.
			fromOrg, authoritative := orgpricing.Mode(cfg.Guard.Budget, budgetEnforcementGranted(ctx, cfg, database, logger))
			if !fromOrg {
				return cost.OrgRows{}, false
			}
			cached, err := st.LoadOrgPricing(ctx)
			if err != nil {
				if logger != nil {
					logger.Warn("org pricing: stored document unreadable; pricing from the seed table", "err", err)
				}
				return cost.OrgRows{}, false
			}
			if !cached.Have {
				return cost.OrgRows{}, false
			}
			// The row is a durable copy of one enrollment epoch. A stale or
			// legacy unbound row may remain on disk after an external
			// re-enrollment; it cannot seed the live table until the pricing
			// client fetches and verifies a document for the current epoch.
			identity, active, ierr := orgclient.CurrentBudgetIdentity(ctx, st)
			if ierr != nil || !active || cached.Binding == "" || cached.Binding != identity.Binding {
				if logger != nil && ierr != nil {
					logger.Warn("pricing: current enrollment identity unavailable; stored org document ignored", "err", ierr)
				}
				return cost.OrgRows{}, false
			}
			if verr := orgclient.VerifyPersistedPricing(ctx, st, cached); verr != nil {
				if logger != nil {
					logger.Warn("pricing: stored org document failed current enrollment/signature verification; pricing from the seed table", "err", verr)
				}
				return cost.OrgRows{}, false
			}
			return cost.OrgRows{
				Rows:          orgPriceRowsOf(cached.Body.Rows),
				Version:       cached.Body.Version,
				Authoritative: authoritative,
				Binding:       cached.Binding,
				Witness:       pricingDocumentWitness(cached.Witness),
			}, true
		}

		// STANDALONE (not enrolled): only the PUBLIC feed may apply, and only
		// because this node has no org rail to take prices from
		// (orgpricing.FeedApplies - trivially true here, kept to document the
		// ruling at the composition site). A node that LEFT its org has already
		// had its org_pricing_cache cleared by DeleteEnrolment, so no stale org
		// document ever reaches here.
		if !orgpricing.FeedApplies(enr != nil) {
			return cost.OrgRows{}, false
		}
		return feedOrgRows(ctx, st, logger)
	}
}

// pricingDocumentWitness converts the storage-owned witness into the neutral
// cost-engine shape without coupling the cost package to SQLite.
func pricingDocumentWitness(w store.OrgPricingWitness) cost.PricingDocumentWitness {
	return cost.PricingDocumentWitness{Known: w.Known, Present: w.Present, SHA256: w.SHA256}
}

// feedOrgRows composes the STANDALONE public pricing feed into the engine's
// org-rows input. It reads the node-local feed cache (agent migration 113,
// through store.LoadPricingFeed — never naming the table here) and projects the
// verified envelope's rows onto cost.OrgPrice.
//
// The feed composes NON-AUTHORITATIVELY, which is the §C.3/D8 ladder made
// concrete: composeOrgRows leaves a developer's own [intelligence.pricing]
// override in force where one exists, so the effective precedence is
// seed -> feed -> local. A public list price is exactly the kind of rate a
// developer's explicit number should win over.
//
// It applies the cache whenever a verified body is present. The
// [pricing.feed].enabled/auto flags gate FETCHING (the one outbound request,
// §C.3); applying an already-synced, already-verified body is pure local
// arithmetic and costs no egress, so gating it would mean fetching a document
// and then refusing to use it.
func feedOrgRows(ctx context.Context, st *store.Store, logger *slog.Logger) (cost.OrgRows, bool) {
	cache, err := st.LoadPricingFeed(ctx)
	if err != nil {
		if logger != nil {
			logger.Warn("pricing feed: stored envelope unreadable; pricing from the seed table", "err", err)
		}
		return cost.OrgRows{}, false
	}
	if !cache.Have || len(cache.Envelope.Rows) == 0 {
		return cost.OrgRows{}, false
	}
	rows := make([]orgcontract.PricingPolicyRow, 0, len(cache.Envelope.Rows))
	for _, r := range cache.Envelope.Rows {
		rows = append(rows, r.PricingPolicyRow)
	}
	return cost.OrgRows{
		Rows:          orgPriceRowsOf(rows),
		Version:       cache.Envelope.FeedVersion,
		Authoritative: false,
	}, true
}

// budgetEnforcementGranted resolves whether this node's governance grant
// carries enforce.budget, from the verified on-disk LKG sidecar.
//
// It reads the LKG rather than taking a live handle because the CLI callers
// have none: `observer cost` runs no policy poller. The daemon overrides this
// answer on its very first pricing notification with the LIVE grant (see
// orgpricing_wire.go), so a revoked grant stops being authoritative on the
// next cycle rather than at the next restart — the LKG is the cold-start
// approximation, not the standing source of truth.
//
// Any failure returns false, which is the INDIVIDUAL ladder: the developer's
// own overrides win. That is the safe direction for a wrong answer — the org
// loses precedence it might have had, rather than a node silently overriding a
// developer's explicit config on the strength of a sidecar it could not read.
func budgetEnforcementGranted(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) bool {
	if database == nil {
		return false
	}
	if logger == nil {
		logger = slog.Default()
	}
	st := store.New(database)
	ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
	loadNodeGovernanceLKG(ctx, cfg, st, ngov, logger)
	return ngov.Effective(ctx).GrantsBudgetEnforcement()
}

// orgPriceRowsOf projects the wire rows onto the engine's input type.
//
// It is a plain field copy and stays that way: the two field sets are
// deliberately identical (orgcontract.PricingPolicyRow is authored in
// cost.Pricing's vocabulary), so anything clever here would be arithmetic
// nobody asked for on a number an org negotiated.
//
// The one thing it MUST carry across is which rates the org actually QUOTED
// (server migration 135): a nil wire rate is "the org quotes nothing here" and
// the engine falls through to the seed or the developer's own override for it,
// while a rate SET to zero is a negotiated FREE rate. Collapsing the two here
// would put the whole cut-over back where it started, silently.
func orgPriceRowsOf(rows []orgcontract.PricingPolicyRow) []cost.OrgPrice {
	out := make([]cost.OrgPrice, 0, len(rows))
	for _, r := range rows {
		p := cost.OrgPrice{
			Model:         r.Model,
			EffectiveFrom: r.EffectiveFrom,
			Pricing:       cost.Pricing{LongContextThreshold: r.LongContextThreshold},
		}
		for _, f := range []struct {
			src *float64
			dst *float64
			set *bool
		}{
			{r.InputPerMTok, &p.Input, &p.Set.Input},
			{r.OutputPerMTok, &p.Output, &p.Set.Output},
			{r.CacheReadPerMTok, &p.CacheRead, &p.Set.CacheRead},
			{r.CacheWritePerMTok, &p.CacheCreation, &p.Set.CacheCreation},
			{r.CacheWrite1hPerMTok, &p.CacheCreation1h, &p.Set.CacheCreation1h},
			{r.LongContextInputPerMTok, &p.LongContextInput, &p.Set.LongContextInput},
			{r.LongContextOutputPerMTok, &p.LongContextOutput, &p.Set.LongContextOutput},
			{r.LongContextCacheReadPerMTok, &p.LongContextCacheRead, &p.Set.LongContextCacheRead},
			{r.LongContextCacheWritePerMTok, &p.LongContextCacheCreation, &p.Set.LongContextCacheCreation},
			{r.LongContextCacheWrite1hPerMTok, &p.LongContextCacheCreation1h, &p.Set.LongContextCacheCreation1h},
			{r.WebSearchPerRequest, &p.WebSearchPerRequest, &p.Set.WebSearchPerRequest},
		} {
			if f.src != nil {
				*f.dst, *f.set = *f.src, true
			}
		}
		p.Peak = peakRatesToCost(r.Peak)
		out = append(out, p)
	}
	return out
}

// peakRatesToCost translates the wire's peak variant into the node engine's
// own vocabulary (a plain field copy, mirroring orgPriceRowsOf's own rule —
// the two shapes are deliberately identical, see orgcontract.RateSet's doc).
// nil in, nil out: a wire row that carries no Peak field composes no peak at
// all, which is what lets [cost.OrgPrice]'s overlay wholesale-replace a
// seed's peak variant with "no peak" for a model the org negotiated flat.
func peakRatesToCost(pr *orgcontract.PeakRates) *cost.PeakRates {
	if pr == nil {
		return nil
	}
	out := &cost.PeakRates{
		RateSet: cost.RateSet{
			Input:           pr.Input,
			Output:          pr.Output,
			CacheRead:       pr.CacheRead,
			CacheCreation:   pr.CacheCreation,
			CacheCreation1h: pr.CacheCreation1h,

			LongContextThreshold:       pr.LongContextThreshold,
			LongContextInput:           pr.LongContextInput,
			LongContextOutput:          pr.LongContextOutput,
			LongContextCacheRead:       pr.LongContextCacheRead,
			LongContextCacheCreation:   pr.LongContextCacheCreation,
			LongContextCacheCreation1h: pr.LongContextCacheCreation1h,
		},
	}
	for _, w := range pr.Schedule.Windows {
		out.Schedule.Windows = append(out.Schedule.Windows, cost.PeakWindow{
			Days:     append([]time.Weekday(nil), w.Days...),
			StartUTC: w.StartUTC,
			EndUTC:   w.EndUTC,
		})
	}
	return out
}
