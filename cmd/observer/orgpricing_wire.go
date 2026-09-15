package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/orgpricing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The org PRICING boundary
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// wave W2).
//
// It is the ONE place three subsystems meet, and each stays ignorant of the
// others (CLAUDE.md #2):
//
//   - internal/orgclient fetches, verifies and persists a signed document and
//     hands over a typed outcome. It knows nothing about a price table.
//   - internal/intelligence/cost takes org rows as an INPUT and re-composes
//     its table. It knows nothing about HTTP, signatures or tenancy.
//   - internal/orgpricing resolves the ladder from two booleans. It knows
//     nothing about either of the above.
//
// The tenancy resolution — "is this node MANAGED and does its grant carry
// enforce.budget?" — happens HERE, live, once per cycle, and travels as a
// bool. Nothing downstream branches on tenancy, on an authority token, or on
// where a rate came from (CLAUDE.md #3).

// nodePricingPosture is what this node reports about which price table it is
// applying. It is process-wide behind an atomic pointer for exactly the reason
// budgetWindowZones is: the BUDGET posture is composed on the budget rail's
// own cycle, while the pricing answer arrives on the pricing rail's, and a
// closure that captured one at wiring time would report a value from before
// the first poll forever.
//
// The two rails are polled in the same cycle, in order, so in practice the
// budget composition that follows a pricing delivery sees the fresh value —
// but the shape does not depend on that ordering, which is what keeps it from
// being a latent bug the first time somebody reorders the loop.
var nodePricingPosture atomic.Pointer[pricingPosture]

// pricingPosture is the enum + version pair that reaches
// orgcontract.BudgetPostureRow.
type pricingPosture struct {
	source  string
	version int64
}

// setNodePricingPosture publishes the pair. Called from the pricing boundary
// on every poll cycle and once at cold start.
func setNodePricingPosture(source string, version int64) {
	nodePricingPosture.Store(&pricingPosture{source: source, version: version})
}

// nodePricingPostureFor returns the published pair, or ("", 0) when nothing
// has been composed yet.
//
// The empty source is load-bearing: it means "not determined", and the server
// side renders an absence rather than a verdict (rollup's pricingNote). A node
// with no pricing wiring at all — every pre-arc agent — reports exactly this,
// so the coverage note stays silent instead of claiming a fleet is on seed
// rates it was never asked about.
func nodePricingPostureFor() (string, int64) {
	if p := nodePricingPosture.Load(); p != nil {
		return p.source, p.version
	}
	return "", 0
}

// orgPricingHandle owns the daemon-lifetime pricing composition state.
type orgPricingHandle struct {
	// engine is the ONE process cost engine (costengine_wire.go). nil when no
	// composition site has built one — the handle then still publishes an
	// honest posture, which is what a node whose proxy failed to assemble
	// should report.
	engine *cost.Engine
	// identityStore is the durable enrollment source used at publication
	// time. It prevents a delayed outcome from one member from replacing the
	// live table after another process re-enrolled this node.
	identityStore *store.Store
	// localOverrides records whether this node's own [intelligence.pricing]
	// authored anything. It decides between the `seed` and `local` posture
	// values, which are genuinely different facts: "nobody has priced
	// anything here" versus "this developer priced things themselves".
	localOverrides bool
	logger         *slog.Logger
}

// newOrgPricingHandle wires the boundary and publishes the pre-fetch posture
// immediately, so a push that happens before the first pricing poll reports
// the node's honest starting state rather than nothing at all.
func newOrgPricingHandle(engine *cost.Engine, cfg config.Config, logger *slog.Logger, identityStores ...*store.Store) *orgPricingHandle {
	var identityStore *store.Store
	if len(identityStores) > 0 {
		identityStore = identityStores[0]
	}
	h := &orgPricingHandle{
		engine:         engine,
		identityStore:  identityStore,
		localOverrides: len(cfg.Intelligence.Pricing.Models) > 0 || len(cfg.Intelligence.Pricing.Dated) > 0,
		logger:         logger,
	}
	h.publish(orgclient.PricingFetchOutcome{State: initialPricingState(cfg.Guard.Budget.FromOrg)})
	return h
}

// initialPricingState is the honest pre-first-poll state: disabled when the
// node never opted in, otherwise unreachable — nothing has been fetched yet,
// and claiming verified before a single successful poll would be a lie in the
// direction that permanently mis-prices captured turns.
func initialPricingState(fromOrg bool) string {
	if !fromOrg {
		return orgcontract.PricingFetchDisabled
	}
	return orgcontract.PricingFetchUnreachable
}

// onPricingFetch is the orgclient pricing sink: one apply + one publish per
// cycle. It never returns an error and never blocks the push loop.
func (h *orgPricingHandle) onPricingFetch(o orgclient.PricingFetchOutcome) {
	if h == nil {
		return
	}
	h.publish(o)
}

// publish applies the outcome to the live engine and publishes the posture.
//
// The ENGINE APPLY comes first and the posture second, deliberately: the
// posture reports what the engine is doing, so publishing it before the apply
// would create a window in which a push could report rates that were not yet
// in force. The window is milliseconds; it is also free to close.
func (h *orgPricingHandle) publish(o orgclient.PricingFetchOutcome) {
	o = h.bindOutcomeToCurrentIdentity(o)
	applied := false
	if h.engine != nil && (o.HaveBody || (o.Witness.Valid() && !o.Witness.Present)) {
		rows := []cost.OrgPrice(nil)
		version := int64(0)
		if o.HaveBody {
			rows = orgPriceRowsOf(o.Body.Rows)
			version = o.Body.Version
		}
		h.engine.SetOrgRowsWithWitness(rows, version, o.Authoritative, o.Binding, pricingDocumentWitness(o.Witness))
		if !o.HaveBody {
			// A known durable absence is evidence that the org has no current
			// document. Preserve that witness on the empty table so a bounded
			// accounting decision can distinguish it from an unreadable cache.
			applied = false
		}
		if o.HaveBody {
			for _, w := range h.engine.PricingWarnings() {
				// A refused org row is an admin's typed number that did NOT take
				// effect. Silence here is how "I set that rate last week" becomes
				// an unanswerable question.
				h.logger.Warn("org pricing", "warning", w)
			}
		}
	}
	if h.engine != nil {
		// A bodyless transport/identity failure leaves a same-binding verified
		// table in force. Read the engine after the optional apply so the
		// posture remains fail-open and describes the rates actually serving.
		applied = h.engine.HasOrgPricing()
	}
	// The identity read before the apply closes the usual delayed-outcome
	// case. Recheck after the atomic table publication as well: an external
	// re-enrollment can land in that small window, and the old body must not
	// become the table that survives it.
	if h.identityStore != nil {
		o = h.bindOutcomeToCurrentIdentity(o)
		if h.engine != nil {
			applied = h.engine.HasOrgPricing()
		}
	}
	version := int64(0)
	if h.engine != nil {
		version = h.engine.OrgPricingVersion()
	}
	setNodePricingPosture(resolvePricingSource(pricingSourceInput{
		fromOrg:        o.State != orgcontract.PricingFetchDisabled,
		state:          o.State,
		orgRowsInForce: applied,
		authoritative:  o.Authoritative,
		localOverrides: h.localOverrides,
	}), version)
}

// bindOutcomeToCurrentIdentity is the publication fence for the live cost
// engine. FetchPricingPolicy fences its own durable and in-memory writes, but
// a sink callback can be delayed across an external unenroll/re-enroll. A
// body from the old epoch is discarded, and any rows that were composed under
// that old epoch are cleared before the posture is published.
func (h *orgPricingHandle) bindOutcomeToCurrentIdentity(o orgclient.PricingFetchOutcome) orgclient.PricingFetchOutcome {
	if h == nil || h.identityStore == nil {
		return o
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, h.identityStore)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("org pricing publication deferred: current enrollment identity is unavailable", "err", err)
		}
		// An ordinary transport failure remains fail-open when identity cannot
		// be established. Do not replace a last verified table with a verdict
		// based only on an unavailable identity read.
		return orgclient.PricingFetchOutcome{State: orgcontract.PricingFetchUnverified}
	}
	if !active || identity.Binding == "" {
		h.clearOrgRows("")
		return orgclient.PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled}
	}

	// Any already-composed rows must belong to this exact enrollment. This
	// also removes standalone feed rows when an enrollment appears in a live
	// process; the org rail starts empty until a current signed body arrives.
	if h.engine != nil {
		if table := h.engine.Table(); table != nil && h.engine.HasOrgPricing() && table.EnrollmentBinding() != identity.Binding {
			h.clearOrgRows(identity.Binding)
		}
	}
	if o.HaveBody {
		if o.Binding == "" || o.Binding != identity.Binding {
			h.clearOrgRowsForBinding(o.Binding, identity.Binding)
			return orgclient.PricingFetchOutcome{
				State: orgcontract.PricingFetchUnverified, Binding: identity.Binding,
			}
		}
	} else if o.Binding != "" && o.Binding != identity.Binding {
		// This outcome can be a delayed transport result from the previous
		// enrollment. Clear an old table only when the table itself still carries
		// that old binding; a replacement enrollment may already have published
		// its own table, which this stale bodyless outcome must never erase.
		h.clearOrgRowsForBinding(o.Binding, identity.Binding)
		return orgclient.PricingFetchOutcome{
			State: orgcontract.PricingFetchUnverified, Binding: identity.Binding,
		}
	}
	if o.Binding == "" {
		// A no-body initial/transport outcome is allowed to leave a verified
		// current table in force. Stamp it with the current identity only when
		// the outcome itself is intentionally bodyless.
		o.Binding = identity.Binding
	}
	return o
}

// clearOrgRows removes every org-authored row from the live table while
// retaining seed and local pricing. The binding argument records the current
// epoch on the empty snapshot so a later no-body outcome cannot mistake it
// for rows from a prior member.
func (h *orgPricingHandle) clearOrgRows(binding string) {
	if h == nil || h.engine == nil {
		return
	}
	h.engine.SetOrgRows(nil, 0, false, binding)
}

// clearOrgRowsForBinding clears an org table only when the table still belongs
// to expected. The replacement binding is stamped onto the empty snapshot so
// a later bodyless outcome can tell that the old table has already been
// retired. A delayed outcome from an older enrollment must not clear a newer
// enrollment's table.
func (h *orgPricingHandle) clearOrgRowsForBinding(expected, replacement string) {
	if h == nil || h.engine == nil || expected == "" {
		return
	}
	table := h.engine.Table()
	if table == nil || !h.engine.HasOrgPricing() || table.EnrollmentBinding() != expected {
		return
	}
	h.clearOrgRows(replacement)
}

// pricingSourceInput is the branch-free view the posture rule reads.
type pricingSourceInput struct {
	fromOrg        bool
	state          string
	orgRowsInForce bool
	authoritative  bool
	localOverrides bool
}

// pricingSourceRules is the ordered posture table (CLAUDE.md #5): first row
// that applies wins, one test case per row.
//
// THE ORDER IS THE ARGUMENT. "Which price table is this node applying" is
// answered by what is IN FORCE, not by how the last poll went — so the org
// rows win the moment they are composed in, even if this cycle's fetch failed.
// Reporting `unverified` over a node that is correctly applying last week's
// verified document would tell an admin their prices are not being used when
// they are. The refusal states are named only when nothing of the org's is in
// force, which is exactly when they are the whole story.
//
// unreachable / auth_failed / channel_off are deliberately NOT posture values:
// they describe a SERVER this node also polls for its budget, and the budget
// posture's own FetchState already carries them. Duplicating them here would
// give an admin two fields that can disagree about one outage.
var pricingSourceRules = []struct {
	name   string
	source func(in pricingSourceInput) string
}{
	{
		name: "never_opted_in",
		source: func(in pricingSourceInput) string {
			if in.fromOrg {
				return ""
			}
			if in.localOverrides {
				return orgcontract.PricingSourceLocal
			}
			return orgcontract.PricingSourceSeed
		},
	},
	{
		name: "org_rows_in_force",
		source: func(in pricingSourceInput) string {
			if !in.orgRowsInForce {
				return ""
			}
			if in.authoritative {
				return orgcontract.PricingSourceOrgAuthoritative
			}
			return orgcontract.PricingSourceOrg
		},
	},
	{
		name: "org_withdrew_its_rates",
		source: func(in pricingSourceInput) string {
			if in.state != orgcontract.PricingFetchNoPricing {
				return ""
			}
			return orgcontract.PricingSourceNoPricing
		},
	},
	{
		name: "body_refused",
		source: func(in pricingSourceInput) string {
			if in.state != orgcontract.PricingFetchUnverified {
				return ""
			}
			return orgcontract.PricingSourceUnverified
		},
	},
	{
		name: "server_predates_the_rail",
		source: func(in pricingSourceInput) string {
			if in.state != orgcontract.PricingFetchNotSupported {
				return ""
			}
			return orgcontract.PricingSourceNotSupported
		},
	},
	{
		// The total fallback: opted in, nothing of the org's in force, and no
		// state that explains why (a transport failure before the first
		// successful poll). What the node IS doing is running its own table,
		// and that is what it says.
		name: "own_table",
		source: func(in pricingSourceInput) string {
			if in.localOverrides {
				return orgcontract.PricingSourceLocal
			}
			return orgcontract.PricingSourceSeed
		},
	},
}

// resolvePricingSource walks the table top-down. The table is total (its last
// row always applies), so this never returns "".
func resolvePricingSource(in pricingSourceInput) string {
	for _, rule := range pricingSourceRules {
		if s := rule.source(in); s != "" {
			return s
		}
	}
	return orgcontract.PricingSourceSeed
}

// guardPricingLine renders the one-line pricing answer `observer guard status`
// prints beside the budget rules.
//
// It reads the PERSISTED document rather than the live posture because the CLI
// runs in its own process: nodePricingPosture is daemon state and would be
// empty here, and printing "not determined" over a node that is correctly
// applying the org's rates would be worse than saying nothing. The stored
// document is the same one the daemon composed from, so the two agree.
//
// It never fails the command. Every degradation is a sentence.
func guardPricingLine(ctx context.Context, cfg config.Config, database *sql.DB) string {
	fromOrg, authoritative := orgpricing.Mode(cfg.Guard.Budget, budgetEnforcementGranted(ctx, cfg, database, slog.Default()))
	localOverrides := len(cfg.Intelligence.Pricing.Models) > 0 || len(cfg.Intelligence.Pricing.Dated) > 0
	if !fromOrg {
		if localOverrides {
			return "your own [intelligence.pricing] rates over the built-in table " +
				"([guard.budget].from_org is off, so the org's negotiated rates are not applied)"
		}
		return "the built-in rate table ([guard.budget].from_org is off, so the org's negotiated rates are not applied)"
	}
	cached, err := store.New(database).LoadOrgPricing(ctx)
	switch {
	case err != nil:
		return "the built-in rate table; the stored org document could not be read (" + err.Error() + ")"
	case !cached.Have:
		return "the built-in rate table; no org price document has been fetched yet"
	case func() bool {
		identity, active, ierr := orgclient.CurrentBudgetIdentity(ctx, store.New(database))
		return ierr != nil || !active || cached.Binding == "" || cached.Binding != identity.Binding
	}():
		return "the built-in rate table; the stored org document belongs to a different or unverifiable enrollment"
	case len(cached.Body.Rows) == 0:
		return fmt.Sprintf("the built-in rate table; the org signed an empty price list at v%d (it has negotiated nothing)",
			cached.Body.Version)
	case authoritative:
		return fmt.Sprintf("org rates v%d for %d model(s), ABOVE your own overrides (this node is managed and holds enforce.budget)",
			cached.Body.Version, len(cached.Body.Rows))
	default:
		return fmt.Sprintf("org rates v%d for %d model(s), under any [intelligence.pricing] override you set",
			cached.Body.Version, len(cached.Body.Rows))
	}
}
