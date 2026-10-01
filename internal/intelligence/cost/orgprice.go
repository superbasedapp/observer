package cost

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ORG-NEGOTIATED RATES AS AN ENGINE INPUT
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// ruling R13, finding F3).
//
// THE PROBLEM THIS SHAPE SOLVES. Before this arc the node's price table had 38
// constructors and no owner: `cost.NewEngine(cfg.Intelligence)` appears in the
// proxy's cost stamper, in the org-push pricer, in the dashboard, in `observer
// cost`, in the MCP server, in metrics. Handing the org's rates to one of them
// would have left the other 37 pricing at list — and worse, [Engine.Reload]
// rebuilds from the seed, so an org rate poked onto a live engine would be
// silently reverted the next time the Settings page saved a config.
//
// So the org's rows are an INPUT to the build, held on the engine beside the
// config, and every rebuild re-composes from both. A caller that wants the
// org's rates asks for them at CONSTRUCTION (WithOrgRows) or pushes them in
// when the rail delivers (SetOrgRows); nothing downstream branches on where a
// rate came from.
//
// THE LADDER, and why it flips (ruling R3):
//
//   - INDIVIDUAL node: seed -> org -> local explicit override. A developer who
//     typed a rate in their own config.toml meant it, and nothing about an org
//     price list should silently overwrite a machine the org does not manage.
//   - MANAGED node holding enforce.budget: seed -> local -> org. The org's
//     rate sits on top, because otherwise a developer could re-price their way
//     out from under an org cap by editing one TOML key — which would make the
//     whole budget rail decorative.
//
// The flip is resolved ONCE, at the daemon/CLI boundary (internal/orgpricing's
// Mode), and arrives here as a bool. Nothing in this package knows what
// "managed" means.

// OrgPrice is ONE org-authored rate in the node's own vocabulary.
//
// Embedding [Pricing] rather than restating twelve fields is the point: the
// server's wire row is deliberately the same field set, so composing an org
// document into this engine is a projection with no arithmetic and no
// per-field mapping that could drift.
type OrgPrice struct {
	// Model is the model id, normalized (lower-cased, trimmed) by the server.
	Model string
	// EffectiveFrom is the RFC3339 timestamp or YYYY-MM-DD date the rate
	// started; "" means "since forever". It is resolved ONCE per rebuild, at
	// the engine's clock, so the flat table stays flat (F13).
	EffectiveFrom string
	Pricing
	// Set says which of the embedded rates the org actually QUOTED (server
	// migration 135). It is carried BESIDE Pricing rather than turning
	// Pricing's own fields into pointers, because the engine's flat table is
	// float64 arithmetic on a hot path and nothing downstream of the compose
	// step has any use for a "not set" rate: by then every field has been
	// resolved against the next precedence level.
	//
	// Its zero value is "the org quoted nothing", which is the honest reading
	// of a row built by a caller that has not been taught the distinction:
	// such a row is REFUSED rather than silently pricing a model at zero.
	Set OrgPriceSet

	// History is the model's dated price timeline as the source stated it
	// (the org document's or the public feed's row `history`, lane
	// R2-PRICING-2): every period ascending, each with its own EffectiveFrom,
	// rates and Set flags, none with a History of its own. When it holds two
	// or more usable periods the engine builds the key's DATED timeline from
	// it (see orgTimeline) instead of applying this row flat across all of
	// history, so an old session prices at the rate that was in force when it
	// ran. nil (every pre-history document) makes the row its own one-period
	// history: flat across all of history when it is undated, and priced
	// from its EffectiveFrom on (the seed, else nothing, before it) when it
	// is dated - see composeOrgRows.
	History []OrgPrice
}

// OrgPriceSet marks which fields of an [OrgPrice] the source actually quoted.
//
// One bool per field whose ABSENCE must be told apart from its zero value,
// named for the [Pricing] field it governs so the correspondence is readable at
// the assignment site. It is the migration-135 contract ("NULL = not quoted, a
// SET value wins, including 0") applied uniformly - to the eleven nullable rate
// columns AND to the three structural dimensions:
//
//   - LongContextThreshold: set to 0 means "quoted: no long-context tier" (a
//     negotiated flat rate); unset keeps the seed's tier.
//   - Peak: set with a nil or window-less schedule means "quoted: flat, no
//     time-of-day premium" and clears the seed's peak; set with a schedule
//     replaces it; unset keeps it.
//   - FastMultiplier: set wins (0 = no fast tier); unset keeps the seed's.
//
// Its zero value is "quoted nothing", which is the honest reading of a row
// built by a caller that has not been taught the distinction: such a row is
// REFUSED (no input and no output) rather than silently pricing a model at
// zero, and it can never clear a seed dimension by omission.
type OrgPriceSet struct {
	Input           bool
	Output          bool
	CacheRead       bool
	CacheCreation   bool
	CacheCreation1h bool

	LongContextInput           bool
	LongContextOutput          bool
	LongContextCacheRead       bool
	LongContextCacheCreation   bool
	LongContextCacheCreation1h bool

	WebSearchPerRequest bool
	FastMultiplier      bool

	Reasoning           bool
	RequestFee          bool
	CacheCreationOther  bool
	ImageInput          bool
	ImageOutputPerImage bool
	AudioInput          bool
	AudioOutput         bool

	LongContextThreshold bool
	Peak                 bool
}

// overlay folds this row's QUOTED dimensions onto whatever the node would
// otherwise have priced the model at, and returns the result. It is the ONE
// overlay rule for every non-local rate source - the generated seed snapshot,
// the standalone Tokenomics feed and the org's signed price document all fold
// through it, so the three can never disagree about what a row means.
//
// THE RULE (migration-135 contract, applied uniformly; orchestrator ruling
// 2026-09-23): a dimension the row did not quote keeps base's value; a quoted
// dimension wins, INCLUDING a quoted zero / empty value, which is how a source
// states "negotiated flat" (threshold 0 = no long-context tier, an empty peak =
// no off-peak split). So omission never erases a seed tier (the rework's
// finding-1 bug on the snapshot, feed and org rails alike), while an org that
// explicitly negotiates a model flat still gets exactly that (peak-off-peak
// plan §R2 R1/N2 is preserved for the explicit case).
//
// What counts as "quoted" for which dimension is decided where the row is
// projected into this type, per rail, not here
// (cmd/observer/costengine_wire.go): on the FEED an absent threshold or peak is
// not quoted; on the ORG rail an absent one keeps the legacy meaning every
// pre-175 node gave it - quoted flat - and only an explicit
// `*_unquoted` marker, written for a NULL org column, means "not quoted"
// (review finding F1, 2026-09-26; docs/pricing.md).
func (p OrgPrice) overlay(base Pricing) Pricing {
	out := p.overlayQuotedRates(base)
	if p.Set.LongContextThreshold {
		out.LongContextThreshold = p.LongContextThreshold
		if p.LongContextThreshold == 0 {
			// Quoted FLAT (the 2026-09-30 ruling: no published tier = flat,
			// never "keep the built-in tier"): the base's long-context
			// rates go too, so the resolved rate carries no dormant tier a
			// display surface or a later overlay could mistake for a live
			// one. A flat row cannot quote a long-context rate that means
			// anything, so none is kept.
			out.LongContextInput, out.LongContextOutput = 0, 0
			out.LongContextCacheRead = 0
			out.LongContextCacheCreation, out.LongContextCacheCreation1h = 0, 0
		}
	}
	if p.Set.Peak {
		if p.Peak == nil || len(p.Peak.Schedule.Windows) == 0 {
			out.Peak = nil // quoted flat: no time-of-day premium
		} else {
			out.Peak = p.Peak
		}
	}
	return out
}

// overlayQuotedRates folds ONLY the Set-gated scalar fields onto base: "a
// quoted value wins, even at zero; an unquoted one falls through".
func (p OrgPrice) overlayQuotedRates(base Pricing) Pricing {
	out := base
	for _, f := range []struct {
		set bool
		dst *float64
		src float64
	}{
		{p.Set.Input, &out.Input, p.Input},
		{p.Set.Output, &out.Output, p.Output},
		{p.Set.CacheRead, &out.CacheRead, p.CacheRead},
		{p.Set.CacheCreation, &out.CacheCreation, p.CacheCreation},
		{p.Set.CacheCreation1h, &out.CacheCreation1h, p.CacheCreation1h},
		{p.Set.LongContextInput, &out.LongContextInput, p.LongContextInput},
		{p.Set.LongContextOutput, &out.LongContextOutput, p.LongContextOutput},
		{p.Set.LongContextCacheRead, &out.LongContextCacheRead, p.LongContextCacheRead},
		{p.Set.LongContextCacheCreation, &out.LongContextCacheCreation, p.LongContextCacheCreation},
		{p.Set.LongContextCacheCreation1h, &out.LongContextCacheCreation1h, p.LongContextCacheCreation1h},
		{p.Set.WebSearchPerRequest, &out.WebSearchPerRequest, p.WebSearchPerRequest},
		{p.Set.FastMultiplier, &out.FastMultiplier, p.FastMultiplier},
		{p.Set.Reasoning, &out.Reasoning, p.Reasoning},
		{p.Set.RequestFee, &out.RequestFee, p.RequestFee},
		{p.Set.CacheCreationOther, &out.CacheCreationOther, p.CacheCreationOther},
		{p.Set.ImageInput, &out.ImageInput, p.ImageInput},
		{p.Set.ImageOutputPerImage, &out.ImageOutputPerImage, p.ImageOutputPerImage},
		{p.Set.AudioInput, &out.AudioInput, p.AudioInput},
		{p.Set.AudioOutput, &out.AudioOutput, p.AudioOutput},
	} {
		if f.set {
			*f.dst = f.src
		}
	}
	return out
}

// negativeQuotedRate reports whether any rate the org actually QUOTED is below
// zero. An unquoted field is not a rate and cannot be negative; checking it
// would refuse a legitimate row over a number nobody authored.
func (p OrgPrice) negativeQuotedRate() bool {
	for _, f := range []struct {
		set   bool
		value float64
	}{
		{p.Set.Input, p.Input},
		{p.Set.Output, p.Output},
		{p.Set.CacheRead, p.CacheRead},
		{p.Set.CacheCreation, p.CacheCreation},
		{p.Set.CacheCreation1h, p.CacheCreation1h},
		{p.Set.LongContextInput, p.LongContextInput},
		{p.Set.LongContextOutput, p.LongContextOutput},
		{p.Set.LongContextCacheRead, p.LongContextCacheRead},
		{p.Set.LongContextCacheCreation, p.LongContextCacheCreation},
		{p.Set.LongContextCacheCreation1h, p.LongContextCacheCreation1h},
		{p.Set.WebSearchPerRequest, p.WebSearchPerRequest},
		{p.Set.FastMultiplier, p.FastMultiplier},
		{p.Set.Reasoning, p.Reasoning},
		{p.Set.RequestFee, p.RequestFee},
		{p.Set.CacheCreationOther, p.CacheCreationOther},
		{p.Set.ImageInput, p.ImageInput},
		{p.Set.ImageOutputPerImage, p.ImageOutputPerImage},
		{p.Set.AudioInput, p.AudioInput},
		{p.Set.AudioOutput, p.AudioOutput},
	} {
		if f.set && f.value < 0 {
			return true
		}
	}
	return false
}

// PricingDocumentWitness identifies the exact durable org pricing document
// state that produced an applied table. Known absence is represented by
// Known=true, Present=false; a present document carries the SHA-256 of the
// durable envelope. The cost package owns this neutral shape so it does not
// depend on the storage package.
type PricingDocumentWitness struct {
	Known   bool
	Present bool
	SHA256  string
}

// Valid reports whether the witness represents a known present or absent
// durable document state.
func (w PricingDocumentWitness) Valid() bool {
	return w.Known && ((!w.Present && w.SHA256 == "") || (w.Present && w.SHA256 != ""))
}

// OrgRows is a whole applied pricing document as the engine consumes it.
type OrgRows struct {
	Rows []OrgPrice
	// Version is the org_pricing_version the rows came from. It is carried
	// for REPORTING (the node posture, `observer guard`, the Privacy card) —
	// the engine never compares versions, because refusing a replay is the
	// fetch rail's job and doing it twice would put the rule in two places.
	Version int64
	// Authoritative is the resolved tenancy flag: true only on a MANAGED node
	// whose grant carries enforce.budget.
	Authoritative bool
	// Binding is the exact enrollment epoch that authenticated the rows. It
	// travels with the rows into the immutable table so accounting can prove
	// that the rate card it used belongs to the current enrollment.
	// Empty is valid for the standalone public feed and for local tests; a
	// managed org table must carry a non-empty binding before it is admitted
	// by the composition boundary.
	Binding string
	// Witness identifies the exact durable document state that produced these
	// rows. It remains paired with the rows when the immutable table is built.
	Witness PricingDocumentWitness
}

// Option customises an [Engine] at construction.
type Option func(*Engine)

// WithOrgRows installs a loader the engine calls ONCE, at construction, to
// pick up the org's persisted price document.
//
// It exists so a standalone CLI (`observer cost`, `observer report`, the MCP
// server) prices the way the daemon does without either of them having to
// coordinate: both read the same node-local row that the fetch rail wrote. A
// loader that returns ok=false leaves the engine on seed + local, which is the
// fail-open direction — the fail-closed direction on a price table is pricing
// everything at zero, which would make every budget look unspent.
//
// It is deliberately NOT re-called on [Engine.Reload]: a Reload is a CONFIG
// event, and re-reading a database from inside it would put an I/O call on a
// path that today only touches memory. The daemon pushes fresh rows in through
// [Engine.SetOrgRows] when the rail delivers them.
func WithOrgRows(loader func() (OrgRows, bool)) Option {
	return func(e *Engine) { e.orgLoader = loader }
}

// withClock replaces the engine's notion of "now" for the effective_from
// resolution. Unexported: it exists for this package's own tests, and a
// production caller that wanted a different clock would be asking for the two
// halves of one install to disagree about which dated rate is live.
func withClock(now func() time.Time) Option {
	return func(e *Engine) { e.now = now }
}

// SetOrgRows installs the org's rates and REBUILDS the table immediately.
//
// It rebuilds rather than merely storing because the alternative — "store now,
// apply on the next Reload" — has no bound on when the next Reload happens. On
// a daemon that never opens the Settings page, that is never, and the fleet
// would poll a document it never applied.
//
// Safe to call from the org push loop while requests are being priced:
// [Engine.Reload]'s atomic.Pointer swap is what makes in-flight readers see
// either the old table or the new one, never a torn state.
func (e *Engine) SetOrgRows(rows []OrgPrice, version int64, authoritative bool, bindings ...string) {
	if e == nil {
		return
	}
	binding := ""
	if len(bindings) > 0 {
		binding = bindings[0]
	}
	e.SetOrgRowsWithWitness(rows, version, authoritative, binding, PricingDocumentWitness{})
}

// SetOrgRowsWithWitness installs org rates and their durable document witness,
// then rebuilds the immutable pricing table immediately. The witness is kept
// beside the rows so a later bounded accounting decision can prove that the
// table it used still matches the durable cache.
func (e *Engine) SetOrgRowsWithWitness(rows []OrgPrice, version int64, authoritative bool, binding string, witness PricingDocumentWitness) {
	if e == nil {
		return
	}
	e.rebuildMu.Lock()
	defer e.rebuildMu.Unlock()
	next := OrgRows{
		Rows: rows, Version: version, Authoritative: authoritative,
		Binding: binding, Witness: witness,
	}
	e.orgRows.Store(&next)
	e.rebuild()
}

// OrgPricingVersion reports the version of the org document currently
// composed into the table, or 0 when none is. Read by the node posture and
// the node's own surfaces; never by the pricing math.
func (e *Engine) OrgPricingVersion() int64 {
	if e == nil {
		return 0
	}
	if r := e.orgRows.Load(); r != nil {
		return r.Version
	}
	return 0
}

// OrgPricingAuthoritative reports whether the org's rates are sitting ABOVE
// this node's own overrides.
func (e *Engine) OrgPricingAuthoritative() bool {
	if e == nil {
		return false
	}
	if r := e.orgRows.Load(); r != nil {
		return r.Authoritative
	}
	return false
}

// HasOrgPricing reports whether any org row is composed into the table. It is
// false both for "no document" and for a document whose every row was refused,
// which is correct: in both cases nothing an admin authored is in force.
func (e *Engine) HasOrgPricing() bool {
	if e == nil {
		return false
	}
	t := e.Table()
	return t != nil && len(t.org) > 0
}

// composeOrgRows folds an applied document onto a table built from seed +
// local, honouring the tenancy ladder, and returns the keys the ORG owns in
// the result, the dated timelines built from rows that carried a history, and
// one warning per refused row or period.
//
// It takes the LOCAL override key set rather than re-deriving it because
// ownership is not "did the org have a row" but "did the org's row WIN", and
// on an individual node it does not win where the developer authored one.
func composeOrgRows(t *Table, doc *OrgRows, localKeys map[string]bool, at time.Time) (orgOwned map[string]bool, timelines map[string][]DatedPricing, warnings []string) {
	orgOwned = map[string]bool{}
	timelines = map[string][]DatedPricing{}
	if doc == nil || len(doc.Rows) == 0 {
		return orgOwned, timelines, nil
	}
	effective, dated, warnings := flattenOrgRows(doc.Rows, at)
	if len(effective) == 0 {
		return orgOwned, timelines, warnings
	}

	apply := map[string]Pricing{}
	keys := make([]string, 0, len(effective))
	for key := range effective {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		p := effective[key]
		// On an individual node the developer's explicit override wins, so
		// the org's row is not applied at all for that key — and, crucially,
		// the key is not marked org-owned either. Reporting it as "org" while
		// serving the developer's number would be the surface lying about
		// whose rate is in force.
		if !doc.Authoritative && localKeys[key] {
			continue
		}
		// A row that carries a price HISTORY prices every instant from the
		// period in force then; its flat rate is the period in force now. A
		// row WITHOUT one is still a timeline when it is DATED: its own
		// effective_from is where its rate begins, and before that instant
		// the key prices at whatever would apply without the row - the seed's
		// dated history or flat rate, else nothing (a miss, never $0). Only an
		// UNDATED row ("since forever") is applied flat across all of history
		// (review finding 1 on PRICE-REPRICE-1: a single dated org row used to
		// reach back before its own date, at capture and on a re-price).
		tl, hw := orgTimeline(t, key, historyOf(p, dated[key]))
		warnings = append(warnings, hw...)
		if tl != nil {
			apply[key] = currentOf(tl, at)
			if len(tl) > 1 {
				timelines[key] = tl
			}
			orgOwned[key] = true
			continue
		}
		// The base is what this node would have priced the model at WITHOUT
		// the org row - the seed, or the developer's own override on an
		// authoritative node, since the ladder has already merged it by the
		// time this runs. An unquoted org rate keeps that number; a quoted
		// one replaces it, at zero as much as at any other value.
		base, _ := t.Lookup(key)
		apply[key] = p.overlay(base)
		orgOwned[key] = true
	}
	t.Merge(apply)
	sort.Strings(warnings)
	return orgOwned, timelines, warnings
}

// historyOf is the dated statement a document makes about one model: the
// in-force row's own History when it carries two or more periods, else every
// usable row the document holds for the key (normally just the in-force row -
// the server flattens - but a document that lists several dated rows for one
// model states that model's history as surely as a History field does).
// orgTimeline decides whether that is a timeline at all (a single undated
// period is not).
func historyOf(p OrgPrice, docRows []OrgPrice) []OrgPrice {
	if len(p.History) >= 2 {
		return p.History
	}
	if len(docRows) == 0 {
		docRows = []OrgPrice{p}
	}
	out := make([]OrgPrice, 0, len(docRows))
	for _, r := range docRows {
		r.History = nil
		out = append(out, r)
	}
	return out
}

// orgTimeline builds the dated timeline a row's HISTORY implies for `key`, or
// nil when the history holds no usable period, or only one that starts "since
// forever" (the caller then applies the row flat, exactly as before histories
// existed). A single DATED period is a timeline: the seed before its start,
// the period from it on.
//
// THE RULE, per instant: the period in force then, overlaid (presence
// semantics, [OrgPrice.overlay]) on what the SEED priced the key at then. The
// seed is consulted at its own boundaries too, so the timeline's boundaries are
// the union of the history's and the seed's: a dimension no period quotes (the
// org rail cannot state a fast multiplier, say) keeps the seed's value for that
// instant rather than today's. Before the history's first period the seed
// alone prices - the source said nothing about that time. Consecutive equal
// periods collapse into one.
//
// A period that cannot be a price (no model-level rate, a negative rate, an
// unreadable start) is REPORTED and skipped, the flattenOrgRows rule; two
// periods at one instant keep the later one in the document and are reported.
func orgTimeline(t *Table, key string, history []OrgPrice) ([]DatedPricing, []string) {
	if len(history) == 0 {
		return nil, nil
	}
	type period struct {
		start time.Time
		price OrgPrice
	}
	var (
		periods  []period
		warnings []string
	)
	for i, h := range history {
		why := ""
		switch {
		case h.negativeQuotedRate():
			why = "a rate is negative"
		case !h.Set.Input && !h.Set.Output:
			why = "it quotes neither an input nor an output rate"
		}
		start, ok := parseOrgEffectiveFrom(h.EffectiveFrom)
		if !ok {
			why = "effective_from " + h.EffectiveFrom + " is not a date this node understands"
		}
		if why != "" {
			warnings = append(warnings, fmt.Sprintf("price history for %q: period %d ignored: %s", key, i, why))
			continue
		}
		periods = append(periods, period{start: start, price: h})
	}
	sort.SliceStable(periods, func(i, j int) bool { return periods[i].start.Before(periods[j].start) })
	deduped := periods[:0]
	for _, p := range periods {
		if n := len(deduped); n > 0 && deduped[n-1].start.Equal(p.start) {
			warnings = append(warnings, fmt.Sprintf("price history for %q: two periods start at %s; the later one in the document is used", key, p.start.Format(time.RFC3339)))
			deduped[n-1] = p
			continue
		}
		deduped = append(deduped, p)
	}
	periods = deduped
	if len(periods) == 0 || (len(periods) == 1 && periods[0].start.IsZero()) {
		return nil, warnings
	}

	// The seed the history is laid over: the key the ladder resolves to (an
	// exact row, a family row, ...), its flat rate and its own timeline.
	var (
		seedFlat  Pricing
		seedTL    []DatedPricing
		seedFound bool
	)
	if rk, ok := t.ResolveModelKey(key); ok {
		seedFlat = t.exact[rk]
		seedTL = t.dated[rk]
		seedFound = true
	}
	// seedAt is the seed's period at b. An Unpriced seed period (no rate in
	// force) stays unpriced unless a history period overlays it, and a key the
	// seed never priced is Unpriced at every instant no period covers: a miss,
	// never an all-zero rate set a capture path would stamp as $0.
	seedAt := func(b time.Time) DatedPricing {
		if i := inForceIndex(seedTL, b); i >= 0 {
			return seedTL[i]
		}
		return DatedPricing{Pricing: seedFlat, Unpriced: !seedFound}
	}

	bounds := []time.Time{{}}
	for _, p := range periods {
		bounds = append(bounds, p.start)
	}
	for _, e := range seedTL {
		bounds = append(bounds, e.EffectiveFrom)
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].Before(bounds[j]) })

	var out []DatedPricing
	for i, b := range bounds {
		if i > 0 && b.Equal(bounds[i-1]) {
			continue
		}
		seed := seedAt(b)
		entry := DatedPricing{EffectiveFrom: b.UTC(), Pricing: seed.Pricing, Unpriced: seed.Unpriced}
		pi := -1
		for j, p := range periods {
			if p.start.After(b) {
				break
			}
			pi = j
		}
		if pi >= 0 {
			entry.Pricing = periods[pi].price.overlay(seed.Pricing)
			entry.Unpriced = false
		}
		if n := len(out); n > 0 && out[n-1].Pricing == entry.Pricing && out[n-1].Unpriced == entry.Unpriced {
			continue
		}
		out = append(out, entry)
	}
	return out, warnings
}

// flattenOrgRows resolves the dated timeline to ONE rate per model at `at`,
// and refuses the rows that cannot be a price.
//
// A refused row is REPORTED rather than dropped silently: an admin who typed a
// rate and saw nothing change deserves a line that says why, and the two
// refusals here are both cases where applying the row would be worse than
// ignoring it —
//
//   - a row with NO model prices nothing;
//   - a row that QUOTES neither an input nor an output rate prices nothing
//     either: every field would fall through, so the row asserts nothing at
//     all. (A row quoting BOTH at zero is a different thing entirely and IS
//     applied: since server migration 135 that is an org saying it negotiated
//     the model free, and refusing it was the defect that change closed.)
//   - a NEGATIVE rate would make spend go down as tokens are burned, which
//     would let a budget be evaded by using the model.
//
// The server validates all three at the write path; this is the node refusing
// to trust that a document it received is well-formed, which is the correct
// posture for anything that crossed a wire.
//
// It also returns every usable row per key, in document order, whatever its
// start (a row not yet in force included): the key's history as the document
// states it, which composeOrgRows turns into a dated timeline.
func flattenOrgRows(rows []OrgPrice, at time.Time) (map[string]OrgPrice, map[string][]OrgPrice, []string) {
	type candidate struct {
		start time.Time
		price OrgPrice
	}
	best := map[string]candidate{}
	usable := map[string][]OrgPrice{}
	var warnings []string
	refuse := func(model, why string) {
		if model == "" {
			model = "(no model id)"
		}
		warnings = append(warnings, fmt.Sprintf("org price for %q ignored: %s", model, why))
	}

	for _, r := range rows {
		key := strings.ToLower(strings.TrimSpace(r.Model))
		switch {
		case key == "":
			refuse("", "the row names no model")
			continue
		case r.negativeQuotedRate():
			refuse(r.Model, "a rate is negative")
			continue
		case !r.Set.Input && !r.Set.Output:
			refuse(r.Model, "the row quotes neither an input nor an output rate, so it prices nothing")
			continue
		}
		start, ok := parseOrgEffectiveFrom(r.EffectiveFrom)
		if !ok {
			refuse(r.Model, "effective_from "+r.EffectiveFrom+" is not a date this node understands")
			continue
		}
		usable[key] = append(usable[key], r)
		if start.After(at) {
			// Not yet in force. Not a refusal — an admin landing next
			// quarter's rates today is the feature, not a mistake — so no
			// warning.
			continue
		}
		if cur, seen := best[key]; seen && !start.After(cur.start) {
			continue
		}
		best[key] = candidate{start: start, price: r}
	}

	out := make(map[string]OrgPrice, len(best))
	for key, c := range best {
		out[key] = c.price
	}
	sort.Strings(warnings)
	return out, usable, warnings
}

// parseOrgEffectiveFrom mirrors the server's ParseEffectiveFrom: "" is the
// zero time ("since forever", earlier than any instant a caller can ask
// about), a bare date is midnight UTC, and RFC3339 is taken as written.
//
// It is a MIRROR and not an import because internal/intelligence/cost is a
// node package and internal/orgserver/pricing is a server one; the server's
// vocab_test.go already pins the field sets against each other, and this
// parser's three cases are checked here.
func parseOrgEffectiveFrom(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}
