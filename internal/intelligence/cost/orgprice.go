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
}

// OrgPriceSet marks which fields of an [OrgPrice] the org actually quoted.
//
// One bool per NULLABLE rate column, named for the [Pricing] field it governs
// so the correspondence is readable at the assignment site. There is
// deliberately no flag for LongContextThreshold: that column is not nullable
// (0 already means "this row declares no long-context tier"), so an org row
// always states it and it always applies.
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
}

// overlay folds this row's QUOTED rates onto whatever the node would otherwise
// have priced the model at, and returns the result.
//
// A field the org did not quote keeps base's value, which is the fall-through
// the nullable-rate change exists to make expressible: an org that negotiated
// an input rate and said nothing about cache reads has not thereby negotiated
// a free cache read. A field the org DID quote wins even at zero, which is the
// other half of it.
//
// LongContextThreshold always comes from the org row, because the row always
// states it. A row carrying no tier (threshold 0) therefore turns the tier OFF
// for that model rather than half-inheriting the vendor's.
func (p OrgPrice) overlay(base Pricing) Pricing {
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
	} {
		if f.set {
			*f.dst = f.src
		}
	}
	out.LongContextThreshold = p.LongContextThreshold
	// Peak is a WHOLESALE REPLACE, unconditional, mirroring the
	// LongContextThreshold precedent above — never an org.Set-gated field
	// like the scalar rates. There is deliberately no OrgPriceSet.Peak bool:
	// "nil inherits the seed's peak" sounds like the safe default but is
	// backwards here. An org that negotiates a model's base rate almost
	// always negotiates it FLAT (no time-of-day premium); if a nil org.Peak
	// inherited the seed's peak variant, that negotiated flat rate would
	// silently double during the seed's peak window — a rebill the org never
	// agreed to. So a quoted org row REPLACES the seed's peak with whatever
	// the org row carries, including nil (no peak at all). Plan §R2 R1/N2.
	out.Peak = p.Peak
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
// the result plus one warning per refused row.
//
// It takes the LOCAL override key set rather than re-deriving it because
// ownership is not "did the org have a row" but "did the org's row WIN", and
// on an individual node it does not win where the developer authored one.
func composeOrgRows(t *Table, doc *OrgRows, localKeys map[string]bool, at time.Time) (orgOwned map[string]bool, warnings []string) {
	orgOwned = map[string]bool{}
	if doc == nil || len(doc.Rows) == 0 {
		return orgOwned, nil
	}
	effective, warnings := flattenOrgRows(doc.Rows, at)
	if len(effective) == 0 {
		return orgOwned, warnings
	}

	apply := map[string]Pricing{}
	for key, p := range effective {
		// On an individual node the developer's explicit override wins, so
		// the org's row is not applied at all for that key — and, crucially,
		// the key is not marked org-owned either. Reporting it as "org" while
		// serving the developer's number would be the surface lying about
		// whose rate is in force.
		if !doc.Authoritative && localKeys[key] {
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
	return orgOwned, warnings
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
func flattenOrgRows(rows []OrgPrice, at time.Time) (map[string]OrgPrice, []string) {
	type candidate struct {
		start time.Time
		price OrgPrice
	}
	best := map[string]candidate{}
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
	return out, warnings
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
