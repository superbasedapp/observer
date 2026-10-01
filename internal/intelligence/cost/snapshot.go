package cost

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// THE COMPILED SEED IS NOW A PROJECTION OF THE TOKENOMICS DATABASE.
//
// THE PROBLEM this file exists to end. [defaultPricing] is a hand-authored Go
// literal. Every new model release therefore required a code edit, a review and
// a package ship before a node could price it — and a MISS prices at $0.00
// silently while a wrong FAMILY prefix over- or under-bills silently (the
// 2026-07-25 Claude Opus 5 incident: 78 live turns billed $0.00 against a real
// $18.04). The runtime half of that problem is already solved: the Tokenomics
// export -> signed feed -> org rail / standalone feed cache lane
// (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md) updates a
// RUNNING node with no release at all. What survived was the BUILD-time half:
// the rates a node holds before it has ever seen a feed — cold start, air gap,
// a hook process, an enrolled node that declined its org's rates — still came
// only from the hand-written literal, so code and database could disagree.
//
// THE SHAPE. pricing_snapshot.json is a GENERATED, versioned projection of the
// same published feed, embedded at build time and layered over the hand
// literal. It is written by `make pricing-snapshot` (tools/pricing-snapshotgen)
// from a SIGNED feed bundle that `model-pricing/cmd/observerpublish` produced,
// and the generator refuses to write an unsigned or unverifiable one. So the
// answer to "where did this rate come from" is the same database at build time
// and at run time, and a new model is a DATABASE row plus one make target
// rather than a Go edit.
//
// WHAT IT IS NOT. It does not replace [defaultPricing]. The literal stays as
// the permanent last-resort floor for everything the export cannot yet name in
// the node vocabulary (family-prefix rows, router/aggregator ids, and any
// dimension a given row does not state: long-context tiers, the FastMultiplier
// premium, peak schedules) - partial snapshot coverage is SAFE precisely
// because the snapshot is ADDITIVE over the literal, field by field.
// An EMPTY snapshot (the committed zero state, feed_version 0) leaves the table
// byte-identical to what it was before this file existed.
//
// WHERE IT SITS ON THE LADDER. The snapshot is PART OF THE SEED rung - it is
// the seed, generated rather than typed - and it is folded in inside
// [NewTable] before anything else composes. It adds NO rung of its own, and
// the ladder above the seed is exactly the tenancy-dependent one docs/pricing.md
// "precedence" and orgprice.go describe, unchanged:
//
//	individual node:                         seed -> org/feed -> local override
//	managed node holding enforce.budget:     seed -> local override -> org
//
// where "seed" = hand literal + this snapshot (+ the baked dated timelines).
// So a snapshot rate beats nothing but the hand literal it overlays; on an
// individual node a developer's own override still beats the org/feed rate,
// and on an authoritative managed node the org's rate still beats the
// developer's override. Nothing in this file changes either order.
//
// THE MERGE RULE IS PRESENCE, NOT ZERO. A snapshot row is a partial statement:
// the Tokenomics export cannot carry every dimension the literal models (the
// operator-captured lane has no long-context fields at all, for example). So
// every dimension is applied ONLY WHEN THE ROW STATES IT, and an absent field
// keeps the literal's value - including LongContextThreshold, Peak and
// FastMultiplier. Treating "not known" as "off" would silently under-bill
// every long prompt (review finding 1). The rule lives in ONE place,
// [OrgPrice.overlay], which the runtime feed and the org's signed document
// fold through too, so the seed, feed and org rungs share it.
//
// DATES ARE KEPT. A snapshot row that carries effective_from does not reprice
// history: the rate in force before that instant is retained as a dated
// timeline entry and the new rate applies only from the stated instant, through
// the same dated.go machinery the hand-authored timelines use (finding 3).
//
// VERSIONS ONLY MOVE FORWARD. A non-empty snapshot whose feed_version is below
// [SnapshotMinFeedVersion] is refused whole: an older signed bundle is still
// validly signed, and without this floor it would silently restore rates the
// hand literal has already corrected (finding 2). The generator additionally
// refuses to overwrite a committed snapshot with an older bundle.

//go:embed pricing_snapshot.json
var pricingSnapshotJSON []byte

// SnapshotSchemaVersion is the only pricing_snapshot.json schema_version this
// build understands. A snapshot carrying any other value is REFUSED whole
// rather than half-applied: a partially-understood price table is worse than
// the seed it would have replaced, because nothing downstream can tell which
// rows were dropped.
const SnapshotSchemaVersion = 1

// SnapshotMinFeedVersion is the oldest Tokenomics feed_version this build will
// accept as its generated seed (review finding 2: monotonic feed version).
//
// WHY A COMPILED FLOOR. A signed bundle stays validly signed forever, and
// [pricingfeed.Verify] is deliberately stateless about replay. The hand literal
// in this build was reconciled with vendor pages on 2026-09-23, AFTER the last
// production publish (feed_version 1, 2026-09-11); a v1 bundle therefore
// carries rates the literal has since corrected (gpt-5.6-sol at $5/$30, no
// gpt-6-sol/luna rows, ...). Folding it in would silently roll those
// corrections back. The floor says "this literal already reflects everything
// up to feed_version N-1; only N or newer may overlay it".
//
// Bump it whenever defaultPricing is hand-corrected ahead of the feed. The
// generator (tools/pricing-snapshotgen) restates this value and refuses a
// bundle below it too, and additionally refuses a bundle older than the
// snapshot already committed; snapshot_test.go pins the two constants
// together. The committed zero state (feed_version 0, no rows) is exempt: it
// states no rate, so there is nothing to roll back.
const SnapshotMinFeedVersion int64 = 2

// FeedVersionRefusal is the ONE rule for whether a signed pricing-feed body at
// (version, digest) may replace what a node already holds. It returns "" when
// the body is acceptable and a human-readable reason otherwise. It is shared by
// every place a feed body can reach the engine - the build-time snapshot (via
// parseSnapshot and the generator, which restates it), the runtime fetch
// (cmd/observer/pricing.go) and the consumption of an already-cached body at
// start and after each sync (costengine_wire.go, mincacheable_wire.go) - so a
// body refused on one path can never be applied through another (round-2
// review finding 1: the runtime rail used to accept a validly signed v1).
//
// Refused, in order:
//   - a version below [SnapshotMinFeedVersion]: this build's hand literal
//     already reflects everything older, so applying it would roll corrected
//     rates back;
//   - (have only) a version below the one already held: a replay;
//   - (have only) the SAME version with a different digest: the publisher bumps
//     the version on every content change, so equal version + different content
//     is not a newer feed, it is a different one.
//
// have=false checks only the floor (a fresh node, or a cached body being
// consumed on its own).
func FeedVersionRefusal(version int64, digest string, have bool, haveVersion int64, haveDigest string) string {
	switch {
	case version < SnapshotMinFeedVersion:
		return fmt.Sprintf("feed_version %d is below this build's compiled floor %d (an older feed would roll corrected rates back)",
			version, SnapshotMinFeedVersion)
	case have && version < haveVersion:
		return fmt.Sprintf("feed_version %d is older than the held v%d (replay)", version, haveVersion)
	case have && version == haveVersion && haveDigest != "" && digest != haveDigest:
		return fmt.Sprintf("feed_version %d arrived with digest %s, but v%d is held with digest %s (same version, different content)",
			version, digest, haveVersion, haveDigest)
	}
	return ""
}

// snapshotDoc is the generated document embedded above.
//
// The rate fields are POINTERS and the vocabulary is deliberately identical to
// the signed feed's row (orgcontract.PricingPolicyRow) field for field, so the
// generator is a straight copy with no arithmetic. The cost package does NOT
// import orgcontract to say so: keeping a local mirror is what lets this
// package stay on stdlib + config + db, and the generator (which imports both)
// is where the two shapes are pinned to each other
// (TestSnapshotGeneratorShapeMatchesConsumer).
//
// nil vs quoted-zero is the load-bearing distinction (server migration 135,
// Tokenomics `state='known_free'`): a nil rate is "the export quotes nothing
// here" and the seed literal's value survives; a rate SET to zero is "quoted
// free" and wins. Collapsing the two would make every unquoted dimension free.
type snapshotDoc struct {
	SchemaVersion int           `json:"schema_version"`
	FeedVersion   int64         `json:"feed_version"`
	Digest        string        `json:"digest"`
	KeyID         string        `json:"key_id"`
	GeneratedAt   string        `json:"generated_at"`
	Source        string        `json:"source"`
	Rows          []snapshotRow `json:"rows"`
	Notes         string        `json:"notes,omitempty"`
}

type snapshotRow struct {
	Model                          string   `json:"model"`
	EffectiveFrom                  string   `json:"effective_from,omitempty"`
	InputPerMTok                   *float64 `json:"input_per_mtok,omitempty"`
	OutputPerMTok                  *float64 `json:"output_per_mtok,omitempty"`
	CacheReadPerMTok               *float64 `json:"cache_read_per_mtok,omitempty"`
	CacheWritePerMTok              *float64 `json:"cache_write_per_mtok,omitempty"`
	CacheWrite1hPerMTok            *float64 `json:"cache_write_1h_per_mtok,omitempty"`
	LongContextThreshold           *int64   `json:"long_context_threshold,omitempty"`
	LongContextInputPerMTok        *float64 `json:"long_context_input_per_mtok,omitempty"`
	LongContextOutputPerMTok       *float64 `json:"long_context_output_per_mtok,omitempty"`
	LongContextCacheReadPerMTok    *float64 `json:"long_context_cache_read_per_mtok,omitempty"`
	LongContextCacheWritePerMTok   *float64 `json:"long_context_cache_write_per_mtok,omitempty"`
	LongContextCacheWrite1hPerMTok *float64 `json:"long_context_cache_write_1h_per_mtok,omitempty"`
	WebSearchPerRequest            *float64 `json:"web_search_per_request,omitempty"`
	// The extended rate dimensions (2026-09-30 pricing-chain contract), with
	// the rates' presence rule: nil = not stated, the literal's value stays.
	ReasoningPerMTok       *float64 `json:"reasoning_per_mtok,omitempty"`
	RequestFeeUSD          *float64 `json:"request_fee_usd,omitempty"`
	CacheWriteOtherPerMTok *float64 `json:"cache_write_other_per_mtok,omitempty"`
	ImageInputPerMTok      *float64 `json:"image_input_per_mtok,omitempty"`
	ImageOutputPerImage    *float64 `json:"image_output_per_image,omitempty"`
	AudioInputPerMTok      *float64 `json:"audio_input_per_mtok,omitempty"`
	AudioOutputPerMTok     *float64 `json:"audio_output_per_mtok,omitempty"`
	// FastMultiplier is the latency-premium multiplier the feed carries (its
	// top-level fast_multiplier, else the one in its Economics object). nil = not stated (the literal's value stays); a stated
	// value replaces it.
	FastMultiplier *float64 `json:"fast_multiplier,omitempty"`
	// Peak is the time-of-day variant, wire-identical to orgcontract.PeakRates.
	// nil = not stated (the literal's peak schedule stays); a stated value
	// replaces it wholesale.
	Peak *PeakRates `json:"peak,omitempty"`
	// MinCacheableTokens is the smallest cacheable prefix the export knew for
	// this model (the feed's economics.min_cacheable_tokens). It is NOT a rate
	// and never reaches [Pricing]; it is carried here so ONE generated artifact
	// can feed both price registries and the cachetrack min-cacheable registry
	// (see [SnapshotMinCacheable]) instead of two hand-edited tables drifting
	// apart on every model release.
	MinCacheableTokens *int64 `json:"min_cacheable_tokens,omitempty"`
	// ContextWindowTokens is the model's context window as the export stated
	// it. Like MinCacheableTokens it is NOT a rate and never reaches
	// [Pricing]; it is declared here so the generator's row shape stays
	// pinned to this one (TestSnapshotGeneratorShapeMatchesConsumer), and the
	// context-window registry reads it from the same artifact.
	ContextWindowTokens *int64 `json:"context_window_tokens,omitempty"`
}

// snapshotPrice is ONE parsed snapshot row: an [OrgPrice] (value + Set flags,
// with threshold, peak and fast multiplier carried only when stated) plus its
// parsed start instant. It folds through [OrgPrice.overlay], the ONE overlay
// rule the feed and org rows use too.
type snapshotPrice struct {
	rates OrgPrice
	// from is the parsed effective_from; the zero time means "since forever".
	from time.Time
}

// overlay folds this row onto base through [OrgPrice.overlay] (presence
// semantics on every dimension).
func (r snapshotPrice) overlay(base Pricing) Pricing {
	return r.rates.overlay(base)
}

// SnapshotMeta is the embedded snapshot's provenance, for surfaces that answer
// "which database version are these compiled rates?".
//
// Err is set when the embedded document could not be used. That is reported
// rather than returned as a hard failure anywhere on a pricing path: a broken
// snapshot falls back to the hand literal, which is the fail-open direction and
// the honest one - an engine with no rates at all prices every turn at $0 and
// makes every budget look unspent.
type SnapshotMeta struct {
	// Present is true when the embedded document parsed AND carried at least
	// one row. A committed zero snapshot (feed_version 0, no rows) is a valid
	// document that is simply not in force yet.
	Present     bool
	FeedVersion int64
	Digest      string
	KeyID       string
	GeneratedAt string
	Source      string
	RowCount    int
	// Skipped names every individual row that was refused (no rate, a
	// negative value, an unparseable effective_from), one line each. Empty on
	// a clean document.
	Skipped []string
	Err     error
}

var (
	snapshotOnce sync.Once
	snapshotMeta SnapshotMeta
	// snapshotRows is the parsed overlay: per model, every row in ascending
	// effective_from order.
	snapshotRows map[string][]snapshotPrice
	// snapshotMinCacheable is the non-rate half of the same document.
	snapshotMinCacheable map[string]int
)

func loadSnapshot() {
	snapshotOnce.Do(func() {
		snapshotMeta, snapshotRows, snapshotMinCacheable = parseSnapshot(pricingSnapshotJSON)
	})
}

// parseSnapshot is the whole of the snapshot's decoding rule, separated from
// the embedded bytes so it can be exercised against documents this build does
// not ship: a schema version it must refuse, a rate-less row it must drop, a
// quoted zero it must keep, a feed version below the compiled floor.
//
// It never returns an error. A snapshot that cannot be used degrades to the
// hand literal and says so through SnapshotMeta.Err - the fail-open direction,
// and the honest one, because an engine with no rates at all prices every turn
// at $0 and makes every budget look unspent.
func parseSnapshot(raw []byte) (SnapshotMeta, map[string][]snapshotPrice, map[string]int) {
	var (
		meta         SnapshotMeta
		rows         = map[string][]snapshotPrice{}
		minCacheable = map[string]int{}
	)

	var doc snapshotDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		meta.Err = fmt.Errorf("cost: pricing snapshot unreadable: %w", err)
		return meta, rows, minCacheable
	}
	if doc.SchemaVersion != SnapshotSchemaVersion {
		meta.Err = fmt.Errorf(
			"cost: pricing snapshot schema_version %d is not the supported %d; ignoring the whole document",
			doc.SchemaVersion, SnapshotSchemaVersion)
		return meta, rows, minCacheable
	}
	meta.FeedVersion = doc.FeedVersion
	meta.Digest = doc.Digest
	meta.KeyID = doc.KeyID
	meta.GeneratedAt = doc.GeneratedAt
	meta.Source = doc.Source
	if len(doc.Rows) > 0 {
		if why := FeedVersionRefusal(doc.FeedVersion, doc.Digest, false, 0, ""); why != "" {
			meta.Err = fmt.Errorf("cost: pricing snapshot refused whole: %s", why)
			return meta, rows, minCacheable
		}
	}

	for _, r := range doc.Rows {
		key := normalizeSnapshotModel(r.Model)
		if key == "" {
			meta.Skipped = append(meta.Skipped, "a row names no model")
			continue
		}
		p, why := snapshotPriceOf(key, r)
		if why != "" {
			meta.Skipped = append(meta.Skipped, fmt.Sprintf("%q: %s", key, why))
			continue
		}
		rows[key] = append(rows[key], p)
		if r.MinCacheableTokens != nil && *r.MinCacheableTokens > 0 {
			minCacheable[key] = int(*r.MinCacheableTokens)
		}
	}
	for key := range rows {
		sort.SliceStable(rows[key], func(i, j int) bool { return rows[key][i].from.Before(rows[key][j].from) })
	}
	meta.RowCount = len(rows)
	meta.Present = len(rows) > 0
	sort.Strings(meta.Skipped)
	return meta, rows, minCacheable
}

// snapshotPriceOf converts one wire row, or explains why it cannot be a price.
func snapshotPriceOf(key string, r snapshotRow) (snapshotPrice, string) {
	p := snapshotPrice{rates: OrgPrice{Model: key, EffectiveFrom: r.EffectiveFrom}}
	for _, f := range []struct {
		src *float64
		dst *float64
		set *bool
	}{
		{r.InputPerMTok, &p.rates.Input, &p.rates.Set.Input},
		{r.OutputPerMTok, &p.rates.Output, &p.rates.Set.Output},
		{r.CacheReadPerMTok, &p.rates.CacheRead, &p.rates.Set.CacheRead},
		{r.CacheWritePerMTok, &p.rates.CacheCreation, &p.rates.Set.CacheCreation},
		{r.CacheWrite1hPerMTok, &p.rates.CacheCreation1h, &p.rates.Set.CacheCreation1h},
		{r.LongContextInputPerMTok, &p.rates.LongContextInput, &p.rates.Set.LongContextInput},
		{r.LongContextOutputPerMTok, &p.rates.LongContextOutput, &p.rates.Set.LongContextOutput},
		{r.LongContextCacheReadPerMTok, &p.rates.LongContextCacheRead, &p.rates.Set.LongContextCacheRead},
		{r.LongContextCacheWritePerMTok, &p.rates.LongContextCacheCreation, &p.rates.Set.LongContextCacheCreation},
		{r.LongContextCacheWrite1hPerMTok, &p.rates.LongContextCacheCreation1h, &p.rates.Set.LongContextCacheCreation1h},
		{r.WebSearchPerRequest, &p.rates.WebSearchPerRequest, &p.rates.Set.WebSearchPerRequest},
		{r.ReasoningPerMTok, &p.rates.Reasoning, &p.rates.Set.Reasoning},
		{r.RequestFeeUSD, &p.rates.RequestFee, &p.rates.Set.RequestFee},
		{r.CacheWriteOtherPerMTok, &p.rates.CacheCreationOther, &p.rates.Set.CacheCreationOther},
		{r.ImageInputPerMTok, &p.rates.ImageInput, &p.rates.Set.ImageInput},
		{r.ImageOutputPerImage, &p.rates.ImageOutputPerImage, &p.rates.Set.ImageOutputPerImage},
		{r.AudioInputPerMTok, &p.rates.AudioInput, &p.rates.Set.AudioInput},
		{r.AudioOutputPerMTok, &p.rates.AudioOutput, &p.rates.Set.AudioOutput},
	} {
		if f.src != nil {
			*f.dst, *f.set = *f.src, true
		}
	}
	// A row that quotes NO rate at all is refused individually rather than
	// taken as "price this model at zero". It is the same rule the publisher
	// enforces (Tokenomics migration 0023) and the org importer enforces
	// (pricing.ErrNoRate); repeating it here is belt-and-braces for a snapshot
	// hand-edited past the generator.
	if !p.rates.Set.Input && !p.rates.Set.Output {
		return p, "the row quotes neither an input nor an output rate"
	}
	if p.rates.negativeQuotedRate() {
		return p, "a quoted rate is negative"
	}
	if r.LongContextThreshold != nil {
		if *r.LongContextThreshold < 0 {
			return p, "the long-context threshold is negative"
		}
		// Present = quoted, 0 included ("no long-context tier"). The
		// generator carries the feed's (nullable since server migration 175)
		// threshold across with its presence intact, so a 0 here was stated
		// on purpose.
		p.rates.LongContextThreshold, p.rates.Set.LongContextThreshold = *r.LongContextThreshold, true
	}
	if r.FastMultiplier != nil {
		if *r.FastMultiplier < 0 {
			return p, "the fast multiplier is negative"
		}
		p.rates.FastMultiplier, p.rates.Set.FastMultiplier = *r.FastMultiplier, true
	}
	if r.Peak != nil {
		if peakHasNegativeRate(r.Peak) {
			return p, "a peak rate is negative"
		}
		// Copied so the parsed table never aliases the decoder's value. A
		// present-but-window-less peak is "quoted flat" and clears the seed's.
		cp := *r.Peak
		p.rates.Peak, p.rates.Set.Peak = &cp, true
	}
	from, ok := parseOrgEffectiveFrom(r.EffectiveFrom)
	if !ok {
		return p, "effective_from " + r.EffectiveFrom + " is not a date this build understands"
	}
	p.from = from
	return p, ""
}

func peakHasNegativeRate(pr *PeakRates) bool {
	for _, v := range []float64{
		pr.Input, pr.Output, pr.CacheRead, pr.CacheCreation, pr.CacheCreation1h,
		pr.LongContextInput, pr.LongContextOutput, pr.LongContextCacheRead,
		pr.LongContextCacheCreation, pr.LongContextCacheCreation1h,
	} {
		if v < 0 {
			return true
		}
	}
	return pr.LongContextThreshold < 0
}

// normalizeSnapshotModel matches the normalization the rest of the ladder uses
// for a model key, so a snapshot row and a seed row for the same model land on
// the same map key. It deliberately does NOT do family-prefix resolution: a
// snapshot row names one model.
func normalizeSnapshotModel(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// PricingSnapshot reports the embedded snapshot's provenance.
//
// Surfaces use it to say WHICH database version the compiled rates came from
// ("seed table, Tokenomics feed v7") instead of the bare "baked-in defaults"
// they could say before, and to surface Err when the embedded document was
// refused.
func PricingSnapshot() SnapshotMeta {
	loadSnapshot()
	out := snapshotMeta
	out.Skipped = append([]string(nil), snapshotMeta.Skipped...)
	return out
}

// SnapshotMinCacheable returns the per-model minimum cacheable prefix lengths
// the embedded snapshot carried, or an empty map.
//
// It exists so the cachetrack registry can be DATA from the same source as the
// prices instead of a second hand-edited table (the "three registries" class:
// cost pricing, cachetrack min-cacheable, routing tiers). The map is a fresh
// copy per call - small, called at wiring time and after each feed sync, and a
// shared map would be a data race waiting for its first concurrent reader.
func SnapshotMinCacheable() map[string]int {
	loadSnapshot()
	out := make(map[string]int, len(snapshotMinCacheable))
	for k, v := range snapshotMinCacheable {
		out[k] = v
	}
	return out
}

// applySnapshot folds the embedded snapshot onto a freshly-seeded table (the
// hand literal plus its baked dated timelines). It is called from [NewTable]
// only, inside the seed rung.
func applySnapshot(t *Table) {
	loadSnapshot()
	applySnapshotRows(t, snapshotRows)
}

// applySnapshotRows is applySnapshot's testable half.
//
// A model the snapshot names but the literal does not is ADDED (that is the
// whole point - a new model reaches the binary without a Go edit). A model both
// know is overlaid with PRESENCE semantics ([snapshotPrice.overlay]), so a
// snapshot that quotes only input/output cannot wipe the literal's cache-write
// rate, its long-context tier, its FastMultiplier or its peak schedule.
//
// A DATED row (effective_from set) keeps history: the rate in force before
// its instant is retained on the model's dated timeline and the overlaid rate
// applies from that instant on. An undated row ("since forever") overlays
// every period. Either way the flat table ends on the period in force at the
// table's clock, the invariant [Table.ValidateDated] checks.
//
// A model with TWO OR MORE rows is different: that is a PRICE HISTORY from the
// database (the feed row's `history`, one snapshot row per period - Tokenomics
// migration 0028), and the database is the authority for it. Its timeline is
// built from those rows ALONE ([Table.setSnapshotHistory]) and REPLACES any
// hand-written dated.go timeline for the key, so once a generated snapshot
// carries a model's history the Go table's copy is dead data (the
// hand-vs-snapshot test then asks for it to be deleted).
//
// [fillDefaults] is deliberately NOT applied here: it runs at lookup time in
// [Table.rate] for every row alike, so baking it in would only freeze a
// derived number into the table that BakedInDefaults exposes.
func applySnapshotRows(t *Table, rows map[string][]snapshotPrice) {
	if len(rows) == 0 {
		return
	}
	if t.exact == nil {
		t.exact = map[string]Pricing{}
	}
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(rows[key]) >= 2 {
			t.setSnapshotHistory(key, rows[key])
			continue
		}
		for _, r := range rows[key] {
			t.foldSnapshotRow(key, r)
		}
	}
}

// setSnapshotHistory installs a database price history for one key. Each
// period is a COMPLETE statement (a rate it does not quote did not exist in
// that period), so each is taken on its own - overlaid on an empty Pricing,
// never on the literal or on the period before it. rows must be ascending by
// start (parseSnapshot sorts them). Before a history whose first period has a
// start, NO rate is in force (an Unpriced period, a miss): the database's
// history is the whole statement for the key, and an id whose earlier card the
// database does not state (deepseek-chat before 2025-09-05) must not be billed
// at the literal's current rate.
func (t *Table) setSnapshotHistory(key string, rows []snapshotPrice) {
	var timeline []DatedPricing
	if !rows[0].from.IsZero() {
		// The database states no rate before its first period: nothing is in
		// force then (a miss), never the literal's current rate.
		timeline = append(timeline, DatedPricing{Unpriced: true})
	}
	for _, r := range rows {
		p := r.overlay(Pricing{})
		if n := len(timeline); n > 0 && !timeline[n-1].Unpriced && timeline[n-1].Pricing == p {
			continue // a restatement is not a new period
		}
		timeline = append(timeline, DatedPricing{EffectiveFrom: r.from.UTC(), Pricing: p})
	}
	t.exact[key] = currentOf(timeline, t.clockNow())
	if len(timeline) == 1 {
		delete(t.dated, key)
		return
	}
	t.setDated(key, timeline)
}

// foldSnapshotRow applies one snapshot row to one key. See applySnapshotRows.
func (t *Table) foldSnapshotRow(key string, r snapshotPrice) {
	flat, hasFlat := t.exact[key]
	timeline := append([]DatedPricing(nil), t.dated[key]...)

	switch {
	case r.from.IsZero():
		// "Since forever": the row's quoted dimensions hold at every instant.
		t.exact[key] = r.overlay(flat)
		for i := range timeline {
			timeline[i].Pricing = r.overlay(timeline[i].Pricing)
		}
		if len(timeline) > 0 {
			t.setDated(key, timeline)
			t.exact[key] = currentOf(timeline, t.clockNow())
		}
		return
	case !hasFlat && len(timeline) == 0:
		// A model the seed never priced: there is no earlier rate to keep.
		t.exact[key] = r.overlay(Pricing{})
		return
	}

	synthesized := len(timeline) == 0
	if synthesized {
		// The literal's flat row IS the rate before the snapshot's instant.
		timeline = []DatedPricing{{EffectiveFrom: time.Time{}, Pricing: flat}}
	}
	idx := -1
	for i := range timeline {
		if timeline[i].EffectiveFrom.After(r.from) {
			break
		}
		idx = i
	}
	inForce := timeline[0].Pricing
	if idx >= 0 {
		inForce = timeline[idx].Pricing
	}
	next := r.overlay(inForce)

	var out []DatedPricing
	switch {
	case idx >= 0 && timeline[idx].EffectiveFrom.Equal(r.from):
		out = append(out, timeline[:idx]...)
		out = append(out, DatedPricing{EffectiveFrom: r.from, Pricing: next})
	case next == inForce:
		// The row restates the rate already in force; no new period.
		out = append(out, timeline[:idx+1]...)
	default:
		out = append(out, timeline[:idx+1]...)
		out = append(out, DatedPricing{EffectiveFrom: r.from.UTC(), Pricing: next})
	}
	// Periods that start after the row's instant carry its quoted dimensions
	// too, until a later snapshot row says otherwise.
	for _, e := range timeline[idx+1:] {
		e.Pricing = r.overlay(e.Pricing)
		out = append(out, e)
	}

	t.exact[key] = currentOf(out, t.clockNow())
	if synthesized && len(out) == 1 {
		return // nothing changed history; keep the key off the dated path.
	}
	t.setDated(key, out)
}

func (t *Table) setDated(key string, timeline []DatedPricing) {
	if t.dated == nil {
		t.dated = map[string][]DatedPricing{}
	}
	t.dated[key] = timeline
}
