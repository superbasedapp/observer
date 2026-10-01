// Command pricing-snapshotgen projects a SIGNED Tokenomics pricing-feed bundle
// into the build-time price snapshot the cost engine embeds
// (internal/intelligence/cost/pricing_snapshot.json).
//
// WHY THIS EXISTS. Prices reach a RUNNING node with no release at all: the
// Tokenomics export is signed, served at GET /v1/observer-pricing, imported by
// the org server and handed to every enrolled node over the existing
// GET /api/agent/pricing rail (or pulled directly by a standalone node that
// opted in). What had no database source was the table a node holds BEFORE it
// has ever seen a feed: cold start, air gap, a hook process, an enrolled node
// that declined its org's rates. That table was a hand-written Go literal, so a
// new model needed a code edit, and code and database could disagree.
//
// This generator closes that: the compiled seed's generated half is a
// projection of the SAME published, SIGNED feed. Adding a model becomes a
// Tokenomics database row, a publish, and one make target - never a Go edit.
//
// THE INPUT IS THE SIGNED BUNDLE, DELIBERATELY. The generator takes the
// air-gap bundle `model-pricing/cmd/observerpublish` writes
// (dist/observer-pricing-v<N>.json), not a database connection. Three reasons,
// all load-bearing:
//
//  1. It VERIFIES. The bundle is checked with internal/pricingfeed.Verify
//     against the vendor keys compiled into this binary - the same check every
//     consumer runs. An unsigned, mis-signed or digest-mismatched body cannot
//     become the seed. A DSN could not offer that. Verify is stateless about
//     REPLAY, so this tool adds the replay rule itself: a bundle older than
//     the compiled floor (snapshotMinFeedVersion) or than the snapshot already
//     at -out is refused (review finding 2).
//  2. It is REPRODUCIBLE. Anyone reviewing the commit can re-run the generator
//     over the same bundle and get the same bytes. A DSN makes the artifact
//     depend on whatever the database held that afternoon.
//  3. It needs no database driver, no credential and no network, so it runs in
//     CI and on an air-gapped machine.
//
// USAGE
//
//	go run ./tools/pricing-snapshotgen -bundle dist/observer-pricing-v7.json
//	go run ./tools/pricing-snapshotgen -bundle dist/observer-pricing-v7.json -check
//
// -check writes nothing and exits non-zero when the committed snapshot differs
// from what the bundle would produce; that is the drift gate
// (`make verify-pricing-snapshot`), the same shape as
// `make verify-distribution-readmes`.
//
// WHAT IT DOES NOT DO. It does not rewrite defaultPricing. The hand literal
// stays as the permanent last-resort floor for everything the export cannot
// name in the node vocabulary - family-prefix rows, router and aggregator ids,
// and any dimension a row does not state. The snapshot is ADDITIVE over it,
// field by field with PRESENCE semantics (an absent long-context threshold,
// peak schedule or fast multiplier keeps the literal's), which is what makes
// partial Tokenomics coverage safe.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// defaultOut is the embedded artifact's path, relative to the repository root.
const defaultOut = "internal/intelligence/cost/pricing_snapshot.json"

// snapshotSchemaVersion must match cost.SnapshotSchemaVersion. It is restated
// here rather than imported so this tool does not drag the whole cost package
// (and its config/db dependencies) into a generator; snapshot_test.go pins the
// two together.
const snapshotSchemaVersion = 1

// snapshotMinFeedVersion must match cost.SnapshotMinFeedVersion (pinned by
// TestSnapshotGeneratorShapeMatchesConsumer). A bundle below it is refused:
// the hand literal in this tree already reflects every feed version before it,
// so projecting an older - still validly signed - bundle would roll the seed
// back.
const snapshotMinFeedVersion = 2

// snapshotDoc mirrors the document cost/snapshot.go parses. The field names and
// json tags are pinned against the cost package's own struct by
// TestSnapshotGeneratorShapeMatchesConsumer in internal/intelligence/cost.
type snapshotDoc struct {
	SchemaVersion int           `json:"schema_version"`
	FeedVersion   int64         `json:"feed_version"`
	Digest        string        `json:"digest"`
	KeyID         string        `json:"key_id"`
	GeneratedAt   string        `json:"generated_at"`
	Source        string        `json:"source"`
	Notes         string        `json:"notes,omitempty"`
	Rows          []snapshotRow `json:"rows"`
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
	// The extended rate dimensions (2026-09-30 pricing-chain contract), copied
	// as pointers like every other rate: nil = not stated.
	ReasoningPerMTok       *float64 `json:"reasoning_per_mtok,omitempty"`
	RequestFeeUSD          *float64 `json:"request_fee_usd,omitempty"`
	CacheWriteOtherPerMTok *float64 `json:"cache_write_other_per_mtok,omitempty"`
	ImageInputPerMTok      *float64 `json:"image_input_per_mtok,omitempty"`
	ImageOutputPerImage    *float64 `json:"image_output_per_image,omitempty"`
	AudioInputPerMTok      *float64 `json:"audio_input_per_mtok,omitempty"`
	AudioOutputPerMTok     *float64 `json:"audio_output_per_mtok,omitempty"`
	// FastMultiplier is the feed row's top-level fast_multiplier, else the one
	// in its Economics object; nil = the feed did not state it, and the
	// literal's value stays in force.
	FastMultiplier *float64 `json:"fast_multiplier,omitempty"`
	// Peak is the feed row's time-of-day variant, copied verbatim; nil = not
	// stated, and the literal's peak schedule stays in force.
	Peak               *orgcontract.PeakRates `json:"peak,omitempty"`
	MinCacheableTokens *int64                 `json:"min_cacheable_tokens,omitempty"`
	// ContextWindowTokens is the model's maximum context window as the feed's
	// economics stated it (Tokenomics falls back to model_versions when
	// model_economics has none). Not a rate; carried FLAT on each row so the
	// cost package's context-window registry reads it from this one artifact
	// (the latest dated row that states a window wins) instead of a hand
	// table. nil = the feed did not state it.
	ContextWindowTokens *int64 `json:"context_window_tokens,omitempty"`
}

const generatedNotes = "GENERATED by tools/pricing-snapshotgen from a signed Tokenomics pricing feed - do not hand-edit. " +
	"Regenerate with `make pricing-snapshot BUNDLE=<signed observer-pricing-vN.json>`; " +
	"`make verify-pricing-snapshot BUNDLE=...` is the drift gate. See internal/intelligence/cost/snapshot.go."

func main() {
	bundle := flag.String("bundle", "", "path to a SIGNED pricing-feed bundle written by model-pricing/cmd/observerpublish (required)")
	out := flag.String("out", defaultOut, "path of the snapshot to write")
	check := flag.Bool("check", false, "write nothing; exit non-zero if the file at -out differs from what -bundle would produce")
	flag.Parse()

	if err := run(*bundle, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "pricing-snapshotgen:", err)
		os.Exit(1)
	}
}

// run is the production entry point: it verifies against the keys THIS BINARY
// compiles in and nothing else. There is deliberately no flag to widen that
// set — a generator that could be pointed at an arbitrary key would not be a
// gate, it would be a formality.
func run(bundlePath, outPath string, check bool) error {
	return runWith(bundlePath, outPath, check, pricingfeed.CompiledKeySet())
}

// runWith is run's testable half. The key set is a parameter ONLY so the test
// suite can prove the SUCCESS path end to end with a throwaway key — the
// private half of the real key is operator-held and is not in this tree, so
// without this seam the only thing the suite could prove is the refusal.
func runWith(bundlePath, outPath string, check bool, keys pricingfeed.KeySet) error {
	if strings.TrimSpace(bundlePath) == "" {
		return errors.New("-bundle is required (a signed observer-pricing-vN.json from model-pricing/cmd/observerpublish)")
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	var env pricingfeed.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}
	// THE GATE. Exactly the check a node runs, against exactly the keys this
	// binary compiles in. An unsigned body, an unknown key id, a digest that
	// does not match the rows, or a row quoting no rate at all all stop here -
	// so an unverifiable feed can never become a shipped price table.
	if err := pricingfeed.Verify(env, keys); err != nil {
		return fmt.Errorf("refusing to generate from an unverifiable bundle: %w", err)
	}
	// THE REPLAY GATE. Verify proves who signed the body, not that it is the
	// newest thing they signed; a validly signed OLD bundle would otherwise
	// silently restore rates the tree has since corrected.
	if err := checkMonotonic(env, outPath); err != nil {
		return err
	}

	doc := snapshotDoc{
		SchemaVersion: snapshotSchemaVersion,
		FeedVersion:   env.FeedVersion,
		Digest:        env.Digest,
		KeyID:         env.KeyID,
		GeneratedAt:   env.GeneratedAt,
		Source:        filepath.Base(bundlePath),
		Notes:         generatedNotes,
		Rows:          rowsOf(env.Rows),
	}

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	encoded = append(encoded, '\n')

	if check {
		current, err := os.ReadFile(outPath)
		if err != nil {
			return fmt.Errorf("read %s for -check: %w", outPath, err)
		}
		if string(current) != string(encoded) {
			return fmt.Errorf("%s is STALE relative to %s - run `make pricing-snapshot BUNDLE=%s` and commit the result",
				outPath, bundlePath, bundlePath)
		}
		fmt.Printf("pricing snapshot up to date: feed_version %d, %d rows\n", doc.FeedVersion, len(doc.Rows))
		return nil
	}

	// 0600: the snapshot holds nothing secret (it is a published list price
	// destined for a public repository), but a generator has no business
	// widening a file's mode, and the repo's gosec gate enforces that.
	if err := os.WriteFile(outPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("wrote %s: feed_version %d, %d rows, digest %s\n", outPath, doc.FeedVersion, len(doc.Rows), doc.Digest)
	return nil
}

// checkMonotonic refuses a bundle that would move the snapshot BACKWARDS:
//
//   - below the compiled floor snapshotMinFeedVersion (the hand literal in this
//     tree already reflects everything older);
//   - below the feed_version of the snapshot already at outPath;
//   - AT that feed_version but with a different digest (the publisher bumps
//     the version on every content change, so equal version + different
//     content is not a newer feed, it is a different one).
//
// Equal version + equal digest is accepted: that is a byte-identical
// regeneration and what -check does. A missing outPath is a first
// generation; an outPath that exists but cannot be read as a snapshot is a
// refusal, because the rule cannot be evaluated against it.
func checkMonotonic(env pricingfeed.Envelope, outPath string) error {
	if env.FeedVersion < snapshotMinFeedVersion {
		return fmt.Errorf("refusing bundle feed_version %d: this tree's compiled floor is %d (an older bundle would roll the seed back)",
			env.FeedVersion, snapshotMinFeedVersion)
	}
	raw, err := os.ReadFile(outPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing snapshot %s: %w", outPath, err)
	}
	var existing snapshotDoc
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("existing snapshot %s is unreadable, so the replay rule cannot be checked: %w", outPath, err)
	}
	switch {
	case env.FeedVersion < existing.FeedVersion:
		return fmt.Errorf("refusing bundle feed_version %d: %s is already at feed_version %d (a snapshot only moves forward)",
			env.FeedVersion, outPath, existing.FeedVersion)
	case env.FeedVersion == existing.FeedVersion && existing.Digest != "" && env.Digest != existing.Digest:
		return fmt.Errorf("refusing bundle feed_version %d digest %s: %s is at the same feed_version with digest %s (same version, different content)",
			env.FeedVersion, env.Digest, outPath, existing.Digest)
	}
	return nil
}

// rowsOf projects the verified feed rows onto the snapshot's shape.
//
// It is a straight field copy with NO arithmetic, which is the point: the feed
// row is already authored in cost.Pricing's vocabulary. The pointers are copied
// as pointers so the nil-vs-quoted-zero distinction survives - a nil rate means
// "the export quotes nothing here" and the hand literal's value stays in force,
// while a rate set to zero means "quoted free" and wins.
//
// The pointers are RE-BOXED rather than aliased. Sharing the envelope's
// pointers would work today (nothing mutates them) and would be a trap
// tomorrow, when a caller that reused the envelope found the snapshot had
// changed underneath it.
//
// Rows are sorted by model so the artifact is byte-stable regardless of feed
// order - a generated file that reorders itself makes every diff unreadable and
// every drift gate a coin flip.
func rowsOf(in []pricingfeed.Row) []snapshotRow {
	out := make([]snapshotRow, 0, len(in))
	for _, r := range in {
		// A row with a PRICE HISTORY (Tokenomics migration 0028) is emitted as
		// one snapshot row per period, each at its own effective_from: the
		// cost package reads two or more rows for one model as that model's
		// database-authored timeline (snapshot.go, setSnapshotHistory), which
		// replaces the hand-written dated.go copy. The top-level row is one of
		// the periods (pricingfeed.Verify has checked the shape), so it is not
		// emitted separately. The min-cacheable fact is not dated; it rides on
		// every period row.
		if len(r.History) >= 2 {
			var minCacheable, window *int64
			if r.Economics != nil && r.Economics.MinCacheableTokens != nil && *r.Economics.MinCacheableTokens > 0 {
				minCacheable = r.Economics.MinCacheableTokens
			}
			if r.Economics != nil && r.Economics.ContextWindowTokens != nil && *r.Economics.ContextWindowTokens > 0 {
				window = r.Economics.ContextWindowTokens
			}
			for _, p := range r.History {
				row := rowOf(p)
				row.MinCacheableTokens = clone(minCacheable)
				// A period's own economics wins; the in-force row's window is
				// the fallback (a window, like the min-cacheable fact, is a
				// model property the history does not usually restate).
				if row.ContextWindowTokens == nil {
					row.ContextWindowTokens = clone(window)
				}
				out = append(out, row)
			}
			continue
		}
		out = append(out, rowOf(r))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Model != out[j].Model {
			return out[i].Model < out[j].Model
		}
		return out[i].EffectiveFrom < out[j].EffectiveFrom
	})
	return out
}

// rowOf projects ONE feed row (a top-level row or a history period) onto the
// snapshot's shape. See rowsOf.
func rowOf(r pricingfeed.Row) snapshotRow {
	// Every float decode boundary rounds to the Tokenomics NUMERIC(20,10)
	// grid (the 2026-09-30 contract), the generator included, so the snapshot
	// and the live feed path can never disagree in the last binary digit.
	r.PricingPolicyRow = r.PricingPolicyRow.RoundedRates()
	row := snapshotRow{
		Model:                          r.Model,
		EffectiveFrom:                  r.EffectiveFrom,
		InputPerMTok:                   clone(r.InputPerMTok),
		OutputPerMTok:                  clone(r.OutputPerMTok),
		CacheReadPerMTok:               clone(r.CacheReadPerMTok),
		CacheWritePerMTok:              clone(r.CacheWritePerMTok),
		CacheWrite1hPerMTok:            clone(r.CacheWrite1hPerMTok),
		LongContextInputPerMTok:        clone(r.LongContextInputPerMTok),
		LongContextOutputPerMTok:       clone(r.LongContextOutputPerMTok),
		LongContextCacheReadPerMTok:    clone(r.LongContextCacheReadPerMTok),
		LongContextCacheWritePerMTok:   clone(r.LongContextCacheWritePerMTok),
		LongContextCacheWrite1hPerMTok: clone(r.LongContextCacheWrite1hPerMTok),
		WebSearchPerRequest:            clone(r.WebSearchPerRequest),
		ReasoningPerMTok:               clone(r.ReasoningPerMTok),
		RequestFeeUSD:                  clone(r.RequestFeeUSD),
		CacheWriteOtherPerMTok:         clone(r.CacheWriteOtherPerMTok),
		ImageInputPerMTok:              clone(r.ImageInputPerMTok),
		ImageOutputPerImage:            clone(r.ImageOutputPerImage),
		AudioInputPerMTok:              clone(r.AudioInputPerMTok),
		AudioOutputPerMTok:             clone(r.AudioOutputPerMTok),
	}
	// LongContextThreshold is nullable on the feed row since server
	// migration 175 / pg 0041, with the presence rule the snapshot
	// already speaks: absent = the export does not know the tier (the
	// operator-captured lane has no long-context fields, and the export
	// omits a 0), so the literal's tier stays in force (review finding
	// 1); a stated value, INCLUDING a stated 0 ("flat"), is a statement
	// and is carried across as-is.
	row.LongContextThreshold = clone(r.LongContextThreshold)
	row.Peak = clonePeak(r.Peak)
	switch {
	case r.FastMultiplier != nil:
		row.FastMultiplier = clone(r.FastMultiplier)
	case r.Economics != nil && r.Economics.FastMultiplier != nil:
		fm := orgcontract.RoundPrice(*r.Economics.FastMultiplier)
		row.FastMultiplier = &fm
	}
	// The ONE non-rate fact carried across: the min-cacheable prefix, when
	// the publisher knew it. It rides in the feed's Economics object (which
	// the node engine never reads) and lands on the snapshot so ONE
	// generated artifact can feed both the price registry and the
	// cachetrack min-cacheable registry, instead of two hand-edited tables
	// drifting apart on every model release. Everything else in Economics
	// except FastMultiplier (lifted above) - cache_mode, reasoning billing,
	// context window, ... - is display-only today and is deliberately NOT
	// copied - carrying a fact nothing reads would be noise in a generated
	// diff.
	if r.Economics != nil && r.Economics.MinCacheableTokens != nil && *r.Economics.MinCacheableTokens > 0 {
		row.MinCacheableTokens = clone(r.Economics.MinCacheableTokens)
	}
	// The context window, likewise a model fact rather than a rate, is
	// carried flat for the context-window registry.
	if r.Economics != nil && r.Economics.ContextWindowTokens != nil && *r.Economics.ContextWindowTokens > 0 {
		row.ContextWindowTokens = clone(r.Economics.ContextWindowTokens)
	}
	return row
}

func clone[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// clonePeak deep-copies a peak variant so the snapshot never aliases the
// envelope's schedule slices.
func clonePeak(p *orgcontract.PeakRates) *orgcontract.PeakRates {
	if p == nil {
		return nil
	}
	out := *p
	out.Schedule.Windows = make([]orgcontract.PeakWindow, len(p.Schedule.Windows))
	for i, w := range p.Schedule.Windows {
		w.Days = append([]time.Weekday(nil), w.Days...)
		out.Schedule.Windows[i] = w
	}
	return &out
}
