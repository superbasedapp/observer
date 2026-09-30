package cost

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// GroupBy selects how summary rows are keyed.
type GroupBy string

const (
	GroupByModel      GroupBy = "model"
	GroupBySession    GroupBy = "session"
	GroupByDay        GroupBy = "day"
	GroupByDayModel   GroupBy = "day_model"
	GroupByDayProject GroupBy = "day_project"
	GroupByDayTool    GroupBy = "day_tool"
	GroupByProject    GroupBy = "project"
	GroupByTool       GroupBy = "tool"
	GroupByModelTool  GroupBy = "model_tool"
	GroupByNone       GroupBy = "none"
)

// dayModelKeySep separates the date and dimension halves of any
// GroupByDay<X> key. Chosen for SQLite/JSON safety (no escaping
// concerns) and because no model / project path / tool id contains
// the literal `||`.
const dayModelKeySep = "||"

// SplitDayModelKey unpacks a Row.Key produced under GroupByDayModel
// into (date, model). Returns ("", key) if the separator is missing,
// so callers can degrade gracefully.
func SplitDayModelKey(key string) (day, model string) {
	return splitDayDimKey(key)
}

// SplitDayProjectKey unpacks a GroupByDayProject Row.Key into
// (date, project_root_path). Same separator as SplitDayModelKey.
func SplitDayProjectKey(key string) (day, project string) {
	return splitDayDimKey(key)
}

// SplitDayToolKey unpacks a GroupByDayTool Row.Key into (date, tool).
func SplitDayToolKey(key string) (day, tool string) {
	return splitDayDimKey(key)
}

// SplitModelToolKey unpacks a GroupByModelTool Row.Key into (model, tool).
// The joint key is `model || dayModelKeySep || tool` (the G25 aggregate rail's
// read path). Returns ("", key) if the separator is missing so callers can
// degrade gracefully; the model/tool sentinels ("<unknown>" / "<no-tool>")
// come back verbatim for the caller to normalize.
func SplitModelToolKey(key string) (model, tool string) {
	return splitDayDimKey(key)
}

func splitDayDimKey(key string) (day, dim string) {
	if i := strings.Index(key, dayModelKeySep); i >= 0 {
		return key[:i], key[i+len(dayModelKeySep):]
	}
	return "", key
}

// Source selects which token sources feed the summary. The default (Proxy)
// is accurate; JSONL is approximate/unreliable. Auto prefers proxy for
// sessions where both exist and falls back to JSONL for the rest — most
// realistic because the proxy often lacks a session_id.
//
// SourceAuto also includes summary_calls (D20 internal Haiku spend that
// goes direct to api.anthropic.com, bypassing the proxy). These rows
// don't dedup against proxy/jsonl because they represent observer-
// initiated calls — different turns, different content. Surfacing them
// makes get_cost_summary / observer cost / dashboard cost-by-model see
// the real total Anthropic spend, not "user-facing turns only".
type Source string

const (
	SourceProxy        Source = "proxy"
	SourceJSONL        Source = "jsonl"
	SourceSummaryCalls Source = "summary_calls"
	SourceAuto         Source = "auto"
)

// Options parameterize Summary.
type Options struct {
	// Days restricts to rows with timestamp ≥ now - Days. Zero means no
	// restriction.
	Days int
	// Since overrides Days when non-zero.
	Since time.Time
	// Until is an optional upper bound on row timestamps (exclusive of
	// "now"). Used by callers that want a closed window — e.g. the
	// Analysis movers endpoint querying the prior period as
	// [now-2N, now-N). Zero means no upper bound (rows up to now).
	Until time.Time
	// GroupBy is the rollup key. Defaults to GroupByModel.
	GroupBy GroupBy
	// Source selects which tables feed the rollup. Defaults to SourceAuto.
	Source Source
	// ProjectRoot filters rows to a single project by matching projects.root_path.
	ProjectRoot string
	// ProjectID filters rows to a single project by id. Takes precedence
	// over ProjectRoot when both are set (avoids an extra projects-table
	// round trip for a caller that already resolved the id — e.g. the
	// Projects page). Proxy rows are scoped by COALESCE(at.project_id,
	// s.project_id): api_turns.project_id is NULL on every row of every
	// grounded install (the proxy learns the session id, not the cwd),
	// so keying on it alone would silently drop every proxy turn from a
	// project-scoped query (2026-09-22 arc review F6/F9 — the same bug
	// internal/store/projectroi.go's turn loader already worked around;
	// this closes it at the engine's own loadProxyRows instead of a
	// parallel loader).
	ProjectID int64
	// Tool filters rows to a single tool by matching sessions.tool. Empty
	// means no tool filter. Mirrors the dashboard's global Tool dropdown
	// so cost rollups can scope to "what did codex cost me this month".
	Tool string
	// SessionIDs scopes the row scan to a specific set of session_ids
	// across api_turns / token_usage / summary_calls. Empty means no
	// session filter. Lets callers like handleSessions amortize one
	// engine call across exactly the page they're rendering instead of
	// loading every row in the window and discarding most of them.
	SessionIDs []string
	// Limit caps returned rows (after sort by cost_usd desc). Zero means 50.
	Limit int
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
	// BucketKey, when set, replaces the calendar-day half of every
	// GroupByDay / GroupByDayModel / GroupByDayProject / GroupByDayTool key
	// (the UTC date prefix of the row's timestamp) with BucketKey(ts) - the
	// bucket grouping the dashboard's time-series use for 5-minute, hour,
	// viewer-local day and week buckets (internal/timebucket supplies the
	// floor; the engine stays free of the vocabulary). Hour and day views of
	// one window therefore come from the SAME rows and the SAME per-row
	// pricing, so their totals agree. ts is the row's stored timestamp
	// string; the func must be pure. Nil keeps the UTC-day prefix.
	BucketKey func(ts string) string
}

// Row is one grouped summary entry.
type Row struct {
	Key    string      `json:"key"`
	Tokens TokenBundle `json:"tokens"`
	// CostUSD is the legacy total (AI + tool). AICostUSD and
	// ToolCostUSD split it so the dashboard can show "API spend"
	// vs "tool fees" (web_search calls, etc.) separately.
	// CostUSD == AICostUSD + ToolCostUSD always.
	CostUSD     float64 `json:"cost_usd"`
	AICostUSD   float64 `json:"ai_cost_usd"`
	ToolCostUSD float64 `json:"tool_cost_usd"`
	// TurnCount is how many underlying rows (api_turns + token_usage) fed
	// this group.
	TurnCount int `json:"turn_count"`
	// AvgLatencyMS is the proxy-observed mean request → response time
	// across the proxy rows in this bucket (V3-5). 0 when no proxy
	// rows contributed (JSONL-only buckets). Computed as
	// SUM(api_turns.total_response_ms) / COUNT(rows with latency > 0).
	AvgLatencyMS int64 `json:"avg_latency_ms,omitempty"`
	// Source is "proxy", "jsonl", or "mixed" depending on which tables fed
	// the group.
	Source string `json:"source"`
	// Reliability is the weakest reliability tag among the rows in the
	// group: "accurate" > "approximate" > "unreliable" > "unknown". The
	// weakest wins so callers know how much to trust the number.
	Reliability string `json:"reliability"`
	// UnknownModels lists model ids that had no pricing entry. Their token
	// counts are still summed; their cost contribution is zero.
	UnknownModels []string `json:"unknown_models,omitempty"`
	// PricingSource reports how the pricing-table lookup resolved across
	// every row that fed this bucket: "exact" / "date-stripped" /
	// "family" / "miss" / "mixed" (multiple paths used). The dashboard
	// surfaces a "~" badge alongside Reliability when this is anything
	// other than "exact" so users can see which numbers came from
	// fallback rates. Empty when no row in the bucket was priced (e.g.
	// every row had recorded estimated_cost_usd).
	PricingSource string `json:"pricing_source,omitempty"`
	// Compression aggregates conversation-layer compression savings over
	// the turns in this group (spec §10 Layer 3 / §24). Only proxy rows
	// contribute — JSONL doesn't see the pre-forward body.
	Compression CompressionStats `json:"compression"`
	// FastTurnCount / FastCostUSD report the subset of this group's turns
	// served in the provider's low-latency "fast" tier (Anthropic Opus
	// 4.8 speed:"fast"). FastCostUSD already reflects the FastMultiplier
	// premium (it's summed from the same per-row cost as CostUSD). Both
	// zero when no fast turns fed the group; the dashboard badges the row
	// only when FastTurnCount > 0. omitempty keeps the common (no-fast)
	// payload lean.
	FastTurnCount int     `json:"fast_turn_count,omitempty"`
	FastCostUSD   float64 `json:"fast_cost_usd,omitempty"`
	// UnpricedTurnCount is this bucket's share of Summary.
	// UnpricedTurnCount — the number of this group's rows that are not
	// FULLY priced: a pricing MISS (no recorded cost AND no pricing-table
	// entry), or a table price whose cache-read rate the vendor never
	// quoted (TurnRow.FullyPriced's same verdict). Added
	// 2026-09-22 so a GroupByProject caller (the Projects list) can
	// report "N turns we couldn't price" per project without a second
	// query — the same count the Projects detail panel's
	// spend.unpriced_turns already surfaces for one project.
	UnpricedTurnCount int `json:"unpriced_turn_count,omitempty"`
	// PricedTurnCount is TurnCount - UnpricedTurnCount: this bucket's
	// rows that DID resolve to a dollar figure (a recorded cost, or a
	// pricing-table hit — including a known-free model's real $0.00).
	// Added 2026-09-22 rework finding #13 so a caller can tell "every
	// turn in this bucket priced to exactly $0.00" (PricedTurnCount ==
	// TurnCount, CostUSD == 0 — a real, known-free-model zero) apart
	// from "we have no pricing coverage for this bucket at all"
	// (PricedTurnCount == 0) without a second query.
	PricedTurnCount int `json:"priced_turn_count,omitempty"`
}

// CompressionStats aggregates savings metadata across every proxy turn
// in a rollup group. See spec §10 Layer 3 step 11.
//
// Bytes are what the proxy can measure directly (it sees the JSON body
// before and after the pipeline runs). Tokens are what cost dollars,
// so we derive a token-savings estimate using Anthropic's tokenizer
// rule of thumb (~4 chars per token on typical English/code) and a
// dollar-savings estimate using the row's model input rate (since
// dropped/compressed content is prompt context).
//
// TokensSavedEst and CostSavedUSDEst are SIGNED — when compression
// makes the payload larger (small payloads where marker overhead
// exceeds what was dropped), they go negative. Aggregating across many
// turns can still net positive even when individual rows are negative.
type CompressionStats struct {
	// OriginalBytes is the sum of pre-compression request body sizes.
	OriginalBytes int64 `json:"original_bytes"`
	// CompressedBytes is the sum of post-compression request body sizes.
	CompressedBytes int64 `json:"compressed_bytes"`
	// CompressedCount is the number of tool_result bodies rewritten.
	CompressedCount int64 `json:"compressed_count"`
	// DroppedCount is the number of original messages replaced by markers.
	DroppedCount int64 `json:"dropped_count"`
	// MarkerCount is the number of marker messages emitted.
	MarkerCount int64 `json:"marker_count"`
	// Turns is the number of turns in this group that had any
	// compression metadata (i.e. proxy turns with compression enabled).
	Turns int `json:"turns"`
	// TokensSavedEst is the byte-saving converted to tokens via the
	// ~4 chars/token rule of thumb. Signed.
	TokensSavedEst int64 `json:"tokens_saved_est"`
	// CostSavedUSDEst is TokensSavedEst valued at a blended input-side
	// rate that mirrors the row's realized Input vs CacheRead share.
	// V7-6 fix (v1.7.6): pre-v1.7.6 this column used pricing.Input
	// flat, which overstated codex/OpenAI savings by ~10× because
	// codex sessions are cache_read-dominant (cache_read is ~10×
	// cheaper than net input). Anthropic sessions are unchanged
	// (their CacheRead share is low). Signed.
	CostSavedUSDEst float64 `json:"cost_saved_usd_est"`
	// CostSavedUSDEstInputTier is the upper-bound USD savings assuming
	// every compressed token would have been billed at the net-input
	// tier (pricing.Input). Equivalent to pre-v1.7.6 cost_saved_usd_est.
	// Useful for operators who want the "if I had paid the worst-case
	// rate" headline. Signed.
	CostSavedUSDEstInputTier float64 `json:"cost_saved_usd_est_input_tier"`
	// CostSavedUSDEstCacheReadTier is the lower-bound USD savings
	// assuming every compressed token would have been billed at the
	// cache_read tier (pricing.CacheRead). Useful for cache-dominant
	// sessions (codex / OpenAI). Signed.
	CostSavedUSDEstCacheReadTier float64 `json:"cost_saved_usd_est_cache_read_tier"`
}

// Add merges other into c.
func (c *CompressionStats) Add(other CompressionStats) {
	c.OriginalBytes += other.OriginalBytes
	c.CompressedBytes += other.CompressedBytes
	c.CompressedCount += other.CompressedCount
	c.DroppedCount += other.DroppedCount
	c.MarkerCount += other.MarkerCount
	c.Turns += other.Turns
	c.TokensSavedEst += other.TokensSavedEst
	c.CostSavedUSDEst += other.CostSavedUSDEst
	c.CostSavedUSDEstInputTier += other.CostSavedUSDEstInputTier
	c.CostSavedUSDEstCacheReadTier += other.CostSavedUSDEstCacheReadTier
}

// SavedBytesSigned returns OriginalBytes - CompressedBytes (can be
// negative when compression added marker overhead beyond what was
// dropped). SavedBytes() (above) clamps to non-negative for backward
// compatibility with summary text formatting.
func (c CompressionStats) SavedBytesSigned() int64 {
	return c.OriginalBytes - c.CompressedBytes
}

// SavedBytes returns max(0, OriginalBytes - CompressedBytes).
func (c CompressionStats) SavedBytes() int64 {
	if c.CompressedBytes >= c.OriginalBytes {
		return 0
	}
	return c.OriginalBytes - c.CompressedBytes
}

// SavedRatio returns the fraction of bytes saved in [0, 1]. Zero when no
// compression data is present.
func (c CompressionStats) SavedRatio() float64 {
	if c.OriginalBytes <= 0 {
		return 0
	}
	ratio := float64(c.SavedBytes()) / float64(c.OriginalBytes)
	if ratio < 0 {
		return 0
	}
	if ratio > 1 {
		return 1
	}
	return ratio
}

// Summary is the result of Engine.Summary.
type Summary struct {
	GroupBy     GroupBy     `json:"group_by"`
	Source      Source      `json:"source"`
	Days        int         `json:"days,omitempty"`
	Since       string      `json:"since,omitempty"`
	Rows        []Row       `json:"rows"`
	TotalTokens TokenBundle `json:"total_tokens"`
	TotalCost   float64     `json:"total_cost_usd"`
	TurnCount   int         `json:"turn_count"`
	// FastTurnCount / TotalFastCostUSD report fast-tier (Opus 4.8
	// speed:"fast") spend over the whole window. TotalFastCostUSD already
	// carries the FastMultiplier premium. The Cost page renders a small
	// "fast-tier" stat when FastTurnCount > 0. omitempty keeps the
	// common (no-fast) payload lean.
	FastTurnCount    int     `json:"fast_turn_count,omitempty"`
	TotalFastCostUSD float64 `json:"total_fast_cost_usd,omitempty"`
	Reliability      string  `json:"reliability"`
	// UnknownModelCount is the number of distinct unknown models seen.
	UnknownModelCount int `json:"unknown_model_count,omitempty"`
	// UnpricedTokens is input+output token volume on rows that resolved to a
	// pricing MISS (empty or unknown model) and were billed $0. It volume-
	// weights UnknownModelCount so a whole-adapter attribution regression
	// (e.g. copilotcli Tier-1 rows going empty-model) is loud rather than
	// hidden behind a small distinct-model count (often just the single
	// empty string "").
	UnpricedTokens int64 `json:"unpriced_tokens,omitempty"`
	// UnpricedTurnCount is the number of rows that hit a pricing MISS.
	UnpricedTurnCount int `json:"unpriced_turn_count,omitempty"`
	// TotalCompression aggregates conversation compression savings over
	// the whole window.
	TotalCompression CompressionStats `json:"total_compression"`
}

// rawRow is the shape pulled from SQLite; kept unexported because callers
// never see it.
type rawRow struct {
	model       string
	tokens      TokenBundle
	recordedUSD float64 // cost_usd column, when set (proxy only)
	ts          string
	sessionID   string
	projectPath string
	tool        string
	source      string // "proxy" | "jsonl"
	reliability string
	compression CompressionStats // non-zero only for proxy rows with savings
	// latencyMS is the proxy-observed total response time in ms
	// (api_turns.total_response_ms). Zero for JSONL rows — the
	// adapter path doesn't see request → response wall time.
	// V3-5 surfaces the bucket average as Row.AvgLatencyMS.
	latencyMS int64
	// turnID identifies one upstream API turn: api_turns.request_id for a
	// proxy row, token_usage.source_event_id for a transcript row. It is
	// reported back as TurnRow.TurnID; the proxy/transcript dedup itself is
	// the stored verdicts (loadRows).
	turnID string
}

// isNoiseRow drops rawRows that don't represent a real API call:
//
//  1. model == "<synthetic>" — Claude Code's compaction / subagent
//     stitching placeholder. The C4 forward fix dropped these at the
//     adapter, but ~19 historical rows persist in the live install.
//     Surfacing them as a separate model bucket on the Cost tab is
//     confusing (the angle-bracketed string also renders invisibly
//     in HTML), and they always carry zero usage anyway, so the row
//     adds nothing.
//
//  2. Every token column AND the recorded cost is zero. Pre-B2 the
//     proxy logged turns even when the upstream stream ended without
//     any usage event (cancellation, mid-flight error). The B2 forward
//     filter now drops these at insert; this catches the historical
//     residue plus any future shape that lands the same way through
//     the JSONL path.
//
// Returning true here causes the row to be skipped at load time so
// turn_count, total_tokens, and total_cost_usd all stay coherent.
func isNoiseRow(r rawRow) bool {
	if r.model == "<synthetic>" {
		return true
	}
	allZeroTokens := r.tokens.Input == 0 && r.tokens.Output == 0 &&
		r.tokens.CacheRead == 0 && r.tokens.CacheCreation == 0 &&
		r.tokens.Reasoning == 0 && r.tokens.WebSearchRequests == 0
	if allZeroTokens && r.recordedUSD == 0 {
		return true
	}
	return false
}

// MaxSessionIDsPerScope bounds how many session ids ride in ONE Options.
// SessionIDs scope. Each id becomes a bound parameter in every source query
// (api_turns / token_usage / summary_calls), and SQLite refuses a statement
// with more than SQLITE_MAX_VARIABLE_NUMBER (32766 in modernc.org/sqlite) of
// them — "SQL logic error: too many SQL variables (1)". 900 leaves ample room
// for the window/project/tool binds that share the statement and keeps each
// prepared statement small enough to plan cheaply.
const MaxSessionIDsPerScope = 900

// SessionRowsByID prices an ARBITRARILY LARGE set of session ids and returns
// the per-session rows keyed by session id. It is the ONE place that knows the
// bind-variable ceiling: ids are de-duplicated, chunked into
// MaxSessionIDsPerScope batches, and each batch runs its own GroupBySession
// Summary. Merging the batches is safe because a session id lands in exactly
// one chunk, so no group is ever split across queries (aggregation stays
// additive and nothing is double-counted).
//
// Shared by BOTH tag-rollup call sites — internal/intelligence/dashboard's
// Server.tagRollup (GET /api/sessions/tags) and cmd/observer's computeTagRollup
// (`observer tags`) — so a large tag vocabulary can't blow the bind cap on one
// surface and not the other. Callers own GroupBy/Limit: this helper forces
// GroupBySession and sizes Limit to the chunk, since a per-chunk limit would
// otherwise silently drop sessions from the merged map.
func (e *Engine) SessionRowsByID(ctx context.Context, db *sql.DB, opts Options, sessionIDs []string) (map[string]Row, error) {
	out := make(map[string]Row, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return out, nil
	}
	// De-duplicate first: a repeated id in two different chunks would be
	// counted twice in the merged map.
	seen := make(map[string]struct{}, len(sessionIDs))
	ids := make([]string, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += MaxSessionIDsPerScope {
		end := start + MaxSessionIDsPerScope
		if end > len(ids) {
			end = len(ids)
		}
		chunk := opts
		chunk.GroupBy = GroupBySession
		chunk.SessionIDs = ids[start:end]
		chunk.Limit = len(chunk.SessionIDs)
		summary, err := e.Summary(ctx, db, chunk)
		if err != nil {
			return nil, fmt.Errorf("cost.SessionRowsByID: %w", err)
		}
		for _, row := range summary.Rows {
			out[row.Key] = row
		}
	}
	return out, nil
}

// Summary runs the query against db and returns a grouped rollup.
func (e *Engine) Summary(ctx context.Context, db *sql.DB, opts Options) (Summary, error) {
	if opts.GroupBy == "" {
		opts.GroupBy = GroupByModel
	}
	if opts.Source == "" {
		opts.Source = SourceAuto
	}
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	since := opts.Since
	if since.IsZero() && opts.Days > 0 {
		since = opts.Now().Add(-time.Duration(opts.Days) * 24 * time.Hour)
	}

	rows, err := e.loadRows(ctx, db, opts, since)
	if err != nil {
		return Summary{}, err
	}
	s := e.rollup(rows, opts)
	s.Days = opts.Days
	if !since.IsZero() {
		s.Since = since.UTC().Format(time.RFC3339)
	}
	return s, nil
}

// TurnRow is one normalized, de-duplicated, PRICED API turn — the
// per-turn (not bucket-grain) substrate the Projects page needs
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md,
// 2026-09-22 rework). It is computed by the SAME loadRows pipeline
// Summary uses (proxy/JSONL/summary_calls union, noise filtering, the
// stored sessionmsg dedup verdicts - twins, shadow rows, the
// session-cumulative reconciliation - and the fast-tier lift) and the SAME
// priceRow pricing rule Summary's
// rollup uses, so a caller scoped to one project sees EXACTLY the turns
// and dollars a GroupByProject Summary would sum for that project. One
// owner, two grains.
type TurnRow struct {
	SessionID string
	At        time.Time
	Model     string
	Tool      string
	// Source is "proxy" | "jsonl" | "summary_calls" — the capture path
	// that supplied the row surviving dedup.
	Source string
	// TurnID is the upstream turn/message id when the capture path
	// recorded one (empty for a legacy orphan proxy row or a
	// session-aggregate JSONL row).
	TurnID string
	// CostUSD is 0 when Priced is false — never a fabricated $0.00.
	CostUSD float64
	// Priced is false only when the row had NO recorded cost AND NO
	// pricing-table entry at all for its model. A model with an
	// explicit $0 rate (a known-free model) IS priced — Priced=true,
	// CostUSD=0 — Priced=false means "no rate found", not "free".
	Priced bool
	// CacheReadUnpriced is true when the row was priced from the table but
	// its model's CACHE-READ rate was never quoted by the vendor
	// ([Engine.CacheReadUnpricedAt]), so its cached tokens billed an
	// intentional unpriced $0 - a PARTIAL price. It is priceRow's own
	// signal, the same one Summary's rollup reports as a miss; read the
	// combined verdict through [TurnRow.FullyPriced].
	CacheReadUnpriced bool
	Tokens            TokenBundle
	// RecordedUSD is the capture path's own recorded cost for this row
	// (api_turns.cost_usd / token_usage.estimated_cost_usd), 0 when none
	// was recorded or when the dedup cleared it to re-price a fast-lifted
	// proxy twin. CostUSD already folds it in (priceRow); it is exposed so
	// a caller that decomposes a turn's cost against the pricing table
	// (the Analysis tab's LC / cache-savings attribution) can tell a
	// recorded figure from a table-priced one.
	RecordedUSD float64
	// ProjectPath is the resolved projects.root_path for this row
	// (COALESCE(at.project_id, s.project_id) for a proxy row; s.
	// project_id for a JSONL row). Empty when the row could not be
	// attributed to any project.
	ProjectPath string
}

// FullyPriced reports whether every token of this turn was priced: a rate was
// found (Priced) AND no dimension billed against an unquoted rate
// (CacheReadUnpriced). It is the one predicate a per-turn surface (the
// Projects page's unpriced / coverage counts) counts against, so a partially
// priced turn is never presented as an exact figure - the same verdict
// Summary's rollup reaches for the same row.
func (r TurnRow) FullyPriced() bool { return r.Priced && !r.CacheReadUnpriced }

// TurnRows runs the same load-and-dedup pipeline Summary does and
// returns the per-turn PRICED rows instead of bucket-grouped ones.
// opts.GroupBy is ignored (there is no grouping at this grain);
// opts.Limit is ignored (a turn-grain caller — the Projects page —
// needs every turn in its window, not a top-N slice). Scope with
// opts.ProjectID (preferred) or opts.ProjectRoot the same way Summary
// is scoped.
func (e *Engine) TurnRows(ctx context.Context, db *sql.DB, opts Options) ([]TurnRow, error) {
	if opts.Source == "" {
		opts.Source = SourceAuto
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	since := opts.Since
	if since.IsZero() && opts.Days > 0 {
		since = opts.Now().Add(-time.Duration(opts.Days) * 24 * time.Hour)
	}
	raws, err := e.loadRows(ctx, db, opts, since)
	if err != nil {
		return nil, err
	}
	out := make([]TurnRow, 0, len(raws))
	for _, r := range raws {
		// TurnRows always needs a real timestamp on the output row (a
		// caller derives session windows / day buckets from it), so —
		// unlike rollup's dateAware-gated parse — this always parses.
		at, _ := time.Parse(time.RFC3339Nano, r.ts)
		pr := e.priceRow(r, at)
		out = append(out, TurnRow{
			SessionID: r.sessionID, At: at, Model: r.model, Tool: r.tool,
			Source: r.source, TurnID: r.turnID,
			CostUSD: pr.CostUSD, Priced: pr.Priced, CacheReadUnpriced: pr.CacheReadUnpriced,
			Tokens:      r.tokens,
			RecordedUSD: r.recordedUSD,
			ProjectPath: r.projectPath,
		})
	}
	return out, nil
}

// pricedRow is priceRow's result — the per-row pricing computation
// shared by rollup (bucket aggregation) and TurnRows (per-turn export)
// so the two surfaces can never disagree about what one turn costs.
type pricedRow struct {
	CostUSD       float64
	AICostUSD     float64
	ToolCostUSD   float64
	PricingSource PricingSource
	// Priced is false when the row had no recorded cost AND no pricing
	// entry for its model at all (see TurnRow.Priced's doc comment — a
	// known-free model IS priced, at $0).
	Priced bool
	// CacheReadUnpriced is true when a TABLE-priced row carried cached
	// tokens and its model's cache-read rate was never quoted
	// ([Engine.CacheReadUnpricedAt]): those tokens billed an intentional
	// unpriced $0, so the row is only partially priced. Never set for a
	// recorded-cost row (the table was not consulted) or a whole-row miss.
	CacheReadUnpriced bool
}

// priceRow resolves one rawRow's dollar cost: the recorded value when
// the capture path stamped one (non-zero), else the pricing table's
// rate for the row's model at rowAt, applied over the row's full token
// bundle. rowAt is the zero time.Time when the caller doesn't need
// date-effective pricing (LookupWithSourceAt's zero-time contract falls
// back to current rates).
func (e *Engine) priceRow(r rawRow, rowAt time.Time) pricedRow {
	// 2026-09-22 rework finding #14: recorded cost wins only when it is
	// POSITIVE. A malformed/negative estimated_cost_usd (a client-side
	// computation bug, or a corrupted row) must never be treated as an
	// authoritative "this turn cost -$4" — that silently REDUCES the
	// project/bucket total below what the token bundle alone would
	// price. r.recordedUSD == 0 already falls through to the pricing
	// table; a negative value now falls through too instead of being
	// trusted at face value (docs/projects-page.md's "recorded cost
	// wins" rule always assumed a real, non-negative client figure).
	if r.recordedUSD > 0 {
		// Recorded cost — pricing table wasn't consulted, but the row
		// still came with a known model. Mark the pricing path as
		// "exact" since the upstream client (which had to know the
		// model's rates to compute it) effectively certified the rate.
		return pricedRow{CostUSD: r.recordedUSD, AICostUSD: r.recordedUSD, PricingSource: PricingSourceExact, Priced: true}
	}
	pricing, src, ok := e.LookupWithSourceAt(r.model, rowAt)
	if !ok {
		return pricedRow{PricingSource: PricingSourceMiss, Priced: false}
	}
	cb := ComputeBreakdown(pricing, r.tokens)
	return pricedRow{
		CostUSD: cb.Total, AICostUSD: cb.AICost, ToolCostUSD: cb.ToolCost, PricingSource: src, Priced: true,
		CacheReadUnpriced: r.tokens.CacheRead > 0 && e.CacheReadUnpricedAt(r.model, rowAt),
	}
}

// loadRows reads the window's spend rows: api_turns (proxy), summary_calls
// and token_usage (transcript), per opts.Source.
//
// Under SourceAuto the two capture paths overlap - a proxied turn is also in
// its transcript - and the rows are deduplicated by the ONE session rule,
// internal/sessionmsg.Derive, whose per-row decisions are STORED
// (internal/spendverdict, agent migration 143) and applied in each loader's
// SQL: a transcript row Derive does not count is not read, a proxy row reads
// its verdict's output / reasoning / fast tier, and a proxy row the
// session-cumulative reconciliation dropped is not read. Because the
// verdicts were derived over each session's WHOLE row set, a session cut by
// the window's edge is judged exactly as its header judges it, and a
// session's rows here sum to its detail header.
//
// This replaced a per-window Go pass (applySessionDedup +
// reconcileSessionAggregates) that re-ran Derive over only the window's rows
// and needed every column Derive reads in the load - ~1.8x slower per
// Analysis panel (lane R2-ONERULE). A single-source read reports that capture
// path as stored, except that a transcript-only read (SourceJSONL) still
// drops a paired output-only shadow row - a duplicate the transcript made of
// itself, not a proxy overlap.
func (e *Engine) loadRows(ctx context.Context, db *sql.DB, opts Options, since time.Time) ([]rawRow, error) {
	var out []rawRow
	applyVerdicts := opts.Source == SourceAuto
	if (applyVerdicts || opts.Source == SourceJSONL) && db != nil {
		// Bring every changed session's verdicts up to date first. A failed
		// refresh (a write lock held past busy_timeout, a cancelled request)
		// leaves the previous verdicts in place and the read proceeds: only
		// a session changed since its last derivation can be off, and the
		// next read retries.
		_, _ = spendverdict.Refresh(ctx, db, spendverdict.Options{})
	}

	// Opt-in raw-row cache (rowcache.go): the two big per-window reads —
	// api_turns and token_usage — may be served from a fresh cached read of
	// the same query shape. The fingerprint is probed once per call; any
	// failure simply reads uncached.
	var fp rowFingerprint
	useCache := db != nil && rowCacheAllowed(ctx)
	if useCache {
		fp, useCache = loadRowFingerprint(ctx, db)
	}
	cachedLoad := func(kind string, load func() ([]rawRow, error)) ([]rawRow, error) {
		if applyVerdicts {
			kind += ":auto" // verdict-applied rows differ from single-source ones
		}
		if useCache {
			if k, ok := rowCacheKeyFor(db, kind, opts, since); ok {
				return e.rows.load(k, since, fp, load)
			}
		}
		return load()
	}

	if opts.Source == SourceProxy || opts.Source == SourceAuto {
		proxy, err := cachedLoad("proxy", func() ([]rawRow, error) { return e.loadProxyRows(ctx, db, opts, since, applyVerdicts) })
		if err != nil {
			return nil, err
		}
		out = append(out, proxy...)
	}

	if opts.Source == SourceSummaryCalls || opts.Source == SourceAuto {
		summaryRows, err := e.loadSummaryCallRows(ctx, db, opts, since)
		if err != nil {
			return nil, err
		}
		out = append(out, summaryRows...)
	}

	if opts.Source == SourceJSONL || opts.Source == SourceAuto {
		jsonl, err := cachedLoad("jsonl", func() ([]rawRow, error) { return e.loadJSONLRows(ctx, db, opts, since, applyVerdicts) })
		// (A transcript-only read still drops paired output-only shadow
		// rows - loadJSONLRows applies that one verdict either way.)
		if err != nil {
			return nil, err
		}
		// One exact-size allocation: appending ~170k rawRows (~330 B each)
		// one by one regrew and recopied the slice many times over.
		res := make([]rawRow, len(out), len(out)+len(jsonl))
		copy(res, out)
		res = append(res, jsonl...)
		out = res
	}
	return out, nil
}

// loadProxyRows reads the window's api_turns rows. With applyVerdicts (the
// SourceAuto read) each row reads its stored dedup verdict: a row the
// session-cumulative reconciliation dropped is not read, a twinned row
// carries its transcript twin's visible output + reasoning (billed at the
// same rate, so the sum prices identically) and, when that twin was fast,
// the fast tier - its recorded cost was priced at the standard wire tier, so
// it is cleared and the row re-priced from the table (the session detail's
// proxyAwareCost applies the same rule).
func (e *Engine) loadProxyRows(ctx context.Context, db *sql.DB, opts Options, since time.Time, applyVerdicts bool) ([]rawRow, error) {
	outputExpr, reasoningExpr, liftExpr, verdictJoin := `COALESCE(at.output_tokens, 0)`, `0`, `0`, ``
	if applyVerdicts {
		outputExpr, reasoningExpr, liftExpr, verdictJoin = spendverdict.ProxyOutput("at"), spendverdict.ProxyReasoning(), spendverdict.ProxyInheritedFast(), spendverdict.ProxyVerdictJoin("at")
	}
	//nolint:gosec // G202: the verdict fragments are compile-time constant SQL; values bind via args.
	q := `SELECT COALESCE(at.model, ''), COALESCE(at.input_tokens, 0),
	             ` + outputExpr + `, COALESCE(at.cache_read_tokens, 0),
	             COALESCE(at.cache_creation_tokens, 0),
	             COALESCE(at.cache_creation_1h_tokens, 0),
	             COALESCE(at.web_search_requests, 0),
	             COALESCE(at.cost_usd, 0),
	             at.timestamp, COALESCE(at.session_id, ''),
	             COALESCE(p.root_path, ''),
	             COALESCE(s.tool, ''),
	             COALESCE(at.compression_original_bytes, 0),
	             COALESCE(at.compression_compressed_bytes, 0),
	             COALESCE(at.compression_count, 0),
	             COALESCE(at.compression_dropped_count, 0),
	             COALESCE(at.compression_marker_count, 0),
	             COALESCE(at.request_id, ''),
	             COALESCE(at.total_response_ms, 0),
	             COALESCE(at.fast, 0),
	             ` + reasoningExpr + `,
	             ` + liftExpr + `
	      FROM api_turns at` + verdictJoin + `
	      LEFT JOIN sessions s ON s.id = at.session_id
	      LEFT JOIN projects p ON p.id = COALESCE(at.project_id, s.project_id)`
	var where []string
	var args []any
	if applyVerdicts {
		where = append(where, spendverdict.CountedProxyRow())
	}
	if !since.IsZero() {
		where = append(where, "at.timestamp >= ?")
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if !opts.Until.IsZero() {
		where = append(where, "at.timestamp < ?")
		args = append(args, opts.Until.UTC().Format(time.RFC3339Nano))
	}
	// COALESCE(at.project_id, s.project_id): api_turns.project_id is NULL
	// on every row of every grounded install (the proxy learns the
	// session id, not the cwd) — matching p.id = at.project_id alone
	// (pre-2026-09-22 arc review F6/F9) silently dropped every proxy
	// turn from a project-scoped query, landing all proxy spend under
	// "<no-project>" on the Cost page. ProjectID (an id the caller
	// already resolved) takes precedence over ProjectRoot so a
	// project-scoped caller (the Projects page) doesn't pay an extra
	// projects-table round trip.
	if opts.ProjectID != 0 {
		where = append(where, "COALESCE(at.project_id, s.project_id) = ?")
		args = append(args, opts.ProjectID)
	} else if opts.ProjectRoot != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, opts.ProjectRoot)
	}
	if opts.Tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, opts.Tool)
	}
	if len(opts.SessionIDs) > 0 {
		ph := strings.TrimRight(strings.Repeat("?,", len(opts.SessionIDs)), ",")
		where = append(where, "at.session_id IN ("+ph+")")
		for _, id := range opts.SessionIDs {
			args = append(args, id)
		}
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cost.Summary: proxy query: %w", err)
	}
	defer rows.Close()
	var out rawRowBlocks
	for rows.Next() {
		var r rawRow
		var fastInt, liftInt int
		if err := rows.Scan(
			&r.model,
			&r.tokens.Input, &r.tokens.Output,
			&r.tokens.CacheRead, &r.tokens.CacheCreation,
			&r.tokens.CacheCreation1h,
			&r.tokens.WebSearchRequests,
			&r.recordedUSD, &r.ts, &r.sessionID, &r.projectPath, &r.tool,
			&r.compression.OriginalBytes, &r.compression.CompressedBytes,
			&r.compression.CompressedCount, &r.compression.DroppedCount,
			&r.compression.MarkerCount,
			&r.turnID,
			&r.latencyMS,
			&fastInt,
			&r.tokens.Reasoning,
			&liftInt,
		); err != nil {
			return nil, fmt.Errorf("cost.Summary: proxy scan: %w", err)
		}
		r.tokens.Fast = fastInt != 0
		if liftInt != 0 && !r.tokens.Fast {
			r.tokens.Fast = true
			r.recordedUSD = 0
		}
		r.source = "proxy"
		r.reliability = "accurate"
		if r.compression.OriginalBytes > 0 || r.compression.CompressedBytes > 0 {
			r.compression.Turns = 1
		}
		if isNoiseRow(r) {
			continue
		}
		out.add(r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cost.Summary: proxy rows: %w", err)
	}
	return out.rows(), nil
}

// loadJSONLRows reads the window's token_usage rows. With applyVerdicts (the
// SourceAuto read) a row Derive does not count - a proxy row's twin, a
// request-id duplicate, a paired output-only shadow row, a row the
// session-cumulative reconciliation dropped - is not read; without it (a
// transcript-only read) only the paired output-only shadow rows are dropped.
func (e *Engine) loadJSONLRows(ctx context.Context, db *sql.DB, opts Options, since time.Time, applyVerdicts bool) ([]rawRow, error) {
	q := `SELECT COALESCE(tu.model, ''), COALESCE(tu.input_tokens, 0),
	             COALESCE(tu.output_tokens, 0), COALESCE(tu.cache_read_tokens, 0),
	             COALESCE(tu.cache_creation_tokens, 0),
	             COALESCE(tu.cache_creation_1h_tokens, 0),
	             COALESCE(tu.reasoning_tokens, 0),
	             COALESCE(tu.web_search_requests, 0),
	             COALESCE(tu.estimated_cost_usd, 0),
	             tu.timestamp, tu.session_id,
	             COALESCE(p.root_path, ''), tu.tool,
	             COALESCE(tu.reliability, 'unknown'),
	             COALESCE(tu.source_event_id, ''),
	             COALESCE(tu.fast, 0)
	      FROM token_usage tu
	      LEFT JOIN sessions s ON s.id = tu.session_id
	      LEFT JOIN projects p ON p.id = s.project_id`
	var where []string
	var args []any
	if applyVerdicts {
		where = append(where, spendverdict.CountedTokenRow("tu"))
	} else {
		where = append(where, spendverdict.UnpairedShadowRow("tu"))
	}
	if !since.IsZero() {
		where = append(where, "tu.timestamp >= ?")
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if !opts.Until.IsZero() {
		where = append(where, "tu.timestamp < ?")
		args = append(args, opts.Until.UTC().Format(time.RFC3339Nano))
	}
	if opts.ProjectID != 0 {
		where = append(where, "s.project_id = ?")
		args = append(args, opts.ProjectID)
	} else if opts.ProjectRoot != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, opts.ProjectRoot)
	}
	if opts.Tool != "" {
		where = append(where, "s.tool = ?")
		args = append(args, opts.Tool)
	}
	if len(opts.SessionIDs) > 0 {
		ph := strings.TrimRight(strings.Repeat("?,", len(opts.SessionIDs)), ",")
		where = append(where, "tu.session_id IN ("+ph+")")
		for _, id := range opts.SessionIDs {
			args = append(args, id)
		}
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cost.Summary: jsonl query: %w", err)
	}
	defer rows.Close()
	var out rawRowBlocks
	for rows.Next() {
		var r rawRow
		var fastInt int
		if err := rows.Scan(
			&r.model,
			&r.tokens.Input, &r.tokens.Output,
			&r.tokens.CacheRead, &r.tokens.CacheCreation,
			&r.tokens.CacheCreation1h,
			&r.tokens.Reasoning,
			&r.tokens.WebSearchRequests,
			&r.recordedUSD, &r.ts, &r.sessionID, &r.projectPath, &r.tool,
			&r.reliability,
			&r.turnID,
			&fastInt,
		); err != nil {
			return nil, fmt.Errorf("cost.Summary: jsonl scan: %w", err)
		}
		r.tokens.Fast = fastInt != 0
		r.source = "jsonl"
		if isNoiseRow(r) {
			continue
		}
		out.add(r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cost.Summary: jsonl rows: %w", err)
	}
	return out.rows(), nil
}

// loadSummaryCallRows reads the D20 summary_calls ledger — Anthropic
// Haiku calls that the rolling-summarisation summariser fires direct
// to api.anthropic.com (not through the proxy). Each row produces one
// rawRow with source = "summary_calls" and tool = "rolling_summary"
// so per-tool aggregations naturally surface this internal spend as a
// separate line. recordedUSD is taken verbatim from the ledger's
// pre-priced cost_usd column.
//
// Skipped silently when summary_calls doesn't exist (legacy DB, before
// migration 016). Other failures still surface so genuine bugs aren't
// hidden.
func (e *Engine) loadSummaryCallRows(ctx context.Context, db *sql.DB, opts Options, since time.Time) ([]rawRow, error) {
	// The project scope (added 2026-09-22, F1/F6/F9 arc review) needs a
	// join to sessions — summary_calls carries no project column of its
	// own. Only join when a project scope was actually requested, OR
	// (2026-09-22 rework finding #3) when the caller GROUPS by project —
	// an unscoped GroupByProject/GroupByDayProject caller (the Projects
	// list, `/api/cost?group_by=project`) still needs each row's project
	// path resolved and SELECTed, or every summary_calls row lands under
	// "<no-project>" instead of its real project, disagreeing with the
	// project-scoped detail panel that already includes it. The common
	// unscoped, non-project-grouped call (observer cost, MCP
	// get_cost_summary) keeps its original plan unchanged.
	needsProjectPath := opts.GroupBy == GroupByProject || opts.GroupBy == GroupByDayProject
	from := "FROM summary_calls"
	selectProject := "''"
	var where []string
	var args []any
	switch {
	case opts.ProjectID != 0:
		from = "FROM summary_calls LEFT JOIN sessions s ON s.id = summary_calls.session_id"
		where = append(where, "s.project_id = ?")
		args = append(args, opts.ProjectID)
		if needsProjectPath {
			from += " LEFT JOIN projects p ON p.id = s.project_id"
			selectProject = "COALESCE(p.root_path, '')"
		}
	case opts.ProjectRoot != "":
		from = "FROM summary_calls LEFT JOIN sessions s ON s.id = summary_calls.session_id LEFT JOIN projects p ON p.id = s.project_id"
		where = append(where, "p.root_path = ?")
		args = append(args, opts.ProjectRoot)
		selectProject = "COALESCE(p.root_path, '')"
	case needsProjectPath:
		from = "FROM summary_calls LEFT JOIN sessions s ON s.id = summary_calls.session_id LEFT JOIN projects p ON p.id = s.project_id"
		selectProject = "COALESCE(p.root_path, '')"
	}
	//nolint:gosec // G202: selectProject/from are compile-time constant SQL fragments chosen by capability; values bind via args.
	q := `SELECT COALESCE(summary_calls.model, ''),
	             COALESCE(summary_calls.input_tokens, 0),
	             COALESCE(summary_calls.output_tokens, 0),
	             COALESCE(summary_calls.cache_read_tokens, 0),
	             COALESCE(summary_calls.cache_creation_tokens, 0),
	             COALESCE(summary_calls.cost_usd, 0),
	             summary_calls.timestamp,
	             COALESCE(summary_calls.session_id, ''),
	             ` + selectProject + `
	      ` + from
	if !since.IsZero() {
		where = append(where, "summary_calls.timestamp >= ?")
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if !opts.Until.IsZero() {
		where = append(where, "summary_calls.timestamp < ?")
		args = append(args, opts.Until.UTC().Format(time.RFC3339Nano))
	}
	if len(opts.SessionIDs) > 0 {
		ph := strings.TrimRight(strings.Repeat("?,", len(opts.SessionIDs)), ",")
		where = append(where, "summary_calls.session_id IN ("+ph+")")
		for _, id := range opts.SessionIDs {
			args = append(args, id)
		}
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		// Fresh installs without migration 016 (or schemas where the
		// table was never created) shouldn't fail the whole cost
		// summary — degrade gracefully and return no rows.
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, fmt.Errorf("cost.Summary: summary_calls query: %w", err)
	}
	defer rows.Close()
	var out []rawRow
	for rows.Next() {
		var r rawRow
		if err := rows.Scan(
			&r.model,
			&r.tokens.Input, &r.tokens.Output,
			&r.tokens.CacheRead, &r.tokens.CacheCreation,
			&r.recordedUSD, &r.ts, &r.sessionID, &r.projectPath,
		); err != nil {
			return nil, fmt.Errorf("cost.Summary: summary_calls scan: %w", err)
		}
		r.source = "summary_calls"
		r.reliability = "accurate"
		// Surface as its own tool so per-tool grouping makes the
		// observer-initiated spend visible without confusing it with
		// real user turns.
		r.tool = "observer-rolling-summary"
		if isNoiseRow(r) {
			continue
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cost.Summary: summary_calls rows: %w", err)
	}
	return out, nil
}

// bucket holds the in-progress aggregation for one group key.
type bucket struct {
	tokens    TokenBundle
	cost      float64
	aiCost    float64
	toolCost  float64
	turnCount int
	// V3-5: cumulative proxy-observed latency. latencyMS sums the
	// non-zero per-turn values; latencyTurnCount counts contributors
	// (proxy rows only — JSONL rows carry 0 and are excluded). Row
	// emits the average as AvgLatencyMS.
	latencyMSSum     int64
	latencyTurnCount int
	sources          map[string]bool
	reliabilities    map[string]bool
	unknownModels    map[string]bool
	// pricingSources tracks which match path the pricing table took
	// for each row contributing to this bucket: PricingSourceExact /
	// DateStripped / Family / Miss. The dashboard surfaces a "~"
	// indicator on the Reliability column when at least one row in
	// the bucket priced via Family or Miss — see audit Phase C.
	pricingSources map[PricingSource]bool
	compression    CompressionStats
	// fastTurnCount / fastCost accumulate the subset of this bucket's
	// turns served in the provider's low-latency "fast" tier (Anthropic
	// Opus 4.8 speed:"fast"). fastCost uses the same per-row cost the
	// bucket total used, so it already reflects the FastMultiplier
	// premium. Surfaced on Row so the dashboard can badge fast-tier spend.
	fastTurnCount int
	fastCost      float64
	// unpricedTurnCount counts this bucket's rows that hit a pricing
	// MISS. Surfaced on Row.UnpricedTurnCount.
	unpricedTurnCount int
}

func (e *Engine) rollup(raws []rawRow, opts Options) Summary {
	buckets := map[string]*bucket{}
	order := []string{}

	totalTokens := TokenBundle{}
	totalCost := 0.0
	totalTurns := 0
	totalFastTurns := 0
	totalFastCost := 0.0
	totalReliability := map[string]bool{}
	totalUnknowns := map[string]bool{}
	var unpricedTokens int64
	var unpricedTurnCount int
	totalCompression := CompressionStats{}

	// DATE-EFFECTIVE PRICING. This rollup is the canonical historical
	// cost surface (`observer cost`, MCP get_cost_summary, the dashboard
	// Cost tab, the tag rollups via SessionRowsByID) and it is already
	// PER-ROW — the long-context dispatch has always forbidden pricing
	// aggregated token sums. So a rate boundary inside the queried window
	// splits itself: each row is priced at the rate in force at its own
	// timestamp, and the buckets sum priced dollars, never tokens-then-
	// price. No SQL-side bucketing is needed or wanted.
	//
	// PERF: gated on the table actually carrying a dated timeline. With
	// zero dated entries (the default install) `dateAware` is false, no
	// row pays a time.Parse, and every Lookup runs the pre-dated path.
	dateAware := e.HasDatedPricing()

	for _, r := range raws {
		key := groupKey(r, opts.GroupBy, opts.BucketKey)
		// Zero when !dateAware or when the row's stamp is unparseable —
		// both fall back to current rates (LookupAt's zero-time contract).
		var rowAt time.Time
		if dateAware {
			rowAt, _ = time.Parse(time.RFC3339Nano, r.ts)
		}
		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				sources:        map[string]bool{},
				reliabilities:  map[string]bool{},
				unknownModels:  map[string]bool{},
				pricingSources: map[PricingSource]bool{},
			}
			buckets[key] = b
			order = append(order, key)
		}
		b.tokens.Add(r.tokens)
		b.turnCount++
		// V3-5: only proxy rows carry observed latency (JSONL adapter
		// path doesn't see request → response wall time). latencyMS == 0
		// is skipped — both 'JSONL row' AND 'proxy row with no
		// recorded latency' produce zero, which would skew the average
		// downward.
		if r.latencyMS > 0 {
			b.latencyMSSum += r.latencyMS
			b.latencyTurnCount++
		}
		b.sources[r.source] = true
		b.reliabilities[r.reliability] = true
		totalReliability[r.reliability] = true

		// Cost: when the row has a recorded estimated_cost_usd (only
		// OpenCode + Pi adapters set this today — they compute cost
		// client-side), use it as-is. Otherwise compute from pricing
		// and track which pricing-table match path was hit. priceRow is
		// the ONE pricing rule — shared with TurnRows (the Projects-page
		// per-turn export) so a turn's dollar figure can never disagree
		// between the two surfaces (2026-09-22 arc review F6).
		pr := e.priceRow(r, rowAt)
		if !pr.Priced {
			b.unknownModels[r.model] = true
			totalUnknowns[r.model] = true
			b.pricingSources[PricingSourceMiss] = true
			unpricedTokens += r.tokens.Input + r.tokens.Output
			unpricedTurnCount++
			b.unpricedTurnCount++
		} else {
			b.pricingSources[pr.PricingSource] = true
			// A table-priced model whose CACHE-READ rate the vendor never
			// quoted: the cached tokens billed $0 as an UNPRICED
			// dimension, not a known-free one. Record it as a miss
			// signal (bucket source no longer "exact", unpriced volume
			// and turn counted) rather than a silent exact $0. priceRow
			// owns the signal (TurnRows carries the same field), and a
			// recorded-cost row never consulted the table, so it never
			// sets it.
			if pr.CacheReadUnpriced {
				b.pricingSources[PricingSourceMiss] = true
				unpricedTokens += r.tokens.CacheRead
				unpricedTurnCount++
				// The BUCKET counts it too, so a grouped row (the /api/projects
				// list's per-project coverage) agrees with the Projects detail
				// path, which counts the same turn through
				// TurnRow.FullyPriced (review round 2, finding 2).
				b.unpricedTurnCount++
			}
		}
		cost := pr.CostUSD
		aiCost, toolCost := pr.AICostUSD, pr.ToolCostUSD
		b.cost += cost
		b.aiCost += aiCost
		b.toolCost += toolCost
		// Fast-tier subtotal: same per-row cost the bucket total used, so it
		// already carries the FastMultiplier premium. Gated on the model
		// actually having a fast-mode premium (FastMultiplier > 0): Codex
		// sends service_tier:"priority" globally so every codex row carries
		// fast=1, but only gpt-5.5 / gpt-5.4 (and Opus 4.8) bill a premium.
		// Counting mini/codex priority turns here would inflate the
		// fast-tier turn count + spend with turns that cost the standard
		// rate. The pill (service_tier on the action row) still surfaces the
		// requested tier for those models.
		if r.tokens.Fast {
			if p, ok := e.LookupAt(r.model, rowAt); ok && p.FastMultiplier > 0 {
				b.fastTurnCount++
				b.fastCost += cost
				totalFastTurns++
				totalFastCost += cost
			}
		}
		// Derive per-row token & $ savings before aggregating. Skip when
		// no compression data was recorded on the row.
		if r.compression.OriginalBytes != 0 || r.compression.CompressedBytes != 0 || r.compression.Turns != 0 {
			savedBytes := r.compression.OriginalBytes - r.compression.CompressedBytes
			// V7-18 clip: when the conversation pipeline runs in pass-
			// through mode (codex-variant recipe with compress_types=[]),
			// per-turn JSON re-marshaling + cache_control envelope
			// overhead can make CompressedBytes > OriginalBytes. The raw
			// bytes are preserved on the row so operators can see the
			// wire inflation, but derived savings clip to zero — a
			// negative "tokens saved" estimate has no operational
			// meaning and misleads operators reading observer cost.
			if savedBytes < 0 {
				savedBytes = 0
			}
			r.compression.TokensSavedEst = savedBytes / 4 // ~4 chars/token
			if pricing, ok := e.LookupAt(r.model, rowAt); ok && pricing.Input > 0 {
				// V7-6 weighted blend: pre-v1.7.6 cost_saved_usd_est
				// used pricing.Input flat, which overstated codex
				// savings ~10× because codex sessions are cache_read-
				// dominant. The main column now reflects the row's
				// realized input-side mix; the two tier columns
				// expose the upper bound (input tier, the prior
				// behavior) and lower bound (cache_read tier) for
				// operators who want the explicit bounds. See
				// docs/v4-codex-compression-recipe-and-issues.md V7-6.
				tokens := float64(r.compression.TokensSavedEst)
				r.compression.CostSavedUSDEstInputTier = tokens * pricing.Input / 1_000_000
				cacheReadRate := pricing.CacheRead
				// An explicitly UNQUOTED cache-read rate stays 0: the 10%
				// fallback below would reinvent the very rate the table
				// declined to fabricate.
				if cacheReadRate == 0 && !e.CacheReadUnpricedAt(r.model, rowAt) {
					// Pricing tables without an explicit cache_read
					// rate fall back to Pricing.normalize's 10%-of-
					// input default (pricing.go:187). If even that
					// didn't fire (e.g. zero pricing.Input slipped
					// past), use pricing.Input so the lower-bound
					// column never exceeds the upper bound.
					cacheReadRate = pricing.Input * 0.10
				}
				r.compression.CostSavedUSDEstCacheReadTier = tokens * cacheReadRate / 1_000_000
				inputSlot := r.tokens.Input + r.tokens.CacheRead + r.tokens.CacheCreation
				if inputSlot > 0 {
					inputShare := float64(r.tokens.Input+r.tokens.CacheCreation) / float64(inputSlot)
					cacheShare := float64(r.tokens.CacheRead) / float64(inputSlot)
					weighted := inputShare*pricing.Input + cacheShare*cacheReadRate
					r.compression.CostSavedUSDEst = tokens * weighted / 1_000_000
				} else {
					// No input-side tokens to weight against — fall
					// back to the upper-bound (input-tier) value so
					// the column stays consistent with pre-v1.7.6
					// behavior for tokenless rows.
					r.compression.CostSavedUSDEst = r.compression.CostSavedUSDEstInputTier
				}
			}
		}
		b.compression.Add(r.compression)

		totalTokens.Add(r.tokens)
		totalCost += cost
		totalTurns++
		totalCompression.Add(r.compression)
	}

	rowsOut := make([]Row, 0, len(order))
	for _, key := range order {
		b := buckets[key]
		var avgLatency int64
		if b.latencyTurnCount > 0 {
			avgLatency = b.latencyMSSum / int64(b.latencyTurnCount)
		}
		rowsOut = append(rowsOut, Row{
			Key:               key,
			Tokens:            b.tokens,
			CostUSD:           b.cost,
			AICostUSD:         b.aiCost,
			ToolCostUSD:       b.toolCost,
			TurnCount:         b.turnCount,
			AvgLatencyMS:      avgLatency,
			Source:            collapseSources(b.sources),
			Reliability:       weakestReliability(b.reliabilities),
			UnknownModels:     sortedKeys(b.unknownModels),
			PricingSource:     collapsePricingSources(b.pricingSources),
			Compression:       b.compression,
			FastTurnCount:     b.fastTurnCount,
			FastCostUSD:       b.fastCost,
			UnpricedTurnCount: b.unpricedTurnCount,
			PricedTurnCount:   b.turnCount - b.unpricedTurnCount,
		})
	}
	sort.SliceStable(rowsOut, func(i, j int) bool {
		if rowsOut[i].CostUSD != rowsOut[j].CostUSD {
			return rowsOut[i].CostUSD > rowsOut[j].CostUSD
		}
		return rowsOut[i].Tokens.Input+rowsOut[i].Tokens.Output >
			rowsOut[j].Tokens.Input+rowsOut[j].Tokens.Output
	})
	if len(rowsOut) > opts.Limit {
		rowsOut = rowsOut[:opts.Limit]
	}

	return Summary{
		GroupBy:           opts.GroupBy,
		Source:            opts.Source,
		Rows:              rowsOut,
		TotalTokens:       totalTokens,
		TotalCost:         totalCost,
		TurnCount:         totalTurns,
		FastTurnCount:     totalFastTurns,
		TotalFastCostUSD:  totalFastCost,
		Reliability:       weakestReliability(totalReliability),
		UnknownModelCount: len(totalUnknowns),
		UnpricedTokens:    unpricedTokens,
		UnpricedTurnCount: unpricedTurnCount,
		TotalCompression:  totalCompression,
	}
}

func groupKey(r rawRow, g GroupBy, bucketKey func(string) string) string {
	day := func() string {
		if bucketKey != nil {
			return bucketKey(r.ts)
		}
		if len(r.ts) >= 10 {
			return r.ts[:10]
		}
		return r.ts
	}
	switch g {
	case GroupBySession:
		if r.sessionID == "" {
			return "<unattributed>"
		}
		return r.sessionID
	case GroupByDay:
		return day()
	case GroupByDayModel:
		model := r.model
		if model == "" {
			model = "<unknown>"
		}
		return day() + dayModelKeySep + model
	case GroupByDayProject:
		proj := r.projectPath
		if proj == "" {
			proj = "<no-project>"
		}
		return day() + dayModelKeySep + proj
	case GroupByDayTool:
		tool := r.tool
		if tool == "" {
			tool = "<no-tool>"
		}
		return day() + dayModelKeySep + tool
	case GroupByProject:
		if r.projectPath == "" {
			return "<no-project>"
		}
		return r.projectPath
	case GroupByTool:
		if r.tool == "" {
			return "<no-tool>"
		}
		return r.tool
	case GroupByModelTool:
		model := r.model
		if model == "" {
			model = "<unknown>"
		}
		tool := r.tool
		if tool == "" {
			tool = "<no-tool>"
		}
		return model + dayModelKeySep + tool
	case GroupByNone:
		return "all"
	default: // GroupByModel
		if r.model == "" {
			return "<unknown>"
		}
		return r.model
	}
}

func collapseSources(set map[string]bool) string {
	if len(set) == 1 {
		for k := range set {
			return k
		}
	}
	return "mixed"
}

// collapsePricingSources reduces a bucket's PricingSource set to a single
// label for the dashboard. Empty set → "" (no rows priced, e.g. all
// recorded). Single tag → that tag. Mixed → "mixed". The dashboard
// renders a "~" indicator unless the result is "exact" or "" (since
// the table-recorded path is also exact-equivalent).
func collapsePricingSources(set map[PricingSource]bool) string {
	if len(set) == 0 {
		return ""
	}
	if len(set) == 1 {
		for k := range set {
			return string(k)
		}
	}
	return "mixed"
}

// weakestReliability picks the weakest tag present — the number should be
// trusted only as much as the least-trustworthy input allows.
func weakestReliability(set map[string]bool) string {
	order := []string{"unknown", "unreliable", "approximate", "accurate"}
	for _, tag := range order {
		if set[tag] {
			return tag
		}
	}
	return "unknown"
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
