# Cache Tracking

Anthropic prompt-cache observation, attribution, and forecasting.
Local, passive, network-free — observes the cache the provider already
keeps, attributes hits and rewrites by cause, and surfaces the
mispredict rate operators care about. Default-on per spec §11.

The three cache tables (`cache_segments`, `cache_entries`,
`cache_events`) are NODE-LOCAL: their names may never appear in
`internal/store/orgpush.go`, pinned by
`tests/invariant/privacy_test.go::TestSelectUnpushedSinceExcludesCacheTables`.
That is a module-boundary rule, not a data embargo - under the
enterprise posture the per-event log DOES reach the org, composed
through the seam file `internal/store/cacheeventorgrows.go` and gated on
the node's own `shipsRawContent()` (`full_content` / `admin_managed`),
landing in server table `session_cache_events` (migration 142). The
engine's `detail` diagnostic JSON is excluded at every posture. The
teams-tier `cache_detail` flag remains orthogonal: it gates only the
content-free fleet day aggregate.

For the full design, see
[`docs/plans/cache-tracking-implementation-spec-2026-06-08.md`](plans/cache-tracking-implementation-spec-2026-06-08.md).

## What it does

The proxy observes every Anthropic Messages API request. Per turn,
the cachetrack engine:

1. **Enumerates blocks** — tools, system, messages in chain order
   (`internal/cachetrack/breakpoints.go::EnumerateAnthropicBlocks`).
2. **Canonicalizes** each block deep — sorts nested map keys at every
   depth, strips `cache_control` recursively, preserves numeric form
   via `json.UseNumber`. Output is byte-identical for logically-equal
   inputs regardless of nested key order or whitespace.
3. **Skips provider-excluded telemetry** — Claude Code 2.1.169+
   prepends a per-request `x-anthropic-billing-header: ... cch=<NONCE>;`
   system block whose nonce changes every request. Anthropic excludes
   it from cache identity; we exclude it from the chain too. Without
   this filter, the cumulative system-level hash drifts every turn and
   §7 row 5 fires a spurious `system_changed → invalidation_rewrite`
   on every healthy warm turn.
4. **Hashes a rolling chain** — each block contributes
   `(level, kind, canonical_bytes)` to a SHA-256 chain. The cumulative
   hash at each block position is the prefix identity.
5. **Attributes the outcome** — walks a 13-row decision table
   (`internal/cachetrack/attribute.go::attributionRules`) to assign one
   of 9 kinds (`hit`, `write`, `expiry_rewrite`,
   `invalidation_rewrite`, `model_switch_rewrite`, `compaction_reset`,
   `reanchor`, `mispredict`, `below_min`) and 15 causes (per
   `internal/cachetrack/attribute.go`'s `Cause` constants). The
   `handoff_rehydration` cause is a `reanchor`-kind variant fired on the
   first turn of a session-handoff TARGET (the handover doc arrives as a
   large cold write BY DESIGN); it carries the same `reanchor` kind (so
   every kind-based denominator/exclusion is unaffected) but a distinct
   cause so the advisor + cache-health treat it as a baseline, not waste
   — see the "Session-handoff accounting" note below.
6. **Reconciles** the engine's prediction against the observed usage
   envelope (`internal/cachetrack/reconcile.go`). Per-session EMA
   tracks the byte-per-token scale factor (R6 calibration).

Output lands in three SQLite tables (migration `036_cache_tracking.sql`
+ `037_cache_events_message_id.sql`):

- `cache_segments` — points of interest on the per-turn prefix chain
  (breakpoints + level boundaries).
- `cache_entries` — modelled live provider cache, keyed by
  `UNIQUE(model, cache_scope, prefix_hash)`.
- `cache_events` — per-turn verdict (kind + cause + diverged_seq +
  predicted_kind + tokens_read/written + message_id).

### Minimum cacheable prefix (Anthropic) — per model, NOT a flat floor

A prefix shorter than the model's minimum never caches upstream, and the
engine labels that turn `kind='below_min'` /
`cause='below_min_cacheable'` (§7 row 10). The threshold is **per model
family**, and the families do not agree — there is no single Anthropic
floor:

| Model family | Min cacheable prefix |
|---|---|
| Claude Opus 5, Claude Fable 5 / 5.1, Claude Mythos 5 / 5.1 | **512** |
| Claude Opus 4.8, Sonnet 5, Sonnet 4.6, Sonnet 4.5, Sonnet 4, Opus 4.1, Opus 4 | 1,024 (the fall-through default) |
| Claude Mythos Preview, **Claude Opus 4.7** | 2,048 |
| Claude Haiku 3.5 | 2,048 |
| Claude Opus 4.6, Claude Opus 4.5 | 4,096 |
| Claude Haiku 4.5 | 4,096 |

Verified 2026-07-25 (Fable 5.1 / Mythos 5.1 rows re-verified 2026-09-02;
they resolve through the same `fable-5` / `mythos-5` substring rows in
`minCacheableTable` — `"fable-5"` is a substring of `claude-fable-5-1` —
so no new table entry was needed) against the vendor page —
[Anthropic prompt caching → "Minimum cacheable prompt
length"](https://platform.claude.com/docs/en/build-with-claude/prompt-caching),
which states these minimums apply on every platform each model is
available on. A prompt shorter than its model's minimum simply does not
cache; the provider returns no error, which is why a wrong number here
is silent.

Two rows are worth calling out because both were wrong before this
revision, in opposite directions:

- **Opus 4.7 is 2,048, not 4,096.** The table previously carried 4,096
  on the strength of an internal research doc; the 2× overstatement made
  every 2,048–4,095-token Opus 4.7 prefix report `below_min` for a
  prefix the provider really did cache.
- **Mythos Preview is 2,048 and needs its own row.** `claude-mythos-5`
  (512) does not substring-match `claude-mythos-preview`, so without a
  row of its own the id fell through to the 1,024 default — the
  dangerous direction: the engine predicts a cache write on a
  1,024–2,047-token prefix that never caches, then grades itself a
  mispredict.

The 512 tier is likewise not a rounding of the old default: **Opus 5
halved the Opus 4.8 minimum from 1,024 to 512**, and Fable 5 + Mythos 5
ship at 512 too. Until those rows existed, 512–1,023-token prefixes on
those three models were classified `below_min` even though the provider
really did cache them — wrong attribution, and mispredict-grading
pollution on top of it.

Source of truth is the table-driven
`internal/cachetrack/tier.go::minCacheableTable`, walked top-down by
`MinCacheableTokens(model)` as a substring scan over the **lowercased**
model id (first match wins; no match → `defaultMinCacheable` = 1,024).
The lowercasing matches the pricing registry's family scan, so an
upper-case or vendor-decorated id (`US.ANTHROPIC.CLAUDE-OPUS-5-V1:0`)
resolves to the same family in both places. A future provider change is
one row plus one test row in `TestMinCacheableTokens` — never an
if/else ladder (§24.5).

Anthropic-only. The 1,024 figures quoted in the OpenAI/Codex and
GPT-5.6 sections below are OpenAI's own implicit-cache floor and are
unrelated to this table.

## Cache expiry — how a prompt cache stays warm (sliding-window TTL)

A provider prompt cache does **not** expire at a fixed time after it was
first written. The TTL is a **sliding window refreshed on every use**:
each cache *hit* (read) resets the clock at no extra cost. So a cache is
warm until **the most recent activity + TTL**, not creation + TTL — and a
session that keeps working keeps its cache warm indefinitely.

| Provider | Cache model | TTL | Refresh-on-use |
|---|---|---|---|
| **Anthropic** (claude-code, cline, cowork, openclaw, pi) | explicit `cache_control` breakpoints; content-addressed, no cache ID | 5 min default, 1 h tier (`cache_control.ttl:"1h"`, ~2× write cost) | **Yes.** Docs: *"The cache is refreshed for no additional cost each time the cached content is used"* — a block hit *"is also a cache refresh"*. |
| **OpenAI / Codex** | implicit/automatic, anonymous, content-addressed (prefixes ≥1024 tok) | evicted after **5–10 min of inactivity**, **max 1 h** in-memory; **extended retention up to 24 h** on gpt-5.5 / gpt-5 / gpt-4.1; no client TTL control | **Yes** — the same idea: as long as the prefix keeps getting hit it stays warm; it lapses only after an idle gap. |
| **Gemini** (gemini-cli) | implicit **and** explicit `CachedContent` (addressable ID) | explicit caches carry a patchable TTL | Explicit caches: TTL patch extends without resending content (niche). |

**Why every turn refreshes the whole chain.** Each request re-sends the
full conversation. The provider matches the **longest** previously-cached
prefix and reads it (a hit) — and that read refreshes the matched prefix,
which contains all the shorter nested prefixes. The initial prefix is part
of *every* request, so it is refreshed every turn and never ages out while
the session is active.

**Consequence for the modelled `cache_entries`.** The engine writes one
entry per turn's *new* prefix tip (`expires_at = write_time + TTL`) and
refreshes the immediately-prior tip on a hit; it does **not** push that
refresh back across every older nested entry. So the raw rows show
staggered `expires_at` values that look like each prefix dies on its own —
which is *not* how the provider behaves. The cache-expiry warning surface
therefore **collapses a session's chain to one logical warm cache** per
`(session, model, scope)`, with expiry taken from the **warm-longest**
entry (most-recent activity + TTL) and a cumulative token estimate of the
prefix at risk. See `internal/cachewarmsvc/svc.go::collapseChains` and the
cache-expiry warning system (`docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md`).
The exact prefix-at-risk size is the latest turn's `cache_read` tokens (a
documented refinement over the current cumulative-sum estimate).

**Implicit caches (OpenAI/Codex) have no `cache_entries` — windows are
ESTIMATED and GRADED.** Implicit caches are anonymous and report no TTL, so
they never land in `cache_entries`; the engine records only `cache_events`
(`implicit_hit`/`implicit_write`/`implicit_miss`). Critically, OpenAI's cache
survival is **a best-effort retention policy, not a fixed lease** — there is
no exact expiry instant (see `docs/general_info/openai_cache_expiry.md`).
Modern models (gpt-5.5/gpt-5/gpt-4.1) use extended caching: reuse is
high-confidence early, then the eviction risk climbs over hours, with a hard
24 h ceiling.

So the surface **synthesizes** a window for a session with implicit activity
(`store.LoadImplicitCacheActivity` → `cachewarmsvc.buildImplicitWindows`)
and grades severity by **idle age** (time since last activity), not a
countdown to a fake instant:

| Idle since last activity | Severity | Meaning |
|---|---|---|
| `< implicit_warn_seconds` (default **1 h**) | ok | high-confidence reuse |
| `1 h – 2 h` (`implicit_critical_seconds`) | soon | **at risk of expiry** |
| `2 h – 24 h` (`implicit_max_seconds`) | critical | **significantly increased risk** |
| `≥ 24 h` | (gone) | hard-max reached — dropped from the surface |

Mechanically, `ExpiresAt = last_activity + implicit_max_seconds` and the
risk bands map onto per-window classifier thresholds
(`CacheWindow.WarnAtOverride/CriticalAtOverride`), so implicit (hour-scale)
and Anthropic (seconds-scale) windows classify in one pass. The window is
flagged **estimated** (the card hedges with `~`). prefix-at-risk = the
latest hit's `cached_tokens`; value-at-risk uses `tokens × (full_input_rate
− cached_read_rate)` (no write premium), vs Anthropic's `tokens ×
(write_rate − read_rate)`. Config: `[cachewarm].implicit_warn_seconds` /
`implicit_critical_seconds` / `implicit_max_seconds` (defaults 3600 / 7200 /
86400) — raise/lower per your org's retention mode.

**Keep-warm lever.** Because a refresh requires re-sending the prefix
*content* (which SuperBased does not store — hashes only), the only
content-free lever is Anthropic's **1 h TTL tier** (a one-time client-side
request-shape change), surfaced as advice. There is no content-free TTL
refresh for Anthropic/OpenAI implicit caches. See the keep-warm plan.

### GPT-5.6 explicit cache-write tier (wire-grounded; safe-but-inert on the Codex lane)

GPT-5.6 is the **first OpenAI line with a billed cache-write term**. Two layers:
what the docs describe, and what we actually see on the wire today.

**Docs (docs-only unless flagged below), per the OpenAI 5.6 cache API:**

- **Writes bill at 1.25× uncached input**; **reads keep the 90% discount**.
  Reads and writes are **disjoint, never additive** (launch-week overlapping
  counts were an OpenAI billing bug, staff-confirmed fixed + refunded).
- New cache API: `prompt_cache_options.mode` = `implicit` (default) | `explicit`;
  `prompt_cache_options.ttl` with **"30m" the only supported value** (a
  guaranteed ≥ 30-min floor; sliding-vs-fixed is undocumented). Explicit
  `prompt_cache_breakpoint` blocks cap at **≤ 4 writes/request** with a
  50-breakpoint read window; the 1024-token min-prefix floor is unchanged.
- `prompt_cache_key` is **recommended** for reliable prefix matching
  (~15 req/min per key; caching still works, degraded, without it).
- The legacy `prompt_cache_retention` (`in_memory` / `24h`) knob is
  **DEPRECATED** on 5.6+.

**Wire (grounded from our own captured `gpt-5.6-sol` responses, 2026-07-16):**

- Usage field is `usage.input_tokens_details.cache_write_tokens` alongside
  `cached_tokens` (Responses API); `prompt_tokens_details.cache_write_tokens`
  is the documented chat.completions analog. `input_tokens` stays GROSS of
  `cached_tokens`.
- The Codex CLI (0.144.x) still sends the **legacy** `prompt_cache_retention:"24h"`
  plus a UUIDv7 `prompt_cache_key` — **not** the new `prompt_cache_options`. So
  the cachewarm implicit-window defaults above (warn 1 h / critical 2 h / max
  24 h) **remain correct for the codex lane today**. They would need to become
  model-family-aware only if/when a 30m-TTL request shape actually appears on
  the wire — do not change the defaults preemptively.

**SuperBased status: safe-but-inert.** The proxy usage parse
(`internal/proxy/provider.go`, `streaming.go`) now reads `cache_write_tokens`
into the existing `cache_creation` columns, and the cost table already carries
the 5.6 write rate. On the **Codex ChatGPT-plan lane the field is present but
always 0** — plan credits have no write term (sample: 30,464 cached read of
31,841 input, `cache_write_tokens` 0), so we are **not under-billing**. Nonzero
values are expected only on **metered API-key** traffic;
`api_turns.cache_creation_tokens > 0` is the detector for the first live
nonzero. The write count is disjoint from `cached_tokens` (docs-confirmed
post-refund), so parsing it as its own term does **not** repeat the codex
reasoning-token double-bill trap (fixed in v1.18.0 / migration 058) — that was
a *subset* count billed as disjoint; this is a genuinely disjoint one.

**Capture is proxy-only.** Codex CLI **drops** `cache_write_tokens` (upstream
bug openai/codex#32479 — its parser structs lack the field), so JSONL / rollout
Tier-2 capture can never observe writes. Only the proxy lane sees them.

### Provider cache-billing shapes (what a "cache write" costs)

Cache **reads** are discounted everywhere. Cache **writes** are where the rate
cards diverge, and the divergence is what the cost engine has to model. The
table below is the grounding of record for `internal/intelligence/cost`:

| Provider | Write (cache creation) | Read | Storage | Where the rate lives |
|---|---|---|---|---|
| Anthropic | **1.25 × input** (5m tier), **2 × input** (1h tier) | 0.10 × input | none | explicit `CacheCreation` / `CacheCreation1h` on the row |
| OpenAI GPT-5.6+ | **1.25 × input** (explicit writes only) | 0.10 × input | none | explicit `CacheCreation` on the row |
| OpenAI pre-5.6 | no write term (caching is automatic) | 0.10 × input | none | row leaves it blank → $0, correct |
| **Google Gemini** | **1.00 × input** — a write *is* an ordinary input token | 0.10 × input | $1.00–$4.50 / 1M-tok / hour, **explicit caches only** | **derived** from the row's `Input` by `cacheWriteRules` |

**Gemini, grounded 2026-09-03** against
<https://ai.google.dev/gemini-api/docs/pricing> (paid/standard tier). Every
Gemini row on that card has exactly four price lines — *Input*, *Output*,
*Context caching*, *Context caching (storage)* — and the *Context caching* line
is the **read** rate, uniformly 10% of input:

| Model | Input | Output | Context caching (= read) | Storage |
|---|---|---|---|---|
| Gemini 2.5 Pro | $1.25 (≤200K) / $2.50 (>200K) | $10 / $15 | $0.125 / $0.25 | $4.50 /1M/hr |
| Gemini 2.5 Flash | $0.30 | $2.50 | $0.03 | $1.00 /1M/hr |
| Gemini 3.5 Flash | $1.50 | $9.00 | $0.15 | $1.00 /1M/hr |
| Gemini 3.6 / 3.7 / 3.8 Flash | $0.75 (intro, → $1.50 on 2027-01-01) | $3.75 (→ $7.50) | $0.075 (→ $0.15) | $0.50 /1M/hr (→ $1.00) |

There is **no cache-creation line anywhere on the card**, for implicit or
explicit caching. Google's model is: you pay the standard input rate for the
tokens the first time they go through (whether or not they land in a cache),
you get the ~90% discount when they come back as a cache read, and an
*explicit* cache additionally accrues an hourly storage fee for its TTL.

**Why that mattered.** A blank `CacheCreation` means **$0** everywhere else in
the table, which is the right answer for a provider that genuinely doesn't
charge for writes (pre-5.6 OpenAI). For Gemini it was the *wrong* answer:
Antigravity's usage submessage normalizes every provider onto an
Anthropic-style split (field 1 = uncached suffix, field 2 = prefix newly
written to cache, field 5 = prefix read from cache), so the **bulk of every
Gemini prompt** lands in `cache_creation_tokens` — grounded 2026-09-03 on 20
real generations, field 1 held constant at ~1,071–1,318 tokens/generation while
field 2 accumulated 151,337 tokens over 10 generations. Pricing field 2 at $0
understated Antigravity/Gemini cost by roughly the whole prompt.

**How it's fixed (`internal/intelligence/cost/pricing.go`).** A per-provider
rule table, `cacheWriteRules`, maps a provider family to a `cacheWritePolicy`:

- `cacheWriteRowPriced` (default, every family with no rule row) — the write
  price is not derivable from `Input`, so it must be on the row; blank stays $0.
- `cacheWriteAtInputRate` (`gemini` today) — a blank `CacheCreation` is filled
  from the row's own `Input`, and `LongContextCacheCreation` from
  `LongContextInput` (Google reprices the *entire* request above 200K on the
  Pro line, so the write follows the LC input rate the same way the read
  follows `LongContextCacheRead`).

`applyCacheWriteRule` runs in `Table.rate` — the single funnel every Lookup
rung passes through with the resolved key in hand — so it covers baked rows,
`config.toml` overrides, dated timelines and family-prefix fallbacks in one
owner rather than restating the same fact on ~25 Gemini rows. It only ever
fills a **zero** field, so an explicit rate always wins.

**Storage is deliberately not modelled.** It is a time-integral over a cache
handle's TTL and we hold no cache-handle lifetimes; more to the point it
applies only to *explicit* caches, and the implicit caching that Antigravity
and Gemini turns actually exercise carries no storage charge.

### Per-model cache economics now also arrive with the pricing feed

The per-model cache facts above - the caching regime (explicit vs implicit),
how a cache write is billed, the TTLs and 1-hour tier, and the minimum
cacheable prefix - live in CODE today (`cachetrack/tier.go::minCacheableTable`,
`internal/cachewarm`, the provider-billing rule table). As of the 2026-09-11
pricing-feed arc those same facts can ALSO travel as DATA, in the optional
`economics` block of each signed pricing-feed row. In v1 the feed **carries,
persists and displays** economics but does NOT yet drive the cachetrack or cost
engines from it - the overlays here stay authoritative until a follow-up proves
each fact against live traffic. See [`pricing.md`](pricing.md) "Where prices
come from" for the economics field list and trust model; the tables in this doc
are not restated there.

## Config

```toml
[cachetrack]
  enabled = true                       # default; opt out by setting false
  max_tracked_sessions = 64            # LRU bound on the engine's session map
  calibrate_log_path = ""              # diagnostic sidecar; off by default
  retention_days = 90                  # cache_segments / cache_events horizon;
                                        # cache_entries terminal-state horizon is
                                        # a hardcoded 14 days inside PruneCacheRows;
                                        # 0 disables the cache prune entirely.
                                        # Live entries are never pruned regardless
                                        # of age (they may still be in the provider).
```

An install with **no `[cachetrack]` section** gets `enabled=true` via
the loader's partial-merge (a previous bug had the missing section
silently zero-value to `false`; pinned by
`TestBuildProxy_DefaultConfigWiresCacheEngine`).

**§9 retention sweep.** The cache_* tables would otherwise grow
unbounded — the engine writes per turn (one event row + zero-or-more
segment rows; an entry row on write turns). The sweep runs from
the existing maintenance tick (`cmd/observer/main.go` →
`runRetention` → `retention.Run` then `store.PruneCacheRows`):
manual via `observer prune`, automatic on boot when
`[observer.retention].prune_on_startup` is set. Idempotent — a
second call within the same horizon returns 0, pinned by
`TestPruneCacheRows_SecondRunNoop`. NODE-LOCAL: the sweep is a
plain DELETE; no org-push coupling exists.

**§9 max_blocks_per_session OOM guard.** The Tier-2 accumulator
caps cumulative blocks at `MaxBlocksPerSession = 4096` per session
(constant in each adapter; `internal/adapter/claudecode/adapter.go:940`,
same in opencode/kilocode/clinecli). When the cap latches,
`capExceeded=true` causes the next emit to surface
`BlockHashes=nil` — the engine flips to `KindReanchor`, preserving
the rest of the watcher's hot path. Compaction resets the cap.
Hardcoded constant (not a config field) because the cap is a
defensive OOM guard, not an operator-tunable signal.

**R7 cache_scope.** The `Scope` parameter handed to the engine at
both seam call sites (`internal/proxy/proxy.go:966` Tier-1 +
`internal/store/store.go:1376` Tier-2) is currently the literal
`"default"` — workspace-blind, single-scope. The spec §11 + §24.4
R7 names `sha256(upstream_host + ":" + auth_identity + scope_salt)[:16]`
as the eventual derivation; the `scope_salt` config field is
**deliberately omitted** because adding the salt without an
`auth_identity` source (proxy doesn't extract one today; same on
the Tier-2 path) would land a half-wired feature. Tracked as
backlog item 9 in
`docs/plans/cachetrack-p3-backlog-2026-06-09.md`.

## CLI surface

### `observer cache-health`

Reports the §10 P0 health gate plus two secondary checks.

```
$ observer cache-health
cache mispredict-rate gate: PASS
  total events     : 247
  graded events    : 213  (need ≥ 200)
  mispredict count : 4
  mispredict rate  : 0.0188  (need ≤ 0.0500)
  unique sessions  : 3
  per-session:
    sA: graded=87 misp=1 rate=0.0115
    sB: graded=64 misp=2 rate=0.0312
    sC: graded=62 misp=1 rate=0.0161
  cause breakdown (all events):
    suffix_growth: 200
    hit:           8
    ttl_expired:   3
    model_changed: 2
read:write consistency: CLEAN  (flag when read > 3.0× write on *_rewrite/compaction_reset)
cause concentration: CLEAN  (no non-suffix_growth cause exceeds 80.0% of graded)
```

Flags:

- `--json` — machine-readable. `MispredictEvents[]` + `CauseBreakdown[]`
  + `InconsistentRewriteEvents[]` + `DominantCause`.
- `--min-events` (default 200) — P0 graded-event minimum for PASS.
- `--max-rate` (default 0.05) — max mispredict rate for PASS.
- `--max-rewrite-read-ratio` (default 3.0) — read:write threshold for
  the inconsistency WARN (mechanically impossible shapes on a real
  invalidation).
- `--max-cause-share` (default 0.80) — share threshold for the
  cause-concentration WARN (one non-suffix_growth cause should never
  dominate a healthy soak; over-firing rule indicator).

The rate gate is the PASS/FAIL signal; the two secondary checks
**never** change the verdict but surface the class of error the rate
is blind to — when the engine's predicted kind and the attributed
kind both land in the same hit-vs-write bucket, a mislabeled cause
still grades "correct."

The cause-concentration WARN excludes `suffix_growth` (the healthy
baseline) **and** `handoff_rehydration` (the by-design first-turn cold
write of a session-handoff target) — see below.

### Session-handoff accounting

A [session-handoff](session-handoff.md) TARGET session's first turn is a
large cold cache write BY DESIGN: the rendered handover doc arrives as
the injected first prompt, the `SessionStart` `additionalContext`, or an
early `HANDOFF-<id>.md` file read. Attributing that write as a plain
`reanchor` would let it trip the advisor's `session_balloon` /
`cache_write_waste` detectors and this WARN. Two layers annotate it:

- **Live (cachetrack), Anthropic lane.** When a turn's content carries the
  `superbased-handoff <id>` marker AND it is the first observed turn for
  `(session, model, scope)`, the §7 attribution table fires
  `cause=handoff_rehydration` (same `reanchor` kind). The marker persists
  in the conversation history on every later request, but the rule
  self-gates on `Prior == nil`, so it only ever fires on the first turn.
  Threaded at the proxy (`parseRequest` body scan) and the Tier-2 store
  boundary (`observationToObserveInput` block-body scan).
- **Live (cachetrack), implicit / OpenAI-Codex lane (§15.3).** The reduced
  implicit-cache attribution mirrors the Anthropic lane: on the bootstrap
  turn (`!PriorObserved`) with the marker set, `ruleImplicitHandoffRehydration`
  fires `cause=handoff_rehydration` with the same `implicit_write` kind the
  plain bootstrap reanchor uses — so every denominator/exclusion is
  unmoved (`implicit_write` routes to `bucketSkipped` + `isRateSkipped`, and
  its predicted kind is also `implicit_write`, so `ImplicitCacheConsistency`
  excludes it as a bootstrap turn). Coverage is **proxy-only**: the
  provider-agnostic `parseRequest` raw-body scan sets the flag, and the
  OpenAI branch of `buildCacheObserveInput` now threads it (it previously
  dropped it). A codex/OpenAI handoff target routed **through** the proxy
  (`observer codex`) gets the live annotation.
  - **Residual — codex Tier-2 (transcript-ingested).** Non-proxied codex is
    the common case on this node, and its Tier-2 `CacheTurnObservation`
    carries `BlockHashes: nil` by design (the implicit path skips the chain
    push), so `observationToObserveInput` has no reconstructed block bodies
    to scan — the marker flag stays false and the live annotation never
    fires. That lane's coverage is the advisor's retroactive
    handoff-target belt below (any future implicit Tier-2 emitter that DOES
    reconstruct block content would pick up the live annotation for free —
    the engine consumes the flag as data, no adapter-name branch).
- **Retroactive (advisor).** The advisor loads `handoffs.target_session_id`
  and exempts a handoff target's leading turn / first cache event from the
  balloon + write-waste aggregations — the belt that also covers
  non-proxied targets (incl. codex Tier-2) whose live marker never reached
  cachetrack.

### `observer backfill --cache-rescan`

Re-walks claude-code transcripts through the Tier-2 cache observation
engine to populate historical `cache_segments` / `cache_entries` /
`cache_events` rows. Use after enabling `[cachetrack].enabled` on a
daemon with historical traffic, or after upgrading to a build that
closes a cachetrack defect (deep canonicalize / billing-header
exclusion / etc.) to retrofit corrected attribution onto past
sessions.

```bash
observer backfill --cache-rescan
```

Idempotent end-to-end via the `CacheEventExistsForMessage` dedup gate:
- First run on fresh history → emits events for every assistant turn
  the proxy didn't observe live.
- Second run → every `msg_id` hits the gate; engine state stays
  consistent; row counts unchanged.
- Run alongside a Tier-1-capturing proxy → proxy-already-seen turns
  hit the gate; Tier-2 emits only the gaps.

Picked up automatically by `observer backfill --all`. Order-sensitive
within each file (chain dependency); files walked in mtime order.

Only claude-code emits Tier-2 observations today. Other adapters
(codex, opencode, kilo, cline-cli) join the Tier-2 emitter pool per
spec §14.3 C21–C24; when they land the same `--cache-rescan` flag will
widen scope.

### `[cachetrack].calibrate_log_path` — per-block diagnostic sidecar

Set to a writable path and restart the daemon. The engine appends one
JSON-Lines entry per block fed to `ObserveTurn`:

```json
{"ts":"...","session_id":"...","api_turn_id":300,"seq":29,"level":"tools","kind":"tool","len_raw":1827,"sha_raw":"a8e2…","len_canon":1814,"sha_canon":"4c19…","canon_prefix":"{\"description\":\"Reads a file...\""}
```

Auto-stops after 200 blocks (~6 turns of a typical claude-code
session). For tools+system blocks the entry carries a 120-char
canonical-bytes prefix so the diff workflow can see WHICH field
differs in one pass. Message-level blocks emit hash-only per
CLAUDE.md "no content in DB / logs" Don't.

Diagnostic interpretation:

| `sha_raw` turn-over-turn | `sha_canon` turn-over-turn | Conclusion |
|---|---|---|
| stable | stable | drift not at this seq |
| stable | DIFFERS | canonicalize regression (shouldn't happen post deep-canon) |
| **DIFFERS** | DIFFERS | source bytes differ → look upstream (compressor / proxy mutation / SDK behavior) |

Unset the path and restart to disable. Sidecar use is one-shot; the
file handle stays open until process exit.

## Architecture

Single store-owned cachetrack engine instance shared by proxy and
watcher (spec §24.4 single-canonicalizer + R-engine = Option A):

```
                        ┌─ cachetrack.Engine ──────────────────────┐
                        │   per-session CacheModel + chain hashes  │
                        │   attribution rules + reconciliation     │
                        └──────────────────────────────────────────┘
                                 ▲                       ▲
                                 │ ObserveTurn           │ ObserveTurn
                                 │ (Tier 1)              │ (Tier 2)
                                 │                       │
              ┌───── proxy.Proxy ─┴───┐    ┌── store.Store ┴──────────┐
              │  /v1/messages         │    │  Ingest (CacheObservations) │
              │  enumerateBlocks      │    │  CacheEventExistsForMessage │
              │  PersistCacheObservation   │  PersistCacheObservation     │
              └────────────────────────┘    └──────────────────────────┘
                       Tier-1 path                     Tier-2 path
                       (live api_turns)                (claude-code transcripts)
```

Tier-1 is per-request from the proxy; Tier-2 is per-assistant-turn
from the watcher reading transcripts. The cross-tier dedup gate
(`CacheEventExistsForMessage`) prevents double-observation —
proxy-already-seen turns short-circuit on the Tier-2 side, keeping
engine state consistent regardless of which tier saw the turn first.

Module boundary discipline (CLAUDE.md / spec §24):

- `internal/cachetrack/` is the pure logic package. It MUST NOT
  import `internal/store`, `internal/proxy`, `internal/adapter`,
  `internal/intelligence`, `database/sql`, `net/http`, or `fsnotify`.
  Pinned by `internal/cachetrack/imports_test.go`.
- Adapters MUST NOT import `internal/cachetrack`. They emit
  `models.CacheTurnObservation` (the cross-package seam type) with a
  string `LevelLabel` instead of the engine's `BlockLevel` enum.
- Attribution decisions are table-driven (`attributionRules`,
  `stateTransitions`, `minCacheableTable`) — no if/else ladders, no
  `tier ==` string switches.

## Known limitations

### opus-4-8 zero-usage envelopes — fixed at the rate level

The 2026-06-09 soak's 4 opus-4-8 `unknown` mispredicts (row-12
fallthrough; predicted=`write`) were diagnosed as **zero-usage
turns**: the provider returned an envelope with `input_tokens=0,
output_tokens=0, cache_read=NULL, cache_creation=NULL, http_status=NULL`,
and the proxy persisted the api_turn row regardless. The engine
emits `KindMispredict + CauseUnknown` because no rule matched
AND no usage signal arrived — but the turn is **observationally
vacant**: there's nothing for the engine's prediction to be
graded against.

Fix: `cachetrack.MispredictRateGraded` (and `observer cache-health`
which now calls it) skip these events from both numerator AND
denominator. Same shape as the existing `KindReanchor` /
`KindBelowMin` / `KindCompactionReset` exclusions — observationally
non-gradable events don't count toward "did we predict hit-vs-write
correctly?" The dashboard `MispredictEvents` list still includes
them (annotated `[zero-usage, excluded from rate]`) so operators
can see the row-12 fallthroughs happened.

If the same shape resurfaces but with **non-zero tokens** (i.e.
real "engine predicted something the data invalidated"), the rate
will surface it normally. The carve-out keys only on
`tokens_read=0 AND tokens_written=0`.

### MCP tools_changed read:write over-flag

A small remaining signal: 2 `inconsistent_rewrite` events per
~150 opus-4-8 turns at the read:write WARN threshold (3.0×).
Cause=`tools_changed`. Likely a real MCP server connect/disconnect
where the new tools array invalidates the cached prefix; the
provider still serves a large `cache_read` from the older prefix
that hit before the tools change rippled through, and the small
new tail rewrites. Cause IS correct; the guard's threshold may
need a per-cause carve-out (the guard fires on a generic
`*_rewrite` shape; tools_changed legitimately has high read:write
when the older cache slice is still warm). Not addressed at P0;
revisit when MCP toggles are common enough to dominate.

### Coverage matrix (§15.3 landed 2026-06-10)

The cachetrack engine now runs TWO disjoint attribution paths,
selected at the engine boundary by a `Capabilities.ImplicitCache`
flag:

| Path | Providers | Adapters | Surface |
|---|---|---|---|
| Marker-aware (Anthropic) | `anthropic`, `anthropic-bedrock`, `anthropic-vertex`, `kilo` (kilo-auto family) | claude-code Tier-1 proxy + Tier-2 transcripts; opencode/kilo/cline-cli when routed to an Anthropic provider | §10 mispredict-rate gate (`MispredictRateGraded`) — high fidelity |
| Implicit-cache (§15.3) | `openai`, `azure-openai`, `deepseek`, `groq`, `fireworks`, `together`, `mistral`, `cohere`, `openrouter` (default) | proxy Tier-1 OpenAI; codex Tier-2 from `token_count` records; opencode/kilo/cline-cli when routed against any implicit-cache provider | Separate `ImplicitCacheConsistency` metric + prefix-survival rate — lower fidelity |

The routing table lives at
`internal/cachetrack/routing.go::implicitProviderTable` and is the
single source of truth — adapters call `cachetrack.IsImplicitCacheProvider`
at their emit boundary. Unknown providers default to FALSE
(Anthropic-shape) — the conservative bias documented in the table's
doc comment.

### §15.3 implicit-cache reduced vocabulary

Implicit cache exposes only a scalar `cached_tokens` per turn — no
markers, no creation count, no per-block breakdown. The engine
treats every implicit-cache turn as "scalar observation against a
per-session estimated stable prefix length" and emits one of:

| Kind | Cause | When |
|---|---|---|
| `implicit_write` | `reanchor` | First turn for (session, model, scope) |
| `implicit_write` | `suffix_growth` | Continuation turn whose prefix grew but is still below the 1024-token min-cacheable floor |
| `implicit_write` | `prompt_cache_key_overflow` | Wired-but-inert today (proxy doesn't yet detect prompt_cache_key rolls) |
| `implicit_hit` | `implicit_hit` | `cached_tokens > 0` within band of the tracked prefix |
| `implicit_hit` | `prefix_shrink` | `cached_tokens > 0` but materially below tracked prefix (≥ one 128-token granule down) |
| `implicit_miss` | `prefix_churn` | `cached_tokens = 0` on a turn whose prior prefix was ≥ min-cacheable (eviction OR prefix change — can't tell which) |
| `below_min` | `below_min_cacheable` | Tracked prefix below model min (reuses Anthropic row 10 shape) |

All three implicit kinds (`implicit_hit` / `implicit_miss` /
`implicit_write`) are routed to `bucketSkipped` by
`cachetrack.bucketOf` and excluded from `MispredictRateGraded` by
`cachetrack.isRateSkipped` — the load-bearing §5 guardrail. Pinned
by `TestMispredictRateGraded_AnthropicRateUnmovedByImplicit`
(interleaves implicit + Anthropic events through the real assembly
path and asserts byte-identical Anthropic rate).

### §15.3 implicit-cache health metric

The separate consistency metric lives at
`cachetrack.ImplicitCacheConsistency`. It grades the
predicted-vs-observed agreement on the implicit-cache subset,
excluding bootstrap `implicit_write` turns (same shape as the §10
`reanchor` skip). The dashboard surfaces this on the new
`tile.cache_implicit_prefix_survival` tile + the rewritten
"Provider coverage" banner; the CLI surface is on the dashboard's
`/api/cache/health` JSON envelope under
`implicit_cache_consistency_rate` + `implicit_cache_prefix_churn_rate`.

A high implicit-cache miss rate is operator-actionable — usually
means `prompt_cache_key` churn, aggressive provider eviction, or a
prompt prefix drifting turn-over-turn. A low engine-consistency
rate (sub-90% across hundreds of events) suggests the per-session
prefix estimate is drifting from what the provider is actually
caching.

### Live soak — first pass closed 2026-06-10

**First pass landed 2026-06-10** against operator-generated codex
traffic (sessions `019eae9d` + `019eae9f`) on a `1c8a38e`-built
daemon. Measured directly against `~/.observer/observer.db`:

| Surface | Measured | Notes |
|---|---|---|
| Implicit-cache events captured | 7 | 2 reanchor bootstraps + 5 hits + 0 misses |
| Codex sessions touched | 2 | Both Tier-1 proxy capture |
| Implicit consistency (Phase 1 metric) | 5 / 5 = **100%** | every graded `(predicted, observed)` pair matched |
| Prefix-survival rate | 5 / 5 = **100%** | hits / (hits + misses); zero churn observed |
| `cause='prefix_shrink'` rows | 1 | engine correctly detected `cached_tokens` dropping 14208 → 4992 turn-over-turn; partial-invalidation flag firing in the wild |
| Anthropic §10 graded events | 147 | unchanged vs pre-§15.3 baseline (the same DB; implicit events bucket-skipped per §5 guardrail) |
| Anthropic §10 mispredicts | 0 | unchanged |
| Anthropic §10 `bucket_mispredicts` | 0 | unchanged |
| `observer cache-health` exit | non-zero (143 < 200-event gate floor) | unchanged from pre-§15.3 — the gate floor is the standing arbitrary deferral, not a §15.3 regression |

**Real-event sample from session `019eae9f` (Tier-1 proxy capture):**

```
T1  implicit_write / reanchor    cached=0     net_input=2432  (bootstrap; prefix seeded)
T2  implicit_hit   / implicit_hit cached=11648
T3  implicit_hit   / implicit_hit cached=14208
T4  implicit_hit   / prefix_shrink cached=4992  (provider rotated prefix — engine caught it)
T5  implicit_hit   / implicit_hit cached=16256
T6  implicit_hit   / implicit_hit cached=20352
```

§5 guardrail evidence on live data: codex session `019eae9f`
contributed 6 cache_events to the persisted table, **all 6 routed
to `bucketSkipped`** via `cachetrack.bucketOf` so none entered the
Anthropic §10 denominator. The session's `per_session` entry in
`observer cache-health --json` reports `graded_events: 0` — the
exact disjoint-surface property the §15.3 plan called out.

**Operator items still useful** (open):

1. Vary request length in 64 / 128 / 192 / 256-token steps and
   confirm `cached_tokens` quantization (the 128-granule assumption
   matched the observed continuation hits but a clean granule
   sweep would close the open question definitively).
2. Send sub-1024 prompts on gpt-4o / gpt-4o-mini / gpt-5* to
   confirm `cached_tokens = 0` below the floor.
3. Observe `prompt_cache_key` rolls under load (≥ 15 rpm per key)
   and decide whether to wire the overflow detector (currently
   inert).
4. Optional: confirm the OpenRouter pass-through strips
   `cache_control` markers.

**Provisional verdict (2026-06-10):** §15.3 holds on real data.
Implicit-cache attribution path emits sensible events with healthy
consistency; Anthropic §10 gate is unmoved at the byte level. The
four open items above can land as one operator follow-up soak,
they don't gate v1.8.3.

---

### Live soak — END-DEFERRED (original procedure)

The §15.3 build landed against documented OpenAI assumptions
(128-token granule, ~1024 min-cacheable, both API shapes — Chat
Completions `prompt_tokens_details.cached_tokens` and Responses API
`input_tokens_details.cached_tokens` — already covered by the proxy
parsers). A LIVE soak against a real OpenAI account is the single
end-deferred validation item:

1. Confirm cached_tokens granularity by varying request length
   in 64 / 128 / 192 / 256-token steps and observing the
   `cached_tokens` quantization.
2. Confirm min-cacheable across families (gpt-4o, gpt-4o-mini,
   gpt-5*) by sending sub-1024 prompts and confirming
   `cached_tokens = 0`.
3. Observe `prompt_cache_key` rolls under load (≥ 15 rpm per key)
   and decide whether to wire the overflow detector.
4. Optionally: confirm the OpenRouter pass-through strips
   Anthropic `cache_control` markers (today the routing table
   defaults `openrouter` to implicit — see
   `internal/cachetrack/routing.go::implicitProviderTable`'s
   doc comment for promotion criteria).

Operator runbook for the soak lives at this section; until it
runs, all §15.3 guarantees rest on the documented assumptions +
the fixture suite.

### Opencode + kilo Tier-2 exclusions are ASSUMED, not confirmed

The opencode + kilo §14.3 audits
(`docs/audits/cachetrack-{opencode,kilo-cli}-tier2-audit-2026-06-09.md`)
exclude wall-clock fields inside tool / reasoning / subtask part
bodies — `state.time.{start,end}`, `state.title`,
`time.{start,end}`, `time.created`, plus kilo's
`metadata.openrouter.reasoning_details` — from CanonicalBytes,
based on the schema's own docstring claim that these are UI-local
metadata. The audit did NOT capture upstream wire traffic to
confirm these fields are stripped before going to the provider.

**Follow-up:** before the §14.3 emitters land in the §10
denominator unconditionally, confirm the exclusions against
Tier-1 §10 reconciliation on real opencode + kilo sessions. The
gate is: do the per-session mispredict rates on the live
emitters stay within the same band as claudecode's pinned 2.7%
soak, or do they spike, indicating the excluded fields actually
do reach the wire and our reconstruction is drifting against the
real upstream chain?

If they spike, two paths:
1. Fold the field back into CanonicalBytes (chain re-matches the
   upstream stream) — preferred if wire capture confirms the
   field reaches the provider.
2. Add a per-adapter §10 exclusion that holds opencode + kilo
   out of the denominator until the §15.3 work lands a
   confirmed model.

Implicit-cache providers (deepseek-flash via OpenRouter; OpenAI
through any provider-plug-in) are a separate gap: their
`cache_creation_tokens=0` shape causes the engine's bucket-
prediction to mispredict every cache-read turn. The cline-cli
fixture-grading test (`internal/cachetrack/fixture_grading_test.go`)
exposes this shape openly; the §15.3 work owns the fix.

### Tier-2 continuation Hit-prediction (§15.3 (c)-phase-2 CLOSED)

**Status:** Closed by the §15.3 (c)-phase-2 commit (snapshot-
before-push lookup + CacheableTokens-gated predictKind with
delta-aware `estimateNewSuffixTokens`). Plan-of-record at
`docs/plans/cachetrack-15.3c-assumedbreakpoints-lookup-plan-2026-06-09.md`.

The fix in three pieces:

1. **Snapshot lookup.** `ObserveTurn` captures
   `priorTurnEndHash := m.Chain.PrefixHashHex()` BEFORE pushing
   the turn's new blocks. `FindByPrefix(priorTurnEndHash)` then
   locates the prior turn's end-of-chain entry on continuation
   turns (where the chain has grown past it). Without the
   snapshot, the post-push hash never matches an entry.
2. **CacheableTokens-gated predictKind.** With a matched live
   entry, predict `KindWrite` iff `CacheableTokens(model,
   predictedNewTokens)` — i.e. the new-tail tokens clear the
   model's min-cacheable threshold. Below threshold → `KindHit`.
   This separates growth-shape ("matched + substantial new
   content") from continuation-shape ("matched + tiny tail").
3. **Delta-aware suffix estimate via a capability flag.**
   `Capabilities.BlocksAreCumulative` is true for Tier-1 (proxy
   passes the full Anthropic request body cumulative every turn)
   and false for Tier-2 (transcript adapter accumulators emit
   per-turn delta). `estimateNewSuffixTokens` consults the
   matched entry's `BlockCount` (recorded as `len(in.Blocks)`
   at entry creation) to slice cumulative inputs down to the
   per-turn delta. The slice anchor is in `in.Blocks` units, NOT
   chain units — `Chain.Count()` accumulates across all pushes
   and diverges from `len(in.Blocks)` past T2 on Tier-1 (caught
   by `TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns`).

**Closure footprint** on the §14.3 fixture surface (pre-fix → post-fix):

| | pre | post |
| --- | ---: | ---: |
| Tier-1 baseline growth | 0 | 0 (invariant — operator-checked) |
| Tier-1 baseline continuation | 1 | 0 (flip ✓) |
| Tier-1 baseline WHH partial | 2 | 1 (T2 flips, T3 v1 limit) |
| §14.3 OpenCode multi-turn | 0 | 0 (with enlarged T2 delta) |
| §14.3 Kilo-CLI multi-turn | 0 | 0 (with enlarged T2 delta) |
| §14.3 OpenCode clean-cont | 1 | 0 (flip ✓) |
| §14.3 Kilo-CLI clean-cont | 1 | 0 (flip ✓) |
| §14.3 Cline-CLI implicit | 2 | 2 (no flip — implicit-cache gap, distinct) |
| **Total** | **7** | **3** |
| **Closure** | | **4-of-7** |

**Documented v1 limitations** (acceptable trade-offs):

- **Consecutive Hit sequences (W H H+).** The first H after a W
  closes; subsequent consecutive Hits still mispredict because
  v1 doesn't refresh the matched entry on Hit turns
  (no entry created at end-of-Hit-turn → snapshot lookup misses
  on the next turn). Pinned by
  `TestEngineTier1Baseline_WHHPartialClosurePattern`. Full
  closure is §15.3 (c)-phase-2 (rolling-entry refresh /
  walkback window) — out of phase-2 scope.
- **Implicit-cache providers (cline-cli `cache_creation=0`
  everywhere).** The §15.3 (c) fix doesn't help: T1 reports
  `cache_creation=0` so no entry is created; every snapshot
  lookup misses; `predictKind` falls to the no-matched-entry
  Write branch. Pre-fix and post-fix both fire mispredicts.
  The distinct fix path is an `ImplicitCache` capability flag
  + dedicated §7 attribution rule that emits Hit (or a new
  ImplicitHit) without requiring a matched entry. Pinned by
  `TestGradeClineCLIImplicitCacheShape`.
- **Boundary residual.** `estimateNewSuffixTokens` uses the v1
  byte→token heuristic. Turns whose new-tail tokens sit near
  the `MinCacheableTokens(model)` threshold may estimate on the
  wrong side → spurious bucket-level mispredict (engine-
  internal; `outcome.Kind` stays Write/Hit so §10 rate stays
  flat). SessionEMA scaling refines the estimate over time. A
  future debugger investigating "why did this boundary turn
  mispredict?" — this is the residual, not a phantom bug.

**G2/G3 instrumentation** for phase-4 soak gating:

- `cachetrack.Engine.Counters()` returns
  `EngineCounters{BucketMispredictTotal, TriggerMispredictCalls}`
  — atomic per-process counters incremented in `ObserveTurn` /
  the entry-demotion path.
- `cmd/observer/cache_health.go` reads persisted (predicted_kind,
  kind) pairs from `cache_events`, computes
  `cachetrack.BucketMismatch(predicted, observed)` per row, and
  surfaces the count + per-session breakdown in
  `CacheHealthReport.BucketMispredicts` /
  `BucketMispredictsPerSession`. The `--json` output carries
  the structured fields; the human-readable output prints
  `bucket-mispredict (G2): N events across M sessions`.
- **Why the §10 rate cannot replace this.** A growth-turn
  regression where the engine wrongly predicts Hit but observes
  Write fires `rec.Mispredicted=true` (engine-internal, drives
  EMA + entry-state demotion) but `outcome.Kind` stays
  `Write` / `InvalidationRewrite` — never `KindMispredict`. The
  §10 `MispredictRateGraded` only counts `KindMispredict`
  outcomes, so the rate stays flat while the regression
  poisons every Sonnet growth turn's forecaster calibration.
  Proven structurally insensitive by
  `TestLiveSection10Rate_OverContinuationSequence` (commit
  c489ddb). G2 is the only catch.

#### Validation status — fixture-validated only

**§15.3 (c) v1 is FIXTURE-VALIDATED only; the phase-4 real-data
soak was NOT run as part of this commit.** The G2/G3 soak
instrumentation is shipped and ready (`observer cache-health`
surfaces `BucketMispredicts` + per-session breakdown from
persisted cache_events without any DB migration); the actual
run is pending.

What IS proven:
- Tree-wide `go test -race ./...` green + `golangci-lint run
  ./...` clean.
- The fix stops the spurious continuation mispredicts at the
  bucket level on the §14.3 fixture surface (4-of-7 closure
  per the table above), including the realistic 3-turn Tier-1
  cumulative goldens (`TestEngineTier1Baseline_RealisticContinuation_FlipSentinel_3Turns`
  + `TestEngineTier1Baseline_RealisticGrowth_NewTailInvariant_3Turns`)
  that fail loudly under a wrong slice anchor.
- The growth-turn invariant (operator-checked) is byte-identical
  pre vs post.

What is INFERRED, not measured:
- **F1 forecaster EMA-convergence measurement is PENDING.** The
  fix's positive effect on SessionEMA calibration drift is the
  expected consequence of removing false-mispredict samples
  from `UpdateEMA(rec.EstimateScale)` — but the EMA-converges-
  toward-1.0 directional gate (F1) wasn't measured against
  real cache-hit-heavy traffic in this commit.
- The §14.2 forecaster's BreakEvenTurns / EstimatedNetSavingsUSD
  improvement is similarly inferred from the EMA correction;
  `forecast.go` math is untouched (F3 trivially holds) but its
  inputs depend on the live EMA scale.

Phase-4 procedure (operator-driven, post-push): run
`observer cache-health --json` against the soak DB; compare
`BucketMispredicts` against the documented Tier-1 baseline
(1 per `TestEngineMispredictionCountersBaseline_v1`); any
growth-turn-shape regression on real data fires G2 — the §10
rate alone cannot see it.

#### Closure status + remaining P3 work

**4-of-7 closure** on the §14.3 fixture surface — see the
per-fixture table above. The 3 remaining residuals are explicit,
each deferred to a named successor:

- **W H H H+ consecutive Hits** (1 residual: WHH T3, Tier-1).
  V1 closes only the first H after a W. Subsequent consecutive
  Hits mispredict because v1 doesn't refresh the matched entry
  on Hit turns (no entry at end-of-Hit-chain → next turn's
  snapshot lookup misses). Successor: **§15.3 (c)-phase-2
  rolling-entry refresh / walkback window.**
- **Implicit-cache providers** (2 residuals: cline-cli T2 + T3,
  Tier-2). V1 doesn't help: `cache_creation=0` everywhere → no
  entry is ever created → snapshot lookup has nothing to find.
  Successor: **§15.3 (c)-phase-2 ImplicitCache capability flag
  + dedicated §7 attribution rule** that emits Hit (or a new
  ImplicitHit) without requiring a matched entry.
- **Boundary residual** (no count — depends on real-traffic
  byte/token estimate accuracy near the threshold). V1 byte→
  token heuristic. Successor: SessionEMA calibration refines
  the estimate over time; full closure is a separate spec
  refinement, not §15.3 territory.

**§15.3 sibling status (UNTOUCHED P3 — no work in this commit):**

- **§15.3 (a) OpenAI prefix-stability confirmation** — pending.
  Independent verification that OpenAI's implicit prefix-cache
  keys off byte-prefix the way the engine's marker-based
  attribution assumes. Blocks the codex live emitter and the
  ImplicitCache capability flag work. See
  `docs/audits/cachetrack-codex-tier2-audit-2026-06-09.md`
  deferral reason (a).
- **§15.3 (b) Codex live Tier-2 emitter** — pending. Depends on
  (a) + this fix landing + a real codex transcript fixture
  graded the same way as the §14.3 opencode/kilo/cline-cli
  fixture-grading tests.
- **P3 keep-alive advisor** — untouched. No work in this commit.

## §15.3 / P3 follow-up summary

(a) **OpenAI prefix-stability confirmation — LIVE SOAK END-DEFERRED
    (2026-06-10).** §15.3 build landed against documented OpenAI
    assumptions (128-token granule, ~1024 min-cacheable, both API
    shapes covered by proxy parsers). Live soak procedure
    documented in the "Live soak" section above. Closes the
    fixture-side question; live confirmation is the single
    operator-runnable validation item.

(b) **Codex live Tier-2 emitter — LANDED (2026-06-10).** Scaffold
    removed; codex emits `CacheTurnObservation` with
    `ImplicitCache=true` at both `token_count` emission sites
    (modern + legacy). Pinned by
    `TestParse_EmitsImplicitCacheObservations` +
    `TestParse_CacheObservationsIdempotent` +
    `TestParse_CodexCacheObservations_DoNotPolluteAnthropicGate`.
    Empty BlockHashes — the implicit attribution path skips the
    chain. Replaced `TestParse_NoCacheObservations_Scaffolded`.

(c) **Engine `assumedBreakpoints()` lookup fix — phase 2 CLOSED
    (pre-§15.3).** Snapshot-before-push lookup + CacheableTokens-
    gated predictKind + capability-flagged delta-aware
    `estimateNewSuffixTokens`. See the "Tier-2 continuation
    Hit-prediction" section above for the closure footprint
    (4-of-7 of the §14.3 fixture surface), v1 limitations
    (consecutive-Hit, implicit-cache providers, boundary
    residual), and G2/G3 instrumentation surface. Phase-2
    follow-ups (rolling-entry refresh / walkback window for
    consecutive Hits, per-marker multi-entry creation) remain
    open.

(d) **ImplicitCache capability flag — LANDED (2026-06-10).** New
    `Capabilities.ImplicitCache` flag dispatches engine to a
    reduced attribution path (`cachetrack.attributeImplicit`) when
    set at the boundary. Adapters resolve the capability at their
    boundary via `cachetrack.IsImplicitCacheProvider`; the engine
    never sees the provider string. Closes P3 backlog item 3
    (the §14.3 cline-cli implicit-cache deferral); also covers
    OpenAI / codex / OpenAI-routed opencode + kilo + cline-cli.

## Files of record

- `internal/cachetrack/` — pure engine package (block / chain / model
  / tier / attribute / reconcile / breakpoints / engine).
- `internal/store/cachetrack.go` — three row types + persistence
  helpers + the cross-tier dedup gate.
- `internal/store/store.go` — `SetCacheEngine` + Tier-2 wiring in
  `Ingest`.
- `internal/proxy/proxy.go` — Tier-1 wiring; `CacheSink` interface.
- `internal/adapter/claudecode/adapter.go::tier2Accumulator` — the
  C21–C24 template for new Tier-2 emitters.
- `cmd/observer/cache_health.go` — `observer cache-health` CLI.
- `cmd/observer/backfill.go::cacheRescan` — `observer backfill
  --cache-rescan` flag.
- `cmd/observer/proxy.go::buildProxy` — daemon wiring (single engine
  instance fed to both proxy.New and store.SetCacheEngine).
- `internal/db/migrations/036_cache_tracking.sql` — three-table base.
- `internal/db/migrations/037_cache_events_message_id.sql` —
  cross-tier dedup column + index.
- `tests/invariant/privacy_test.go::TestSelectUnpushedSinceExcludesCacheTables`
  - privacy sentinel pinning the cache_* table NAMES out of
  `internal/store/orgpush.go` (a module boundary; see the opening
  section).
- `internal/store/cacheeventorgrows.go` - the ONE seam that reads
  `cache_events` for the org wire. Returns nothing unless the node's
  share posture ships raw content; a 7-day trailing window, capped at
  500 events per session in SQL (`ROW_NUMBER()`, most-recent-first);
  the `detail` column and the node-local anchor ids are never in the
  SELECT list.
- `tests/invariant/privacy_test.go::TestSessionCacheEventsShipOnlyUnderRawContent`
  - the wire-surface pin for that seam (present under
  `full_content` / `admin_managed`, absent otherwise).
