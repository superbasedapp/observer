# Codex compression recipe

> **Short version:** when observer's proxy sits in front of an OpenAI
> codex session, the default `compress_types = ["json", "logs", "code"]`
> can regress costs sharply — up to +120% on `*-codex` reasoning models.
> v1.7.6 ships three named recipes selectable via
> `observer start --recipe <name>`. Pick the recipe that matches your
> primary model family.

> **v1.7.23 update (2026-06-01):** new baseline measurement on
> `gpt-5.4` (the operator's daily-driver after `gpt-5.3-codex` was
> deprecated) with the `codex-safe` recipe found the proxy is a
> **functional no-op** on apply_patch-heavy workloads — the model's
> tool_results classified as `Code`, not `Logs`, so the recipe's
> `compress_types = ["logs"]` never fired. n=4 OFF + n=3 valid B:
> mean cost $0.786 vs $0.727 (−7.4%, but driven by a single OFF
> outlier; excl outlier: +5.9%). **Inconclusive — within session
> noise.** The V7-21 codex-variant result ($0.270 vs $0.30 = −10%
> on `gpt-5.3-codex`) still holds for operators on the `-codex`
> family. Operators on `gpt-5.4` or other non-`-codex` models should
> A/B their own workload before assuming codex-safe delivers
> measurable savings — the V7-21 result was on a different model
> with a different tool-use pattern. See V7-26 in the V4 compendium
> and `docs/v1.7.23-compression-savings-empirical-2026-06-01.md`
> §"Codex side" for full data + methodology lessons.

---

## Quick start

```bash
# Anthropic Claude (any claude-* / opus / sonnet / haiku model) → claude-code
observer start --recipe claude-code

# Plain OpenAI GPT under the codex CLI (gpt-5.4, gpt-5.4-mini, gpt-5.5, gpt-4o, …) → codex-safe
observer start --recipe codex-safe

# OpenAI's `-codex` reasoning fork (gpt-5.3-codex, gpt-5.4-codex, gpt-5-codex-agent, …) → codex-variant
observer start --recipe codex-variant
```

**Naming note.** Both `codex-variant` and `codex-safe` are recipes for
the codex CLI; the suffix names the *model family*, not a variant of
the codex CLI itself. "variant" = the `-codex` model variant of GPT;
"safe" = safe-to-compress (plain GPT tolerates logs trimming). Pick
by your model identifier, not by your CLI.

The recipe applies as a base layer; your `~/.observer/config.toml`
still wins on every key it sets. Merge order:

```
Default()  →  --recipe overlay  →  ~/.observer/config.toml  →  env vars
```

If you'd rather paste TOML by hand, copies of every recipe live at
`docs/recipes/<name>.toml` in the public repo (or
`internal/config/recipes/<name>.toml` in the source tree). Drop the
contents into `~/.observer/config.toml` and restart observer.

---

## Why three recipes?

OpenAI and Anthropic models react very differently to a "compressed
prior tool_result." The asymmetry is structural:

* **Anthropic API** carries explicit `cache_control:
  {type: "ephemeral"}` markers. Claude is trained to treat content
  behind a cache breakpoint as "established context, do not
  re-derive." A compressed tool_result inside a cached span reads as
  settled.
* **OpenAI Responses API** has no in-band cache marker. Caching is
  automatic prefix-hash matching that the model has no awareness of.
  Codex sees a compressed `function_call_output` body and treats it
  as fresh data with missing values — and reacts by re-running tools.

On top of that, **`*-codex` reasoning models** (gpt-5.3-codex,
gpt-5.4-codex etc.) are more reactive than the standard mini/full
GPT line. They pay closer attention to tool_result content and treat
any post-hoc rewriting — even safe logs dedup — as a signal to
re-verify.

So:

| Model family | Recipe | Compression strategy |
|---|---|---|
| `claude-*`, `claude-opus-*`, `claude-sonnet-*`, `claude-haiku-*` | `claude-code` | full per-type set + cache-aware mode |
| OpenAI mini / full (gpt-5.4-mini, gpt-5.5, gpt-5, ...) | `codex-safe` | logs + tools-defs trim + conservative budget |
| `*-codex` variants (gpt-5.3-codex, gpt-5.4-codex-high, codex-agent, ...) | `codex-variant` | per-type compression disabled |

The proxy emits a one-line warning per session when it sees a model
in the codex-variant family while `compress_types` is non-empty
(V7-2 mitigation). Switching to `--recipe codex-variant` silences it.

---

## Empirical results (v4 batch, 2026-05-29)

Cost delta vs. the Anthropic-style default, single workload per cell:

| Model | Effort | Recipe applied | Δ cost vs. default | Notes |
|---|---|---|---|---|
| gpt-5.4-mini | medium | codex-safe | **−22%** | logs-only is correct |
| gpt-5.4-mini | high | codex-safe | **−56%** | peak effect |
| gpt-5.4-mini | xhigh | codex-safe | −19% | still positive |
| gpt-5.3-codex | medium | codex-safe | +5.6% | ≈ neutral |
| gpt-5.3-codex | high | codex-safe | **+121%** | logs-only HURTS — use `codex-variant` instead |

The `*-codex` regression at high effort is the headline reason
`codex-variant` exists.

---

## What each recipe does (in detail)

### `claude-code`

Formalises observer's shipped defaults with `enabled = true`. Use
this if you're routing Claude Code (or any Anthropic-shape model)
through the proxy:

* `compress_types = ["json", "logs", "code", "tools"]` — every
  content-preserving compressor in the registry, plus the tool-defs
  envelope trim (A2-adopted 2026-06-11).
* `mode = "cache_aware"` — skips drops and narrows per-type
  compression to RoleTool only, so Anthropic's prefix cache holds
  across turns.
* `target_ratio = 0.85`, `preserve_last_n = 5` — the v1.4.40
  conservative budget.

### `codex-safe`

For OpenAI mini/full family on codex CLI:

* `compress_types = ["logs", "tools"]` — JSON sentinel substitution
  destroys data values codex relies on, so JSON compression is off.
  Text head-tail is also off. Code skeleton is debatable on codex; we
  leave it off for safety. The `"tools"` sentinel (A6-adopted
  2026-06-11) trims tool-DEFINITION prose in the envelope — long
  descriptions and JSON-Schema `examples`; names, types,
  required-ness, enums never touched, tool_result bodies never
  touched. Byte-stable across turns, so OpenAI's implicit prompt
  cache keeps hitting.
* `mode = "token"` — OpenAI Responses API has no `cache_control`;
  cache_aware semantics don't apply.
* `target_ratio = 0.95`, `preserve_last_n = 15` — codex re-pays
  cache_read on every dropped-message marker each turn; less
  aggressive budget pays for itself.
* `[compression.indexing] max_excerpt_bytes = 16384` — codex
  re-reads in chunks if the first chunk is too small; one big
  chunk is cheaper.
* Expanded `[compression.shell] exclude_commands` — outputs the
  agent will parse (`rg`, `cat`, `head`, verify scripts) must come
  through verbatim.

### `codex-variant`

For `*-codex` reasoning models, even logs dedup hurts:

* `compress_types = []` — per-type compression disabled. The
  conversation pipeline still runs so the scrubber (secrets
  redaction) is on the wire; the per-type compressors and the
  budget enforcer degenerate to no-ops.
* `[compression.conversation.logs] max_lines = 0` — LogsCompressor
  middle-truncation pass is disabled even in code paths that
  bypass `compress_types`.
* `target_ratio = 0.99`, `preserve_last_n = 50` — preserve nearly
  everything.
* Same shell/indexing trims as `codex-safe` (those don't hurt
  codex-variant models).

---

## Operator overrides

Every key a recipe sets can be overridden in `~/.observer/config.toml`
or via `OBSERVER_*` env vars. Common patterns:

```toml
# Take the codex-safe recipe but raise the budget further.
# Run: observer start --recipe codex-safe
# This config layers on top:
[compression.conversation]
target_ratio    = 0.99   # was 0.95 from recipe
preserve_last_n = 30     # was 15 from recipe
```

```toml
# Take the codex-variant recipe but re-enable logs-only.
# Run: observer start --recipe codex-variant
[compression.conversation]
compress_types = ["logs"]

[compression.conversation.logs]
max_lines = 500   # was 0 from recipe
head      = 250
tail      = 250
```

---

## Troubleshooting

**The codex-variant warning still fires after I switched recipes.**

The warning fires when the proxy sees `compress_types` non-empty
*for the session*. If you've layered a config file that re-adds
`compress_types`, it wins over the recipe. Run
`observer cost --json | head` and confirm the row's session matches
your expectation; `grep "codex-variant model" ~/.observer/proxy.log`
shows the first occurrence with the `compress_types` value the
proxy saw.

**Tokens-saved figures dropped sharply after v1.7.6 on codex sessions.**

This is the V7-6 fix: pre-v1.7.6 the `cost_saved_usd_est` column
multiplied saved tokens by the input tier price. Codex sessions are
cache_read-dominant, where cached input is ~10× cheaper than net
input — so the prior value overstated savings by roughly that
factor. The new column weights by the row's realized input/cache_read
mix. Anthropic sessions are unchanged. Two explicit-tier columns
(`cost_saved_usd_est_input_tier` and
`cost_saved_usd_est_cache_read_tier`) sit alongside for upper/lower
bound visibility.

**I'm using a `-codex-*` model not in the warning regex.**

The regex matches any model where `codex` appears as a dash-
delimited token: `codex-...`, `...-codex`, `...-codex-...`. If your
model name doesn't match (e.g. `gpt-codexspecial` with no dash),
file a small PR adjusting the regex at `internal/proxy/proxy.go`.

---

## Retrieving elided ranges (v1.7.7 + v1.7.8)

The v1.7.7 marker enrichment tells the agent *what* lives in an
elided range: `"… [231 lines elided from src/Editor.tsx; contains
fn handleClick (140), class Editor (220) …]"`. The v1.7.8
[`mcp__observer__get_file`](mcp-get-file-reference.md) tool gives
it a way to fetch the bytes when the summary isn't enough — without
going through codex's shell tool, which would re-feed
`LogsCompressor` and re-truncate.

For codex-variant models specifically (where re-derivation cost is
highest), `get_file` flips the incentive from defensive re-derivation
("let me re-cat the file to be safe") to targeted verification
("read lines 200-280 of src/Editor.tsx"). See
[`docs/mcp-get-file-reference.md`](mcp-get-file-reference.md) for
the full operator surface — config knobs, path-safety defenses, audit
log queries.

**v1.7.9 adds `get_symbols`** — batched symbol-level retrieval (one
MCP turn returns N symbol bodies across M files via the codeintel
index). Pairs with `get_file` for the "tell me what's in
`handleClick` AND give me its callers/callees" verification pattern.
See [`docs/mcp-get-symbols-reference.md`](mcp-get-symbols-reference.md).

**v1.7.10 adds `get_relations`** — code-index BFS traversal. Ask
"what calls X within 2 hops?" and get back the reachability set in
one MCP turn (no recursive grep, no multi-round-trip discovery).
Returns metadata only; use `get_symbols` for bodies. Supports three
kinds: `callers`, `callees`, `contains`. See
[`docs/mcp-get-relations-reference.md`](mcp-get-relations-reference.md).

All three retrieval tools (`get_file`, `get_symbols`, `get_relations`)
are ON by default after upgrading. One more V7-12 tool
(`retrieve_stashed_batch`) ships in a follow-up PR.

---

## See also

* `docs/v4-codex-compression-recipe-and-issues.md` — the source-of-
  truth empirical session this recipe was distilled from (V7-2,
  V7-11, V7-13, V7-12 findings).
* `docs/mcp-get-file-reference.md` — v1.7.8 `get_file` operator
  reference (config, schema, audit-log queries, defense layers).
* `docs/mcp-get-symbols-reference.md` — v1.7.9 `get_symbols`
  operator reference (batched symbol lookup, V7-15 ranking,
  include_relations payload, body-cap behavior).
* `docs/mcp-get-relations-reference.md` — v1.7.10 `get_relations`
  operator reference (code-index BFS, three kinds, ambiguity
  handling, CONTAINS-population caveat).
* `docs/compression-modes.md` — the existing per-mode reference for
  the conversation pipeline.
* `docs/codex-shared-app-server-gotcha.md` — V5-1 / V6-2 / V6-3
  operator-facing guide. Some of those mitigations interact with
  whether the proxy even captures your codex traffic; resolve those
  before reasoning about compression cost.
