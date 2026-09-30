# `mcp__observer__retrieve_stashed` — operator reference

**Available since:** v1.4.41 (single-sha legacy form);
extended in **v1.7.11** to batch + line-range slicing (fourth and
final V7-12 retrieval-surface MCP tool).

`retrieve_stashed` returns the original bytes of a tool_result body
that the proxy stashed during compression. The marker that replaces
the inline body looks like
`[output 47KB stashed at observer://stash/<sha>; use retrieve_stashed]`
— the agent pulls the sha out of the marker and calls this tool to
recover the content without re-running the producing tool.

v1.7.11 closes the V7-12 retrieval arc by making the tool batched
(array of shas in one call → one MCP turn) and slice-aware
(`start_line` / `end_line` to pull just the section the agent needs).
The single-sha-no-range call shape is **byte-identical** to v1.7.10
— pre-extension callers see zero observable change (V7-16 BC contract).

Pairs with the other three V7-12 tools:

- **`get_file`** when you need bytes by disk path (file still exists)
- **`get_symbols`** when you need bodies + relations metadata
- **`get_relations`** when you only need the dependency edges
- **`retrieve_stashed`** when the bytes only live in the proxy's
  content-addressed blob store (compressed-out shell stdout, browser
  output, network response — anything not still on disk)

---

## Quick start

`observer serve` registers `retrieve_stashed` automatically when:

1. `[compression.conversation.stash].enabled = true` (proxy-side stash
   is configured), AND
2. `[intelligence.mcp.retrieve_stashed].enabled = true` (default).

To turn the tool off while keeping proxy-side stash compression
active (e.g. asymmetric trust scenarios — the proxy may write the
stash but the agent shouldn't be able to read from it):

```toml
[intelligence.mcp.retrieve_stashed]
enabled = false
```

The proxy keeps compressing oversized bodies into stash blobs; the
marker still tells the agent the body was stashed; but the agent
gets a clean "tool not registered" error instead of being able to
retrieve.

---

## Full TOML reference

```toml
[intelligence.mcp.retrieve_stashed]
# Master switch. Default true.
enabled = true

# Cap on the number of shas in one array-form call. Default 25
# (matches get_symbols's per-call batch cap). Set higher only if
# your agent reliably emits larger batches AND your audit budget
# can absorb the per-sha row volume — N shas == N audit rows.
max_shas_per_call = 25

# (V7-8 alignment — operator hygiene rather than a TOML knob.
#  The proxy that wrote a sha and the MCP server that reads it must
#  share the same [compression.conversation.stash].Dir. If you run
#  multiple observer processes with different --config files,
#  verify by comparing both startup logs for the
#  "mcp: stash dir active" line.)
```

---

## Tool schema

```json
{
  "name": "retrieve_stashed",
  "inputSchema": {
    "type": "object",
    "properties": {
      "sha": {
        "oneOf": [
          {"type": "string"},
          {"type": "array", "items": {"type": "string"},
           "minItems": 1, "maxItems": 25}
        ]
      },
      "start_line": {"type": "integer", "minimum": 1},
      "end_line":   {"type": "integer", "minimum": 1},
      "max_bytes":  {"type": "integer"},
      "session_id": {"type": "string"}
    },
    "required": ["sha"]
  }
}
```

### Three response branches (V7-16 BC contract)

The response shape is determined purely by the **input shape**, never
by length-dependent branches inside the tool. This keeps OpenAI's
prefix cache stable and lets the agent emit a single parsing path
for each branch.

**Branch A — single-string sha, no range params.**
v1.7.10 byte-identical legacy shape:

```json
{
  "sha":        "abc123…",
  "size_bytes": 4096,
  "content":   "the full stashed body"
}
```

With `max_bytes` clipping: an extra `"truncated": true` flag (plus
`size_bytes` reporting the original blob's size, NOT the clipped
length — so the agent can see "I asked for 4 KB, blob is 47 KB").

**Branch B — single-string sha + at least one range param.**
Same shape as Branch A, augmented with line-bookkeeping fields:

```json
{
  "sha":        "abc123…",
  "size_bytes": 920,
  "content":   "L100\nL101\n…L250\n",
  "returned":  {"start": 100, "end": 250, "total": 431},
  "total_lines_in_blob": 431
}
```

Extra fields don't break callers reading only the v1.7.10 keys.
Setting both `start_line = 0` and `end_line = 0` is treated as "no
range" and triggers Branch A.

**Branch C — array sha (any length, including one).**
Switches to the `{ok, responses: [...]}` envelope. **Array-of-one
ALWAYS returns this shape**, never Branch A — an array literal is
explicit caller intent to use the new wire (per D-2 in the
v1.7.11 plan doc).

```json
{
  "ok": true,
  "responses": [
    {"sha": "a…", "ok": true,  "size_bytes": 4096, "content": "…"},
    {"sha": "b…", "ok": false, "reason": "sha_not_found: b… (may have been GCed; re-run the producing tool to regenerate)"},
    {"sha": "c…", "ok": true,  "size_bytes": 920,  "content": "…",
                  "returned": {"start": 100, "end": 250, "total": 431},
                  "total_lines_in_blob": 431}
  ]
}
```

**Input order is preserved** in `responses`: position N in the
request array ↔ position N in the response. Mixed-success batches
don't poison successful resolutions — bad shas surface as
`ok: false` per row, not as a top-level error.

---

## When to use which branch

| Situation | Best branch |
|---|---|
| Marker says "stashed at <sha>"; you want the full body | A — `sha: "X"` |
| Marker line range "lines 100-331 elided"; you only need lines 200-220 | B — `sha: "X", start_line: 200, end_line: 220` |
| Multi-elision marker references shas a, b, c | C — `sha: ["a","b","c"]` |
| Same elision but you want only a slice from each | C — `sha: ["a","b","c"], start_line: …, end_line: …` (range applies uniformly) |
| You want the legacy v1.7.10 wire (e.g. compatibility-test harness) | A — single-string form, no other params |

---

## Failure modes

Each per-sha failure surfaces as a `reason` string. Two are common
enough to handle explicitly:

| Reason | Meaning | Recovery |
|---|---|---|
| `sha_required` | Empty string or whitespace passed as sha | Trim and retry |
| `sha_not_found: X (may have been GCed; …)` | Sha valid format, no blob on disk | Re-run the producing tool. If this happens repeatedly across sessions, raise `[compression.conversation.stash].max_total_mb` (default 1024) — see [[V7-13 Gap 2]] |
| `sha_corrupt: X (re-run the producing tool)` | Blob exists but content doesn't re-hash to its filename. Usually means an interrupted write or external tampering | Re-run; investigate stash dir if recurring |
| `retrieve_stashed: <other>` | Unexpected I/O error | Operator triage; check disk space + permissions on stash dir |

**Branch A (single string)** surfaces failures as a top-level
JSON-RPC tool error (`isError: true`) so legacy callers using
`try/catch` still work. **Branch C (array)** surfaces failures
per-row in `responses[].ok=false` so a single bad sha doesn't fail
the whole batch.

---

## Audit semantics (V7-14)

When `[intelligence.mcp.audit].enabled = true` (default), every sha
attempt writes one row to `mcp_audit`:

- `tool_name = 'retrieve_stashed'`
- `path_requested = 'stashed://<sha>'`
- `response_ok = 1` for resolved, `0` for failures
- `reason` populated on failure
- `request_hash` covers the full request (including range params),
  so re-issues of the same batch hash identically

For an array-form call with N shas, **N audit rows** land in
`mcp_audit`. This makes operator queries like "which shas does this
session keep re-requesting?" trivial:

```sql
SELECT path_requested, COUNT(*) AS calls
FROM mcp_audit
WHERE tool_name = 'retrieve_stashed'
  AND session_id = '<id>'
GROUP BY path_requested
ORDER BY calls DESC
LIMIT 10;
```

The `stashed://<sha>` encoding lets the same query scan all
retrieve_stashed activity uniformly:

```sql
SELECT path_requested, response_ok, reason, ts
FROM mcp_audit
WHERE path_requested LIKE 'stashed://%'
  AND response_ok = 0
ORDER BY ts DESC;
```

---

## V7-16 feature-flag gating

If `[intelligence.mcp].features` is set, the V7-16 allow-list
filter applies. `retrieve_stashed` survives iff it appears in the
list (and per-tool `enabled` is true):

```toml
[intelligence.mcp]
# Restrict the V7-12 retrieval surface to just two tools.
features = ["get_file", "retrieve_stashed"]
```

Empty / unset `features` = no filter applied (every per-tool-enabled
V7-12 tool registers). The 13 built-in observability tools
(check_*, get_action_details, get_cost_summary, get_failure_context,
get_file_history, get_last_test_result, get_project_patterns,
get_redundancy_report, get_session_recovery_context,
get_session_summary, list_actions_around, search_past_outputs) are
NOT subject to the filter — they always register. See
`docs/plans/v1.7.11-stash-retrieval-correctness-plan-2026-05-31.md` (D-3)
for the scope decision rationale.

**Precedence**: per-tool `[intelligence.mcp.retrieve_stashed].enabled
= false` always wins over the features list. The filter cannot
re-enable a per-tool-disabled tool.

---

## V7-8 stash-dir alignment (operator transparency)

The proxy that **writes** stash blobs and the MCP server that
**reads** them must share the same
`[compression.conversation.stash].Dir`. v1.7.11 logs the active dir
at startup so operators can verify alignment by eyeballing two log
lines:

```
mcp: stash dir active  dir=/home/me/.observer/stash  max_total_mb=1024  note="the proxy that wrote any sha you retrieve must use the same dir; compare against the proxy's startup log"
```

If you run multiple `observer` processes (e.g. proxy from
`~/.observer/config-codex.toml`, MCP server from default
`~/.observer/config.toml`), check both processes' startup logs for
this line and confirm the dir matches. **No automatic cross-process
detection is performed** in v1.7.11 — that's tracked as a future
operator-CLI improvement.

---

## Worked example — multi-elision marker

The proxy emits a marker for a batch site that elided three files:

```
[files compressed in this batch:
   src/components/Editor.tsx   stashed at sha=abc123 (lines 101-331, 4180 bytes)
   src/components/Outline.tsx  stashed at sha=def456 (lines  50-180, 2750 bytes)
   src/components/Status.tsx   stashed at sha=ghi789 (full file, 1240 bytes)
 retrieval: mcp__observer__retrieve_stashed sha=["abc123","def456","ghi789"]
            or sliced: same call with start_line=N end_line=M]
```

The agent makes **one** MCP call:

```json
{
  "name": "retrieve_stashed",
  "arguments": {
    "sha":        ["abc123", "def456", "ghi789"],
    "start_line": 200,
    "end_line":   250
  }
}
```

Response is the Branch-C envelope with one row per sha. Each row
carries its own `returned` + `total_lines_in_blob` so the agent can
see what it actually got per blob:

```json
{
  "ok": true,
  "responses": [
    {"sha": "abc123", "ok": true, "content": "…51 lines from Editor…",
     "returned": {"start": 200, "end": 250, "total": 431},
     "total_lines_in_blob": 431},
    {"sha": "def456", "ok": true, "content": "…",
     "returned": {"start": 200, "end": 180, "total": 180},
     "total_lines_in_blob": 180},
    {"sha": "ghi789", "ok": true, "content": "…",
     "returned": {"start": 0, "end": 0, "total": 47},
     "total_lines_in_blob": 47}
  ]
}
```

Audit-wise: three rows land in `mcp_audit` with
`path_requested = 'stashed://abc123' / 'stashed://def456' /
'stashed://ghi789'`. Operator queries by session or sha work
without any post-processing.

**Cost comparison vs. the alternative:**

- This batched call: 1 MCP turn + 3 audit rows + ~5 KB inbound bytes
  for content.
- Three separate single-sha calls: 3 MCP turns + 3 audit rows +
  3× cache_read tax on the growing conversation + ~5 KB inbound.

For codex-variant models that re-pay cache_read on every turn, the
3× tax is the load-bearing cost. Batching trades many small turns
for one larger turn — the same compression-objective math that
v1.7.9 `get_symbols` already validates.

---

## Backwards-compat contract (V7-16)

The following calls are pinned to v1.7.10's byte-identical output
by `TestRetrieveStashed_BackwardsCompat_*`:

- `{"sha": "X"}` → `{"sha":"X","size_bytes":N,"content":"..."}`
  (no extra keys, key order matches v1.7.10).
- `{"sha": "X", "max_bytes": 30}` → adds only `"truncated": true`;
  no new keys leak in.

**Editing those tests' `want` strings requires a major version
bump.** OpenAI's prefix cache hashes the literal response bytes;
any change breaks cache for pre-extension callers.

---

## Related

- `docs/mcp-get-file-reference.md` — disk-path retrieval (file still
  exists on disk)
- `docs/mcp-get-symbols-reference.md` — symbol-targeted retrieval
  with relations metadata
- `docs/mcp-get-relations-reference.md` — code-index BFS without
  bodies
- `docs/v4-codex-compression-recipe-and-issues.md` — the V7 arc
  compendium (V7-12, V7-13, V7-16 design proposals)
- `docs/plans/v1.7.11-stash-retrieval-correctness-plan-2026-05-31.md` —
  this release's plan doc + decision log
