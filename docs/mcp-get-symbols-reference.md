# `mcp__observer__get_symbols` — operator reference

**Available since:** v1.7.9 (second of four V7-12 retrieval-surface MCP tools).

`get_symbols` lets an AI coding assistant ask "give me the body of
`handleClick` in `src/components/Editor.tsx`" — batched, one MCP turn
returns N symbols across M files. Bypasses codex's shell tool so the
response isn't re-fed to `LogsCompressor`.

Pairs with v1.7.7 marker enrichment + v1.7.8 `get_file`:

- Marker says *"contains fn handleClick (140), class Editor (220)"*
- Agent calls `get_symbols([{file, name: "handleClick"}, {file, name: "Editor"}])`
- One turn returns both bodies. No re-derivation cascade.

---

## Quick start

`observer serve` registers `get_symbols` automatically on upgrade as long
as `[intelligence.mcp.get_symbols].enabled` is true (default). The tool
remains registered even when the code index is missing — calls
then return `degraded: true` per-request and the agent falls back to
`get_file` for the bytes.

To disable entirely:

```toml
[intelligence.mcp.get_symbols]
enabled = false
```

---

## Prerequisites

- **The project is indexed** by the in-process code index
  (`internal/codeintel`; `[codeintel].enabled`, default on). `observer
  start` indexes projects when `[codeintel.index].on_start` is set;
  `observer index <path>` indexes one on demand. Without an index,
  `get_symbols` reports `degraded: true` per-request.
- **Path-safety knobs** come from `[intelligence.mcp.get_file]` — the
  same `allow_extensions` and `deny_paths` apply. One place to keep in
  sync.

---

## Full TOML reference

```toml
[intelligence.mcp.get_symbols]
# Master switch. Default true.
enabled = true

# Per-symbol callers list cap when include_relations: true is set.
# Default 20 (matches V7-12 design). The accompanying callers_count
# field reports the unlimited total.
max_callers = 20

# Per-symbol callees list cap. Default 20.
max_callees = 20

# (Path-safety knobs live on [intelligence.mcp.get_file]; same
#  allow_extensions / deny_paths apply to both tools.)
```

---

## Tool schema

```json
{
  "name": "get_symbols",
  "inputSchema": {
    "type": "object",
    "properties": {
      "project_root": {"type": "string"},
      "session_id":   {"type": "string"},
      "requests": {
        "type": "array",
        "minItems": 1,
        "maxItems": 25,
        "items": {
          "type": "object",
          "properties": {
            "file":              {"type": "string"},
            "name":              {"type": "string"},
            "fqn":               {"type": "string"},
            "kind":              {"type": "string"},
            "include_relations": {"type": "boolean"},
            "include_body":      {"type": "boolean"}
          },
          "required": ["file"]
        }
      }
    },
    "required": ["project_root", "requests"]
  }
}
```

### Request modes

| Combination | Behaviour |
|---|---|
| `{file, name}` | Named lookup. May return 0..N matches. |
| `{file, fqn}` | Exact-fqn lookup. At most 1 match in well-formed code. |
| `{file, name, kind}` | Named + kind filter (e.g. only methods). |
| `{file}` only | **Discovery mode** — returns every user-facing symbol in the file (functions, methods, classes, interfaces, types), **without** body. Cheap preview; agent picks bodies to fetch in a follow-up call. |
| `{file, ..., include_relations: true}` | Adds `callers_count`, `callees_count`, top-N `callers`/`callees` lists. Default off (opt-in). |
| `{file, ..., include_body: false}` | Forces body omission even when `name`/`fqn` is set. |

### Response shape (success)

```json
{
  "ok": true,
  "results": [
    {
      "request": {"file": "src/Editor.tsx", "name": "handleClick"},
      "ok":      true,
      "matches": [
        {
          "name": "handleClick",
          "fqn":  "handleClick",
          "kind": "function",
          "file": "/abs/path/src/Editor.tsx",
          "project_relative_path": "src/Editor.tsx",
          "language": "typescript",
          "start_line": 50,
          "end_line":   88,
          "body": "function handleClick(e) {\n  ...\n}\n",
          "callers_count": 4,
          "callees_count": 7,
          "callers": [
            {"name": "render", "fqn": "Editor.render", "kind": "method", "file": "/abs/.../Editor.tsx", "start_line": 220}
          ],
          "callees": [...]
        },
        {
          "name": "handleClick",
          "fqn":  "Editor.handleClick",
          "kind": "method",
          ...
        }
      ],
      "ambiguous": true,
      "disambiguation_hint": "Use fqn (e.g. \"handleClick\") to select a specific match."
    }
  ]
}
```

### Per-result denial

Path-safety failures land per-result. Top-level `ok` stays `true`:

```json
{
  "request": {"file": "../../etc/passwd", "name": "x"},
  "ok":      false,
  "matches": [],
  "reason":  "get_symbols: path outside project_root"
}
```

### Per-result degradation

When the code index is unavailable OR stale for that file:

```json
{
  "request": {"file": "src/Editor.tsx", "name": "handleClick"},
  "ok":      true,
  "matches": [],
  "degraded": true,
  "reason":  "code index stale relative to file; fall back to get_file"
}
```

Top-level `degraded: true` is set when the code index is unavailable for
the whole call.

---

## V7-15 ranking — how ambiguity is resolved

When the request doesn't pin an `fqn`, multiple symbols may match.
The `matches[]` array is sorted by:

1. **Exact `fqn`** filter — applied at SQL time. If the request
   supplied `fqn`, only the exact match comes back.
2. **`kind`** filter — applied at SQL time.
3. **`start_line` ASC** — earlier definitions first (typically the
   header/primary form).
4. **`fqn` ASC** — alphabetical.
5. **`file` ASC** — paths sorted.
6. **`id` ASC** — terminal tiebreaker, deterministic via the index's
   primary key.

`ambiguous: true` fires when `len(matches) > 1` AND the request didn't
pin `fqn`. `disambiguation_hint` carries a literal-recipe form
(`Use fqn (e.g. "Editor.handleClick") to select a specific match.`) so
the agent can pattern-match and copy the structure.

### Deviation from V7-15 spec — `is_exported` factor

The V7-15 design spec'd an `is_exported` ranking factor (exported
symbols rank above non-exported). The code-index schema doesn't carry
that column today, so this factor is **deferred**. Practical impact:
when two symbols share a name (one exported, one not), they sort by
`start_line` instead. The agent still gets both bodies, `ambiguous`
still fires, the hint still works — so the deviation only affects
*which match appears first*, not the agent's ability to resolve the
ambiguity. Documented; planned for a future code-index schema
bump.

---

## Body size cap (200 KB per batch)

The total body bytes across all matches in one response is capped at
**200 KB**. Algorithm:

1. Results are processed in input order (deterministic for prefix-cache
   stability).
2. Bodies are appended until the running total exceeds 200 KB.
3. After the cap, subsequent matches **omit body** and carry
   `body_truncated: true` — metadata is still returned.
4. Top-level `truncated: true` fires when any match was truncated.

Batching recommendation: aim for batches under 5-10 mid-sized symbols
to stay clear of the cap. The 25-request `maxItems` is mostly for
discovery-mode calls (which omit body).

---

## Audit log

Every per-request entry writes one row to `mcp_audit` (same table as
`get_file`, see [`docs/mcp-get-file-reference.md`](mcp-get-file-reference.md)).

```sql
-- Last day of get_symbols calls
SELECT ts, session_id, path_requested,
       response_size_bytes, response_ok, reason
FROM mcp_audit
WHERE tool_name = 'get_symbols'
  AND ts > datetime('now', '-1 day')
ORDER BY ts DESC;

-- Discovery vs named calls
SELECT
  CASE WHEN response_size_bytes = 0 THEN 'discovery_or_empty' ELSE 'with_body' END AS shape,
  COUNT(*) AS calls
FROM mcp_audit
WHERE tool_name = 'get_symbols'
  AND ts > datetime('now', '-1 day')
GROUP BY shape;

-- "Why was this request denied?"
SELECT path_requested, reason, COUNT(*) AS times
FROM mcp_audit
WHERE tool_name = 'get_symbols'
  AND response_ok = 0
  AND ts > datetime('now', '-7 days')
GROUP BY path_requested, reason
ORDER BY times DESC;
```

---

## Common flows

### Flow A: verify after marker

Marker says *"contains fn handleClick (140), class Editor (220)"*:

```json
{
  "name": "get_symbols",
  "arguments": {
    "project_root": "/path/to/proj",
    "requests": [
      {"file": "src/Editor.tsx", "name": "handleClick", "include_relations": true}
    ]
  }
}
```

One turn returns body + `"called by 4 places, calls 7 things, 0 errors"`
context. Replaces 2-5 codex shell re-runs with one targeted MCP call.

### Flow B: cross-file batch verify

Agent suspects a refactor changed three related methods:

```json
{
  "name": "get_symbols",
  "arguments": {
    "project_root": "/path/to/proj",
    "requests": [
      {"file": "src/Editor.tsx", "name": "handleClick"},
      {"file": "src/Toolbar.tsx", "name": "onSave"},
      {"file": "src/api/client.ts", "fqn": "ApiClient.send"}
    ]
  }
}
```

One MCP roundtrip; three bodies + metadata. Cost model favors fewer
turns on codex; batching is a load-bearing optimization.

### Flow C: discovery before fetch

Agent doesn't know what's in the file yet:

```json
{
  "name": "get_symbols",
  "arguments": {
    "project_root": "/path/to/proj",
    "requests": [{"file": "src/Editor.tsx"}]
  }
}
```

Returns the symbol list (no bodies). Agent picks 2-3 to fetch in a
second batched call.

---

## Operator-transparency contract

- **Zero per-call log spam.** Every call writes one `mcp_audit` row per
  request; stderr stays clean.
- **No startup failure mode** — the code index is in-process; an
  unindexed project degrades per-request.
- **Per-request `degraded: true`** instead of silent zeros when the
  index is stale; agent sees a recovery suggestion.

---

## See also

- [`docs/mcp-get-file-reference.md`](mcp-get-file-reference.md) — the
  v1.7.8 retrieval tool; pairs with `get_symbols` for byte-level
  follow-ups when symbols aren't enough.
- [`docs/mcp-get-relations-reference.md`](mcp-get-relations-reference.md) —
  the v1.7.10 graph-traversal tool. Use for impact analysis
  ("if I change X, what breaks?") and reachability without bodies.
  Cheaper than `get_symbols(include_relations: true)` when you
  want multi-hop traversal.
- [`docs/codex-compression-recipe.md`](codex-compression-recipe.md) —
  recommends enabling `get_symbols` for codex-variant model operators
  where re-derivation cost is highest.
- [`docs/v4-codex-compression-recipe-and-issues.md`](v4-codex-compression-recipe-and-issues.md) —
  V7-12 + V7-15 design source-of-truth.
- [`docs/plans/v1.7.9-mcp-get-symbols-plan-2026-05-30.md`](plans/v1.7.9-mcp-get-symbols-plan-2026-05-30.md) —
  implementation plan + open-question answers + out-of-scope items.
