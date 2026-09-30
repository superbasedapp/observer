# `mcp__observer__get_relations` — operator reference

**Available since:** v1.7.10 (third of four V7-12 retrieval-surface MCP tools).

`get_relations` does graph traversal over the in-process code index (`internal/codeintel`). The agent asks
*"what calls `handleClick` within 2 hops?"* and gets back the
reachability set — without writing recursive logic, without spawning
shell tools to grep, without multiple round-trips.

Pairs with v1.7.7 marker enrichment + v1.7.8 `get_file` + v1.7.9
`get_symbols`:

- Marker says *"contains fn handleClick (140)"*
- Agent calls `get_symbols` to see the body
- Agent calls `get_relations(name: "handleClick", kind: "callers", depth: 2)` to find what's affected by a refactor
- Each step is one MCP turn; no shell tool involvement

---

## Quick start

`observer serve` registers `get_relations` automatically when
`[intelligence.mcp.get_relations].enabled` is true (default). It stays
registered even when the code index is unavailable — calls then return
`degraded: true` with a recovery hint.

To disable:

```toml
[intelligence.mcp.get_relations]
enabled = false
```

---

## Full TOML reference

```toml
[intelligence.mcp.get_relations]
# Master switch. Default true.
enabled = true

# BFS depth ceiling. Calls supplying a larger `depth` are silently
# clamped to this value. Default 5. Lower on huge codebases where
# a worst-case BFS could otherwise visit thousands of nodes per call.
max_depth = 5

# Per-call cap on reachable nodes. Truncated responses surface
# via top-level truncated: true. Default 100.
max_results = 100

# (Path-safety knobs — allow_extensions, deny_paths — live on
#  [intelligence.mcp.get_file]; same set applies to all three V7-12
#  retrieval tools.)
```

---

## Tool schema

```json
{
  "name": "get_relations",
  "inputSchema": {
    "type": "object",
    "properties": {
      "project_root": {"type": "string"},
      "file":         {"type": "string"},
      "name":         {"type": "string"},
      "fqn":          {"type": "string"},
      "kind":         {"type": "string", "enum": ["callers", "callees", "contains"]},
      "depth":        {"type": "integer", "minimum": 1},
      "session_id":   {"type": "string"}
    },
    "required": ["project_root", "file", "name", "kind"]
  }
}
```

### Kinds

| kind | What it returns | Edge kind | Direction |
|---|---|---|---|
| `callers` | Symbols that CALL the anchor | `CALLS` | anchor = target → walk back to source |
| `callees` | Symbols the anchor CALLS | `CALLS` | anchor = source → walk forward to target |
| `contains` | Symbols the anchor CONTAINS (e.g. module → class → method) | `CONTAINS` | anchor = source → walk forward to target |

### Depth semantics

- **`depth: 1`** (default) — immediate neighbors only.
- **`depth: 2`** — neighbors + their neighbors.
- **`depth: N`** — BFS to N hops, clamped to `max_depth` config.
- The anchor itself is NOT included in `results` (echoed separately
  at the top level).

---

## Response shape — success

```json
{
  "ok": true,
  "anchor": {
    "name": "handleClick",
    "fqn":  "Editor.handleClick",
    "kind": "method",
    "file": "/abs/path/src/Editor.tsx",
    "project_relative_path": "src/Editor.tsx",
    "start_line": 220
  },
  "kind":  "callers",
  "depth": 2,
  "results": [
    {
      "symbol": {
        "name": "render",
        "fqn":  "Editor.render",
        "kind": "method",
        "file": "/abs/path/src/Editor.tsx",
        "project_relative_path": "src/Editor.tsx",
        "start_line": 400,
        "language": "typescript"
      },
      "depth": 1,
      "via_edge": "CALLS"
    },
    {
      "symbol": {"name": "App", "fqn": "App", "kind": "class", "file": "...", "start_line": 12},
      "depth": 2,
      "via_edge": "CALLS"
    }
  ]
}
```

## Response shape — ambiguous anchor

When `(file, name)` matches multiple symbols and no `fqn` is supplied:

```json
{
  "ok":     false,
  "results": [],
  "reason": "get_relations: ambiguous anchor; 2 symbols named \"handleClick\" in src/Editor.tsx — supply fqn to disambiguate",
  "candidates": [
    {"fqn": "handleClick",        "kind": "function", "start_line": 50},
    {"fqn": "Editor.handleClick", "kind": "method",   "start_line": 220}
  ]
}
```

**Why error instead of auto-picking?** Wrong-anchor traversal costs the
agent more tokens than a clean retry with the disambiguated `fqn`.
The `candidates` list is structured so the agent can immediately
extract the correct fqn and re-call.

## Response shape — degraded

When the code index is unavailable, stale, or the requested edge kind
isn't populated:

```json
{
  "ok":       true,
  "anchor":   {...},
  "kind":     "contains",
  "depth":    1,
  "results":  [],
  "degraded": true,
  "reason":   "edge kind 'contains' not populated by the code index for this project; fall back to get_symbols or get_file"
}
```

Reason texts you may see:

- `"code index unavailable; fall back to get_file"`
- `"code index stale relative to file; fall back to get_file"`
- `"edge kind 'contains' not populated by the code index for this project; fall back to get_symbols or get_file"`

The `degraded: true` flag distinguishes "we tried and got nothing"
from "the symbol genuinely has zero relations".

---

## CONTAINS-edge caveat

The code-index schema defines CONTAINS edges (module → class →
method), but not every language backend emits them. The tool detects
this automatically: when a `kind: "contains"` query returns zero
results AND zero CONTAINS edges exist for the project, the response
sets `degraded: true` with the population hint.

This avoids two failure modes:

- Agent doesn't waste turns retrying when CONTAINS will always be empty.
- Operators see a clear signal in the audit log
  (`reason: "edge kind 'contains' not populated..."`) and know the
  project's language backend does not emit CONTAINS edges yet.

Once the index carries CONTAINS edges for the project, the tool starts
returning real results with no other operator action — the
`degraded: true` flag disappears naturally.

---

## Cycle handling + BFS termination

The BFS is implemented as a single SQLite recursive CTE. Termination
is guaranteed by two mechanisms:

1. **Depth bound**: `WHERE r.depth < $max_depth` in the recursive
   step. Once the BFS reaches the depth ceiling, recursion stops.
2. **Visited-tuple dedup**: `UNION` (not `UNION ALL`) on
   `(id, depth, via_edge)`. Re-discovering a node at the same depth
   contributes nothing.

A cycle reachable from the anchor (e.g. A → B → C → A) is collected
to the depth cap but doesn't loop forever. The outer
`GROUP BY n.id MIN(depth)` collapses any remaining duplicates to the
shortest path.

---

## Audit log

Each call writes one `mcp_audit` row (same table as `get_file` /
`get_symbols`, see [`docs/mcp-get-file-reference.md`](mcp-get-file-reference.md)).

```sql
-- Last day of get_relations calls
SELECT ts, session_id, path_requested, response_ok, reason
FROM mcp_audit
WHERE tool_name = 'get_relations'
  AND ts > datetime('now', '-1 day')
ORDER BY ts DESC;

-- How often is contains hitting the upstream-population caveat?
SELECT COUNT(*) AS hits
FROM mcp_audit
WHERE tool_name = 'get_relations'
  AND reason LIKE '%not populated%'
  AND ts > datetime('now', '-7 days');

-- Disambiguation churn — agent calling without fqn first
SELECT path_requested, COUNT(*) AS ambiguous_calls
FROM mcp_audit
WHERE tool_name = 'get_relations'
  AND reason LIKE '%ambiguous anchor%'
  AND ts > datetime('now', '-7 days')
GROUP BY path_requested
ORDER BY ambiguous_calls DESC;
```

---

## Common flows

### Flow A: impact analysis ("if I change X, what breaks?")

```json
{
  "name": "get_relations",
  "arguments": {
    "project_root": "/path/to/proj",
    "file": "src/api/client.ts",
    "name": "send",
    "fqn":  "ApiClient.send",
    "kind": "callers",
    "depth": 2
  }
}
```

One MCP turn returns every caller within 2 hops. Agent decides which
call sites need updates without spawning grep.

### Flow B: reachability ("what does this entrypoint touch?")

```json
{
  "name": "get_relations",
  "arguments": {
    "project_root": "/path/to/proj",
    "file": "cmd/main.go",
    "name": "main",
    "kind": "callees",
    "depth": 3
  }
}
```

The agent gets a flat reachability set ordered by depth, then picks
the unfamiliar ones to fetch via `get_symbols`.

### Flow C: structural orientation

```json
{
  "name": "get_relations",
  "arguments": {
    "project_root": "/path/to/proj",
    "file": "src/Editor.tsx",
    "name": "Editor",
    "kind": "contains"
  }
}
```

Returns the class's methods (when the index carries CONTAINS edges
for the project). Otherwise `degraded: true` with the population
hint — agent can fall back to `get_symbols` discovery mode.

---

## Operator-transparency contract

- **Zero per-call log spam.** Every call writes one `mcp_audit` row;
  stderr stays clean.
- **No startup failure mode.** The code index is in-process; until a
  project is indexed, calls degrade per-request (below).
- **`degraded: true`** instead of silent zeros for every "we know
  this won't work" case (unavailable, stale, edge kind missing).

---

## See also

- [`docs/mcp-get-file-reference.md`](mcp-get-file-reference.md) —
  byte-level file reads; fall back here when the code index is unavailable.
- [`docs/mcp-get-symbols-reference.md`](mcp-get-symbols-reference.md) —
  per-symbol bodies + `include_relations`. Use when you want body
  content alongside callers. `get_relations` is the cheaper, deeper-
  traversal alternative when you only need metadata.
- [`docs/codex-compression-recipe.md`](codex-compression-recipe.md) —
  recommends enabling all three V7-12 tools for codex-variant models.
- [`docs/v4-codex-compression-recipe-and-issues.md`](v4-codex-compression-recipe-and-issues.md) —
  V7-12 design source-of-truth.
- [`docs/plans/v1.7.10-mcp-get-relations-plan-2026-05-31.md`](plans/v1.7.10-mcp-get-relations-plan-2026-05-31.md) —
  implementation plan.
