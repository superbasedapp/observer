# `mcp__observer__get_file` — operator reference

**Available since:** v1.7.8 (first of four V7-12 retrieval-surface MCP tools).

`get_file` lets an AI coding assistant read a file from disk under the
project root, optionally line-sliced, **without going through its shell
tool**. This bypasses `LogsCompressor`'s middle-truncation pass, which
otherwise re-elides content the agent fetched specifically to read.

Pairs naturally with the v1.7.7 elision-marker enrichment (V7-11
mitigation (e)): the marker tells the agent *what* lives in the elided
range; `get_file` fetches the bytes directly.

---

## Quick start

`observer serve` registers `get_file` automatically on upgrade. No
client-side configuration changes needed (codex / Claude Code re-query
`tools/list` on each session start).

To disable:

```toml
[intelligence.mcp.get_file]
enabled = false
```

---

## Full TOML reference

```toml
[intelligence.mcp.get_file]
# Master switch. Default true.
enabled = true

# Allow-list of file extensions (case-insensitive, no leading dot).
# Empty list disables the check.
allow_extensions = [
  "ts", "tsx", "js", "jsx", "mjs", "cjs",
  "py", "rs", "go", "java", "kt", "rb", "php", "swift",
  "c", "cc", "cpp", "h", "hpp", "cs",
  "md", "txt", "json", "toml", "yaml", "yml",
  "html", "css", "scss", "sass",
  "sh", "bash", "ps1", "sql",
]

# Deny-glob list. Matched after symlink expansion. Supports:
#   *           — non-slash chars in a single segment
#   ?           — one non-slash char
#   <dir>/**    — directory-prefix match (recursive)
# Patterns using unsupported syntax (character classes, braces,
# escape sequences) are silently dead; `observer serve` logs one
# warning per such pattern at startup.
deny_paths = [
  ".env*", "*.key", "*.pem", "*.pfx", "*.p12",
  ".git/**", ".hg/**", ".svn/**",
  "node_modules/**", "vendor/**",
  ".ssh/**", ".aws/**", ".gnupg/**",
  ".npmrc", ".pypirc", ".netrc",
]

# Per-call response size cap. Truncated responses carry truncated=true
# so the agent knows to retry with a tighter line range. Default 100 KB.
max_response_kb = 100

[intelligence.mcp.audit]
# When true, every get_file call (success or denial) writes one row
# to mcp_audit. Default true — local-only, high forensic value.
enabled = true
```

---

## Tool schema

```json
{
  "name": "get_file",
  "inputSchema": {
    "type": "object",
    "properties": {
      "project_root": {"type": "string"},
      "path":         {"type": "string"},
      "start_line":   {"type": "integer", "minimum": 1},
      "end_line":     {"type": "integer", "minimum": 1},
      "session_id":   {"type": "string"}
    },
    "required": ["project_root", "path"]
  }
}
```

### Success response

```json
{
  "ok": true,
  "path": "/abs/path/to/src/Editor.tsx",
  "project_relative_path": "src/Editor.tsx",
  "lines": {"start": 100, "end": 280, "total": 431},
  "body": "...",
  "size_bytes": 4823,
  "truncated": false
}
```

`lines.total` is the file's full line count so the agent knows whether
to follow up with a wider window. `truncated: true` means the response
was capped at `max_response_kb` — `lines.end` reports the cap point.

### Denial response

In-band MCP tool error (`isError: true`) with the deny reason in the
message text:

| Deny reason | Defense layer |
|---|---|
| `get_file: path outside project_root` | V7-13 Gap 4 containment (symlink-resolved) |
| `get_file: extension "X" not in allow list` | `allow_extensions` |
| `get_file: path "X" matches deny pattern` | `deny_paths` |
| `get_file: file not found` | `os.Stat` |
| `get_file: not a regular file` | Mode check (dirs, devices, fifos all rejected) |
| `get_file: invalid line range: start_line=N > end_line=M` | Input validation |
| `get_file: start_line=N exceeds file's M lines` | Read-time check |

Every denial writes a `mcp_audit` row with `response_ok=0` and `reason`
populated.

---

## Defense layers (V7-13 Gap 4)

1. **Project-root containment**: paths are joined to `project_root`,
   `filepath.Abs`'d, then `filepath.EvalSymlinks`'d. The resolved path
   must share the resolved project root as a prefix. Symlink-escape
   attempts (a symlink under the project tree pointing outside) are
   denied because containment is checked **after** symlink expansion.

2. **Allow-extension allow-list**: configurable. Files with no
   extension are denied unless the allow list is empty. Match is
   case-insensitive.

3. **Deny-glob list**: configurable. Matched against both the
   project-relative path AND the basename, first match wins. Supported
   syntax: `*`, `?`, `<dir>/**`.

4. **Response-size cap**: `max_response_kb`. Default 100 KB (~4k
   tokens). Larger files truncate cleanly at a line boundary.

5. **Per-call audit**: every call (success or denial) writes to
   `mcp_audit`.

### What we DON'T defend against (accepted risks)

- **TOCTOU race** between symlink resolution and `os.Open`. The MCP
  server runs in the same trust domain as the agent — an attacker
  with symlink-swap capability has equivalent access via the shell
  tool. Documented in
  [`docs/v4-codex-compression-recipe-and-issues.md`](v4-codex-compression-recipe-and-issues.md)
  V7-13 Gap 4.
- **Symlinks under the project tree pointing to other in-tree
  locations** — these are allowed (legitimate TS path mapping,
  monorepo symlinks). `O_NOFOLLOW` would break these.
- **Content-scanning for secrets**. The scrub package handles secret
  scrubbing at ingestion; we don't re-scan on read.

---

## Audit log (`mcp_audit` table)

Schema (migration 030):

```sql
CREATE TABLE mcp_audit (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT    NOT NULL,            -- RFC3339Nano UTC
    session_id          TEXT,
    tool_name           TEXT    NOT NULL,            -- 'get_file' today
    request_hash        TEXT    NOT NULL,            -- sha256(tool:args)
    path_requested      TEXT,
    response_size_bytes INTEGER NOT NULL,
    response_truncated  INTEGER NOT NULL,            -- 0|1
    response_ok         INTEGER NOT NULL,            -- 0|1
    reason              TEXT,
    duration_us         INTEGER NOT NULL
);
```

### Useful queries

```sql
-- Last 24 hours of denials
SELECT ts, session_id, path_requested, reason
FROM mcp_audit
WHERE response_ok = 0
  AND ts > datetime('now', '-1 day')
ORDER BY ts DESC;

-- Top paths over the last day
SELECT path_requested,
       COUNT(*) AS calls,
       SUM(response_size_bytes) AS total_bytes
FROM mcp_audit
WHERE response_ok = 1
  AND ts > datetime('now', '-1 day')
GROUP BY path_requested
ORDER BY calls DESC
LIMIT 25;

-- Per-tool roll-up (will become more interesting once get_symbols,
-- get_relations, retrieve_stashed_batch land in follow-up PRs).
SELECT tool_name,
       COUNT(*)                            AS calls,
       SUM(response_ok)                    AS ok_calls,
       COUNT(*) - SUM(response_ok)         AS denied_calls,
       AVG(duration_us)                    AS avg_us
FROM mcp_audit
WHERE ts > datetime('now', '-7 days')
GROUP BY tool_name;

-- "Why is the agent re-issuing the same query?"
SELECT request_hash, COUNT(*) AS times,
       MAX(path_requested) AS path
FROM mcp_audit
WHERE ts > datetime('now', '-1 day')
GROUP BY request_hash
HAVING times > 5
ORDER BY times DESC;
```

### Retention

The audit table grows unbounded today. At realistic MCP rates
(~1k calls/day per heavy user, ~365k rows/year) SQLite handles this
comfortably, but operators with privacy hygiene requirements can prune
manually:

```sql
DELETE FROM mcp_audit WHERE ts < datetime('now', '-30 days');
```

A managed `observer mcp-audit purge --older-than 30d` CLI is the
v1.8.x follow-up.

---

## How the agent discovers `get_file`

Codex / Claude Code re-query `tools/list` from observer's MCP server at
each session start. Operator changes (enable/disable, tweak
`allow_extensions`, etc.) take effect on the **next** session — no
restart needed for the AI tool, but observer's `serve` process must
restart to pick up TOML changes.

Verify the tool is registered:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  observer serve --config ~/.observer/config.toml | \
  jq '.result.tools[].name'
```

---

## Operator-transparency contract

- At most **one stderr line per startup** per silently-dead deny
  pattern.
- At most **one stderr line per startup** when `audit.enabled = false`
  (just confirms the operator's choice).
- **Zero per-call log spam.** Every call's record lives in `mcp_audit`,
  not stderr.

---

## Cross-references

- [`docs/mcp-get-symbols-reference.md`](mcp-get-symbols-reference.md) —
  the v1.7.9 symbol-level retrieval tool. `get_symbols` is usually
  cheaper than `get_file` when the agent knows the symbol name; fall
  back to `get_file` when the code index is unavailable / stale or when
  byte-level granularity is needed.
- [`docs/mcp-get-relations-reference.md`](mcp-get-relations-reference.md) —
  the v1.7.10 graph-traversal tool. Use for impact analysis and
  reachability questions; returns metadata only (call `get_file` or
  `get_symbols` for bodies).
- [`docs/codex-compression-recipe.md`](codex-compression-recipe.md) —
  pairs the v1.7.7 marker enrichment with v1.7.8 + v1.7.9 retrieval.
  Recommends enabling both for codex-variant models where
  re-derivation cost is highest.
- [`docs/v4-codex-compression-recipe-and-issues.md`](v4-codex-compression-recipe-and-issues.md)
  — V7-12 / V7-13 / V7-14 design source-of-truth.
- [`docs/plans/v1.7.8-mcp-get-file-plan-2026-05-30.md`](plans/v1.7.8-mcp-get-file-plan-2026-05-30.md)
  — implementation plan (untracked, persistent operator doc).
