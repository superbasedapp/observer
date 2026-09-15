# mistralcode fixtures

> **Two layouts live here.** Everything at the top level
> (`session_*/`, `growth-snapshots/`) is the **vibe CLI** layout,
> hand-built from shapes confirmed against a real install. The
> `ide/` subtree is the **Mistral Code IDE (Continue-fork) layout**
> and is **FULLY SYNTHETIC** — see
> ["ide/ — synthetic Continue-fork fixtures"](#ide--synthetic-continue-fork-fixtures)
> at the bottom of this file before trusting anything in it.

Captured/derived: 2026-08-24, against a real Mistral Code (`vibe` 2.24.0)
install on this machine (WSL2, `~/.vibe/logs/session/`). One genuine live
session was inspected read-only (never committed) to confirm shapes, key
names, and the gross-vs-net token arithmetic; every fixture below is then
**hand-built from that confirmed shape**, not a raw copy — all prompts,
paths, session ids, git refs, and numeric values are synthetic. No real
API keys, file paths, prompt text, or account-identifying strings appear
anywhere in this directory.

Operator: santosh@marmut.app.

## File inventory

| Path | Purpose | Use in tests |
| --- | --- | --- |
| `session_20260815_090512_a1b2c3d4/meta.json` | "Happy path" session metadata: 3 candidate models (`mistral-medium-3.5`, `devstral-small`, `local`) under `config.models`, both `active_model` and `routed_default_model` empty, real-shaped `stats` block (steps, tool_calls_*, last_turn_*, and the three `*_price_per_million` fields). | Exercises the price-match model-resolution path: `stats.input_price_per_million`/`output_price_per_million` (1.5/7.5) match only `mistral-medium-3.5`'s own `input_price`/`output_price`, not `devstral-small` or `local` — the adapter must not fall back to a random/first map key. |
| `session_20260815_090512_a1b2c3d4/messages.jsonl` | Full transcript: a `bash` success, a `read_file`, a `bash` failure wrapped as `<tool_error>...</tool_error>`, a `write_file`, an `ask_user_question`, and a `skill` invocation, plus the opening user prompt and closing assistant message. | Exercises every `mapVibeTool` case added in this pass (`ask_user_question` → `ActionAskUser`, `skill` → `ActionSkillInvoke`), the `<tool_error>` failure-detection fix, and content-over-tool_result precedence (tool messages carry both `content` and a structured `tool_result` — the flattened `content` string is what should surface as `ToolOutput`). |
| `session_20260816_140033_partial1/meta.json` | Degraded/partial metadata: no `stats` block and no `config` block at all (as if the session ended before its first turn completed, or `meta.json` was read mid-write). | Missing/partial `meta.json` handling — the adapter must not panic and must emit zero token events (all three stat fields default to 0) while still parsing the transcript's actions normally. |
| `session_20260816_140033_partial1/messages.jsonl` | Minimal 2-line transcript (one user prompt, one assistant reply, no tool calls). | Paired with the degraded meta.json above. |
| `growth-snapshots/t1/session_20260817_101500_deadbeef/{meta.json,messages.jsonl}` | The SAME session (`deadbeef-1111-...`) captured early: 2 transcript lines, modest `stats` totals. | First parse pass in the growth/idempotency test. |
| `growth-snapshots/t2/session_20260817_101500_deadbeef/{meta.json,messages.jsonl}` | The SAME session captured later: the original 2 lines plus 2 more appended (a `write_file` call + result), and `stats` totals increased monotonically (more prompt/completion/cached tokens, higher cost). | Second parse pass: re-parsing from the offset returned by the t1 pass against the t2 files must yield only the 1 NEW tool event (write_file; the appended tool-role line only feeds the result buffer, it is not itself an event) rather than duplicating the first pass's 2 events, and the session-level token event must re-emit with the SAME `SourceEventID` (`tokens:session:deadbeef`) so the store's ON CONFLICT MAX-upgrade can safely replace the smaller t1 totals with the larger t2 totals. |

## What the captured data covers

| Aspect | Covered by a fixture? | Notes |
| --- | --- | --- |
| Session-dir naming / 8-hex session id derivation | Yes | All three session dirs follow the real `session_<YYYYMMDD>_<HHMMSS>_<8hex>` naming; the adapter derives `SessionID` from the trailing 8-hex suffix, not from `meta.json`'s own (longer, hyphenated) `session_id` field. |
| Gross-vs-net token math | Yes | `session_20260815.../meta.json`: 52340 gross − 41200 cached = 11140 net input (verified against the real machine's session, whose real numbers were 146062 − 115072 = 30990 — the same subtraction, different magnitudes). |
| Model resolution: direct `active_model` match | No | Not exercised by these fixtures (the one real session captured had `active_model` empty in both cases seen). Existing inline-literal tests in `adapter_test.go` may add this case separately. |
| Model resolution: `routed_default_model` fallback | No | Same as above — not present in the one real session captured. |
| Model resolution: price-match against `config.models` | Yes | `session_20260815.../meta.json`'s 3-candidate `models` map. |
| Model resolution: sorted-first-key fallback (no price signal) | Partial | `partial1`'s empty `config` exercises the "nothing to resolve" edge (empty map); the "multiple models, no price data" case is covered by an inline-literal table test (`TestModelName_SortedFallbackNoPriceSignal` in `internal/adapter/mistralcode/fixtures_test.go`), not a fixture file. |
| `<tool_error>`-wrapped tool failures | Yes | `session_20260815.../messages.jsonl`'s `python hello_world.py` call. |
| `content` vs `tool_result` precedence | Yes | Every `role":"tool"` line in `session_20260815...` carries both fields. |
| `ask_user_question` / `skill` tool mapping | Yes | `session_20260815.../messages.jsonl`. |
| Missing/partial `meta.json` | Yes | `partial1`. |
| Cursor/offset idempotency across a growing transcript | Yes | `growth-snapshots/t1` → `t2`. |
| `VIBE_HOME` root override | No | Environment-variable behavior; covered by an inline unit test (`TestDefaultRoots_VibeHomeOverride` in `internal/adapter/mistralcode/fixtures_test.go`), not a fixture (there is nothing file-shaped to fixture). |

## Reproducing the dumps

There is no live dump to reproduce here — unlike some other adapters'
fixtures, nothing in this directory was copied byte-for-byte from a real
`~/.vibe` install. The shapes were confirmed once, read-only, against a
real session on this machine (`vibe --version` → `vibe 2.24.0`) and then
hand-authored as synthetic fixtures. To re-confirm the real shape
yourself: run a `vibe` session, then inspect
`~/.vibe/logs/session/<session_dir>/{meta.json,messages.jsonl}` (or set
`MISTRALCODE_LIVE_ROOT=$HOME/.vibe/logs/session` and run
`go test ./internal/adapter/mistralcode/... -run TestLiveVerify_RealStore -v`,
which walks a real store read-only and logs parsed sessions/models/tokens
without ever touching `testdata/`).

## `ide/` — synthetic Continue-fork fixtures

Added: 2026-09-02, for the Mistral Code **IDE** layout (audit finding
IDE-09; `docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md`
ticket F). Operator reference:
[`docs/mistral-code-adapter.md`](../../docs/mistral-code-adapter.md)
§"Mistral Code IDE layout (Continue fork)".

**These fixtures are SYNTHETIC — no live store was ever observed.**
The IDE store (`$MISTRALCODE_GLOBAL_DIR ?? ~/.mistralcode/sessions/`) is
written by the VS Code extension `mistralai.mistral-code` and the
JetBrains "Mistral Code Enterprise" plugin, both of which are
login-gated and were **not installed / not reachable** on the machine
this layout was written on. The shape below is Continue's own `Session`
type (`continuedev/continue`, `core/index.d.ts` — the upstream both
plugins fork), cross-read against the Mistral Code extension bundle.
Field names, nesting and the `usage` sub-objects come from that schema;
every value — session ids, prompts, paths, tool arguments, token counts
— is invented.

| Path | Purpose | Use in tests |
| --- | --- | --- |
| `ide/sessions/sessions.json` | The session INDEX: two entries, one with an epoch-ms NUMBER `dateCreated`, one with an ISO-8601 STRING, so both index-timestamp spellings are exercised. | `ideIndexDate` / `parseFlexTime`; the document carries no timestamps, so entry 0's timestamp comes from here. |
| `ide/sessions/11111111-2222-4333-8444-555555555555.json` | A 6-entry `history[]`: user prompt → assistant with 2 tool calls + full `usage` (cached + cacheWrite + reasoning) → two `role:"tool"` results (one clean, one `Error: …`) → assistant with 4 tool calls and NO prose (edit / terminal / an `mcp__*` call / an unmapped name) + a bare `usage` → closing assistant prose whose `usage` is cache-read-only and whose entry has NO `promptLogs`. | Every row of the IDE mapping table: the `ideToolActions` lookup, the MCP-name fallthrough, `unknown` for an unlisted name, target extraction from `filepath`/`query`/`command`/`name`, tool-role outcome folding + `Error:` failure detection, the assistant-with-empty-content case minting no `assistant_message`, gross→net input math, and the `promptLogs[0].modelTitle` → `chatModelTitle` model ladder. |

### Replacing these with real-shape fixtures

Follow the operator checklist in
[`docs/mistral-code-adapter.md`](../../docs/mistral-code-adapter.md)
§"Operator checklist — confirming the IDE layout on a real install".
When a real store is finally captured, anonymize it, replace the two
files above, and **update this section's "SYNTHETIC" labelling** —
leaving it stale would be the exact honesty failure the label exists
to prevent.
