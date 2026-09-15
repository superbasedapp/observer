# Zed test fixtures

`thread.json` is the DECOMPRESSED thread payload (schema `"version":
"0.3.0"`) — an anonymized, structurally faithful derivative of a real Zed
native-agent session captured live 2026-09-06 (model `gpt-5.6-luna`,
provider `zed.dev`). It is stored decompressed, not as a `threads.db`
file, because the on-disk store needs the zstd-compressed blob wrapped in
a SQLite row — `internal/adapter/zed/adapter_test.go`'s `buildTestDB`
helper compresses this JSON at test time and inserts it as one `threads`
row, mirroring how other SQLite-store adapters here build fixtures at
test setup rather than committing a binary `.db`.

Anonymization applied to the real capture: the prompt text is a
paraphrase, the worktree path is the placeholder `/w/project`, the git
`head_sha` is a filler hex string, and tool-output text bodies are
shortened — but every content-block kind (`Text` / `ToolUse` /
`Thinking`), every native tool name, the externally-tagged `messages`
enum shape, the `tool_results` correlation shape, and the token-usage
field NAMES and relative magnitudes (`input_tokens` already net of
`cache_read_input_tokens`) are preserved verbatim from the live capture.

It exercises:

- Two `User` messages and two `Agent` messages.
- All 7 grounded native tool names: `list_directory`, `find_path`,
  `write_file`, `terminal`, `edit_file`, `delete_path`, and a second
  `list_directory` call verifying a deletion.
- A `Thinking` content block (reasoning text threaded onto the next
  actionable row as `PrecedingReasoning`).
- A canceled tool call (`terminal`, `is_error: true`, content
  `"Tool canceled by user"`) alongside successful calls, exercising the
  outcome-correlation path.
- `tool_results.output` in BOTH shapes seen live: a plain string
  (`delete_path`) and a structured object (`write_file`, `edit_file`,
  `find_path`) — the adapter only ever reads the `content` array's Text
  elements, never the `output` field, so both shapes are inert either
  way; the fixture keeps them for documentation fidelity.
- `request_token_usage` entries for both user messages, with
  `input_tokens` values smaller than their paired
  `cache_read_input_tokens` — the same already-net signature the real
  capture showed (`input_tokens: 455` against
  `cache_read_input_tokens: 9728`).
