# Poolside test fixtures

`trajectory-standalone_11111111-2222-7333-8444-555555555555.ndjson` is a
small, hand-built fixture in the exact record shape captured live from a
real Poolside session on 2026-09-05 (JetBrains IDEA 2026.2.2, ACP agent
`acp.registry.poolside`, `pool-acp` 1.0.16, model `poolside/laguna-s-2.1`).

It is NOT a byte-anonymized copy of the live capture — the live session's
`tool_call.inference.start` records each embed the model's full system
prompt (several KB of vendor boilerplate the adapter never reads), so a
faithful-but-small fixture was constructed by hand instead, using a
placeholder username/path and reusing the real, grounded field names and
shapes documented in `internal/adapter/poolside/doc.go`.

It exercises:

  - `session.start` (cwd) → `session.input` (a user prompt) → the full
    thought/assistant-message/tool-call loop for one step, ending in
    `session.exit`.
  - Every native tool name observed live: `read`, `write`, `edit`,
    `shell`, `list_directory_tree`, `todo_action`, and the synthetic
    `exit` completion tool.
  - The two verdict shapes: a `shell` call whose result carries a
    non-zero `exit_code` (failure), and a `list_directory_tree` call
    whose `tool_call.parsed` carries a `validation_error` (the tool was
    never actually run).
  - A `tool_call.approval` with `denied: true` on a second `shell` call
    that never gets a result (the denial itself is the terminal signal).
  - Two `tool_call.inference.end` rows whose input/cache_read values are
    consistent with the GROSS-input netting rule documented in the
    package doc (turn 2's `cache_read_input_tokens` ≈ turn 1's full
    `input_tokens`).

`malformed.ndjson` is a short prefix (session.start + one clean
session.input line) used by the CRLF/partial-line cursor test.
