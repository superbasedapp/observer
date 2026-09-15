# testdata/taskflow — task-tracking decoder fixtures

Minimal, synthetic-but-shape-accurate excerpts for
`internal/taskflow`'s decoder table (docs/task-tracking.md,
docs/audits/task-tracking-capture-audit-2026-09-07.md). Each `.jsonl`
line is one decoded call: `{tool, raw_tool_name, raw_tool_input,
raw_tool_output}` — the exact shape `internal/taskflow.ActionInput`
expects (minus session/action/timestamp bookkeeping, which
`decoder_fixtures_test.go` fills in per-line).

**Provenance.** These are NOT raw pulls from the operator's live
`~/.claude/projects/` transcripts or `~/.observer/observer.db`. They
are hand-constructed to match the exact field names, container keys,
and status vocabularies the audit measured live (§R2.2's decoder
table), using generic placeholder task content ("Fix the login
redirect bug", "Draft the migration script", …) instead of the
operator's actual project history. This trades a live-pull's
"observed in the wild" provenance for a privacy guarantee that needs
no scrubbing pass and no per-line review: nothing here ever touched a
real path, username, or project detail.

| File | Tool | Shapes covered |
|---|---|---|
| `claudecode.jsonl` | claude-code | `TaskCreate` (output-text id recovery), `TaskUpdate` (status change, owner field, content-only edit, failed update), `TodoWrite` (whole-list snapshot), `post_tool_batch` (mixed Task + non-task envelope) |
| `codex.jsonl` | codex | `update_plan` plain JSON (`plan` key and the fixture-only `steps` key), and the Unified Exec JS-source encoding |
| `opencode.jsonl` | opencode | `todowrite` whole-list snapshot, two consecutive calls (exercises content-hash re-matching on an unchanged item) |
| `gemini-cli.jsonl` | gemini-cli | `write_todos` — **vendor-schema-derived, not locally observed** (§2.6: the tool's local surface was cold on the grounding box, 0 live rows anywhere). Exercises all three non-3-value statuses (`in_progress`/`pending`/`blocked`) |
| `kirocli.jsonl` | kiro-cli | `todo_list` `create` (0-based index keys) then `complete` (1-based `completed_task_ids` values — exercises the off-by-one adjustment, §R2.6 item 8) |
| `droid.jsonl` | droid | `TodoWrite` JSON-array path (identical shape to claude-code's legacy TodoWrite) AND the markdown-string `emitTodo` fallback (§2.10 — not observed live, code path exists) |
| `poolside.jsonl` | poolside | `todo_action` flat content-addressed Delta — multi-line `add` (one item per line) then `set_in_progress`/`complete` against the same content key |
| `copilot.jsonl` | copilot (VS Code core) | `manage_todo_list` — the rare KEYED snapshot (real per-item `id`, hyphenated/`done` status dialect) |
| `cline-task_progress.md` | cline | Reference only — the `task_progress` PARAMETER shape, which `internal/taskflow` deliberately does not decode (a third capture-shape class the (tool, raw_tool_name) table cannot represent; see docs/task-tracking.md). Not consumed by any test. |

## Privacy grep proof

Every `.jsonl`/`.md` file in this directory was grepped clean of the
project's own identifying strings before commit. The `sk-` pattern
(meant to catch an OpenAI/Anthropic-style secret) ALSO matches the
literal substring "task-tracking" (`ta[sk-]tracking`) — a false
positive from this very directory's own name, not a leaked secret.
Excluding this README (whose own prose names the doc/directory) and
that one expected hit, the fixture payloads are clean:

```
$ grep -riE 'marmu|LOGONSERVER|COMPUTERNAME|sk-|ghp_|AKIA' testdata/taskflow/* | grep -v README.md
testdata/taskflow/cline-task_progress.md:docs/task-tracking.md "Deferred: cline's task_progress parameter").
```

That one hit is the same "task-tracking" false positive, in a
reference-only doc-pointer comment, not fixture payload content — no
real secret pattern appears anywhere in this directory.

## Use in tests

`internal/taskflow/decoder_fixtures_test.go` reads every `.jsonl` file
here and asserts `Decode` produces the expected event count per line
(0 for the deliberately-failed TaskUpdate and the non-task envelope
element; ≥1 otherwise).
