# testdata/freebuff — Freebuff (CodebuffAI) fixtures

**Captured**: 2026-08 against a live `freebuff` (CodebuffAI, `deepseek/deepseek-v4-flash`,
`agentTemplateId: base2-free-deepseek-flash`) session on WSL2 Ubuntu, in
`~/.config/manicode/projects/<slug>/chats/<RFC3339-dir>/`, plus a same-day
check of a native Windows install (`.config\manicode\freebuff.exe`) to
confirm the storage path is identical cross-OS.

**Anonymisation**: the real project slug/path (`needlehaystack` was itself
a synthetic benchmark repo, not sensitive) and `hostname`/`userId`/
`userEmail` fields visible in the app's own `log.jsonl` debug log (never
read by the adapter — see the off-limits list in
[`docs/freebuff-adapter.md`](../../docs/freebuff-adapter.md)) are NOT
reproduced here at all; only `chat-messages.json` / `run-state.json` /
`chat-meta.json` shapes are captured, with real file bodies replaced by
short synthetic stand-ins. Real `output` strings (e.g. file contents,
command stdout) were shortened but kept as **plain strings** — the real
shape, not JSON-encoded strings-of-strings.

## File inventory

| Path | Purpose |
|------|---------|
| `manicode/projects/needlehaystack/chats/2026-08-11T07-07-38.552Z/chat-messages.json` | Primary fixture. 6 messages: 2 mode-dividers, 2 user prompts, 2 `ai` messages. Exercises: reasoning-then-text threading, `read_files`/`write_file`/`run_terminal_command`/`glob`/`write_todos`/`ask_user` tool blocks, ONE `agent` block (`agentName`/`agentType` both `"basher"`, `params.command` carrying the real invocation args since `initialPrompt` is empty in practice) with its own nested `blocks` (a further `run_terminal_command` + `set_output`), and one genuinely-unmapped real tool name (`suggest_followups`) landing on `ActionUnknown`. |
| `manicode/projects/needlehaystack/chats/2026-08-11T07-07-38.552Z/run-state.json` | Sibling state file. `sessionState.fileContext.{projectRoot,cwd}` is the real-cwd source; `sessionState.mainAgentState.{contextTokenCount,creditsUsed,directCreditsUsed}` — the evidence that `contextTokenCount` is a context-window size (grows monotonically across a session) and CodebuffAI's actual billing unit is the separate `credits` currency, never token counts. |
| `manicode/projects/needlehaystack/chats/2026-08-11T07-07-38.552Z/chat-meta.json` | Undocumented-but-harmless corroborating sidecar (`messageCount`/`firstPrompt`/`messagesSize`/`messagesMtimeMs`) the app also writes per chat dir. NOT read by the adapter; included only so the fixture directory matches the real shape of a chat dir. |
| `manicode/projects/otherslug/chats/2026-07-09T00-12-09.857Z/chat-messages.json` | One-message fixture with **no sibling `run-state.json`** — pins the `resolveProjectRoot` fallback to `"[freebuff]"` when the state file is absent (e.g. a launch where no message was ever sent, matching a real observed `log.jsonl`-only chat dir). |
| `manicode/projects/mismatched-slug/chats/2026-07-10T00-00-00.000Z/{chat-messages.json,run-state.json}` | Project slug (`mismatched-slug`) deliberately does NOT match the real cwd's basename (`actual-project-name`) in `run-state.json` — pins that project-root resolution reads `run-state.json`, never the manicode project-directory slug. |

## What the captured data covers

- Whole-file-rewrite / message-count cursor semantics (grounded separately
  against three live chat dirs' `chat-meta.json.messageCount`, shared
  sibling mtimes, and a `--continue` invocation's `log.jsonl` line
  explicitly logging `"Loaded chat state from chat directory"` against the
  ORIGINAL dir).
- Nested-agent block recursion: real `agent` blocks carry their own
  `blocks` array (the subagent's private tool-call transcript) which is
  walked with a depth cap, not just the agent block itself.
- The full real `toolNames` capability-list line from a live `log.jsonl`
  (`spawn_agents, read_files, read_subtree, write_todos, suggest_followups,
  str_replace, write_file, ask_user, read_url, skill, set_output,
  list_directory, glob, render_ui, gravity_index, file_picker,
  code_searcher, researcher_web, researcher_docs, basher, tmux_cli,
  browser_use, code_reviewer_deepseek_flash, context_pruner`) — cross-
  referenced against every observed real `toolCall` to separate genuine
  TOOL names (mapped in `mapFreebuffTool`) from AGENT TYPE names
  (`basher`, `code_searcher`, `researcher_web`, `researcher_docs`,
  `code_reviewer_deepseek_flash` — these are `agentType` values on
  `agent` blocks, not `toolName`s, and need no separate mapping since
  `RawToolName` already carries the real `agentType` string).
- A real, observed-but-deliberately-unmapped tool name (`suggest_followups`
  — a "propose next prompts" UI hint with no corresponding normalized
  action) landing honestly on `ActionUnknown`, instead of a synthetic
  placeholder name.

## Known gap: names in the capability list with no captured invocation

`tmux_cli`, `read_subtree`, `render_ui`, `gravity_index`, `file_picker`,
`context_pruner` appear in the real `toolNames` list but were never
actually invoked in the captured session, so their `input`/`output`
shapes are ungrounded. `mapFreebuffTool` deliberately leaves them
unmapped (`ActionUnknown`) rather than guessing — see
`docs/freebuff-adapter.md`'s known-gaps section.

---

# Freebuff Desktop fixture (layout 2)

**Captured**: 2026-09-03 against a live, signed-in **Freebuff Desktop**
run on native Windows 11, in
`C:\Users\<u>\.config\freebuff-desktop\projects\<name>-<uuid>\`. The
prompt kit was a single message asking for five things (summarise the
project / create + run `hello_world.py` / edit it to "Hello Universe" +
run / delete it / verify the deletion), which the app recorded as ONE
user `messages` row and ONE assistant `messages` row.

## File inventory

| Path | Purpose |
|------|---------|
| `freebuff-desktop/projects/demo-11111111-2222-3333-4444-555555555555/desktop-v2.sql` | The store, as a **text `.sql` seed** (the repo tracks no SQLite binaries — tree-wide `*.db` gitignore — so `internal/adapter/freebuff/desktop_test.go::desktopFixture` materializes it into a temp `desktop-v2.db` per run, exactly the `testdata/devin/desktop/sessions.sql` convention). Schema + rows for `projects` / `threads` / `messages` / `queue_items` / `freebuff_storage_metadata`. |
| `freebuff-desktop/projects/demo-11111111-2222-3333-4444-555555555555/project.json` | The real sibling sidecar (`{version, projectId, projectPath, database}`) — the LAST project-root fallback, after `threads.project_path` and `projects.root_path`. |

## What the captured data covers

- **Two layouts, one tool id.** The desktop store re-tags nothing: every
  row still reports `models.ToolFreebuff`. Only the store shape and the
  capture-surface stamp differ (`desktop` / `freebuff-desktop` vs the CLI's
  `cli` / `freebuff`).
- **The whole turn in one row.** `messages.parts_json` is an ordered array
  of parts: `text`, `reasoning` (`id`/`text`/`open`/`collapse`), `tool`
  (`id`/`toolName`/`input`, plus `status`+`output` only where the tool
  produced one), `ad`, and a trailing `changes` part carrying the turn's
  per-file workspace diff.
- **Real per-turn usage** — unlike the CLI layout. `messages.metrics_json`
  carries `usage.{inputTokens,cachedInputTokens,outputTokens,totalTokens}`
  and `costUsd`. The fixture keeps the real numbers
  (108245 / 94208 / 1622 / 109867, `costUsd` 0), which is what pins the
  GROSS-input netting: `108245 = 14037 fresh + 94208 cached`, and
  `totalTokens = inputTokens + outputTokens`.
- **The `changes`-vs-tool-parts dedupe.** The single changed file
  (`hello_world.py`) is covered by BOTH a `write_file` and a `str_replace`
  tool part AND the `changes` part, so the fixture is the regression case
  for the per-message dedupe.
- **`changes.status` is not history.** The captured `changes` part reports
  `hello_world.py` as `"added"` even though the same turn ended by deleting
  it — evidence the part is a point-in-time diff panel, not an event log.
- **A genuinely-unmapped real tool name**, `suggest_prompts` (the Desktop
  sibling of the CLI's `suggest_followups`), landing honestly on
  `ActionUnknown`.
- **Status is usually absent.** Only `run_terminal_command` persisted
  `status`/`output`; `list_directory` / `read_files` / `write_file` /
  `str_replace` / `suggest_prompts` carry neither, by design.

## Anonymisation — what was withheld

- **`state.json` is NOT here, and was never read.** The real file (at the
  `freebuff-desktop` root, beside `projects/`) carries an OAuth-style auth
  **token** plus the operator's name and email under `authSessions`. Neither
  it nor its `state.json.orchestrator-lock.sqlite` sibling is copied,
  quoted, or opened; `layoutFor` rejects both by name.
- **Ad payloads are placeholders.** The real `ad` parts embed a
  `clickUrl` whose path is a signed JWT containing the operator's own user
  id (`"u":"<uuid>"`), plus BuySellAds impression/click URLs. The fixture
  keeps three `ad` parts so the skip path is exercised, but with an inert
  payload (`https://example.invalid/plans`, no click/impression URLs, no
  ids). The adapter's `desktopPart` struct declares **no** `ad` field at
  all, so the payload is never even decoded.
- **Identifiers are fixture-shaped.** The real project dir
  (`antigravity-<uuid>`), thread uuid, queue-item uuid, project path
  (a real `C:\Users\<u>\...` workspace) and the `ls -la` output's owner
  column are all replaced. `projects.id` is kept as a PATH, because that
  is genuinely what the Desktop stores there.
- **Prose was shortened.** Reasoning / assistant text bodies are short
  synthetic stand-ins of the real ones; structure, part order and part
  kinds are byte-faithful to the capture.
- **`threads.harness_state`** (a large engine-internal blob, in the real
  capture a full `sessionState` with the workspace file tree) is replaced
  by a one-key sentinel object. The adapter never reads the column, and
  `TestDesktopOffLimitsFilesNeverDispatchedOrIngested` asserts the
  sentinel never reaches a row.

## Finding: there is no CLI twin

On the grounding host the Desktop wrote **no** `~/.config/manicode` store
at all — it is not a front-end over the CLI's chats directory, it is a
separate store. So the two layouts cannot double-count the same run today.
Their `SourceEventID` shapes are disjoint anyway (`<kind>:<thread
uuid>:<messages.seq>:<part id>` vs `<kind>:<RFC3339 chat dir>:<message
index>:<block path>`), so a future build that wrote both stores would
still produce two clearly-distinguishable row sets rather than silently
merged ones.
