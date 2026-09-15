# testdata/junie — JetBrains Junie fixtures

**Captured**: 2026-08-16 from a live `~/.junie/` install on the operator's
own WSL2 Ubuntu box (Junie runs as a TUI embedded in a JetBrains IDE).
**Operator**: Santosh, running the IDE's own "hello world" starter
prompt against a scratch project at `/home/marmutapp/parking-game`.
**Anonymisation**: none for paths/names — these are the operator's own
throwaway hello-world test runs, not a client/production capture (HARD
RULE #4 of the adapter build task explicitly waived anonymisation for
this reason). No credential file (`secure_credentials.json`, `trust/`,
or `settings.json`'s credential fields) was ever read to produce these
fixtures.

**★ Environment scrubbed 2026-09-07 (retroactive fix).** The initial
2026-08-16 capture committed `session-260816-220304-lrfz/events.jsonl`
verbatim, including 14 `EnvironmentVariablesUpdatedEvent` records whose
`env[]` carried the operator's real process environment — Junie
ciphertext-encrypts each `value`, but every `key` (48 distinct names,
including `OPENAI_API_KEY`, `USERNAME`, `USERPROFILE`,
`COMPUTERNAME`) was plaintext. A small script re-serialized every
matching record with `"env":[]` (a shape the fixture already carried
elsewhere) and left every other byte of every line untouched — no
trimming, no reordering, no re-anonymisation of the paths/names above.
Verified: `grep -c '"env":\[{' session-260816-220304-lrfz/events.jsonl`
is now 0, and grepping the file for any of the stripped key names
returns nothing. The same fix was applied to
`cli/session-260907-002452-cli1/events.jsonl` below (18 records, 56
key names, including `CONTEXT_DEV_API_KEY`,
`AZURE_COGNITIVE_SERVICES_RESOURCE_NAME`) at the same time it was
anonymised for names/paths — see its own section.

## `jetbrains-mcp/session-260903-163227-mcp1/` — the IDE/MCP lane

**Captured**: 2026-09-03 from `~/.junie/sessions/` on the operator's
**Windows 11** box. **Host**: IntelliJ IDEA 2026.2 AI Assistant driving
Junie as its `junie` ACP agent (NOT the plugin's own chat, NOT the
CLI). **Prompt**: the five-turn step-in kit — summarise the project /
create + run `hello_world.py` / edit to "Hello Universe" + run /
delete / verify.

**Why it exists**: this is the capture that revealed the MCP lane. When
the IDE hosts Junie it serves its own tools over MCP, so the run emits
**42 `McpBlockUpdatedEvent` and ZERO
`TerminalBlockUpdatedEvent`/`FileChangesBlockUpdatedEvent`** — the exact
two kinds the 2026-08-16 fixture is built from. Before
`internal/adapter/junie/mcpblocks.go`, this whole session reduced to 3
actions; it now yields 14. It is also the first **Windows-native**
Junie capture, closing the "Windows path is an assumption" gap in
`docs/junie-adapter.md` (`%USERPROFILE%\.junie` is confirmed real).

| File | Purpose |
|------|---------|
| `jetbrains-mcp/index.jsonl` | The session's own `index.jsonl` row (project-root fallback) |
| `jetbrains-mcp/session-260903-163227-mcp1/events.jsonl` | 101 lines trimmed from the live 338 |

**Trimming rule**: EVERY occurrence of the six block kinds
(`McpBlockUpdatedEvent`, `ViewFilesBlockUpdatedEvent`,
`ToolBlockUpdatedEvent`, `ResultBlockUpdatedEvent`,
`AgentThoughtBlockUpdatedEvent`, `LlmResponseMetadataEvent`) is kept so
the `stepId` collapse and the completion rebroadcast are both exercised
end to end; every OTHER `(kind, agentEvent.kind)` pair is kept exactly
once, plus the first non-empty `CurrentDirectoryUpdatedEvent` so the
header pre-scan runs on a real value.

**★ `EnvironmentVariablesUpdatedEvent` payload is STRIPPED.** The live
records carry the operator's entire process environment. The single
kept occurrence has its `env` replaced with
`{"FIXTURE_PLACEHOLDER": "<stripped>"}` — real values were never copied
into this repo. `TestMCPFixtureNeverEmitsEnvironment` asserts that
placeholder never reaches an emitted row. The sibling `state.json`
(which holds the same `env`, plus `lastAgentParameters.ide_name`) is
**not fixtured at all** and is on the adapter's never-read list.

**Anonymisation**: unlike the 2026-08-16 fixtures below, this one IS
anonymised — the operator's Windows account name, the real workspace
path (rewritten to `C:\Users\dev\projects\demo\text`, in both backslash
and forward-slash spellings) and the session id suffix are replaced. The
prompt text and every tool call, argument and outcome summary are
verbatim.

**Reality-check findings baked in** (pinned by
`internal/adapter/junie/mcpblocks_test.go`):

- **8 MCP steps, 4 distinct tool names**: `idea/list_directory_tree` ×3,
  `idea/create_new_file`, `idea/execute_terminal_command` ×3 (run, run
  again, and the DELETE — via PowerShell `Remove-Item`, since the
  vocabulary has no `idea/delete_file`), `idea/apply_patch`.
- **`details` mirrors `input` while `IN_PROGRESS`** and becomes the
  outcome summary only at the terminal transition.
- **`cancelRequest` is not a cancellation** — it appears on 7 of the 8
  steps as the UI's cancel handle while the step runs.
- **One `approvalRequest`**, on the first MCP call, offering
  `idea:list_directory_tree` and `idea:*`.
- **`ToolBlockUpdatedEvent` (×3) always shares a `stepId`** with a
  `ViewFilesBlockUpdatedEvent`, which is why it is not mapped.
- **`AgentPatchCreatedEvent` carries `"patch": ""`** — empty, so it
  stays skipped.
- **Tokens**: 32 `LlmResponseMetadataEvent` → 32 rows, 14,788 net input
  + 1,618 output (= the 16,406 the live daemon recorded), 18,206
  cache-create, 136,555 cache-read. Four different models in ONE
  session. `inputTokens` is confirmed already NET: one call states
  `inputTokens: 3` with `cacheCreateTokens: 15847`.
- **Capture-surface discriminator (updated 2026-09-07, tightened same
  day)**: this fixture's own `UserPromptEvent.extraAttachments[]` DOES
  carry a `"TaskRequestMcpServersAttachment"` entry whose
  `mcpServers[].env[]` names an `IJ_MCP_AUTH_TOKEN` key — the positive
  IDE marker grounded against the 2026-09-07 CLI/IDE diff (see
  `internal/adapter/junie/surface.go` and `docs/junie-adapter.md`).
  The attachment KIND alone was the original (looser) discriminator;
  it was tightened to also require the auth-token key name after
  noticing the CLI lane runs MCP clients too (33 "Initializing MCP
  clients" lines in the `cli/` fixture below) whenever the operator
  configures one, so kind alone could misstamp such a CLI run `ide`.
  `TestMCPFixtureSelfStampsIDE` pins the adapter still self-stamping
  this fixture `ide`/`jetbrains` under the tightened predicate;
  `TestHasIDEMCPAttachment` / `TestSyntheticIDEAttachmentWithoutAuthTokenNoStamp`
  / `TestSyntheticBothMarkersIDEWins` (all in `surface_test.go`) pin the
  predicate itself against synthetic attachments the real fixtures
  don't otherwise exercise in isolation. (The original claim here —
  "no discriminator exists anywhere" — was true only in the sense that
  nothing NAMED a client/host/transport field; the attachment sat in
  this fixture unnoticed until the CLI comparison gave it meaning.)

### Reproducing the copy

Not a plain `cp`: the trim + strip + anonymise pass above must be
re-applied. The rule set is fully described in this section.

## `cli/session-260907-002452-cli1/` — the standalone CLI lane

**Captured**: 2026-09-07 from `~/.junie/sessions/` on the operator's
Windows 11 box, via `junie --session-id session-260907-002452-gk1t`.
**Prompt**: the same five-turn step-in kit as the `jetbrains-mcp/`
fixture (create + run `hello_world.py` / edit to "Hello Universe" +
run / delete / verify), run the SAME day as a same-prompt IntelliJ
IDEA AI-Assistant session (`session-260907-002018-1eui`, not itself
fixtured — it stalled on an unapproved `ijembedded/execute_tool` MCP
call and never completed).

**Why it exists**: this is the capture that closed the "no CLI capture
exists" gap in `docs/junie-adapter.md`'s Operator verification
checklist. Diffing this file against the IDE-hosted fixtures
surfaced the capture-surface discriminator: this file has NO
`UserPromptEvent.extraAttachments` field at all, and DOES carry a
top-level `SessionCostTrajectorySnapshotEvent` record (line 263 of
279) — the CLI's own end-of-task cost-breakdown table, emitted right
before `TaskState:"COMPLETED"`. Neither completed IDE fixture
(`jetbrains-mcp/` here, or `session-260816-220304-lrfz/` below) ever
emits that record. See `internal/adapter/junie/surface.go` for the
full grounding and `TestCLIFixtureSelfStampsCLI` /
`TestCLIFixtureNoIDEAttachment` for the pins.

**Anonymisation**: the operator's real Windows account name and
workspace path are replaced the same way as `jetbrains-mcp/` (the real
`C:\Users\<account>\...` path → `C:\Users\dev\projects\demo`); the
session id suffix (`gk1t` → `cli1`) is replaced too. Nothing else is
trimmed — unlike `jetbrains-mcp/`, this is a straight anonymised copy
of the full 279-line / 279-record live capture, matching the
untrimmed-copy precedent set by `session-260816-220304-lrfz/` below.

**★ Environment scrubbed at the same pass.** 18 of this file's
`EnvironmentVariablesUpdatedEvent` records carried the operator's real
process environment (56 distinct plaintext key names, values
ciphertext-encrypted by Junie — including `CONTEXT_DEV_API_KEY`,
`AZURE_COGNITIVE_SERVICES_RESOURCE_NAME`, `USERNAME`, `USERPROFILE`,
`COMPUTERNAME`, `LOGONSERVER`, `OneDrive`, `HERMES_HOME`); the other 3
already carried `"env":[]`. All 18 non-empty records were rewritten to
`"env":[]` by the same mechanical script used on
`session-260816-220304-lrfz/` above, byte-identical otherwise. Verified:
`grep -c '"env":\[{' cli/session-260907-002452-cli1/events.jsonl` is
now 0.

| File | Purpose |
|------|---------|
| `cli/index.jsonl` | The session's own `index.jsonl` row (project-root fallback) |
| `cli/session-260907-002452-cli1/events.jsonl` | 279 lines, verbatim (anonymised) live capture |

## `JUNIE_HOME` and `/local`: still no fixture

"Junie" also covers a `/local` CLI subcommand, and `JUNIE_HOME` can
relocate the whole store — both share the same
`${JUNIE_HOME:-~/.junie}/sessions` shape (see
`internal/adapter/junie/doc.go` and `docs/junie-adapter.md`). **No
`/local` fixture and no `JUNIE_HOME`-relocated fixture exist yet** —
the roots.go support for `JUNIE_HOME` and the relocated-store shape
match are pinned by synthetic `t.TempDir()`-based unit tests
(`internal/adapter/junie/roots_test.go`) only, not by a real capture.
When a live `/local`/`JUNIE_HOME` session becomes available (see the
"Operator verification checklist" in `docs/junie-adapter.md`, which
points at
`docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md` §4 P7),
the placeholder fixture would land as a sibling directory here, e.g.
`testdata/junie/local-<date>-<id>/events.jsonl`, with its own
paragraph in this README following the format above.

## File inventory

| File | Purpose | Use in tests |
|------|---------|---------------|
| `index.jsonl` | Verbatim copy of the sibling `~/.junie/sessions/index.jsonl` — one line per session (`sessionId`/`createdAt`/`updatedAt`/`projectDir`/`taskName`) | `TestIndexFallback` — the project-root fallback path when a session's own `events.jsonl` never states a `CurrentDirectoryUpdatedEvent` |
| `session-260816-220304-lrfz/events.jsonl` | Verbatim copy of a real session log, 219 lines | The main fixture — every other adapter_test.go test parses this file |
| `jetbrains-mcp/session-260903-163227-mcp1/events.jsonl` | Trimmed + anonymised IDE/AI-Assistant capture, 101 lines | `mcpblocks_test.go` — MCP tool-name table, plus `TestMCPFixtureSelfStampsIDE` (surface_test.go's IDE-marker pin lives alongside it) |
| `cli/session-260907-002452-cli1/events.jsonl` | Anonymised, untrimmed standalone CLI capture, 279 lines | `surface_test.go` — `TestCLIFixtureSelfStampsCLI`, `TestCLIFixtureNoIDEAttachment` |

## The two observed sessions

`~/.junie/sessions/` held exactly two session directories at capture
time:

- **`session-260816-220304-lrfz`** (the fixture above) — a real,
  completed hello-world task ("Python Hello World Program Creation and
  File Management" per `index.jsonl`'s `taskName`). 219 lines, 5
  top-level `kind` values, 13 distinct `agentEvent.kind` values nested
  under `SessionA2uxEvent`. This is the only session with an
  `events.jsonl` at all.
- **`session-260816-220208-d62c`** — an aborted/near-instant session:
  its directory holds only a 21-byte `transcript.md` containing the
  literal text `# Session transcript` and nothing else. No
  `events.jsonl`, no `state.json`. This is evidence (not itself
  fixtured, since there's nothing to fixture) that a session the
  operator closed before Junie ever got as far as emitting a
  `TaskStartedEvent` produces no `events.jsonl` file at all — the
  adapter's `IsSessionFile`/`ParseSessionFile` never has to special-case
  an empty-but-present log, only a missing one (which the watcher
  already skips at the file-existence layer).

## Reality-check findings baked into the fixture

Counts and structural findings below are all reproduced by
`adapter_test.go`'s `TestParseFixtureCounts` and friends; see
`internal/adapter/junie/doc.go`'s package doc for the full narrative.

- **Top-level `kind` counts**: `UserPromptEvent:1`,
  `TaskStartedEvent:1`, `SessionA2uxEvent:201`,
  `UserMessagesCommittedToHistory:15`, `TaskState:1`.
- **`SessionA2uxEvent.event.agentEvent.kind` counts** (13 distinct
  values): `AgentCurrentStatusUpdatedEvent:112`,
  `CurrentDirectoryUpdatedEvent:17`,
  `EnvironmentVariablesUpdatedEvent:17`, `LlmResponseMetadataEvent:22`,
  `TipSuggestionCreatedEvent:2`, `AgentTaskNameUpdatedEvent:1`,
  `AgentThoughtBlockUpdatedEvent:2`, `TerminalBlockUpdatedEvent:12`,
  `ContextWindowReportEvent:6`, `FileChangesBlockUpdatedEvent:6`,
  `AgentPatchCreatedEvent:1`, `ResultBlockUpdatedEvent:2`,
  `NextPromptSuggestionEvent:1`. Only 6 of the 13 have a
  normalized-action counterpart; the rest are scheduler/UI/diagnostic
  bookkeeping and are skipped silently.
- **Block collapse by `stepId`**: Terminal, FileChanges, and Result
  blocks each recur 2-4 times under the same `stepId` (an `IN_PROGRESS`
  occurrence, a terminal-status occurrence, and — once the enclosing
  task completes — a byte-identical rebroadcast). The fixture yields
  exactly 3 collapsed Terminal rows, 2 collapsed FileChanges rows, and
  1 collapsed Result row.
- **Rebroadcast-after-completion**: once `event.state` reaches
  `COMPLETED`, every block belonging to that task is re-emitted once
  more, unchanged except for timestamp jitter. Example: the Terminal
  block keyed `62c01dad-eff2-4fcc-bde3-332dde2a43c5` appears at lines
  41 (`IN_PROGRESS`), 45 (`IN_PROGRESS`), 69 (`FAILED`, its real
  terminal status), and 208 (the post-completion rebroadcast of the
  same `FAILED` occurrence).
- **`completion` is a sibling of `event`, not nested inside it**, and
  appears ONLY on a `ResultBlockUpdatedEvent` envelope:
  `{"event":{...},"completion":{"startedAtMs":...,"endedAtMs":...,"taskCostUsd":...}}`.
- **Tokens are NET, cost is provider-stated**: all 22
  `LlmResponseMetadataEvent` lines carry a non-zero `modelUsage[]`
  entry (22 `TokenEvent`s total). The first (line 8):
  `{"model":"gpt-4.1-2025-04-14","cost":0.002332,"inputTokens":1138,"cacheInputTokens":0,"cacheCreateTokens":0,"outputTokens":7,"time":0}`.
  `inputTokens` is already net of `cacheInputTokens`
  (both observed as 0 in this capture); `cost` is a genuine per-call
  dollar figure, carried straight through rather than priced by the
  cost engine.
- **Project root**: `CurrentDirectoryUpdatedEvent.currentDirectory`
  first appears around line 50 (roughly a quarter into the file), not
  on line 1 — the adapter's header pre-scan (bounded to 2000 lines,
  always re-run from byte 0 on every `ParseSessionFile` call) is what
  lets even the FIRST emitted `ToolEvent` (from line 1) carry a
  correct, non-empty `ProjectRoot`.

## Reproducing the copy

```bash
cp ~/.junie/sessions/session-260816-220304-lrfz/events.jsonl \
   testdata/junie/session-260816-220304-lrfz/events.jsonl
cp ~/.junie/sessions/index.jsonl testdata/junie/index.jsonl
```

No path/name anonymisation script is needed or applied to this fixture
— see the note at the top. The env-stripping script IS applied (see
"Environment scrubbed 2026-09-07" above); it touches only the
`EnvironmentVariablesUpdatedEvent` records' `env` field and nothing
else.
