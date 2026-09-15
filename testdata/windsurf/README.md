# testdata/windsurf — fixture PLACEHOLDER (no capture exists yet)

**Status: EMPTY on purpose.** No Windsurf install has ever been launched on a
host this project can read, so there is no Cascade byte anywhere to anonymise.
`internal/adapter/windsurf` is the matching UNREGISTERED skeleton: it declares
watch roots and a file-shape predicate, and its `ParseSessionFile` emits
nothing but one warning pointing back at this file.

This README is the capture recipe. It is filled in — with real files and a
real inventory table — during **step-in P8** of
[`docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md`](../../docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md)
(§3, "Cognition: Windsurf / Devin Desktop"). Ticket U4 of
[`docs/plans/uncaptured-surfaces-wiring-plan-2026-09-03.md`](../../docs/plans/uncaptured-surfaces-wiring-plan-2026-09-03.md).

## What Cascade is, and what it is not

Cascade is Windsurf's own in-IDE agent, driven by the bundled
Codeium/Exafunction language server. It is a **different producer** from
Devin-in-Windsurf: the bundled `extensions\windsurf\devin\bin\devin.exe` IS
the Devin CLI, and whatever it writes is already captured by
`internal/adapter/devin`. Nothing devin-shaped belongs in this directory.

## The two candidate stores

| # | Path | Confidence | What it is expected to hold |
|---|------|-----------|------------------------------|
| 1 | `%USERPROFILE%\.codeium\windsurf\cascade\` (POSIX `~/.codeium/windsurf/cascade`) | **MEDIUM** | Conversation history. Vendor docs (docs.windsurf.com/windsurf/cascade/memories) + community. **File format undocumented** — could be JSON, protobuf, SQLite, anything. The bundle contains no `cascade` path literal and zero `.jsonl` strings, so make no assumption. |
| 2 | `%APPDATA%\Windsurf\User\globalStorage\state.vscdb` | **STATIC / UNVERIFIED** | The VS Code memento `windsurf.workspaceCascadeMap`. Bundle-verbatim: a `{workspaceFolderUri: cascadeId}` map that the extension **deletes on read**. Expect a transient workspace↔cascade-id correlation, **not** a conversation index. |

The `.codeium/<channel>` parent is bundle-grounded and has three channel
spellings — `windsurf`, `windsurf-insiders`, `windsurf-next` — so capture
whichever exists on the box, and note which channel was installed.

A third path is grounded but is almost certainly **not** a conversation
store: `~/.codeium/<channel>/database/9c0694567290725d9dcba14ade58e297`, the
language server's `--database_dir`, passed alongside `--enable_index_service`
and `--enable_local_search` (a code index / local search store). Note its
contents in passing; do not build a parser against it without evidence.

## What to capture during P8

Windsurf 2.3.15 is installed at `%LOCALAPPDATA%\Programs\Windsurf` and has
never been launched. Sign-in is a Cognition/Windsurf account (free Desktop
tier suffices) — **the operator does the login; this arc never enters
credentials.**

1. **Before launching**, record the "absent" baseline:
   `~/.codeium`, `%APPDATA%\Windsurf`, `~/.devin` — list what exists (nothing
   is expected).
2. Launch Windsurf, sign in, open a real folder, and run the prompt kit in
   the **Cascade** panel (at least two prompts in one conversation, plus a
   second conversation in a **second workspace folder** — the
   `workspaceCascadeMap` only becomes interesting with more than one
   workspace, and it is cleared on read, so capture `state.vscdb`
   immediately after opening the second folder).
3. If the palette offers "Install Devin CLI", run one prompt through it too —
   that lane's output belongs to `testdata/devin`, not here, but the diff is
   what proves the two stores are separate.
4. **Then diff and copy (read-only):**
   - `%USERPROFILE%\.codeium\<channel>\cascade\` — full recursive listing
     (names, sizes, mtimes) **plus** the first 64 bytes of each file in hex,
     so the format is identified before anything is parsed.
   - `%USERPROFILE%\.codeium\<channel>\` — one level of siblings: what
     appeared next to `cascade` (`database/`, `memories/`, settings,
     `mcp_config.json`).
   - `%APPDATA%\Windsurf\User\globalStorage\state.vscdb`.
   - `%USERPROFILE%\.devin\` — to confirm the Devin lane lands there.

### Copy the DB before opening it

Never open a live `state.vscdb` in place, and never let a tool open it
read-write. The rule this repo already follows for Cursor's state database
(`internal/adapter/cursor/statedb.go`):

1. Copy `state.vscdb` (and, if present, `-wal` / `-shm`) to the scratchpad
   **first** — a plain file copy, while Windsurf is closed if possible.
2. Query the **copy** with `mode=ro&immutable=1`, e.g.
   `file:<copy>?mode=ro&immutable=1&_pragma=busy_timeout(2000)`.
3. Note in the capture whether the `-wal` was copied: a base-file-only copy
   under-reports rows (that caveat is already recorded for the Cursor capture
   in the 2026-09-02 IDE audit).

The memento is expected to be a JSON blob in `ItemTable` keyed by the
extension identifier `codeium.windsurf`, with `windsurf.workspaceCascadeMap`
as a field inside it — **verify this**, it is a VS Code convention, not an
observed fact.

## Off limits — never copied into this directory, never parsed

- `~/.codeium/<channel>/memories/` — Cascade auto-memories (user context, not
  sessions).
- `~/.codeium/<channel>/config.json` or any sibling holding the Codeium API
  key; any `*.token` / `*.key`; the OS keyring.
- `mcp_config.json` — MCP server definitions routinely embed API keys in
  their `env` blocks.
- Anything under `~/.devin` / `%APPDATA%\devin\config.json` (the Devin lane).

## Anonymisation rules for anything committed here

Follow the conventions the existing fixtures use (`testdata/clinecli`,
`testdata/hermes`):

- **User segment** → `<u>`: every `C:\Users\marmu`, `/home/marmu`,
  `/mnt/c/Users/marmu` becomes `C:\Users\<u>` / `/home/<u>` /
  `/mnt/c/Users/<u>`. Keep the ORIGINAL separators and casing around it — the
  path normaliser is exercised by real Windows-shaped strings.
- **Project paths** → `/home/dev/proj` (POSIX) or `C:\dev\proj` (Windows),
  consistently, so cwd resolution stays testable.
- **Prompts and assistant text** → replaced with short neutral stand-ins that
  preserve LENGTH CLASS and structure (a long body becomes
  `<redacted: N chars>`), never real content.
- **Ids** (cascade id, session id, conversation id, workspace hash) →
  regenerated as same-shape placeholders (same length, same alphabet), kept
  internally consistent so cross-file joins still resolve.
- **Never** commit: API keys, tokens, the `codeium.installationId`, account
  email, machine name, or anything from the off-limits list above.
- Record the anonymisation actually performed at the top of this file when
  the fixture lands (the `testdata/clinecli/README.md` header is the model).

## Target filenames for the future fixture

Use these names so the adapter's tests can reference them without a second
round of renaming:

| File | Contents |
|---|---|
| `cascade-listing.txt` | Recursive listing of `~/.codeium/<channel>/cascade` — name, size, mtime, first-64-bytes hex per file. The format-identification artefact. |
| `cascade-sample.<ext>` | ONE anonymised conversation file, extension matching whatever the store actually uses. Add `-2` etc. for a second conversation. |
| `state-vscdb-itemtable.json` | `SELECT key, value FROM ItemTable` for the rows that matter (`codeium.windsurf`, any `windsurf.*` key), anonymised, from the **copy**. |
| `state-vscdb-schema.sql` | `.schema` of the copied `state.vscdb`. |
| `workspace-cascade-map.json` | The decoded `windsurf.workspaceCascadeMap` value, with workspace URIs and cascade ids anonymised. |
| `codeium-dir-listing.txt` | One-level listing of `~/.codeium/<channel>/` (what sits next to `cascade`). |
| `reality-check.txt` | Free-form notes: Windsurf version + channel, what existed before/after launch, whether the `-wal` was copied, which of the two candidate stores actually held the conversation, and every assumption in `internal/adapter/windsurf/doc.go` that the capture confirmed or refuted. **Not loaded by tests.** |

Once these exist, the adapter's `IsSessionFile` is narrowed to the observed
shape, `ParseSessionFile` gets a real parser, and the wiring checklist in
`internal/adapter/windsurf/doc.go` ("Not registered") is executed in one
commit.
