# testdata/geminicodeassist — FIXTURE PLACEHOLDER

**This directory holds no fixtures yet.** It is the landing site for the
Gemini Code Assist **Chat Mode** capture that the operator step-in **P3**
produces (`docs/plans/uncaptured-surfaces-login-schedule-2026-09-03.md`
§1). Until then, `internal/adapter/geminicodeassist` is an UNREGISTERED
skeleton whose parser refuses to guess, and every test fixture in that
package is **SYNTHETIC** — written by hand to pin the skeleton's own
behaviour, never captured from a real install.

Nothing here was ever observed on the measurement host: the presence
check on 2026-09-03 found `globalStorage/google.geminicodeassist` absent
entirely. Every shape below comes from a static read of the shipped
`google.geminicodeassist` 2.98.0 bundle
(`docs/audits/ide-session-tracking-audit-2026-09-02.md` §3.7).

## Scope: Chat Mode only

Gemini Code Assist has two agents. **Agent Mode** writes
`~/.gemini/tmp/<projectId>/chats/session-*.jsonl` — the exact store
`internal/adapter/gemini` already parses, tagged `gemini-cli`. It is
**already captured** and is NOT what this directory is for. Run the
prompt kit in **Chat** mode, or the capture lands in the wrong adapter.

## The three candidate stores

| # | Store | What it should hold | Transient? |
|---|---|---|---|
| 1 | `<globalStorage>/state.vscdb` → `ItemTable` row keyed `google.geminicodeassist` | The `geminiCodeAssist.chatThreads` memento: the chat threads themselves | No — persists until the extension rewrites it |
| 2 | `<globalStorage>/google.geminicodeassist/metrics_to_send/<uuid>.json` | Telemetry events (`CHAT_STREAMING_OFFERED_START` / `_CHUNK`) carrying a `usageMetadata` token block — **the only known token signal** | **YES — drained and DELETED on upload** |
| 3 | `<globalStorage>/google.geminicodeassist/chat_checkpoint_files/` | Per-chat checkpoint files; contents and naming unknown | Unknown |

`<globalStorage>` is `%APPDATA%\Code\User\globalStorage` on Windows,
`~/.config/Code/User/globalStorage` on Linux,
`~/Library/Application Support/Code/User/globalStorage` on macOS — and
the same path under any other VS Code-family product the extension is
installed into.

One caveat for step 3 below: `state.vscdb` is a SHARED file, one per
editor product, and the adapter declares it as a watch root only for the
products no other adapter already owns — Cursor's belongs to
`internal/adapter/cursor` and Windsurf's to `internal/adapter/windsurf`
(see `internal/adapter/geminicodeassist/roots.go`). **Run the P3 capture
in plain VS Code**, not in Cursor or Windsurf, or the memento fixture
will describe a file this adapter will never open.

## What to copy during P3, and WHEN

Order matters, because store 2 is transient.

1. **Before the first prompt**, snapshot the roots so the after-diff is
   unambiguous:
   `Get-ChildItem -Recurse -Force "<globalStorage>\google.geminicodeassist" | Select FullName,Length,LastWriteTime`
   → scratchpad. Do **not** snapshot anything auth-shaped (see
   "Never copy" below).
2. **Immediately after EACH prompt**, before the next upload tick,
   copy every `metrics_to_send\*.json` to the scratchpad. A `.tmp` file
   is half-written — wait for its `.json` rename, or copy the `.tmp`
   only as a curiosity, never as the fixture. If the directory is
   already empty, the upload beat you; the extension's own upload
   interval is the constraint, so take the next prompt's spool faster.
3. **After both threads exist**, copy `state.vscdb` **as a file copy**
   to the scratchpad and query the COPY with `mode=ro&immutable=1`.
   Never open the live database.
4. **After both threads exist**, copy the whole
   `chat_checkpoint_files\` directory listing plus one representative
   file.

Prompt plan (from the step-in schedule): the standard prompt kit, in
Chat mode, split across **two threads** (prompts 1+2 in thread A,
prompt 3 in thread B) so the memento holds more than one thread and the
thread-id linkage is visible.

## Never copy

Off-limits by name, at snapshot time and at fixture time alike:

- `~/.gemini/oauth_creds.json`, `~/.gemini/google_accounts.json`
- any file whose name contains `auth`, `credential`, `token`, `secret`
  or `account`
- the OS keyring / Windows Credential Manager entries
- any `ItemTable` row of `state.vscdb` other than the single
  `google.geminicodeassist` key — other extensions' rows routinely hold
  secrets, so the extraction query must select that one key, never
  `SELECT * FROM ItemTable`.

## Anonymization rules

Applied before anything lands in this directory:

| Field | Replace with |
|---|---|
| Prompt / response text | The prompt-kit text verbatim (it is already synthetic); any incidental content → `[redacted]` |
| Absolute paths | `/home/dev/project` (POSIX) and `C:\dev\project` (Windows), keeping one of each so the crossmount path is exercised |
| Thread / session / conversation ids | Stable placeholders `thread-a`, `thread-b`, `sess-0001` |
| Spool file names (uuids) | `aaaa1111-2222-3333-4444-555566667777.json`, incrementing |
| Timestamps | Fixed `2026-09-03T12:00:00Z` plus fixed offsets; keep relative ordering |
| Account email / user id / project number / GCP project id | `dev@example.com`, `user-0001`, `000000000000`, `example-project` |
| Machine name, OS user | `devbox`, `dev` |
| Token counts | **Kept verbatim** — they are the point of the fixture and carry no PII |
| Model ids | **Kept verbatim** |

Run one deliberately-injected `sk-…`-shaped string through a prompt so
the scrubber path can be asserted once the parser emits content.

## Target filenames

Land the anonymized capture as:

| File | What it is |
|---|---|
| `metrics-spool-with-usage.json` | One drained spool file that DOES carry a `usageMetadata` block — the token-path fixture |
| `metrics-spool-no-usage.json` | One drained spool file with only `CHAT_STREAMING_OFFERED_START`-style records — pins the zero-events, zero-warnings contract |
| `chat-threads-memento.json` | The decoded `value` of the `google.geminicodeassist` `ItemTable` row (JSON text, **not** a `.vscdb` binary — the memento tests build their SQLite in-process, the way `testdata/kirocli` does) |
| `chat-checkpoint-sample` | One representative checkpoint file, extension preserved if it has one |
| `listing.txt` | The before/after `Get-ChildItem` diff, so the directory shape is recorded even for files not committed |

Commit no `.vscdb`, `.db`, `-wal` or `-shm` binary.

## Field-name provenance

Carry these marks forward into the adapter's comments; **do not upgrade
one without a live capture**.

| Name | Provenance |
|---|---|
| `google.geminicodeassist` (extension id / memento row key) | **Bundle-grounded** |
| `geminiCodeAssist.chatThreads` (memento key) | **Bundle-grounded** |
| `metrics_to_send` (dir), `.tmp` → `.json` rename, `sendMetricsFromDisk` | **Bundle-grounded** |
| `chat_checkpoint_files` (dir) | **Bundle-grounded** |
| `CHAT_STREAMING_OFFERED_START`, `CHAT_STREAMING_OFFERED_CHUNK` | **Bundle-grounded** (event names) |
| `usageMetadata` | **Bundle-grounded** |
| `promptTokenCount`, `candidatesTokenCount`, `totalTokenCount`, `cachedContentTokenCount` | **Bundle-grounded** |
| The spool file's ENCLOSING envelope (object vs array, nesting depth of `usageMetadata`) | **INVENTED** — the skeleton accepts both shapes precisely because neither was observed |
| `event_name`, `payload`, `threadId` (as used in the synthetic test fixtures) | **INVENTED** — plausible spellings only, never observed |
| `model` / `modelName` beside `usageMetadata` | **INVENTED** — the two spellings the Gemini API family uses elsewhere; a miss leaves the model empty, which is the honest outcome |
| The spool → thread-id linkage | **UNKNOWN** — the skeleton uses the spool file stem as a placeholder SessionID until P3 settles it |
| Anything about the thread JSON inside the memento | **UNKNOWN** — login-gated; the skeleton opens no SQLite at all |

## Token arithmetic to preserve

Gemini's `promptTokenCount` is **GROSS**: it INCLUDES
`cachedContentTokenCount`. The adapter nets at emit time, mirroring
`internal/adapter/gemini/parser.go::tokenEventFor` —
`InputTokens = max(0, promptTokenCount - cachedContentTokenCount)`,
`CacheReadTokens = cachedContentTokenCount`,
`OutputTokens = candidatesTokenCount`. Pick a P3 prompt pair that
actually produces a non-zero `cachedContentTokenCount` (the second
prompt in the same thread should) so the fixture exercises the netting
rather than the trivial zero-cache path.
