// Package stakpak implements a SQLite-store adapter for the Stakpak agent
// CLI (binary `stakpak`, https://stakpak.dev, installed with
// `curl -sSL https://stakpak.dev/install.sh | sh`). Live-verified against
// stakpak 0.3.88 on WSL (Ubuntu) and Windows 11, 2026-10-21; the full
// research record is docs/stakpak-adapter.md.
//
// # Storage
//
// With NO Stakpak API key on the active profile, Stakpak persists every
// session in one local SQLite database under its data home, identically on
// every OS:
//
//   - Linux/macOS: ~/.stakpak/data/local.db
//   - Windows:     %USERPROFILE%\.stakpak\data\local.db
//
// (`stakpak sessions list` prints "Backend: local (<that path>)"; its own
// help says the session commands use the Stakpak API when the profile has
// an API key and the local SQLite store otherwise. A keyed profile keeps
// transcripts SERVER-SIDE, so this adapter only sees keyless/BYOK local
// profiles. That is a documented scope limit, not a bug.) The watch root
// is the `data` directory, discovered across every cross-mount-resolved
// home so a WSL2 observer reaches a Windows-side store and vice-versa. The
// database runs in WAL mode; the -wal/-shm siblings are watched and mapped
// back to the main .db, and a foreign-mount source is mirrored locally
// before open (modernc.org/sqlite hits SQLITE_IOERR against a DrvFs path
// the vendor is actively writing).
//
// # Store shape (live-verified 2026-10-21, schema migrations 1 and 2)
//
//   - sessions(id, title, agent_id, visibility, status, cwd, created_at,
//     updated_at). `id` is a UUID — exactly what `stakpak -s <id>` /
//     `stakpak sessions show <id>` accept, so it is the canonical session
//     id. `cwd` is the RAW OS path (a `C:\...` string on Windows).
//     `title` is the first prompt's head; `agent_id` is NULL locally.
//   - checkpoints(id, session_id, status, execution_depth, parent_id,
//     state, created_at, updated_at). One checkpoint per agent step, a
//     parent_id chain (a tree when a session is resumed at an older
//     checkpoint with `-c`). `state` is JSON {"messages":[...]} holding
//     the WHOLE OpenAI-chat-shaped conversation up to that step
//     (role/content/tool_calls/tool_call_id), so every checkpoint repeats
//     all earlier messages. `status` / `execution_depth` are NULL locally.
//
// # Incremental parse
//
// Neither table carries a per-message timestamp or id, so the unit of
// work is the checkpoint: the messages a checkpoint ADDS are
// messages[len(parent.messages):], and the checkpoint's own created_at
// stamps them. The persisted cursor is a rowid watermark
// (MAX(checkpoints.rowid)), not a byte offset. Each parse decodes only
// the checkpoints past the watermark and learns the parent's length in
// SQL (json_array_length), so a long session is never re-decoded.
//
// # Token capture
//
// The step's LAST message (the assistant response) carries
// usage{prompt_tokens, completion_tokens, total_tokens}; Stakpak strips
// `usage` from earlier messages in later checkpoints, so a delta scan
// sees each call's usage exactly once. That is ONE per-call TokenEvent
// keyed by the checkpoint id. prompt_tokens is the provider's prompt size
// and no cache split was present in any live capture, so it is recorded
// as plain input. The vendor binary also defines an optional
// usage.prompt_tokens_details{input_tokens, output_tokens,
// cache_read_input_tokens, cache_write_input_tokens} (never observed
// live); when present, input_tokens is taken as the NET input and the
// cache fields are recorded, otherwise the GROSS prompt_tokens is
// reduced by whatever cache counts exist (clamped at zero).
//
// # Model
//
// The store records NO model: neither the checkpoint state nor the session
// row names one (the active model comes from the profile `model`,
// `--model` or STAKPAK_MODEL at run time and is never persisted). The
// adapter therefore leaves Model empty, and decodes a per-message `model`
// field only if a future build writes one (the vendor binary's message
// struct names it; no live capture has it). Cost is not estimated for an
// unnamed model.
//
// # Tool taxonomy and sub-agents
//
// Tools reach the model as `stakpak__<name>` (the namespace of Stakpak's
// own tool server); the namespace is stripped to the native name
// (view, create, str_replace, remove, run_command, ...). The sub-agent
// spawn (`dynamic_subagent_task`) is classified ActionSpawnSubagent only:
// the child runs as a separate background process whose transcript was not
// available on any grounding run, so the spawn is visible but the child's
// work is not attributed back (checklist 7.1, mechanism 3).
//
// # Version, session start, transcript
//
// No file records a per-session version; the installed binary's compiled-in
// `stakpak v<semver> (...)` banner is read (never executed) from the store
// home's .local/bin or .cargo/bin and stamped on every session as an
// install-level SessionToolVersion (version.go, memoized per binary). The
// root checkpoint of a session yields a session_start row stamped from
// sessions.created_at. ReadTranscript / ReadTranscriptFull (transcript.go)
// re-read the newest checkpoint's cumulative message list for session
// handoff. The session's git branch is resolved from its cwd and stamped on
// every row.
//
// # Off-limits
//
// ~/.stakpak/config.toml (profile api_key / provider auth),
// ~/.stakpak/auth.toml (OAuth credentials), the project-local
// .stakpak/session/** backup tree, ~/.stakpak/knowledge/** (agent notes)
// and ~/.stakpak/autopilot/** are NEVER read; everything the adapter
// needs is in data/local.db.
package stakpak
