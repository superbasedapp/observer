// Package ibmbob implements a SQLite-store adapter for IBM Bob's terminal
// agent ("Bob Shell", npm package `bobshell`, binary `bob`). Live-grounded
// against bobshell 2.0.6 (release commit 88346061a) on WSL Ubuntu and on
// Windows 11, 2026-10-21. See docs/ibmbob-adapter.md for the full Phase 0
// research note.
//
// # Storage
//
// Bob Shell keeps every task (= session) in ONE WAL SQLite store per home,
// at the same relative path on every OS (the vendor code is
// path.join(os.homedir(), ".bob", "db", "bob.db"); a development build
// writes ".bob/dev-db/bob.db" instead and is not watched):
//
//   - Linux / macOS / WSL: ~/.bob/db/bob.db
//   - Windows:             %USERPROFILE%\.bob\db\bob.db
//
// The watch root is the enclosing `db` directory, discovered across every
// cross-mount-resolved home so a WSL observer reaches the Windows store
// and vice-versa. The WAL siblings (bob.db-wal / -shm) are watched and
// mapped back to the main .db; a foreign-mount source is mirrored locally
// before open, the same staging the goose / crush / devin adapters use.
//
// # Store shape (live-grounded 2026-10-21)
//
//   - tasks(id TEXT 32-hex, project_id "file:<workspace>", parent_id,
//     title, status, first_message, directory (written ""), version
//     (written NULL), git_sha, git_branch, env JSON, costs JSON,
//     created_at / updated_at epoch MILLISECONDS, task_type
//     normal|subtask|subagent, ...). tasks.id is exactly what
//     `bob --resume <id>` accepts and is the canonical SessionID. env holds
//     workspace, staticEnvInfo.systemInfo, model {id, contextWindow, ...},
//     modeId and the current todo list. Bob creates an EMPTY placeholder
//     task on every launch before the first prompt; it has no messages and
//     emits nothing.
//   - messages(id TEXT 32-hex, task_id, role system|user|assistant|tool,
//     data JSON, created_at). created_at is the SAVE time (a whole turn is
//     written with one value), so the true per-message time is
//     data._meta.timestamp (epoch ms); rows are ordered by (created_at,
//     rowid), the insertion order Bob itself replays.
//
// Each message's data is one of:
//
//   - user: {content, envContext, availableTools, _meta:{mode, timestamp}}.
//     envContext is Bob's injected <environment_details> block and is never
//     recorded as the prompt.
//   - assistant: {content, toolCalls:[{id, name, arguments}], stop,
//     _meta:{timestamp, spend:{cost, contextTokens}}}.
//   - tool: {content, toolUsage:{signature:{id, name, arguments, isError},
//     permission, ...}, _meta:{exitCode, durationMs, timestamp, ...}} — the
//     paired tool RESULT, consumed into the tool call it answers.
//   - system: the system prompt. Not emitted.
//
// # Token capture — none (vendor strips the split)
//
// Bob's provider callback computes a full per-call usage bundle {input,
// output, cacheRead, cacheWrite, reasoningTokens, cost, contextTokens}, but
// the production persistence path strips input / output / cacheRead /
// cacheWrite / reasoningTokens before writing (the vendor's own serializer
// keeps them only in a developer-keyed build). What survives on disk is
// spend.contextTokens (= input + output of that call, unsplit) and
// spend.cost, which is denominated in Bobcoins (IBM Bob's credit unit), NOT
// US dollars. Neither can honestly fill a TokenEvent: an unsplit total
// cannot be priced and Bobcoins are not EstimatedCostUSD. This adapter
// therefore emits NO TokenEvents; per-call token truth would need the
// proxy route (BOB_GATEWAY_URL), which is not live-verified. No per-turn
// cache counts exist on disk, so Tier-2 cache observation is impossible.
//
// # Subagents (§7.1: SessionLineage)
//
// spawn_subagent creates a SEPARATE tasks row (task_type subagent,
// parent_id = the spawning task) with its own messages; the tool result's
// _meta.subagentId names it. The child is emitted as its own session and
// linked to the parent with a models.SessionLineage (ThreadSource
// "subagent"); the spawn call itself is ActionSpawnSubagent. Grounded from
// the store DDL and the vendor code; the operator sessions spawned no
// subagent.
//
// # Per-event dimensions (2026-10-21 parity round)
//
//   - Permission mode: tasks.approval_config {autoApprovalEnabled,
//     allowed_permissions} -> Metadata.PermissionMode ("auto:read+todo+
//     edit+execute" / "auto:read" / "ask"); the mode Bob runs in (env.modeId,
//     then the latest _meta.mode.id, so a switch_mode shows on later rows)
//     -> Metadata.CollaborationMode. Per-task command approvals name
//     commands and are never recorded.
//   - Tool version: tasks.version when a build records one (NULL on every
//     grounded 2.0.6 row), else the install-level `bobShell.lastRunVersion`
//     of the sibling settings/settings.json (operator ruling 2026-10-21: stamp
//     every session). Only that key is decoded.
//   - Git branch: tasks.git_branch, else the resolved project identity's
//     branch.
//   - tasks.last_error ({name, category, message, data}; the JSON text
//     "null" when clear) -> one failed action keyed on a hash of the error
//     JSON: turn_aborted for a hook-blocked prompt (such a task has NO
//     message rows, so this row is the session's only trace), api_error
//     otherwise.
//   - Compaction: the assistant message flagged _meta.summary + notAi
//     becomes ActionContextCompacted (size only, not the summary text).
//   - Stop: assistant `stop: true` -> Metadata.StopReason "end_turn".
//   - Attachments: message-level `images` (vendor TaskMessage.images) and
//     image/file parts of array-form content -> UserAttachments (kind +
//     media type only). Vendor-code grounded, no live row.
//   - Reasoning: the assistant `reasoning` field (vendor-code grounded; the
//     premium-ide tier emits none) -> PrecedingReasoning.
//   - TurnIndex: 1-based user-prompt ordinal; child tasks flag
//     Metadata.IsSubagent / ParentSessionID.
//
// # Account identity (operator ruling 2026-10-21)
//
// Bob Shell's per-process debug log (~/.bob/logs/shell/bob-shell-<ts>.log,
// NDJSON) records an SSO sign-in as module "Auth", msg "Login successful",
// data = the login's userId, which is the signed-in e-mail on every
// grounded install; later launches log "Restored session from stored
// tokens" (no e-mail) and a sign-out logs "Logged out". No line names a
// task, so account.go builds a per-home sign-in timeline and binds the
// e-mail in force at each message's time to that message (BindingKind
// "message", user prompts "submission", everything else "activity";
// Source ibm_bob_shell_log, Scope login_log). It is PERSON-level evidence
// (Email, not the account-level marker): Normalize refuses an account-level
// row with an e-mail, and an e-mail as AccountID would ship an enumerable
// key under the metadata-only org posture (PRIV-1). Bob keeps only its 10
// newest logs, so the login line disappears ten launches after the
// sign-in; the adapter's log cache keeps events from deleted logs for the
// daemon's lifetime, and a daemon that starts after the line is gone binds
// nothing.
//
// # Exact LOC (internal/loc ShapeBobChanges)
//
// An edit/write result's _meta.changes maps each touched file URI to
// {before, after, patch}. For edit_file / write_file actions the adapter
// adds the patch, reduced to its +/- lines with each context run replaced
// by a bare "@@" separator, to RawToolInput under loc.BobChangesKey
// (changes.go); the LOC ladder counts that instead of estimating from the
// arguments. before/after (whole-file images) are never decoded. A payload
// that would exceed the raw-input cap only with the record keeps the plain
// arguments.
//
// # Session handoff
//
// ReadTranscript re-reads one task's messages (user prompts, assistant text,
// tool calls paired with their results; the compaction summary is kept,
// system prompts / hidden replays / harness notices are dropped).
//
// # Effort (§7.2): structural-absent
//
// The runtime carries a reasoningEffort, but it is never persisted in
// tasks.env or any message, so there is nothing to capture.
//
// # Off-limits
//
// ~/.bob/settings/auth-secrets.json (login tokens) is NEVER read.
// settings.json is read for the single key bobShell.lastRunVersion;
// logs/shell/bob-shell-*.log is read for its Auth sign-in / sign-out lines
// only (account.go); mcp.json and trustedFolders.json are not read.
// Everything else the adapter needs is in bob.db.
package ibmbob
