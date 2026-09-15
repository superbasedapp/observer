package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/adapter/antigravity"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/adapter/codex"
	"github.com/marmutapp/superbased-observer/internal/adapter/cowork"
	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/adapter/opencode"
	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// newBackfillCmd implements `observer backfill` — re-process historical
// JSONL data to populate columns added by later migrations on rows that
// were ingested before the migration shipped.
//
// Supported dimensions:
//
//	--is-sidechain    Migration 010 added is_sidechain to actions; the
//	                  JSONL adapter now copies isSidechain per line for
//	                  new ingests, but pre-migration rows default to 0.
//	                  Walks Claude Code session logs and UPDATEs the
//	                  matching action rows by (source_file,
//	                  source_event_id) where the stored value still
//	                  reads 0.
//
//	--cache-tier      Migration 008 added cache_creation_1h_tokens to
//	                  token_usage and api_turns. Pre-migration rows have
//	                  NULL in the new column, which the cost engine
//	                  treats as 0 → "all 5m tier" → silently under-bills
//	                  1h cache writes (Anthropic's 2× tier vs 1.25× for
//	                  5m). This pass extracts
//	                  usage.cache_creation.ephemeral_1h_input_tokens
//	                  per Anthropic message id and UPDATEs both tables
//	                  by (session_id, source_event_id / request_id)
//	                  where cache_creation_1h_tokens IS NULL.
//
//	--message-id      Migration 012 added message_id to actions and
//	                  token_usage. The new column is the natural unit
//	                  for grouping tool calls and token usage by the
//	                  upstream Anthropic message that produced them
//	                  (msg_xxx). Pre-migration rows have NULL; this
//	                  pass extracts line.message.id per JSONL line and
//	                  UPDATEs both tables by (session_id, source_event_id)
//	                  trying both message.id and per-line uuid as keys.
//
//	--all             Convenience: equivalent to --is-sidechain
//	                  --cache-tier --message-id.
//
// All flags can run in the same invocation. Idempotent — safe to run
// multiple times; UPDATEs are no-ops when the stored value already
// matches the JSONL.
func newBackfillCmd() *cobra.Command {
	var (
		configPath             string
		isSidechain            bool
		cacheTier              bool
		messageID              bool
		opencodeMessageID      bool
		opencodeParts          bool
		opencodeTokens         bool
		openclawActionTypes    bool
		openclawModel          bool
		openclawProjectRoot    bool
		openclawReasoning      bool
		openclawSessionID      bool
		codexReasoning         bool
		codexProjectRoot       bool
		claudecodeProjectRoot  bool
		antigravityProjectRoot bool
		cursorModel            bool
		sessionModels          bool
		copilotMessageID       bool
		piMessageID            bool
		claudecodeUserPrompts  bool
		claudecodeAPIErrors    bool
		cursorUserPrompts      bool
		cursorSubagents        bool
		coworkRescan           bool
		coworkProjectRoot      bool
		codexRescan            bool
		antigravityRescan      bool
		antigravityCliRescan   bool
		geminiCliRescan        bool
		copilotCliRescan       bool
		hermesRescan           bool
		clinecliRescan         bool
		cacheRescan            bool
		content                bool
		zedRescan              bool
		tasksRescan            bool
		codexForkDedup         bool

		reasoningConverge        bool
		reasoningConvergeDiscard bool

		codexToolInput bool

		locBackfill bool
		locSince    string
		locRescan   bool
		locDryRun   bool
		locLimit    int
		locSessions []string

		apply   bool
		all     bool
		dryRun  bool
		jsonOut bool
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "Re-populate columns added by later migrations / parity passes on pre-existing rows",
		Long: `Re-walks platform session files (Claude Code JSONL, Codex rollouts,
OpenCode SQLite, OpenClaw mixed formats, Cursor hook logs) and updates
the actions / token_usage / api_turns tables for rows that were
ingested before a later migration or adapter parity fix.

After upgrading the binary, run ` + "`observer backfill --all`" + ` once to bring
historical data up to current. The command is idempotent — re-running
is safe; matched rows that already carry the new value are no-ops.

Flags are grouped below by lifespan — see
docs/backfill-flag-audit-2026-05-19.md for the full per-flag
classification.

  ┌─ Schema migration backfills ────────────────────────────────────┐
  │  Run once per install. Backfill columns added by a migration   │
  │  on rows ingested before that migration shipped.               │
  └─────────────────────────────────────────────────────────────────┘
    --is-sidechain    actions.is_sidechain (migration 010)
    --cache-tier      token_usage / api_turns.cache_creation_1h_tokens
                      (migration 008)
    --message-id      actions / token_usage.message_id (migration 012);
                      umbrella covering claudecode + codex + cursor +
                      opencode (granular variants below).

  ┌─ Cross-mount project-root reattribution ───────────────────────┐
  │  WSL2 users who captured Windows-side sessions before the      │
  │  corresponding fix shipped: each pass re-resolves cwd through  │
  │  crossmount.TranslateForeignPath so sessions.project_id lands  │
  │  on the right project (pre-fix every Windows row attributed    │
  │  to the observer's own repo).                                  │
  └─────────────────────────────────────────────────────────────────┘
    --codex-project-root        (v1.4.28)
    --claudecode-project-root   (v1.6.10 audit B1)
    --openclaw-project-root     (v1.6.14 audit B3)
    --antigravity-project-root  (also lifts model + token_usage from
                                 state.vscdb when network_recovery="local")
    --cowork-project-root       (v1.4.54)

  ┌─ Per-adapter rescan catch-alls ────────────────────────────────┐
  │  Re-walk an adapter's tree to pick up parser additions or fill │
  │  in an adapter newly added to enabled_adapters. Equivalent to  │
  │  ` + "`observer scan --force --adapter=X`" + ` but discoverable from the   │
  │  dashboard Backfill UI.                                        │
  └─────────────────────────────────────────────────────────────────┘
    --cowork-rescan
    --codex-rescan         (picks up v1.4.53+ adapter additions)
    --antigravity-rescan   (local decrypt + gRPC fallback)
    --gemini-cli-rescan    (gemini-cli's only retroactive path)
    --copilot-cli-rescan   (run after ` + "`copilot --log-level debug`" + `)
    --cache-rescan         (re-emit cache_segments / cache_entries /
                            cache_events through the Tier-2 cache
                            engine — claude-code transcripts only
                            today; widens with §14.3 C21-C24)
    --content              Re-walk EVERY adapter's transcripts through the
                            adapter-side message-content producer
                            (store.captureMessageContent) to backfill
                            otel_content for sessions ingested before the
                            producer shipped. Gated exactly like live
                            capture — [org_client.share] full_content /
                            admin_managed AND [ingest.otel]
                            content_capture — and a no-op with an honest
                            message naming the blocking key when either is
                            off. Idempotent via otel_content's
                            (content_hash, kind, request_id, tool_use_id)
                            UNIQUE key. NOT included in --all's flag
                            composition: --all's own top-level full rescan
                            already re-derives content as a side effect of
                            wireContentCapture being unconditional, so
                            adding --content there would just re-walk every
                            adapter a second time. Use --content standalone
                            when you've just turned content sharing on and
                            want ONLY the content backfill, without
                            re-running every other --all pass.
    --zed-rescan           (threads.db is a watermark store — a thread
                            that predates the daemon first seeing its
                            file is never re-read until its next turn;
                            this forces every thread to re-emit)

  ┌─ Historical adapter-parity passes ─────────────────────────────┐
  │  One-shot fixes for specific corpus gaps. Likely 0 rows on any │
  │  install made after their introducing release; kept for audit  │
  │  trail. Run via --all post-upgrade and ignore the "0 updated". │
  └─────────────────────────────────────────────────────────────────┘
    --opencode-message-id    Granular split of --message-id (opencode)
    --opencode-parts         Re-read opencode.db parts for tool_output /
                             duration_ms / message_id on tool/subtask rows
    --opencode-tokens        Re-run adapter for missing token_usage rows
    --openclaw-action-types  Retag historical 'sessions_spawn' from
                             mcp_call → spawn_subagent, plus newly-
                             classified process/canvas/etc rows
    --openclaw-model         Lift model from sessions.json aliases
    --openclaw-session-id    Collapse raw sessionId split rows onto the
                             alias/session-key form
    --openclaw-reasoning     Walk JSONL for preceding_reasoning on tools
    --codex-reasoning        Walk codex rollouts for preceding_reasoning
    --cursor-model           Copy model from matching token_usage row
                             onto cursor action rows
    --copilot-message-id     Granular split of --message-id (copilot)
    --pi-message-id          Granular split of --message-id (pi)
    --claudecode-user-prompts  Insert missing user_prompt action rows
    --claudecode-api-errors    Insert api_error rows (pre-v1.4.20)
    --cursor-user-prompts      Insert user_prompt rows (pre-beforeSubmitPrompt)
    --cursor-subagents         Walk agent-transcripts/<sid>/subagents/

  ┌─ Destructive one-shot cleanups ────────────────────────────────┐
  │  DRY-RUN BY DEFAULT — report only; pass --apply to mutate.     │
  │  NOT run by --all.                                             │
  └─────────────────────────────────────────────────────────────────┘
    --codex-fork-dedup   Purge duplicate codex token_usage rows a
                         fork / subagent spawn created by replaying
                         its parent rollout's token_count telemetry.
                         Dry run reports matched rows / tokens /
                         sessions; --apply DELETEs them (idempotent)
                         and backfills session fork lineage.
    --reasoning-converge Converge the B3 reasoning residue: carry each
                         surviving reasoning task_complete row's text
                         onto its successor's preceding_reasoning, then
                         delete the row (migration 079's dependency
                         protocol). Dry run reports per-tool counts and
                         which rows it will NOT delete because their
                         text would be destroyed; --apply mutates.
    --codex-tool-input   Re-derive raw_tool_input for the codex-family
                         rows genuinely MISSING one, by re-reading the
                         rollout files. Grounded per action_type: the
                         assistant_message / task_complete /
                         turn_aborted / session_start rows legitimately
                         have NO input and are reported in their own
                         bucket, never written to. Joins on
                         source_event_id = the record's call_id. Never
                         overwrites, never invents; --apply mutates.

  ┌─ Convenience / utility ────────────────────────────────────────┐
  └─────────────────────────────────────────────────────────────────┘
    --all       Run every backfill in one invocation (recommended
                after upgrading).
    --dry-run   Snapshot the live DB via VACUUM INTO, run every
                requested backfill against the snapshot, report
                row counts that WOULD have updated the live DB,
                then delete the snapshot. Live DB untouched. Use
                this to audit whether a historical-parity flag
                still updates any rows on your corpus before
                running it for real, or to spot which flags
                report 0 (candidates for removal). See
                docs/backfill-flag-audit-2026-05-19.md §3.
    --json      Emit machine-readable summary.
    --limit N   Stop after N source files per JSONL-walking pass.

Run ` + "`observer backfill --all`" + ` after each binary upgrade to keep
historical rows in sync with the latest schema and adapter behaviour.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if all {
				coworkProjectRoot = true
				isSidechain = true
				cacheTier = true
				messageID = true
				opencodeMessageID = true
				opencodeParts = true
				opencodeTokens = true
				openclawActionTypes = true
				openclawModel = true
				openclawProjectRoot = true
				openclawReasoning = true
				openclawSessionID = true
				codexReasoning = true
				codexProjectRoot = true
				claudecodeProjectRoot = true
				antigravityProjectRoot = true
				cursorModel = true
				sessionModels = true
				copilotMessageID = true
				piMessageID = true
				claudecodeUserPrompts = true
				claudecodeAPIErrors = true
				cursorUserPrompts = true
				cursorSubagents = true
				codexRescan = true
				antigravityRescan = true
				antigravityCliRescan = true
				geminiCliRescan = true
				copilotCliRescan = true
				hermesRescan = true
				clinecliRescan = true
				cacheRescan = true
				zedRescan = true
				tasksRescan = true
			}
			if !isSidechain && !cacheTier && !messageID &&
				!opencodeMessageID && !opencodeParts && !opencodeTokens &&
				!openclawActionTypes && !openclawModel && !openclawProjectRoot && !openclawReasoning && !openclawSessionID &&
				!codexReasoning && !codexProjectRoot && !claudecodeProjectRoot && !antigravityProjectRoot && !cursorModel && !sessionModels &&
				!copilotMessageID && !piMessageID &&
				!claudecodeUserPrompts && !claudecodeAPIErrors &&
				!cursorUserPrompts && !cursorSubagents && !coworkRescan && !coworkProjectRoot && !codexRescan &&
				!antigravityRescan && !antigravityCliRescan && !geminiCliRescan && !copilotCliRescan && !hermesRescan && !clinecliRescan && !cacheRescan && !zedRescan &&
				!content && !tasksRescan &&
				!codexForkDedup && !reasoningConverge && !codexToolInput && !locBackfill {
				return fmt.Errorf("nothing to backfill — pass one of the dimension flags or --all")
			}

			// --dry-run: snapshot the live DB and re-point every
			// downstream config.Load call at the snapshot via the
			// OBSERVER_OBSERVER_DB_PATH env override. The backfill
			// then runs normally — same code path, same row-count
			// reports — but mutates only the snapshot. Cleanup
			// removes the snapshot file (+ its WAL/SHM siblings) and
			// restores the prior env. The "rows updated" counts in
			// the final summary represent what WOULD apply to the
			// live DB.
			if dryRun {
				snapshotPath, dryRunCleanup, err := setupBackfillDryRun(cmd.Context(), configPath, cmd.OutOrStdout())
				if err != nil {
					return fmt.Errorf("--dry-run: %w", err)
				}
				defer dryRunCleanup()
				_ = snapshotPath // referenced via env override; defer cleans up.
			}

			// --message-id is the umbrella for adapter message-id work; it
			// drives the opencode + copilot + pi passes too so users only
			// need the one flag for routine use. The granular flags stay
			// for targeted re-runs.
			if messageID {
				opencodeMessageID = true
				copilotMessageID = true
				piMessageID = true
			}

			summary := struct {
				Rescan                 *watcher.ScanResult             `json:"rescan,omitempty"`
				IsSidechain            *BackfillResult                 `json:"is_sidechain,omitempty"`
				CacheTier              *CacheTierBackfill              `json:"cache_tier,omitempty"`
				MessageID              *MessageIDBackfill              `json:"message_id,omitempty"`
				OpenCodeMessageID      *MessageIDBackfill              `json:"opencode_message_id,omitempty"`
				OpenCodeParts          *OpenCodePartsBackfill          `json:"opencode_parts,omitempty"`
				OpenCodeTokens         *OpenCodeTokensBackfill         `json:"opencode_tokens,omitempty"`
				OpenClawActionTypes    *OpenClawActionsBackfill        `json:"openclaw_action_types,omitempty"`
				OpenClawModel          *OpenClawModelBackfill          `json:"openclaw_model,omitempty"`
				OpenClawProjectRoot    *OpenClawProjectRootBackfill    `json:"openclaw_project_root,omitempty"`
				OpenClawReasoning      *OpenClawReasoningBackfill      `json:"openclaw_reasoning,omitempty"`
				OpenClawSessionID      *OpenClawSessionIDBackfill      `json:"openclaw_session_id,omitempty"`
				CodexReasoning         *CodexReasoningBackfill         `json:"codex_reasoning,omitempty"`
				CodexProjectRoot       *CodexProjectRootBackfill       `json:"codex_project_root,omitempty"`
				ClaudeCodeProjectRoot  *ClaudeCodeProjectRootBackfill  `json:"claudecode_project_root,omitempty"`
				CoworkProjectRoot      *CoworkProjectRootBackfill      `json:"cowork_project_root,omitempty"`
				AntigravityProjectRoot *AntigravityProjectRootBackfill `json:"antigravity_project_root,omitempty"`
				CursorModel            *CursorModelBackfill            `json:"cursor_model,omitempty"`
				SessionModels          *SessionModelsBackfill          `json:"session_models,omitempty"`
				CopilotMessageID       *MessageIDBackfill              `json:"copilot_message_id,omitempty"`
				PiMessageID            *MessageIDBackfill              `json:"pi_message_id,omitempty"`
				ClaudeCodeUserPrompts  *ClaudeCodeUserPromptsBackfill  `json:"claudecode_user_prompts,omitempty"`
				ClaudeCodeAPIErrors    *ClaudeCodeAPIErrorsBackfill    `json:"claudecode_api_errors,omitempty"`
				CursorUserPrompts      *CursorUserPromptsBackfill      `json:"cursor_user_prompts,omitempty"`
				CursorSubagents        *CursorSubagentsBackfill        `json:"cursor_subagents,omitempty"`
				CodexForkDedup         *CodexForkDedupBackfill         `json:"codex_fork_dedup,omitempty"`
				ReasoningConverge      *ReasoningConvergeBackfill      `json:"reasoning_converge,omitempty"`
				CodexToolInput         *ToolInputBackfill              `json:"codex_tool_input,omitempty"`
				Content                *ContentRescanBackfill          `json:"content,omitempty"`
				LOC                    *LOCBackfillReport              `json:"loc,omitempty"`
				Tasks                  *store.TaskBackfillResult       `json:"tasks,omitempty"`
			}{}

			// --all kicks a full rescan from offset 0 BEFORE the surgical
			// backfills. This is the recovery path for when the live
			// watcher fell behind silently (fsnotify event drops, daemon
			// restart with stale parse_cursors, etc.) — without this,
			// missing assistant tool-call rows would never re-ingest.
			// Surgical backfills only update specific columns on rows
			// that already exist; they don't insert anything new.
			if all {
				w, wCleanup, err := buildWatcher(cmd.Context(), configPath)
				if err != nil {
					return fmt.Errorf("--all rescan: %w", err)
				}
				rescanRes, rescanErr := w.Rescan(cmd.Context())
				wCleanup()
				if rescanErr != nil {
					return fmt.Errorf("--all rescan: %w", rescanErr)
				}
				summary.Rescan = &rescanRes
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"rescan complete: files_processed=%d errors=%d (re-walked every JSONL from offset 0; (source_file, source_event_id) UNIQUE keeps it idempotent)\n",
						rescanRes.FilesProcessed, rescanRes.Errors,
					)
				}
			}

			// Per-adapter rescan catch-alls: scope the watcher to a
			// single adapter (buildWatcherWithOverride's adapterFilter)
			// and re-walk it from offset 0 via w.Rescan. Every one of
			// these shares the identical shape — build, rescan, cleanup,
			// report files/errors, land the (first-wins) result under
			// summary.Rescan — so they're driven off one table instead
			// of a growing copy-paste ladder (CLAUDE.md "Module
			// Boundaries & Anti-Spaghetti Discipline" #5). Adding a new
			// adapter's dedicated rescan flag is one row here (plus the
			// cobra flag registration + optional --all wiring below);
			// see rescan_flag_audit_test.go for the pin that keeps the
			// per-flag stdout/error text byte-identical to the pre-
			// refactor ladder.
			rescanPasses := buildRescanPasses(
				&coworkRescan, &codexRescan, &antigravityRescan, &antigravityCliRescan,
				&geminiCliRescan, &copilotCliRescan, &hermesRescan, &clinecliRescan,
				&cacheRescan, &zedRescan,
			)
			for _, p := range rescanPasses {
				if !*p.enabled {
					continue
				}
				w, wCleanup, err := buildWatcherWithOverride(cmd.Context(), configPath, p.adapter)
				if err != nil {
					return fmt.Errorf("%s: %w", p.flag, err)
				}
				rescanRes, rescanErr := w.Rescan(cmd.Context())
				wCleanup()
				if rescanErr != nil {
					return fmt.Errorf("%s: %w", p.flag, rescanErr)
				}
				if summary.Rescan == nil {
					summary.Rescan = &rescanRes
				}
				if !jsonOut {
					fmt.Fprint(cmd.OutOrStdout(), p.summaryLine(rescanRes))
				}
			}

			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			// --tasks: re-derive task_items/task_transitions
			// (docs/task-tracking.md) from actions rows already in the
			// DB — a pure re-read of raw_tool_input/raw_tool_output,
			// no adapter re-parse, no source-file walk (the "surgical
			// column backfill" lane). Ignores [tasks].enabled — the
			// operator explicitly asked for this pass. Idempotent:
			// re-running applies the same upserts and INSERT OR IGNORE
			// transitions, so a repeat run writes zero new rows.
			if tasksRescan {
				res, err := store.New(database).BackfillTaskItems(cmd.Context(), limit)
				if err != nil {
					return fmt.Errorf("--tasks: %w", err)
				}
				summary.Tasks = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"tasks backfill complete: scanned %d todo_update/post_tool_batch action rows; wrote %d new transitions\n",
						res.ActionsScanned, res.TransitionsWritten,
					)
				}
			}

			// --content: re-walk EVERY adapter's transcripts through the
			// adapter-side message-content producer
			// (store.captureMessageContent, wired unconditionally by
			// buildWatcher via wireContentCapture) so historical
			// sessions — ingested before the producer shipped
			// (263a3cadc), or before this node turned content sharing
			// on — get otel_content rows too.
			//
			// This reuses the SAME Rescan -> Ingest -> captureMessageContent
			// chain --all's own top-level rescan already drives
			// (CLAUDE.md #4: one owner, InsertOTelContent, reached
			// through two feed paths — live watcher ingest and this
			// rescan). No new store export was needed: Store.Ingest was
			// already exported and the producer is already keyed to be
			// idempotent on re-parse via otel_content's
			// (content_hash, kind, request_id, tool_use_id) UNIQUE key,
			// so this is a thin CLI composition, not a duplicated
			// implementation.
			//
			// Gated exactly like live capture, checked BEFORE building a
			// watcher: when the gate is off this is an honest no-op that
			// names the exact blocking config key (never a silent
			// "0 rows"), per the honest-disabled-copy convention.
			if content {
				gateCfg, gateErr := config.Load(config.LoadOptions{GlobalPath: configPath})
				if gateErr != nil {
					return fmt.Errorf("--content: %w", gateErr)
				}
				if reason := contentCaptureBlockReason(gateCfg); reason != "" {
					summary.Content = &ContentRescanBackfill{Skipped: true, SkipReason: reason}
					if !jsonOut {
						fmt.Fprintf(cmd.OutOrStdout(), "content backfill skipped: %s\n", reason)
					}
				} else {
					w, wCleanup, err := buildWatcher(cmd.Context(), configPath)
					if err != nil {
						return fmt.Errorf("--content: %w", err)
					}
					rescanRes, rescanErr := w.Rescan(cmd.Context())
					wCleanup()
					if rescanErr != nil {
						return fmt.Errorf("--content: %w", rescanErr)
					}
					if summary.Rescan == nil {
						summary.Rescan = &rescanRes
					}
					summary.Content = &ContentRescanBackfill{
						FilesProcessed: rescanRes.FilesProcessed,
						Errors:         rescanRes.Errors,
					}
					if !jsonOut {
						fmt.Fprintf(
							cmd.OutOrStdout(),
							"content rescan complete: files_processed=%d errors=%d (every adapter's transcripts through the message-content producer; idempotent via otel_content's UNIQUE key)\n",
							rescanRes.FilesProcessed, rescanRes.Errors,
						)
					}
				}
			}

			if isSidechain {
				res, err := backfillIsSidechain(cmd.Context(), database, claudeProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.IsSidechain = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"is_sidechain backfill complete: scanned %d files, %d sidechain lines, updated %d rows (skipped %d unmatched)\n",
						res.FilesScanned, res.SidechainLines, res.RowsUpdated, res.UnmatchedLines,
					)
				}
			}
			if cacheTier {
				res, err := backfillCacheTier(cmd.Context(), database, claudeProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.CacheTier = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"cache-tier backfill complete: scanned %d files, %d msg-id rows examined, updated %d token_usage rows + %d api_turns rows (1h tokens recovered: %d)\n",
						res.FilesScanned, res.MsgIDsExamined, res.TokenUsageUpdated, res.APITurnsUpdated, res.TokensRecovered,
					)
				}
			}
			if messageID {
				res, err := backfillMessageID(cmd.Context(), database, claudeProjectsDir(), limit)
				if err != nil {
					return err
				}
				codexRes, err := backfillCodexMessageID(cmd.Context(), database, codexSessionsDir(), limit)
				if err != nil {
					return err
				}
				cursorRes, err := backfillCursorMessageID(cmd.Context(), database)
				if err != nil {
					return err
				}
				cursorUsageRes, err := backfillCursorHookUsage(cmd.Context(), database, cursorLogsDir(), limit)
				if err != nil {
					return err
				}
				res.FilesScanned += codexRes.FilesScanned
				res.LinesExamined += codexRes.LinesExamined
				res.ActionsUpdated += codexRes.ActionsUpdated
				res.TokenUsageUpdated += codexRes.TokenUsageUpdated
				res.ActionsUpdated += cursorRes.ActionsUpdated
				res.FilesScanned += cursorUsageRes.FilesScanned
				res.LinesExamined += cursorUsageRes.LinesExamined
				res.TokenUsageUpdated += cursorUsageRes.TokenUsageUpdated
				cursorTranscriptRes, err := backfillCursorTranscriptActions(cmd.Context(), database, cursorProjectsDir(), limit)
				if err != nil {
					return err
				}
				res.FilesScanned += cursorTranscriptRes.FilesScanned
				res.LinesExamined += cursorTranscriptRes.LinesExamined
				res.ActionsUpdated += cursorTranscriptRes.ActionsUpdated
				summary.MessageID = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"message-id backfill complete: scanned %d files, %d lines examined, updated %d action rows + %d token_usage rows\n",
						res.FilesScanned, res.LinesExamined, res.ActionsUpdated, res.TokenUsageUpdated,
					)
				}
			}

			if opencodeMessageID {
				res, err := backfillOpenCodeMessageID(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.OpenCodeMessageID = &res
				if !jsonOut && (res.ActionsUpdated > 0 || res.TokenUsageUpdated > 0) {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"opencode message-id backfill complete: updated %d action rows + %d token_usage rows\n",
						res.ActionsUpdated, res.TokenUsageUpdated,
					)
				}
			}
			if opencodeParts {
				res, err := backfillOpenCodeParts(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.OpenCodeParts = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"opencode-parts backfill complete: scanned %d DB(s), examined %d parts; updated tool_output=%d, duration=%d, message_id=%d\n",
						res.DBsScanned, res.PartsExamined,
						res.ToolOutputUpdated, res.DurationUpdated, res.MessageIDUpdated,
					)
				}
			}
			if opencodeTokens {
				res, err := backfillOpenCodeTokens(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.OpenCodeTokens = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"opencode-tokens backfill complete: scanned %d DB(s), extracted %d token events; inserted %d new token_usage rows\n",
						res.DBsScanned, res.TokenRowsExtracted, res.TokenRowsInserted,
					)
				}
			}
			if openclawActionTypes {
				res, err := backfillOpenClawActionTypes(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.OpenClawActionTypes = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"openclaw action-types backfill complete: %d sessions_spawn rows retagged to spawn_subagent\n",
						res.ActionsUpdated,
					)
				}
			}
			if openclawModel {
				res, err := backfillOpenClawModel(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.OpenClawModel = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"openclaw-model backfill complete: scanned %d alias file(s), %d aliases loaded; lifted model onto %d session row(s)\n",
						res.AliasFilesScanned, res.AliasesLoaded, res.SessionsUpdated,
					)
				}
			}
			if openclawSessionID {
				res, err := backfillOpenClawSessionID(cmd.Context(), database, openclawProjectRootBackfillDirs(), limit)
				if err != nil {
					return err
				}
				summary.OpenClawSessionID = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"openclaw-session-id backfill complete: scanned %d alias file(s); merged %d split session(s); updated %d action rows + %d token_usage rows; deleted %d orphan session row(s)\n",
						res.AliasFilesScanned, res.SessionRowsMerged, res.ActionsUpdated, res.TokenUsageUpdated, res.SessionsDeleted,
					)
				}
			}
			if openclawProjectRoot {
				res, err := backfillOpenClawProjectRoot(cmd.Context(), database, openclawProjectRootBackfillDirs(), limit)
				if err != nil {
					return err
				}
				summary.OpenClawProjectRoot = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"openclaw-project-root backfill complete: scanned %d file(s), %d sessions reattributed; %d action rows updated\n",
						res.FilesScanned, res.SessionsReattributed, res.ActionsUpdated,
					)
				}
			}
			if openclawReasoning {
				res, err := backfillOpenClawReasoning(cmd.Context(), database, openclawAgentsDir(), limit)
				if err != nil {
					return err
				}
				summary.OpenClawReasoning = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"openclaw-reasoning backfill complete: scanned %d files, examined %d lines; updated %d action rows\n",
						res.FilesScanned, res.LinesExamined, res.ActionsUpdated,
					)
				}
			}
			if codexReasoning {
				res, err := backfillCodexReasoning(cmd.Context(), database, codexSessionsDir(), limit)
				if err != nil {
					return err
				}
				summary.CodexReasoning = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"codex-reasoning backfill complete: scanned %d files, captured %d turn preambles; updated %d action rows\n",
						res.FilesScanned, res.TurnsCaptured, res.ActionsUpdated,
					)
				}
			}
			if codexProjectRoot {
				res, err := backfillCodexProjectRoot(cmd.Context(), database, codexProjectRootBackfillDirs(), limit)
				if err != nil {
					return err
				}
				summary.CodexProjectRoot = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"codex-project-root backfill complete: scanned %d files, %d sessions reattributed; %d action rows updated\n",
						res.FilesScanned, res.SessionsReattributed, res.ActionsUpdated,
					)
				}
			}
			if claudecodeProjectRoot {
				res, err := backfillClaudecodeProjectRoot(cmd.Context(), database, claudecodeProjectRootBackfillDirs(), limit)
				if err != nil {
					return err
				}
				summary.ClaudeCodeProjectRoot = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"claudecode-project-root backfill complete: scanned %d files, %d sessions reattributed; %d action rows updated\n",
						res.FilesScanned, res.SessionsReattributed, res.ActionsUpdated,
					)
				}
			}
			if coworkProjectRoot {
				ag := cowork.New()
				res, err := backfillCoworkProjectRoot(cmd.Context(), database, ag.WatchPaths(), limit)
				if err != nil {
					return err
				}
				summary.CoworkProjectRoot = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"cowork-project-root backfill complete: scanned %d files, %d sessions reattributed; %d action rows updated\n",
						res.FilesScanned, res.SessionsReattributed, res.ActionsUpdated,
					)
				}
			}
			if antigravityProjectRoot {
				res, err := backfillAntigravityProjectRoot(cmd.Context(), database, antigravityProjectRootBackfillDirs(), limit)
				if err != nil {
					return err
				}
				summary.AntigravityProjectRoot = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"antigravity-project-root backfill complete: scanned %d files, %d sessions reattributed; %d action rows updated; %d sessions had model/started_at refreshed; structured fetch: %d hits / %d misses, %d token rows + %d tool rows inserted, %d sessions had model lifted, %d token timestamps refreshed, %d token message_ids rewired, %d action message_ids rewired, %d markdown actions realigned to real timeline, %d markdown inline tools deduped against structured, %d markdown planner_response rows recovered\n",
						res.FilesScanned, res.SessionsReattributed, res.ActionsUpdated, res.SessionsRefreshed,
						res.StructuredFetched, res.StructuredFetchFailed,
						res.StructuredTokensInserted, res.StructuredToolsInserted,
						res.StructuredModelLifted,
						res.TokenTimestampsRefreshed, res.TokenMessageIDsRefreshed,
						res.ActionMessageIDsRefreshed,
						res.MarkdownActionsRealigned,
						res.MarkdownInlineToolsDedup,
						res.MarkdownPlannerRecovered,
					)
				}
			}
			if cursorModel {
				res, err := backfillCursorModel(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.CursorModel = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"cursor-model backfill complete: %d cursor session(s) had model lifted from matching token_usage\n",
						res.SessionsUpdated,
					)
				}
			}
			if sessionModels {
				res, err := backfillSessionModels(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.SessionModels = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"session-models backfill complete: %d session(s) across all adapters had model rolled up from token_usage\n",
						res.SessionsUpdated,
					)
				}
			}
			if copilotMessageID {
				res, err := backfillCopilotMessageID(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.CopilotMessageID = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"copilot message-id backfill complete: scanned %d files, examined %d lines; updated %d action rows + %d token_usage rows\n",
						res.FilesScanned, res.LinesExamined, res.ActionsUpdated, res.TokenUsageUpdated,
					)
				}
			}
			if piMessageID {
				res, err := backfillPiMessageID(cmd.Context(), database)
				if err != nil {
					return err
				}
				summary.PiMessageID = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"pi message-id backfill complete: scanned %d files, examined %d lines; updated %d action rows + %d token_usage rows\n",
						res.FilesScanned, res.LinesExamined, res.ActionsUpdated, res.TokenUsageUpdated,
					)
				}
			}
			if claudecodeUserPrompts {
				res, err := backfillClaudeCodeUserPrompts(cmd.Context(), database, claudeProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.ClaudeCodeUserPrompts = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"claudecode user-prompts backfill complete: scanned %d files, found %d user_prompt events; inserted %d new action rows\n",
						res.FilesScanned, res.UserEventsFound, res.ActionsInserted,
					)
				}
			}
			if claudecodeAPIErrors {
				res, err := backfillClaudeCodeAPIErrors(cmd.Context(), database, claudeProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.ClaudeCodeAPIErrors = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"claudecode api-errors backfill complete: scanned %d files, found %d api_error events; inserted %d new action rows\n",
						res.FilesScanned, res.APIErrorsFound, res.ActionsInserted,
					)
				}
			}
			if cursorUserPrompts {
				res, err := backfillCursorUserPrompts(cmd.Context(), database, cursorProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.CursorUserPrompts = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"cursor user-prompts backfill complete: scanned %d files, found %d user_prompt events; inserted %d new action rows\n",
						res.FilesScanned, res.UserEventsFound, res.ActionsInserted,
					)
				}
			}
			if cursorSubagents {
				res, err := backfillCursorSubagents(cmd.Context(), database, cursorProjectsDir(), limit)
				if err != nil {
					return err
				}
				summary.CursorSubagents = &res
				if !jsonOut {
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"cursor subagents backfill complete: scanned %d files, built %d sidechain events; inserted %d new action rows\n",
						res.FilesScanned, res.EventsBuilt, res.ActionsInserted,
					)
				}
			}
			if codexForkDedup {
				var dedupOut io.Writer
				if !jsonOut {
					dedupOut = cmd.OutOrStdout()
				}
				res, err := backfillCodexForkDedup(cmd.Context(), database, apply, limit, dedupOut)
				if err != nil {
					return err
				}
				summary.CodexForkDedup = &res
				if !jsonOut {
					if apply {
						fmt.Fprintf(
							cmd.OutOrStdout(),
							"codex-fork-dedup complete: deleted %d duplicate token_usage row(s) across %d session(s) (input=%d output=%d cache_read=%d reasoning=%d web_search=%d est_cost=$%.4f); scanned %d file(s), skipped %d (rollout no longer on disk); %d session(s) lineage-backfilled\n",
							res.RowsDeleted, res.SessionsTouched, res.InputTokens, res.OutputTokens, res.CacheReadTokens,
							res.ReasoningTokens, res.WebSearchRequests, res.EstimatedCostUSD,
							res.FilesScanned, res.FilesMissing, res.LineageBackfilled,
						)
					} else {
						fmt.Fprintf(
							cmd.OutOrStdout(),
							"codex-fork-dedup dry run: %d duplicate token_usage row(s) matched across %d session(s) (input=%d output=%d cache_read=%d reasoning=%d web_search=%d est_cost=$%.4f); scanned %d file(s), skipped %d (rollout no longer on disk); %d session(s) would be lineage-backfilled\n",
							res.RowsMatched, res.SessionsTouched, res.InputTokens, res.OutputTokens, res.CacheReadTokens,
							res.ReasoningTokens, res.WebSearchRequests, res.EstimatedCostUSD,
							res.FilesScanned, res.FilesMissing, res.LineageBackfilled,
						)
						fmt.Fprintf(
							cmd.OutOrStdout(),
							"no rows deleted (dry run) — re-run with --apply to delete:\n  observer backfill --codex-fork-dedup --apply\n",
						)
					}
					// Honest caveat (finding 6): local deletes are not
					// propagated to an org server. Rows already pushed
					// under [org_client.share] remain on the server
					// (ingest is INSERT OR IGNORE); this command only
					// cleans the node-local DB.
					fmt.Fprintf(
						cmd.OutOrStdout(),
						"note: duplicate rows already pushed to an org server are NOT retracted — this cleans the local DB only.\n",
					)
				}
			}

			if reasoningConverge {
				var convergeOut io.Writer
				if !jsonOut {
					convergeOut = cmd.OutOrStdout()
				}
				res, err := backfillReasoningConverge(cmd.Context(), database, apply, reasoningConvergeDiscard, convergeOut)
				if err != nil {
					return err
				}
				summary.ReasoningConverge = &res
			}

			if codexToolInput {
				var toolInputOut io.Writer
				if !jsonOut {
					toolInputOut = cmd.OutOrStdout()
				}
				res, err := backfillToolInput(cmd.Context(), database, apply, toolInputOut)
				if err != nil {
					return err
				}
				summary.CodexToolInput = &res
			}

			if locBackfill {
				var locOut io.Writer
				if !jsonOut {
					locOut = cmd.OutOrStdout()
				}
				res, err := backfillLOC(cmd.Context(), database, locBackfillArgs{
					Since:    locSince,
					Rescan:   locRescan,
					DryRun:   locDryRun,
					Limit:    locLimit,
					Sessions: locSessions,
				}, locOut)
				if err != nil {
					return err
				}
				summary.LOC = &res
			}

			if jsonOut {
				body, _ := json.MarshalIndent(summary, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&locBackfill, "loc", false, "Count lines of code (added / modified / deleted, comments and blanks separated) for every historical edit_file / write_file action, from the raw_tool_input the row already holds. Writes file_changes (migration 103) — counts and path HASHES only, never content. Idempotent: at the same classifier version a re-run rewrites nothing and does not even re-read rows it already counted; bumping internal/loc.Version and re-running replaces every row exactly once. Pages by keyset on actions.id in short read transactions, so it is safe on a multi-gigabyte database. NOT part of --all.")
	cmd.Flags().StringVar(&locSince, "loc-since", "", "Restrict --loc to actions at or after this timestamp (RFC3339, or YYYY-MM-DD). Counts older than the org push window (the trailing 7 days) stay node-local — the node's own LOC surfaces render them, but session_loc / loc_days never ship them to an org server.")
	cmd.Flags().BoolVar(&locRescan, "loc-rescan", false, "With --loc, re-read AND re-write actions that already have counts at the current classifier version (the default skips them, and would refuse the write even if it read them). Use after changing a language table or lexer rule without bumping the version. This is the ONE path that replaces a row at an equal version; every other writer keeps the strict version guard that makes a re-ingest a no-op.")
	cmd.Flags().BoolVar(&locDryRun, "loc-dry-run", false, "With --loc, compute everything and write nothing. Distinct from the global --dry-run, which snapshots the whole database — impractical on a large one.")
	cmd.Flags().IntVar(&locLimit, "loc-limit", 0, "With --loc, stop after this many actions (0 = no limit)")
	cmd.Flags().StringSliceVar(&locSessions, "loc-session", nil, "With --loc, also print the per-session totals for these session ids (repeatable, or comma-separated)")
	cmd.Flags().BoolVar(&isSidechain, "is-sidechain", false, "Backfill actions.is_sidechain from JSONL")
	cmd.Flags().BoolVar(&cacheTier, "cache-tier", false, "Backfill cache_creation_1h_tokens from JSONL")
	cmd.Flags().BoolVar(&messageID, "message-id", false, "Backfill message_id columns from JSONL (umbrella covering claudecode + codex + cursor + opencode)")
	cmd.Flags().BoolVar(&opencodeMessageID, "opencode-message-id", false, "Backfill message_id on opencode rows from source_event_id prefix")
	cmd.Flags().BoolVar(&opencodeParts, "opencode-parts", false, "Re-read opencode.db parts to populate tool_output / duration_ms / message_id")
	cmd.Flags().BoolVar(&opencodeTokens, "opencode-tokens", false, "Re-run the opencode adapter to insert any missing token_usage rows from data.tokens")
	cmd.Flags().BoolVar(&openclawActionTypes, "openclaw-action-types", false, "Retag historical openclaw action_type drift from raw_tool_name (sessions_spawn → spawn_subagent, process → run_command, canvas/cron/etc → mcp_call)")
	cmd.Flags().BoolVar(&openclawModel, "openclaw-model", false, "Lift model from sessions.json aliases onto openclaw sqlite-path action rows")
	cmd.Flags().BoolVar(&openclawProjectRoot, "openclaw-project-root", false, "Re-attribute openclaw action / session rows to the correct project when sessions.json workspaceDir previously collapsed to the [openclaw] placeholder or a foreign-OS path")
	cmd.Flags().BoolVar(&openclawReasoning, "openclaw-reasoning", false, "Re-walk openclaw jsonl to populate preceding_reasoning on tool calls")
	cmd.Flags().BoolVar(&openclawSessionID, "openclaw-session-id", false, "Collapse historical openclaw split sessions where sessions.json used raw sessionId but JSONL / task_runs used the alias session key")
	cmd.Flags().BoolVar(&codexReasoning, "codex-reasoning", false, "Re-walk codex rollouts to populate preceding_reasoning from agent_message")
	cmd.Flags().BoolVar(&codexProjectRoot, "codex-project-root", false, "Re-attribute codex action / token / session rows to the correct project when their cwd was a Windows-style path that previously misresolved to observer's own repo (v1.4.28)")
	cmd.Flags().BoolVar(&claudecodeProjectRoot, "claudecode-project-root", false, "Re-attribute claude-code action / token / session rows to the correct project when their cwd was a Windows-style path that previously misresolved to observer's own repo (v1.6.10 / audit B1)")
	cmd.Flags().BoolVar(&antigravityProjectRoot, "antigravity-project-root", false, "Re-attribute antigravity action / session rows to the correct project + refresh session.model and session.started_at from the state.vscdb index entry. Also lifts per-turn token_usage rows + the actual model name (e.g. claude-sonnet-4-5) into the DB via the language_server's GetCascadeTrajectory endpoint when [observer.antigravity] network_recovery = \"local\" is set (best-effort).")
	cmd.Flags().BoolVar(&cursorModel, "cursor-model", false, "Lift model from matching token_usage row onto cursor session rows whose model is empty")
	cmd.Flags().BoolVar(&sessionModels, "session-models", false, "Adapter-agnostic sessions.model rollup: fill an EMPTY sessions.model from the newest model-bearing token_usage row of the same session (audit IDE-13 / class C8). The live ingest path already does this per batch; this repairs rows written before that existed — the codex / cursor / cline / cowork sessions whose adapters emit ToolEvents with no Model. Never overwrites a model an adapter already supplied; a session with no model-bearing token row is left untouched. Idempotent. Picked up by --all.")
	cmd.Flags().BoolVar(&copilotMessageID, "copilot-message-id", false, "Backfill message_id on copilot rows by walking debug-log JSONL")
	cmd.Flags().BoolVar(&piMessageID, "pi-message-id", false, "Backfill message_id on pi rows by walking session JSONL")
	cmd.Flags().BoolVar(&claudecodeUserPrompts, "claudecode-user-prompts", false, "Insert missing user_prompt action rows for Claude Code sessions ingested before the adapter started emitting them")
	cmd.Flags().BoolVar(&claudecodeAPIErrors, "claudecode-api-errors", false, "Insert api_error action rows for Claude Code system/api_error JSONL records (content-policy blocks, rate limits, etc.) ingested before v1.4.20 added capture")
	cmd.Flags().BoolVar(&cursorUserPrompts, "cursor-user-prompts", false, "Insert user_prompt action rows for Cursor sessions by walking agent-transcripts JSONL — fills the gap for sessions before the beforeSubmitPrompt hook was installed, with the <user_query> wrapper stripped")
	cmd.Flags().BoolVar(&cursorSubagents, "cursor-subagents", false, "Walk Cursor agent-transcripts/<session>/subagents/<sub>.jsonl files and ingest as sidechain rows under the parent session (IsSidechain=true)")
	cmd.Flags().BoolVar(&coworkRescan, "cowork-rescan", false, "Fast rescan of the Cowork audit.jsonl tree only — same effect as `observer scan --force --adapter cowork` but discoverable via the dashboard Backfill UI. Use when adding cowork to enabled_adapters mid-flight without rescanning every other adapter's tree.")
	cmd.Flags().BoolVar(&coworkProjectRoot, "cowork-project-root", false, "Re-attribute Cowork action / session rows to the correct project_id when their sidecar.userSelectedFolders was a Windows-style path that previously misresolved to observer's own repo (v1.4.54)")
	cmd.Flags().BoolVar(&codexRescan, "codex-rescan", false, "Fast rescan of the Codex rollout tree only — re-walks every JSONL from offset 0 to pick up v1.4.53 adapter additions: token_usage.web_search_requests + ActionRateLimit rows from token_count.rate_limits + codex.reasoning rows from response_item.reasoning. Idempotent via the (source_file, source_event_id) UNIQUE index.")
	cmd.Flags().BoolVar(&antigravityRescan, "antigravity-rescan", false, "Fast rescan of the Antigravity tree only — re-walks every .pb / state.vscdb under the configured watch roots and re-ingests via the antigravity adapter (local decrypt first, falls back to language_server gRPC when [observer.antigravity] network_recovery = \"local\"). Idempotent.")
	cmd.Flags().BoolVar(&antigravityCliRescan, "antigravity-cli-rescan", false, "Fast rescan of the Antigravity CLI tree only — re-walks every .pb / .db under the configured watch roots and re-ingests via the antigravity-cli adapter. Idempotent.")
	cmd.Flags().BoolVar(&geminiCliRescan, "gemini-cli-rescan", false, "Fast rescan of the Gemini CLI tree only — re-walks ~/.gemini/tmp/<hash>/chats/ JSON / JSONL. gemini-cli has no surgical column backfills; this is its only retroactive path. Idempotent.")
	cmd.Flags().BoolVar(&hermesRescan, "hermes-rescan", false, "Fast rescan of the Hermes Agent tree only — re-walks every state.db under ~/.hermes (or %LOCALAPPDATA%\\hermes on Windows + cross-mount homes) from messages.id=0. Useful for importing sessions that predate `observer init --hermes` plugin install — the SQLite backfill catches what the hook path missed. Idempotent via the (source_file, source_event_id) UNIQUE index.")
	cmd.Flags().BoolVar(&clinecliRescan, "clinecli-rescan", false, "Fast rescan of the Cline CLI tree only — re-walks every sessions.db under ~/.cline/data/db/ (cross-mount aware) from updated_at='0'. Re-reads each session's paired messages.json + re-emits session_start / session_end / user_prompt / assistant_text / tool_use / per-message metrics rows. Useful for importing sessions that pre-date adapter install + picking up Phase 0 reality-check upgrades (per-message metrics, modelInfo, tool_result structured shape) on historical data. Idempotent via the (source_file, source_event_id) UNIQUE index.")
	cmd.Flags().BoolVar(&copilotCliRescan, "copilot-cli-rescan", false, "Fast rescan of the GitHub Copilot CLI tree only — re-walks events.jsonl under ~/.copilot/session-state AND process-*.log under ~/.copilot/logs (cross-mount aware). Run after enabling `copilot --log-level debug` to retrofit Tier-1 accurate input/cache/reasoning tokens onto historical sessions. Idempotent.")
	cmd.Flags().BoolVar(&cacheRescan, "cache-rescan", false, "Re-walk claude-code transcripts through the Tier-2 cache observation engine to populate historical cache_segments / cache_entries / cache_events rows. Order-sensitive within each file (chain dependency); files in mtime order. Idempotent via CacheEventExistsForMessage — a turn already captured by the Tier-1 proxy path skips Tier-2 emission, so re-runs are no-ops and proxy-already-observed turns don't double-write. Use after enabling [cachetrack].enabled on a daemon that has historical claude-code traffic, or after upgrading to a build that closes a cachetrack bug (Fix B deep canonicalize / x-anthropic-billing-header exclusion / etc.) to retrofit corrected attribution onto past sessions. Picked up by --all.")
	cmd.Flags().BoolVar(&content, "content", false, "Re-walk EVERY adapter's transcripts through the adapter-side message-content producer (store.captureMessageContent) to populate historical otel_content rows — the data the org admin's Messages panel reads — for sessions ingested before the producer shipped (263a3cadc) or before this node turned content sharing on. Gated exactly like live capture: [org_client.share] full_content / admin_managed AND [ingest.otel] content_capture; a no-op with an honest message naming the blocking key when either is off. Idempotent via otel_content's (content_hash, kind, request_id, tool_use_id) UNIQUE key. NOT picked up by --all — --all's own top-level rescan already re-derives content as a side effect of wireContentCapture being unconditional, so run --content standalone after turning content sharing on, rather than re-running everything --all does.")
	cmd.Flags().BoolVar(&zedRescan, "zed-rescan", false, "Fast rescan of the Zed native-agent tree only — re-walks every threads.db under the configured Zed watch roots from watermark 0, forcing every thread to re-emit regardless of its stored updated_at cursor. threads.db is a watermark store (migration 107-era surface capture): a thread that predates the daemon first observing its file is never re-read until its NEXT turn advances updated_at, so this is the only retroactive path for pre-existing Zed conversations. Idempotent via the (source_file, source_event_id) UNIQUE index — deterministic per-block SourceEventIDs make re-emitting an already-seen row a store-level no-op. Picked up by --all.")
	cmd.Flags().BoolVar(&tasksRescan, "tasks", false, "Re-derive task_items / task_transitions (docs/task-tracking.md) from todo_update / task_complete / post_tool_batch action rows already in the DB. No adapter re-parse, no source-file walk — a pure re-read of raw_tool_input / raw_tool_output. Ignores [tasks].enabled. Idempotent. Use after enabling [tasks].enabled on a daemon with historical task-tool traffic, or after upgrading to a build with wider decoder coverage (e.g. the gemini-cli write_todos fix). Picked up by --all.")
	cmd.Flags().BoolVar(&codexForkDedup, "codex-fork-dedup", false, "Purge historical duplicate codex token_usage rows created when a fork / subagent spawn replayed its parent rollout's token_count telemetry into the child's rollout (~65% of codex input tokens in a pre-fix DB are these duplicates). Enumerates codex token_usage source_files, re-runs the fork-replay detector, and matches the replayed tk:<basename>:L<line> rows. DRY-RUN BY DEFAULT — reports matched rows / summed tokens (input/output/cache_read/reasoning/web_search/est_cost) / sessions touched and deletes nothing; pass --apply to delete. Uses a 2s safety margin (vs the strict-boundary ingest suppression) so a second-boundary or clock-regression edge case is never auto-deleted. Also backfills session lineage (forked_from_id / parent_thread_id / thread_source) onto pre-fix sessions. NOT part of --all (destructive). Idempotent — deletes by (source_file, source_event_id) key. CAVEATS: duplicate rows already pushed to an org server are NOT retracted (server ingest is INSERT OR IGNORE) — this cleans the local DB only; and any cache_events / cache_segments the replayed rows produced are NOT cascade-deleted (node-local cache tables are left as-is).")
	cmd.Flags().BoolVar(&reasoningConverge, "reasoning-converge", false, "Converge the B3 reasoning residue (docs/plans/b3-reasoning-convergence-plan-2026-07-31.md): the content-bearing `*.reasoning` / `cursor.thinking` task_complete rows migration 079 deliberately kept because deleting them would be lossy. Carries each row's full text onto its successor's preceding_reasoning under B3's own semantics (consumed-once / last-wins / turn-boundary-discarded / never crossing a session id / never overwriting a populated successor), then deletes the row through migration 079's dependency protocol (action_excerpts + failure_context deleted, file_state / retrieval_signals / guard_events / process_runs / process_events references NULLed). DB-only — the text already lives in the rows (target = the 200-char preview, raw_tool_output = the full body), so no source file is re-parsed. DRY-RUN BY DEFAULT; pass --apply to mutate. One transaction, so a mid-run failure can never leave a row deleted with its text uncarried. NOT part of --all (destructive). Idempotent. A row is deleted only when its bytes provably survive — see --reasoning-converge-discard-unresolved.")
	cmd.Flags().BoolVar(&reasoningConvergeDiscard, "reasoning-converge-discard-unresolved", false, "Widen --reasoning-converge's delete to every row B3's semantics account for, including the ones whose text B3 sends nowhere (superseded by last-wins, discarded at a turn boundary, no successor in the session, or a successor whose preceding_reasoning already holds DIFFERENT text). That is the strict reading of B3 and it DESTROYS reasoning text that exists nowhere else — the dry run reports exactly how many rows and bytes. Rows whose raw_tool_output diverges from target are never deleted under either setting.")
	cmd.Flags().BoolVar(&codexToolInput, "codex-tool-input", false, "Re-derive raw_tool_input for the codex-family rows that are genuinely MISSING one, by re-reading the rollout files the rows came from. The candidate set is grounded per action_type, not assumed: four of the six codex action types with an empty raw_tool_input (assistant_message / task_complete / turn_aborted / session_start) come from emit sites that assign no input because the event HAS none — empty is correct there and this pass never writes to them, reporting them in their own named bucket. Only edit_file (patch_apply_end.changes, which buildPatchApplyStandaloneEvent drops) and web_search are recoverable. Rows join to source records on source_event_id = the record's own call_id — never on ordinal position or timestamp. Never overwrites a populated raw_tool_input; a missing file, an absent record or an empty derived value all stay UNRESOLVED rather than gaining a fabricated value. DRY-RUN BY DEFAULT; pass --apply to mutate. One transaction. NOT part of --all. Idempotent.")
	cmd.Flags().BoolVar(&apply, "apply", false, "Actually perform destructive deletes for --codex-fork-dedup and --reasoning-converge, and the writes for --codex-tool-input (default is dry-run, which reports what WOULD change and touches nothing).")
	cmd.Flags().BoolVar(&all, "all", false, "Run every supported backfill in one invocation (recommended after upgrading)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Snapshot the live DB via VACUUM INTO and run the requested backfills against the snapshot instead of the live DB. Reports what WOULD update; live DB untouched. Snapshot is deleted on exit. See docs/backfill-flag-audit-2026-05-19.md.")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.Flags().IntVar(&limit, "limit", 0, "Stop after N source files per JSONL-walking pass (0 = all)")
	return cmd
}

// rescanPass describes one `--<adapter>-rescan` catch-all: scope the
// watcher to a single adapter (buildWatcherWithOverride's
// adapterFilter) and re-walk it from offset 0 via watcher.Rescan. See
// the loop in newBackfillCmd's RunE for how these are driven.
type rescanPass struct {
	// enabled is the address of the flag var this pass is gated on.
	enabled *bool
	// flag is the exact `--flag-name` used as the error-wrap prefix on
	// both the buildWatcherWithOverride and Rescan failure paths.
	flag string
	// adapter is the adapterFilter passed to buildWatcherWithOverride
	// — narrows watcher.Options.Allow to this one adapter name.
	adapter string
	// label is the leading word(s) of the stdout summary line, e.g.
	// "codex rescan complete: ...".
	label string
	// note is the parenthetical at the end of the stdout summary line.
	note string
}

// summaryLine renders the exact stdout line this pass prints on success:
// "<label> rescan complete: files_processed=<n> errors=<n> (<note>)\n".
// Pulled out of the RunE loop below so the format is production code a
// test can call directly (rescan_flag_audit_test.go), rather than a test
// re-implementing the same fmt.Sprintf and silently drifting from it.
func (p rescanPass) summaryLine(res watcher.ScanResult) string {
	return fmt.Sprintf(
		"%s rescan complete: files_processed=%d errors=%d (%s)\n",
		p.label, res.FilesProcessed, res.Errors, p.note,
	)
}

// buildRescanPasses returns the ordered table of per-adapter rescan
// passes, one row per `--<adapter>-rescan` flag, taking the address
// of each flag var so the table stays a thin view over
// newBackfillCmd's cobra-owned bools. Pulled into its own function
// (rather than a literal inlined in RunE) so a table-driven test can
// assert the flag/adapter/label/note strings directly — the stdout
// line + error-wrap prefix are a de facto contract (dashboard
// job-output display, docs examples quote them verbatim), so a table
// edit here should be exactly as reviewable as the string literals it
// replaced. Order matters only for which pass's ScanResult lands in
// the shared, first-wins `summary.Rescan` field when multiple flags
// (e.g. via --all) run together — this preserves the pre-refactor
// order exactly, with --zed-rescan appended last (a new flag, so it
// can't disturb any existing combination's summary.Rescan value).
func buildRescanPasses(
	coworkRescan, codexRescan, antigravityRescan, antigravityCliRescan,
	geminiCliRescan, copilotCliRescan, hermesRescan, clinecliRescan,
	cacheRescan, zedRescan *bool,
) []rescanPass {
	return []rescanPass{
		{coworkRescan, "--cowork-rescan", "cowork", "cowork", "cowork audit.jsonl only"},
		{codexRescan, "--codex-rescan", "codex", "codex", "codex rollouts only"},
		{antigravityRescan, "--antigravity-rescan", "antigravity", "antigravity", "antigravity .pb / state.vscdb only"},
		{antigravityCliRescan, "--antigravity-cli-rescan", "antigravity-cli", "antigravity-cli", "antigravity-cli .pb / .db only"},
		{geminiCliRescan, "--gemini-cli-rescan", "gemini-cli", "gemini-cli", "~/.gemini/tmp only"},
		{copilotCliRescan, "--copilot-cli-rescan", "copilot-cli", "copilot-cli", "~/.copilot/{session-state,logs} only"},
		{hermesRescan, "--hermes-rescan", "hermes", "hermes", "~/.hermes/state.db only"},
		{clinecliRescan, "--clinecli-rescan", "cline-cli", "cline-cli", "~/.cline/data/db/sessions.db only"},
		{cacheRescan, "--cache-rescan", "claude-code", "cache", "claude-code transcripts through the Tier-2 cache engine; idempotent via CacheEventExistsForMessage"},
		{zedRescan, "--zed-rescan", "zed", "zed", "threads.db only; watermark reset (fromOffset=0) re-reads every thread regardless of updated_at"},
	}
}

// BackfillResult is the per-run summary returned to the caller.
type BackfillResult struct {
	FilesScanned   int `json:"files_scanned"`
	SidechainLines int `json:"sidechain_lines"`
	RowsUpdated    int `json:"rows_updated"`
	UnmatchedLines int `json:"unmatched_lines"`
}

// CacheTierBackfill summarises the --cache-tier pass.
type CacheTierBackfill struct {
	FilesScanned      int   `json:"files_scanned"`
	MsgIDsExamined    int   `json:"msg_ids_examined"`
	TokenUsageUpdated int   `json:"token_usage_updated"`
	APITurnsUpdated   int   `json:"api_turns_updated"`
	TokensRecovered   int64 `json:"tokens_recovered"`
}

// MessageIDBackfill summarises the --message-id pass.
type MessageIDBackfill struct {
	FilesScanned      int `json:"files_scanned"`
	LinesExamined     int `json:"lines_examined"`
	ActionsUpdated    int `json:"actions_updated"`
	TokenUsageUpdated int `json:"token_usage_updated"`
}

// ContentRescanBackfill summarises the --content pass: a full-adapter
// Rescan wired through the same message-content producer live capture
// uses (store.captureMessageContent), so its shape mirrors
// watcher.ScanResult rather than a surgical column-update count.
//
// Skipped is true when the node's content-capture posture is off; when
// it is, SkipReason names the exact blocking config key
// (contentCaptureBlockReason) instead of leaving the operator to guess
// why zero rows landed.
type ContentRescanBackfill struct {
	Skipped        bool   `json:"skipped"`
	SkipReason     string `json:"skip_reason,omitempty"`
	FilesProcessed int    `json:"files_processed,omitempty"`
	Errors         int    `json:"errors,omitempty"`
}

// claudeProjectsDir returns the location Claude Code writes its session
// JSONL files. Honors $CLAUDE_HOME for tests + non-default installs;
// falls back to ~/.claude/projects/.
func claudeProjectsDir() string {
	if v := os.Getenv("CLAUDE_HOME"); v != "" {
		return filepath.Join(v, "projects")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "projects")
}

// codexSessionsDir returns the location Codex Desktop / CLI writes rollout
// JSONL files. Honors $CODEX_HOME for tests + non-default installs; falls
// back to ~/.codex/sessions/.
func codexSessionsDir() string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return filepath.Join(v, "sessions")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex", "sessions")
}

func cursorLogsDir() string {
	if v := os.Getenv("APPDATA"); v != "" {
		return filepath.Join(v, "Cursor", "logs")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "AppData", "Roaming", "Cursor", "logs")
}

func cursorProjectsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cursor", "projects")
}

// backfillIsSidechain walks every *.jsonl under projectsDir, extracts
// `(uuid, isSidechain)` pairs from each line where isSidechain is true,
// and UPDATEs the matching actions row by source_event_id (= the line's
// content[].id for tool_use blocks, which is what the adapter writes).
//
// UUID matching: the adapter uses the tool_use block's id as
// source_event_id, NOT the line uuid. So we scan content[] looking for
// tool_use blocks. Lines without tool_use blocks contribute zero to
// the update count even if isSidechain=true (text-only assistant
// messages don't produce action rows; only tool calls do).
func backfillIsSidechain(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (BackfillResult, error) {
	res := BackfillResult{}

	updateStmt, err := db.PrepareContext(ctx,
		`UPDATE actions SET is_sidechain = 1
		 WHERE source_file = ? AND source_event_id = ? AND is_sidechain = 0`)
	if err != nil {
		return res, fmt.Errorf("backfill: prepare: %w", err)
	}
	defer updateStmt.Close()

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees rather than fail the whole pass
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		// Increase the bufio scanner's max line size — Claude Code's
		// JSONL lines can carry large tool_results that exceed the
		// default 64 KB.
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			var rl struct {
				IsSidechain bool `json:"isSidechain"`
				Message     struct {
					Content json.RawMessage `json:"content"`
				} `json:"message"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			if !rl.IsSidechain {
				continue
			}
			res.SidechainLines++
			// Decode content[] looking for tool_use blocks.
			var blocks []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			}
			if err := json.Unmarshal(rl.Message.Content, &blocks); err != nil {
				continue
			}
			for _, b := range blocks {
				if b.Type != "tool_use" || b.ID == "" {
					continue
				}
				rs, err := updateStmt.ExecContext(ctx, path, b.ID)
				if err != nil {
					continue
				}
				n, _ := rs.RowsAffected()
				if n > 0 {
					res.RowsUpdated += int(n)
				} else {
					res.UnmatchedLines++
				}
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// backfillCacheTier walks every *.jsonl under projectsDir, extracts
// (session_id, message.id, ephemeral_1h_input_tokens) tuples from each
// assistant-message line that carries a usage block, and UPDATEs:
//
//   - token_usage SET cache_creation_1h_tokens = ? WHERE session_id = ?
//     AND source_event_id = ? AND cache_creation_1h_tokens IS NULL
//   - api_turns SET cache_creation_1h_tokens = ? WHERE session_id = ?
//     AND request_id = ? AND cache_creation_1h_tokens IS NULL
//
// The IS NULL guard preserves any explicit value already written by
// post-migration ingests; the backfill only fills in the NULLs left
// behind when migration 008 ran on existing data.
//
// Note that we only update if the JSONL row HAS the
// `cache_creation.ephemeral_1h_input_tokens` field — older Claude Code
// JSONL didn't emit the per-tier breakdown at all, in which case the
// historical row was 100% 5m and the NULL → 0 default is correct. We
// only correct rows where Anthropic actually returned a 1h subset.
func backfillCacheTier(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (CacheTierBackfill, error) {
	res := CacheTierBackfill{}

	updateTokenUsage, err := db.PrepareContext(ctx,
		`UPDATE token_usage SET cache_creation_1h_tokens = ?
		 WHERE session_id = ? AND source_event_id = ?
		   AND cache_creation_1h_tokens IS NULL`)
	if err != nil {
		return res, fmt.Errorf("backfill cache-tier: prepare token_usage: %w", err)
	}
	defer updateTokenUsage.Close()

	updateAPITurns, err := db.PrepareContext(ctx,
		`UPDATE api_turns SET cache_creation_1h_tokens = ?
		 WHERE session_id = ? AND request_id = ?
		   AND cache_creation_1h_tokens IS NULL`)
	if err != nil {
		return res, fmt.Errorf("backfill cache-tier: prepare api_turns: %w", err)
	}
	defer updateAPITurns.Close()

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

		// We iterate every line and try BOTH the message.id and the
		// line.uuid as source_event_id keys, because historical
		// claudecode adapter ingests used the line uuid (one per
		// content block) while later versions use the message.id.
		// The IS NULL guard makes each UPDATE a no-op when the row
		// has already been corrected (or was never NULL to begin
		// with), so trying both keys is safe and idempotent.
		//
		// We DON'T dedup by message.id within the file because the
		// per-line uuid changes line-to-line even when the message.id
		// is the same — and the token_usage rows we need to update
		// were keyed by line.uuid in the older adapter version.

		// Track which message.ids we've already credited toward
		// MsgIDsExamined / TokensRecovered so the summary numbers
		// reflect the true count of corrected upstream turns, not
		// the multi-line content-block fan-out.
		seenMsgs := map[string]bool{}

		for scanner.Scan() {
			line := scanner.Bytes()
			var rl struct {
				UUID      string `json:"uuid"`
				SessionID string `json:"sessionId"`
				Message   struct {
					ID    string `json:"id"`
					Usage struct {
						CacheCreation struct {
							Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
						} `json:"cache_creation"`
					} `json:"usage"`
				} `json:"message"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			cw1h := rl.Message.Usage.CacheCreation.Ephemeral1hInputTokens
			if cw1h == 0 || rl.SessionID == "" {
				continue
			}
			if rl.Message.ID != "" && !seenMsgs[rl.Message.ID] {
				seenMsgs[rl.Message.ID] = true
				res.MsgIDsExamined++
			}

			// Try both message.id and line.uuid as the source_event_id
			// key. Historical (pre-2025-Q3) claudecode ingest used
			// line.uuid; current uses message.id. Both forms exist in
			// the wild and the IS-NULL guard makes the second attempt
			// a no-op when the first already wrote.
			tryUpdateTokenUsage := func(eid string) {
				if eid == "" {
					return
				}
				r, err := updateTokenUsage.ExecContext(ctx, cw1h, rl.SessionID, eid)
				if err != nil {
					return
				}
				n, _ := r.RowsAffected()
				if n > 0 {
					res.TokenUsageUpdated += int(n)
					res.TokensRecovered += cw1h * n
				}
			}
			tryUpdateAPITurns := func(eid string) {
				if eid == "" {
					return
				}
				r, err := updateAPITurns.ExecContext(ctx, cw1h, rl.SessionID, eid)
				if err != nil {
					return
				}
				n, _ := r.RowsAffected()
				if n > 0 {
					res.APITurnsUpdated += int(n)
					res.TokensRecovered += cw1h * n
				}
			}
			tryUpdateTokenUsage(rl.Message.ID)
			tryUpdateTokenUsage(rl.UUID)
			tryUpdateAPITurns(rl.Message.ID)
			tryUpdateAPITurns(rl.UUID)
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill cache-tier: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// backfillMessageID walks every *.jsonl under projectsDir, extracts
// (sessionId, line.uuid, message.id, content[].id) tuples, and UPDATEs
// the new message_id column on actions and token_usage where it's
// currently NULL.
//
// Two key shapes for the source_event_id match:
//   - actions.source_event_id stores the tool_use block's id (toolu_xxx)
//     for tool calls, or line.uuid for non-tool actions.
//   - token_usage.source_event_id stores message.id (msg_xxx) for newer
//     ingests, line.uuid for older.
//
// We try both message.id and line.uuid as the key for each row, and
// for actions also walk content[] to capture every tool_use block id
// that belongs to this message. The IS-NULL guard makes redundant
// UPDATEs no-ops.
func backfillMessageID(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions
		    SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE session_id = ? AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill message-id: prepare actions: %w", err)
	}
	defer updateActions.Close()

	updateTokenUsage, err := db.PrepareContext(ctx,
		`UPDATE token_usage
		    SET message_id = COALESCE(NULLIF(message_id, ''), ?),
		        model = COALESCE(NULLIF(model, ''), ?)
		 WHERE session_id = ? AND source_event_id = ?
		   AND ((message_id IS NULL OR message_id = '')
		        OR (model IS NULL OR model = ''))`)
	if err != nil {
		return res, fmt.Errorf("backfill message-id: prepare token_usage: %w", err)
	}
	defer updateTokenUsage.Close()

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

		for scanner.Scan() {
			line := scanner.Bytes()
			var rl struct {
				UUID      string `json:"uuid"`
				SessionID string `json:"sessionId"`
				Message   struct {
					ID      string          `json:"id"`
					Content json.RawMessage `json:"content"`
				} `json:"message"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			if rl.SessionID == "" || rl.Message.ID == "" {
				continue
			}
			res.LinesExamined++
			msgID := rl.Message.ID

			// token_usage: source_event_id can be msg.id (newer
			// adapter) or line.uuid (legacy). Try both.
			for _, eid := range [2]string{msgID, rl.UUID} {
				if eid == "" {
					continue
				}
				if r, err := updateTokenUsage.ExecContext(ctx, msgID, "", rl.SessionID, eid); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.TokenUsageUpdated += int(n)
					}
				}
			}

			// actions: source_event_id is the tool_use block's id
			// (toolu_xxx) for tool calls, or line.uuid otherwise.
			// Walk content[] for tool_use ids and try them all.
			if r, err := updateActions.ExecContext(ctx, msgID, rl.SessionID, rl.UUID); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
			var blocks []struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			}
			if err := json.Unmarshal(rl.Message.Content, &blocks); err == nil {
				for _, b := range blocks {
					if b.Type != "tool_use" || b.ID == "" {
						continue
					}
					if r, err := updateActions.ExecContext(ctx, msgID, rl.SessionID, b.ID); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.ActionsUpdated += int(n)
						}
					}
				}
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill message-id: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// backfillCodexMessageID walks Codex rollout JSONL files and populates the
// message_id column using Codex turn ids as the assistant-message key, plus a
// synthetic "user:<turn_id>" key for user prompts. It also backfills the model
// onto actions/token rows that were ingested before the adapter started
// carrying it through consistently.
func backfillCodexMessageID(ctx context.Context, db *sql.DB, sessionsDir string, fileLimit int) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions
		    SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE session_id = ? AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill codex message-id: prepare actions: %w", err)
	}
	defer updateActions.Close()

	updateTokenUsage, err := db.PrepareContext(ctx,
		`UPDATE token_usage
		    SET message_id = COALESCE(NULLIF(message_id, ''), ?),
		        model = COALESCE(NULLIF(model, ''), ?)
		 WHERE session_id = ? AND source_event_id = ?
		   AND ((message_id IS NULL OR message_id = '')
		        OR (model IS NULL OR model = ''))`)
	if err != nil {
		return res, fmt.Errorf("backfill codex message-id: prepare token_usage: %w", err)
	}
	defer updateTokenUsage.Close()

	updateTokenUsageByMessage, err := db.PrepareContext(ctx,
		`UPDATE token_usage
		    SET model = COALESCE(NULLIF(model, ''), ?)
		 WHERE session_id = ? AND message_id = ?
		   AND (model IS NULL OR model = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill codex message-id: prepare token_usage by message: %w", err)
	}
	defer updateTokenUsageByMessage.Close()

	walkErr := filepath.WalkDir(sessionsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if filepath.Ext(path) != ".jsonl" || !strings.HasPrefix(base, "rollout-") {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

		sessionIDs := []string{strings.TrimPrefix(strings.TrimSuffix(base, ".jsonl"), "rollout-")}
		currentTurnID := ""
		currentModel := ""
		lineNum := 0
		addSessionID := func(id string) {
			if id == "" {
				return
			}
			for _, existing := range sessionIDs {
				if existing == id {
					return
				}
			}
			sessionIDs = append(sessionIDs, id)
		}
		updateActionsForSessions := func(messageID, sourceEventID string) int {
			updated := 0
			for _, sessionID := range sessionIDs {
				if r, err := updateActions.ExecContext(ctx, messageID, sessionID, sourceEventID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						updated += int(n)
					}
				}
			}
			return updated
		}
		updateTokenUsageForSessions := func(messageID, model, sourceEventID string) int {
			updated := 0
			for _, sessionID := range sessionIDs {
				if r, err := updateTokenUsage.ExecContext(ctx, messageID, model, sessionID, sourceEventID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						updated += int(n)
					}
				}
			}
			return updated
		}
		updateTokenUsageByMessageForSessions := func(model, messageID string) int {
			updated := 0
			for _, sessionID := range sessionIDs {
				if r, err := updateTokenUsageByMessage.ExecContext(ctx, model, sessionID, messageID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						updated += int(n)
					}
				}
			}
			return updated
		}
		pendingTurnlessTokenSourceIDs := []string{}

		for scanner.Scan() {
			lineNum++
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			res.LinesExamined++

			var rl struct {
				ID      string          `json:"id"`
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}

			switch rl.Type {
			case "session_meta", "session_configured", "session_start", "turn_context":
				var payload struct {
					ID        string `json:"id"`
					SessionID string `json:"session_id"`
					TurnID    string `json:"turn_id"`
					Model     string `json:"model"`
				}
				if err := json.Unmarshal(rl.Payload, &payload); err != nil {
					continue
				}
				if payload.ID != "" {
					addSessionID(payload.ID)
				}
				if payload.SessionID != "" {
					addSessionID(payload.SessionID)
				}
				if payload.TurnID != "" {
					currentTurnID = payload.TurnID
				}
				if payload.Model != "" {
					currentModel = payload.Model
					if currentTurnID != "" {
						res.TokenUsageUpdated += updateTokenUsageByMessageForSessions(currentModel, currentTurnID)
					}
				}
				if currentTurnID != "" && len(pendingTurnlessTokenSourceIDs) > 0 {
					for _, sourceID := range pendingTurnlessTokenSourceIDs {
						res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
					}
					pendingTurnlessTokenSourceIDs = nil
				}
			case "event_msg":
				var env struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(rl.Payload, &env); err != nil {
					continue
				}
				switch env.Type {
				case "task_started":
					var payload struct {
						TurnID string `json:"turn_id"`
					}
					if err := json.Unmarshal(rl.Payload, &payload); err == nil && payload.TurnID != "" {
						currentTurnID = payload.TurnID
						if len(pendingTurnlessTokenSourceIDs) > 0 {
							for _, sourceID := range pendingTurnlessTokenSourceIDs {
								res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
							}
							pendingTurnlessTokenSourceIDs = nil
						}
					}
				case "user_message":
					var payload struct {
						Message string `json:"message"`
					}
					if err := json.Unmarshal(rl.Payload, &payload); err != nil {
						continue
					}
					msgID := ""
					if currentTurnID != "" {
						msgID = "user:" + currentTurnID
					} else {
						msgID = fmt.Sprintf("user:%s:L%d:%s", base, lineNum, shortHash(strings.TrimSpace(payload.Message)))
					}
					sourceID := fmt.Sprintf("user:%s:L%d:%s", base, lineNum, shortHash(strings.TrimSpace(payload.Message)))
					res.ActionsUpdated += updateActionsForSessions(msgID, sourceID)
				case "exec_command_end":
					var payload struct {
						CallID string `json:"call_id"`
						TurnID string `json:"turn_id"`
					}
					if err := json.Unmarshal(rl.Payload, &payload); err != nil {
						continue
					}
					if payload.TurnID != "" {
						currentTurnID = payload.TurnID
						if len(pendingTurnlessTokenSourceIDs) > 0 {
							for _, sourceID := range pendingTurnlessTokenSourceIDs {
								res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
							}
							pendingTurnlessTokenSourceIDs = nil
						}
					}
					msgID := firstNonEmpty(payload.TurnID, currentTurnID)
					if msgID == "" || payload.CallID == "" {
						continue
					}
					res.ActionsUpdated += updateActionsForSessions(msgID, payload.CallID)
				case "web_search_end":
					var payload struct {
						CallID string `json:"call_id"`
						TurnID string `json:"turn_id"`
						Query  string `json:"query"`
						Action struct {
							Query   string   `json:"query"`
							Queries []string `json:"queries"`
						} `json:"action"`
					}
					if err := json.Unmarshal(rl.Payload, &payload); err != nil {
						continue
					}
					if payload.TurnID != "" {
						currentTurnID = payload.TurnID
						if len(pendingTurnlessTokenSourceIDs) > 0 {
							for _, sourceID := range pendingTurnlessTokenSourceIDs {
								res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
							}
							pendingTurnlessTokenSourceIDs = nil
						}
					}
					msgID := firstNonEmpty(payload.TurnID, currentTurnID)
					if msgID == "" {
						continue
					}
					sourceID := payload.CallID
					if sourceID == "" {
						query := firstNonEmpty(payload.Query, payload.Action.Query, strings.Join(payload.Action.Queries, "; "))
						sourceID = fmt.Sprintf("web:%s:L%d:%s", base, lineNum, shortHash(query))
					}
					res.ActionsUpdated += updateActionsForSessions(msgID, sourceID)
				case "task_complete":
					var payload struct {
						TurnID string `json:"turn_id"`
					}
					if err := json.Unmarshal(rl.Payload, &payload); err != nil {
						continue
					}
					if payload.TurnID != "" {
						currentTurnID = payload.TurnID
						if len(pendingTurnlessTokenSourceIDs) > 0 {
							for _, sourceID := range pendingTurnlessTokenSourceIDs {
								res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
							}
							pendingTurnlessTokenSourceIDs = nil
						}
					}
					msgID := firstNonEmpty(payload.TurnID, currentTurnID)
					if msgID == "" {
						continue
					}
					sourceID := fmt.Sprintf("complete:%s:%d", firstNonEmpty(payload.TurnID, sessionIDs[0], base), lineNum)
					res.ActionsUpdated += updateActionsForSessions(msgID, sourceID)
				case "token_count":
					msgID := currentTurnID
					sourceID := fmt.Sprintf("tk:%s:L%d", base, lineNum)
					if msgID == "" {
						pendingTurnlessTokenSourceIDs = append(pendingTurnlessTokenSourceIDs, sourceID)
						continue
					}
					res.TokenUsageUpdated += updateTokenUsageForSessions(msgID, currentModel, sourceID)
				}
			case "token_count", "usage":
				sourceID := fmt.Sprintf("tk:%s:L%d", base, lineNum)
				if currentTurnID == "" {
					pendingTurnlessTokenSourceIDs = append(pendingTurnlessTokenSourceIDs, sourceID)
					continue
				}
				res.TokenUsageUpdated += updateTokenUsageForSessions(currentTurnID, currentModel, sourceID)
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill codex message-id: walk %s: %w", sessionsDir, walkErr)
	}
	return res, nil
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// backfillOpenCodeMessageID populates message_id on actions and token_usage
// rows for the opencode adapter. Pre-parity-pass ingests stored the
// upstream message id in source_event_id (with a `message:` / `part:` /
// `tokens:` / `complete:` / `subtask:` prefix) but never wrote it to
// the dedicated message_id column, so the dashboard's per-message
// timeline / per-turn dedup couldn't see those rows.
//
// The fix is pure SQL — strip the prefix from source_event_id and
// write what's left to message_id. For tool-part rows, source_event_id
// is `part:<id>` while the parent message id is what we want; we get
// it from the actions row's link to its parent message_id (already
// populated by the post-parity adapter). The IS NULL/empty guard
// preserves any explicit value already written.
func backfillOpenCodeMessageID(ctx context.Context, db *sql.DB) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	// Actions: prefix mapping per source_event_id shape.
	//   message:<id>   → user prompt, message_id = "user:<id>"
	//   complete:<id>  → assistant completion, message_id = <id>
	//   subtask:<id>   → subagent spawn (parent's part), message_id = <part-id-derived>
	//                    parts don't carry message_id directly in source_event_id,
	//                    so subtask rows can't be cleanly backfilled here — they need
	//                    the source DB re-read. Skip in this SQL-only pass.
	//   part:<id>      → tool call; message_id is the parent message, which the part
	//                    row's parent_message_id would carry but we don't store that.
	//                    Skip in SQL-only; backfillOpenCodeParts handles it.
	//   todo:<sess>:<pos>:<tu> → todos aren't message-attached; leave message_id empty.
	//
	// So this pass handles the message-keyed rows: user prompts and
	// completions. The remaining shapes need a source DB re-read,
	// which lives in backfillOpenCodeParts.
	r, err := db.ExecContext(ctx, `
		UPDATE actions
		   SET message_id = 'user:' || substr(source_event_id, length('message:') + 1)
		 WHERE tool = 'opencode'
		   AND action_type = 'user_prompt'
		   AND source_event_id LIKE 'message:%'
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode message-id (user prompts): %w", err)
	}
	if n, _ := r.RowsAffected(); n > 0 {
		res.ActionsUpdated += int(n)
	}

	r, err = db.ExecContext(ctx, `
		UPDATE actions
		   SET message_id = substr(source_event_id, length('complete:') + 1)
		 WHERE tool = 'opencode'
		   AND action_type = 'task_complete'
		   AND source_event_id LIKE 'complete:%'
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode message-id (completions): %w", err)
	}
	if n, _ := r.RowsAffected(); n > 0 {
		res.ActionsUpdated += int(n)
	}

	// Token usage: source_event_id is `tokens:<message_id>`. Pure prefix strip.
	r, err = db.ExecContext(ctx, `
		UPDATE token_usage
		   SET message_id = substr(source_event_id, length('tokens:') + 1)
		 WHERE tool = 'opencode'
		   AND source_event_id LIKE 'tokens:%'
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode message-id (token rows): %w", err)
	}
	if n, _ := r.RowsAffected(); n > 0 {
		res.TokenUsageUpdated += int(n)
	}

	return res, nil
}

// OpenClawActionsBackfill summarises the --openclaw-action-types pass.
type OpenClawActionsBackfill struct {
	ActionsUpdated int `json:"actions_updated"`
}

// backfillOpenClawActionTypes corrects historical openclaw rows whose
// raw_tool_name is now classified more precisely than it was at ingest
// time. Today that covers:
//
//   - sessions_spawn: mcp_call → spawn_subagent
//   - process: unknown → run_command
//   - canvas / cron / memory_get / message / nodes / session_status /
//     sessions_yield / subagents / tts: unknown → mcp_call
//
// The adapter itself handles new ingests; this SQL-only pass catches
// up rows already in the DB.
func backfillOpenClawActionTypes(ctx context.Context, db *sql.DB) (OpenClawActionsBackfill, error) {
	res := OpenClawActionsBackfill{}
	r, err := db.ExecContext(ctx, `
		UPDATE actions
		   SET action_type = CASE
		         WHEN raw_tool_name = 'sessions_spawn' THEN 'spawn_subagent'
		         WHEN LOWER(raw_tool_name) = 'process' THEN 'run_command'
		         ELSE 'mcp_call'
		       END
		 WHERE tool = 'openclaw'
		   AND (
		         (raw_tool_name = 'sessions_spawn' AND action_type = 'mcp_call')
		         OR (LOWER(raw_tool_name) = 'process' AND action_type = 'unknown')
		         OR (LOWER(raw_tool_name) IN (
		              'canvas', 'cron', 'memory_get', 'message', 'nodes',
		              'session_status', 'sessions_yield', 'subagents', 'tts'
		            ) AND action_type = 'unknown')
		       )`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw action-types: %w", err)
	}
	if n, _ := r.RowsAffected(); n > 0 {
		res.ActionsUpdated = int(n)
	}
	return res, nil
}

// OpenClawSessionIDBackfill summarises the --openclaw-session-id pass.
type OpenClawSessionIDBackfill struct {
	AliasFilesScanned int `json:"alias_files_scanned"`
	SessionRowsMerged int `json:"session_rows_merged"`
	ActionsUpdated    int `json:"actions_updated"`
	TokenUsageUpdated int `json:"token_usage_updated"`
	SessionsDeleted   int `json:"sessions_deleted"`
}

// OpenClawProjectRootBackfill summarises the --openclaw-project-root pass.
type OpenClawProjectRootBackfill struct {
	FilesScanned         int `json:"files_scanned"`
	SessionsReattributed int `json:"sessions_reattributed"`
	ActionsUpdated       int `json:"actions_updated"`
}

// CursorModelBackfill summarises the --cursor-model pass.
type CursorModelBackfill struct {
	SessionsUpdated int `json:"sessions_updated"`
}

// SessionModelsBackfill summarises the --session-models pass.
type SessionModelsBackfill struct {
	SessionsUpdated int `json:"sessions_updated"`
}

// backfillSessionModels runs the ADAPTER-AGNOSTIC sessions.model rollup
// (store.BackfillSessionModels — IDE-13 / plan class C8) over every
// session in the DB: an empty sessions.model is filled from the newest
// model-bearing token_usage row of that session.
//
// This is the retroactive half of the rollup the live ingest path
// already performs (store.rollupSessionModels, run after each token
// batch). It repairs rows written BEFORE that rollup existed — the
// codex / cursor / cline / cowork sessions whose adapters emit
// ToolEvents with no Model, leaving sessions.model empty while
// token_usage.model resolved perfectly one table over.
//
// Distinct from --cursor-model, which is the cursor-only precursor of
// the same repair; running both is harmless (each only ever fills an
// EMPTY model, so whichever runs first wins and the other is a no-op).
func backfillSessionModels(ctx context.Context, db *sql.DB) (SessionModelsBackfill, error) {
	n, err := store.New(db).BackfillSessionModels(ctx)
	if err != nil {
		return SessionModelsBackfill{}, fmt.Errorf("backfill session models: %w", err)
	}
	return SessionModelsBackfill{SessionsUpdated: int(n)}, nil
}

// backfillCursorModel populates the model column on cursor session
// rows from the matching token_usage row. Pre-parity-pass the cursor
// hook decoded rawHookPayload.Model into the struct but never assigned
// it to the ToolEvent — so for sessions where only tool events landed
// before the stop token row, the session row's model stayed empty.
// (The actions table itself has no model column; per-action model is
// always read off the joining token_usage row, so there's nothing to
// backfill there.)
//
// The post-parity hook does set Model on every ToolEvent so
// UpsertSession lifts it correctly going forward; this catches up
// historical sessions whose first ingest was a tool event without a
// model and whose session row therefore stayed empty.
func backfillCursorModel(ctx context.Context, db *sql.DB) (CursorModelBackfill, error) {
	res := CursorModelBackfill{}
	r, err := db.ExecContext(ctx, `
		UPDATE sessions
		   SET model = (
		         SELECT t.model
		           FROM token_usage t
		          WHERE t.tool = 'cursor'
		            AND t.session_id = sessions.id
		            AND t.model IS NOT NULL AND t.model != ''
		          ORDER BY t.id DESC
		          LIMIT 1
		       )
		 WHERE tool = 'cursor'
		   AND (model IS NULL OR model = '')
		   AND EXISTS (
		         SELECT 1 FROM token_usage t
		          WHERE t.tool = 'cursor'
		            AND t.session_id = sessions.id
		            AND t.model IS NOT NULL AND t.model != ''
		       )`)
	if err != nil {
		return res, fmt.Errorf("backfill cursor model: %w", err)
	}
	if n, _ := r.RowsAffected(); n > 0 {
		res.SessionsUpdated = int(n)
	}
	return res, nil
}

func backfillCursorMessageID(ctx context.Context, db *sql.DB) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	result, err := db.ExecContext(ctx, `
		UPDATE actions
		   SET message_id = substr(source_event_id, 1, instr(source_event_id, ':') - 1)
		 WHERE tool = 'cursor'
		   AND action_type != 'user_prompt'
		   AND (message_id IS NULL OR message_id = '')
		   AND instr(source_event_id, ':') > 0`)
	if err != nil {
		return res, fmt.Errorf("backfill cursor message-id: %w", err)
	}
	if n, _ := result.RowsAffected(); n > 0 {
		res.ActionsUpdated = int(n)
	}
	result, err = db.ExecContext(ctx, `
		UPDATE actions
		   SET message_id = 'user:' || substr(source_event_id, 1, instr(source_event_id, ':') - 1)
		 WHERE tool = 'cursor'
		   AND action_type = 'user_prompt'
		   AND (message_id IS NULL OR message_id = '' OR message_id = substr(source_event_id, 1, instr(source_event_id, ':') - 1))
		   AND instr(source_event_id, ':') > 0`)
	if err != nil {
		return res, fmt.Errorf("backfill cursor user-prompt message-id: %w", err)
	}
	if n, _ := result.RowsAffected(); n > 0 {
		res.ActionsUpdated += int(n)
	}
	return res, nil
}

func backfillCursorHookUsage(ctx context.Context, db *sql.DB, logsDir string, fileLimit int) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}
	st := store.New(db)

	walkErr := filepath.WalkDir(logsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasPrefix(filepath.Base(path), "cursor.hooks.") || filepath.Ext(path) != ".log" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, block := range extractCursorHookInputs(string(body)) {
			res.LinesExamined++
			tk, ok, err := cursor.BuildStopTokenEvent([]byte(block))
			if err != nil || !ok {
				continue
			}
			if tk.ProjectRoot == "" || tk.SessionID == "" {
				continue
			}
			n, err := st.InsertTokenEvents(ctx, []models.TokenEvent{tk})
			if err != nil {
				return err
			}
			res.TokenUsageUpdated += n
			if tk.Model != "" {
				if _, err := db.ExecContext(ctx,
					`UPDATE sessions SET model = COALESCE(NULLIF(model, ''), ?) WHERE id = ?`,
					tk.Model, tk.SessionID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor hook usage: walk: %w", walkErr)
	}
	return res, nil
}

// OpenCodePartsBackfill summarises the --opencode-parts pass.
type OpenCodePartsBackfill struct {
	DBsScanned        int `json:"dbs_scanned"`
	PartsExamined     int `json:"parts_examined"`
	ToolOutputUpdated int `json:"tool_output_updated"`
	DurationUpdated   int `json:"duration_updated"`
	MessageIDUpdated  int `json:"message_id_updated"`
}

// backfillOpenCodeParts re-reads each opencode.db referenced by
// historical action rows and populates the post-parity-pass values
// that pure SQL can't recover:
//
//   - duration_ms on actions (State.Time.End − Start)
//   - message_id on actions for tool / subtask rows where the parent
//     message id lives in the part row itself rather than encoded in
//     source_event_id
//   - tool_output excerpts in the FTS5 action_excerpts table (where
//     ToolOutput actually lives — the actions table has no
//     tool_output column; the indexer.Indexer writes excerpts keyed
//     by action_id so search_past_outputs can retrieve them).
//
// Idempotent: actions UPDATE has IS NULL/zero guards; the indexer
// re-indexes by deleting the prior excerpt for the same action_id
// before inserting. Each opencode.db is opened read-only.
func backfillOpenCodeParts(ctx context.Context, db *sql.DB) (OpenCodePartsBackfill, error) {
	res := OpenCodePartsBackfill{}

	srcRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM actions
		 WHERE tool = 'opencode'
		   AND source_file IS NOT NULL
		   AND source_file != ''`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode-parts: list source_files: %w", err)
	}
	var dbPaths []string
	for srcRows.Next() {
		var p string
		if err := srcRows.Scan(&p); err != nil {
			srcRows.Close()
			return res, err
		}
		dbPaths = append(dbPaths, p)
	}
	srcRows.Close()

	// Two prepared statements: one to update the persistent action row
	// (duration + message_id), one to look up the action's id +
	// metadata so we can write its excerpt to action_excerpts.
	updateAction, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET duration_ms = CASE
		           WHEN duration_ms IS NULL OR duration_ms = 0 THEN ?
		           ELSE duration_ms
		       END,
		       message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE tool = 'opencode'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND ((duration_ms IS NULL OR duration_ms = 0)
		        OR (message_id IS NULL OR message_id = ''))`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode-parts: prepare action update: %w", err)
	}
	defer updateAction.Close()

	lookupAction, err := db.PrepareContext(ctx, `
		SELECT id, COALESCE(raw_tool_name, ''), COALESCE(target, ''), COALESCE(error_message, '')
		  FROM actions
		 WHERE tool = 'opencode'
		   AND source_file = ?
		   AND source_event_id = ?`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode-parts: prepare action lookup: %w", err)
	}
	defer lookupAction.Close()

	excerptExists, err := db.PrepareContext(ctx, `
		SELECT 1 FROM action_excerpts WHERE action_id = ? LIMIT 1`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode-parts: prepare excerpt check: %w", err)
	}
	defer excerptExists.Close()

	indexer := indexing.New(db, 0) // 0 → DefaultMaxExcerptBytes (2KB)

	for _, dbPath := range dbPaths {
		if _, err := os.Stat(dbPath); err != nil {
			continue // db gone — skip silently
		}
		ocDB, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(dbPath)))
		if err != nil {
			continue
		}
		res.DBsScanned++

		partRows, err := ocDB.QueryContext(ctx, `
			SELECT p.id, COALESCE(p.message_id, ''), p.data
			  FROM part p
			 WHERE json_extract(p.data, '$.type') IN ('tool', 'subtask')`)
		if err != nil {
			ocDB.Close()
			continue
		}
		for partRows.Next() {
			var (
				partID    string
				messageID string
				data      string
			)
			if err := partRows.Scan(&partID, &messageID, &data); err != nil {
				partRows.Close()
				ocDB.Close()
				return res, err
			}
			res.PartsExamined++

			var part struct {
				Type  string `json:"type"`
				State struct {
					Output   string `json:"output"`
					Metadata struct {
						Output string `json:"output"`
					} `json:"metadata"`
					Time struct {
						Start int64 `json:"start"`
						End   int64 `json:"end"`
					} `json:"time"`
				} `json:"state"`
			}
			if err := json.Unmarshal([]byte(data), &part); err != nil {
				continue
			}
			output := part.State.Output
			if output == "" {
				output = part.State.Metadata.Output
			}
			var durationMs int64
			if part.State.Time.Start > 0 && part.State.Time.End > part.State.Time.Start {
				durationMs = part.State.Time.End - part.State.Time.Start
			}
			if output == "" && durationMs == 0 && messageID == "" {
				continue
			}

			// SourceEventID the adapter writes for tool parts is `part:<id>`,
			// for subtask parts it's `subtask:<id>`. Try both shapes; the
			// IS-NULL/zero guards make the wrong one a no-op.
			for _, prefix := range []string{"part:", "subtask:"} {
				sourceID := prefix + partID
				r, err := updateAction.ExecContext(ctx, durationMs, messageID, dbPath, sourceID)
				if err != nil {
					continue
				}
				if n, _ := r.RowsAffected(); n > 0 {
					if durationMs > 0 {
						res.DurationUpdated += int(n)
					}
					if messageID != "" {
						res.MessageIDUpdated += int(n)
					}
				}

				// Index the tool output excerpt against this action's id.
				// Skip when the action row didn't exist (sourceID didn't
				// match) or when an excerpt is already indexed.
				if output == "" {
					continue
				}
				var (
					actionID int64
					rawTool  string
					target   string
					errMsg   string
				)
				if err := lookupAction.QueryRowContext(ctx, dbPath, sourceID).Scan(&actionID, &rawTool, &target, &errMsg); err != nil {
					continue
				}
				var present int
				if err := excerptExists.QueryRowContext(ctx, actionID).Scan(&present); err == nil && present == 1 {
					continue // already indexed
				}
				if err := indexer.Index(ctx, actionID, rawTool, target, output, errMsg); err != nil {
					continue
				}
				res.ToolOutputUpdated++
				break
			}
		}
		partRows.Close()
		ocDB.Close()
	}
	return res, nil
}

// OpenClawModelBackfill summarises the --openclaw-model pass.
type OpenClawModelBackfill struct {
	AliasFilesScanned int `json:"alias_files_scanned"`
	AliasesLoaded     int `json:"aliases_loaded"`
	SessionsUpdated   int `json:"sessions_updated"`
}

// backfillOpenClawModel populates the model column on openclaw
// SESSION rows whose model is empty. Pre-parity-pass the sqlite-path
// taskPromptEvent / taskCompleteEvent set Model="" on the ToolEvent,
// which became sessions.model="" via UpsertSession. The parity adapter
// looks the model up via sessions.json aliases; this backfill catches
// up historical session rows.
//
// (Note: the actions table has no model column — per-action model is
// always derived from the joining token_usage row. There's nothing to
// backfill on actions for OpenClaw model; the gap is on sessions.)
//
// Strategy: for each runs.sqlite file referenced by openclaw actions,
// (1) load every sibling sessions.json under .../agents/*/sessions/,
// (2) walk task_runs and resolve each row's session_id via the same
// key-priority chain the adapter uses, (3) UPDATE sessions SET model
// where the resolved alias has provider/model and the session row's
// model is empty.
func backfillOpenClawModel(ctx context.Context, db *sql.DB) (OpenClawModelBackfill, error) {
	res := OpenClawModelBackfill{}

	srcRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM actions
		 WHERE tool = 'openclaw'
		   AND source_file LIKE '%runs.sqlite'`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-model: list runs.sqlite paths: %w", err)
	}
	var runsPaths []string
	for srcRows.Next() {
		var p string
		if err := srcRows.Scan(&p); err != nil {
			srcRows.Close()
			return res, err
		}
		runsPaths = append(runsPaths, p)
	}
	srcRows.Close()

	updateSession, err := db.PrepareContext(ctx, `
		UPDATE sessions
		   SET model = ?
		 WHERE id = ?
		   AND tool = 'openclaw'
		   AND (model IS NULL OR model = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-model: prepare session update: %w", err)
	}
	defer updateSession.Close()

	for _, runsPath := range runsPaths {
		if _, err := os.Stat(runsPath); err != nil {
			continue
		}
		// Sibling agents/ tree lives at .openclaw/agents/ (parent of tasks/).
		agentsRoot := filepath.Join(filepath.Dir(filepath.Dir(runsPath)), "agents")

		// Load aliases.
		aliases := map[string]struct {
			Provider string
			Model    string
		}{}
		matches, _ := filepath.Glob(filepath.Join(agentsRoot, "*", "sessions", "sessions.json"))
		for _, indexPath := range matches {
			body, err := os.ReadFile(indexPath)
			if err != nil {
				continue
			}
			res.AliasFilesScanned++
			var idx map[string]struct {
				SessionID     string `json:"sessionId"`
				ModelProvider string `json:"modelProvider"`
				Model         string `json:"model"`
				SystemPrompt  struct {
					Provider string `json:"provider"`
					Model    string `json:"model"`
				} `json:"systemPromptReport"`
			}
			if err := json.Unmarshal(body, &idx); err != nil {
				continue
			}
			for key, entry := range idx {
				provider := entry.ModelProvider
				if provider == "" {
					provider = entry.SystemPrompt.Provider
				}
				model := entry.Model
				if model == "" {
					model = entry.SystemPrompt.Model
				}
				if provider == "" && model == "" {
					continue
				}
				aliases[key] = struct {
					Provider string
					Model    string
				}{provider, model}
				if entry.SessionID != "" {
					aliases[entry.SessionID] = struct {
						Provider string
						Model    string
					}{provider, model}
				}
				res.AliasesLoaded++
			}
		}

		// Walk task_runs and resolve each row's session_id + model via the
		// same priority chain the adapter uses (child_session_key →
		// owner_key → requester_session_key → run_id → source_id → task_id).
		ocDB, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(runsPath)))
		if err != nil {
			continue
		}
		taskRows, err := ocDB.QueryContext(ctx, `
			SELECT task_id, COALESCE(child_session_key, ''), owner_key,
			       COALESCE(requester_session_key, ''), COALESCE(run_id, ''),
			       COALESCE(source_id, '')
			  FROM task_runs`)
		if err != nil {
			ocDB.Close()
			continue
		}
		for taskRows.Next() {
			var taskID, child, owner, requester, run, source string
			if err := taskRows.Scan(&taskID, &child, &owner, &requester, &run, &source); err != nil {
				taskRows.Close()
				ocDB.Close()
				return res, err
			}
			// Resolve the session_id: same priority chain as
			// openclaw/adapter.go::sessionID().
			sessionID := ""
			for _, key := range []string{child, owner, requester, run, source, taskID} {
				if key != "" {
					sessionID = key
					break
				}
			}
			if sessionID == "" {
				continue
			}
			// Resolve the alias by trying the same keys.
			var alias struct {
				Provider string
				Model    string
			}
			for _, key := range []string{child, owner, requester, run, source} {
				if a, ok := aliases[key]; ok && (a.Provider != "" || a.Model != "") {
					alias = a
					break
				}
			}
			if alias.Provider == "" && alias.Model == "" {
				continue
			}
			model := alias.Model
			if alias.Provider != "" && alias.Model != "" {
				model = alias.Provider + "/" + alias.Model
			}
			r, err := updateSession.ExecContext(ctx, model, sessionID)
			if err != nil {
				continue
			}
			if n, _ := r.RowsAffected(); n > 0 {
				res.SessionsUpdated += int(n)
			}
		}
		taskRows.Close()
		ocDB.Close()
	}
	return res, nil
}

func openclawProjectRootBackfillDirs() []string {
	var dirs []string
	for _, h := range crossmount.AllHomes() {
		dirs = append(dirs, filepath.Join(h.Path, ".openclaw", "agents"))
	}
	return dirs
}

// backfillOpenClawSessionID collapses historical openclaw split
// sessions created when sessions.json emitted raw `sessionId` while
// JSONL + task_runs used the alias/session-key form. The adapter now
// canonicalizes to sessionKey/alias first; this pass merges any old
// raw-id rows onto that canonical session id.
func backfillOpenClawSessionID(ctx context.Context, db *sql.DB, agentsDirs []string, fileLimit int) (OpenClawSessionIDBackfill, error) {
	res := OpenClawSessionIDBackfill{}

	insertTarget, err := db.PrepareContext(ctx, `
		INSERT INTO sessions (
			id, project_id, tool, model, git_branch, started_at, ended_at,
			total_actions, metadata, quality_score, redundancy_ratio,
			error_rate, onboarding_cost, turns_to_first_edit, retry_cost_tokens
		)
		SELECT ?, project_id, tool, model, git_branch, started_at, ended_at,
		       total_actions, metadata, quality_score, redundancy_ratio,
		       error_rate, onboarding_cost, turns_to_first_edit, retry_cost_tokens
		  FROM sessions
		 WHERE id = ?
		   AND tool = 'openclaw'
		ON CONFLICT(id) DO UPDATE SET
		   model = COALESCE(NULLIF(excluded.model, ''), sessions.model),
		   git_branch = COALESCE(NULLIF(excluded.git_branch, ''), sessions.git_branch),
		   started_at = MIN(sessions.started_at, excluded.started_at),
		   ended_at = COALESCE(excluded.ended_at, sessions.ended_at),
		   total_actions = MAX(sessions.total_actions, excluded.total_actions),
		   metadata = COALESCE(NULLIF(excluded.metadata, ''), sessions.metadata),
		   quality_score = COALESCE(excluded.quality_score, sessions.quality_score),
		   redundancy_ratio = COALESCE(excluded.redundancy_ratio, sessions.redundancy_ratio),
		   error_rate = COALESCE(excluded.error_rate, sessions.error_rate),
		   onboarding_cost = COALESCE(excluded.onboarding_cost, sessions.onboarding_cost),
		   turns_to_first_edit = COALESCE(excluded.turns_to_first_edit, sessions.turns_to_first_edit),
		   retry_cost_tokens = COALESCE(excluded.retry_cost_tokens, sessions.retry_cost_tokens)`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-session-id: prepare session merge: %w", err)
	}
	defer insertTarget.Close()

	updateActions, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET session_id = ?,
		       project_id = COALESCE((SELECT project_id FROM sessions WHERE id = ?), project_id)
		 WHERE tool = 'openclaw'
		   AND session_id = ?`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-session-id: prepare actions update: %w", err)
	}
	defer updateActions.Close()

	updateTokens, err := db.PrepareContext(ctx, `
		UPDATE token_usage
		   SET session_id = ?
		 WHERE tool = 'openclaw'
		   AND session_id = ?`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-session-id: prepare token update: %w", err)
	}
	defer updateTokens.Close()

	deleteSession, err := db.PrepareContext(ctx, `
		DELETE FROM sessions
		 WHERE id = ?
		   AND tool = 'openclaw'
		   AND NOT EXISTS (SELECT 1 FROM actions WHERE session_id = sessions.id)
		   AND NOT EXISTS (SELECT 1 FROM token_usage WHERE session_id = sessions.id)`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-session-id: prepare session delete: %w", err)
	}
	defer deleteSession.Close()

	for _, agentsDir := range agentsDirs {
		walkErr := filepath.WalkDir(agentsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() || strings.ToLower(filepath.Base(path)) != "sessions.json" {
				return nil
			}
			if fileLimit > 0 && res.AliasFilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.AliasFilesScanned++

			idx, err := loadOpenClawBackfillIndex(path)
			if err != nil {
				return nil
			}
			for key, entry := range idx {
				canonical := canonicalOpenClawBackfillSessionID(entry, key)
				legacy := strings.TrimSpace(entry.SessionID)
				if canonical == "" || legacy == "" || canonical == legacy {
					continue
				}
				if _, err := insertTarget.ExecContext(ctx, canonical, legacy); err != nil {
					return err
				}
				if r, err := updateActions.ExecContext(ctx, canonical, canonical, legacy); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.ActionsUpdated += int(n)
						res.SessionRowsMerged++
					}
				}
				if r, err := updateTokens.ExecContext(ctx, canonical, legacy); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.TokenUsageUpdated += int(n)
					}
				}
				if r, err := deleteSession.ExecContext(ctx, legacy); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.SessionsDeleted += int(n)
					}
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			return res, fmt.Errorf("backfill openclaw-session-id: walk %s: %w", agentsDir, walkErr)
		}
	}
	return res, nil
}

// backfillOpenClawProjectRoot re-attributes openclaw action / session
// rows to the real project derived from sessions.json
// systemPromptReport.workspaceDir. Pre-fix the adapter fed foreign-OS
// paths directly to git.Resolve and returned "[openclaw]" when the
// workspace couldn't be resolved, so live rows often coalesced under
// the placeholder instead of the actual repo (audit B3, 2026-05-19).
func backfillOpenClawProjectRoot(ctx context.Context, db *sql.DB, agentsDirs []string, fileLimit int) (OpenClawProjectRootBackfill, error) {
	res := OpenClawProjectRootBackfill{}
	st := store.New(db)

	updateSession, err := db.PrepareContext(ctx,
		`UPDATE sessions SET project_id = ? WHERE id = ? AND tool = 'openclaw' AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-project-root: prepare session: %w", err)
	}
	defer updateSession.Close()

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions SET project_id = ? WHERE tool = 'openclaw' AND session_id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-project-root: prepare actions: %w", err)
	}
	defer updateActions.Close()

	for _, agentsDir := range agentsDirs {
		walkErr := filepath.WalkDir(agentsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() || strings.ToLower(filepath.Base(path)) != "sessions.json" {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.FilesScanned++

			idx, err := loadOpenClawBackfillIndex(path)
			if err != nil {
				return nil
			}
			for key, entry := range idx {
				projectRoot, remote := resolveOpenClawProjectRootForBackfill(strings.TrimSpace(entry.SystemPromptReport.WorkspaceDir))
				if projectRoot == "" {
					continue
				}
				pid, err := st.UpsertProject(ctx, projectRoot, remote)
				if err != nil {
					continue
				}
				for _, sid := range uniqueNonEmptyStrings(
					canonicalOpenClawBackfillSessionID(entry, key),
					strings.TrimSpace(entry.SessionID),
				) {
					if r, err := updateSession.ExecContext(ctx, pid, sid, pid); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.SessionsReattributed += int(n)
						}
					}
					if r, err := updateActions.ExecContext(ctx, pid, sid, pid); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.ActionsUpdated += int(n)
						}
					}
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			return res, fmt.Errorf("backfill openclaw-project-root: walk %s: %w", agentsDir, walkErr)
		}
	}
	return res, nil
}

type openclawBackfillIndex map[string]openclawBackfillIndexEntry

type openclawBackfillIndexEntry struct {
	SessionID          string `json:"sessionId"`
	SystemPromptReport struct {
		SessionKey   string `json:"sessionKey"`
		WorkspaceDir string `json:"workspaceDir"`
	} `json:"systemPromptReport"`
}

func loadOpenClawBackfillIndex(path string) (openclawBackfillIndex, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var idx openclawBackfillIndex
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, err
	}
	return idx, nil
}

func canonicalOpenClawBackfillSessionID(entry openclawBackfillIndexEntry, key string) string {
	return firstNonEmpty(
		strings.TrimSpace(entry.SystemPromptReport.SessionKey),
		strings.TrimSpace(key),
		strings.TrimSpace(entry.SessionID),
	)
}

// resolveOpenClawProjectRootForBackfill mirrors
// openclaw.Adapter.resolveProjectRoot (B3): it returns the resolved
// project root plus its normalized git remote so backfill-driven
// reattribution converges on the same (root, remote) pair the live
// parser would have written.
func resolveOpenClawProjectRootForBackfill(cwd string) (string, string) {
	if cwd == "" {
		return "", ""
	}
	translated := crossmount.TranslateForeignPath(cwd)
	if _, err := os.Stat(translated); err == nil {
		if info, err := git.Resolve(translated); err == nil && info.IsGit {
			return info.Root, git.NormalizeRemote(info.Remote)
		}
		return translated, ""
	}
	return cwd, ""
}

func uniqueNonEmptyStrings(values ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// CodexReasoningBackfill summarises the --codex-reasoning pass.
type CodexReasoningBackfill struct {
	FilesScanned   int `json:"files_scanned"`
	LinesExamined  int `json:"lines_examined"`
	TurnsCaptured  int `json:"turns_captured"`
	ActionsUpdated int `json:"actions_updated"`
}

// CodexProjectRootBackfill summarises the --codex-project-root pass.
// SessionsReattributed counts sessions whose project_id changed;
// ActionsUpdated counts the cascaded action rows. token_usage has no
// project_id column (the cost engine joins to sessions for project
// context), so it's not surfaced here.
type CodexProjectRootBackfill struct {
	FilesScanned         int `json:"files_scanned"`
	SessionsReattributed int `json:"sessions_reattributed"`
	ActionsUpdated       int `json:"actions_updated"`
}

// CodexForkDedupBackfill summarises the --codex-fork-dedup pass.
// RowsMatched is the count of token_usage rows the fork-replay detector
// identified as duplicates of a parent rollout's telemetry; RowsDeleted
// is 0 on a dry run and equals RowsMatched (minus already-gone rows) on
// --apply. Input/Output/CacheReadTokens sum the matched rows' token
// columns; SessionsTouched is the distinct sessions whose rows matched;
// FilesMissing counts source_files whose rollout is no longer on disk;
// LineageBackfilled counts sessions whose fork lineage was (or would be)
// filled in from the rollout's session_meta.
type CodexForkDedupBackfill struct {
	FilesScanned      int     `json:"files_scanned"`
	FilesMissing      int     `json:"files_missing"`
	RowsMatched       int     `json:"rows_matched"`
	RowsDeleted       int     `json:"rows_deleted"`
	InputTokens       int64   `json:"input_tokens"`
	OutputTokens      int64   `json:"output_tokens"`
	CacheReadTokens   int64   `json:"cache_read_tokens"`
	ReasoningTokens   int64   `json:"reasoning_tokens"`
	WebSearchRequests int64   `json:"web_search_requests"`
	EstimatedCostUSD  float64 `json:"estimated_cost_usd"`
	SessionsTouched   int     `json:"sessions_touched"`
	// LineageBackfilled counts sessions whose fork lineage was actually
	// written. On --apply it counts only sessions where SetSessionLineage
	// changed a row (a re-run over already-stamped sessions reports 0);
	// on a dry run it counts the candidate sessions that WOULD be
	// stamped.
	LineageBackfilled int  `json:"lineage_backfilled"`
	Applied           bool `json:"applied"`
}

// codexProjectRootBackfillDirs returns the set of codex sessions
// directories to scan: every crossmount-resolved home's .codex/sessions,
// or just the CODEX_HOME override when set. Exposed so the cmd
// dispatcher and tests can compute / inject the same set.
func codexProjectRootBackfillDirs() []string {
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return []string{filepath.Join(v, "sessions")}
	}
	var dirs []string
	for _, h := range crossmount.AllHomes() {
		dirs = append(dirs, filepath.Join(h.Path, ".codex", "sessions"))
	}
	return dirs
}

// backfillCodexProjectRoot re-attributes codex action / token /
// session rows to the correct project when their cwd was a
// Windows-style path. Pre-v1.4.28 the codex adapter passed cwd
// directly to git.Resolve, which on a non-Windows host treats
// "c:\foo\bar" as a relative path, prepends the observer's CWD, and
// then walks UP that bogus path looking for .git — landing on
// observer's own repo in the worst case. v1.4.28's adapter fix
// translates the cwd via crossmount.TranslateForeignPath; this
// backfill applies the same translation to rows ingested before the
// fix shipped, so existing data converges to the correct project.
//
// Walks codex rollout JSONL across every supplied directory — the
// dispatcher passes crossmount-resolved homes so /mnt/c/Users/*/.codex
// is included when observer runs on WSL2. Each file's first
// session_meta line provides the cwd. We translate, run git.Resolve,
// upsert the project, and UPDATE the session, all of its actions, and
// all of its token_usage rows to point to the new project_id when it
// differs.
func backfillCodexProjectRoot(ctx context.Context, db *sql.DB, sessionsDirs []string, fileLimit int) (CodexProjectRootBackfill, error) {
	res := CodexProjectRootBackfill{}

	st := store.New(db)

	updateSession, err := db.PrepareContext(ctx,
		`UPDATE sessions SET project_id = ? WHERE id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill codex-project-root: prepare session: %w", err)
	}
	defer updateSession.Close()

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions SET project_id = ? WHERE session_id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill codex-project-root: prepare actions: %w", err)
	}
	defer updateActions.Close()

	// token_usage has no project_id column — the cost engine resolves
	// project context by joining token_usage → sessions, so updating
	// the session row is enough to fix the per-project rollup.

	for _, sessionsDir := range sessionsDirs {
		walkErr := filepath.WalkDir(sessionsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			if filepath.Ext(path) != ".jsonl" || !strings.HasPrefix(base, "rollout-") {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.FilesScanned++

			sessionID, cwd, ok := readCodexSessionMeta(path)
			if !ok || sessionID == "" || cwd == "" {
				return nil
			}
			translated := crossmount.TranslateForeignPath(cwd)
			info, gerr := git.Resolve(translated)
			if gerr != nil {
				return nil
			}
			newRoot := info.Root
			if newRoot == "" {
				return nil
			}
			// git.Resolve succeeded above (gerr checked), so info.Remote
			// reflects this cwd's "origin" remote when it has one; B3
			// normalizes it the same way the live codex parser does.
			pid, err := st.UpsertProject(ctx, newRoot, git.NormalizeRemote(info.Remote))
			if err != nil {
				return nil
			}

			if r, err := updateSession.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.SessionsReattributed += int(n)
				}
			}
			if r, err := updateActions.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			// Per-tree errors are non-fatal — the watcher tolerates the
			// same failure modes (ENOENT on a stale crossmount home,
			// EACCES on a Windows-side directory).
			continue
		}
	}
	return res, nil
}

// codexForkDedupDeleteBatch bounds how many source_event_ids one DELETE
// transaction carries so a huge forked file can't build an unbounded
// IN(...) list or hold one long-running write lock.
const codexForkDedupDeleteBatch = 500

// lastPathSegment returns the final path segment of p, treating BOTH
// '/' and '\\' as separators regardless of the host OS. Unlike
// filepath.Base (which honors only the runtime's own separator), this
// recovers the basename of a foreign-OS path — a Windows-captured
// rollout's "C:\\Users\\x\\rollout.jsonl" read from a Linux observer
// yields "rollout.jsonl", matching the source_event_id the Windows-side
// parse built with filepath.Base. Returns p unchanged when it holds no
// separator.
func lastPathSegment(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// backfillCodexForkDedup purges historical duplicate codex token_usage
// rows that a fork / subagent spawn created by replaying its parent
// rollout's token_count telemetry into the child's rollout file. The
// ingest fix (codex.ReplayedTokenLines) now suppresses these at parse
// time; this pass cleans up rows inserted before the fix shipped.
//
// It enumerates the DISTINCT source_file of codex token_usage rows,
// re-runs codex.ReplayedTokenLines over each file still on disk, and
// matches the replayed lines' synthetic source_event_ids
// ("tk:<basename>:L<line>") against the stored rows. DRY-RUN BY DEFAULT
// (apply=false): it only tallies matched rows / summed tokens / touched
// sessions and deletes nothing. With apply=true it DELETEs the matched
// rows in bounded transactions. Deletion is keyed by (source_file,
// source_event_id) so a second --apply is a natural no-op.
//
// As a cheap bonus it captures each file's session lineage
// (forked_from_id / parent_thread_id / thread_source) via
// codex.ScanForkLineage and persists it with Store.SetSessionLineage so
// pre-fix sessions gain the lineage the ingest path now records. Lineage
// is only written on apply; the dry run reports what it would set.
//
// Foreign-OS paths (a Windows-captured rollout read from a WSL2
// observer) are handled the way the sibling project-root backfills do:
// when the stored source_file no longer stats, a
// crossmount.TranslateForeignPath fallback is attempted before treating
// the file as missing. out receives per-file notes when non-nil (the
// caller passes nil under --json).
func backfillCodexForkDedup(ctx context.Context, database *sql.DB, apply bool, fileLimit int, out io.Writer) (CodexForkDedupBackfill, error) {
	res := CodexForkDedupBackfill{Applied: apply}
	st := store.New(database)

	rows, err := database.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM token_usage
		 WHERE tool = 'codex'
		   AND source_file IS NOT NULL
		   AND source_file != ''
		 ORDER BY source_file`)
	if err != nil {
		return res, fmt.Errorf("backfill codex-fork-dedup: list source_files: %w", err)
	}
	var files []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			rows.Close()
			return res, fmt.Errorf("backfill codex-fork-dedup: scan source_file: %w", err)
		}
		files = append(files, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("backfill codex-fork-dedup: iterate source_files: %w", err)
	}

	sessionsSeen := map[string]bool{}

	for _, sourceFile := range files {
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			break
		}

		// Resolve the on-disk path: prefer the stored path; fall back
		// to a crossmount translation for foreign-OS (Windows) paths
		// captured before the observer moved to WSL, mirroring the
		// sibling project-root backfills.
		diskPath := sourceFile
		if _, statErr := os.Stat(diskPath); statErr != nil {
			if translated := crossmount.TranslateForeignPath(sourceFile); translated != sourceFile {
				if _, statErr2 := os.Stat(translated); statErr2 == nil {
					diskPath = translated
				}
			}
		}

		f, openErr := os.Open(diskPath)
		if openErr != nil {
			res.FilesMissing++
			if out != nil {
				fmt.Fprintf(out, "  skip %s (rollout no longer on disk)\n", sourceFile)
			}
			continue
		}
		res.FilesScanned++

		replayed, scanErr := codex.ReplayedTokenLines(f)
		f.Close()
		if scanErr != nil {
			if out != nil {
				fmt.Fprintf(out, "  warn %s: scan failed: %v\n", sourceFile, scanErr)
			}
			continue
		}

		// Bonus: retrofit the owning session's fork lineage. Cheap
		// second read of a small header; independent of the delete set.
		if lf, lopenErr := os.Open(diskPath); lopenErr == nil {
			lin, ok, lerr := codex.ScanForkLineage(lf)
			lf.Close()
			hasLineage := ok && lin.SessionID != "" &&
				(lin.ForkedFromID != "" || lin.ParentThreadID != "" || lin.ThreadSource != "")
			if lerr == nil && hasLineage {
				if apply {
					// Count only when the UPDATE actually changed a row —
					// a re-run over an already-stamped session returns
					// changed=false, so the counter stays honest.
					if changed, serr := st.SetSessionLineage(ctx, models.SessionLineage{
						SessionID:      lin.SessionID,
						ForkedFromID:   lin.ForkedFromID,
						ParentThreadID: lin.ParentThreadID,
						ThreadSource:   lin.ThreadSource,
					}); serr == nil && changed {
						res.LineageBackfilled++
					}
				} else {
					// Dry-run: count only what an --apply UPDATE would
					// actually change — the session must EXIST and at
					// least one supplied marker must differ from what's
					// stored (mirrors SetSessionLineage's WHERE guard).
					var curFork, curParent, curSource string
					qerr := database.QueryRowContext(ctx,
						`SELECT IFNULL(forked_from_id, ''), IFNULL(parent_thread_id, ''), IFNULL(thread_source, '')
						   FROM sessions WHERE id = ?`, lin.SessionID).
						Scan(&curFork, &curParent, &curSource)
					switch {
					case errors.Is(qerr, sql.ErrNoRows):
						// Session never ingested — nothing to backfill.
					case qerr != nil:
						return res, fmt.Errorf("backfill codex-fork-dedup: check lineage for %s: %w", lin.SessionID, qerr)
					case (lin.ForkedFromID != "" && lin.ForkedFromID != curFork) ||
						(lin.ParentThreadID != "" && lin.ParentThreadID != curParent) ||
						(lin.ThreadSource != "" && lin.ThreadSource != curSource):
						res.LineageBackfilled++
					}
				}
			}
		}

		if len(replayed) == 0 {
			continue
		}

		// Build the replayed source_event_id set the adapter would have
		// written for these lines. Use a separator-aware basename: the
		// adapter builds the id with filepath.Base at PARSE time on the
		// capturing host, so a Windows-captured rollout carries a
		// backslash-separated path in source_file. filepath.Base on a
		// Linux observer would return the whole "C:\\...\\rollout.jsonl"
		// string and never match "tk:rollout.jsonl:L<n>". lastPathSegment
		// strips after the last '/' OR '\\' regardless of host OS.
		base := lastPathSegment(sourceFile)
		wantIDs := make(map[string]bool, len(replayed))
		for ln := range replayed {
			wantIDs[fmt.Sprintf("tk:%s:L%d", base, ln)] = true
		}

		urows, qerr := database.QueryContext(ctx, `
			SELECT session_id, source_event_id,
			       COALESCE(input_tokens, 0), COALESCE(output_tokens, 0), COALESCE(cache_read_tokens, 0),
			       COALESCE(reasoning_tokens, 0), COALESCE(web_search_requests, 0), COALESCE(estimated_cost_usd, 0)
			  FROM token_usage
			 WHERE tool = 'codex' AND source_file = ?`, sourceFile)
		if qerr != nil {
			return res, fmt.Errorf("backfill codex-fork-dedup: select rows for %s: %w", sourceFile, qerr)
		}
		var matchedIDs []string
		var fileMatched int
		var fileInput, fileOutput, fileCacheRead, fileReasoning, fileWebSearch int64
		var fileCost float64
		fileSessions := map[string]bool{}
		for urows.Next() {
			var sid, eid string
			var in, outp, cr, reason, web int64
			var cost float64
			if err := urows.Scan(&sid, &eid, &in, &outp, &cr, &reason, &web, &cost); err != nil {
				urows.Close()
				return res, fmt.Errorf("backfill codex-fork-dedup: scan row: %w", err)
			}
			if !wantIDs[eid] {
				continue
			}
			matchedIDs = append(matchedIDs, eid)
			fileMatched++
			fileInput += in
			fileOutput += outp
			fileCacheRead += cr
			fileReasoning += reason
			fileWebSearch += web
			fileCost += cost
			fileSessions[sid] = true
			sessionsSeen[sid] = true
		}
		urows.Close()
		if err := urows.Err(); err != nil {
			return res, fmt.Errorf("backfill codex-fork-dedup: iterate rows: %w", err)
		}

		res.RowsMatched += fileMatched
		res.InputTokens += fileInput
		res.OutputTokens += fileOutput
		res.CacheReadTokens += fileCacheRead
		res.ReasoningTokens += fileReasoning
		res.WebSearchRequests += fileWebSearch
		res.EstimatedCostUSD += fileCost

		if fileMatched > 0 && out != nil {
			fmt.Fprintf(
				out,
				"  %s: %d duplicate token row(s) (input=%d output=%d cache_read=%d reasoning=%d web_search=%d est_cost=$%.4f) across %d session(s)\n",
				sourceFile, fileMatched, fileInput, fileOutput, fileCacheRead, fileReasoning, fileWebSearch, fileCost, len(fileSessions),
			)
		}

		if apply && len(matchedIDs) > 0 {
			deleted, derr := deleteCodexForkDedupRows(ctx, database, sourceFile, matchedIDs)
			if derr != nil {
				return res, derr
			}
			res.RowsDeleted += deleted
		}
	}

	res.SessionsTouched = len(sessionsSeen)
	return res, nil
}

// deleteCodexForkDedupRows deletes the given token_usage rows for one
// source_file in bounded transactions, returning the total rows
// affected. Keyed by (source_file, source_event_id) so re-runs are
// idempotent (already-deleted rows simply match nothing).
func deleteCodexForkDedupRows(ctx context.Context, database *sql.DB, sourceFile string, eventIDs []string) (int, error) {
	total := 0
	for start := 0; start < len(eventIDs); start += codexForkDedupDeleteBatch {
		end := start + codexForkDedupDeleteBatch
		if end > len(eventIDs) {
			end = len(eventIDs)
		}
		batch := eventIDs[start:end]

		placeholders := make([]string, len(batch))
		args := make([]any, 0, len(batch)+1)
		args = append(args, sourceFile)
		for i, id := range batch {
			placeholders[i] = "?"
			args = append(args, id)
		}
		// nolint:gosec // placeholders is a fixed count of '?', values bound.
		query := `DELETE FROM token_usage WHERE tool = 'codex' AND source_file = ? AND source_event_id IN (` +
			strings.Join(placeholders, ",") + `)`

		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return total, fmt.Errorf("backfill codex-fork-dedup: begin tx: %w", err)
		}
		r, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			_ = tx.Rollback()
			return total, fmt.Errorf("backfill codex-fork-dedup: delete batch: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return total, fmt.Errorf("backfill codex-fork-dedup: commit: %w", err)
		}
		n, _ := r.RowsAffected()
		total += int(n)
	}
	return total, nil
}

// ClaudeCodeProjectRootBackfill summarises the --claudecode-project-root pass.
// Mirrors CodexProjectRootBackfill — token_usage has no project_id column,
// so per-session attribution is fixed via sessions.project_id and the
// cost engine's join walks naturally.
type ClaudeCodeProjectRootBackfill struct {
	FilesScanned         int `json:"files_scanned"`
	SessionsReattributed int `json:"sessions_reattributed"`
	ActionsUpdated       int `json:"actions_updated"`
}

// claudecodeProjectRootBackfillDirs returns the claude-code session
// projects roots across every crossmount-resolved home, matching the
// adapter's WatchPaths() expansion. WSL2 observers pick up
// /mnt/c/Users/*/.claude/projects automatically.
func claudecodeProjectRootBackfillDirs() []string {
	var dirs []string
	for _, h := range crossmount.AllHomes() {
		dirs = append(dirs, filepath.Join(h.Path, ".claude", "projects"))
	}
	return dirs
}

// backfillClaudecodeProjectRoot re-attributes claude-code action /
// session rows to the correct project when their cwd was a Windows-
// style path. Pre-v1.6.10 the claudecode adapter passed cwd directly
// to git.Resolve, which on a non-Windows host treats "C:\foo\bar" as
// a relative path, prepends the observer's CWD, and the .git-walk
// lands on observer's own repo — every Windows-side claude-code
// session ends up filed under /home/marmutapp/superbased-observer in
// the dashboard's project view (audit B1, 2026-05-18:
// 90 sessions / 3,536 rows on the maintainer DB before the fix).
// v1.6.10's adapter fix translates the cwd via
// crossmount.TranslateForeignPath; this backfill applies the same
// translation to rows ingested before the fix shipped, so existing
// data converges to the correct project.
//
// Walks every *.jsonl under the supplied project-tree directories.
// Subagent files (`<sid>/subagents/agent-*.jsonl`) inherit the
// parent's sessionId but carry their own cwd line, so they CAN
// recover a session whose parent JSONL is no longer on disk —
// important because ~36 sessions in the maintainer corpus are
// parent-absent with only subagent traces remaining. First file per
// session_id wins (we use a seen-set to skip the rest).
//
// token_usage has no project_id column — the cost engine resolves
// project context by joining token_usage → sessions, so updating
// the session row is enough to fix the per-project rollup.
func backfillClaudecodeProjectRoot(ctx context.Context, db *sql.DB, projectDirs []string, fileLimit int) (ClaudeCodeProjectRootBackfill, error) {
	res := ClaudeCodeProjectRootBackfill{}
	st := store.New(db)

	updateSession, err := db.PrepareContext(ctx,
		`UPDATE sessions SET project_id = ? WHERE id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill claudecode-project-root: prepare session: %w", err)
	}
	defer updateSession.Close()

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions SET project_id = ? WHERE session_id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill claudecode-project-root: prepare actions: %w", err)
	}
	defer updateActions.Close()

	seen := map[string]struct{}{}

	for _, projectsDir := range projectDirs {
		walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".jsonl" {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.FilesScanned++

			sessionID, cwd, ok := readClaudecodeSessionCwd(path)
			if !ok || sessionID == "" || cwd == "" {
				return nil
			}
			if _, dup := seen[sessionID]; dup {
				return nil
			}
			seen[sessionID] = struct{}{}

			translated := crossmount.TranslateForeignPath(cwd)
			info, gerr := git.Resolve(translated)
			if gerr != nil {
				return nil
			}
			newRoot := info.Root
			if newRoot == "" {
				return nil
			}
			// git.Resolve succeeded above (gerr checked), so info.Remote
			// reflects this cwd's "origin" remote when it has one; B3
			// normalizes it the same way the live claudecode parser does.
			pid, err := st.UpsertProject(ctx, newRoot, git.NormalizeRemote(info.Remote))
			if err != nil {
				return nil
			}

			if r, err := updateSession.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.SessionsReattributed += int(n)
				}
			}
			if r, err := updateActions.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			continue
		}
	}
	return res, nil
}

// readClaudecodeSessionCwd extracts (sessionId, cwd) from the first
// JSONL line in `path` that carries both. Claude Code writes
// sessionId + cwd on every user / assistant / system line, so the
// first line usually wins; we scan up to 32 lines for resilience
// against leading metadata-only lines (file-history-snapshot,
// queue-operation, custom-title, etc. — see
// docs/audits/claude-code-audit-2026-05-18-scope.md §2a).
func readClaudecodeSessionCwd(path string) (sessionID string, cwd string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for i := 0; i < 32 && scanner.Scan(); i++ {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rl struct {
			SessionID string `json:"sessionId"`
			Cwd       string `json:"cwd"`
		}
		if err := json.Unmarshal(line, &rl); err != nil {
			continue
		}
		if rl.SessionID != "" && rl.Cwd != "" {
			return rl.SessionID, rl.Cwd, true
		}
	}
	return "", "", false
}

// CoworkProjectRootBackfill summarises the --cowork-project-root pass.
type CoworkProjectRootBackfill struct {
	FilesScanned         int `json:"files_scanned"`
	SessionsReattributed int `json:"sessions_reattributed"`
	ActionsUpdated       int `json:"actions_updated"`
}

// backfillCoworkProjectRoot re-attributes cowork action / session
// rows to the correct project when their sidecar.userSelectedFolders
// was a Windows-style path. Pre-v1.4.54 the cowork adapter passed
// the path directly to git.Resolve, which on a non-Windows host
// treats "C:\foo\bar" as a relative path, prepends observer's CWD,
// then walks UP looking for .git — landing on observer's own repo
// in the worst case. The adapter now translates via
// crossmount.TranslateForeignPath and stat-gates git.Resolve; this
// backfill applies the same resolution to already-ingested rows so
// historical data converges to the correct project.
//
// Walks every supplied watch root, finds local_<id>/audit.jsonl
// files, derives the (session_id, project_root) pair via
// cowork.ProjectAttribution, upserts the project, then UPDATEs the
// session row + all of its actions when project_id differs.
func backfillCoworkProjectRoot(ctx context.Context, db *sql.DB, watchRoots []string, fileLimit int) (CoworkProjectRootBackfill, error) {
	res := CoworkProjectRootBackfill{}
	st := store.New(db)

	updateSession, err := db.PrepareContext(ctx,
		`UPDATE sessions SET project_id = ? WHERE id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill cowork-project-root: prepare session: %w", err)
	}
	defer updateSession.Close()

	updateActions, err := db.PrepareContext(ctx,
		`UPDATE actions SET project_id = ? WHERE session_id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill cowork-project-root: prepare actions: %w", err)
	}
	defer updateActions.Close()

	for _, root := range watchRoots {
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Base(path) != "audit.jsonl" {
				return nil
			}
			parent := filepath.Base(filepath.Dir(path))
			if !strings.HasPrefix(parent, "local_") {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.FilesScanned++

			sessionID, newRoot, remote, ok := cowork.ProjectAttribution(path)
			if !ok || sessionID == "" || newRoot == "" {
				return nil
			}
			// remote is already normalized by cowork.ProjectAttribution
			// (it delegates to the same resolveProjectRoot the live
			// parser uses).
			pid, err := st.UpsertProject(ctx, newRoot, remote)
			if err != nil {
				return nil
			}
			if r, err := updateSession.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.SessionsReattributed += int(n)
				}
			}
			if r, err := updateActions.ExecContext(ctx, pid, sessionID, pid); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			// Per-tree errors are non-fatal — matches the codex
			// pattern. A stale crossmount home or an EACCES on a
			// Windows-side directory shouldn't abort the whole pass.
			continue
		}
	}
	return res, nil
}

// AntigravityProjectRootBackfill summarises the
// --antigravity-project-root pass.
type AntigravityProjectRootBackfill struct {
	FilesScanned         int `json:"files_scanned"`
	IndexHits            int `json:"index_hits"`
	SessionsReattributed int `json:"sessions_reattributed"`
	ActionsUpdated       int `json:"actions_updated"`
	SessionsRefreshed    int `json:"sessions_refreshed"`
	// StructuredFetched is the count of .pb files for which the
	// language_server's GetCascadeTrajectory returned usable per-turn
	// token + model data via the bridge. Misses (conversation not
	// loaded by any running language_server, gRPC error) increment
	// StructuredFetchFailed.
	StructuredFetched        int `json:"structured_fetched"`
	StructuredFetchFailed    int `json:"structured_fetch_failed"`
	StructuredTokensInserted int `json:"structured_tokens_inserted"`
	StructuredToolsInserted  int `json:"structured_tools_inserted"`
	// StructuredModelLifted counts sessions whose model column got
	// upgraded from "" / state.vscdb model_hint to the actual model
	// reported in the structured trajectory (e.g. claude-sonnet-4-5).
	StructuredModelLifted int `json:"structured_model_lifted"`
	// TokenTimestampsRefreshed is the count of token_usage rows whose
	// stored timestamp was rewritten because the parser now spreads
	// per-turn ts across the conversation duration instead of
	// 1-second-apart from StartedAt.
	TokenTimestampsRefreshed int `json:"token_timestamps_refreshed"`
	// TokenMessageIDsRefreshed is the count of token_usage rows whose
	// message_id was rewritten from the legacy `antigravity-struct:`
	// prefix to the shared `antigravity:` scheme so the dashboard's
	// per-message join lines up structured ToolEvents under their
	// parent token row.
	TokenMessageIDsRefreshed int `json:"token_message_ids_refreshed"`
	// ActionMessageIDsRefreshed is the count of action rows whose
	// message_id was rewritten because ParseStructuredTrajectory's
	// turn-assignment scheme changed between observer versions
	// (Option 1 moved run_command from step-fraction to nearest-token).
	ActionMessageIDsRefreshed int `json:"action_message_ids_refreshed"`
	// MarkdownActionsRealigned is the count of action rows shifted
	// from recovery wall-clock onto the real conversation timeline,
	// distributed across [StartedAt, EndedAt].
	MarkdownActionsRealigned int `json:"markdown_actions_realigned"`
	// MarkdownInlineToolsDedup is the count of legacy
	// markdown.inline.<verb> action rows deleted after a structured
	// fetch surfaced authoritative ToolEvents for the same session
	// (Tier 1 dedup). Re-runs find no rows to delete (idempotent).
	MarkdownInlineToolsDedup int `json:"markdown_inline_tools_dedup"`
	// MarkdownPlannerRecovered is the count of markdown.planner_response
	// rows re-inserted in sessions where structured.assistant_text
	// coverage of LLM calls is below
	// antigravity.AssistantTextCoverageThreshold. Targets gemini
	// sessions whose 1.2.20 PLANNER_RESPONSE step is sparse — without
	// this re-fetch, ~90% of token rows would have no joined
	// assistant content because Tier 3 dedup deleted markdown rows
	// that had richer coverage than structured.
	MarkdownPlannerRecovered int `json:"markdown_planner_recovered"`
}

// antigravityProjectRootBackfillDirs returns the set of antigravity
// conversations directories to scan: every crossmount-resolved home's
// `.gemini/antigravity/conversations`. Mirrors the codex helper so
// the dispatcher and tests can compute / inject the same set.
func antigravityProjectRootBackfillDirs() []string {
	var homes []string
	for _, h := range crossmount.AllHomes() {
		homes = append(homes, h.Path)
	}
	return antigravity.ConversationsDirs(homes)
}

// backfillAntigravityProjectRoot re-attributes antigravity action /
// session rows to the correct project, refreshes session.model +
// session.started_at, AND lifts per-turn token rows + the actual
// model name into the DB via the language_server's structured
// trajectory endpoint (Path B, MVP scope).
//
// Targets data ingested before the statedb deep-parser fix landed
// (every session pinned to project_id=[antigravity] with model=""
// and started_at = recovery-run wall-clock) and before structured
// recovery shipped (zero token_usage rows).
//
// Walks every .pb file under the supplied conversations directories.
// For each file:
//  1. Extract conversation UUID from filename, look up the index
//     entry, resolve project root via antigravity.ResolveIndexEntry,
//     upsert the project, and UPDATE the session + cascaded action
//     rows when project_id differs.
//  2. Best-effort: fetch GetCascadeTrajectory via the bridge,
//     parse the structured trajectory for model + per-turn tokens
//     + real conversation start time, INSERT token_usage rows, and
//     prefer the structured model over the state.vscdb hint when
//     refreshing session.model.
//  3. Refresh session.model and session.started_at — only when
//     the existing value is empty / placeholder, so a real value
//     is never overwritten.
//
// The structured fetch is best-effort: ~85% hit rate on the user's
// host (the bridge can only reach conversations loaded by a running
// language_server). Misses are logged and skipped.
func backfillAntigravityProjectRoot(ctx context.Context, db *sql.DB, conversationsDirs []string, fileLimit int) (AntigravityProjectRootBackfill, error) {
	res := AntigravityProjectRootBackfill{}
	st := store.New(db)

	updateSessionPID, err := db.PrepareContext(ctx,
		`UPDATE sessions SET project_id = ? WHERE id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare session pid: %w", err)
	}
	defer updateSessionPID.Close()

	updateActionsPID, err := db.PrepareContext(ctx,
		`UPDATE actions SET project_id = ? WHERE session_id = ? AND project_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare actions pid: %w", err)
	}
	defer updateActionsPID.Close()

	// session.model + session.started_at — refresh only when the
	// existing value is empty / placeholder, so a real value is never
	// overwritten by an older index snapshot.
	refreshSessionMeta, err := db.PrepareContext(ctx,
		`UPDATE sessions
		    SET model      = COALESCE(NULLIF(?, ''), model),
		        started_at = CASE WHEN ?<>'' THEN ? ELSE started_at END
		  WHERE id = ?
		    AND tool = 'antigravity'`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare session meta: %w", err)
	}
	defer refreshSessionMeta.Close()

	// Refresh existing token_usage rows' timestamps. The first Path B
	// release synthesised per-turn ts as StartedAt + i*1s; the parser
	// now spreads them across [StartedAt, EndedAt] so the dashboard's
	// chronological view spans the actual conversation duration.
	updateTokenTimestamp, err := db.PrepareContext(ctx,
		`UPDATE token_usage
		    SET timestamp = ?
		  WHERE source_file = ?
		    AND source_event_id = ?
		    AND timestamp != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare token ts: %w", err)
	}
	defer updateTokenTimestamp.Close()

	// Refresh existing token_usage rows' message_id. The original Path
	// B commit (5af3771) used `antigravity-struct:<uuid>:turn:N`; the
	// shared scheme adopted in the bug-fix session uses
	// `antigravity:<uuid>:turn:N` so tokens and structured ToolEvents
	// join on the dashboard. Token rows already in the DB carry the
	// stale prefix and are orphaned from every joined row until this
	// UPDATE runs. Keyed by (source_file, source_event_id) so re-runs
	// are no-ops once corrected.
	updateTokenMessageID, err := db.PrepareContext(ctx,
		`UPDATE token_usage
		    SET message_id = ?
		  WHERE source_file = ?
		    AND source_event_id = ?
		    AND message_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare token msg id: %w", err)
	}
	defer updateTokenMessageID.Close()

	// Refresh existing structured action rows' message_id when
	// ParseStructuredTrajectory's assignment scheme changes between
	// observer versions (e.g. Option 1 flipped run_command from
	// step-fraction to time-nearest-token). InsertActions' ON CONFLICT
	// only refreshes duration_ms, so without this UPDATE existing rows
	// keep stale ids and stay orphaned from the dashboard's per-turn
	// grouping. Keyed on (source_file, source_event_id) so re-runs
	// no-op once corrected.
	updateActionMessageID, err := db.PrepareContext(ctx,
		`UPDATE actions
		    SET message_id = ?
		  WHERE source_file = ?
		    AND source_event_id = ?
		    AND message_id != ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare action msg id: %w", err)
	}
	defer updateActionMessageID.Close()

	// Realign markdown action timestamps onto the real conversation
	// timeline. Pre-Path-B markdown recovery used the recovery
	// wall-clock as the base ts (so all markdown rows clustered at
	// the time observer last ran the recovery, sometimes 2+ months
	// after the actual conversation). The realignment spreads them
	// evenly across [StartedAt, EndedAt] in their original order.
	selectMarkdownActions, err := db.PrepareContext(ctx,
		`SELECT id, timestamp FROM actions
		  WHERE session_id = ?
		    AND tool = 'antigravity'
		    AND raw_tool_name LIKE 'markdown.%'
		  ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare select markdown actions: %w", err)
	}
	defer selectMarkdownActions.Close()
	updateActionTimestamp, err := db.PrepareContext(ctx,
		`UPDATE actions SET timestamp = ? WHERE id = ?`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare action ts: %w", err)
	}
	defer updateActionTimestamp.Close()

	// Tier 1 dedup: when structured trajectory surfaces authoritative
	// ToolEvents (artifact edits, file views), delete the markdown
	// `*Edited file…*` / `*Viewed…*` inline-tool rows that recovered
	// the same edits with less detail. Run only for sessions where
	// structured emitted tools; markdown user/assistant text rows are
	// untouched (assistant text only lives in markdown — see Tier 2
	// probe notes in docs/handovers/antigravity-tier-1-2-3-handoff-2026-05-04.md).
	deleteMarkdownInlineTools, err := db.PrepareContext(ctx,
		`DELETE FROM actions
		  WHERE session_id = ?
		    AND tool = 'antigravity'
		    AND raw_tool_name LIKE 'markdown.inline.%'`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare delete inline tools: %w", err)
	}
	defer deleteMarkdownInlineTools.Close()

	// Tier 2 dedup: when structured surfaces user_prompt rows from
	// 1.2.19.2, delete markdown.user_input rows for the same session.
	// Markdown's user_input was synthesized from `### User Input`
	// blocks in the converted trajectory; structured carries the same
	// text with deterministic SourceEventIDs and real per-step ts.
	deleteMarkdownUserInputs, err := db.PrepareContext(ctx,
		`DELETE FROM actions
		  WHERE session_id = ?
		    AND tool = 'antigravity'
		    AND raw_tool_name = 'markdown.user_input'`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare delete user inputs: %w", err)
	}
	defer deleteMarkdownUserInputs.Close()

	// Tier 3 dedup: when structured surfaces assistant_text rows
	// from 1.2.20.1, delete markdown.planner_response rows for the
	// same session.
	deleteMarkdownPlanner, err := db.PrepareContext(ctx,
		`DELETE FROM actions
		  WHERE session_id = ?
		    AND tool = 'antigravity'
		    AND raw_tool_name = 'markdown.planner_response'`)
	if err != nil {
		return res, fmt.Errorf("backfill antigravity-project-root: prepare delete planner: %w", err)
	}
	defer deleteMarkdownPlanner.Close()

	scrubber := scrub.New()

	for _, dir := range conversationsDirs {
		walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(path) != ".pb" {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return filepath.SkipAll
			}
			res.FilesScanned++

			entry, ok := antigravity.ResolveIndexEntry(path)
			if !ok {
				return nil
			}
			res.IndexHits++

			sessionID := strings.TrimSuffix(filepath.Base(path), ".pb")

			if entry.ProjectRoot != "" && entry.ProjectRoot != "[antigravity]" {
				info, gerr := git.Resolve(entry.ProjectRoot)
				newRoot := entry.ProjectRoot
				remote := ""
				if gerr == nil && info.Root != "" {
					newRoot = info.Root
					remote = git.NormalizeRemote(info.Remote)
				}
				pid, err := st.UpsertProject(ctx, newRoot, remote)
				if err == nil {
					if r, err := updateSessionPID.ExecContext(ctx, pid, sessionID, pid); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.SessionsReattributed += int(n)
						}
					}
					if r, err := updateActionsPID.ExecContext(ctx, pid, sessionID, pid); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.ActionsUpdated += int(n)
						}
					}
				}
			}

			// Best-effort structured-trajectory enrichment.
			// Re-fetching via the bridge is ~250ms per conversation;
			// for ~100 sessions the total is ~30s. Failure (no
			// language_server has the conversation loaded) is the
			// common case for the ~15% miss rate — log and continue.
			modelHint := entry.ModelHint
			startedAt := ""
			if !entry.Created.IsZero() {
				startedAt = entry.Created.UTC().Format(time.RFC3339Nano)
			}
			structured, sErr := antigravity.FetchStructuredTrajectory(ctx, sessionID, entry.ProjectRoot, path, 30*time.Second, scrubber)
			if sErr != nil {
				res.StructuredFetchFailed++
			} else {
				res.StructuredFetched++
				if structured.Model != "" {
					modelHint = structured.Model
				}
				if !structured.StartedAt.IsZero() {
					startedAt = structured.StartedAt.UTC().Format(time.RFC3339Nano)
				}
				// Insert tokens + new structured tool events in one
				// idempotent Ingest call. Existing rows are
				// no-op'd via the (source_file, source_event_id)
				// UNIQUE constraint.
				if len(structured.TokenEvents) > 0 || len(structured.ToolEvents) > 0 {
					ir, ierr := st.Ingest(ctx, structured.ToolEvents, structured.TokenEvents, store.IngestOptions{})
					if ierr == nil {
						res.StructuredTokensInserted += ir.TokensInserted
						res.StructuredToolsInserted += ir.ActionsInserted
					}
				}
				// Tier 1 dedup: now that authoritative structured tool
				// events are in the DB, drop the legacy markdown.inline.*
				// rows for this session. Idempotent — re-runs find no
				// rows to delete.
				if len(structured.ToolEvents) > 0 {
					if r, derr := deleteMarkdownInlineTools.ExecContext(ctx, sessionID); derr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.MarkdownInlineToolsDedup += int(n)
						}
					}
				}
				// Tier 2 dedup: when structured surfaces user_prompt
				// rows from 1.2.19.2, drop the markdown.user_input
				// rows for this session.
				var sawUserPrompt bool
				assistantTextCount := 0
				for _, ev := range structured.ToolEvents {
					switch ev.RawToolName {
					case "structured.user_prompt":
						sawUserPrompt = true
					case "structured.assistant_text":
						assistantTextCount++
					}
				}
				if sawUserPrompt {
					if r, derr := deleteMarkdownUserInputs.ExecContext(ctx, sessionID); derr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.MarkdownInlineToolsDedup += int(n)
						}
					}
				}
				// Tier 3 dedup is coverage-conditional. Only suppress
				// markdown.planner_response when structured carries
				// the assistant text for at least the threshold
				// fraction of LLM calls. Below threshold (gemini
				// sessions; 803add5e is 3/130 = 2%), markdown carries
				// the missing narrative and must stay.
				coverage := 0.0
				if len(structured.TokenEvents) > 0 {
					coverage = float64(assistantTextCount) / float64(len(structured.TokenEvents))
				}
				if coverage >= antigravity.AssistantTextCoverageThreshold {
					if r, derr := deleteMarkdownPlanner.ExecContext(ctx, sessionID); derr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.MarkdownInlineToolsDedup += int(n)
						}
					}
				} else if coverage < antigravity.AssistantTextCoverageThreshold {
					// Recover markdown.planner_response rows that may
					// have been deleted by a prior over-aggressive
					// dedup pass. Re-fetch markdown via the bridge,
					// extract planner-response-only events, and
					// idempotently INSERT (UNIQUE on
					// (source_file, source_event_id) collapses re-runs).
					md, mdErr := antigravity.FetchMarkdownTrajectory(ctx, sessionID, 30*time.Second)
					if mdErr == nil && md != "" {
						baseTs := structured.StartedAt
						if baseTs.IsZero() && !entry.Created.IsZero() {
							baseTs = entry.Created
						}
						if baseTs.IsZero() {
							baseTs = time.Now().UTC()
						}
						plannerEvents := antigravity.ParseMarkdownPlannerResponses(
							path, sessionID, entry.ProjectRoot, baseTs, scrubber, md,
						)
						if len(plannerEvents) > 0 {
							ir, ierr := st.Ingest(ctx, plannerEvents, nil, store.IngestOptions{})
							if ierr == nil {
								res.MarkdownPlannerRecovered += ir.ActionsInserted
							}
						}
					}
				}
				// Refresh existing token_usage timestamps so old rows
				// (synthesised at 1s-apart from StartedAt by the
				// first Path B release) get the new spread values.
				// Also refresh stale message_id prefixes so the
				// dashboard's per-message join lines up structured
				// ToolEvents under their owning token row.
				for _, te := range structured.TokenEvents {
					newTs := te.Timestamp.UTC().Format(time.RFC3339Nano)
					if r, uerr := updateTokenTimestamp.ExecContext(ctx,
						newTs, te.SourceFile, te.SourceEventID, newTs); uerr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.TokenTimestampsRefreshed += int(n)
						}
					}
					if r, uerr := updateTokenMessageID.ExecContext(ctx,
						te.MessageID, te.SourceFile, te.SourceEventID, te.MessageID); uerr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.TokenMessageIDsRefreshed += int(n)
						}
					}
				}
				// Refresh existing structured action rows whose
				// MessageID assignment changed (e.g. Option 1 moved
				// run_command from step-fraction to nearest-token).
				for _, ev := range structured.ToolEvents {
					if r, uerr := updateActionMessageID.ExecContext(ctx,
						ev.MessageID, ev.SourceFile, ev.SourceEventID, ev.MessageID); uerr == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.ActionMessageIDsRefreshed += int(n)
						}
					}
				}
				// Realign markdown actions if we know the real
				// conversation window AND the existing rows look
				// like recovery wall-clock (i.e. they're more than
				// a minute off the structured StartedAt).
				if !structured.StartedAt.IsZero() {
					n, _ := realignMarkdownActions(ctx,
						selectMarkdownActions, updateActionTimestamp,
						sessionID, structured.StartedAt, structured.EndedAt)
					res.MarkdownActionsRealigned += n
				}
			}

			if modelHint != "" || startedAt != "" {
				if r, err := refreshSessionMeta.ExecContext(ctx, modelHint, startedAt, startedAt, sessionID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.SessionsRefreshed += int(n)
						if structured.Model != "" {
							res.StructuredModelLifted += int(n)
						}
					}
				}
			}
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			continue
		}
	}
	return res, nil
}

// realignMarkdownActions spreads existing markdown-derived action
// rows for a session evenly across [startedAt, endedAt]. Pre-Path-B
// markdown recovery used the recovery wall-clock as the base ts, so
// all markdown rows clustered at the time observer last ran the
// recovery — sometimes months after the actual conversation. This
// realignment puts them back on the real timeline.
//
// No-op when:
//   - no markdown actions exist for the session,
//   - the existing min(timestamp) is already within 60s of startedAt
//     (already realigned on a prior run, idempotent),
//   - endedAt is zero or doesn't exceed startedAt (no spread window).
//
// Returns the count of rows whose timestamp changed.
func realignMarkdownActions(ctx context.Context,
	selectStmt, updateStmt *sql.Stmt,
	sessionID string, startedAt, endedAt time.Time,
) (int, error) {
	rows, err := selectStmt.QueryContext(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	type row struct {
		id int64
		ts time.Time
	}
	var batch []row
	for rows.Next() {
		var r row
		var tsStr string
		if err := rows.Scan(&r.id, &tsStr); err != nil {
			rows.Close()
			return 0, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, tsStr); perr == nil {
			r.ts = t
		} else if t, perr := time.Parse("2006-01-02T15:04:05Z", tsStr); perr == nil {
			r.ts = t
		}
		batch = append(batch, r)
	}
	rows.Close()
	if len(batch) == 0 {
		return 0, nil
	}
	// Idempotency guard: if the earliest stored ts is already within
	// 60s of startedAt, the realignment already ran. Skip.
	if !batch[0].ts.IsZero() && batch[0].ts.Sub(startedAt).Abs() < time.Minute {
		return 0, nil
	}
	// Determine the spread window. If endedAt is missing, fall back
	// to a synthetic 1s-apart window starting at startedAt — still
	// a huge improvement over the recovery wall-clock since at
	// least the absolute time anchor is correct.
	dur := time.Duration(0)
	if !endedAt.IsZero() && endedAt.After(startedAt) {
		dur = endedAt.Sub(startedAt)
	}
	updated := 0
	for i, r := range batch {
		var newTs time.Time
		if dur > 0 && len(batch) > 1 {
			off := time.Duration(int64(dur) * int64(i) / int64(len(batch)-1))
			newTs = startedAt.Add(off)
		} else {
			newTs = startedAt.Add(time.Duration(i) * time.Second)
		}
		if !newTs.Equal(r.ts) {
			if _, err := updateStmt.ExecContext(ctx, newTs.UTC().Format(time.RFC3339Nano), r.id); err == nil {
				updated++
			}
		}
	}
	return updated, nil
}

// readCodexSessionMeta pulls the (session_id, cwd) pair from a codex
// rollout's first session_meta record. Returns ok=false if the file
// is unreadable or doesn't contain a session_meta line in its first
// few records.
func readCodexSessionMeta(path string) (sessionID string, cwd string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for i := 0; i < 32 && scanner.Scan(); i++ {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rl struct {
			Type    string `json:"type"`
			Payload struct {
				ID  string `json:"id"`
				Cwd string `json:"cwd"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(line, &rl); err != nil {
			continue
		}
		if rl.Type != "session_meta" {
			continue
		}
		return rl.Payload.ID, rl.Payload.Cwd, true
	}
	return "", "", false
}

// backfillCodexReasoning re-walks codex rollout JSONL to capture
// `event_msg`/`agent_message` text per turn and writes it to
// `actions.preceding_reasoning` for tool / exec / web / task_complete
// rows in that turn. The post-parity adapter does this on ingest;
// this catches up historical rows.
//
// One pass per file. Within each file we track currentTurnID across
// session_meta / turn_context / task_started / event_msg payloads
// that carry it, and bind every agent_message to that turn. After the
// file is fully scanned we issue one UPDATE per (session_id, turn_id)
// pair with the captured preamble.
func backfillCodexReasoning(ctx context.Context, db *sql.DB, sessionsDir string, fileLimit int) (CodexReasoningBackfill, error) {
	res := CodexReasoningBackfill{}

	updateAction, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET preceding_reasoning = ?
		 WHERE tool = 'codex'
		   AND session_id = ?
		   AND message_id = ?
		   AND (preceding_reasoning IS NULL OR preceding_reasoning = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill codex-reasoning: prepare update: %w", err)
	}
	defer updateAction.Close()

	walkErr := filepath.WalkDir(sessionsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if filepath.Ext(path) != ".jsonl" || !strings.HasPrefix(base, "rollout-") {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

		// (session_id, turn_id) → preamble text. Multiple session ids
		// can apply per file (filename stem fallback + explicit session_id).
		sessionIDs := []string{strings.TrimPrefix(strings.TrimSuffix(base, ".jsonl"), "rollout-")}
		addSession := func(id string) {
			if id == "" {
				return
			}
			for _, e := range sessionIDs {
				if e == id {
					return
				}
			}
			sessionIDs = append(sessionIDs, id)
		}
		preambles := map[string]string{} // turn_id → text
		currentTurnID := ""

		for scanner.Scan() {
			res.LinesExamined++
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var rl struct {
				Type    string          `json:"type"`
				Payload json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			switch rl.Type {
			case "session_meta", "session_configured", "session_start", "turn_context":
				var p struct {
					ID        string `json:"id"`
					SessionID string `json:"session_id"`
					TurnID    string `json:"turn_id"`
				}
				if err := json.Unmarshal(rl.Payload, &p); err == nil {
					addSession(p.ID)
					addSession(p.SessionID)
					if p.TurnID != "" {
						currentTurnID = p.TurnID
					}
				}
			case "event_msg":
				var env struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(rl.Payload, &env); err != nil {
					continue
				}
				switch env.Type {
				case "task_started":
					var p struct {
						TurnID string `json:"turn_id"`
					}
					if err := json.Unmarshal(rl.Payload, &p); err == nil && p.TurnID != "" {
						currentTurnID = p.TurnID
					}
				case "agent_message":
					var p struct {
						TurnID  string `json:"turn_id"`
						Message string `json:"message"`
					}
					if err := json.Unmarshal(rl.Payload, &p); err != nil {
						continue
					}
					turnID := p.TurnID
					if turnID == "" {
						turnID = currentTurnID
					}
					if turnID == "" {
						continue
					}
					msg := strings.TrimSpace(p.Message)
					if msg == "" {
						continue
					}
					preambles[turnID] = msg
				case "exec_command_end", "web_search_end", "task_complete":
					var p struct {
						TurnID string `json:"turn_id"`
					}
					if err := json.Unmarshal(rl.Payload, &p); err == nil && p.TurnID != "" {
						currentTurnID = p.TurnID
					}
				}
			}
		}

		// Apply: one UPDATE per (sessionID, turnID, preamble).
		for turnID, text := range preambles {
			truncated := text
			if len(truncated) > 500 {
				truncated = truncated[:500]
			}
			res.TurnsCaptured++
			for _, sessID := range sessionIDs {
				r, err := updateAction.ExecContext(ctx, truncated, sessID, turnID)
				if err != nil {
					continue
				}
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill codex-reasoning: walk %s: %w", sessionsDir, walkErr)
	}
	return res, nil
}

// OpenClawReasoningBackfill summarises the --openclaw-reasoning pass.
type OpenClawReasoningBackfill struct {
	FilesScanned   int `json:"files_scanned"`
	LinesExamined  int `json:"lines_examined"`
	ActionsUpdated int `json:"actions_updated"`
}

// backfillOpenClawReasoning re-walks openclaw session JSONL files and
// populates `actions.preceding_reasoning` from text/thinking content
// blocks that precede each toolCall in an assistant message. Mirrors
// the post-parity adapter's per-toolCall capture: as content iterates,
// each text/thinking block updates the running preamble, and each
// toolCall block captures its current value.
//
// The action row is identified by (source_file, source_event_id),
// where source_event_id is `firstNonEmpty(content.ID, "tool:<name>:L<n>")`
// matching what the adapter wrote.
func backfillOpenClawReasoning(ctx context.Context, db *sql.DB, sessionsDir string, fileLimit int) (OpenClawReasoningBackfill, error) {
	res := OpenClawReasoningBackfill{}

	updateAction, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET preceding_reasoning = ?
		 WHERE tool = 'openclaw'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND (preceding_reasoning IS NULL OR preceding_reasoning = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill openclaw-reasoning: prepare update: %w", err)
	}
	defer updateAction.Close()

	walkErr := filepath.WalkDir(sessionsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			res.LinesExamined++
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var rl struct {
				Type    string `json:"type"`
				Message struct {
					Role    string `json:"role"`
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"content"`
				} `json:"message"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			if rl.Type != "message" || rl.Message.Role != "assistant" {
				continue
			}
			var preceding string
			for _, c := range rl.Message.Content {
				switch c.Type {
				case "text", "thinking":
					if t := strings.TrimSpace(c.Text); t != "" {
						preceding = t
					}
				case "toolCall":
					if preceding == "" {
						continue
					}
					sourceEventID := c.ID
					if sourceEventID == "" {
						sourceEventID = fmt.Sprintf("tool:%s:L%d", c.Name, lineNum)
					}
					truncated := preceding
					if len(truncated) > 500 {
						truncated = truncated[:500]
					}
					r, err := updateAction.ExecContext(ctx, truncated, path, sourceEventID)
					if err != nil {
						continue
					}
					if n, _ := r.RowsAffected(); n > 0 {
						res.ActionsUpdated += int(n)
					}
				}
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill openclaw-reasoning: walk %s: %w", sessionsDir, walkErr)
	}
	return res, nil
}

// openclawAgentsDir returns the openclaw agents tree (where session
// jsonl files live). Defaults to ~/.openclaw/agents.
func openclawAgentsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openclaw", "agents")
}

// ClaudeCodeUserPromptsBackfill summarises the --claudecode-user-prompts pass.
type ClaudeCodeUserPromptsBackfill struct {
	FilesScanned    int `json:"files_scanned"`
	UserEventsFound int `json:"user_events_found"`
	ActionsInserted int `json:"actions_inserted"`
}

// backfillClaudeCodeUserPrompts walks every Claude Code JSONL file
// under the projects tree, re-runs the adapter, and ingests only the
// user_prompt events. Catches sessions ingested before the adapter
// started emitting user_prompt actions for user-role lines with text
// content. Idempotent via the (source_file, source_event_id) UNIQUE
// index — already-present rows are no-ops.
func backfillClaudeCodeUserPrompts(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (ClaudeCodeUserPromptsBackfill, error) {
	res := ClaudeCodeUserPromptsBackfill{}
	a := claudecode.New()
	st := store.New(db)

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		parseRes, err := a.ParseSessionFile(ctx, path, 0)
		if err != nil {
			return nil // skip unreadable files rather than fail the whole pass
		}
		var userPrompts []models.ToolEvent
		for _, ev := range parseRes.ToolEvents {
			if ev.ActionType == models.ActionUserPrompt {
				userPrompts = append(userPrompts, ev)
			}
		}
		res.UserEventsFound += len(userPrompts)
		if len(userPrompts) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, userPrompts, nil, store.IngestOptions{
			IsNativeTool: claudecode.IsNativeTool,
		})
		if err != nil {
			return fmt.Errorf("backfill claudecode-user-prompts: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill claudecode-user-prompts: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// ClaudeCodeAPIErrorsBackfill summarises the --claudecode-api-errors pass.
type ClaudeCodeAPIErrorsBackfill struct {
	FilesScanned    int `json:"files_scanned"`
	APIErrorsFound  int `json:"api_errors_found"`
	ActionsInserted int `json:"actions_inserted"`
}

// backfillClaudeCodeAPIErrors walks every Claude Code JSONL file under
// projectsDir, re-runs the adapter, and ingests only the api_error
// events. Catches sessions ingested before v1.4.20 — pre-fix the
// adapter dropped type=system records (where api_error subtype lives)
// because of the `len(line.Message) == 0` short-circuit. Idempotent
// via the (source_file, source_event_id) UNIQUE index — already-
// present rows are no-ops.
func backfillClaudeCodeAPIErrors(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (ClaudeCodeAPIErrorsBackfill, error) {
	res := ClaudeCodeAPIErrorsBackfill{}
	a := claudecode.New()
	st := store.New(db)

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return filepath.SkipAll
		}
		res.FilesScanned++

		parseRes, err := a.ParseSessionFile(ctx, path, 0)
		if err != nil {
			return nil // skip unreadable files rather than fail the whole pass
		}
		var apiErrors []models.ToolEvent
		for _, ev := range parseRes.ToolEvents {
			if ev.ActionType == models.ActionAPIError {
				apiErrors = append(apiErrors, ev)
			}
		}
		res.APIErrorsFound += len(apiErrors)
		if len(apiErrors) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, apiErrors, nil, store.IngestOptions{
			IsNativeTool: claudecode.IsNativeTool,
		})
		if err != nil {
			return fmt.Errorf("backfill claudecode-api-errors: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return res, fmt.Errorf("backfill claudecode-api-errors: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// OpenCodeTokensBackfill summarises the --opencode-tokens pass.
type OpenCodeTokensBackfill struct {
	DBsScanned         int `json:"dbs_scanned"`
	TokenRowsExtracted int `json:"token_rows_extracted"`
	TokenRowsInserted  int `json:"token_rows_inserted"`
}

// backfillOpenCodeTokens re-runs the opencode adapter against every
// opencode.db referenced by historical action rows and ingests any
// token_usage rows that aren't already present. Catches the case
// where actions were ingested by an older adapter version that
// didn't yet read data.tokens, or where the parse_cursors watermark
// advanced past the assistant message before token extraction was
// added.
//
// Each opencode.db is parsed with fromOffset=0 so the full message
// table is re-scanned. ToolEvents from the parse result are
// discarded (actions are already in observer's DB); only TokenEvents
// are passed to store.Ingest, which is idempotent on
// (source_file, source_event_id) — duplicate token rows are
// rejected by the unique index.
func backfillOpenCodeTokens(ctx context.Context, db *sql.DB) (OpenCodeTokensBackfill, error) {
	res := OpenCodeTokensBackfill{}

	srcRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM actions
		 WHERE tool = 'opencode'
		   AND source_file IS NOT NULL
		   AND source_file != ''`)
	if err != nil {
		return res, fmt.Errorf("backfill opencode-tokens: list source_files: %w", err)
	}
	var dbPaths []string
	for srcRows.Next() {
		var p string
		if err := srcRows.Scan(&p); err != nil {
			srcRows.Close()
			return res, err
		}
		dbPaths = append(dbPaths, p)
	}
	srcRows.Close()

	a := opencode.New()
	st := store.New(db)

	for _, dbPath := range dbPaths {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		parseRes, err := a.ParseSessionFile(ctx, dbPath, 0)
		if err != nil {
			continue
		}
		res.DBsScanned++
		res.TokenRowsExtracted += len(parseRes.TokenEvents)
		if len(parseRes.TokenEvents) == 0 {
			continue
		}
		// Ingest only the token events. ToolEvents are already in the
		// DB from the original ingest pass; re-ingesting them would be
		// safe (idempotent on source_event_id) but wasteful.
		ingestRes, err := st.Ingest(ctx, nil, parseRes.TokenEvents, store.IngestOptions{})
		if err != nil {
			return res, fmt.Errorf("backfill opencode-tokens: ingest: %w", err)
		}
		res.TokenRowsInserted += ingestRes.TokensInserted
	}
	return res, nil
}

// backfillCopilotMessageID walks the Copilot debug log paths
// referenced by historical action rows and populates message_id where
// it's still NULL. Mirrors the post-parity adapter's grouping:
//
//   - user_message lines: message_id = "user:" + spanId
//   - tool_call / agent_response / llm_request lines: message_id =
//     "assistant:" + (parentSpanId | spanId)
//
// The action's source_event_id is the line's spanId verbatim (with a
// synthesized fallback when spanId is empty), so we match by
// (source_file, source_event_id).
func backfillCopilotMessageID(ctx context.Context, db *sql.DB) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	srcRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM actions
		 WHERE tool = 'copilot'
		   AND source_file IS NOT NULL
		   AND source_file != ''`)
	if err != nil {
		return res, fmt.Errorf("backfill copilot message-id: list source_files: %w", err)
	}
	var paths []string
	for srcRows.Next() {
		var p string
		if err := srcRows.Scan(&p); err != nil {
			srcRows.Close()
			return res, err
		}
		paths = append(paths, p)
	}
	srcRows.Close()

	updateAction, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE tool = 'copilot'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill copilot message-id: prepare actions: %w", err)
	}
	defer updateAction.Close()

	updateTokenUsage, err := db.PrepareContext(ctx, `
		UPDATE token_usage
		   SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE tool = 'copilot'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill copilot message-id: prepare token_usage: %w", err)
	}
	defer updateTokenUsage.Close()

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		res.FilesScanned++
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			res.LinesExamined++
			var rl struct {
				Type         string `json:"type"`
				SpanID       string `json:"spanId"`
				ParentSpanID string `json:"parentSpanId"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			if rl.SpanID == "" {
				continue
			}
			var msgID string
			switch rl.Type {
			case "user_message":
				msgID = "user:" + rl.SpanID
			default:
				root := rl.ParentSpanID
				if root == "" {
					root = rl.SpanID
				}
				msgID = "assistant:" + root
			}
			if r, err := updateAction.ExecContext(ctx, msgID, path, rl.SpanID); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}
			// llm_request lines drive token_usage rows; same source_event_id key.
			if rl.Type == "llm_request" {
				if r, err := updateTokenUsage.ExecContext(ctx, msgID, path, rl.SpanID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.TokenUsageUpdated += int(n)
					}
				}
			}
		}
		f.Close()
	}
	return res, nil
}

// backfillPiMessageID walks Pi session JSONL files referenced by
// historical action rows and populates message_id where NULL.
// Mirrors the post-parity adapter's grouping:
//
//   - user role messages: message_id = "user:" + id (or
//     "user:L<n>" fallback when id is empty)
//   - assistant role messages: message_id = id (or
//     "assistant:L<n>" fallback)
//
// The source_event_id for tool calls within an assistant message is
// the inner content.id (synthesized as `tool:<name>:L<n>` when that's
// missing), so we ALSO sweep content[] entries when assistant rows
// produce multiple actions per message.
func backfillPiMessageID(ctx context.Context, db *sql.DB) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}

	srcRows, err := db.QueryContext(ctx, `
		SELECT DISTINCT source_file FROM actions
		 WHERE tool = 'pi'
		   AND source_file IS NOT NULL
		   AND source_file != ''`)
	if err != nil {
		return res, fmt.Errorf("backfill pi message-id: list source_files: %w", err)
	}
	var paths []string
	for srcRows.Next() {
		var p string
		if err := srcRows.Scan(&p); err != nil {
			srcRows.Close()
			return res, err
		}
		paths = append(paths, p)
	}
	srcRows.Close()

	updateAction, err := db.PrepareContext(ctx, `
		UPDATE actions
		   SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE tool = 'pi'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill pi message-id: prepare actions: %w", err)
	}
	defer updateAction.Close()

	updateTokenUsage, err := db.PrepareContext(ctx, `
		UPDATE token_usage
		   SET message_id = COALESCE(NULLIF(message_id, ''), ?)
		 WHERE tool = 'pi'
		   AND source_file = ?
		   AND source_event_id = ?
		   AND (message_id IS NULL OR message_id = '')`)
	if err != nil {
		return res, fmt.Errorf("backfill pi message-id: prepare token_usage: %w", err)
	}
	defer updateTokenUsage.Close()

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		res.FilesScanned++
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		lineNum := 0
		base := filepath.Base(path)
		_ = base
		for scanner.Scan() {
			lineNum++
			res.LinesExamined++
			line := scanner.Bytes()
			var rl struct {
				ID      string `json:"id"`
				Message struct {
					Role    string `json:"role"`
					Content []struct {
						Type string `json:"type"`
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"content"`
				} `json:"message"`
			}
			if err := json.Unmarshal(line, &rl); err != nil {
				continue
			}
			role := rl.Message.Role
			if role == "" {
				continue
			}
			// Compute the per-line message_id the adapter would have
			// written — assistantMessageID(id, lineNum) for assistant
			// rows, "user:" + (id|L<n>) for user rows.
			var msgID string
			if role == "user" {
				if rl.ID != "" {
					msgID = "user:" + rl.ID
				} else {
					msgID = fmt.Sprintf("user:L%d", lineNum)
				}
			} else {
				if rl.ID != "" {
					msgID = rl.ID
				} else {
					msgID = fmt.Sprintf("assistant:L%d", lineNum)
				}
			}

			// Match the source_event_id the adapter wrote for this row's
			// outer envelope (user prompt / task_complete / usage).
			outerSourceID := rl.ID
			if outerSourceID == "" {
				switch role {
				case "user":
					outerSourceID = fmt.Sprintf("user:L%d", lineNum)
				default:
					outerSourceID = fmt.Sprintf("complete:L%d", lineNum)
				}
			}
			if r, err := updateAction.ExecContext(ctx, msgID, path, outerSourceID); err == nil {
				if n, _ := r.RowsAffected(); n > 0 {
					res.ActionsUpdated += int(n)
				}
			}

			// For assistant rows, sweep content[] for tool_use blocks —
			// each gets its own action keyed by content.id (or the
			// `tool:<name>:L<n>` synthesis).
			if role == "assistant" {
				for _, c := range rl.Message.Content {
					eid := c.ID
					if eid == "" {
						eid = fmt.Sprintf("tool:%s:L%d", c.Name, lineNum)
					}
					if r, err := updateAction.ExecContext(ctx, msgID, path, eid); err == nil {
						if n, _ := r.RowsAffected(); n > 0 {
							res.ActionsUpdated += int(n)
						}
					}
				}
				// Token rows on assistant messages — source_event_id
				// is `usage:<id>` or `usage:L<n>`.
				usageID := "usage:" + rl.ID
				if rl.ID == "" {
					usageID = fmt.Sprintf("usage:L%d", lineNum)
				}
				if r, err := updateTokenUsage.ExecContext(ctx, msgID, path, usageID); err == nil {
					if n, _ := r.RowsAffected(); n > 0 {
						res.TokenUsageUpdated += int(n)
					}
				}
			}
		}
		f.Close()
	}
	return res, nil
}

func extractCursorHookInputs(body string) []string {
	lines := strings.Split(body, "\n")
	var blocks []string
	var cur []string
	inInput := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "INPUT:":
			inInput = true
			cur = cur[:0]
		case trimmed == "OUTPUT:":
			if inInput && len(cur) > 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
			}
			inInput = false
		case inInput:
			cur = append(cur, line)
		}
	}
	return blocks
}

// CursorUserPromptsBackfill summarises the --cursor-user-prompts pass.
type CursorUserPromptsBackfill struct {
	FilesScanned    int `json:"files_scanned"`
	UserEventsFound int `json:"user_events_found"`
	ActionsInserted int `json:"actions_inserted"`
}

// backfillCursorUserPrompts walks every cursor agent-transcripts JSONL
// file under projectsDir and ingests user_prompt action rows for the
// turn-opening user lines. The cursor adapter's live path emits user
// prompts via the beforeSubmitPrompt hook; this catches sessions that
// pre-date the hook installation (or sessions where the hook fires for
// some prompts but not others).
//
// Each user line's text is unwrapped via stripUserQueryWrapper so the
// row carries the user-typed prompt rather than the
// `<user_query>...</user_query>` envelope cursor's runtime injects.
//
// Idempotent via the (source_file, source_event_id) UNIQUE index —
// re-running over a session that already has user_prompt rows is a
// no-op. Skips subagents/*.jsonl explicitly; those are handled in
// the parallel --cursor-subagents pass.
func backfillCursorUserPrompts(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (CursorUserPromptsBackfill, error) {
	res := CursorUserPromptsBackfill{}
	st := store.New(db)

	type turnRef struct {
		MessageID string
		Timestamp string
	}

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" || strings.Contains(path, string(filepath.Separator)+"subagents"+string(filepath.Separator)) {
			return nil
		}
		sessionID := filepath.Base(filepath.Dir(path))
		if strings.TrimSuffix(filepath.Base(path), ".jsonl") != sessionID {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"agent-transcripts"+string(filepath.Separator)) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, sessionID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		rows, err := db.QueryContext(ctx, `
			SELECT message_id, timestamp
			  FROM token_usage
			 WHERE tool = 'cursor' AND session_id = ? AND message_id IS NOT NULL AND message_id != ''
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		var refs []turnRef
		for rows.Next() {
			var ref turnRef
			if err := rows.Scan(&ref.MessageID, &ref.Timestamp); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref)
		}
		rows.Close()
		if len(refs) == 0 {
			return nil
		}

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}
		n := len(turns)
		if len(refs) < n {
			n = len(refs)
		}
		var events []models.ToolEvent
		for i := 0; i < n; i++ {
			ts, _ := time.Parse(time.RFC3339Nano, refs[i].Timestamp)
			ev, ok := cursor.BuildTranscriptUserPromptEvent(turns[i], sessionID, projectRoot, refs[i].MessageID, path, ts, nil)
			if !ok {
				continue
			}
			events = append(events, ev)
		}
		res.UserEventsFound += len(events)
		if len(events) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
		if err != nil {
			return fmt.Errorf("backfill cursor-user-prompts: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor-user-prompts: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// CursorSubagentsBackfill summarises the --cursor-subagents pass.
type CursorSubagentsBackfill struct {
	FilesScanned    int `json:"files_scanned"`
	EventsBuilt     int `json:"events_built"`
	ActionsInserted int `json:"actions_inserted"`
}

// backfillCursorSubagents walks the
// agent-transcripts/<parent_uuid>/subagents/<sub_uuid>.jsonl files
// Cursor writes when the parent agent spawns a sub-agent. The current
// cursor backfill explicitly skips these (the parent transcript only
// records a `Subagent` tool_use; the sub-agent's actual work is
// in the sub-file). This pass ingests those nested transcripts as
// sidechain rows under the parent session (IsSidechain=true,
// SessionID = parent_uuid), mirroring claudecode's isSidechain
// semantics.
//
// Each sub-agent line is timestamped from the file's mtime (the
// sub transcript carries no per-line timestamps). MessageID is
// synthesized as "sub:<sub_uuid>:turn<N>" so rows from the same
// sub-agent thread group together; SourceEventID prefixes ensure
// idempotency on re-runs.
func backfillCursorSubagents(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (CursorSubagentsBackfill, error) {
	res := CursorSubagentsBackfill{}
	st := store.New(db)

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		sep := string(filepath.Separator)
		if !strings.Contains(path, sep+"subagents"+sep) || !strings.Contains(path, sep+"agent-transcripts"+sep) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		subUUID := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		// path = .../agent-transcripts/<parent_uuid>/subagents/<sub>.jsonl
		// dir(path) = .../subagents
		// dir(dir(path)) = .../<parent_uuid>
		parentUUID := filepath.Base(filepath.Dir(filepath.Dir(path)))

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, parentUUID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil
		}
		ts := info.ModTime().UTC()

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}

		var events []models.ToolEvent
		for i, turn := range turns {
			generationID := fmt.Sprintf("sub:%s:turn%d", subUUID, i)
			if ev, ok := cursor.BuildTranscriptUserPromptEvent(turn, parentUUID, projectRoot, generationID, path, ts, nil); ok {
				ev.IsSidechain = true
				events = append(events, ev)
			}
			toolEvs := cursor.BuildTranscriptToolEvents(turn, parentUUID, projectRoot, generationID, path, ts, nil)
			for _, te := range toolEvs {
				te.IsSidechain = true
				events = append(events, te)
			}
		}
		res.EventsBuilt += len(events)
		if len(events) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
		if err != nil {
			return fmt.Errorf("backfill cursor-subagents: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor-subagents: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

func backfillCursorTranscriptActions(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}
	st := store.New(db)

	type turnRef struct {
		MessageID string
		Timestamp string
	}

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" || strings.Contains(path, string(filepath.Separator)+"subagents"+string(filepath.Separator)) {
			return nil
		}
		sessionID := filepath.Base(filepath.Dir(path))
		if strings.TrimSuffix(filepath.Base(path), ".jsonl") != sessionID {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"agent-transcripts"+string(filepath.Separator)) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, sessionID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		rows, err := db.QueryContext(ctx, `
			SELECT message_id, timestamp
			  FROM token_usage
			 WHERE tool = 'cursor' AND session_id = ? AND message_id IS NOT NULL AND message_id != ''
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		var refs []turnRef
		for rows.Next() {
			var ref turnRef
			if err := rows.Scan(&ref.MessageID, &ref.Timestamp); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref)
		}
		rows.Close()
		if len(refs) == 0 {
			return nil
		}

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}
		n := len(turns)
		if len(refs) < n {
			n = len(refs)
		}
		for i := 0; i < n; i++ {
			ts, _ := time.Parse(time.RFC3339Nano, refs[i].Timestamp)
			events := cursor.BuildTranscriptToolEvents(turns[i], sessionID, projectRoot, refs[i].MessageID, path, ts, nil)
			res.LinesExamined += len(events)
			ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
			if err != nil {
				return err
			}
			res.ActionsUpdated += ingestRes.ActionsInserted
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor transcript actions: walk: %w", walkErr)
	}
	return res, nil
}

// setupBackfillDryRun implements the `observer backfill --dry-run`
// snapshot-and-redirect flow (Issue #3 follow-up).
//
// Mechanism:
//  1. Load the live config to find Observer.DBPath.
//  2. Use SQLite's VACUUM INTO to write an atomic snapshot to a
//     temp file. This is a read-only operation against the live DB
//     and is safe to run while the watcher is writing.
//  3. Set the OBSERVER_OBSERVER_DB_PATH environment variable
//     (recognized by config.applyEnvOverrides) so every downstream
//     config.Load call — buildWatcher, buildWatcherWithOverride,
//     direct db.Open in this file — picks up the snapshot path
//     instead of the live path.
//  4. Print a banner so the operator sees what's happening (and
//     where the snapshot lives if they want to inspect it before
//     cleanup).
//
// Returns the snapshot path and a cleanup func that:
//   - Restores any prior value of OBSERVER_OBSERVER_DB_PATH (or
//     unsets if it wasn't set before).
//   - Deletes the snapshot file plus its potential -wal and -shm
//     siblings (SQLite creates these alongside the main file when
//     WAL mode is active).
//
// On error the partially-created snapshot is removed before
// returning so the caller doesn't need to manage cleanup.
func setupBackfillDryRun(ctx context.Context, configPath string, out io.Writer) (string, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return "", nil, fmt.Errorf("load config: %w", err)
	}
	livePath := cfg.Observer.DBPath
	if livePath == "" {
		return "", nil, fmt.Errorf("config has no observer.db_path — cannot snapshot")
	}

	snapshotPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("observer-dryrun-%d.db", time.Now().UnixNano()))

	if err := snapshotSQLiteDB(ctx, livePath, snapshotPath); err != nil {
		// Best-effort cleanup if the snapshot file was partially
		// created before the error.
		_ = os.Remove(snapshotPath)
		return "", nil, fmt.Errorf("snapshot %s -> %s: %w", livePath, snapshotPath, err)
	}

	const envKey = "OBSERVER_OBSERVER_DB_PATH"
	prevValue, prevSet := os.LookupEnv(envKey)
	if err := os.Setenv(envKey, snapshotPath); err != nil {
		_ = os.Remove(snapshotPath)
		return "", nil, fmt.Errorf("set env override: %w", err)
	}

	fmt.Fprintln(out, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out, "  DRY RUN — live database is not modified")
	fmt.Fprintf(out, "  live DB:  %s\n", livePath)
	fmt.Fprintf(out, "  snapshot: %s\n", snapshotPath)
	fmt.Fprintln(out, "  the row counts reported below reflect what WOULD update")
	fmt.Fprintln(out, "  the live DB if you re-ran without --dry-run.")
	fmt.Fprintln(out, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(out)

	cleanup := func() {
		if prevSet {
			_ = os.Setenv(envKey, prevValue)
		} else {
			_ = os.Unsetenv(envKey)
		}
		// Remove the main DB file plus the WAL/SHM siblings SQLite
		// may have created. Errors swallowed — cleanup is
		// best-effort; a leftover /tmp file is a minor annoyance,
		// not a correctness issue.
		_ = os.Remove(snapshotPath)
		_ = os.Remove(snapshotPath + "-wal")
		_ = os.Remove(snapshotPath + "-shm")
	}
	return snapshotPath, cleanup, nil
}

// snapshotSQLiteDB writes an atomic clean-image copy of the SQLite
// DB at src to dst using VACUUM INTO. The source DB is opened
// read-write (VACUUM requires write capability even though no schema
// or data mutates) and immediately closed. The target file MUST NOT
// pre-exist — SQLite errors out on overwrite to avoid clobbering a
// live DB by mistake.
func snapshotSQLiteDB(ctx context.Context, src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("destination %s already exists; refusing to overwrite", dst)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat destination: %w", err)
	}
	srcDB, err := db.Open(ctx, db.Options{Path: src})
	if err != nil {
		return fmt.Errorf("open source DB: %w", err)
	}
	defer srcDB.Close()

	// VACUUM INTO is the documented atomic snapshot primitive
	// (https://sqlite.org/lang_vacuum.html#vacuuminto). Holds a
	// read lock on the source while writing the snapshot; concurrent
	// writers on the live DB don't see disruption.
	if _, err := srcDB.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return fmt.Errorf("VACUUM INTO: %w", err)
	}
	return nil
}
