package antigravity

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// loadPersistedTargetCoverage returns the (user_prompt, task_complete)
// Target strings already persisted for this source_file via the
// adapter's TargetCoverageReader. Returns (nil, nil) when no reader
// is wired (tests, probe-cli) — callers treat that as the v1.6.29
// in-memory-dedup-only baseline. Errors are returned as empty slices
// (logged at trace level) because the augmentation path is
// best-effort and stale dedup is preferable to crashing the parse.
func (a *Adapter) loadPersistedTargetCoverage(sourceFile string) (userTargets, asstTargets []string) {
	if a.targetCoverageReader == nil {
		return nil, nil
	}
	u, t, err := a.targetCoverageReader.LoadActionTargets(context.Background(), sourceFile)
	if err != nil {
		tracef("target_coverage_load_err src=%s err=%v", sourceFile, err)
		return nil, nil
	}
	return u, t
}

// historyJSONLEntry mirrors the on-disk shape of one record in
// ~/.gemini/antigravity-cli/history.jsonl. The CLI writes one line
// per user-typed message:
//
//	{"display":"hey","timestamp":1779562038857,"workspace":"...","conversationId":"<uuid>"}
//
// Empirically:
//   - timestamp is wall-clock unix milliseconds
//   - conversationId is sometimes absent on the very first message of
//     a new agy invocation (before the conversation_id has been
//     allocated). Those entries are skipped — the lookup is
//     scoped per-conversation.
type historyJSONLEntry struct {
	Display        string `json:"display"`
	Timestamp      int64  `json:"timestamp"`
	Workspace      string `json:"workspace"`
	ConversationID string `json:"conversationId"`
}

// readCLIHistoryEntries reads + decodes every line of history.jsonl
// for the conversation's CLI install. Filtering by conversationId is
// the caller's job (most callers only want one conversation). Best-
// effort: empty result on any I/O error.
func readCLIHistoryEntries(cliRoot string) []historyJSONLEntry {
	path := filepath.Join(cliRoot, "history.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	var out []historyJSONLEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e historyJSONLEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Display == "" || e.Timestamp == 0 {
			continue
		}
		out = append(out, e)
	}
	return out
}

// synthesizeHistoryUserPrompts builds models.ToolEvent user_prompt
// rows from history.jsonl entries that aren't already represented in
// `existing` (compared by `Target` text after the same truncation the
// markdown / structured emitters apply). This is the CLI's escape
// hatch: agy.exe's gRPC ConvertTrajectoryToMarkdown returns an
// unstable / truncated view of the trajectory — user-typed messages
// often disappear from the bridge response even though they're
// reliably persisted in history.jsonl. Without this fallback, every
// user prompt the bridge fails to expose is permanently lost from
// observer's record.
//
// Each synthesized event's SourceEventID is derived from the
// conversation_uuid + history timestamp (which is unique per
// message in agy's CLI), so:
//
//   - Re-processing the same .pb file is idempotent: the same
//     history entry produces the same SourceEventID, which the
//     store-level (source_file, source_event_id) UNIQUE constraint
//     rejects as a duplicate.
//   - The SourceEventID is independent of the markdown / structured
//     emitters' step-based IDs. If the bridge later catches up and
//     surfaces the same user message as `step:N:user`, the DB
//     accepts both — observer treats the history fallback as the
//     authoritative source of user inputs (it never lies), and any
//     bridge-surfaced duplicate is a same-content row that the
//     dashboard's per-turn rendering deduplicates by message text.
//
// projectRoot, scrubber, sessionID come from the same resolution
// path the bridge-success branch uses, so the synthesized rows
// attribute to the correct project + scrub secrets identically.
//
// existing is the events from the markdown / structured bridge
// pipeline — used only to elide history entries the bridge already
// surfaced (string-equality on Target after truncation).
func synthesizeHistoryUserPrompts(
	sessionPath, conversationID, projectRoot, gitRemote, sessionID string,
	scrubber Scrubber,
	historyEntries []historyJSONLEntry,
	existing []models.ToolEvent,
) []models.ToolEvent {
	if len(historyEntries) == 0 {
		return nil
	}
	covered := map[string]bool{}
	for _, ev := range existing {
		if ev.ActionType == models.ActionUserPrompt {
			covered[ev.Target] = true
		}
	}
	var out []models.ToolEvent
	for _, e := range historyEntries {
		if e.ConversationID != conversationID {
			continue
		}
		target := truncate(e.Display, 200)
		if covered[target] {
			continue
		}
		// Each synthesized event must be deterministic across re-
		// parses of the same .pb so the UNIQUE(source_file,
		// source_event_id) constraint deduplicates idempotently.
		eid := "antigravity-cli-history:" + conversationID + ":" + strconv.FormatInt(e.Timestamp, 10)
		out = append(out, models.ToolEvent{
			SourceFile:    sessionPath,
			SourceEventID: eid,
			SessionID:     sessionID,
			ProjectRoot:   projectRoot,
			GitRemote:     gitRemote,
			Timestamp:     time.UnixMilli(e.Timestamp).UTC(),
			Tool:          models.ToolAntigravity,
			ActionType:    models.ActionUserPrompt,
			Target:        target,
			Success:       true,
			RawToolName:   "history.user_input",
			RawToolInput:  scrubber.String(e.Display),
			MessageID:     "antigravity-cli-history:" + conversationID + ":" + strconv.FormatInt(e.Timestamp, 10),
		})
	}
	return out
}

// augmentResultFromHistory tops up an existing ParseResult with
// user_prompt + assistant_text rows that the bridge / structured
// fetch didn't surface. Sources tried in order:
//
//  1. brain/<conv>/.system_generated/logs/transcript.jsonl (CLI) or
//     overview.txt (desktop) — same JSONL schema, plaintext trace of
//     every completed turn (both sides of the conversation).
//     Strongly preferred when present.
//  2. history.jsonl — global user-input log (user side only, CLI
//     ONLY — desktop has no analogue), fallback for CLI
//     conversations whose brain/ subdir hasn't been created yet or
//     was cleaned up.
//
// Mutates res in place; safe to call when res has zero events (the
// synthesized events become the entire result). Returns the count
// of synthesized events added for caller diagnostics.
//
// Works for both CLI and desktop layouts now — the layout-aware path
// resolver picks the right per-turn file. Previously gated to CLI
// only because desktop's plaintext trace wasn't known; that gating
// is now in the caller's responsibility (it isn't — see adapter.go).
func (a *Adapter) augmentResultFromHistory(sessionPath, conversationID, projectRoot, gitRemote string, res *adapter.ParseResult) int {
	// identity mirrors projectRoot/gitRemote's own "pull from an
	// existing event" derivation (Project Identity Resolver v2,
	// 2026-09-06, §3.1 / W1): synthesized rows below attribute
	// identically to the bridge/decrypt-surfaced rows for the same
	// conversation.
	identity := identityFromResult(res)
	// Primary: layout-appropriate brain/<uuid> transcript (CLI:
	// transcript.jsonl; desktop: overview.txt). Both decode through
	// readCLITranscriptEntries — same schema.
	if path := transcriptPathFor(sessionPath, conversationID); path != "" {
		if transcript := readCLITranscriptEntries(path); len(transcript) > 0 {
			// Project-root recovery, same rationale as in
			// historyOnlyResult: when the caller's projectRoot is the
			// "[antigravity]" placeholder (state.vscdb miss for fresh
			// conversations), retroactively patch every emitted event
			// once we discover the real workspace from metadata. Keeps
			// the augmentation path symmetric across all entry sites.
			// extractProjectRootFromTranscript has no git remote of its
			// own (it isn't a git.Resolve call site), so gitRemote is
			// deliberately left as-is rather than cleared or guessed.
			if projectRoot == "[antigravity]" {
				if derived := extractProjectRootFromTranscript(transcript); derived != "" {
					projectRoot = derived
					applyResolvedProjectRoot(res, derived)
				}
			}
			extraU, extraA := a.loadPersistedTargetCoverage(sessionPath)
			synth := synthesizeTranscriptEvents(
				sessionPath, conversationID, projectRoot, gitRemote, conversationID,
				a.scrubber, transcript, res.ToolEvents,
				extraU, extraA,
			)
			if len(synth) > 0 {
				scoped := adapter.ParseResult{ToolEvents: synth}
				adapter.ApplyProjectIdentity(&scoped, identity)
				res.ToolEvents = append(res.ToolEvents, synth...)
			}
			return len(synth)
		}
	}
	// Fallback: history.jsonl (user side only, CLI ONLY — desktop
	// doesn't write a global history.jsonl).
	cliRoot, _ := cliRootsFor(sessionPath)
	if cliRoot == "" {
		return 0
	}
	entries := readCLIHistoryEntries(cliRoot)
	if len(entries) == 0 {
		return 0
	}
	synth := synthesizeHistoryUserPrompts(
		sessionPath, conversationID, projectRoot, gitRemote, conversationID,
		a.scrubber, entries, res.ToolEvents,
	)
	if len(synth) == 0 {
		return 0
	}
	scoped := adapter.ParseResult{ToolEvents: synth}
	adapter.ApplyProjectIdentity(&scoped, identity)
	res.ToolEvents = append(res.ToolEvents, synth...)
	return len(synth)
}

// projectRootFromResult extracts the project root attribution from
// an existing ParseResult's ToolEvents — the bridge / structured
// pipeline records it on each event, so any one of them carries it.
// Falls back to a synthetic "[antigravity]" tag when the result is
// empty, mirroring recoverViaLocalGRPC's behaviour for the no-index
// case. Used by the history.jsonl augmentation so synthesized rows
// attribute identically to bridge-surfaced rows for the same
// conversation.
func projectRootFromResult(res *adapter.ParseResult, conversationID string) string {
	if res != nil {
		for _, ev := range res.ToolEvents {
			if ev.ProjectRoot != "" {
				return ev.ProjectRoot
			}
		}
	}
	_ = conversationID
	return "[antigravity]"
}

// gitRemoteFromResult is projectRootFromResult's sibling: it pulls
// the normalized git remote off the same ToolEvent that carried the
// project root, so history.jsonl augmentation rows attribute to the
// identical (root, remote) pair as the bridge/decrypt-surfaced rows
// for the same conversation. Returns "" when no event carries one
// (no git remote configured, or the workspace wasn't git-resolved).
func gitRemoteFromResult(res *adapter.ParseResult, conversationID string) string {
	if res != nil {
		for _, ev := range res.ToolEvents {
			if ev.ProjectRoot != "" {
				return ev.GitRemote
			}
		}
	}
	_ = conversationID
	return ""
}

// identityFromResult is projectRootFromResult/gitRemoteFromResult's
// sibling for the full Project Identity Resolver v2 bundle: it pulls
// every additive field off the same ToolEvent that carried the
// project root, so synthesized history/transcript rows attribute
// identically to the bridge/decrypt-surfaced rows for the same
// conversation. Returns a zero Identity when no event carries one.
func identityFromResult(res *adapter.ParseResult) git.Identity {
	if res == nil {
		return git.Identity{}
	}
	for _, ev := range res.ToolEvents {
		if ev.ProjectRoot == "" {
			continue
		}
		return git.Identity{
			UpstreamRemote:     ev.GitUpstreamRemote,
			RemoteOwner:        ev.GitRemoteOwner,
			UpstreamOwner:      ev.GitUpstreamOwner,
			RootCommitSHA:      ev.RootCommitSHA,
			ContentFingerprint: ev.ContentFingerprint,
			Workspace:          ev.Workspace,
			IsWorktree:         ev.IsWorktree,
		}
	}
	// Fall back to TokenEvents: parseCLIDB's gen_metadata pass only ever
	// produces TokenEvents before augmentResultFromHistory runs, so the
	// ToolEvents-only scan above would otherwise always miss it.
	for _, tk := range res.TokenEvents {
		if tk.ProjectRoot == "" {
			continue
		}
		return git.Identity{
			UpstreamRemote:     tk.GitUpstreamRemote,
			RemoteOwner:        tk.GitRemoteOwner,
			UpstreamOwner:      tk.GitUpstreamOwner,
			RootCommitSHA:      tk.RootCommitSHA,
			ContentFingerprint: tk.ContentFingerprint,
			Workspace:          tk.Workspace,
			IsWorktree:         tk.IsWorktree,
		}
	}
	return git.Identity{}
}

// historyOnlyResult builds a ParseResult populated entirely from
// on-disk plaintext sources — used in the decrypt + gRPC double-
// failure branch as a final escape hatch. Returns nil when no source
// has any entries for this conversation (caller falls back to the
// existing unrecoverable-marking path); otherwise returns a fully-
// formed result with NewOffset=fi.Size() so the cursor advances and
// the file isn't retried until it grows again.
//
// Source preference (per layout):
//   - CLI: brain/<uuid>/.system_generated/logs/transcript.jsonl,
//     falling back to history.jsonl (global user-input log) when the
//     brain/ subdir hasn't been written yet.
//   - Desktop: brain/<uuid>/.system_generated/logs/overview.txt
//     (same JSONL schema as CLI's transcript.jsonl, just renamed).
//     No history.jsonl analogue exists — desktop has no fallback if
//     overview.txt is missing.
//
// Project root resolution mirrors recoverViaLocalGRPC: lookup the
// index entry (CLI hits the metadata_cli resolver; desktop hits
// state.vscdb) and use its workspace URI if available; otherwise tag
// synthetic.
//
// Returns nil for layouts other than CLI / desktop (no known
// plaintext source). Critically, this path is what unblocks fresh
// desktop conversations when oscrypt can't decrypt the .pb (rotated
// cipher) AND the bridge can't reach an agy.exe / language_server
// that hosts the conversation — the same plaintext overview.txt the
// Antigravity IDE itself writes is now the recovery source.
func (a *Adapter) historyOnlyResult(sessionPath string, fi os.FileInfo) *adapter.ParseResult {
	layout := classifyLayout(sessionPath)
	if layout != LayoutCLI && layout != LayoutDesktop {
		return nil
	}
	conversationID := uuidFromFilename(sessionPath)
	projectRoot, gitRemote, projectIdentity := "[antigravity]", "", git.Identity{}
	if idx := a.lookupIndexEntry(sessionPath, conversationID); idx != nil && idx.workspaceURI != "" {
		projectRoot, gitRemote, projectIdentity = decodeFileURIToRoot(idx.workspaceURI)
	}
	// Primary: layout-appropriate brain/<uuid>/...txt|jsonl.
	if path := transcriptPathFor(sessionPath, conversationID); path != "" {
		if transcript := readCLITranscriptEntries(path); len(transcript) > 0 {
			// Project-root recovery: when state.vscdb's
			// trajectorySummaries hasn't been flushed yet for this
			// conversation, idx is nil and projectRoot is the
			// "[antigravity]" placeholder. The IDE's own ADDITIONAL_METADATA
			// stamp in every USER_INPUT carries the active workspace
			// context — using it surfaces the real project before the
			// next state.vscdb flush. (No-op for CLI-from-bash sessions
			// whose metadata block only carries the timestamp.)
			if projectRoot == "[antigravity]" {
				if derived := extractProjectRootFromTranscript(transcript); derived != "" {
					projectRoot = derived
				}
			}
			extraU, extraA := a.loadPersistedTargetCoverage(sessionPath)
			synth := synthesizeTranscriptEvents(
				sessionPath, conversationID, projectRoot, gitRemote, conversationID,
				a.scrubber, transcript, nil,
				extraU, extraA,
			)
			if len(synth) > 0 {
				sourceName := "transcript.jsonl"
				if layout == LayoutDesktop {
					sourceName = "overview.txt"
				}
				out := &adapter.ParseResult{
					NewOffset:  fi.Size(),
					ToolEvents: synth,
					Warnings: []string{
						"antigravity: decrypt + gRPC both failed; surfacing " +
							strconv.Itoa(len(synth)) +
							" event(s) from " + sourceName,
					},
				}
				adapter.ApplyProjectIdentity(out, projectIdentity)
				return out
			}
		}
	}
	// Fallback: history.jsonl (CLI-only; desktop has no analogue).
	if layout != LayoutCLI {
		return nil
	}
	cliRoot, _ := cliRootsFor(sessionPath)
	if cliRoot == "" {
		return nil
	}
	entries := readCLIHistoryEntries(cliRoot)
	if len(entries) == 0 {
		return nil
	}
	synth := synthesizeHistoryUserPrompts(
		sessionPath, conversationID, projectRoot, gitRemote, conversationID,
		a.scrubber, entries, nil,
	)
	if len(synth) == 0 {
		return nil
	}
	out := &adapter.ParseResult{
		NewOffset:  fi.Size(),
		ToolEvents: synth,
		Warnings: []string{
			"antigravity: decrypt + gRPC both failed; surfacing " +
				strconv.Itoa(len(synth)) +
				" user_prompt(s) from history.jsonl (no assistant responses available without the bridge)",
		},
	}
	adapter.ApplyProjectIdentity(out, projectIdentity)
	return out
}
