package antigravity

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// cliTranscriptEntry mirrors one line of
//
//	~/.gemini/antigravity-cli/brain/<uuid>/.system_generated/logs/transcript.jsonl
//
// This file is the CLI's own trace of every conversation turn, in
// PLAIN JSON with timestamps + content. Vastly richer than
// history.jsonl (which is user-only) — transcript.jsonl includes
// the assistant `PLANNER_RESPONSE` content that agy's gRPC
// `ConvertTrajectoryToMarkdown` endpoint refuses to surface for
// in-progress conversations.
//
// Observed turn types (2026-05-24, agy CLI 1.x):
//
//	USER_EXPLICIT/USER_INPUT       — user-typed message (content
//	                                 wrapped in <USER_REQUEST>…)
//	MODEL/PLANNER_RESPONSE         — assistant text response
//	                                 (content) and/or tool_calls
//	MODEL/{GREP_SEARCH,LIST_DIRECTORY,RUN_COMMAND,VIEW_FILE,...}
//	                               — tool RESULT (content = the
//	                                 returned data, not the
//	                                 invocation arguments)
//	SYSTEM/CONVERSATION_HISTORY    — system event, no content,
//	                                 ignored
//
// This parser extracts USER_INPUT + PLANNER_RESPONSE text only — the
// two text-bearing turn types observer's session view actually
// renders. `ToolCalls` is decoded but deliberately NOT promoted into
// action rows. That deferral is now GROUNDED rather than assumed;
// TestSynthesizeTranscriptEvents_ToolCallsAreNotPromoted and
// TestTranscriptToolTargetsCannotDedupAgainstStructured pin it.
//
// Measured 2026-08-01 against the live corpus + the desktop sidecar
// for conversation b070924e (~/.gemini/antigravity/brain/…/overview.txt):
//
//   - The invocation and the result are DIFFERENT entries. tool_calls
//     rides a PLANNER_RESPONSE at step N; the typed result entry
//     (MODEL/VIEW_FILE, …) lands at step N+1. A single tool_calls
//     ARRAY fans out: step 17 carries 2 calls → results at steps 18
//     and 19; step 21 carries 3 → steps 22, 23, 24. So neither the
//     step index nor a fixed offset is a usable join key.
//   - The structured/bridge path keys its rows on the RESULT step
//     ("antigravity-struct-tool:<conv>:step:<N+1>"). For b070924e all
//     14 structured tool rows are the same invocations this file's
//     tool_calls describe — a naive promotion double-counts 1:1.
//   - The two namespaces differ, so the (source_file,
//     source_event_id) UNIQUE constraint cannot suppress the overlap
//     — the same gap TargetCoverageReader exists to close for text.
//   - Target-keyed dedup does not transfer. structured.file_view
//     stores decodeFileURIToPath's output ("home/marmutapp/x.go" —
//     file:/// strips the leading slash), while tool_calls carries a
//     JSON-quoted absolute path ("\"/home/marmutapp/x.go\""). The
//     TargetCoverageReader docstring's "byte-exact, no normalisation
//     needed" premise holds for free text ONLY.
//   - The overlap is not layout-specific, so a CLI-only gate is not a
//     safe shortcut. antigravity-cli has no structured.* tool rows
//     TODAY, but that is a corpus property, not an invariant: the
//     structured/bridge machinery demonstrably runs on CLI
//     conversations (47 token_usage rows across 16 antigravity-cli
//     `.pb` source files), and log_scan.go exists precisely to map CLI
//     conversation UUIDs onto the agy host that serves the cascade
//     trajectory. A CLI conversation can therefore start producing
//     structured tool rows at any time.
//
// Promoting tool calls therefore needs a THIRD coverage bucket on
// TargetCoverageReader.LoadActionTargets (whose SQL filters to
// user_prompt/task_complete/assistant_message today) plus an explicit
// normalisation contract for tool targets. Both live outside this
// package (internal/store + cmd/observer), so the promotion is
// blocked here by design rather than by effort.
type cliTranscriptEntry struct {
	StepIndex int             `json:"step_index"`
	Source    string          `json:"source"`
	Type      string          `json:"type"`
	Status    string          `json:"status"`
	CreatedAt string          `json:"created_at"`
	Content   string          `json:"content,omitempty"`
	ToolCalls json.RawMessage `json:"tool_calls,omitempty"`
	// Thinking is the model's reasoning summary that the desktop IDE
	// writes on some PLANNER_RESPONSE steps (live-grounded 2026-09-03;
	// absent on the CLI corpus). Read only by transcript.go, where it
	// becomes the PrecedingReasoning of the row the step produces.
	Thinking string `json:"thinking,omitempty"`
}

// cliTranscriptPath returns the on-disk path for a given conversation's
// transcript.jsonl. The brain/ subdir is created by agy when the
// conversation starts; the file is appended to as turns happen.
func cliTranscriptPath(cliRoot, conversationID string) string {
	return filepath.Join(cliRoot, "brain", conversationID, ".system_generated", "logs", "transcript.jsonl")
}

// desktopTranscriptPath returns the on-disk path for a desktop
// Antigravity conversation's plaintext per-turn trace. Two layouts
// are supported, in preference order:
//
//	<desktopRoot>/brain/<uuid>/.system_generated/logs/transcript.jsonl  (v1.8.2+ unified name)
//	<desktopRoot>/brain/<uuid>/.system_generated/logs/overview.txt      (pre-rename legacy)
//
// where desktopRoot is `<gemini-root>/antigravity` (the parent of the
// conversations/ directory). The wire format is the same JSONL schema
// on both files (verified 2026-05-24 + 2026-06-07: same `step_index`
// / `source` / `type` / `status` / `created_at` / `content` /
// `tool_calls` keys, same DONE-only finalisation contract).
//
// Why two names: as of the IDE build active 2026-05-24 on the
// operator's host, desktop Antigravity rotated its .pb encryption
// cipher to one oscrypt can't currently decrypt — the same blocker
// that gated CLI recovery. Plaintext sidecar files are the reliable
// recovery path. The 2026-06-06 desktop build renamed the sidecar
// from `overview.txt` to `transcript.jsonl`, unifying it with the
// CLI variant's filename. Without this fallback chain, every fresh
// desktop conversation on the new build lands as zero-events-
// extracted after decrypt fails and the adapter marks the .pb
// unrecoverable (`oscrypt.DecryptAuto: no cipher mode produced a
// validating plaintext (no network_recovery)`).
//
// The function prefers the new filename and falls back to the legacy
// only if it exists on disk. When NEITHER exists (e.g. the brain/
// subdir hasn't been created yet), the new-format path is returned
// so a later re-poll (after the conversation file finalises and the
// sidecar appears) finds it. Returning the legacy in the no-sidecar
// case would silently regress newer installs back to the
// rename-blind v1.6.x behaviour.
func desktopTranscriptPath(desktopRoot, conversationID string) string {
	logsDir := filepath.Join(desktopRoot, "brain", conversationID, ".system_generated", "logs")
	newPath := filepath.Join(logsDir, "transcript.jsonl")
	if fileExists(newPath) {
		return newPath
	}
	legacyPath := filepath.Join(logsDir, "overview.txt")
	if fileExists(legacyPath) {
		return legacyPath
	}
	return newPath
}

// fileExists is a thin os.Stat wrapper that treats any error (not
// just os.ErrNotExist) as "absent" — permission denied / EPERM /
// EIO all reduce to "skip this candidate, try the next." Used by
// desktopTranscriptPath to pick between transcript.jsonl and the
// legacy overview.txt without surfacing the underlying stat error.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readCLITranscriptEntries decodes every line of transcript.jsonl
// into ordered entries. Filters to status="DONE" — partial / streaming
// turns aren't surfaced until agy finalises them, matching observer's
// "completed turns only" guarantee. Empty result on I/O error
// (missing brain/ subdir, file not yet created) so callers can fall
// back to history.jsonl or the legacy bridge path.
func readCLITranscriptEntries(path string) []cliTranscriptEntry {
	return readTranscriptEntries(path, true)
}

// readTranscriptEntries is the worker behind readCLITranscriptEntries.
// doneOnly=false keeps in-flight (non-DONE) lines so a caller that
// pairs invocations with results (transcript.go) can keep its FIFO
// aligned while still emitting nothing for a step the IDE has not
// finalised.
func readTranscriptEntries(path string, doneOnly bool) []cliTranscriptEntry {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// Transcript lines can be large (tool results contain full
	// command output, file content). Allow up to 4 MiB per line.
	scanner.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)
	var out []cliTranscriptEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e cliTranscriptEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if doneOnly && e.Status != "DONE" {
			continue
		}
		out = append(out, e)
	}
	return out
}

// extractUserRequestText pulls the user-typed text out of a USER_INPUT
// entry's content field. agy wraps it in:
//
//	<USER_REQUEST>\n<text>\n</USER_REQUEST>
//	<ADDITIONAL_METADATA>...</ADDITIONAL_METADATA>
//	<USER_SETTINGS_CHANGE>...</USER_SETTINGS_CHANGE>
//
// Only the USER_REQUEST inner text is the actual prompt; the rest
// is system context observer doesn't surface. Falls back to the
// whole content (trimmed) if the wrapper is missing — defensive
// against future agy format changes.
func extractUserRequestText(content string) string {
	const startTag = "<USER_REQUEST>"
	const endTag = "</USER_REQUEST>"
	startIdx := strings.Index(content, startTag)
	endIdx := strings.Index(content, endTag)
	if startIdx < 0 || endIdx < 0 || endIdx <= startIdx {
		return strings.TrimSpace(content)
	}
	return strings.TrimSpace(content[startIdx+len(startTag) : endIdx])
}

// synthesizeTranscriptEvents builds ToolEvents (user_prompt +
// task_complete pairs) from transcript.jsonl entries. Dedup against
// `existing` happens on Target text — if the bridge already
// surfaced "ok" as the assistant response to "Just say ok", we
// don't double-emit the transcript-derived row for the same content.
//
// `extraCoveredUser` and `extraCoveredAssistant` carry Target strings
// from outside the current parse cycle — typically rows already
// persisted in the DB for this source_file from prior parse cycles.
// Without them, a later parse cycle that reaches this function with
// an empty in-memory `existing` (decrypt-fail → historyOnlyResult, or
// decrypt-success-with-zero-events) re-emits every transcript entry,
// landing duplicates because the structured side uses a different
// SourceEventID namespace and the UNIQUE constraint can't suppress
// them. Either slice may be nil (the v1.6.29 baseline behaviour).
//
// Each event's SourceEventID is keyed off step_index from
// transcript.jsonl, so re-parses of the same file are idempotent:
// the (source_file, source_event_id) UNIQUE constraint rejects
// duplicate inserts cleanly.
func synthesizeTranscriptEvents(
	sessionPath, conversationID, projectRoot, gitRemote, sessionID string,
	scrubber Scrubber,
	entries []cliTranscriptEntry,
	existing []models.ToolEvent,
	extraCoveredUser, extraCoveredAssistant []string,
) []models.ToolEvent {
	if len(entries) == 0 {
		return nil
	}
	coveredUser := map[string]bool{}
	coveredAssistant := map[string]bool{}
	for _, ev := range existing {
		switch ev.ActionType {
		case models.ActionUserPrompt:
			coveredUser[ev.Target] = true
		case models.ActionAssistantMessage, models.ActionTaskComplete:
			// BOTH types, deliberately. The structured/markdown parsers
			// now emit assistant text as assistant_message (WP-T6 B2a),
			// while genuinely-terminal rows (structured.final_summary,
			// markdown.planner_response) stay task_complete — and a
			// mid-upgrade database carries BOTH spellings for the same
			// text until migration 078 lands. Matching only one of them
			// would silently reopen the duplicate-assistant-row bug this
			// coverage set exists to close.
			coveredAssistant[ev.Target] = true
		}
	}
	for _, t := range extraCoveredUser {
		coveredUser[t] = true
	}
	for _, t := range extraCoveredAssistant {
		coveredAssistant[t] = true
	}
	var out []models.ToolEvent
	for _, e := range entries {
		ts, tsErr := time.Parse(time.RFC3339, e.CreatedAt)
		if tsErr != nil {
			ts = time.Now().UTC()
		}
		switch {
		case e.Source == "USER_EXPLICIT" && e.Type == "USER_INPUT":
			text := extractUserRequestText(e.Content)
			if text == "" {
				continue
			}
			target := truncate(text, 200)
			if coveredUser[target] {
				continue
			}
			eid := "antigravity-cli-transcript:" + conversationID + ":step:" + strconv.Itoa(e.StepIndex) + ":user"
			out = append(out, models.ToolEvent{
				SourceFile:    sessionPath,
				SourceEventID: eid,
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitRemote:     gitRemote,
				Timestamp:     ts.UTC(),
				Tool:          models.ToolAntigravity,
				ActionType:    models.ActionUserPrompt,
				Target:        target,
				Success:       true,
				RawToolName:   "transcript.user_input",
				RawToolInput:  scrubber.String(text),
				MessageID:     eid,
			})
		case e.Source == "MODEL" && e.Type == "PLANNER_RESPONSE" && e.Content != "":
			target := truncate(e.Content, 200)
			if coveredAssistant[target] {
				continue
			}
			eid := "antigravity-cli-transcript:" + conversationID + ":step:" + strconv.Itoa(e.StepIndex) + ":assistant"
			out = append(out, models.ToolEvent{
				SourceFile:    sessionPath,
				SourceEventID: eid,
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitRemote:     gitRemote,
				Timestamp:     ts.UTC(),
				Tool:          models.ToolAntigravity,
				// One row per MODEL/PLANNER_RESPONSE step, many steps per
				// turn — per-message assistant text, not a turn terminus.
				ActionType:   models.ActionAssistantMessage,
				Target:       target,
				Success:      true,
				RawToolName:  "transcript.assistant_text",
				RawToolInput: scrubber.String(e.Content),
				MessageID:    eid,
			})
		}
	}
	return out
}
