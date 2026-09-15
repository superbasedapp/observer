package antigravity

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// This file is the desktop Antigravity IDE's PLAINTEXT session-file
// path (LayoutDesktopTranscript):
//
//	~/.gemini/antigravity/brain/<uuid>/.system_generated/logs/transcript.jsonl
//
// Live-grounded 2026-09-03 on the operator's Windows box (Antigravity
// IDE signed in, one agent conversation, the 5-turn prompt kit); the
// anonymized fixture is testdata/antigravity/desktop/. One JSON object
// per line, keys: step_index (int, 0-based, NOT contiguous — step 4 was
// absent in the live file), source (USER_EXPLICIT / MODEL / SYSTEM),
// type, status (DONE …), created_at (RFC3339 UTC), content (string),
// tool_calls (array, on PLANNER_RESPONSE steps that invoke tools),
// thinking (string, on some PLANNER_RESPONSE steps).
//
// Turn shape. The INVOCATION and the RESULT are different lines: a
// MODEL/PLANNER_RESPONSE at step N carries tool_calls[{name,args}];
// the typed result (MODEL/RUN_COMMAND, VIEW_FILE, LIST_DIRECTORY,
// CODE_ACTION, GENERIC, …) lands at a LATER step with the result body in
// `content`, prefixed by "Created At: …\nCompleted At: …" lines. A
// tool_calls array fans out to one result step per call, in order, so
// the parser pairs them FIFO (the 2026-08-01 measurement in
// transcript_cli.go: step 17 carried 2 calls → results at 18 and 19).
// The action row is keyed on the RESULT step (same convention as the
// structured .pb decoder), so a call whose result has not landed yet is
// simply not emitted until it does.
//
// tool_calls[].args values are DOUBLE-ENCODED: after decoding the line,
// each value is itself a JSON literal in a string — "CommandLine":
// "\"git status\"", "WaitMsBeforeAsync": "5000", "IsArtifact": "false".
// decodeToolArgs unwraps one level so Target carries `git status`, not
// `"git status"`.
//
// Model. Nothing on a step names the model. The ONLY model evidence is
// the <USER_SETTINGS_CHANGE> block the IDE appends to a USER_INPUT when
// the user picks a model ("changed setting `Model Selection` from None
// to Gemini 3.6 Flash (High)"); it is extracted by a table of regexes
// and carried forward onto every later row until the next change. The
// vendor's DISPLAY name is stored verbatim — it is not an API model id
// and is not normalized into one. `antigravity_state.pbtxt`'s
// `last_selected_agent_model: MODEL_PLACEHOLDER_M71` is an opaque enum,
// NOT a model name, and is never read (the same file's
// `installation_uuid` is never persisted either).
//
// Tokens. No field on any step carries usage. The transcript emits NO
// TokenEvents — the honest zero, not an estimate. Desktop token
// capture still needs the .pb cipher (parked, IDE-12) or a vendor
// telemetry surface.
//
// Cursor. Whether the IDE only appends is UNVERIFIED from a single
// snapshot (the status field exists precisely so an in-flight step can
// be finalised later, which implies a rewrite is possible), so the
// parser re-reads the WHOLE file on every size change — like cline —
// and relies on the store's UNIQUE(source_file, source_event_id) index
// to drop the repeats; every SourceEventID is keyed on step_index, and
// a step whose status is not DONE emits nothing (a partial line must
// never be the one that sticks). The IDE also mirrors the file into
// chunks/transcript/00000000.jsonl and a transcript_full.jsonl sibling;
// neither is a session file (exact tail match in classifyLayout), so
// one step is ingested exactly once.
//
// Two owners, one key. When an agy .db exists for the same uuid (the
// VS Code extension writes one into this tree), BOTH the .db parse and
// this parse synthesize the text + action rows — keyed identically:
// SourceFile = this transcript path, SourceEventID =
// transcriptEventIDPrefix + "<uuid>:step:<n>:<kind>", the .db's API
// model id and trajectory_meta.source on both (agyDBEnrichmentFor).
// Whichever lands first wins and the other is a UNIQUE no-op, in either
// arrival order — a .db that appears AFTER the transcript was already
// ingested (Antigravity 2.0, a future IDE build, a conversation reopened
// in the extension) cannot re-list the conversation. Rows an OLDER build
// persisted under other source_files (the .pb augmentation, the
// text-only .db augmentation) are suppressed by Target through
// legacyTextCoverage.
//
// Known upgrade duplicate (tool rows only). On a host where .pb decrypt
// or the gRPC bridge worked (macOS / Linux with a readable OSCrypt
// secret), conversations ingested before this layout shipped carry
// structured.* tool rows (read_file / edit_file / run_command, keyed
// "antigravity-struct-tool:<uuid>:step:<n>") under source_file = the
// .pb; the transcript now emits the same tool calls under its own
// source_file, and Target-keyed coverage cannot pair them (the
// structured path stores decodeFileURIToPath output, this path stores
// pathnorm.Normalize output — transcript_cli.go's 2026-08-01
// measurement). Text rows ARE covered. Cleanup, run once after
// upgrading such a host:
//
//	DELETE FROM actions WHERE source_file LIKE '%/.gemini/antigravity/conversations/%.pb'
//	  AND raw_tool_name IN ('structured.file_view','structured.artifact_write','structured.run_command')
//	  AND session_id IN (SELECT session_id FROM actions WHERE source_event_id LIKE 'antigravity-transcript:%:tool');
//
// Surface. The transcript itself has no field saying WHICH Antigravity
// app wrote it. With a sibling .db the discriminator is
// trajectory_meta.source (clidb.go's table; nothing is stamped until
// that row exists). Without one — the standalone IDE — the store SHAPE
// is the evidence (the checklist's cursor / kiro rule): brain/ under
// ~/.gemini/antigravity is the IDE's own tree, so the session is stamped
// ide/antigravity. Known gap: if Antigravity 2.0 (the editor-less
// orchestration dashboard) shares this tree without a .db, its sessions
// carry the same stamp — see docs/audits/antigravity-family-surfaces-
// 2026-09-03.md for what is and is not verified.
//
// Watch-root cost (follow-up). brain/ is watched recursively, and each
// conversation adds its .system_generated/{logs,logs/chunks/*,steps/<n>}
// + .user_uploaded + scratch dirs to the inotify set (~8-10 watches per
// conversation). The watcher has no per-root ignore API, and a root set
// enumerating brain/<uuid>/.system_generated/logs per conversation
// would miss a brand-new conversation until the next root refresh, so
// the recursive root stays; a watcher-level ignore-glob is the clean fix.

// transcriptEventIDPrefix namespaces every SourceEventID this file
// emits — the SAME namespace whichever owner (this file's parse or the
// sibling .db's parse) synthesized the row. Distinct from the
// "antigravity-cli-transcript:" namespace the .pb-side AUGMENTATION
// uses for the same steps, so the two can never collide on one
// source_file — and the .pb guard in parseSessionFile makes sure they
// never target the same session from two files.
const transcriptEventIDPrefix = "antigravity-transcript:"

// transcriptStepKind is what the type table says to do with a step.
type transcriptStepKind int

const (
	// stepUser is a USER_EXPLICIT/USER_INPUT prompt.
	stepUser transcriptStepKind = iota
	// stepPlanner is a MODEL/PLANNER_RESPONSE: assistant text and/or
	// tool_calls.
	stepPlanner
	// stepToolResult is a typed tool-result step; the action type comes
	// from the paired tool_calls name first, the row's fallback second.
	stepToolResult
	// stepSkip is a system marker with no content of its own.
	stepSkip
)

// transcriptStepRow is one row of the step-type table.
type transcriptStepRow struct {
	kind transcriptStepKind
	// fallback is the ActionType used for a tool-result step whose paired
	// tool_calls name (or its absence) leaves mapToolName at unknown.
	fallback string
}

// transcriptStepTable is THE step-type table (CLAUDE.md #5): every type
// observed live is a row; a type that is NOT a row is a tool-result
// step with an ActionUnknown fallback (never dropped — the raw type
// rides in RawToolName as "transcript.<type>").
//
// Grounding: USER_INPUT / CONVERSATION_HISTORY / PLANNER_RESPONSE /
// LIST_DIRECTORY / VIEW_FILE / RUN_COMMAND / CODE_ACTION from the
// 2026-09-03 step-in; GENERIC (a find_by_name result with a JSON body)
// from a second live desktop conversation the same day; GREP_SEARCH
// from the 2026-05-24 agy CLI observation recorded in transcript_cli.go
// (same schema).
var transcriptStepTable = map[string]transcriptStepRow{
	"USER_INPUT":           {kind: stepUser},
	"CONVERSATION_HISTORY": {kind: stepSkip},
	"PLANNER_RESPONSE":     {kind: stepPlanner},
	"LIST_DIRECTORY":       {kind: stepToolResult, fallback: models.ActionSearchFiles},
	"VIEW_FILE":            {kind: stepToolResult, fallback: models.ActionReadFile},
	"RUN_COMMAND":          {kind: stepToolResult, fallback: models.ActionRunCommand},
	"CODE_ACTION":          {kind: stepToolResult, fallback: models.ActionEditFile},
	"GREP_SEARCH":          {kind: stepToolResult, fallback: models.ActionSearchText},
	"GENERIC":              {kind: stepToolResult, fallback: models.ActionUnknown},
}

// transcriptStepRowFor resolves a step type through the table; an
// unlisted type is a tool-result step with an unknown fallback.
func transcriptStepRowFor(stepType string) transcriptStepRow {
	if row, ok := transcriptStepTable[stepType]; ok {
		return row
	}
	return transcriptStepRow{kind: stepToolResult, fallback: models.ActionUnknown}
}

// transcriptArgSpec says which tool_calls arg is the row's Target and
// whether it is a filesystem path (normalized) or free text (kept
// verbatim, scrubbed). Cwd is the project-root hint.
type transcriptArgSpec struct {
	key    string
	isPath bool
}

// transcriptTargetArgs is the ordered arg-key table walked to pick a
// row's Target: the first key present wins. Ordered so a command's
// CommandLine beats its Cwd, and a file tool's file beats a directory.
var transcriptTargetArgs = []transcriptArgSpec{
	{key: "CommandLine", isPath: false},
	{key: "AbsolutePath", isPath: true},
	{key: "TargetFile", isPath: true},
	{key: "DirectoryPath", isPath: true},
	{key: "SearchDirectory", isPath: true},
	{key: "Pattern", isPath: false},
	{key: "Query", isPath: false},
	{key: "Url", isPath: false},
}

// transcriptCwdArg is the tool_calls arg that names the directory the
// agent worked in — the project-root hint.
const transcriptCwdArg = "Cwd"

// transcriptContentArgs are the args whose byte length is the code the
// model authored (ToolEvent.ContentBytes).
var transcriptContentArgs = []string{"CodeContent", "ReplacementContent"}

// transcriptToolCall is one decoded tool_calls[] element.
type transcriptToolCall struct {
	Name string                     `json:"name"`
	Args map[string]json.RawMessage `json:"args"`
}

// decodeTranscriptToolCalls decodes a PLANNER_RESPONSE's tool_calls
// array. Malformed input yields nil (the step then contributes no
// pending calls; its result steps fall back to the type table).
func decodeTranscriptToolCalls(raw json.RawMessage) []transcriptToolCall {
	if len(raw) == 0 {
		return nil
	}
	var calls []transcriptToolCall
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil
	}
	return calls
}

// decodeToolArgs unwraps the double-encoded args into plain strings:
// each raw value that is a JSON string is decoded once, and if the
// result is itself a quoted JSON string literal it is decoded again.
// Non-string literals (numbers, booleans) are kept as their source text.
func decodeToolArgs(args map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(args))
	for k, raw := range args {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			out[k] = strings.TrimSpace(string(raw))
			continue
		}
		var inner string
		if t := strings.TrimSpace(s); len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"' &&
			json.Unmarshal([]byte(t), &inner) == nil {
			s = inner
		}
		out[k] = s
	}
	return out
}

// transcriptTarget picks a row's Target from decoded args through
// transcriptTargetArgs; paths are normalized to the host-canonical
// form. Returns "" when no known key is present.
func transcriptTarget(args map[string]string) string {
	for _, spec := range transcriptTargetArgs {
		v := strings.TrimSpace(args[spec.key])
		if v == "" {
			continue
		}
		if spec.isPath {
			if n := pathnorm.Normalize(v); n != "" {
				return n
			}
		}
		return v
	}
	return ""
}

// transcriptContentBytes sums the authored-code args of a call.
func transcriptContentBytes(args map[string]string) int64 {
	var n int64
	for _, k := range transcriptContentArgs {
		n += int64(len(args[k]))
	}
	return n
}

// settingsChangeBlock brackets the IDE's settings-change annotation
// inside a USER_INPUT content.
var settingsChangeBlock = regexp.MustCompile(`(?s)<USER_SETTINGS_CHANGE>(.*?)</USER_SETTINGS_CHANGE>`)

// settingsChangeModelRules is the model-extraction rule table walked
// top-down over the settings-change block; the first capture wins.
// One live-grounded row today ("changed setting `Model Selection` from
// None to Gemini 3.6 Flash (High). No need to comment…"); a future IDE
// wording is a new row, not a new branch.
var settingsChangeModelRules = []*regexp.Regexp{
	regexp.MustCompile("changed setting `Model Selection` from .+? to (.+?)\\.(?:\\s|$)"),
}

// modelFromSettingsChange returns the model display name a USER_INPUT's
// <USER_SETTINGS_CHANGE> block announces, or "" when the content has no
// such block or no rule matches (the honest empty).
func modelFromSettingsChange(content string) string {
	// Every block, in order; the LAST model announcement wins (a step
	// that carries two changes reports the newer selection).
	model := ""
	for _, m := range settingsChangeBlock.FindAllStringSubmatch(content, -1) {
		if len(m) != 2 {
			continue
		}
		for _, rule := range settingsChangeModelRules {
			if hit := rule.FindStringSubmatch(m[1]); len(hit) == 2 {
				model = strings.TrimSpace(hit[1])
				break
			}
		}
	}
	return model
}

// resultHeaderRe matches the "Created At: … / Completed At: …" header
// the IDE prefixes to every tool-result content.
var resultHeaderRe = regexp.MustCompile(`(?m)^(Created At|Completed At):\s*(\S+)\s*$`)

// transcriptResultDuration derives a tool-result step's DurationMs from
// its content header; 0 when either stamp is missing or unparseable.
// The span is Created At → Completed At of the RESULT step, which for
// run_command INCLUDES the wait for the user's approval of the command
// (live values of 289 s and 721 s for sub-second `python hello.py`
// runs) — wall time as the user experienced it, not process runtime.
func transcriptResultDuration(content string) int64 {
	var created, completed time.Time
	for _, m := range resultHeaderRe.FindAllStringSubmatch(content, -1) {
		ts, err := time.Parse(time.RFC3339, m[2])
		if err != nil {
			continue
		}
		switch m[1] {
		case "Created At":
			created = ts
		case "Completed At":
			completed = ts
		}
	}
	if created.IsZero() || completed.IsZero() || completed.Before(created) {
		return 0
	}
	return completed.Sub(created).Milliseconds()
}

// transcriptResultPreview returns the first non-empty, non-header line
// of a tool-result content, for the Target of an orphan result step.
func transcriptResultPreview(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || resultHeaderRe.MatchString(line) {
			continue
		}
		return line
	}
	return ""
}

// desktopTranscriptSurface is the surface-stamp table keyed on layout
// (CLAUDE.md #5). The desktop transcript has no in-file discriminator,
// so the STORE SHAPE is the evidence — see the file comment.
var desktopTranscriptSurface = map[Layout]models.SessionSurface{
	LayoutDesktopTranscript: {Surface: models.SurfaceIDE, SurfaceHost: "antigravity"},
}

// pendingTranscriptCall is an invocation awaiting its result step.
type pendingTranscriptCall struct {
	call        transcriptToolCall
	plannerStep int
	thinking    string
}

// transcriptSynthInput carries the per-conversation context the pure
// synthesizer needs.
type transcriptSynthInput struct {
	sessionPath    string
	conversationID string
	projectRoot    string
	gitRemote      string
	scrubber       Scrubber
	entries        []cliTranscriptEntry
	// coveredUser / coveredAssistant are Targets already persisted for
	// this conversation under the sibling .pb's source_file by the
	// pre-2026-09-03 augmentation path (loadPersistedTargetCoverage);
	// matching text rows are suppressed so the cut-over never
	// double-lists a prompt or reply.
	coveredUser      []string
	coveredAssistant []string
	// modelOverride, when set, replaces the transcript's settings-change
	// display name on every row (the .db knows the real API model id).
	modelOverride string
	// captureSource is the raw client-discriminator string recorded in
	// ActionMetadata.CaptureSource on the user_prompt rows ("" = none).
	captureSource string
}

// commandOutcomeRule is one row of the run-result outcome table: the
// first regex that matches the result content decides Success and the
// ErrorMessage. Grounded 2026-09-03: the standalone IDE writes "The
// command completed successfully."; the agy-backed clients (VS Code
// extension, CLI) write "The command exited with code N.".
type commandOutcomeRule struct {
	re      *regexp.Regexp
	success func(m []string) bool
	errMsg  func(m []string) string
}

var commandOutcomeRules = []commandOutcomeRule{
	{
		re:      regexp.MustCompile(`The command exited with code (\d+)\.`),
		success: func(m []string) bool { return m[1] == "0" },
		errMsg: func(m []string) string {
			if m[1] == "0" {
				return ""
			}
			return "exit code " + m[1]
		},
	},
	{
		re:      regexp.MustCompile(`The command completed successfully\.`),
		success: func([]string) bool { return true },
		errMsg:  func([]string) string { return "" },
	},
}

// commandOutcome walks commandOutcomeRules top-down; a content that
// matches no rule is reported as (true, "") — a DONE step with no
// failure vocabulary is not evidence of failure.
func commandOutcome(content string) (success bool, errMsg string) {
	for _, rule := range commandOutcomeRules {
		if m := rule.re.FindStringSubmatch(content); m != nil {
			return rule.success(m), rule.errMsg(m)
		}
	}
	return true, ""
}

// synthesizeDesktopTranscriptEvents walks the DONE steps of one
// transcript in order and emits ToolEvents. Pure: no I/O.
func synthesizeDesktopTranscriptEvents(in transcriptSynthInput) []models.ToolEvent {
	coveredUser := map[string]bool{}
	for _, t := range in.coveredUser {
		coveredUser[t] = true
	}
	coveredAssistant := map[string]bool{}
	for _, t := range in.coveredAssistant {
		coveredAssistant[t] = true
	}
	scrubText := func(s string) string {
		if in.scrubber == nil {
			return s
		}
		return in.scrubber.String(s)
	}
	const prefix = transcriptEventIDPrefix
	eid := func(step int, suffix string) string {
		return prefix + in.conversationID + ":step:" + strconv.Itoa(step) + ":" + suffix
	}

	var (
		out       []models.ToolEvent
		pending   []pendingTranscriptCall
		model     = in.modelOverride
		turnIndex int
	)
	base := func(ts time.Time) models.ToolEvent {
		return models.ToolEvent{
			SourceFile:  in.sessionPath,
			SessionID:   in.conversationID,
			ProjectRoot: in.projectRoot,
			GitRemote:   in.gitRemote,
			Timestamp:   ts,
			TurnIndex:   turnIndex,
			Model:       model,
			Tool:        models.ToolAntigravity,
			Success:     true,
		}
	}

	for _, e := range in.entries {
		ts, tsErr := time.Parse(time.RFC3339, e.CreatedAt)
		if tsErr != nil {
			ts = time.Now().UTC()
		}
		ts = ts.UTC()
		row := transcriptStepRowFor(e.Type)

		// An in-flight step (status != DONE) emits NOTHING: its ids are
		// keyed on step_index and the store's INSERT OR IGNORE would
		// otherwise freeze the partial content forever. The line is
		// re-read on the next size change once the IDE finalises it. A
		// pending invocation whose result is still in flight is consumed
		// now so the FIFO pairing stays aligned for the steps after it.
		if e.Status != "DONE" {
			if row.kind == stepToolResult && len(pending) > 0 {
				pending = pending[1:]
			}
			continue
		}

		switch row.kind {
		case stepSkip:
			continue

		case stepUser:
			if in.modelOverride == "" {
				if m := modelFromSettingsChange(e.Content); m != "" {
					model = m
				}
			}
			turnIndex++
			text := extractUserRequestText(e.Content)
			if text == "" {
				continue
			}
			target := truncate(text, 200)
			if coveredUser[target] {
				continue
			}
			ev := base(ts)
			ev.SourceEventID = eid(e.StepIndex, "user")
			ev.ActionType = models.ActionUserPrompt
			ev.Target = target
			ev.RawToolName = "transcript.user_input"
			ev.RawToolInput = scrubText(text)
			ev.MessageID = ev.SourceEventID
			if in.captureSource != "" {
				ev.Metadata = &models.ActionMetadata{CaptureSource: in.captureSource}
			}
			out = append(out, ev)

		case stepPlanner:
			thinking := scrubText(strings.TrimSpace(e.Thinking))
			if content := strings.TrimSpace(e.Content); content != "" {
				target := truncate(content, 200)
				if !coveredAssistant[target] {
					ev := base(ts)
					ev.SourceEventID = eid(e.StepIndex, "assistant")
					ev.ActionType = models.ActionAssistantMessage
					ev.Target = target
					ev.RawToolName = "transcript.assistant_text"
					ev.RawToolInput = scrubText(content)
					ev.PrecedingReasoning = thinking
					ev.MessageID = ev.SourceEventID
					out = append(out, ev)
					thinking = "" // consumed by the text row
				}
			}
			for _, call := range decodeTranscriptToolCalls(e.ToolCalls) {
				pending = append(pending, pendingTranscriptCall{call: call, plannerStep: e.StepIndex, thinking: thinking})
				thinking = "" // only the first call of a step carries it
			}

		case stepToolResult:
			ev := base(ts)
			ev.SourceEventID = eid(e.StepIndex, "tool")
			ev.MessageID = ev.SourceEventID
			ev.DurationMs = transcriptResultDuration(e.Content)
			ev.ToolOutput = scrubText(contentcap.Cap(e.Content, contentcap.DefaultMaxBytes))
			if len(pending) > 0 {
				p := pending[0]
				pending = pending[1:]
				args := decodeToolArgs(p.call.Args)
				ev.ActionType = mapToolName(p.call.Name)
				if ev.ActionType == models.ActionUnknown {
					ev.ActionType = row.fallback
				}
				ev.RawToolName = p.call.Name
				ev.Target = transcriptTarget(args)
				if ev.Target == "" {
					ev.Target = transcriptResultPreview(e.Content)
				}
				if enc, err := json.Marshal(args); err == nil {
					ev.RawToolInput = scrubText(contentcap.Cap(string(enc), contentcap.DefaultMaxBytes))
				}
				ev.ContentBytes = transcriptContentBytes(args)
				ev.PrecedingReasoning = p.thinking
				ev.MessageID = prefix + in.conversationID + ":step:" + strconv.Itoa(p.plannerStep)
			} else {
				// Orphan result: no invocation seen for it. Keep the
				// row — the type table names the action, the raw type
				// rides on RawToolName.
				ev.ActionType = row.fallback
				ev.RawToolName = "transcript." + strings.ToLower(e.Type)
				ev.Target = transcriptResultPreview(e.Content)
			}
			if ev.Target == "" {
				ev.Target = strings.ToLower(e.Type)
			}
			ev.Target = truncate(ev.Target, 200)
			if ev.ActionType == models.ActionRunCommand {
				ev.Success, ev.ErrorMessage = commandOutcome(e.Content)
			}
			out = append(out, ev)
		}
	}
	return out
}

// transcriptProjectRootHint returns the first Cwd a tool call names,
// as the conversation's own statement of where the agent worked.
func transcriptProjectRootHint(entries []cliTranscriptEntry) string {
	for _, e := range entries {
		if e.Type != "PLANNER_RESPONSE" {
			continue
		}
		for _, call := range decodeTranscriptToolCalls(e.ToolCalls) {
			args := decodeToolArgs(call.Args)
			if cwd := strings.TrimSpace(args[transcriptCwdArg]); cwd != "" {
				return cwd
			}
		}
	}
	return ""
}

// resolveTranscriptProjectRoot is the project-root ladder for a desktop
// transcript, walked top-down (CLAUDE.md #5):
//
//  1. the Cwd of the conversation's own tool calls (decodeFileURIToRoot
//     normalizes it and walks up to the git root when there is one);
//  2. the desktop state.vscdb trajectorySummaries workspace URI (the
//     existing adapter's resolution; absent on some installs — IDE-12);
//  3. the <ADDITIONAL_METADATA> "Active Document" path (the existing
//     transcript-metadata recovery);
//  4. the "[antigravity]" placeholder.
func (a *Adapter) resolveTranscriptProjectRoot(path, conversationID string, entries []cliTranscriptEntry) (root, remote string) {
	if cwd := transcriptProjectRootHint(entries); cwd != "" {
		if r, rem := rootFromWorkingDir(cwd); r != "" {
			return r, rem
		}
	}
	if idx := a.lookupIndexEntry(path, conversationID); idx != nil && idx.workspaceURI != "" {
		if r, rem, _ := decodeFileURIToRoot(idx.workspaceURI); r != "" && r != "[antigravity]" {
			return r, rem
		}
	}
	if r := extractProjectRootFromTranscript(entries); r != "" {
		return r, ""
	}
	return "[antigravity]", ""
}

// rootFromWorkingDir normalizes a tool call's Cwd to the host-canonical
// form and walks up to its git root when it sits inside a repository;
// otherwise the directory itself is the root. Unlike decodeFileURIToRoot
// it never strips a trailing segment for looking file-like — a Cwd is a
// directory by construction, and workspace names with dots are real.
// Returns "" only for an empty / unnormalizable input.
func rootFromWorkingDir(cwd string) (root, remote string) {
	n := pathnorm.Normalize(cwd)
	if n == "" {
		return "", ""
	}
	if info, err := git.Resolve(n); err == nil {
		return info.Root, git.NormalizeRemote(info.Remote)
	}
	return n, ""
}

// parseDesktopTranscript is the LayoutDesktopTranscript entry point:
// whole-file re-parse (see the file comment on cursoring), one session
// per <uuid>, surface stamp ide/antigravity, no TokenEvents.
func (a *Adapter) parseDesktopTranscript(ctx context.Context, path string, fi os.FileInfo, _ int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fi.Size()}
	conversationID := desktopTranscriptConversationID(path)
	if conversationID == "" {
		return res, nil
	}
	entries := readTranscriptEntries(path, false)
	if len(entries) == 0 {
		return res, nil
	}
	projectRoot, gitRemote := a.resolveTranscriptProjectRoot(path, conversationID, entries)
	coveredUser, coveredAssistant := a.legacyTextCoverage(path, conversationID)

	// A nil *scrub.Scrubber must not become a non-nil Scrubber interface
	// holding a nil pointer (the &Adapter{} literal some tests use).
	var sc Scrubber
	if a.scrubber != nil {
		sc = a.scrubber
	}
	in := transcriptSynthInput{
		sessionPath:      path,
		conversationID:   conversationID,
		projectRoot:      projectRoot,
		gitRemote:        gitRemote,
		scrubber:         sc,
		entries:          entries,
		coveredUser:      coveredUser,
		coveredAssistant: coveredAssistant,
	}
	// A sibling agy .db (VS Code extension, or any agy-backed client
	// writing this tree) is the richer authority on model and surface:
	// read its enrichment so THIS parse emits byte-identical rows to
	// the .db parse (same model id, same CaptureSource, same stamp) —
	// whichever owner lands first, the other is a UNIQUE no-op. A .db
	// that exists but has no trajectory_meta row yet stamps nothing
	// (first-wins at the store would freeze a guessed default).
	if enrich, ok := agyDBEnrichmentFor(ctx, desktopSiblingPath(path, conversationID, ".db")); ok {
		in.modelOverride = enrich.model
		in.captureSource = enrich.captureSource()
		if surf, _, stamp := enrich.surface(LayoutDesktopDB); stamp {
			surf.SessionID = conversationID
			res.SessionSurfaces = append(res.SessionSurfaces, surf)
		}
	} else if surf, ok := desktopTranscriptSurface[LayoutDesktopTranscript]; ok {
		// Transcript-only conversation (the standalone IDE): the store
		// shape is the evidence.
		surf.SessionID = conversationID
		res.SessionSurfaces = append(res.SessionSurfaces, surf)
	}
	res.ToolEvents = synthesizeDesktopTranscriptEvents(in)
	return res, nil
}
