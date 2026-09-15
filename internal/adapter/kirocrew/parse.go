package kirocrew

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// metaLine is the FIRST line of every Crew chat transcript:
// `{"_type":"metadata", …}`. Grounded 2026-09-03; every key observed on
// the live file is typed here, and the ones this adapter deliberately
// does not use are named in the field comments so a reader can see the
// choice was made rather than missed.
type metaLine struct {
	Type       string `json:"_type"`
	CreatedAt  string `json:"created_at"`
	MemoryMode string `json:"memory_mode"`
	Title      string `json:"title"`
	Agent      string `json:"agent"`
	// Model is EMPTY on the grounded capture ("" — Crew leaves model
	// selection to the driven agent; ~/.kiro/crew/agent_model_state.json
	// records `{"kirocrew": {"model_managed": true}}`). Carried through
	// honestly: empty stays empty, never a guess.
	Model string `json:"model"`
	// Project is the workspace directory the chat is bound to — the
	// project-root source for this adapter (the transcript carries no
	// per-turn cwd).
	Project string `json:"project"`
	// Tags are opaque 12-hex ids into ~/.kiro/crew/tags.json, not
	// human labels; recorded as metadata only.
	Tags []string `json:"tags"`
	// FolderID indexes ~/.kiro/crew/folders.json. TitleOrigin is
	// "auto"|"user"; Origin is the chat's creator ("user"). TabID and
	// HumanSeen / LastConsolidated / AutoTagged are desktop-UI state.
	FolderID    string `json:"folder_id"`
	TitleOrigin string `json:"title_origin"`
	Origin      string `json:"origin"`
}

// turnLine is any non-metadata line: `role` ∈ {user, assistant, tool}.
type turnLine struct {
	Role    string   `json:"role"`
	Content string   `json:"content"`
	TS      string   `json:"ts"`
	Thread  string   `json:"source_thread"`
	User    string   `json:"source_user"`
	Meta    turnMeta `json:"meta"`
}

// turnMeta is the per-line `meta` object. `pastes` (the desktop app's
// paste-buffer echo of the user's own message) is deliberately NOT typed:
// it duplicates Content verbatim and adds nothing but bulk.
type turnMeta struct {
	// MID is the stable per-message id ("m-230116baa0784979") — the
	// SourceEventID for user / assistant lines.
	MID string `json:"mid"`
	// ToolCallID ("tooluse_uEOpM9XzoQzTpy3JhbCpuG") is the SourceEventID
	// for tool lines. It is BYTE-IDENTICAL to the driven kiro-cli
	// session's `toolUse.toolUseId` for the same call — the fact that
	// makes the two stores provably the same conversation.
	ToolCallID string `json:"tool_call_id"`
	// Kind is Crew's own normalized tool vocabulary: "read" | "edit" |
	// "execute" on the grounded capture. It is EMPTY on the completion
	// half of a tool pair (see mergeToolLines).
	Kind string `json:"kind"`
	// Purpose is the model-authored `__tool_use_purpose` string.
	Purpose string `json:"purpose"`
	// Input is the tool arguments. On the CALL half of an edit pair it
	// is a human-readable unified DIFF (not JSON); on the COMPLETION
	// half it is the structured JSON object. mergeToolLines prefers the
	// JSON-valid one.
	Input string `json:"input"`
	// Output is the tool result body.
	Output string `json:"output"`
	// Done marks the call complete.
	Done bool `json:"done"`
	// TurnStats rides on the LAST assistant line of a user turn only.
	TurnStats *turnStats `json:"turn_stats"`
	// FileChanges is a per-turn list of touched paths with empty
	// before/after bodies. Deliberately NOT decoded: the same paths
	// already ride on the tool actions, and the field adds no capture.
}

// turnStats is the per-turn accounting block Crew appends to the last
// assistant line of a turn: `{"elapsed_ms":77343,"credits":1.2768}`.
//
// `credits` is Kiro's BILLING unit, not tokens — it equals the sum of the
// driven kiro-cli session's per-call `metering_usage` credits to four
// decimal places (1.2768 vs 1.2769 on the grounded capture). This repo
// deliberately does not treat credits as tokens (see
// internal/adapter/kirocli/flat.go's "Credits are NOT tokens" note), so
// the field is decoded to document the choice and then dropped.
// `elapsed_ms` IS a real measured wall-clock duration and is carried onto
// the turn's terminal assistant message.
type turnStats struct {
	ElapsedMS int64   `json:"elapsed_ms"`
	Credits   float64 `json:"credits"`
}

// shellOutput is the `{exit_status, stdout, stderr}` envelope a Crew
// `execute` tool line can carry in `meta.output`. It is BYTE-IDENTICAL
// to the envelope internal/adapter/kirocli reads out of the driven
// kiro-cli session's `json` toolResult block — the same tool, the same
// result, rendered into two stores.
//
// The envelope is CONDITIONAL, which is why this is a try-decode and not
// a branch on `kind`: of the six grounded `execute` calls, three carried
// the envelope (`del hello.py && dir /b`, `del hello.py`, `dir /b`) and
// three carried the command's plain stdout as a raw string
// (`python hello.py` twice, `Get-ChildItem -Name`). Both shapes must
// work, so a decode that does not yield an `exit_status` falls back to
// treating `meta.output` as literal text.
type shellOutput struct {
	ExitStatus string `json:"exit_status"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

// zeroExitStatus is the exact `exit_status` spelling Kiro emits for a
// successful command. Anything else is a failure — the conservative
// direction, and the vocabulary is not otherwise documented. Same
// constant, same rule as internal/adapter/kirocli's flat path.
const zeroExitStatus = "exit code: 0"

// toolOutcome renders a merged tool record's output and reports its
// outcome.
//
// The `done` flag is NOT an outcome: Crew sets it on the completion half
// of every pair, successful or not. The only failure signal Crew records
// is the shell envelope's `exit_status` — which is exactly why this
// exists. Two of the six grounded `execute` calls came back with
// `exit code: 1` (PowerShell rejecting `&&`, then a bare `dir /b`);
// without this rule both would have been filed as successful commands,
// the same trap the kiro-cli side documents.
//
// A raw (non-envelope) output carries no verdict at all, so it stays
// successful — the honest answer, since Crew records none.
func toolOutcome(rec toolRecord) (out string, success bool, errMsg string) {
	var sh shellOutput
	if err := json.Unmarshal([]byte(rec.output), &sh); err == nil && sh.ExitStatus != "" {
		// Render what the command actually printed, not the JSON
		// envelope — stdout then stderr, matching kirocli.resultText.
		if sh.ExitStatus != zeroExitStatus {
			return sh.Stdout + sh.Stderr, false, "kiro shell " + sh.ExitStatus
		}
		return sh.Stdout + sh.Stderr, true, ""
	}
	return rec.output, true, ""
}

// toolArgs is the decoded structured `meta.input` of a Crew tool call.
// Mirrors internal/adapter/kirocli/normalize.go's toolArgs — the fields
// are the SAME kiro-cli built-in tool arguments, because Crew drives
// kiro-cli and echoes its argument objects verbatim.
type toolArgs struct {
	Command    string `json:"command"`     // "create"|"strReplace" for edits; the shell line for executes
	Path       string `json:"path"`        // file target
	Content    string `json:"content"`     // create body
	NewStr     string `json:"newStr"`      // strReplace replacement
	WorkingDir string `json:"working_dir"` // execute cwd
	Operations []struct {
		Path string `json:"path"`
	} `json:"operations"` // batch read
}

// toolKind* are the Crew tool-vocabulary tokens. Declared as constants so
// the action table below is the one place the vocabulary is spelled.
const (
	toolKindRead    = "read"
	toolKindEdit    = "edit"
	toolKindExecute = "execute"
)

// kindActions is THE table mapping Crew's tool vocabulary onto the spec
// §5 normalized action taxonomy. It mirrors the `kiro-crew` rows in
// internal/tooltax/table.go (TestKiroCrewKindsMatchTooltax pins the two
// against each other), and an unlisted kind resolves to ActionUnknown
// with the raw kind preserved in RawToolName — never a guess.
//
// Crew's vocabulary is a LOSSY re-label of the kiro-cli tool names it
// drives: the same call logged as `name:"write"` in the kiro-cli store
// appears here as kind `edit`, for BOTH a file create and a str-replace.
// resolveTool recovers the create case from the `command` sub-arg, the
// same sub-arg branch kirocli's normalizeTool keeps for `fs_write`.
var kindActions = map[string]string{
	toolKindRead:    models.ActionReadFile,
	toolKindEdit:    models.ActionEditFile,
	toolKindExecute: models.ActionRunCommand,
}

// toolRecord is one logical tool call, merged from the 1..2 lines that
// carry its tool_call_id.
type toolRecord struct {
	id      string
	kind    string
	purpose string
	input   string
	output  string
	done    bool
	ts      time.Time
	order   int
	turn    int
}

// conversation is the fully decoded transcript: the metadata header plus
// the ordered, deduplicated records. Pure data — the adapter's emit
// decision (ownership) is applied on top of it, never inside it.
type conversation struct {
	meta     metaLine
	events   []convEvent
	warnings []string
}

// convEvent is one emitted-shaped record: a user prompt, an assistant
// message, or a merged tool call.
type convEvent struct {
	kind string // "user" | "assistant" | "tool"
	mid  string
	text string
	ts   time.Time
	turn int
	tool toolRecord
	// durationMs is the turn's measured wall clock, present only on the
	// assistant line that closed a user turn (meta.turn_stats.elapsed_ms).
	durationMs int64
	order      int
}

// parseConversation decodes a whole Crew chat transcript. It NEVER does
// I/O and never decides whether to emit — that is resolveOwnership's job
// — so it is directly testable against a fixture.
//
// The whole file is decoded on every call by design: line 1 is a MUTABLE
// metadata header (`title` is auto-derived after the first turn,
// `human_seen` / `last_consolidated` flip as the desktop UI is used), so
// its byte length changes during a session's life and a byte-offset tail
// would resume mid-line. Idempotence comes from deterministic,
// content-derived SourceEventIDs instead (the `mid` / `tool_call_id`
// values), exactly as internal/adapter/kirocli's flat bundle does.
func parseConversation(body []byte) conversation {
	var c conversation
	toolByID := map[string]int{}
	turn := -1
	order := 0
	// The header is the first NON-BLANK line, not line 0: a leading
	// blank (a stray newline, a torn write) would otherwise shift the
	// header into the turn-line branch, where it decodes as a role-less
	// turn and the whole session silently loses its project root, title
	// and model.
	headerSeen := false

	for i, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !headerSeen {
			headerSeen = true
			if err := json.Unmarshal([]byte(line), &c.meta); err != nil || c.meta.Type != "metadata" {
				c.warnings = append(c.warnings,
					"kiro-crew: first non-blank line is not a `_type:metadata` header; transcript not decoded")
				return conversation{warnings: c.warnings}
			}
			continue
		}
		var tl turnLine
		if err := json.Unmarshal([]byte(line), &tl); err != nil {
			c.warnings = append(c.warnings, "kiro-crew: malformed transcript line "+strconv.Itoa(i+1))
			continue
		}
		ts := parseCrewTime(tl.TS)
		switch tl.Role {
		case "user":
			turn++
			order++
			c.events = append(c.events, convEvent{
				kind: "user", mid: tl.Meta.MID, text: tl.Content, ts: ts,
				turn: max0(turn), order: order,
			})
		case "assistant":
			order++
			ev := convEvent{
				kind: "assistant", mid: tl.Meta.MID, text: tl.Content, ts: ts,
				turn: max0(turn), order: order,
			}
			if tl.Meta.TurnStats != nil {
				ev.durationMs = tl.Meta.TurnStats.ElapsedMS
			}
			c.events = append(c.events, ev)
		case "tool":
			id := tl.Meta.ToolCallID
			if id == "" {
				c.warnings = append(c.warnings, "kiro-crew: tool line "+strconv.Itoa(i+1)+" has no tool_call_id; skipped")
				continue
			}
			if at, seen := toolByID[id]; seen {
				mergeToolLines(&c.events[at].tool, tl.Meta)
				continue
			}
			order++
			rec := toolRecord{
				id: id, kind: tl.Meta.Kind, purpose: tl.Meta.Purpose,
				input: tl.Meta.Input, output: tl.Meta.Output,
				done: tl.Meta.Done, ts: ts, order: order, turn: max0(turn),
			}
			toolByID[id] = len(c.events)
			c.events = append(c.events, convEvent{kind: "tool", ts: ts, turn: max0(turn), tool: rec, order: order})
		default:
			c.warnings = append(c.warnings, "kiro-crew: unknown role "+tl.Role+" on line "+strconv.Itoa(i+1))
		}
	}
	return c
}

// mergeToolLines folds the COMPLETION half of a tool pair into the record
// created from its CALL half. Grounded merge rules, one per field:
//
//	kind    first non-empty — only the call half carries it
//	purpose first non-empty
//	input   prefer the JSON-VALID one — the call half of an edit carries a
//	        unified diff, the completion half the structured arguments
//	output  last non-empty — the call half may predate the result
//	done    latched true
//
// The call half's timestamp is kept (it is when the call STARTED).
func mergeToolLines(rec *toolRecord, m turnMeta) {
	if rec.kind == "" {
		rec.kind = m.Kind
	}
	if rec.purpose == "" {
		rec.purpose = m.Purpose
	}
	if m.Input != "" && !json.Valid([]byte(rec.input)) && json.Valid([]byte(m.Input)) {
		rec.input = m.Input
	} else if rec.input == "" {
		rec.input = m.Input
	}
	if m.Output != "" {
		rec.output = m.Output
	}
	rec.done = rec.done || m.Done
}

// resolveTool maps a merged tool record onto (action, target,
// contentBytes) via kindActions plus the ONE sub-arg branch Crew's lossy
// `edit` label needs. The raw kind always survives in RawToolName.
func resolveTool(rec toolRecord) (action, target string, contentBytes int64) {
	var a toolArgs
	if json.Valid([]byte(rec.input)) {
		_ = json.Unmarshal([]byte(rec.input), &a)
	}
	action, ok := kindActions[rec.kind]
	if !ok {
		return models.ActionUnknown, "", 0
	}
	switch rec.kind {
	case toolKindRead:
		if a.Path != "" {
			return action, a.Path, 0
		}
		if len(a.Operations) > 0 {
			return action, a.Operations[0].Path, 0
		}
		return action, "", 0
	case toolKindEdit:
		// Crew labels BOTH a file create and a str-replace `edit`; the
		// `command` sub-arg is what tells them apart (same branch
		// kirocli.normalizeTool keeps for `fs_write`).
		if a.Command == "create" {
			return models.ActionWriteFile, a.Path, int64(len(a.Content))
		}
		return action, a.Path, int64(len(a.NewStr))
	case toolKindExecute:
		return action, a.Command, 0
	}
	return action, "", 0
}

// resolveProjectRoot translates a foreign-OS project path (WSL2 reading
// /mnt/c, or a Windows observer reading \\wsl.localhost) BEFORE
// git.Resolve, so a `C:\…` drive string never reaches filepath.Abs where
// it would be treated as relative. Identical to kirocli's own helper.
func resolveProjectRoot(rawPath string) (root, branch, remote string) {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return "", "", ""
	}
	p = crossmount.TranslateForeignPath(p)
	info, err := git.Resolve(p)
	if err != nil {
		return p, "", ""
	}
	return info.Root, info.Branch, git.NormalizeRemote(info.Remote)
}

// parseCrewTime decodes a Crew timestamp
// ("2026-09-03T09:41:06.472819+00:00"). A blank or unparseable value
// yields the zero time rather than a fabricated one.
func parseCrewTime(s string) time.Time {
	if strings.TrimSpace(s) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
