package kirocli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// flatState is the `<uuid>.json` session-state envelope. Both observed
// shapes decode into it: the finished shape (user_turn_metadatas
// populated) and the live/killed shape (user_turn_metadatas absent →
// nil slice, no token events).
type flatState struct {
	SessionID    string           `json:"session_id"`
	CWD          string           `json:"cwd"`
	CreatedAt    string           `json:"created_at"`
	UpdatedAt    string           `json:"updated_at"`
	Title        string           `json:"title"`
	SessionState flatSessionState `json:"session_state"`
}

type flatSessionState struct {
	ConversationMetadata flatConvMeta `json:"conversation_metadata"`
	RTSModelState        flatRTSModel `json:"rts_model_state"`
	// AgentName is the kiro-cli agent profile that drove the session.
	// Grounded 2026-09-03 across five live sessions: "kiro_default" for
	// a plain terminal run, "kirocrew" when AWS's Kiro Crew desktop app
	// orchestrated the run, and null on one older session. It is the
	// SURFACE discriminator — see agentSurfaces.
	AgentName string `json:"agent_name"`
}

type flatRTSModel struct {
	ModelInfo struct {
		ModelID string `json:"model_id"`
	} `json:"model_info"`
}

type flatConvMeta struct {
	UserTurnMetadatas []flatTurnMeta `json:"user_turn_metadatas"`
}

type flatTurnMeta struct {
	MessageIDs             []string       `json:"message_ids"`
	InputTokenCount        int64          `json:"input_token_count"`
	OutputTokenCount       int64          `json:"output_token_count"`
	ContextUsagePercentage float64        `json:"context_usage_percentage"`
	MeteringUsage          []flatMetering `json:"metering_usage"`
	EndReason              string         `json:"end_reason"`
	EndTimestamp           string         `json:"end_timestamp"`
}

type flatMetering struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
}

// flatStreamLine is one line of the `<uuid>.jsonl` message stream.
type flatStreamLine struct {
	Version string        `json:"version"`
	Kind    string        `json:"kind"`
	Data    flatStreamMsg `json:"data"`
}

type flatStreamMsg struct {
	MessageID string            `json:"message_id"`
	Content   []flatStreamBlock `json:"content"`
	Meta      struct {
		Timestamp int64 `json:"timestamp"`
	} `json:"meta"`
}

// flatStreamBlock is one content block of a stream message.
//
// `data` is POLYMORPHIC: a plain string for `kind:"text"`, and an OBJECT
// for every other kind (`thinking` {text,signature,redactedContent,
// modelId}, `toolUse` {toolUseId,name,input}, `toolResult`
// {toolUseId,content,status}). It was typed `string` until 2026-09-03,
// which made json.Unmarshal fail for the WHOLE LINE the moment a session
// carried anything but text — so a real interactive session captured only
// its first pure-text Prompt and warned "malformed stream line" for every
// assistant turn. Grounded on the live Kiro Crew step-in capture; see
// testdata/kirocrew/kiro-cli/.
type flatStreamBlock struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// flatToolUse is the decoded `data` of a `toolUse` block.
type flatToolUse struct {
	ToolUseID string          `json:"toolUseId"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
}

// flatToolResult is the decoded `data` of a `toolResult` block. `content`
// is a nested block list of the same polymorphic shape.
type flatToolResult struct {
	ToolUseID string            `json:"toolUseId"`
	Content   []flatStreamBlock `json:"content"`
	Status    string            `json:"status"`
}

// parseFlatBundle parses an interactive flat-file session bundle. Both
// the `.json` and `.jsonl` triggers route here; events are always
// emitted under the canonical `.jsonl` SourceFile so the store's
// (source_file, source_event_id) dedup drops the cross-trigger
// duplicates. NewOffset is the size of the TRIGGERING file so each
// per-path parse cursor advances on its own file's growth; the parse
// itself is idempotent (deterministic, content-derived SourceEventIDs)
// so a full re-read every tick is safe.
func (a *Adapter) parseFlatBundle(ctx context.Context, trigger string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if fi, err := os.Stat(trigger); err == nil {
		res.NewOffset = fi.Size()
	}

	jsonlPath, jsonPath, sessionID := bundlePaths(trigger)

	// Read the sibling `.json` state (best-effort — a live session's
	// stream may exist before the state flush). The canonical session id
	// is the FILENAME uuid (kiro names the bundle <session_id>.json), so
	// the embedded session_id is NOT allowed to override it (§4.5a — a
	// re-keyed id orphans rows). In practice they are always equal.
	state, turnByMsg := readFlatState(jsonPath)
	projectRoot, gitBranch, gitRemote, projectIdentity := resolveProjectRoot(state.CWD)
	model := state.SessionState.RTSModelState.ModelInfo.ModelID

	body, err := os.ReadFile(jsonlPath) //nolint:gosec // jsonlPath derives from a validated watch-root trigger
	if err != nil {
		if os.IsNotExist(err) {
			// The `.json` may fire before the `.jsonl` lands; nothing to
			// emit yet.
			return res, nil
		}
		return res, nil
	}

	// Surface stamp. The layout says a flat bundle was written; the
	// bundle's own `session_state.agent_name` says WHO drove it, and a
	// Crew-orchestrated run is a desktop surface, not a terminal one
	// (see agentSurfaces — the kiro-cli half of the kiro-crew
	// double-count rule).
	res.SessionSurfaces = append(res.SessionSurfaces,
		surfaceForAgent(layoutFlat, sessionID, state.SessionState.AgentName))

	turnIndex := -1
	// results accumulates every ToolResults record seen in this pass; the
	// correlation onto action rows happens after the scan.
	results := map[string]flatToolResult{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var sl flatStreamLine
		if err := json.Unmarshal([]byte(line), &sl); err != nil {
			warnf(&res, "kirocli: flat bundle %s: malformed stream line: %v", sessionID, err)
			continue
		}
		switch sl.Kind {
		case "Prompt":
			turnIndex++
			ts := unixSeconds(sl.Data.Meta.Timestamp)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    jsonlPath,
				SourceEventID: sl.Data.MessageID + ":prompt",
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitBranch:     gitBranch,
				GitRemote:     gitRemote,
				Timestamp:     ts,
				TurnIndex:     max0(turnIndex),
				Model:         model,
				Tool:          models.ToolKiroCLI,
				ActionType:    models.ActionUserPrompt,
				Target:        a.scrubber.String(flatText(sl.Data.Content)),
				Success:       true,
				MessageID:     sl.Data.MessageID,
			})
		case "AssistantMessage":
			text := flatText(sl.Data.Content)
			meta, hasMeta := turnByMsg[sl.Data.MessageID]
			ts := time.Time{}
			if hasMeta {
				ts = parseRFC3339(meta.EndTimestamp)
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    jsonlPath,
				SourceEventID: sl.Data.MessageID + ":assistant",
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitBranch:     gitBranch,
				GitRemote:     gitRemote,
				Timestamp:     ts,
				TurnIndex:     max0(turnIndex),
				Model:         model,
				Tool:          models.ToolKiroCLI,
				ActionType:    models.ActionAssistantMessage,
				Target:        a.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes)),
				Success:       true,
				MessageID:     sl.Data.MessageID,
			})
			// Token event — emitted only when the turn accounting block
			// exists for this assistant message. The counts are honest
			// (0 when kiro reported 0); no proxy tier is possible
			// (SigV4). Credits are NOT tokens and are deliberately
			// dropped. Reliability is "unreliable": the local counts
			// were observed structurally zero.
			if hasMeta {
				res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
					SourceFile:    jsonlPath,
					SourceEventID: sl.Data.MessageID + ":tok",
					SessionID:     sessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     gitBranch,
					GitRemote:     gitRemote,
					Timestamp:     ts,
					Tool:          models.ToolKiroCLI,
					Model:         model,
					InputTokens:   meta.InputTokenCount,
					OutputTokens:  meta.OutputTokenCount,
					Source:        "jsonl",
					Reliability:   "unreliable",
					MessageID:     sl.Data.MessageID,
				})
			}
			// Tool calls ride INSIDE the assistant message as `toolUse`
			// blocks (grounded 2026-09-03 — the package doc's older claim
			// that interactive streams carry no tool uses was measured on
			// a text-only session). Each becomes its own action row,
			// optimistically successful until the paired ToolResults
			// record lands (see the correlation pass below).
			for _, tu := range flatToolUses(sl.Data.Content) {
				action, target, contentBytes := normalizeTool(tu.Name, tu.Input)
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile:    jsonlPath,
					SourceEventID: tu.ToolUseID,
					SessionID:     sessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     gitBranch,
					GitRemote:     gitRemote,
					Timestamp:     ts,
					TurnIndex:     max0(turnIndex),
					Model:         model,
					Tool:          models.ToolKiroCLI,
					ActionType:    action,
					Target:        a.scrubber.String(contentcap.Cap(target, contentcap.DefaultMaxBytes)),
					RawToolName:   tu.Name,
					RawToolInput:  a.scrubber.String(contentcap.Cap(string(tu.Input), contentcap.DefaultMaxBytes)),
					ContentBytes:  contentBytes,
					Success:       true,
					// Flipped by the correlation pass when the paired
					// ToolResults record is in this same window — which,
					// because the bundle is re-read whole every tick, it
					// always is once kiro has written it.
					OutcomePending: true,
					MessageID:      sl.Data.MessageID,
				})
			}
		case "ToolResults":
			for id, tr := range flatToolResults(sl.Data.Content) {
				results[id] = tr
			}
		default:
			warnf(&res, "kirocli: flat bundle %s: unknown stream kind %q", sessionID, sl.Kind)
		}
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)

	applyFlatToolResults(&res, a.scrubber, results)
	return res, nil
}

// applyFlatToolResults folds each ToolResults record onto the action row
// its toolUseId created. Correlation is IN-WINDOW by construction: the
// bundle is re-read whole on every parse, so a result that exists on disk
// is always seen in the same pass as its call.
//
// `status` is kiro's own verdict ("success" observed live; anything else
// is treated as a failure rather than guessing the failure vocabulary).
func applyFlatToolResults(res *adapter.ParseResult, s *scrub.Scrubber, results map[string]flatToolResult) {
	if len(results) == 0 {
		return
	}
	for i := range res.ToolEvents {
		tr, ok := results[res.ToolEvents[i].SourceEventID]
		if !ok {
			continue
		}
		e := &res.ToolEvents[i]
		out, exitStatus := resultText(tr.Content)
		e.OutcomePending = false
		e.ToolOutput = s.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		switch {
		case tr.Status != "" && !strings.EqualFold(tr.Status, "success"):
			e.Success = false
			e.ErrorMessage = "kiro tool result status: " + tr.Status
		case exitStatus != "" && exitStatus != zeroExitStatus:
			// The tool RAN but the command failed. Kiro still reports
			// status="success" here, so the exit status is the only
			// honest outcome signal.
			e.Success = false
			e.ErrorMessage = "kiro shell " + exitStatus
		default:
			e.Success = true
		}
	}
}

// readFlatState reads and decodes the `.json` sibling, returning the
// state plus a map from every message id in a turn's message_ids to
// that turn's accounting block. Best-effort: a missing/malformed file
// yields a zero state and a nil map (no token events).
func readFlatState(jsonPath string) (flatState, map[string]flatTurnMeta) {
	var state flatState
	body, err := os.ReadFile(jsonPath) //nolint:gosec // jsonPath derives from a validated watch-root trigger
	if err != nil {
		return state, nil
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return flatState{}, nil
	}
	turns := state.SessionState.ConversationMetadata.UserTurnMetadatas
	if len(turns) == 0 {
		return state, nil
	}
	byMsg := make(map[string]flatTurnMeta, len(turns)*2)
	for _, t := range turns {
		for _, id := range t.MessageIDs {
			byMsg[id] = t
		}
	}
	return state, byMsg
}

// flatText joins the text blocks of a stream message. Only `kind:"text"`
// carries a JSON string; every other block's `data` is an object and is
// skipped (a `thinking` block's inner text is reasoning, not output, and
// is deliberately not folded into the assistant message).
func flatText(blocks []flatStreamBlock) string {
	var sb strings.Builder
	for _, b := range blocks {
		if b.Kind != "text" {
			continue
		}
		var s string
		if json.Unmarshal(b.Data, &s) == nil {
			sb.WriteString(s)
		}
	}
	return sb.String()
}

// flatToolUses decodes the `toolUse` blocks of an assistant message.
func flatToolUses(blocks []flatStreamBlock) []flatToolUse {
	var out []flatToolUse
	for _, b := range blocks {
		if b.Kind != "toolUse" {
			continue
		}
		var tu flatToolUse
		if json.Unmarshal(b.Data, &tu) == nil && tu.ToolUseID != "" {
			out = append(out, tu)
		}
	}
	return out
}

// flatShellResult is the `json` result block a shell tool returns. Kiro
// reports the toolResult `status` as "success" whenever the tool RAN, so
// a non-zero exit code is only visible here — grounded 2026-09-03, where
// `del hello.py && dir /b` came back status="success" with
// exit_status="exit code: 1" and a PowerShell parser error on stderr.
// Reading `status` alone would file that as a successful command.
type flatShellResult struct {
	ExitStatus string `json:"exit_status"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

// zeroExitStatus is the exact `exit_status` spelling kiro emits for a
// successful command. Anything else is treated as a failure — the
// conservative direction, and the vocabulary is not otherwise documented.
const zeroExitStatus = "exit code: 0"

// resultText renders a toolResult's content blocks into the action's
// ToolOutput, and reports the shell exit status when one is present.
//
// Two block shapes are grounded: `text` (file tools — "Successfully
// created …", a directory listing) and `json` (shell tools —
// {exit_status, stdout, stderr}). A `json` block is rendered as its
// stdout followed by its stderr so the operator sees what the command
// actually printed, not a JSON envelope.
func resultText(blocks []flatStreamBlock) (out, exitStatus string) {
	var sb strings.Builder
	for _, b := range blocks {
		switch b.Kind {
		case "text":
			var s string
			if json.Unmarshal(b.Data, &s) == nil {
				sb.WriteString(s)
			}
		case "json":
			var sr flatShellResult
			if json.Unmarshal(b.Data, &sr) != nil {
				continue
			}
			if sr.ExitStatus != "" {
				exitStatus = sr.ExitStatus
			}
			sb.WriteString(sr.Stdout)
			sb.WriteString(sr.Stderr)
		}
	}
	return sb.String(), exitStatus
}

// flatToolResults decodes the `toolResult` blocks of a ToolResults
// message into (toolUseId → result).
func flatToolResults(blocks []flatStreamBlock) map[string]flatToolResult {
	out := map[string]flatToolResult{}
	for _, b := range blocks {
		if b.Kind != "toolResult" {
			continue
		}
		var tr flatToolResult
		if json.Unmarshal(b.Data, &tr) == nil && tr.ToolUseID != "" {
			out[tr.ToolUseID] = tr
		}
	}
	return out
}

func unixSeconds(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

func parseRFC3339(s string) time.Time {
	if s == "" {
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
