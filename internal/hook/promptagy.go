package hook

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// Antigravity CLI (`agy`) PreInvocation: the pre-model-call prompt seam
// (audit proposal P1, operator ruling 2026-10-02; guard-enforcement fix
// 2026-10-15).
//
// Grounding (antigravity.google/docs/hooks, fetched 2026-10-02, and a
// lead-verified live probe of agy 1.3.5 on demo node 1, 2026-10-15): agy's
// hooks are SessionStart / PreToolUse / PostToolUse / PreInvocation /
// PostInvocation / Stop. None receives the user's prompt text.
// PreInvocation runs before every model invocation; its stdin carries
// conversationId, transcriptPath (<app_data_dir>/brain/<conversationId>/
// .system_generated/logs/transcript_full.jsonl), invocationNum and more,
// and its output is `injectSteps`. Live on 1.3.5:
//
//   - a `userMessage` step is shown to the DEVELOPER as a "> ..." line (it
//     also becomes a user turn), so a flag warns the developer in band;
//   - an empty step `{}` aborts the turn before the main model request
//     (an undocumented error path), so a stop blocks the model call, with
//     no message (the toast carries the reason, PromptSeamCaps.BlockSilent);
//   - any other bad output fails OPEN.
//
// Two limits are recorded, never hidden: agy's title-generation request
// carrying the prompt is sent BEFORE any hook (only the proxy can stop it),
// so this is a pre-model-call block, not a pre-send one; and a stopped
// prompt stays in the conversation and is resent with every later turn, so
// the dialect taints the conversation (promptDialect.taintsSession) and
// stops every later turn of it with a toast to start a new conversation.
// The abort is offered only to an agy whose version is proven to honour
// it (agyPreInvocationCaps); otherwise the seam warns.
//
// Transcript shape (live-grounded on demo node 1, agy session
// b9cba337, 2026-10-02): one JSON object per line; the user's prompt is
// {"type":"USER_INPUT","source":"USER_EXPLICIT","content":
// "<USER_REQUEST>\n...\n</USER_REQUEST>", ...}.

// agyTranscriptTailBytes bounds how much of a long transcript the hook
// reads: only the tail, where the latest user input is.
const agyTranscriptTailBytes = 4 << 20

// agyTranscriptNames are the transcript file names agy has pointed
// PreInvocation's transcriptPath at: transcript.jsonl (agy 1.2.16, demo node
// 1, 2026-10-03) and transcript_full.jsonl (agy 1.3.0, demo node 1,
// 2026-10-06, T-476: the USER_INPUT step is already in it at invocationNum
// 0, before the first model call). Any other file name is not read.
var agyTranscriptNames = map[string]bool{
	"transcript.jsonl":      true,
	"transcript_full.jsonl": true,
}

type agyPreInvocationPayload struct {
	ConversationID string `json:"conversationId"`
	TranscriptPath string `json:"transcriptPath"`
}

type agyTranscriptStep struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// extractAntigravityPreInvocationPrompt reads the latest user input from
// the transcript the payload points at. A payload without a readable
// transcript (none yet, or not a known transcript file) returns ok=false: the
// caller replies without scanning, and the post-hoc capture lane still
// covers the prompt. Firing the FIX-2 "schema drift" degrade here would
// warn on every model invocation of every turn.
func extractAntigravityPreInvocationPrompt(body []byte) (prompt, sessionID string, ok, fieldMissing bool) {
	var p agyPreInvocationPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", false, false
	}
	text, found := latestAgyUserInput(p.TranscriptPath)
	if !found {
		return "", p.ConversationID, false, false
	}
	return text, p.ConversationID, true, false
}

// latestAgyUserInput returns the content of the last USER_INPUT step in
// an agy transcript, without its <USER_REQUEST> wrapper. Only a file named
// in agyTranscriptNames is read, and only its tail.
func latestAgyUserInput(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		path = filepath.Join(home, path[2:])
	}
	if !agyTranscriptNames[filepath.Base(path)] {
		return "", false
	}
	// A payload-named path: read through the hook context seam
	// (internal/hookctx): the host default is os.Open, the relay path the run's confined reader.
	f, err := hookctx.Process().Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > agyTranscriptTailBytes {
		if _, err := f.Seek(st.Size()-agyTranscriptTailBytes, io.SeekStart); err != nil {
			return "", false
		}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), agyTranscriptTailBytes)
	latest, found := "", false
	for sc.Scan() {
		line := sc.Bytes()
		if !strings.Contains(string(line), `"USER_INPUT"`) {
			continue
		}
		var step agyTranscriptStep
		if err := json.Unmarshal(line, &step); err != nil || step.Type != "USER_INPUT" {
			continue
		}
		latest, found = unwrapAgyUserRequest(step.Content), true
	}
	return latest, found
}

// unwrapAgyUserRequest strips agy's <USER_REQUEST> wrapper.
func unwrapAgyUserRequest(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<USER_REQUEST>")
	s = strings.TrimSuffix(s, "</USER_REQUEST>")
	return strings.TrimSpace(s)
}

// agyInjectStep / agyPreInvocationReply are PreInvocation's output:
// {"injectSteps":[{"userMessage": "..."}, {"ephemeralMessage": "..."}]}.
// Each step names one step type by its one key (agy 1.3.5, live
// 2026-10-15): userMessage is shown to the DEVELOPER in the TUI as a
// "> ..." user line and also becomes a user turn for the model;
// ephemeralMessage is a transient message for the model only. A step with
// NO key is an unknown step type: agy aborts the turn with "agent executor
// error: pre-invocation hook: failed to inject steps ... unknown injected
// step type" BEFORE the main model request (-p exits 3; the TUI shows a
// warning line and the session survives). That undocumented error path is
// the block.
type agyInjectStep struct {
	UserMessage      string `json:"userMessage,omitempty"`
	EphemeralMessage string `json:"ephemeralMessage,omitempty"`
}

type agyPreInvocationReply struct {
	InjectSteps []agyInjectStep `json:"injectSteps,omitempty"`
}

// promptAgyAbortOrWarns is the PreInvocation seam's honest capability set:
// a developer-visible warning (userMessage) and a block (the abort) that
// carries no message, so the toast is the developer's only signal for it
// (BlockSilent). No confirm and no resend-to-confirm: the abort is atomic
// and the stopped prompt stays in the conversation, so an ask resolves
// down promptaction.go's ask ladder to block. The block is pre-model-call,
// not pre-send: agy's title request carrying the prompt goes out before
// any hook.
var promptAgyAbortOrWarns = guard.PromptSeamCaps{Warn: true, Block: true, BlockSilent: true}

// agyPreInvocationCaps withdraws the block when the agy running this hook
// is not a version proven to abort on the empty step (agyhost.go): the
// seam then warns, and the verdict records the degrade instead of claiming
// a block that agy would not honour.
func agyPreInvocationCaps(c guard.PromptSeamCaps) guard.PromptSeamCaps {
	if c.Block && !agyAbortProbe() {
		c.Block, c.BlockSilent = false, false
	}
	return c
}

// agyNoticePrefix opens the developer-visible notice line.
const agyNoticePrefix = "SuperBased Observer: "

// buildAntigravityPreInvocationReply renders one PreInvocation outcome: a
// block is the abort ({"injectSteps":[{}]}); a warning is a userMessage the
// developer sees plus an ephemeralMessage that asks the model not to use
// the flagged value; anything else is the empty allow. The texts name
// detector types only, never the value.
func buildAntigravityPreInvocationReply(out promptReplyOutcome) any {
	switch {
	case out.Blocking:
		return agyPreInvocationReply{InjectSteps: []agyInjectStep{{}}}
	case out.Warn:
		notice := strings.TrimPrefix(out.Reason, "observer: ")
		model := "SuperBased Observer guard notice for the user: " + out.Reason +
			" The user has been shown this notice. Do not repeat, store, or use the flagged value."
		return agyPreInvocationReply{InjectSteps: []agyInjectStep{
			{UserMessage: agyNoticePrefix + notice},
			{EphemeralMessage: model},
		}}
	default:
		return agyPreInvocationReply{}
	}
}
