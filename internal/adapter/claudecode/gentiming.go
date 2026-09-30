package claudecode

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Generation timing for claude-code transcript rows (S10-SPEED, agent
// migration 136). A Claude Code transcript writes one JSONL record per
// content block of an API message (same message.id), each stamped with the
// time that block was produced, interleaved with the user/attachment records
// that fed the request. The request's span is therefore
//
//	start = the input record the message's FIRST block responds to
//	        (its parentUuid - the latest tool_result / prompt / attachment
//	        written before the request was sent)
//	end   = the message's LAST block record
//
// Records Claude Code writes WITH the response are not request input and
// never a start: they are skipped on the way up (ccResponseSideAttachments,
// e.g. deferred_tools_record since 2026-09-26, stamped at the first block's
// own millisecond), and any start not strictly BEFORE the first block is
// rejected. Without that rule the span collapsed to first-block-to-last-block
// and showed 300-127,000 tok/s (lane BL4, 2026-09-27).
//
// Validated live (2026-09-23) on 336 messages of a proxy-routed session:
// never shorter than 0.8x the proxy's measured duration, median +0.47 s
// (client-side pre-send time), end within ~9 ms of the proxy's stream end.
// It includes time to first token, API retries and hook latency, so it can
// only UNDER-state throughput, never over-state it.
//
// Stamped ONLY when PROVEN, never guessed:
//   - FIRST block: walking the first visible block's parentUuid chain back
//     reaches an assistant record of a DIFFERENT message, a user prompt or
//     the chain root WITHOUT passing a block of the same message. Current
//     Claude Code streams tool execution INSIDE a message (tool_result
//     records sit between two blocks of one message.id), so "my parent is
//     an input" alone does not prove a block is the first one.
//   - COMPLETE: a later record of the same thread DESCENDS from the
//     message's last block and could only exist after the message ended -
//     the next API message's block, or a turn_duration / stop_hook_summary
//     system record. Without it the message may still be streaming and its
//     last visible block is not its end.
//
// The watcher parses incrementally, so the start record (or, for a message
// at the tail of the previous window, the whole message) often sits before
// fromOffset. When a chain leaves the window, one bounded look-back read
// (genLookbackBytes) supplies the missing records as CONTEXT ONLY - they
// emit nothing except the re-emitted TokenEvent of a message whose
// completion is proven by a record in THIS window. Anything still
// unresolvable stays unstamped (gen_ms NULL = "not measured").

// ccGenTimingV is this parser's gen-timing version (TokenEvent.GenTimingV):
// bump it when the span rule changes so a rescan re-derives stored spans.
//
// v2 (2026-09-27): response-side records are skipped and a start must be
// strictly before the first block (a v1 span could start at a record
// written with the response itself).
const ccGenTimingV = 2

// genLookbackBytes bounds the look-back per parse call. The look-back is
// read BACKWARDS in steps starting at genLookbackFirstBytes and doubling
// until every chain resolves (usually the first step: the missing record is
// the one just before fromOffset), so a live parse pays a few KiB, not
// 2 MiB.
const genLookbackBytes = 2 << 20

// genLookbackFirstBytes is the first look-back step (a var so the split
// replay test can force the doubling path on a small fixture).
var genLookbackFirstBytes int64 = 32 << 10

// genChainHops bounds every parentUuid walk.
const genChainHops = 256

type ccLineKind int

const (
	ccKindOther        ccLineKind = iota
	ccKindAssistant               // a content-block record of an API message
	ccKindInput                   // tool_result / attachment: request input, chain continues
	ccKindPrompt                  // a user prompt: request input AND a chain terminator
	ccKindTurnEnd                 // turn_duration / stop_hook_summary: completion evidence
	ccKindResponseSide            // written WITH the response: never a start, chain continues
)

// ccTimingLine is the minimal per-record projection the span rule needs.
type ccTimingLine struct {
	UUID      string
	Parent    string
	Kind      ccLineKind
	TS        time.Time
	MsgID     string
	Sidechain bool
	// InWindow is false for look-back context records.
	InWindow bool
}

// ccSystemTurnEnd is the table of system subtypes Claude Code writes only
// after the turn's last API message completed.
var ccSystemTurnEnd = map[string]bool{
	"turn_duration":     true,
	"stop_hook_summary": true,
}

// ccResponseSideAttachments is the table of attachment types Claude Code
// writes together with the response's first block (same millisecond, or
// just after it) rather than before the request was sent. They sit on the
// parentUuid chain between the request's real input and the first block, so
// taking one as the start would drop time to first token and most of the
// generation from the span. Grounded 2026-09-27: 765 of 765
// deferred_tools_record parents of a first block over 30 days of live
// transcripts were stamped within 1 ms of that block (first seen
// 2026-09-26); no other attachment type was within 50 ms of it.
var ccResponseSideAttachments = map[string]bool{
	"deferred_tools_record": true,
}

// rawAttachment is the light decode of an attachment record: its type only
// (bodies such as system-prompt snapshots and tool lists are skipped).
type rawAttachment struct {
	Type string `json:"type"`
}

// UnmarshalJSON tolerates an attachment value of any shape: a non-object
// leaves Type empty instead of failing the whole record's decode (the
// span rule is the only reader, and an unknown shape is plain input).
func (a *rawAttachment) UnmarshalJSON(b []byte) error {
	var v struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(b, &v) == nil {
		a.Type = v.Type
	}
	return nil
}

// timingMsg is the light decode of a record's message the span rule needs:
// the message id / model of an assistant block, and whether a user record's
// content blocks are tool_results. Content block bodies are skipped.
type timingMsg struct {
	ID      string          `json:"id"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
}

// classifyRecord projects one decoded record for the span rule.
func classifyRecord(line rawLine, inWindow bool) ccTimingLine {
	tl := ccTimingLine{
		UUID:      line.UUID,
		Parent:    line.ParentUuid,
		TS:        parseTimestamp(line.Timestamp),
		Sidechain: line.IsSidechain,
		InWindow:  inWindow,
	}
	var msg timingMsg
	if (line.Type == "assistant" || line.Type == "user") && len(line.Message) > 0 {
		_ = json.Unmarshal(line.Message, &msg)
	}
	switch line.Type {
	case "assistant":
		if msg.ID != "" && msg.Model != "<synthetic>" {
			tl.Kind, tl.MsgID = ccKindAssistant, msg.ID
		}
	case "attachment":
		tl.Kind = ccKindInput
		if line.Attachment != nil && ccResponseSideAttachments[line.Attachment.Type] {
			tl.Kind = ccKindResponseSide
		}
	case "user":
		tl.Kind = ccKindPrompt
		if contentHasToolResult(msg.Content) {
			tl.Kind = ccKindInput
		}
	case "system":
		if ccSystemTurnEnd[line.Subtype] {
			tl.Kind = ccKindTurnEnd
		}
	}
	return tl
}

// contentHasToolResult reports whether a user record's content is an array
// carrying a tool_result block (request input mid-turn) rather than a human
// prompt (a bare string or text blocks).
func contentHasToolResult(content json.RawMessage) bool {
	var blocks []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return false
	}
	for _, b := range blocks {
		if b.Type == "tool_result" {
			return true
		}
	}
	return false
}

// ccSpan is one proven request span.
type ccSpan struct {
	MsgID string
	Ms    int64
	// InWindow reports whether any block of the message is in this window;
	// false means the message must be re-emitted from look-back context.
	InWindow bool
}

// ccGenSpans applies the span rule to records in file order. It returns the
// proven spans whose completion evidence lies in THIS window, and whether
// some chain walk left the known records (the caller may then retry with
// look-back context).
func ccGenSpans(lines []ccTimingLine) (spans []ccSpan, incomplete bool) {
	byUUID := make(map[string]int, len(lines))
	children := make(map[string][]int, len(lines))
	var order []string
	blocks := map[string][]int{}
	for i, l := range lines {
		if l.UUID != "" {
			byUUID[l.UUID] = i
		}
		if l.Parent != "" {
			children[l.Parent] = append(children[l.Parent], i)
		}
		if l.Kind == ccKindAssistant {
			if _, ok := blocks[l.MsgID]; !ok {
				order = append(order, l.MsgID)
			}
			blocks[l.MsgID] = append(blocks[l.MsgID], i)
		}
	}
	for _, id := range order {
		idx := blocks[id]
		first, last := idx[0], idx[len(idx)-1]
		evidence, ok := completionEvidence(lines, children, id, last)
		if !ok || !lines[evidence].InWindow {
			continue
		}
		start, proven, missing := firstBlockStart(lines, byUUID, id, first)
		if missing {
			incomplete = true
		}
		if !proven {
			continue
		}
		end := lines[last].TS
		// Both ends must bracket the first block: a start written at or
		// after the first output record (a clock step, a re-stamped record,
		// a response-side record the table does not know yet) or an end
		// before it is not a span of this request - a request cannot return
		// its first block in the millisecond it was sent.
		if start.IsZero() || end.IsZero() || end.Before(lines[first].TS) || !start.Before(lines[first].TS) {
			continue
		}
		ms := end.Sub(start).Milliseconds()
		if ms <= 0 {
			continue
		}
		inWindow := false
		for _, j := range idx {
			if lines[j].InWindow {
				inWindow = true
				break
			}
		}
		spans = append(spans, ccSpan{MsgID: id, Ms: ms, InWindow: inWindow})
	}
	// An in-window evidence-kind record (an assistant block or a turn-end
	// record) may complete a message written BEFORE the known records:
	// walk its ancestry back to the message it could complete (the first
	// assistant block of a different message), a prompt or the chain root.
	// Leaving the known records first means that message is out of sight -
	// read further back. A tool_result-only window never qualifies.
	if !incomplete {
		for _, l := range lines {
			if l.InWindow && (l.Kind == ccKindAssistant || l.Kind == ccKindTurnEnd) && ancestryLeaves(lines, byUUID, l) {
				incomplete = true
				break
			}
		}
	}
	return spans, incomplete
}

// firstBlockStart walks back from the earliest visible block of message id.
// It returns the request start (the block's direct parent's timestamp) and
// proven=true only when the walk reaches a terminator without meeting
// another block of the same message. missing reports that the walk left the
// known records.
func firstBlockStart(lines []ccTimingLine, byUUID map[string]int, id string, first int) (start time.Time, proven, missing bool) {
	parent, ok := byUUID[lines[first].Parent]
	if lines[first].Parent == "" || !ok {
		return time.Time{}, false, lines[first].Parent != ""
	}
	// Records written WITH the response are not the request's input: step
	// over them to the record the request actually answered.
	for hop := 0; lines[parent].Kind == ccKindResponseSide; hop++ {
		up := lines[parent].Parent
		if up == "" || hop >= genChainHops {
			return time.Time{}, false, false
		}
		next, ok := byUUID[up]
		if !ok {
			return time.Time{}, false, true
		}
		parent = next
	}
	p := lines[parent]
	if p.Kind != ccKindInput && p.Kind != ccKindPrompt {
		// Not provable from THIS block - but when the known records are a
		// look-back slice, this may not be the message's first block at
		// all: report missing when the chain leaves the known records
		// before meeting an earlier block of the same message, so the
		// caller reads further back (found live: a progress record between
		// two blocks, the first block 40 KiB before the window).
		return time.Time{}, false, chainLeaves(lines, byUUID, id, parent)
	}
	start = p.TS
	cur := parent
	for hop := 0; hop < genChainHops; hop++ {
		l := lines[cur]
		switch {
		case l.Kind == ccKindAssistant && l.MsgID == id:
			return time.Time{}, false, false // an earlier block of this message
		case l.Kind == ccKindAssistant, l.Kind == ccKindPrompt:
			return start, true, false
		}
		if l.Parent == "" {
			return start, true, false // chain root
		}
		next, ok := byUUID[l.Parent]
		if !ok {
			return time.Time{}, false, true
		}
		cur = next
	}
	return time.Time{}, false, false
}

// ancestryLeaves reports whether the parentUuid chain above evidence-kind
// record ev leaves the known records before reaching an assistant block of
// ANOTHER message, a prompt, or the chain root.
func ancestryLeaves(lines []ccTimingLine, byUUID map[string]int, ev ccTimingLine) bool {
	parent := ev.Parent
	for hop := 0; hop < genChainHops; hop++ {
		if parent == "" {
			return false
		}
		idx, ok := byUUID[parent]
		if !ok {
			return true
		}
		l := lines[idx]
		if l.Kind == ccKindPrompt || (l.Kind == ccKindAssistant && l.MsgID != ev.MsgID) {
			return false
		}
		parent = l.Parent
	}
	return false
}

// chainLeaves reports whether walking the parentUuid chain back from cur
// leaves the known records before meeting a block of message id or the
// chain root.
func chainLeaves(lines []ccTimingLine, byUUID map[string]int, id string, cur int) bool {
	for hop := 0; hop < genChainHops; hop++ {
		l := lines[cur]
		if l.Kind == ccKindAssistant && l.MsgID == id {
			return false
		}
		if l.Parent == "" {
			return false
		}
		next, ok := byUUID[l.Parent]
		if !ok {
			return true
		}
		cur = next
	}
	return false
}

// completionEvidence finds a record that descends from block `last` of
// message id and proves the message ended: a block of a different message
// in the same thread, or a turn-end system record. Breadth-first over the
// children index, bounded.
func completionEvidence(lines []ccTimingLine, children map[string][]int, id string, last int) (int, bool) {
	queue := []int{last}
	for hop := 0; len(queue) > 0 && hop < genChainHops; hop++ {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range children[lines[cur].UUID] {
			l := lines[c]
			if l.Sidechain != lines[last].Sidechain {
				continue
			}
			switch {
			case l.Kind == ccKindAssistant && l.MsgID != id:
				return c, true
			case l.Kind == ccKindTurnEnd:
				return c, true
			}
			queue = append(queue, c)
		}
	}
	return 0, false
}

// readGenLookback reads up to size bytes before fromOffset and returns its
// complete records as look-back context, plus the highest-output record of
// each assistant message (for re-emission). atStart reports that the read
// reached the start of the file (a larger step cannot add records).
func readGenLookback(path string, fromOffset, size int64) (lines []ccTimingLine, msgs map[string]ccLookbackMsg, atStart bool) {
	start := fromOffset - size
	if start < 0 {
		start = 0
	}
	atStart = start == 0
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, true
	}
	defer f.Close()
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, nil, true
	}
	buf := make([]byte, fromOffset-start)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, nil, true
	}
	text := string(buf)
	if start > 0 {
		// The first record is probably cut: skip to the first full line.
		nl := strings.IndexByte(text, '\n')
		if nl < 0 {
			return nil, nil, atStart
		}
		text = text[nl+1:]
	}
	msgs = map[string]ccLookbackMsg{}
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" {
			continue
		}
		var line rawLine
		if json.Unmarshal([]byte(raw), &line) != nil {
			continue
		}
		// Only an assistant record can be re-emitted; skip the full
		// message decode (content bodies) for every other record.
		var msg *rawMessage
		if line.Type == "assistant" && len(line.Message) > 0 {
			var m rawMessage
			if json.Unmarshal(line.Message, &m) == nil {
				msg = &m
			}
		}
		lines = append(lines, classifyRecord(line, false))
		if line.Type == "assistant" && msg != nil && msg.ID != "" && msg.Usage != nil && msg.Model != "<synthetic>" {
			if prev, ok := msgs[msg.ID]; !ok || msg.Usage.OutputTokens >= prev.msg.Usage.OutputTokens {
				msgs[msg.ID] = ccLookbackMsg{line: line, msg: *msg}
			}
		}
	}
	return lines, msgs, atStart
}

// ccLookbackMsg is a look-back message's highest-output record.
type ccLookbackMsg struct {
	line rawLine
	msg  rawMessage
}

// applyGenTiming stamps proven spans onto res.TokenEvents (by message id)
// and re-emits the previous window's tail message when its completion is
// proven here. resolveRoot resolves (projectRoot, projectRemote) for a cwd.
func applyGenTiming(path string, fromOffset int64, window []ccTimingLine, events []models.TokenEvent, msgIDToIdx map[string]int, resolveRoot func(cwd string) (string, string)) []models.TokenEvent {
	spans, incomplete := ccGenSpans(window)
	var lookMsgs map[string]ccLookbackMsg
	if incomplete && fromOffset > 0 {
		for size := genLookbackFirstBytes; ; size *= 2 {
			if size > genLookbackBytes {
				size = genLookbackBytes
			}
			ctxLines, msgs, atStart := readGenLookback(path, fromOffset, size)
			more := true
			if len(ctxLines) > 0 {
				spans, more = ccGenSpans(append(ctxLines, window...))
				lookMsgs = msgs
			}
			if !more || atStart || size >= genLookbackBytes {
				break
			}
		}
	}
	for _, sp := range spans {
		if idx, ok := msgIDToIdx[sp.MsgID]; ok {
			stampGen(&events[idx], sp.Ms)
			continue
		}
		if sp.InWindow {
			continue
		}
		lm, ok := lookMsgs[sp.MsgID]
		if !ok || lm.msg.Usage == nil {
			continue
		}
		root, remote := resolveRoot(lm.line.Cwd)
		ev := tokenEventFromLine(path, lm.line, lm.msg, parseTimestamp(lm.line.Timestamp), root, remote)
		stampGen(&ev, sp.Ms)
		// The row was inserted by an earlier parse: stamp it, never
		// re-insert it (store.stampGenTiming).
		ev.GenStampOnly = true
		events = append(events, ev)
	}
	return events
}

func stampGen(ev *models.TokenEvent, ms int64) {
	ev.GenMs, ev.GenBasis, ev.GenTimingV = ms, models.GenBasisTranscript, ccGenTimingV
}
