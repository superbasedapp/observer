package codex

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Generation timing for codex rollout rows (S10-SPEED, agent migration
// 136). A current codex rollout writes, per model inference:
//
//	input records   (user / developer message, *_call_output, world_state,
//	                 turn_context, event_msg user_message / task_started)
//	output records  (reasoning, assistant message, function_call,
//	                 custom_tool_call, web_search_call, local_shell_call)
//	token_usage_record  {response_id, usage}   <- the inference ended here
//	... tool execution, its *_call_output records (the NEXT inference's input)
//	event_msg token_count {last_token_usage}   <- what the adapter emits
//
// The token_count is written AFTER tool execution, so its timestamp is NOT
// the inference end; the token_usage_record is. The span is
//
//	start = the latest input record before the inference's first output
//	end   = the inference's token_usage_record
//
// and it is stamped on the token_count's TokenEvent ONLY when PROVEN:
//   - the token_count's last_token_usage equals the nearest preceding
//     token_usage_record's usage on all four counters (the binding);
//   - walking back from that record passes only output / neutral records
//     (at least one output) before reaching an input - meeting another
//     token_usage_record first means the start is not provable. A
//     token_count is NEUTRAL in this walk: codex writes the previous
//     inference's token_count AFTER the tool output that is this
//     inference's input (live 0.154 rollouts, 2026-09-22).
//
// Rollouts without token_usage_record (older codex builds) are never
// stamped: their token_count timestamp includes tool execution. When the
// walk leaves the parse window, a bounded backward look-back supplies
// context records (they emit nothing). The span includes time to first token and
// any client-side retry, so it can only UNDER-state throughput.

// codexGenTimingV is this parser's gen-timing version (TokenEvent.
// GenTimingV): bump it when the span rule changes.
const codexGenTimingV = 1

// codexGenLookbackBytes bounds the look-back per parse call. It is read
// BACKWARDS from codexGenLookbackFirstBytes, doubling until every walk
// resolves - and abandoned once codexGenProbeBytes of look-back hold no
// token_usage_record (nor does the window) (an older codex build, or
// open-interpreter's desktop codex-home, never stamps: no futile 2 MiB
// read on every parse).
const codexGenLookbackBytes = 2 << 20

// codexGenProbeBytes is how far back the look-back must have read, finding
// no token_usage_record anywhere, before it concludes the rollout's build
// never writes one. It is larger than the first step because one tool
// output (written between an inference's usage record and its token_count)
// can itself be tens of KiB.
const codexGenProbeBytes = 256 << 10

// codexGenLookbackFirstBytes is the first step (a var so the split replay
// test can force the doubling path on a small fixture).
var codexGenLookbackFirstBytes int64 = 64 << 10

type codexTimingKind int

const (
	cxNeutral codexTimingKind = iota
	cxInput
	cxOutput
	cxUsageRecord
	cxTokenCount
	// cxUnknown is a record whose kind is unknown: an oversized record the
	// parser skipped undecoded. A start walk that meets it proves nothing
	// (it could be the input that started the request), so the span is not
	// stamped - identically in-window and in look-back context.
	cxUnknown
)

// cxUsage is one inference's four counters.
type cxUsage struct {
	Input, Cached, Output, Reasoning int64
}

// codexTimingLine is the minimal per-record projection the span rule needs.
type codexTimingLine struct {
	Kind  codexTimingKind
	TS    time.Time
	Usage cxUsage
	// TokIdx is the res.TokenEvents index a token_count produced (-1 when
	// it produced none - a deduped re-emission, or a look-back record).
	TokIdx int
}

// cxResponseItemKind is the response_item payload-type table.
var cxResponseItemKind = map[string]codexTimingKind{
	"reasoning":               cxOutput,
	"function_call":           cxOutput,
	"custom_tool_call":        cxOutput,
	"web_search_call":         cxOutput,
	"local_shell_call":        cxOutput,
	"function_call_output":    cxInput,
	"custom_tool_call_output": cxInput,
}

// cxTopLevelKind is the top-level record-type table (types not listed are
// neutral; response_item / event_msg / token_usage_record are decoded).
var cxTopLevelKind = map[string]codexTimingKind{
	"world_state":  cxInput,
	"turn_context": cxInput,
	"compacted":    cxInput,
}

// cxEventMsgKind is the event_msg payload-type table.
var cxEventMsgKind = map[string]codexTimingKind{
	"user_message": cxInput,
	"task_started": cxInput,
	"token_count":  cxTokenCount,
}

// classifyCodexRecord projects one decoded record.
func classifyCodexRecord(line rawLine, pType string) codexTimingLine {
	tl := codexTimingLine{TS: parseTimestamp(line.Timestamp), TokIdx: -1}
	switch line.Type {
	case "response_item":
		if pType == "message" {
			var m struct {
				Role string `json:"role"`
			}
			_ = json.Unmarshal(line.Payload, &m)
			if m.Role == "assistant" {
				tl.Kind = cxOutput
			} else {
				tl.Kind = cxInput
			}
		} else {
			tl.Kind = cxResponseItemKind[pType]
		}
	case "event_msg":
		tl.Kind = cxEventMsgKind[pType]
	case "token_usage_record":
		var r struct {
			Usage struct {
				Input     int64 `json:"input_tokens"`
				Cached    int64 `json:"cached_input_tokens"`
				Output    int64 `json:"output_tokens"`
				Reasoning int64 `json:"reasoning_output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal(line.Payload, &r) == nil {
			tl.Kind = cxUsageRecord
			tl.Usage = cxUsage{r.Usage.Input, r.Usage.Cached, r.Usage.Output, r.Usage.Reasoning}
		}
	default:
		tl.Kind = cxTopLevelKind[line.Type]
	}
	return tl
}

// codexGenSpans returns TokenEvent index -> span ms for every token_count
// whose span is proven, and whether a walk left the known records.
func codexGenSpans(lines []codexTimingLine) (spans map[int]int64, incomplete bool) {
	spans = map[int]int64{}
	for ti, t := range lines {
		if t.Kind != cxTokenCount || t.TokIdx < 0 {
			continue
		}
		u := -1
		for j := ti - 1; j >= 0; j-- {
			if lines[j].Kind == cxUsageRecord {
				u = j
				break
			}
		}
		if u < 0 {
			incomplete = true
			continue
		}
		if lines[u].Usage != t.Usage {
			continue
		}
		start, firstOut, outputs, found, exhausted := time.Time{}, time.Time{}, 0, false, true
	walk:
		for j := u - 1; j >= 0; j-- {
			switch l := lines[j]; l.Kind {
			case cxUsageRecord, cxUnknown:
				exhausted = false // another inference's end, or an unknown record, before any input
				break walk
			case cxOutput:
				outputs++
				firstOut = l.TS // walking back: the last one met is the earliest
			case cxInput:
				start, found, exhausted = l.TS, true, false
				break walk
			}
		}
		if exhausted {
			incomplete = true
		}
		if !found || outputs == 0 || start.IsZero() || lines[u].TS.IsZero() {
			continue
		}
		// Both ends must bracket the first output record.
		if !firstOut.IsZero() && (start.After(firstOut) || lines[u].TS.Before(firstOut)) {
			continue
		}
		if ms := lines[u].TS.Sub(start).Milliseconds(); ms > 0 {
			spans[t.TokIdx] = ms
		}
	}
	return spans, incomplete
}

// readCodexGenLookback reads up to size bytes before fromOffset and
// classifies its complete records as context. atStart reports that the
// read reached the start of the file.
func readCodexGenLookback(path string, fromOffset, size int64) (out []codexTimingLine, atStart bool) {
	start := fromOffset - size
	if start < 0 {
		start = 0
	}
	atStart = start == 0
	f, err := os.Open(path)
	if err != nil {
		return nil, true
	}
	defer f.Close()
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, true
	}
	buf := make([]byte, fromOffset-start)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, true
	}
	text := string(buf)
	if start > 0 {
		nl := strings.IndexByte(text, '\n')
		if nl < 0 {
			return nil, atStart
		}
		text = text[nl+1:]
	}
	for _, raw := range strings.Split(text, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if raw == "" {
			continue
		}
		if int64(len(raw)) > maxRecordBytes {
			// The in-window parser skips such a record undecoded; mirror it.
			out = append(out, codexTimingLine{Kind: cxUnknown, TokIdx: -1})
			continue
		}
		var line rawLine
		if json.Unmarshal([]byte(raw), &line) != nil {
			continue
		}
		out = append(out, classifyCodexRecord(line, payloadType(line.Payload)))
	}
	return out, atStart
}

// hasUsageRecord reports whether any line is a token_usage_record.
func hasUsageRecord(lines []codexTimingLine) bool {
	for _, l := range lines {
		if l.Kind == cxUsageRecord {
			return true
		}
	}
	return false
}

// applyCodexGenTiming stamps every proven span onto its TokenEvent.
func applyCodexGenTiming(path string, fromOffset int64, window []codexTimingLine, events []models.TokenEvent) {
	spans, incomplete := codexGenSpans(window)
	if incomplete && fromOffset > 0 {
		windowHasUsage := hasUsageRecord(window)
		for size := codexGenLookbackFirstBytes; ; size *= 2 {
			if size > codexGenLookbackBytes {
				size = codexGenLookbackBytes
			}
			ctxLines, atStart := readCodexGenLookback(path, fromOffset, size)
			more := true
			if len(ctxLines) > 0 {
				spans, more = codexGenSpans(append(ctxLines, window...))
			}
			if size >= codexGenProbeBytes && !windowHasUsage && !hasUsageRecord(ctxLines) {
				break // a build that writes no token_usage_record: never stampable
			}
			if !more || atStart || size >= codexGenLookbackBytes {
				break
			}
		}
	}
	for idx, ms := range spans {
		if idx >= 0 && idx < len(events) {
			events[idx].GenMs, events[idx].GenBasis, events[idx].GenTimingV = ms, models.GenBasisTranscript, codexGenTimingV
		}
	}
}

// bindCodexTokenCount records, on the window's latest token_count timing
// line, the TokenEvent it produced and that event's four counters.
func bindCodexTokenCount(lines []codexTimingLine, tokIdx int, u cxUsage) {
	if n := len(lines); n > 0 && lines[n-1].Kind == cxTokenCount {
		lines[n-1].TokIdx, lines[n-1].Usage = tokIdx, u
	}
}
