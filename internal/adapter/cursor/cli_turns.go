package cursor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The cursor-agent debug log (cursor-agent-logs-<user>/session-*.log, one
// file per process) is the ONLY local record of a turn that never
// finished. Usage itself is reported in exactly two places, both only when
// a turn finishes (grounded against the 2026.09.18 + 2026.09.26 bundles and
// demo node-1's logs, 2026-09-27):
//
//	surface      usage carrier                                   read by
//	-----------  ----------------------------------------------  --------------------------------
//	headless     agent_cli.turn.outcome (net input, both caches)  parseCLIOutcome (cli_usage.go)
//	interactive  stop + afterAgentResponse hooks (gross input)    internal/hook/cursor.go
//
// The interactive turn-outcome record carries NO token fields (the TUI
// never calls setTokenUsage) and no conversation id, and it is keyed by a
// tracker id that is not the hook generation id - so it is never read for
// usage (accepting it would also double count against the hooks). A turn
// that is still retrying when the user quits (/quit exits without running
// stop) or whose process is killed leaves NO usage anywhere on disk.
//
// This file turns that debug log into evidence instead: one api_error row
// per failed request attempt and one turn_aborted row per turn that never
// finished (or finished without success), each naming the attempts and
// which hooks fired. internal/cursorusage reads those rows to say exactly
// why a session has no usage. It never fabricates a token count.

// cliRecKind classifies one debug-log line. The classifier is the
// cliRecDecoders table below; a line no row claims is recNone.
type cliRecKind int

const (
	recNone cliRecKind = iota
	recRequestCreate
	recConvInit
	recConvDispose
	recTurnStart
	recTurnOutcome
	recAttemptFailed
	recHookExecuted
)

// cliRec is one classified line (only the fields its kind uses are set).
type cliRec struct {
	kind cliRecKind
	ts   time.Time

	conv      string // request.create / conversationClassification / turn metadata
	gen       string // request.create invocationID (== the hook generation_id)
	workspace string // conversationClassification.init workspacePath

	tracker      string // turn.start / turn.outcome request_id
	surface      string
	outcome      string
	errorType    string
	errorCode    string
	cancelSource string

	requestID string // failed attempt
	errorName string
	decision  string
	attempt   int

	hookStep   string
	hookSource string

	hasUsage bool // turn.outcome carried token fields (headless only)
}

// cliRecDecoder decodes the JSON payload of one record name.
type cliRecDecoder func(payload []byte) (cliRec, bool)

// cliRecDecoders maps a debug-log record name (the token after the
// timestamp) to its decoder. One row per record shape.
var cliRecDecoders = map[string]cliRecDecoder{
	"analytics.track":                    decodeAnalyticsTrack,
	"conversationClassification.init":    decodeConvInit,
	"conversationClassification.dispose": decodeConvDispose,
	"structured-log.info":                decodeStructuredTurn,
	"logger":                             decodeRetryDiagnostic,
}

// classifyCLILine splits `[<RFC3339>] <name> <json>` and dispatches on name.
func classifyCLILine(line string) cliRec {
	if len(line) < 3 || line[0] != '[' {
		return cliRec{}
	}
	end := strings.Index(line, "] ")
	if end < 2 {
		return cliRec{}
	}
	ts, err := time.Parse(time.RFC3339Nano, line[1:end])
	if err != nil {
		return cliRec{}
	}
	rest := line[end+2:]
	sp := strings.IndexByte(rest, ' ')
	if sp <= 0 {
		return cliRec{}
	}
	dec, ok := cliRecDecoders[rest[:sp]]
	if !ok {
		return cliRec{}
	}
	rec, ok := dec([]byte(strings.TrimSpace(rest[sp+1:])))
	if !ok {
		return cliRec{}
	}
	rec.ts = ts.UTC()
	return rec
}

func decodeAnalyticsTrack(p []byte) (cliRec, bool) {
	var v struct {
		EventName string `json:"eventName"`
		Props     struct {
			ConversationID string `json:"conversationId"`
			InvocationID   string `json:"invocationID"`
			HookStep       string `json:"hookStep"`
			HookSource     string `json:"hookSource"`
		} `json:"props"`
	}
	if json.Unmarshal(p, &v) != nil {
		return cliRec{}, false
	}
	switch v.EventName {
	case "cli.request.create":
		if !validCLIUsageID(v.Props.ConversationID) {
			return cliRec{}, false
		}
		return cliRec{kind: recRequestCreate, conv: v.Props.ConversationID, gen: v.Props.InvocationID}, true
	case "cli.hook.executed":
		if v.Props.HookStep == "" {
			return cliRec{}, false
		}
		return cliRec{kind: recHookExecuted, hookStep: v.Props.HookStep, hookSource: v.Props.HookSource}, true
	}
	return cliRec{}, false
}

func decodeConvInit(p []byte) (cliRec, bool) {
	var v struct {
		ConversationID string `json:"conversationId"`
		WorkspacePath  string `json:"workspacePath"`
	}
	if json.Unmarshal(p, &v) != nil || !validCLIUsageID(v.ConversationID) {
		return cliRec{}, false
	}
	return cliRec{kind: recConvInit, conv: v.ConversationID, workspace: v.WorkspacePath}, true
}

func decodeConvDispose(p []byte) (cliRec, bool) {
	var v struct {
		ConversationID string `json:"conversationId"`
	}
	if json.Unmarshal(p, &v) != nil {
		return cliRec{}, false
	}
	return cliRec{kind: recConvDispose, conv: v.ConversationID}, true
}

func decodeStructuredTurn(p []byte) (cliRec, bool) {
	var v struct {
		Key      string            `json:"key"`
		Message  string            `json:"message"`
		Metadata map[string]string `json:"metadata"`
	}
	if json.Unmarshal(p, &v) != nil || v.Key != "agent_cli" {
		return cliRec{}, false
	}
	m := v.Metadata
	rec := cliRec{tracker: m["request_id"], conv: m["conversation_id"], surface: m["surface"]}
	if !validCLIUsageID(rec.tracker) {
		return cliRec{}, false
	}
	if rec.conv != "" && !validCLIUsageID(rec.conv) {
		rec.conv = ""
	}
	switch v.Message {
	case "agent_cli.turn.start":
		rec.kind = recTurnStart
	case "agent_cli.turn.outcome":
		rec.kind = recTurnOutcome
		rec.outcome, rec.errorType, rec.errorCode, rec.cancelSource = m["outcome"], m["error_type"], m["error_code"], m["cancel_source"]
		_, rec.hasUsage = m["input_tokens"]
	default:
		return cliRec{}, false
	}
	return rec, true
}

// decodeRetryDiagnostic reads the agent's per-attempt failure line:
// logger {"message":"[AGENT_ERROR_DIAGNOSTICS] ...","metadata":{...}}.
func decodeRetryDiagnostic(p []byte) (cliRec, bool) {
	var v struct {
		Message  string `json:"message"`
		Metadata struct {
			Decision  string `json:"decision"`
			Attempt   int    `json:"attempt"`
			RequestID string `json:"requestId"`
			ErrorName string `json:"errorName"`
		} `json:"metadata"`
	}
	if json.Unmarshal(p, &v) != nil || !strings.HasPrefix(v.Message, "[AGENT_ERROR_DIAGNOSTICS]") {
		return cliRec{}, false
	}
	md := v.Metadata
	if !validCLIUsageID(md.RequestID) {
		return cliRec{}, false
	}
	decision := md.Decision
	if i := strings.IndexByte(decision, ' '); i > 0 {
		decision = decision[:i] // "RETRY (countAsServerError=true, ...)" -> "RETRY"
	}
	return cliRec{kind: recAttemptFailed, requestID: md.RequestID, errorName: md.ErrorName, decision: decision, attempt: md.Attempt}, true
}

// cliTurn is one turn folded out of a process log.
type cliTurn struct {
	tracker, conv, gen, surface string
	started                     time.Time
	outcome                     *cliRec
	attempts                    []cliRec
	hooks                       []string // Cursor-sourced hook steps, in firing order
	endedAt                     time.Time
	processEnded                bool // the process exited with this turn still open
	workspace                   string
}

// cliProcess is the fold state for one debug-log file.
type cliProcess struct {
	conv, gen, workspace string
	pendingHooks         []string
	open                 *cliTurn
	turns                []*cliTurn
	orphanAttempts       []cliRec // failed attempts seen with no open turn
}

// isCursorHookSource reports hooks from Cursor's own hooks.json (user /
// project / enterprise). cursor-agent also runs Claude Code's hooks
// ("claude-user"), which are not the ones that report Cursor usage.
func isCursorHookSource(src string) bool {
	return !strings.HasPrefix(src, "claude")
}

// foldCLIRecords walks one process log's records in order.
func foldCLIRecords(recs []cliRec) *cliProcess {
	p := &cliProcess{}
	closeOpen := func(at time.Time, ended bool) {
		if p.open == nil {
			return
		}
		p.open.endedAt = at
		p.open.processEnded = ended
		p.open = nil
	}
	for _, r := range recs {
		switch r.kind {
		case recConvInit:
			p.conv, p.workspace = r.conv, r.workspace
		case recRequestCreate:
			p.conv, p.gen = r.conv, r.gen
		case recTurnStart:
			if p.open != nil {
				closeOpen(r.ts, false) // a new turn began before the old one reported an outcome
			}
			t := &cliTurn{tracker: r.tracker, conv: r.conv, surface: r.surface, started: r.ts, workspace: p.workspace, hooks: p.pendingHooks}
			if t.conv == "" {
				t.conv = p.conv
			}
			// Headless turns are keyed by the request id itself; interactive
			// ones by the invocation id the hooks also carry.
			t.gen = r.tracker
			if r.surface != "headless" && p.gen != "" {
				t.gen = p.gen
			}
			p.pendingHooks = nil
			p.open = t
			p.turns = append(p.turns, t)
		case recAttemptFailed:
			if p.open != nil {
				p.open.attempts = append(p.open.attempts, r)
			} else {
				r.conv = p.conv
				p.orphanAttempts = append(p.orphanAttempts, r)
			}
		case recHookExecuted:
			if !isCursorHookSource(r.hookSource) || r.hookStep == "sessionStart" {
				continue
			}
			if p.open != nil {
				p.open.hooks = append(p.open.hooks, r.hookStep)
			} else {
				p.pendingHooks = append(p.pendingHooks, r.hookStep)
			}
			if r.hookStep == "sessionEnd" {
				closeOpen(r.ts, true)
			}
		case recTurnOutcome:
			for i := len(p.turns) - 1; i >= 0; i-- {
				if t := p.turns[i]; t.tracker == r.tracker && t.outcome == nil {
					rec := r
					t.outcome = &rec
					if t.conv == "" {
						t.conv = r.conv
					}
					t.endedAt = r.ts
					if p.open == t {
						p.open = nil
					}
					break
				}
			}
		case recConvDispose:
			closeOpen(r.ts, true)
		}
	}
	return p
}

// cliTurnFacts is the per-turn gap classification: the ordered table below
// maps a turn's shape to the row kind it becomes (first match wins).
type cliTurnFacts struct {
	finished, success, processEnded, superseded bool
}

var cliTurnRows = []struct {
	match   func(cliTurnFacts) bool
	rawTool func(t *cliTurn) string
	target  func(t *cliTurn) string
}{
	// Reported a successful outcome: usage (if any) came through its own carrier.
	{match: func(f cliTurnFacts) bool { return f.finished && f.success }},
	// Reported a non-success outcome.
	{
		match:   func(f cliTurnFacts) bool { return f.finished },
		rawTool: func(t *cliTurn) string { return cursorusage.RawToolTurnFailedPrefix + safeToken(t.outcome.outcome) },
		target:  func(t *cliTurn) string { return "Turn ended with outcome " + safeToken(t.outcome.outcome) },
	},
	// Never reported an outcome and the process (or a newer turn) moved on.
	{
		match:   func(f cliTurnFacts) bool { return f.processEnded || f.superseded },
		rawTool: func(*cliTurn) string { return cursorusage.RawToolTurnUnfinished },
		target:  func(*cliTurn) string { return "Turn did not finish - Cursor reported no usage" },
	},
	// Still running: say nothing yet.
	{match: func(cliTurnFacts) bool { return true }},
}

func turnFacts(t *cliTurn) cliTurnFacts {
	f := cliTurnFacts{finished: t.outcome != nil, processEnded: t.processEnded}
	f.success = f.finished && t.outcome.outcome == "success"
	f.superseded = !f.finished && !t.endedAt.IsZero() && !t.processEnded
	return f
}

func safeToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "unknown"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// usageCarrier names where a turn's usage would have been reported.
func usageCarrier(surface string) string {
	if surface == "headless" {
		return "the headless turn-outcome log record"
	}
	return "the stop and afterAgentResponse hooks"
}

// describeTurn builds the evidence sentence stored on a turn_aborted row.
func describeTurn(t *cliTurn) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The cursor-agent turn started at %s UTC", t.started.Format("15:04:05"))
	if n := len(t.attempts); n > 0 {
		fmt.Fprintf(&b, " had %s (%s)", pluralize(n, "failed request attempt", "failed request attempts"), attemptSummary(t.attempts))
	}
	switch {
	case t.outcome != nil:
		fmt.Fprintf(&b, " and ended with outcome %s", safeToken(t.outcome.outcome))
		var tags []string
		for _, kv := range [][2]string{{"error_type", t.outcome.errorType}, {"error_code", t.outcome.errorCode}, {"cancel_source", t.outcome.cancelSource}} {
			if kv[1] != "" {
				tags = append(tags, kv[0]+" "+kv[1])
			}
		}
		if len(tags) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(tags, ", "))
		}
	case len(t.attempts) > 0 && t.attempts[len(t.attempts)-1].decision == "RETRY" && t.processEnded:
		b.WriteString(", and the session ended while Cursor was still retrying")
	case t.processEnded:
		b.WriteString(", and the session ended before the turn finished")
	default:
		b.WriteString(", and a new turn started before it finished")
	}
	if t.outcome != nil && t.outcome.hasUsage {
		b.WriteString(". Cursor logged usage for the final attempt only; earlier attempts are not reported")
	} else {
		fmt.Fprintf(&b, ". Cursor reports usage only through %s when a turn finishes", usageCarrier(t.surface))
	}
	if hooks := hookSummary(t.hooks); hooks != "" {
		fmt.Fprintf(&b, "; hooks that fired: %s", hooks)
	}
	if missing := missingFinishHooks(t); len(missing) > 0 {
		fmt.Fprintf(&b, "; did not fire: %s", strings.Join(missing, ", "))
	}
	b.WriteString(".")
	return b.String()
}

func attemptSummary(atts []cliRec) string {
	counts := map[string]int{}
	var order []string
	for _, a := range atts {
		name := a.errorName
		if name == "" {
			name = "unknown error"
		}
		if counts[name] == 0 {
			order = append(order, name)
		}
		counts[name]++
	}
	parts := make([]string, 0, len(order))
	for _, n := range order {
		if counts[n] > 1 {
			parts = append(parts, fmt.Sprintf("%s x%d", n, counts[n]))
		} else {
			parts = append(parts, n)
		}
	}
	return strings.Join(parts, ", ")
}

func hookSummary(hooks []string) string {
	counts := map[string]int{}
	var order []string
	for _, h := range hooks {
		if counts[h] == 0 {
			order = append(order, h)
		}
		counts[h]++
	}
	parts := make([]string, 0, len(order))
	for _, h := range order {
		if counts[h] > 1 {
			parts = append(parts, fmt.Sprintf("%s x%d", h, counts[h]))
		} else {
			parts = append(parts, h)
		}
	}
	return strings.Join(parts, ", ")
}

// missingFinishHooks lists the usage-carrying hooks an interactive turn
// never ran (headless runs never run them, so nothing is "missing" there).
func missingFinishHooks(t *cliTurn) []string {
	if t.surface == "headless" {
		return nil
	}
	fired := map[string]bool{}
	for _, h := range t.hooks {
		fired[h] = true
	}
	var out []string
	for _, h := range []string{EventStop, EventAfterAgentResponse} {
		if !fired[h] {
			out = append(out, h)
		}
	}
	return out
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// cliLogHasTerminalMarker reports a line that can close a turn: only then
// is the whole-file fold worth running.
func cliLogHasTerminalMarker(line string) bool {
	return strings.Contains(line, "agent_cli.turn.outcome") ||
		strings.Contains(line, "conversationClassification.dispose") ||
		(strings.Contains(line, "cli.hook.executed") && strings.Contains(line, `"hookStep":"sessionEnd"`))
}

// cliTurnEvents re-reads [0, limit) of one process log and returns the
// evidence rows for every closed turn. IDs are deterministic, so a re-read
// dedups on UNIQUE(source_file, source_event_id).
func (a *Adapter) cliTurnEvents(ctx context.Context, path string, limit int64) ([]models.ToolEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []cliRec
	r := bufio.NewReader(io.LimitReader(f, limit))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, _, err := readCLIUsageLine(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if rec := classifyCLILine(line); rec.kind != recNone {
			recs = append(recs, rec)
		}
	}
	proc := foldCLIRecords(recs)

	type sessCtx struct{ model, root string }
	ctxCache := map[string]sessCtx{}
	resolve := func(conv, workspace string) sessCtx {
		if c, ok := ctxCache[conv]; ok {
			return c
		}
		model, root := a.cliUsageContext(ctx, conv, "")
		if root == "" && filepath.IsAbs(workspace) {
			root = workspace
		}
		c := sessCtx{model, root}
		ctxCache[conv] = c
		return c
	}

	var out []models.ToolEvent
	attemptRow := func(att cliRec, conv, workspace string) {
		if conv == "" {
			return
		}
		c := resolve(conv, workspace)
		msg := fmt.Sprintf("cursor-agent request attempt %d failed", att.attempt)
		if att.errorName != "" {
			msg += " with " + att.errorName
		}
		if att.decision != "" {
			msg += "; Cursor's decision: " + att.decision
		}
		out = append(out, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: cursorusage.SourceEventAttemptPrefix + att.requestID,
			SessionID:     conv,
			MessageID:     "attempt:" + att.requestID,
			ProjectRoot:   c.root,
			Timestamp:     att.ts,
			Model:         c.model,
			Tool:          models.ToolCursor,
			ActionType:    models.ActionAPIError,
			Target:        att.requestID,
			RawToolName:   nonEmpty(att.errorName, "cursor_cli.attempt_failed"),
			ErrorMessage:  msg + ".",
			Success:       false,
		})
	}
	for _, att := range proc.orphanAttempts {
		attemptRow(att, att.conv, proc.workspace)
	}
	for _, t := range proc.turns {
		if t.conv == "" {
			continue
		}
		for _, att := range t.attempts {
			attemptRow(att, t.conv, t.workspace)
		}
		facts := turnFacts(t)
		var rawTool, target string
		for _, row := range cliTurnRows {
			if row.match(facts) {
				if row.rawTool != nil {
					rawTool, target = row.rawTool(t), row.target(t)
				}
				break
			}
		}
		if rawTool == "" {
			continue
		}
		c := resolve(t.conv, t.workspace)
		ts := t.endedAt
		if ts.IsZero() {
			ts = t.started
		}
		out = append(out, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: cursorusage.TurnSourceEventID(t.tracker, rawTool),
			SessionID:     t.conv,
			MessageID:     t.gen,
			ProjectRoot:   c.root,
			Timestamp:     ts,
			Model:         c.model,
			Tool:          models.ToolCursor,
			ActionType:    models.ActionTurnAborted,
			Target:        target,
			RawToolName:   rawTool,
			ErrorMessage:  describeTurn(t),
			Success:       false,
		})
	}
	return out, nil
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
