package superbased

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// The app's first-trace line (SDK quickstart plan section 3.8, ruling R12;
// contract sdk-api-surface.md section 16; cases sdk-behaviour-cases.json
// first_trace_link): after the first root span of the process
// is exported, the SDK writes one line to stderr, directly (not through the
// logger, which apps usually keep at warnings), with a link to its trace on
// the dashboard:
//
//	superbased: first trace from this process: <link>
//
// Only when stderr is a terminal, CI is unset (or empty, 0, false) and
// SUPERBASED_FIRST_TRACE_LINK is not 0, false or off, so production logs
// stay quiet. Once per process; a plan refusal is said in its place.

// EnvFirstTraceLink set to 0, false or off turns the first-trace line off.
const EnvFirstTraceLink = "SUPERBASED_FIRST_TRACE_LINK"

const (
	// firstTracePrefix starts the line.
	firstTracePrefix = "superbased: first trace from this process: "
	// firstTraceRefusedPrefix starts the line that says a plan refusal.
	firstTraceRefusedPrefix = "superbased: traces from this process were refused: "
	localTracePath          = "/apps/traces?trace="
	onlineTracePath         = "/trajectories?trace="
)

var (
	// firstTraceOut is where the line goes (a variable for tests).
	firstTraceOut io.Writer = os.Stderr
	// stderrIsTerminal reports whether stderr is a terminal (a variable for
	// tests).
	stderrIsTerminal = func() bool {
		fi, err := os.Stderr.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
	firstTrace = &firstTraceTracker{}
)

// firstTraceAllowed is ruling R12's gate: a terminal, CI unset (or empty,
// 0, false), and SUPERBASED_FIRST_TRACE_LINK not 0, false or off.
func firstTraceAllowed(terminal bool, env envFunc) bool {
	if !terminal {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(env.get("CI"))) {
	case "", "0", "false":
	default:
		return false
	}
	switch strings.ToLower(strings.TrimSpace(env.get(EnvFirstTraceLink))) {
	case "0", "false", "off":
		return false
	}
	return true
}

// firstTraceLink is the dashboard link to traceID for a destination.
func firstTraceLink(dest, base, traceID string) string {
	base = strings.TrimRight(base, "/")
	switch {
	case base == "" || traceID == "":
		return ""
	case dest == DestinationOnline:
		return base + onlineTracePath + traceID
	case dest == DestinationLocal:
		return base + localTracePath + traceID
	}
	return ""
}

// firstTraceRefusalLine is the line that says a plan refusal: the server's
// message as sent, then its upgrade link when it has one.
func firstTraceRefusalLine(r *PlanRefusalError) string {
	line := firstTraceRefusedPrefix + strings.TrimSpace(r.Message)
	if r.UpgradeURL != "" {
		line += " " + r.UpgradeURL
	}
	return line
}

// firstTraceBases are the link bases a plan knows: local is the machine's
// dashboard when the plan exports locally and the machine answered
// discovery; online is the organization's dashboard when the plan exports
// online under record 2 or 3 (none under record 1). waitOnline: under both
// with an online base, a local success waits for the online verdict.
type firstTraceBases struct {
	local, online string
	waitOnline    bool
}

func basesOf(p *plan) firstTraceBases {
	var b firstTraceBases
	if p == nil {
		return b
	}
	if p.destination == DestinationLocal || p.destination == DestinationBoth {
		b.local = p.localDashboard
	}
	if p.onlineEnabled() {
		b.online = p.onlineDashboard
	}
	b.waitOnline = p.destination == DestinationBoth && b.online != ""
	return b
}

// firstTraceTracker decides the line from the exports of root spans, in the
// order they finish (one owner of this state).
type firstTraceTracker struct {
	mu           sync.Mutex
	done         bool
	pendingLocal string // a local link waiting for the online verdict (both)
	onlineFailed bool   // an online export failed and none succeeded since
	link         string // the link once written (Diagnostics.FirstTraceLink)
}

// step is one export of a batch whose first root span has traceID to dest:
// (line, link), both "" when nothing is to be written yet. Pure over the
// tracker's state; the caller gates and writes.
func (t *firstTraceTracker) step(b firstTraceBases, dest, traceID string, ok bool, refusal *PlanRefusalError) (string, string) {
	if t.done || traceID == "" {
		return "", ""
	}
	switch dest {
	case DestinationOnline:
		switch {
		case refusal != nil:
			return firstTraceRefusalLine(refusal), ""
		case ok && b.online != "":
			link := firstTraceLink(DestinationOnline, b.online, traceID)
			return firstTracePrefix + link, link
		case ok:
			t.onlineFailed = false
		case t.pendingLocal != "":
			return firstTracePrefix + t.pendingLocal, t.pendingLocal
		default:
			t.onlineFailed = true
		}
	case DestinationLocal:
		if !ok || b.local == "" {
			return "", ""
		}
		link := firstTraceLink(DestinationLocal, b.local, traceID)
		if b.waitOnline && !t.onlineFailed {
			if t.pendingLocal == "" {
				t.pendingLocal = link
			}
			return "", ""
		}
		return firstTracePrefix + link, link
	}
	return "", ""
}

// note runs one export through the tracker and, when a line is due and the
// gate allows it, writes it once per process.
func (t *firstTraceTracker) note(b firstTraceBases, dest, traceID string, ok bool, refusal *PlanRefusalError, allowed func() bool, out io.Writer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	line, link := t.step(b, dest, traceID, ok, refusal)
	if line == "" {
		return
	}
	t.done = true
	if !allowed() {
		return // not a terminal, CI or opted out: for good
	}
	t.link = link
	_, _ = fmt.Fprintln(out, line)
}

func (t *firstTraceTracker) printed() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.link
}

func (t *firstTraceTracker) reset() {
	t.mu.Lock()
	t.done, t.pendingLocal, t.onlineFailed, t.link = false, "", false, ""
	t.mu.Unlock()
}

// firstRootTraceID is the trace id of the first local root span in spans
// (no parent, or a parent from another process), "" when there is none.
func firstRootTraceID(spans []sdktrace.ReadOnlySpan) string {
	for _, s := range spans {
		if parent := s.Parent(); !parent.IsValid() || parent.IsRemote() {
			return s.SpanContext().TraceID().String()
		}
	}
	return ""
}

// noteFirstTrace is the exporter's one call: an export to dest of spans
// finished (ok, or refused by the organization's plan).
func noteFirstTrace(dest string, spans []sdktrace.ReadOnlySpan, ok bool, refusal *PlanRefusalError) {
	firstTrace.mu.Lock()
	done := firstTrace.done
	firstTrace.mu.Unlock()
	if done {
		return
	}
	traceID := firstRootTraceID(spans)
	if traceID == "" {
		return
	}
	firstTrace.note(basesOf(activePlan()), dest, traceID, ok, refusal,
		func() bool { return firstTraceAllowed(stderrIsTerminal(), osEnv) }, firstTraceOut)
}
