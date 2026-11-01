package sandboxnet

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// notice.go keeps the gateway's log lines off the agent's screen (Windows
// 11 Pro run 5, plans decision log P-111): a host helper whose stderr IS
// the sandboxed tool's terminal must never print a log-formatted line there,
// because it lands in the middle of a full-screen TUI. RefusalLogger sends
// every gateway record to the run's own log as one plain line and shows the
// user at most ONE plain line per refused host:
//
//	observer sandbox: blocked <host> (<rule>)
//
// Once the tool has started that line is not printed either (Windows 11 Pro
// run 4, N2: it drew over Claude Code's folder trust dialog and hid "Yes, I
// trust this folder"). A TerminalNotices told ToolStarted holds every later
// refusal: the run log still gets each record, the run's status gets the
// count (OnHeld), and after the tool exited Finish prints one summary line.
//
// The rule names in both are the gateway's own (hyphenated, the spelling of
// the 403 body and docs/sandboxed-terminals.md).

// maxNoticedHosts bounds the hosts one logger remembers; past it no further
// user line is printed (the run log still gets every record).
const maxNoticedHosts = 256

// summaryHosts is how many held hosts the summary line names.
const summaryHosts = 3

// TerminalNotices is the user side of a refusal logger: the terminal the
// sandboxed tool owns once it has started. Before ToolStarted it prints one
// plain line per refused host; after it, nothing reaches the terminal until
// Finish. Safe for concurrent use.
type TerminalNotices struct {
	mu       sync.Mutex
	w        io.Writer
	seen     map[string]bool
	started  bool
	finished bool
	held     int
	hosts    []string
	rules    map[string]string
	reported int
	onHeld   func(total int)
}

// NewTerminalNotices returns the notices for the terminal w (nil for none:
// nothing is printed, the count is still kept).
func NewTerminalNotices(w io.Writer) *TerminalNotices {
	return &TerminalNotices{w: w, seen: map[string]bool{}, rules: map[string]string{}}
}

// OnHeld sets the run's status hook: it is called with the number of
// refusals held since the tool started, at the first one and each time the
// count doubles (so a box that floods the gateway cannot flood the status),
// and once more by Finish with the final count. Call it before the gateway
// serves.
func (n *TerminalNotices) OnHeld(f func(total int)) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.onHeld = f
	n.mu.Unlock()
}

// ToolStarted marks the moment the tool owns the terminal: no notice is
// printed there from now on.
func (n *TerminalNotices) ToolStarted() {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.started = true
	n.mu.Unlock()
}

// Held is the number of refusals held since the tool started.
func (n *TerminalNotices) Held() int {
	if n == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.held
}

// refused records one refusal of host by rules.
func (n *TerminalNotices) refused(host, rules string) {
	n.mu.Lock()
	if !n.started || n.finished {
		first := !n.seen[host] && len(n.seen) < maxNoticedHosts
		if first {
			n.seen[host] = true
		}
		w := n.w
		n.mu.Unlock()
		if first && w != nil {
			_, _ = fmt.Fprintf(w, "\r\nobserver sandbox: blocked %s (%s)\r\n", oneLine(host), oneLine(rules))
		}
		return
	}
	n.held++
	if _, ok := n.rules[host]; !ok && len(n.rules) < maxNoticedHosts {
		n.rules[host] = rules
		n.hosts = append(n.hosts, host)
	}
	total := n.held
	report := n.onHeld != nil && total&(total-1) == 0 // 1, 2, 4, 8, ...
	if report {
		n.reported = total
	}
	f := n.onHeld
	n.mu.Unlock()
	if report {
		f(total)
	}
}

// Finish is called once the tool has exited: when refusals were held, it
// prints one summary line to the terminal and reports the final count to
// the status hook. Later refusals print as before the tool started.
func (n *TerminalNotices) Finish() {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.finished {
		n.mu.Unlock()
		return
	}
	n.finished = true
	held, w, f := n.held, n.w, n.onHeld
	line := ""
	if held > 0 {
		line = summaryLine(held, n.hosts, n.rules)
	}
	final := f != nil && held > 0 && n.reported != held
	n.mu.Unlock()
	if final {
		f(held)
	}
	if line != "" && w != nil {
		_, _ = io.WriteString(w, line)
	}
}

// summaryLine is Finish's line: the count, then up to summaryHosts hosts
// with their rule.
func summaryLine(held int, hosts []string, rules map[string]string) string {
	noun := "connections were"
	if held == 1 {
		noun = "connection was"
	}
	parts := make([]string, 0, summaryHosts+1)
	for i, h := range hosts {
		if i == summaryHosts {
			parts = append(parts, fmt.Sprintf("and %d more host(s)", len(hosts)-summaryHosts))
			break
		}
		parts = append(parts, oneLine(h)+" ("+oneLine(rules[h])+")")
	}
	return fmt.Sprintf("\r\nobserver sandbox: %d %s blocked while the tool ran: %s\r\n", held, noun, strings.Join(parts, ", "))
}

// RefusalLogger returns the logger a gateway in a terminal-owning helper
// uses: runLog (nil to drop) receives every record as one line, user (nil
// for none) receives at most one "observer sandbox: blocked" line per
// refused host, written at the start of a line and ended with "\r\n" so a
// terminal in raw mode shows it whole. For a terminal a full-screen tool
// takes over, use RefusalLoggerTo with a TerminalNotices.
func RefusalLogger(runLog func(string), user io.Writer) *slog.Logger {
	return RefusalLoggerTo(runLog, NewTerminalNotices(user))
}

// RefusalLoggerTo is RefusalLogger with the user side given as notices
// (nil for none), so the caller can mark the tool's start and finish.
func RefusalLoggerTo(runLog func(string), notices *TerminalNotices) *slog.Logger {
	return slog.New(&refusalHandler{shared: &refusalShared{runLog: runLog, notices: notices}})
}

// refusalShared is the state every handler derived from one RefusalLogger
// shares.
type refusalShared struct {
	runLog  func(string)
	notices *TerminalNotices
}

// refusalHandler is the slog.Handler behind RefusalLogger.
type refusalHandler struct {
	shared *refusalShared
	attrs  []slog.Attr
}

// Enabled implements slog.Handler: every level is kept (the run log is the
// place a refusal or an upstream failure is read later).
func (h *refusalHandler) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler.
func (h *refusalHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String())
	b.WriteByte(' ')
	b.WriteString(r.Message)
	var host, rules string
	add := func(a slog.Attr) {
		v := a.Value.Resolve().String()
		switch a.Key {
		case "host":
			host = v
		case "rules":
			rules = v
		}
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(oneLine(v))
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		add(a)
		return true
	})
	s := h.shared
	if s.runLog != nil {
		s.runLog(b.String())
	}
	if r.Message != LogEgressRefused || host == "" || s.notices == nil {
		return nil
	}
	s.notices.refused(host, rules)
	return nil
}

// WithAttrs implements slog.Handler.
func (h *refusalHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &refusalHandler{shared: h.shared, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

// WithGroup implements slog.Handler; groups are flattened (the gateway logs
// none).
func (h *refusalHandler) WithGroup(string) slog.Handler { return h }

// oneLine keeps a value on one printable line: control characters (a name a
// box sent could carry an escape sequence) become "?", and it is capped.
func oneLine(s string) string {
	const max = 256
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
