package sandboxnet

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakeTUI is a full-screen tool's first screen as a terminal receives it:
// the alternate screen, a cleared page, Claude Code's folder trust dialog and
// the cursor parked on the "No, exit" row (Windows 11 Pro run 4, N2).
const fakeTUI = "\x1b[?1049h\x1b[2J\x1b[H" +
	"Accessing workspace:\r\n\r\n C:\\work\r\n\r\n" +
	" Quick safety check: Is this a project you created or one you trust?\r\n\r\n" +
	" > No, exit\r\n   Yes, I trust this folder\r\n\r\n Enter to confirm\x1b[7;3H"

// TestTerminalNotices_NeverDrawIntoARunningTUI pins N2: once the tool has
// started, a refusal never reaches its terminal (the stream is the TUI's
// bytes only, so both trust choices stay visible); the run log gets every
// record, the run's status gets the count, and after the tool exits one
// summary line is printed. A refusal before the tool starts is still shown.
func TestTerminalNotices_NeverDrawIntoARunningTUI(t *testing.T) {
	t.Parallel()
	var term bytes.Buffer
	var mu sync.Mutex
	var runLog []string
	var status []int
	n := NewTerminalNotices(&term)
	n.OnHeld(func(total int) { status = append(status, total) })
	l := RefusalLoggerTo(func(s string) { mu.Lock(); runLog = append(runLog, s); mu.Unlock() }, n)

	l.Warn(LogEgressRefused, "host", "pre.example", "port", 443, "rules", RuleHostNotListed)
	pre := term.String()
	if pre != "\r\nobserver sandbox: blocked pre.example (host-not-listed)\r\n" {
		t.Fatalf("before the tool starts the notice is shown; got %q", pre)
	}

	n.ToolStarted()
	term.WriteString(fakeTUI)
	for i := 0; i < 16; i++ {
		l.Warn(LogEgressRefused, "host", "api.anthropic.com", "port", 443, "rules", RuleModelProviderHost)
	}
	l.Warn(LogEgressRefused, "host", "statsig.example", "port", 443, "rules", RuleHostNotListed)
	if got := term.String(); got != pre+fakeTUI {
		t.Fatalf("a notice reached the running TUI:\n got %q\nwant %q", got, pre+fakeTUI)
	}
	if !strings.Contains(term.String(), "Yes, I trust this folder") || strings.Count(term.String(), "observer sandbox") != 1 {
		t.Fatalf("screen %q", term.String())
	}
	if n.Held() != 17 {
		t.Fatalf("held %d, want 17", n.Held())
	}
	if !reflect.DeepEqual(status, []int{1, 2, 4, 8, 16}) {
		t.Fatalf("status reports %v, want 1 2 4 8 16 (doubling, never one per refusal)", status)
	}

	term.WriteString("\x1b[?1049l")
	n.Finish()
	tail := strings.TrimPrefix(term.String(), pre+fakeTUI+"\x1b[?1049l")
	want := "\r\nobserver sandbox: 17 connections were blocked while the tool ran: api.anthropic.com (model-provider-host), statsig.example (host-not-listed)\r\n"
	if tail != want {
		t.Fatalf("summary %q, want %q", tail, want)
	}
	if !reflect.DeepEqual(status, []int{1, 2, 4, 8, 16, 17}) {
		t.Fatalf("status after Finish %v, want the final count once", status)
	}
	if len(runLog) != 18 {
		t.Fatalf("run log has %d lines, want every record (18)", len(runLog))
	}
	n.Finish()
	if strings.Count(term.String(), "were blocked") != 1 {
		t.Fatalf("Finish printed twice: %q", term.String())
	}
}

// TestTerminalNotices_SummaryNamesAtMostThreeHosts keeps the summary one
// short line.
func TestTerminalNotices_SummaryNamesAtMostThreeHosts(t *testing.T) {
	t.Parallel()
	var term bytes.Buffer
	n := NewTerminalNotices(&term)
	l := RefusalLoggerTo(nil, n)
	n.ToolStarted()
	for _, h := range []string{"a.example", "b.example", "c.example", "d.example", "e\x1b[2J.example"} {
		l.Warn(LogEgressRefused, "host", h, "rules", RuleHostNotListed)
	}
	if term.Len() != 0 {
		t.Fatalf("printed while the tool ran: %q", term.String())
	}
	n.Finish()
	got := term.String()
	if !strings.Contains(got, "5 connections were blocked") || !strings.Contains(got, "and 2 more host(s)") || strings.Contains(got, "d.example") {
		t.Fatalf("summary %q", got)
	}
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("an escape reached the terminal: %q", got)
	}
}

// TestTerminalNotices_NothingHeldNothingPrinted: a run with no refusal while
// the tool ran prints no summary.
func TestTerminalNotices_NothingHeldNothingPrinted(t *testing.T) {
	t.Parallel()
	var term bytes.Buffer
	called := false
	n := NewTerminalNotices(&term)
	n.OnHeld(func(int) { called = true })
	n.ToolStarted()
	n.Finish()
	if term.Len() != 0 || called {
		t.Fatalf("printed %q, status called %v", term.String(), called)
	}
	var nilN *TerminalNotices
	nilN.ToolStarted()
	nilN.Finish()
	if nilN.Held() != 0 {
		t.Fatal("nil notices hold nothing")
	}
}
