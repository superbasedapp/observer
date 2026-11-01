package captureprogress

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// EventKind is one thing the watcher reports about a capture walk.
type EventKind uint8

// The event kinds, in the order a walk produces them.
const (
	// ScanStarted: the daemon's initial full scan began.
	ScanStarted EventKind = iota + 1
	// WalkStarted: the walk of one tool's session store began (one per
	// tool in the initial scan; one per new root for a store that appears
	// after start).
	WalkStarted
	// FileFound: the walk found one session file it will hand over.
	FileFound
	// FileProcessed: one found file was read and ingested.
	FileProcessed
	// FileFailed: one found file could not be read; Event.Err says why.
	FileFailed
	// WalkFinished: the walk found every file it will hand over (the found
	// count for this walk is final; reading may still be under way).
	WalkFinished
	// ScanFinished: the initial full scan returned; Event.Cancelled is set
	// when it stopped early (the daemon shutting down).
	ScanFinished
)

// Event is one report from the watcher.
type Event struct {
	Kind EventKind
	// Tool is the adapter name (empty for the scan-level kinds).
	Tool string
	// Err is a short failure text (FileFailed only).
	Err string
	// Cancelled marks a ScanFinished that stopped before the end.
	Cancelled bool
}

// ScanState is the overall capture state.
type ScanState string

// The overall states.
const (
	// ScanIdle: nothing has been reported yet (the watcher has not started,
	// or this process runs no watcher).
	ScanIdle ScanState = "idle"
	// ScanRunning: at least one walk is still finding or reading files.
	ScanRunning ScanState = "scanning"
	// ScanDone: every walk finished.
	ScanDone ScanState = "done"
	// ScanStopped: the initial scan stopped before the end; the next daemon
	// start picks it up where the saved cursors left it.
	ScanStopped ScanState = "stopped"
)

// ToolState is one tool's capture state.
type ToolState string

// The per-tool states.
const (
	ToolScanning ToolState = "scanning"
	ToolDone     ToolState = "done"
	ToolFailed   ToolState = "failed"
	ToolStopped  ToolState = "stopped"
)

// ToolProgress is one tool's counts and state in a Snapshot.
type ToolProgress struct {
	Tool           string
	State          ToolState
	Reason         string
	FilesFound     int
	FilesProcessed int
	FilesFailed    int
	StartedAt      time.Time
	FinishedAt     time.Time
}

// Snapshot is a plain copy of the model at one instant.
type Snapshot struct {
	State          ScanState
	StartedAt      time.Time
	FinishedAt     time.Time
	FilesFound     int
	FilesProcessed int
	FilesFailed    int
	// Tools is sorted by tool name.
	Tools []ToolProgress
}

// Tool returns the progress of one tool, if any walk of it was reported.
func (s Snapshot) Tool(name string) (ToolProgress, bool) {
	for _, t := range s.Tools {
		if t.Tool == name {
			return t, true
		}
	}
	return ToolProgress{}, false
}

// maxReason bounds the failure text carried into a Snapshot.
const maxReason = 160

type toolCounts struct {
	found, processed, failed int
	// walking is the number of this tool's walks that have not reported
	// WalkFinished yet.
	walking    int
	lastErr    string
	startedAt  time.Time
	finishedAt time.Time
}

// Tracker accumulates Events. The zero value is not usable; use New. A nil
// *Tracker accepts Record and returns an idle Snapshot, so the watcher can
// call it unconditionally.
type Tracker struct {
	now func() time.Time

	mu         sync.Mutex
	started    bool
	finished   bool
	cancelled  bool
	startedAt  time.Time
	finishedAt time.Time
	tools      map[string]*toolCounts
}

// New returns an empty tracker. now is the clock (nil means time.Now).
func New(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{now: now, tools: map[string]*toolCounts{}}
}

// Record applies one event. Unknown kinds and tool events without a tool
// name are ignored. Safe for concurrent use.
func (t *Tracker) Record(ev Event) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	switch ev.Kind {
	case ScanStarted:
		if !t.started {
			t.started = true
			t.startedAt = now
		}
		t.finished, t.cancelled = false, false
		t.finishedAt = time.Time{}
		return
	case ScanFinished:
		t.finished = true
		t.cancelled = ev.Cancelled
		t.finishedAt = now
		return
	}
	if ev.Tool == "" {
		return
	}
	c := t.tools[ev.Tool]
	if c == nil {
		if ev.Kind != WalkStarted {
			// A file event for a tool whose walk was never announced is a
			// wiring slip; count it anyway rather than lose it.
			c = &toolCounts{startedAt: now}
		} else {
			c = &toolCounts{}
		}
		t.tools[ev.Tool] = c
	}
	switch ev.Kind {
	case WalkStarted:
		if c.walking == 0 && c.found == c.processed+c.failed {
			// A fresh walk of a tool whose earlier work is complete
			// (a hot-added root) re-opens it.
			c.finishedAt = time.Time{}
		}
		if c.startedAt.IsZero() {
			c.startedAt = now
		}
		c.walking++
	case FileFound:
		c.found++
	case FileProcessed:
		c.processed++
	case FileFailed:
		c.failed++
		if msg := strings.TrimSpace(ev.Err); msg != "" {
			c.lastErr = truncate(msg, maxReason)
		}
	case WalkFinished:
		if c.walking > 0 {
			c.walking--
		}
	default:
		return
	}
	if c.walking == 0 && c.found <= c.processed+c.failed && c.finishedAt.IsZero() {
		c.finishedAt = now
	}
}

// Snapshot returns a copy of the model. A nil tracker is idle.
func (t *Tracker) Snapshot() Snapshot {
	if t == nil {
		return Snapshot{State: ScanIdle}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := Snapshot{StartedAt: t.startedAt, FinishedAt: t.finishedAt}
	names := make([]string, 0, len(t.tools))
	for name := range t.tools {
		names = append(names, name)
	}
	sort.Strings(names)
	anyOpen := false
	for _, name := range names {
		c := t.tools[name]
		f := toolFacts{
			found: c.found, processed: c.processed, failed: c.failed,
			walking: c.walking, lastErr: c.lastErr,
			stopped: t.finished && t.cancelled,
		}
		state, reason := decideTool(f)
		if state == ToolScanning {
			anyOpen = true
		}
		tp := ToolProgress{
			Tool: name, State: state, Reason: reason,
			FilesFound: c.found, FilesProcessed: c.processed, FilesFailed: c.failed,
			StartedAt: c.startedAt,
		}
		if state != ToolScanning {
			tp.FinishedAt = c.finishedAt
		}
		out.Tools = append(out.Tools, tp)
		out.FilesFound += c.found
		out.FilesProcessed += c.processed
		out.FilesFailed += c.failed
	}
	out.State = decideScan(scanFacts{
		started: t.started, finished: t.finished, cancelled: t.cancelled,
		anyTool: len(names) > 0, anyOpen: anyOpen,
	})
	if out.State == ScanRunning {
		out.FinishedAt = time.Time{}
	}
	return out
}

// toolFacts is what the per-tool rules read.
type toolFacts struct {
	found, processed, failed, walking int
	lastErr                           string
	// stopped: the initial scan was cancelled.
	stopped bool
}

func (f toolFacts) pending() bool { return f.walking > 0 || f.processed+f.failed < f.found }

// toolStateRules is the ordered decision table for one tool's state: the
// first row whose when holds decides.
var toolStateRules = []struct {
	name   string
	when   func(f toolFacts) bool
	state  ToolState
	reason func(f toolFacts) string
}{
	{
		name:  "stopped before finishing",
		when:  func(f toolFacts) bool { return f.stopped && f.pending() },
		state: ToolStopped,
		reason: func(toolFacts) string {
			return "The daemon stopped before this finished. It continues on the next start."
		},
	},
	{
		name:  "still finding or reading files",
		when:  toolFacts.pending,
		state: ToolScanning,
	},
	{
		name:  "every file failed",
		when:  func(f toolFacts) bool { return f.failed > 0 && f.processed == 0 },
		state: ToolFailed,
		reason: func(f toolFacts) string {
			msg := fmt.Sprintf("Could not read %s.", plural(f.failed, "file"))
			if f.lastErr != "" {
				msg += " Last error: " + f.lastErr
			}
			return msg
		},
	},
	{
		name:  "some files failed",
		when:  func(f toolFacts) bool { return f.failed > 0 },
		state: ToolDone,
		reason: func(f toolFacts) string {
			return fmt.Sprintf("%d of %s could not be read.", f.failed, plural(f.found, "file"))
		},
	},
	{
		name:  "finished",
		when:  func(toolFacts) bool { return true },
		state: ToolDone,
	},
}

func decideTool(f toolFacts) (ToolState, string) {
	for _, r := range toolStateRules {
		if !r.when(f) {
			continue
		}
		if r.reason == nil {
			return r.state, ""
		}
		return r.state, r.reason(f)
	}
	return ToolDone, ""
}

// scanFacts is what the overall rules read.
type scanFacts struct {
	started, finished, cancelled bool
	anyTool, anyOpen             bool
}

// scanStateRules is the ordered decision table for the overall state.
var scanStateRules = []struct {
	name  string
	when  func(f scanFacts) bool
	state ScanState
}{
	{"nothing reported", func(f scanFacts) bool { return !f.started && !f.anyTool }, ScanIdle},
	{"stopped early", func(f scanFacts) bool { return f.finished && f.cancelled }, ScanStopped},
	{"initial scan running", func(f scanFacts) bool { return f.started && !f.finished }, ScanRunning},
	{"a walk is still open", func(f scanFacts) bool { return f.anyOpen }, ScanRunning},
	{"everything finished", func(scanFacts) bool { return true }, ScanDone},
}

func decideScan(f scanFacts) ScanState {
	for _, r := range scanStateRules {
		if r.when(f) {
			return r.state
		}
	}
	return ScanDone
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}
