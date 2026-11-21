//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_relaylog.go is the hosted run's kept relay log
// (lane SBX-UPD, finding H1 of P-103): a hosted box's in-box log is lost with
// the box, so a launch refused with "closed the relay stream without
// answering" left no reason anywhere. The home side of every hosted relay
// now keeps an owner-only, size-capped, redacted log per run at
// ~/.observer/sandbox-hosted/<run>/relay.log: each stream the home side
// refused or could not connect (and why), each line the guest relay sends
// for it (why it closed a box connection), the relay's starts, drops and
// re-opens, and the relay process's own stderr. It is kept after the box is
// deleted, like diff-errors.json, and `observer sandbox hosted status`
// lists it. The newest hostedRelayLogsKept logs are kept.

const (
	hostedRelayLogName = "relay.log"
	// hostedRelayLogMax caps one run's log; the line that reaches it says
	// so and nothing more is written.
	hostedRelayLogMax = 256 << 10
	// hostedRelayLineMax bounds one line.
	hostedRelayLineMax = 1024
	// hostedRelayLogsKept is how many runs' logs are kept.
	hostedRelayLogsKept = 20
)

// hostedRelayLogPath is one run's kept relay log.
func hostedRelayLogPath(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), runID, hostedRelayLogName)
}

// hostedRelayLog appends to one run's kept relay log. Every method is safe
// on a nil log (the log is best effort: a run never fails for it).
type hostedRelayLog struct {
	mu      sync.Mutex
	path    string
	secrets []string
	now     func() time.Time
	size    int64
	full    bool
	// pending holds a stderr line not yet ended by a newline.
	pending []byte
}

// openHostedRelayLog opens (creating owner-only) runID's relay log and
// prunes the oldest kept logs; nil when the run id or the directory is
// unusable.
func openHostedRelayLog(observerDir, runID string, secrets []string, now func() time.Time) *hostedRelayLog {
	if observerDir == "" || !sandboxrelay.ValidRunID(runID) {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	p := hostedRelayLogPath(observerDir, runID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil
	}
	l := &hostedRelayLog{path: p, secrets: secrets, now: now}
	if fi, err := os.Lstat(p); err == nil {
		if !fi.Mode().IsRegular() {
			return nil
		}
		l.size = fi.Size()
		l.full = l.size >= hostedRelayLogMax
	}
	pruneHostedRelayLogs(observerDir, runID)
	return l
}

// noteHostedRelayLog appends one line of the daemon's relay to runID's kept
// relay log (lane FX6, F-P7-5: a hook the daemon refused path_outside_run
// left no line there, though the box's answer points to it). The run's host
// helper owns the log; this is its one other feed path: an append to a log
// the helper already made (a run with no kept log, a local run, gets
// nothing, and nothing is created), within the same cap. The line carries
// the refusal's class, the payload key and the run, never a value.
func noteHostedRelayLog(observerDir, runID, msg string) {
	if observerDir == "" || !sandboxrelay.ValidRunID(runID) {
		return
	}
	p := hostedRelayLogPath(observerDir, runID)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	// The size is read again at the append (appendLocked), as both writers do.
	l := &hostedRelayLog{path: p, now: time.Now}
	l.line("the daemon's relay %s", msg)
}

// cleanRelayLine redacts the run's secrets, replaces control characters
// and bounds the length.
func cleanRelayLine(s string, secrets []string) string {
	s = sandboxremote.Redact(s, secrets)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		if b.Len()+len(string(r)) > hostedRelayLineMax {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// line appends one timestamped line.
func (l *hostedRelayLog) line(format string, a ...any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appendLocked(cleanRelayLine(fmt.Sprintf(format, a...), l.secrets))
}

// hostedRelayCapLine is the line that marks a full log (once).
const hostedRelayCapLine = "the relay log reached its cap; later lines are not kept"

// hostedRelayLineRoom is the most one appended line takes: the stamp, a
// space, a bounded line and its newline. A log with less room than that
// left under its cap is full (lane FX6, FX6-A6), so the cap line always
// fits and two writers racing the last append pass the cap by at most
// one line.
const hostedRelayLineRoom = len(time.RFC3339) + 1 + hostedRelayLineMax + 1

// appendLocked appends one line. The size is re-read from the file before
// every append (lane FX6, FX6-A6): the daemon's relay appends to the same
// log (noteHostedRelayLog), so a count kept by one writer misses the
// other's lines and the log passed its cap. The cap line is written once:
// a log that already ends with it gets no second one.
func (l *hostedRelayLog) appendLocked(msg string) {
	if l.full || msg == "" {
		return
	}
	l.size = 0
	if fi, err := os.Lstat(l.path); err == nil { //nolint:gosec // G703: a metadata read of the run's own log under ~/.observer/sandbox-hosted, run id shape-checked
		if !fi.Mode().IsRegular() {
			return
		}
		l.size = fi.Size()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return
	}
	stamp := l.now().UTC().Format(time.RFC3339)
	text := stamp + " " + msg + "\n"
	if l.size+int64(hostedRelayLineRoom) > hostedRelayLogMax {
		l.full = true
		if relayLogEndsCapped(l.path, l.size) {
			return
		}
		text = stamp + " " + hostedRelayCapLine + "\n"
	}
	f, err := openRelayLogAppend(l.path)
	if err != nil {
		return
	}
	n, _ := f.WriteString(text)
	_ = f.Close()
	l.size += int64(n)
}

// relayLogEndsCapped reports whether the log of the given size already
// ends with the cap line (written by either writer).
func relayLogEndsCapped(p string, size int64) bool {
	tail := int64(len(hostedRelayCapLine) + 1)
	if size < tail {
		return false
	}
	f, err := os.Open(p) //nolint:gosec // G304: the run's own log under ~/.observer/sandbox-hosted
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, size-tail); err != nil {
		return false
	}
	return string(buf) == hostedRelayCapLine+"\n"
}

// openRelayLogAppend opens the log for append, owner-only, never through a
// link.
func openRelayLogAppend(p string) (*os.File, error) {
	if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() { //nolint:gosec // G703: a metadata read of the run's own log under ~/.observer/sandbox-hosted, run id shape-checked
		return nil, errors.New("the relay log is not a regular file")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: the run's own log under ~/.observer/sandbox-hosted
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		_ = f.Chmod(0o600)
	}
	return f, nil
}

// Write takes the relay process's stderr: each line is kept, prefixed.
func (l *hostedRelayLog) Write(p []byte) (int, error) {
	if l == nil {
		return len(p), nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = append(l.pending, p...)
	for {
		i := bytes.IndexByte(l.pending, '\n')
		if i < 0 {
			break
		}
		l.appendLocked(cleanRelayLine("relay process stderr: "+string(l.pending[:i]), l.secrets))
		l.pending = l.pending[i+1:]
	}
	if len(l.pending) > hostedRelayLineMax {
		l.appendLocked(cleanRelayLine("relay process stderr: "+string(l.pending), l.secrets))
		l.pending = l.pending[:0]
	}
	return len(p), nil
}

// flush keeps a stderr line that never ended.
func (l *hostedRelayLog) flush() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pending) > 0 {
		l.appendLocked(cleanRelayLine("relay process stderr: "+string(l.pending), l.secrets))
		l.pending = nil
	}
}

// keptHostedRelayLog is one kept log the status lists.
type keptHostedRelayLog struct {
	RunID string
	Path  string
	At    time.Time
}

// hostedKeptRelayLogs lists the kept relay logs, newest first.
func hostedKeptRelayLogs(observerDir string) []keptHostedRelayLog {
	entries, err := os.ReadDir(hostedStateDir(observerDir))
	if err != nil {
		return nil
	}
	var out []keptHostedRelayLog
	for _, e := range entries {
		if !e.IsDir() || !sandboxrelay.ValidRunID(e.Name()) {
			continue
		}
		p := hostedRelayLogPath(observerDir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, keptHostedRelayLog{RunID: e.Name(), Path: p, At: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// pruneHostedRelayLogs removes the relay logs beyond the newest
// hostedRelayLogsKept (never keep's), and each emptied run directory. Only
// relay.log files are removed, never anything else in a directory.
func pruneHostedRelayLogs(observerDir, keep string) {
	logs := hostedKeptRelayLogs(observerDir)
	kept := 0
	for _, l := range logs {
		if l.RunID == keep || kept < hostedRelayLogsKept-1 {
			if l.RunID != keep {
				kept++
			}
			continue
		}
		_ = os.Remove(l.Path)
		_ = os.Remove(filepath.Dir(l.Path)) // only when empty
	}
}
