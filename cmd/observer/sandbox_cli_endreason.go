//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// sandbox_cli_endreason.go names why a sandboxed CLI launch ended (Windows 11 Pro
// run 4, N3). A launch whose console window was closed with its X recorded
// exit code 1 with no reason, its exit line went to the closed window, and
// the daemon logged nothing. Now the first signal the launch got decides the
// reason (sandboxCLIEndReason), the run's row records it with the exit code
// (terminal_run.end_reason, an existing column), the CLI prints the reason's
// named line, and the CLI leaves a small end note the daemon turns into one
// log line (logSandboxCLIEnded), as it does for a run whose process is gone.

// sandboxCLIEndRows map the first signal a sandboxed CLI launch got to its
// end reason, walked top-down; goos "" matches every OS. On Windows the
// runtime turns a console window's close (CTRL_CLOSE_EVENT), a log off and a
// shutdown into SIGTERM; a POSIX terminal that closes sends SIGHUP, and a
// SIGTERM there comes from outside. A daemon end request also arrives as
// SIGHUP, but its own reason is taken first (sandboxCLIEndReason).
var sandboxCLIEndRows = []struct {
	goos   string
	sig    os.Signal
	reason string
}{
	{"windows", syscall.SIGTERM, termrun.EndConsoleClosed},
	{"", syscall.SIGHUP, termrun.EndConsoleClosed},
	{"", syscall.SIGTERM, termrun.EndStoppedOutside},
}

// sandboxCLIEndReason is the reason a sandboxed CLI launch's end records:
// the reason a daemon end request named, else the first signal's row, else
// what the exit code alone says (termrun.EndReasonForExit).
func sandboxCLIEndReason(goos, requested string, sig os.Signal, code int) string {
	if requested != "" {
		return requested
	}
	if sig != nil {
		for _, r := range sandboxCLIEndRows {
			if (r.goos == "" || r.goos == goos) && r.sig == sig {
				return r.reason
			}
		}
	}
	return termrun.EndReasonForExit(code)
}

// sandboxCLISignals passes every signal from in on to ch and keeps the
// first one, so the launch's end can be named after the child is gone.
type sandboxCLISignals struct {
	ch   chan os.Signal
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	got  os.Signal
}

// recordSandboxCLISignals starts passing in on; stop ends it.
func recordSandboxCLISignals(in <-chan os.Signal) *sandboxCLISignals {
	s := &sandboxCLISignals{ch: make(chan os.Signal, 4), done: make(chan struct{})}
	go func() {
		for {
			select {
			case <-s.done:
				return
			case sig := <-in:
				s.mu.Lock()
				if s.got == nil {
					s.got = sig
				}
				s.mu.Unlock()
				select {
				case s.ch <- sig:
				case <-s.done:
					return
				}
			}
		}
	}()
	return s
}

// first is the first signal seen (nil for none).
func (s *sandboxCLISignals) first() os.Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}

// stop ends the passing on (idempotent).
func (s *sandboxCLISignals) stop() { s.once.Do(func() { close(s.done) }) }

// sandboxCLIEnded is a CLI launch's end note for the daemon's log.
type sandboxCLIEnded struct {
	V         int    `json:"v"`
	EndReason string `json:"end_reason"`
	ExitCode  int    `json:"exit_code"`
}

// sandboxCLIEndedSuffix names an end note: <run id>.ended in the cli-end
// directory beside the watch markers (owner-only, under the relay's
// directory; a box cannot reach it).
const sandboxCLIEndedSuffix = ".ended"

// sandboxCLIEndedMax bounds an end note read.
const sandboxCLIEndedMax = 4 << 10

// writeSandboxCLIEnded leaves runID's end note for the daemon (best effort:
// the run's row is the record; the note only feeds the daemon's log line).
func writeSandboxCLIEnded(observerDir, runID, reason string, exit int) {
	if observerDir == "" || !sandboxCLIRunIDRE.MatchString(runID) {
		return
	}
	dir := sandboxCLIEndDir(observerDir)
	if err := mkdirSandboxOwned(dir); err != nil {
		return
	}
	b, err := json.Marshal(sandboxCLIEnded{V: 1, EndReason: reason, ExitCode: exit})
	if err != nil {
		return
	}
	p := filepath.Join(dir, runID+sandboxCLIEndedSuffix)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name under the observer's relay directory, run id shape-checked
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = ownSandboxRecord(p)
	}
	if werr != nil {
		_ = os.Remove(p)
	}
}

// readSandboxCLIEnded reads one end note: a regular file, capped, one note.
func readSandboxCLIEnded(p string) (sandboxCLIEnded, bool) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > sandboxCLIEndedMax {
		return sandboxCLIEnded{}, false
	}
	f, err := os.Open(p) //nolint:gosec // G304: an end note under the observer's relay directory, lstat-checked regular and capped
	if err != nil {
		return sandboxCLIEnded{}, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, sandboxCLIEndedMax))
	if err != nil {
		return sandboxCLIEnded{}, false
	}
	var e sandboxCLIEnded
	if json.Unmarshal(b, &e) != nil || e.V != 1 {
		return sandboxCLIEnded{}, false
	}
	return e, true
}

// logSandboxCLIEnded logs one daemon line for each end note in observerDir
// and removes it; it returns how many it logged. A note that cannot be read
// is removed with a line saying so; a reason outside the vocabulary is
// logged as "unknown".
func logSandboxCLIEnded(observerDir string, logger *slog.Logger) int {
	dir := sandboxCLIEndDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && logger != nil {
			logger.Warn("terminal: read the sandboxed CLI end notes", "err", err)
		}
		return 0
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		runID, ok := strings.CutSuffix(name, sandboxCLIEndedSuffix)
		if !ok || !sandboxCLIRunIDRE.MatchString(runID) {
			continue
		}
		p := filepath.Join(dir, name)
		note, ok := readSandboxCLIEnded(p)
		_ = os.Remove(p)
		if logger == nil {
			continue
		}
		if !ok {
			logger.Warn("terminal: a sandboxed CLI run ended; its end note could not be read", "run", runID)
			continue
		}
		reason := note.EndReason
		if !termrun.KnownEndReason(reason) {
			reason = "unknown"
		}
		logger.Info("terminal: ended a sandboxed CLI run", "run", runID, "end_reason", reason, "exit_code", note.ExitCode)
		n++
	}
	return n
}

// sandboxCLIEndedPoll is how often the daemon reads the end notes.
var sandboxCLIEndedPoll = 5 * time.Second

// startSandboxCLIEndLog logs the end notes now and every sandboxCLIEndedPoll
// until ctx ends (a relay start hook, so it runs where the relay serves
// sandboxed CLI launches).
func startSandboxCLIEndLog(ctx context.Context, observerDir string, logger *slog.Logger) {
	logSandboxCLIEnded(observerDir, logger)
	go func() {
		t := time.NewTicker(sandboxCLIEndedPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				logSandboxCLIEnded(observerDir, logger)
			}
		}
	}()
}

func init() { sandboxRelayStartHooks = append(sandboxRelayStartHooks, startSandboxCLIEndLog) }
