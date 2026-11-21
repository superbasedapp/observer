//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// terminal_sandbox_hosted_ptyend.go says which side ended a hosted run's
// agent stream when the agent ran on a PTY the in-box helper owns (live run
// 2026-11-19, defect D7: five of eight Daytona runs ended on their own, four
// with "exit 255", and nothing said whether the agent, Observer's helper in
// the box, or the provider ended them, because the helper's stderr was
// thrown away). The helper sends an end record (guestPTYEndRecord) on the
// mux and on its stderr; this collector keeps both in the run's relay log
// and the end compares it with what the provider reported.

// hostedPTYEnd collects the in-box PTY helper's stderr and log lines.
type hostedPTYEnd struct {
	log     *hostedRelayLog
	mu      sync.Mutex
	pending []byte
	record  string
}

// Write takes the helper's stderr, one kept line per line.
func (e *hostedPTYEnd) Write(p []byte) (int, error) {
	e.mu.Lock()
	e.pending = append(e.pending, p...)
	var lines []string
	for {
		i := bytes.IndexByte(e.pending, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, string(e.pending[:i]))
		e.pending = e.pending[i+1:]
	}
	if len(e.pending) > hostedRelayLineMax {
		lines = append(lines, string(e.pending))
		e.pending = e.pending[:0]
	}
	e.mu.Unlock()
	for _, l := range lines {
		e.note("PTY helper stderr: " + l)
	}
	return len(p), nil
}

// note keeps one line, remembering the helper's end record.
func (e *hostedPTYEnd) note(line string) {
	if i := strings.Index(line, relaymux.PTYEndPrefix); i >= 0 {
		e.mu.Lock()
		e.record = strings.TrimSpace(line[i+len(relaymux.PTYEndPrefix):])
		e.mu.Unlock()
	}
	e.log.line("%s", line)
}

// endRecord is the helper's end record ("" when none came).
func (e *hostedPTYEnd) endRecord() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.record
}

// hostedPTYEndFacts are what the home side knows when the agent's stream
// ended.
type hostedPTYEndFacts struct {
	Vendor string
	Code   int
	// WaitErr: the stream ended without an exit status.
	WaitErr error
	// Record is the in-box helper's end record ("" when none came).
	Record string
	// MuxErr is why the home side's mux session ended (nil: it was still
	// up).
	MuxErr error
	// Quiet is how long ago the box's last frame arrived.
	Quiet time.Duration
}

// hostedPTYEndAttribution is the run-log line and, for an exit the agent
// did not report itself, the terminal line that say which side ended the
// agent's stream. The rules, in order: no exit status (the cut, said by
// cutStream); the helper's record present (it is the truth from the box);
// a clean exit with no record (an older helper); an exit status with no
// record (the provider's side reported it, not the agent).
func hostedPTYEndAttribution(f hostedPTYEndFacts) (logLine, say string) {
	mux := "the home side's mux was still up"
	switch {
	case f.MuxErr == nil, errors.Is(f.MuxErr, relaymux.ErrClosed):
	case errors.Is(f.MuxErr, io.EOF):
		mux = "the box closed the mux stream"
	default:
		mux = "the home side's mux had ended: " + f.MuxErr.Error()
	}
	quiet := fmt.Sprintf("the box's last frame came %s before", f.Quiet)
	switch {
	case f.WaitErr != nil:
		return fmt.Sprintf("the agent's stream ended without an exit status (%v); %s; %s", f.WaitErr, mux, quiet), ""
	case f.Record != "":
		line := fmt.Sprintf("the agent's stream ended with exit %d; the box's helper says: %s; %s; %s", f.Code, f.Record, mux, quiet)
		if strings.Contains(f.Record, "hung up the agent") {
			return line, "Observer's helper in the box lost its session to this machine and hung up the agent: " + f.Record
		}
		return line, ""
	case f.Code == 0:
		return fmt.Sprintf("the agent's stream ended with exit 0 and no end record from the box's helper; %s; %s", mux, quiet), ""
	}
	return fmt.Sprintf("the agent's stream ended with exit %d reported by %s, and the box's helper sent no end record: the provider's side ended the session, not the agent; %s; %s", f.Code, f.Vendor, mux, quiet),
		fmt.Sprintf("%s ended the agent's stream with exit %d, but Observer's helper in the box reported no exit of the agent: the provider's side ended the session (details in the run's relay log)", f.Vendor, f.Code)
}

// hostedPTYRecordWait bounds the wait for the helper's last mux frames
// after the provider reported the exit (a variable for tests).
var hostedPTYRecordWait = time.Second

// redactPTYEnd redacts the run's secrets from a line.
func (r *hostedRun) redactPTYEnd(s string) string {
	return sandboxremote.Redact(s, r.cred.Secrets())
}

// attributePTYEnd logs which side ended the agent's guest-PTY stream and,
// when the provider reported an exit the box's helper did not, says so on
// the terminal (D7). It waits a moment for the helper's last mux frames.
func (r *hostedRun) attributePTYEnd(h *relaymux.Host, pend *hostedPTYEnd, code int, werr error) {
	select {
	case <-h.Done():
	case <-time.After(hostedPTYRecordWait):
	}
	var waitErr error
	if werr != nil {
		waitErr = errors.New(r.redactPTYEnd(werr.Error()))
	}
	logLine, say := hostedPTYEndAttribution(hostedPTYEndFacts{
		Vendor: r.vendor.Name, Code: code, WaitErr: waitErr, Record: pend.endRecord(),
		MuxErr: h.Err(), Quiet: h.SinceLastFrame(),
	})
	r.rlog().line("%s", logLine)
	r.rlog().flush()
	if say != "" {
		r.say("%s", r.redactPTYEnd(say))
	}
}
