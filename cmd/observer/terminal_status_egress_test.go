//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termoob"
	"github.com/marmutapp/superbased-observer/internal/termstatus"
)

type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

// TestSandboxEgressReachesTheRunStatus pins N2's other half (Windows 11 Pro
// run 4): the egress refusals kept off the tool's screen reach the run's
// status. The host helper's uplink sends the count, publishOOB carries it
// into the feed, and the status hub folds it into the run's evidence.
func TestSandboxEgressReachesTheRunStatus(t *testing.T) {
	var wire bytes.Buffer
	up := newMXCOOBUplink(nopWriteCloser{&wire}, termoob.Hello{AuthToken: "tok", Tool: "claude-code"}, 1)
	up.egressRefused(8)
	up.egressRefused(16)
	var nilUp *mxcOOBUplink
	nilUp.egressRefused(3) // nil-safe

	feed := termfeed.New(termfeed.Options{})
	sub := feed.Subscribe()
	defer feed.Unsubscribe(sub)
	l := &ptyLauncher{feed: feed}
	dec := termoob.NewDecoder(&wire, "tok")
	for {
		f, err := dec.Read()
		if err != nil {
			break
		}
		l.publishOOB("run-1", "claude-code", f)
	}

	now := time.Now().UTC()
	h := &terminalStatusHub{
		lastActivity:   func(string) (time.Time, bool) { return now, true },
		exitStatus:     func(string) (bool, int, bool) { return false, 0, false },
		runIDForHandle: func(string) (string, bool) { return "run-1", true },
		th:             termstatus.Thresholds{},
		now:            func() time.Time { return now },
		sig:            map[string]*runSig{},
	}
	got := 0
	for done := false; !done; {
		select {
		case ev := <-sub.C():
			if ev.Kind == sandboxEgressKind {
				got++
			}
			h.ingest(ev)
		case <-time.After(200 * time.Millisecond):
			done = true
		}
	}
	if got != 2 {
		t.Fatalf("%d egress events reached the feed, want 2", got)
	}
	res, ok := h.compute("handle-1")
	if !ok {
		t.Fatal("no status")
	}
	if !strings.Contains(res.Evidence, "the sandbox blocked 16 connections") {
		t.Fatalf("evidence %q does not carry the held refusals", res.Evidence)
	}
	if withSandboxEgress("e", 0) != "e" || !strings.Contains(withSandboxEgress("e", 1), "1 connection (") {
		t.Fatal("withSandboxEgress")
	}
}
