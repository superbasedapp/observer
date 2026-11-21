//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_egress_refusal_linkloss_test.go pins what a run does when its
// relay link to the daemon is lost mid-run (tracker F-012, audit finding
// N4-A4): under require_refusal_audit its egress closes until the link is
// back; without it the run keeps its egress; either way the first report
// that gets through carries what was lost and closed, and the daemon adds
// it to the run's counts.

// linkMode is how a flakyLink answers a send.
type linkMode int

const (
	linkOK        linkMode = iota
	linkDialFails          // the daemon is gone (dial refused)
	linkTransport          // dialled, then EOF before any answer
	linkOther              // dialled, then a non-transport failure
)

// flakyLink is a send func whose link can be taken down and brought back.
type flakyLink struct {
	mu       sync.Mutex
	mode     linkMode
	attempts int
	sent     []sandboxrelay.EgressRefusalReport
}

func (l *flakyLink) set(m linkMode) {
	l.mu.Lock()
	l.mode = m
	l.mu.Unlock()
}

func (l *flakyLink) send(_ context.Context, rep sandboxrelay.EgressRefusalReport) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts++
	switch l.mode {
	case linkDialFails:
		return fmt.Errorf("reach the daemon: %w: connection refused", errEgressLinkDown)
	case linkTransport:
		return fmt.Errorf("relay round trip: %w", io.EOF)
	case linkOther:
		return errors.New("relay session: a non-transport failure")
	}
	l.sent = append(l.sent, rep)
	return nil
}

func (l *flakyLink) reports() []sandboxrelay.EgressRefusalReport {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]sandboxrelay.EgressRefusalReport(nil), l.sent...)
}

func (l *flakyLink) tries() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attempts
}

// reporterState reads the reporter's counts.
func reporterState(r *egressRefusalReporter) (down bool, lost, closed int, pending bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.down, r.lost, r.closed, r.pending != nil
}

// TestEgressRefusalLinkLoss is one row per case: whether the floor was in
// force at launch, how the link fails, and what the gateway and the first
// report after the outage see (audit findings N4-A4, FU5-A1, FU5-A2).
func TestEgressRefusalLinkLoss(t *testing.T) {
	old := egressRefusalRetry
	egressRefusalRetry = 20 * time.Millisecond
	defer func() { egressRefusalRetry = old }()
	cases := []struct {
		name       string
		required   bool
		mode       linkMode
		refusals   int
		wantClosed bool // new connections refused during the outage
		wantLost   int  // carried by the first report through, or counted
		pending    bool // a report waits to be retried
	}{
		{"floor, dial fails", true, linkDialFails, 3, true, 2, true},
		{"no floor, dial fails", false, linkDialFails, 3, false, 2, true},
		{"floor, transport breaks after the dial", true, linkTransport, 1, true, 0, true},
		{"no floor, transport breaks after the dial", false, linkTransport, 2, false, 2, false},
		{"floor, two non-transport failures stay up", true, linkOther, 2, false, 2, false},
		{"floor, three non-transport failures in a row mark it down", true, linkOther, 3, true, 2, true},
		{"no floor, non-transport failures never mark it down", false, linkOther, 3, false, 3, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			link := &flakyLink{}
			link.set(c.mode)
			r := newEgressRefusalReporter(ctx, link.send, c.required)
			at := time.Now()
			hosts := []string{"a.example", "b.example", "c.example"}[:c.refusals]
			for i, h := range hosts {
				r.Report(sandboxnet.Refusal{Host: h, Port: 443, Rule: sandboxnet.RefusalAllowListMiss, Key: sandboxnet.KeyEgressAllowHosts, At: at})
				// One at a time, so each send is judged in order: every
				// refusal ends either counted or waiting to be retried.
				waitForRefusal(t, func() bool {
					_, lost, _, pending := reporterState(r)
					return lost+boolInt(pending) == i+1
				})
			}
			_, lost, _, pending := reporterState(r)
			if pending != c.pending {
				t.Fatalf("pending %v, want %v", pending, c.pending)
			}
			reason := r.Closed()
			if got := reason != ""; got != c.wantClosed {
				t.Fatalf("new connections refused during the outage: %v, want %v", got, c.wantClosed)
			}
			if c.wantClosed && !strings.Contains(reason, `"Require refusal audit"`) {
				t.Fatalf("the reason does not name the floor: %s", reason)
			}
			link.set(linkOK)
			if !c.pending {
				if lost != c.wantLost {
					t.Fatalf("lost %d, want %d", lost, c.wantLost)
				}
				// Nothing waits: the next refusal carries the count.
				r.Report(sandboxnet.Refusal{Host: "d.example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: at})
			}
			waitForRefusal(t, func() bool { return len(link.reports()) >= 1 })
			first := link.reports()[0]
			wantClosed := boolInt(c.wantClosed)
			if first.Lost != c.wantLost || first.Closed != wantClosed {
				t.Fatalf("first report after the outage %+v, want lost %d closed %d", first, c.wantLost, wantClosed)
			}
			if r.Closed() != "" {
				t.Fatal("new connections still refused after the link is back")
			}
			if _, lost, closed, _ := reporterState(r); lost+closed != 0 {
				t.Fatalf("counts left after they were carried: lost %d closed %d", lost, closed)
			}
		})
	}
}

// TestEgressRefusalStaysPendingWhileDown (audit finding FU5-A1): under the
// floor, a retry that reaches the daemon but fails with a non-transport
// failure (a daemon still starting) keeps the report pending, so the run
// is not left refusing new connections for the rest of its life; the next
// retry that gets through reopens it.
func TestEgressRefusalStaysPendingWhileDown(t *testing.T) {
	old := egressRefusalRetry
	egressRefusalRetry = 20 * time.Millisecond
	defer func() { egressRefusalRetry = old }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	link := &flakyLink{}
	link.set(linkDialFails)
	r := newEgressRefusalReporter(ctx, link.send, true)
	r.Report(sandboxnet.Refusal{Host: "a.example", Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: time.Now()})
	waitForRefusal(t, func() bool { down, _, _, _ := reporterState(r); return down })
	link.set(linkOther)
	before := link.tries()
	waitForRefusal(t, func() bool { return link.tries() >= before+3 })
	if down, _, _, pending := reporterState(r); !down || !pending || r.Closed() == "" {
		t.Fatalf("a failed retry while down dropped the report or reopened: down %v pending %v", down, pending)
	}
	link.set(linkOK)
	waitForRefusal(t, func() bool { return r.Closed() == "" })
	if got := link.reports(); len(got) != 1 || got[0].Host != "a.example" {
		t.Fatalf("reports after the link came back: %+v", got)
	}
}

// TestEgressRefusalLocalFailureNeverMarksDown (audit finding FU5-R1): a
// report this helper cannot encode, or that its sender refuses as a schema
// error, is dropped and counted; it never counts toward marking the link
// down, so under the floor new connections stay allowed however many
// arrive. And a box naming a non-ASCII host gets its refusal delivered in
// the safe form (%XX), never an unencodable report.
func TestEgressRefusalLocalFailureNeverMarksDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var sent []sandboxrelay.EgressRefusalReport
	schema := true
	r := newEgressRefusalReporter(ctx, func(_ context.Context, rep sandboxrelay.EgressRefusalReport) error {
		mu.Lock()
		defer mu.Unlock()
		if schema {
			return fmt.Errorf("%w: encode: %w", sandboxrelayd.ErrEgressLocal, sandboxrelay.ErrHookSchema)
		}
		sent = append(sent, rep)
		return nil
	}, true)
	at := time.Now()
	for i, h := range []string{"a.example", "b.example", "c.example", "d.example"} {
		r.Report(sandboxnet.Refusal{Host: h, Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: at})
		waitForRefusal(t, func() bool { _, lost, _, _ := reporterState(r); return lost == i+1 })
	}
	r.mu.Lock()
	down, fails := r.down, r.fails
	r.mu.Unlock()
	if down || fails != 0 || r.Closed() != "" {
		t.Fatalf("a local failure touched the link: down %v fails %d", down, fails)
	}
	mu.Lock()
	schema = false
	mu.Unlock()
	// Three refusals of a UTF-8 host under the floor: each is delivered in
	// the safe form, nothing is dropped, the link stays up.
	for _, h := range []string{"\u00e9.example", "\u00e8.example", "\u00ea.example"} {
		r.Report(sandboxnet.Refusal{Host: h, Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: at})
	}
	waitForRefusal(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(sent) == 3 })
	mu.Lock()
	first := sent[0]
	mu.Unlock()
	if first.Host != "%C3%A9.example" || first.Lost != 4 || r.Closed() != "" {
		t.Fatalf("first report %+v (closed %q)", first, r.Closed())
	}
}

// TestEgressRefusalOutcomes is one case per row of egressRefusalOutcomes,
// plus the failures no row matches.
func TestEgressRefusalOutcomes(t *testing.T) {
	cases := []struct {
		name string
		f    egressRefusalFailure
		down bool
	}{
		{"the dial failed (no floor)", egressRefusalFailure{dial: true, fails: 1}, true},
		{"floor: a retry while down failed", egressRefusalFailure{required: true, down: true, fails: 1}, true},
		{"floor: the round trip broke after the dial", egressRefusalFailure{required: true, transport: true, fails: 1}, true},
		{"floor: consecutive failures", egressRefusalFailure{required: true, fails: egressRefusalDownAfter}, true},
		{"floor: one non-transport failure", egressRefusalFailure{required: true, fails: 1}, false},
		{"no floor: transport", egressRefusalFailure{transport: true, fails: 9}, false},
		{"no floor: a retry while down failed", egressRefusalFailure{down: true, fails: 9}, false},
	}
	for _, c := range cases {
		if got := egressRefusalMarksDown(c.f); got != c.down {
			t.Errorf("%s: marks down %v, want %v", c.name, got, c.down)
		}
	}
	for _, e := range []error{io.EOF, fmt.Errorf("x: %w", io.ErrUnexpectedEOF), context.DeadlineExceeded, fmt.Errorf("x: %w", syscall.ECONNRESET)} {
		if !egressTransportFailure(e) {
			t.Errorf("%v is not read as a transport failure", e)
		}
	}
	if egressTransportFailure(errors.New("relay session: a non-transport failure")) {
		t.Error("a non-transport failure was read as a transport failure")
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// TestEgressRefusalLinkLossLandsWithTheRun: the daemon's receiver writes a
// report's lost and closed counts against the run, beside its row.
func TestEgressRefusalLinkLossLandsWithTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &fakeRefusalStore{}
	r := newEgressRefusalReceiver(ctx, st, nil)
	run := sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1", RefusalAuditRequired: true}
	r.OnEgressRefusal(run, sandboxrelay.EgressRefusalReport{V: 1, Host: "c.example", Port: 443, Rule: "allow-list-miss", AtMS: time.Now().UnixMilli(), Lost: 2, Closed: 5})
	waitForRefusal(t, func() bool {
		l, c := st.linkLoss()
		return l["term-1"] == 2 && c["term-1"] == 5
	})
	waitForRefusal(t, func() bool { return len(st.all()) == 1 })
	if d, _ := st.dropCounts(); d["term-1"] != 0 {
		t.Fatalf("the link-lost refusals were also written as plain drops: %v", d)
	}
}
