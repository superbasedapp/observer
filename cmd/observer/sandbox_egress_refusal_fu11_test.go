//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fu11Report is one valid report of host h.
func fu11Report(h string) sandboxrelay.EgressRefusalReport {
	return egressRefusalReport(sandboxnet.Refusal{Host: h, Port: 443, Rule: sandboxnet.RefusalAllowListMiss, At: time.Now()})
}

// TestEgressRefusalDeliverF037 is one case per F-037 rule of deliver, each
// driven synchronously on a reporter with no sender goroutine: a local
// failure (before anything is sent) leaves the report already pending and
// the link as it was; a schema error after the send (the daemon's answer
// does not decode) is a failure of the round trip, counted toward the link.
func TestEgressRefusalDeliverF037(t *testing.T) {
	errDial := fmt.Errorf("reach the daemon: %w", errEgressLinkDown)
	errLocal := fmt.Errorf("%w: encode: %w", sandboxrelayd.ErrEgressLocal, sandboxrelay.ErrHookSchema)
	errAnswer := fmt.Errorf("relay answer: %w", sandboxrelay.ErrHookSchema)
	bad := fu11Report("b.example")
	bad.Port = 70000 // the pre-send encoder refuses it
	for _, tc := range []struct {
		name     string
		required bool
		down     bool // start with the link down and report a.example pending
		rep      sandboxrelay.EgressRefusalReport
		err      error
		// want
		wantDown    bool
		wantPending string // the pending report's host, "" none
		wantLost    int
		wantFails   int
	}{
		{"pre-send encode failure while down keeps the prior report pending", true, true, bad, nil, true, "a.example", 1, 0},
		{"sender local failure while down keeps the prior report pending", true, true, fu11Report("b.example"), errLocal, true, "a.example", 1, 0},
		{"sender local failure while up never touches the link", true, false, fu11Report("b.example"), errLocal, false, "", 1, 0},
		{"answer decode failure while down: still down, the new report pending", true, true, fu11Report("b.example"), errAnswer, true, "b.example", 1, 1},
		{"answer decode failure under the floor is a counted link failure", true, false, fu11Report("b.example"), errAnswer, false, "", 1, 1},
		{"answer decode failure without the floor: counted, not retried", false, false, fu11Report("b.example"), errAnswer, false, "", 1, 1},
		{"dial failure while down replaces the pending report", true, true, fu11Report("b.example"), errDial, true, "b.example", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent := 0
			r := &egressRefusalReporter{required: tc.required, send: func(context.Context, sandboxrelay.EgressRefusalReport) error {
				sent++
				return tc.err
			}}
			if tc.down {
				p := fu11Report("a.example")
				r.down, r.pending = true, &p
			}
			r.deliver(context.Background(), tc.rep)
			pending := ""
			if r.pending != nil {
				pending = r.pending.Host
			}
			if r.down != tc.wantDown || pending != tc.wantPending || r.lost != tc.wantLost || r.fails != tc.wantFails {
				t.Fatalf("down %v pending %q lost %d fails %d, want %v %q %d %d", r.down, pending, r.lost, r.fails, tc.wantDown, tc.wantPending, tc.wantLost, tc.wantFails)
			}
		})
	}
}

// TestEgressRefusalLocalFailureWhileDownReopens is the F-037 outage end to
// end: under the floor the link goes down with a report pending, a local
// failure arrives while it is down, and when the link is back the pending
// report gets through and egress reopens (before the fix the local failure
// cleared the pending report and the run refused egress for good).
func TestEgressRefusalLocalFailureWhileDownReopens(t *testing.T) {
	mode := "dial"
	var sent []sandboxrelay.EgressRefusalReport
	r := &egressRefusalReporter{required: true, send: func(_ context.Context, rep sandboxrelay.EgressRefusalReport) error {
		switch mode {
		case "dial":
			return fmt.Errorf("reach the daemon: %w", errEgressLinkDown)
		case "local":
			return fmt.Errorf("%w: encode", sandboxrelayd.ErrEgressLocal)
		}
		sent = append(sent, rep)
		return nil
	}}
	ctx := context.Background()
	r.deliver(ctx, fu11Report("a.example"))
	if !r.down || r.Closed() == "" {
		t.Fatal("the failed dial did not close egress under the floor")
	}
	mode = "local"
	r.deliver(ctx, fu11Report("b.example"))
	if r.pending == nil {
		t.Fatal("a local failure while down left nothing to retry")
	}
	mode = "ok"
	r.deliver(ctx, *r.pending) // the retry tick
	if r.down || r.Closed() != "" {
		t.Fatal("egress did not reopen when the link came back")
	}
	if len(sent) != 1 || sent[0].Host != "a.example" || sent[0].Lost != 1 || sent[0].Closed != 1 {
		t.Fatalf("reports after the outage: %+v", sent)
	}
}

// TestEgressRefusalReceiverCountsBeforeRowCheck pins F-038: the lost and
// closed counts a report carries are kept under the run's id even when the
// row itself is rejected (a rule outside this daemon's vocabulary), since
// the daemon answers the report OK and the helper subtracts them.
func TestEgressRefusalReceiverCountsBeforeRowCheck(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		run       sandboxrelayd.RunRecord
		rule      string
		lost      int
		closed    int
		wantCount egressRefusalDropCount
		wantKey   string
		wantRow   bool
	}{
		{"rejected row keeps its counts", sandboxrelayd.RunRecord{RunID: "relaySENTINEL", TerminalRunID: "termSENTINEL"}, "rule-from-a-newer-helper", 2, 1, egressRefusalDropCount{LinkLost: 2, Closed: 1}, "termSENTINEL", false},
		{"valid row: counts and row", sandboxrelayd.RunRecord{RunID: "relaySENTINEL"}, string(sandboxnet.RefusalAllowListMiss), 3, 0, egressRefusalDropCount{LinkLost: 3}, "relaySENTINEL", true},
		{"rejected row with no counts: nothing", sandboxrelayd.RunRecord{RunID: "relaySENTINEL"}, "rule-from-a-newer-helper", 0, 0, egressRefusalDropCount{}, "relaySENTINEL", false},
		{"no run id: nothing", sandboxrelayd.RunRecord{}, string(sandboxnet.RefusalAllowListMiss), 2, 0, egressRefusalDropCount{}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &egressRefusalReceiver{
				lim: sandboxnet.NewRefusalLimiter(0), ch: make(chan store.SandboxEgressRefusal, 4),
				drops: map[string]egressRefusalDropCount{}, dropKick: make(chan struct{}, 1),
				now: func() time.Time { return now },
			}
			r.OnEgressRefusal(tc.run, sandboxrelay.EgressRefusalReport{Host: "refused.invalid", Port: 80, Rule: tc.rule, AtMS: now.UnixMilli(), Lost: tc.lost, Closed: tc.closed})
			if got := r.drops[tc.wantKey]; got != tc.wantCount {
				t.Fatalf("counts under %q = %+v, want %+v (all %+v)", tc.wantKey, got, tc.wantCount, r.drops)
			}
			if got := len(r.ch) == 1; got != tc.wantRow {
				t.Fatalf("row queued %v, want %v", got, tc.wantRow)
			}
		})
	}
}
