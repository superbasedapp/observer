//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_egress_refusal_report.go is the host helper's side of the egress
// refusal audit (OpenShell build plan 05 section 3.1, lane N1). The run's
// gateway reports each refusal to Report; the helper bounds them (one per
// host per minute, sandboxnet.RefusalLimiter) and sends each one that
// passes to the daemon on the capture relay link as a KindEgressRefusal
// request, from one goroutine, so the gateway never waits on the daemon.
// The helper never opens the database.
//
// Channel per backend (the brief's order of preference, first choice
// everywhere): every helper that runs the gateway already holds its run's
// relay record and dials the daemon's link endpoint, so the report is a new
// message kind on the existing relay protocol. Linux (bwrap, process_lite,
// oci-runc, through hostEgressGateway, shared by the re-adopt helper), the
// macOS Seatbelt and Apple container helper, and the MXC helper on
// Windows (over its named pipe, dialSandboxRelay) all take this path. A
// run with no relay record has no channel: its refusals are answered in
// the 403 body and not recorded.

// The link to the daemon can be lost mid-run (the daemon restarts or dies;
// tracker F-012, audit finding N4-A4). The reporter keeps the refusal it
// could not send and retries it every egressRefusalRetry until a send gets
// through; every other refusal it could not send is counted, and the first
// report that gets through carries the counts (Lost, Closed), so the daemon
// adds them to the run's counts beside its rows. When the run's record says
// the org's require_refusal_audit floor was in force at launch
// (RunRecord.RefusalAuditRequired), new connections of the run are refused
// while the link is down (Gateway.Closed): no new request leaves
// unrecorded, and each one refused is counted. Without the floor the run
// keeps its egress and only the counts are kept.
//
// What marks the link down is the table egressRefusalOutcomes (audit
// findings FU5-A1 and FU5-A2): a failed dial always; under the floor also a
// transport failure after the dial (a deadline, EOF or reset before any
// answer) and egressRefusalDownAfter consecutive failures of any kind; and
// while the link is down every failure keeps the report pending, so egress
// reopens only when a report gets through, never stays closed because one
// retry failed for another reason. Without the floor a failure that is not
// a failed dial is counted and not retried, as before. The helper logs
// nothing (its stderr is the tool's terminal): a refused request is
// answered with the reason, and the daemon logs the counts when they land.

// egressRefusalQueue bounds the refusals waiting to be sent; past it a
// refusal is dropped and counted (the limiter already passes at most
// sandboxnet.DefaultRefusalsPerMinute a minute).
const egressRefusalQueue = 64

// egressRefusalRetry is how often a lost link is tried again (a var for
// tests).
var egressRefusalRetry = 2 * time.Second

// egressRefusalDownAfter is how many consecutive failed reports of any kind
// mark the link down under the floor (a daemon that accepts the dial but
// never answers costs a report timeout each, so the queue would otherwise
// fill while egress stays open; audit finding FU5-A2).
const egressRefusalDownAfter = 3

// egressRefusalClosedReason is what a request refused for a lost link is
// answered with. The floor is named from the one floor table, as the
// launch refusal names it (lane FU10, F-050).
var egressRefusalClosedReason = "new connections are refused: this run's link to Observer's refusal audit is lost, and your organization's sandbox setting " +
	terminalsisolation.FloorLabelWithKey("require_refusal_audit") +
	" is in force, so no new request may leave unrecorded (they are allowed again when the link is back)"

// errEgressLinkDown marks a report whose dial to the daemon failed.
var errEgressLinkDown = errors.New("the link to the daemon is down")

// egressRefusalReporter is one run's bounded sender.
type egressRefusalReporter struct {
	lim      *sandboxnet.RefusalLimiter
	ch       chan sandboxnet.Refusal
	send     func(context.Context, sandboxrelay.EgressRefusalReport) error
	required bool
	retry    time.Duration

	mu      sync.Mutex
	down    bool
	fails   int // consecutive failed reports
	lost    int
	closed  int
	pending *sandboxrelay.EgressRefusalReport
}

// newEgressRefusalReporter starts the sender goroutine, which ends with ctx.
// required closes the run's egress while the link is down.
func newEgressRefusalReporter(ctx context.Context, send func(context.Context, sandboxrelay.EgressRefusalReport) error, required bool) *egressRefusalReporter {
	r := &egressRefusalReporter{
		lim: sandboxnet.NewRefusalLimiter(0), ch: make(chan sandboxnet.Refusal, egressRefusalQueue), send: send,
		required: required, retry: egressRefusalRetry,
	}
	go r.loop(ctx)
	return r
}

// Report is the gateway's Report: it never blocks.
func (r *egressRefusalReporter) Report(ref sandboxnet.Refusal) {
	if !r.lim.Allow("", ref.Host, ref.At) {
		return
	}
	select {
	case r.ch <- ref:
	default:
		r.mu.Lock()
		r.lost++
		r.mu.Unlock()
	}
}

// Closed is the gateway's Closed: a reason while the floor requires the
// audit and the link is down, else "". Each attempt it closes is counted.
func (r *egressRefusalReporter) Closed() string {
	if !r.required {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.down {
		return ""
	}
	r.closed = min(r.closed+1, sandboxrelay.MaxEgressLossCount)
	return egressRefusalClosedReason
}

func (r *egressRefusalReporter) loop(ctx context.Context) {
	t := time.NewTicker(r.retry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ref := <-r.ch:
			r.deliver(ctx, egressRefusalReport(ref))
		case <-t.C:
			r.mu.Lock()
			p := r.pending
			r.mu.Unlock()
			if p != nil {
				r.deliver(ctx, *p)
			}
		}
	}
}

// deliver sends rep with the counts waiting. A report sent while another is
// pending replaces it (the older one is counted lost), so one outage keeps
// at most one report waiting. The pending report is let go only once rep
// has gone out (tracker F-037): a local failure, found before anything was
// sent, leaves it pending, so a link that is down keeps something to retry
// and egress closed under the floor reopens when the link is back.
func (r *egressRefusalReporter) deliver(ctx context.Context, rep sandboxrelay.EgressRefusalReport) {
	r.mu.Lock()
	retry := r.pending != nil && *r.pending == rep
	replaces := r.pending != nil && !retry
	lost := r.lost
	if replaces {
		lost++
	}
	rep.Lost, rep.Closed = min(lost, sandboxrelay.MaxEgressLossCount), r.closed
	r.mu.Unlock()
	// A report this helper cannot encode is dropped and counted here, before
	// any send (audit finding FU5-R1): a local failure says nothing about the
	// link, so it never counts toward marking it down and never changes down
	// (a retry of it would fail the same way forever). The report pending
	// before it stays pending.
	if _, err := sandboxrelay.EncodeEgressRefusalReport(rep); err != nil {
		r.localFailure(retry)
		return
	}
	err := r.send(ctx, rep)
	if errors.Is(err, sandboxrelayd.ErrEgressLocal) {
		// The same local failure, found by the sender's own encoder before
		// it sent anything. A schema error after the send (the daemon's
		// answer does not decode, a version skew) is not local: it is a
		// failure of the round trip and goes through the table below.
		r.localFailure(retry)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// rep went out (or was tried on the link): the report it replaces is
	// gone, and counted with the lost ones rep carries.
	if replaces {
		r.lost++
	}
	r.pending = nil
	if err == nil {
		r.down, r.fails = false, 0
		r.lost -= rep.Lost
		r.closed -= rep.Closed
		return
	}
	r.fails++
	f := egressRefusalFailure{
		required: r.required, down: r.down, fails: r.fails,
		dial: errors.Is(err, errEgressLinkDown), transport: egressTransportFailure(err),
	}
	if egressRefusalMarksDown(f) {
		r.down = true
		rep.Lost, rep.Closed = 0, 0
		r.pending = &rep
		return
	}
	// A non-transport failure no row marks down (the dial worked and the
	// round trip failed some other way than a deadline, EOF or reset, such
	// as a daemon answer that does not decode, tracker F-037): not
	// retried, counted, and the link is taken as up (audit finding FU5-R2).
	// The daemon never answers a busy or malformed report with an error: it
	// closes the session, which the helper reads as EOF, a transport
	// failure, so under the floor that marks the link down and the report
	// is retried.
	r.down = false
	r.lost++
}

// localFailure counts a report dropped for a local failure, unless it is
// the pending report's own retry (still waiting, counted when it is let
// go); the pending report and the link state are left as they are.
func (r *egressRefusalReporter) localFailure(retry bool) {
	if retry {
		return
	}
	r.mu.Lock()
	r.lost++
	r.mu.Unlock()
}

// egressRefusalFailure is what is known about one failed report.
type egressRefusalFailure struct {
	required  bool // the run's floor requires the refusal audit
	down      bool // the link was already down
	fails     int  // consecutive failed reports, this one included
	dial      bool // the dial to the daemon failed
	transport bool // the dial worked and the round trip broke before an answer
}

// egressRefusalOutcomes is the ordered table of failures that mark the link
// down (and keep the report pending to retry); a failure no row matches is
// counted and not retried. One test row each (TestEgressRefusalOutcomes).
var egressRefusalOutcomes = []struct {
	name string
	when func(f egressRefusalFailure) bool
}{
	{"the dial failed", func(f egressRefusalFailure) bool { return f.dial }},
	{"floor: a retry while down failed", func(f egressRefusalFailure) bool { return f.required && f.down }},
	{"floor: the round trip broke after the dial", func(f egressRefusalFailure) bool { return f.required && f.transport }},
	{"floor: consecutive failures", func(f egressRefusalFailure) bool {
		return f.required && f.fails >= egressRefusalDownAfter
	}},
}

// egressRefusalMarksDown walks egressRefusalOutcomes.
func egressRefusalMarksDown(f egressRefusalFailure) bool {
	for _, o := range egressRefusalOutcomes {
		if o.when(f) {
			return true
		}
	}
	return false
}

// egressTransportFailure reports whether err is the round trip breaking
// before any answer: a deadline, an EOF or a reset or closed connection.
func egressTransportFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// egressRefusalReport is ref as the link payload. The host is put in the
// form the payload always accepts (sandboxrelay.SafeEgressHost: bytes
// outside printable ASCII written as %XX, then cut to the bound with a
// marker), so a refusal of any target the box names still lands instead
// of failing the encoder (audit findings N1-A2 and FU5-R1).
func egressRefusalReport(ref sandboxnet.Refusal) sandboxrelay.EgressRefusalReport {
	return sandboxrelay.EgressRefusalReport{
		Host: sandboxrelay.SafeEgressHost(ref.Host), Port: ref.Port, Rule: string(ref.Rule), Key: ref.Key,
		AtMS: max(ref.At.UnixMilli(), 0),
	}
}

// egressRefusalHooks are the two gateway hooks of one run: Report hands
// its refusals to the daemon on the relay link, Closed closes its egress
// while the org requires the audit and the link is lost.
type egressRefusalHooks struct {
	Report func(sandboxnet.Refusal)
	Closed func() string
}

// sandboxEgressRefusalHooks returns run runID's gateway hooks; both nil
// when the run has no relay record (no channel exists), so the gateway
// reports nothing and never closes.
func sandboxEgressRefusalHooks(ctx context.Context, observerDir, runID string) egressRefusalHooks {
	if observerDir == "" || runID == "" {
		return egressRefusalHooks{}
	}
	rec, err := sandboxrelayd.ReadRun(observerDir, runID)
	if err != nil {
		return egressRefusalHooks{}
	}
	base := dialSandboxRelay(observerDir)
	dial := func(ctx context.Context) (net.Conn, error) {
		c, err := base(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errEgressLinkDown, err)
		}
		return c, nil
	}
	r := newEgressRefusalReporter(ctx, func(ctx context.Context, rep sandboxrelay.EgressRefusalReport) error {
		return sandboxrelayd.SendEgressRefusal(ctx, dial, rec, rep, sandboxrelay.ConnLimits{})
	}, rec.RefusalAuditRequired)
	return egressRefusalHooks{Report: r.Report, Closed: r.Closed}
}

// sandboxEgressRefusalSink is the Report hook alone (callers that build
// their gateway field by field keep it); see sandboxEgressRefusalHooks.
func sandboxEgressRefusalSink(ctx context.Context, observerDir, runID string) func(sandboxnet.Refusal) {
	return sandboxEgressRefusalHooks(ctx, observerDir, runID).Report
}
