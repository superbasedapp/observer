package sandboxrelayd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// egress.go carries the egress refusal audit on the link (OpenShell build
// plan 05 section 3.1, lane N1): the host helper's gateway refuses a
// request, the helper sends one KindEgressRefusal request to the daemon
// (SendEgressRefusal), and the daemon hands the validated report to
// Daemon.OnEgressRefusal with the run the channel names. A refusal never
// lowers the run's capture: it is the gateway doing its job. A report takes
// none of the run's hook slots (its own one-slot budget, refusalSem), and a
// report that fails (busy, malformed, a broken link) is wrapped in
// errEgressRefusalReport so ServeConn lowers nothing for it.

// errEgressRefusalReport marks an error of a refusal report.
var errEgressRefusalReport = errors.New("sandboxrelayd: egress refusal report")

// egressRefusalTimeout bounds one report's round trip.
const egressRefusalTimeout = 5 * time.Second

// serveEgressRefusal hands the helper's report on and answers it.
// A report arriving while another of the run's reports is being handled
// is dropped (the helper does not retry; the box already has its 403).
func (d *Daemon) serveEgressRefusal(s *sandboxrelay.Session, rec RunRecord, st *RunState, req sandboxrelay.HookRequest) error {
	select {
	case st.refusalSem <- struct{}{}:
	default:
		return fmt.Errorf("sandboxrelayd.ServeConn: %w: %w", errEgressRefusalReport, ErrBusy)
	}
	defer func() { <-st.refusalSem }()
	rep, err := sandboxrelay.DecodeEgressRefusalReport(req.Stdin)
	if err != nil {
		st.Refused.Add(1)
		return fmt.Errorf("sandboxrelayd.ServeConn: %w: %w", errEgressRefusalReport, err)
	}
	if d.OnEgressRefusal != nil {
		d.OnEgressRefusal(rec, rep)
	}
	out, err := sandboxrelay.EncodeHookResponse(sandboxrelay.HookResponse{V: req.V})
	if err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w: %w", errEgressRefusalReport, err)
	}
	if err := s.Send(sandboxrelay.StreamHook, out); err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w: %w", errEgressRefusalReport, err)
	}
	closeAnswered(s)
	return nil
}

// ErrEgressLocal marks a report SendEgressRefusal could not encode, before
// anything was sent (tracker F-037): a local failure that says nothing
// about the link. A schema error after the send (the daemon's answer does
// not decode, a version skew) is not wrapped in it: that is a failure of
// the round trip.
var ErrEgressLocal = errors.New("sandboxrelayd: the egress refusal report could not be encoded")

// SendEgressRefusal is the host helper's side: one report of run's gateway
// to the daemon on the link dial reaches, bounded by egressRefusalTimeout.
func SendEgressRefusal(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), run RunRecord, rep sandboxrelay.EgressRefusalReport, c sandboxrelay.ConnLimits) error {
	body, err := sandboxrelay.EncodeEgressRefusalReport(rep)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEgressLocal, err)
	}
	tool := run.Tool
	if tool == "" {
		tool = "relay"
	}
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindEgressRefusal, Args: []string{tool}, Stdin: body})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEgressLocal, err)
	}
	if c == (sandboxrelay.ConnLimits{}) {
		c = sandboxrelay.DefaultConnLimits
	}
	ctx, cancel := context.WithTimeout(ctx, egressRefusalTimeout)
	defer cancel()
	_, err = LinkRoundTrip(ctx, dial, run, msg, c)
	return err
}
