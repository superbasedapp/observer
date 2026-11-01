package secipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// The feedback request kind (security pillar plan sections 5.11 (c) and
// 6.2 step 2, lane sec-h): after a write, the post-tool hook asks the
// daemon for the session's new, high-confidence, unexcepted findings it has
// not yet put into the agent's reply. It rides the quick-scan endpoint (one
// owner-only endpoint per security directory), on its own wire version so a
// daemon that predates the kind answers bad_request and never runs a scan
// for it.
//
// Delivery (lane sec-polish, audit finding F3): a request that sets "ack"
// gets the findings under a lease, and the hook keeps the connection open
// until it has written the reply that carries them; then it sends one
// acknowledgement line on the same connection (no second round trip: the
// hook does not wait for anything after it). Only that acknowledgement,
// read within FeedbackAckWait, marks the findings sent. An answer over the
// budget, a hook that gave up waiting, a reply the host refused or a hook
// stopped before it wrote leaves them unacknowledged, and the daemon
// offers them again on a later post hook once the lease lapses. A request
// without "ack" (an older hook binary) is marked sent once its answer was
// written, at most once as before. An older daemon ignores "ack", and the
// acknowledgement line then reaches a closed connection, harmlessly.

const (
	// KindFeedback names the feedback request.
	KindFeedback = "feedback"
	// feedbackVersion is the feedback request's wire version.
	feedbackVersion = 2
	// FeedbackBudget is the daemon's answer budget (the post-tool hook
	// adds no wait an agent would notice; JSP-2's added-work rows).
	FeedbackBudget = 50 * time.Millisecond
	// MaxFeedbackFindings caps the hits a feedback answer carries (the
	// line cap of internal/secfeedback).
	MaxFeedbackFindings = 3
	// maxSessionIDBytes caps the session id a request carries.
	maxSessionIDBytes = 256
	// FeedbackAckWait is how long the daemon waits, after writing an
	// answer, for the hook's acknowledgement that the reply carrying it
	// was written. It is shorter than the lease (internal/secfeedback
	// LeaseFor), so an acknowledgement never marks a line another reply
	// was offered meanwhile.
	FeedbackAckWait = 2 * time.Second
	// kindFeedbackAck names the acknowledgement line.
	kindFeedbackAck = "feedback_ack"
)

// ErrFeedbackDeclined reports a daemon that answered the request with no
// findings and a reason (not available, root refused, over budget): an
// answer, so the caller does not fall back to its own scan.
var ErrFeedbackDeclined = errors.New("secipc: feedback declined")

// FeedbackRequest is one post-tool feedback request.
type FeedbackRequest struct {
	ProjectRoot string
	SessionID   string
	// AckOffer, when set, is not a request for findings: it is a late
	// acknowledgement of the offer the token names (lane SEC-H2, audit
	// finding F3), sent on a fresh connection by a hook whose reply was
	// written after FeedbackAckWait. The answerer records that offer's
	// findings idempotently and answers nothing.
	AckOffer string
}

// FeedbackOffer is the daemon's answer to one feedback request: the hits,
// with rule data only (no message, evidence or snippet; security plan
// section 9 T8), held under a lease until Ack.
type FeedbackOffer struct {
	Hits []policy.SecurityHit
	// Ack records the hits as delivered. The endpoint calls it at most
	// once, only after the reply carrying them was acknowledged (or, for a
	// request without "ack", after the answer was written); otherwise the
	// lease lapses and the daemon offers them again. Nil records nothing.
	Ack func(ctx context.Context)
	// Token names the offer for a late acknowledgement (lane SEC-H2); ""
	// sends none, and the hook then acknowledges on the connection only.
	Token string
	// Pending is called once the answer was written to a hook that will
	// acknowledge it (lane SEC-H2): the daemon keeps the offer's findings
	// out of other replies for its longer pending window and records the
	// token durably, so a reply written late, or a daemon restart, does
	// not offer the lines again before the acknowledgement can land. Nil
	// keeps the short lease.
	Pending func(ctx context.Context)
}

// FeedbackAnswerer answers a feedback request. The daemon leases what it
// offers, so a finding is in at most one reply at a time, and records it
// only through the offer's Ack.
type FeedbackAnswerer func(ctx context.Context, req FeedbackRequest) (FeedbackOffer, error)

type feedbackWireRequest struct {
	V           int    `json:"v"`
	Kind        string `json:"kind"`
	ProjectRoot string `json:"project_root"`
	SessionID   string `json:"session_id"`
	// Ack says the hook will acknowledge the reply (lane sec-polish).
	Ack bool `json:"ack,omitempty"`
	// AckOffer is a late acknowledgement's offer token (lane SEC-H2).
	AckOffer string `json:"ack_offer,omitempty"`
	// LateAck says the hook can send a late acknowledgement on a fresh
	// connection (SEC-H2 merge, audit finding 6). Only such a hook is given
	// the offer token and the longer pending hold; an older hook that
	// acknowledges on the connection only keeps the short lease, so a
	// missed acknowledgement delays its lines by the lease, not the hold.
	LateAck bool `json:"late_ack,omitempty"`
}

// feedbackAckLine is the hook's acknowledgement, on the same connection.
type feedbackAckLine struct {
	V    int    `json:"v"`
	Kind string `json:"kind"`
	// N is how many findings the acknowledged reply carried.
	N int `json:"n"`
	// Offer repeats the answer's offer token (lane SEC-H2), "" from an
	// older hook.
	Offer string `json:"offer,omitempty"`
}

type feedbackWireResponse struct {
	V        int    `json:"v"`
	Kind     string `json:"kind"`
	Findings []hit  `json:"findings,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Offer is the offer's token for a late acknowledgement (lane SEC-H2);
	// an older hook ignores it.
	Offer string `json:"offer,omitempty"`
}

// maxOfferTokenBytes caps an offer token on the wire.
const maxOfferTokenBytes = 64

// validOfferToken reports whether t is an offer token's shape (lowercase
// hex), the only form a late acknowledgement may carry.
func validOfferToken(t string) bool {
	if t == "" || len(t) > maxOfferTokenBytes {
		return false
	}
	for _, c := range t {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// feedbackRequestOf reports whether raw is a feedback request.
func feedbackRequestOf(raw []byte) (feedbackWireRequest, bool) {
	var q feedbackWireRequest
	if json.Unmarshal(raw, &q) != nil || q.Kind != KindFeedback {
		return feedbackWireRequest{}, false
	}
	return q, true
}

// answerFeedback answers one feedback request under FeedbackBudget. Any
// failure is an empty answer with a reason: feedback is never a verdict.
// The offer comes back only for an answer that carries findings; one that
// arrives over the budget is dropped unacknowledged (its lease lapses).
func answerFeedback(ctx context.Context, q feedbackWireRequest, f FeedbackAnswerer, allow func(string) bool) (feedbackWireResponse, *FeedbackOffer) {
	empty := func(reason string) feedbackWireResponse {
		return feedbackWireResponse{V: feedbackVersion, Kind: KindFeedback, Reason: reason}
	}
	if q.V != feedbackVersion || q.ProjectRoot == "" || q.SessionID == "" || len(q.SessionID) > maxSessionIDBytes {
		return empty("bad_request"), nil
	}
	if f == nil {
		return empty("feedback_not_available"), nil
	}
	if !filepath.IsAbs(q.ProjectRoot) || (allow != nil && !allow(q.ProjectRoot)) {
		return empty("root_not_allowed"), nil
	}
	if q.AckOffer != "" {
		// A late acknowledgement (lane SEC-H2): recorded by the answerer,
		// answered empty either way.
		if !validOfferToken(q.AckOffer) {
			return empty("bad_request"), nil
		}
		actx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_, _ = f(actx, FeedbackRequest{ProjectRoot: q.ProjectRoot, SessionID: q.SessionID, AckOffer: q.AckOffer})
		return empty("acknowledged"), nil
	}
	fctx, cancel := context.WithTimeout(ctx, FeedbackBudget)
	defer cancel()
	type out struct {
		offer FeedbackOffer
		err   error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{err: fmt.Errorf("feedback panic: %v", r)}
			}
		}()
		offer, err := f(fctx, FeedbackRequest{ProjectRoot: q.ProjectRoot, SessionID: q.SessionID})
		ch <- out{offer: offer, err: err}
	}()
	select {
	case o := <-ch:
		if o.err != nil {
			return empty("feedback_failed"), nil
		}
		resp := empty("")
		resp.Findings = encodeHits(o.offer.Hits, MaxFeedbackFindings)
		if len(resp.Findings) == 0 {
			return resp, nil
		}
		if q.Ack && q.LateAck && validOfferToken(o.offer.Token) {
			resp.Offer = o.offer.Token
		}
		return resp, &o.offer
	case <-fctx.Done():
		return empty("over_budget"), nil
	}
}

// serveFeedbackConn answers one feedback request on conn and settles its
// offer: acknowledged within FeedbackAckWait (or, for a request without
// "ack", written), it is recorded; otherwise its lease lapses.
func serveFeedbackConn(ctx context.Context, conn net.Conn, q feedbackWireRequest, f FeedbackAnswerer, allow func(string) bool) {
	resp, offer := answerFeedback(ctx, q, f, allow)
	if !writeFeedback(conn, resp) || offer == nil || offer.Ack == nil {
		return
	}
	if q.Ack {
		if offer.Pending != nil && resp.Offer != "" {
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			offer.Pending(pctx)
			cancel()
		}
		_ = conn.SetReadDeadline(time.Now().Add(FeedbackAckWait))
		raw, err := readLine(conn)
		if err != nil {
			return
		}
		var a feedbackAckLine
		if json.Unmarshal(raw, &a) != nil || a.V != feedbackVersion || a.Kind != kindFeedbackAck || a.N != len(resp.Findings) {
			return
		}
	}
	actx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	offer.Ack(actx)
}

func encodeHits(hits []policy.SecurityHit, max int) []hit {
	var out []hit
	for i, h := range hits {
		if i >= max {
			break
		}
		out = append(out, hit{
			Category: string(h.Category), Severity: string(h.Severity), Confidence: string(h.Confidence),
			RuleID: h.RuleID, Path: h.Path, Line: h.Line,
		})
	}
	return out
}

func decodeHits(in []hit, max int) []policy.SecurityHit {
	var out []policy.SecurityHit
	for i, h := range in {
		if i >= max {
			break
		}
		path := h.Path
		if len(path) > policy.SecurityHitPathMax {
			path = path[:policy.SecurityHitPathMax]
		}
		out = append(out, policy.SecurityHit{
			Category: policy.FindingCategory(h.Category), Severity: policy.FindingSeverity(h.Severity),
			Confidence: policy.FindingConfidence(h.Confidence), RuleID: h.RuleID, Path: path, Line: h.Line,
		})
	}
	return out
}

// writeFeedback writes one feedback answer line on conn and reports
// whether the whole line was written.
func writeFeedback(conn net.Conn, resp feedbackWireResponse) bool {
	line, err := json.Marshal(resp)
	if err != nil {
		return false
	}
	_, err = conn.Write(append(line, '\n'))
	return err == nil
}

// FeedbackLease is a feedback answer the hook has not yet acknowledged:
// its hits, and the connection it came on, kept open until the reply that
// carries them is written (Ack) or abandoned (Close).
type FeedbackLease struct {
	conn  net.Conn
	hits  []policy.SecurityHit
	ackBy time.Time
	once  sync.Once
	// endpoint, req and offer let a reply written after ackBy still
	// acknowledge the offer on a fresh connection (lane SEC-H2); offer ""
	// (an older daemon) leaves the old rule.
	endpoint string
	req      FeedbackRequest
	offer    string
}

// Hits returns the leased hits.
func (l *FeedbackLease) Hits() []policy.SecurityHit {
	if l == nil {
		return nil
	}
	return l.hits
}

// Ack tells the daemon the reply carrying the hits was written, then
// closes the connection. It waits for nothing: one line written on the
// open connection, so the hook pays no second round trip. Past the
// daemon's acknowledgement window it only closes (the lines are offered
// again after their lease). Safe on a nil lease and after Close.
func (l *FeedbackLease) Ack() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		defer func() { _ = l.conn.Close() }()
		if len(l.hits) == 0 {
			return
		}
		if !time.Now().Before(l.ackBy) {
			l.lateAck()
			return
		}
		line, err := json.Marshal(feedbackAckLine{V: feedbackVersion, Kind: kindFeedbackAck, N: len(l.hits), Offer: l.offer})
		if err != nil {
			return
		}
		_ = l.conn.SetWriteDeadline(l.ackBy)
		_, _ = l.conn.Write(append(line, '\n'))
	})
}

// lateAckTimeout bounds a late acknowledgement's dial and write: the hook
// writes one line and waits for no answer.
const lateAckTimeout = 250 * time.Millisecond

// lateAck sends the offer's token as a late acknowledgement on a fresh
// connection (lane SEC-H2): the reply that carried the lines was written
// after the daemon stopped waiting on the first connection. It writes one
// request line and closes; the daemon records the offer idempotently. With
// no token (an older daemon) it does nothing, and the lines are offered
// again after their lease, as before.
func (l *FeedbackLease) lateAck() {
	if l.offer == "" || l.endpoint == "" {
		return
	}
	conn, err := localipc.DefaultTransport().Dial(context.Background(), l.endpoint, lateAckTimeout)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	line, err := json.Marshal(feedbackWireRequest{
		V: feedbackVersion, Kind: KindFeedback, ProjectRoot: l.req.ProjectRoot, SessionID: l.req.SessionID, AckOffer: l.offer,
	})
	if err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(lateAckTimeout))
	_, _ = conn.Write(append(line, '\n'))
}

// Close abandons the lease without acknowledging it: the daemon offers
// the hits again after their lease. Safe on a nil lease and after Ack.
func (l *FeedbackLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() { _ = l.conn.Close() })
}

// AskFeedbackLease sends one feedback request that the hook will
// acknowledge and waits for the answer, bounded by ctx and budget (zero:
// FeedbackBudget plus a transport allowance). On success the connection
// stays open in the lease: the caller must Ack it once the reply carrying
// its hits is written, or Close it. Any transport or decode failure is an
// error (the connection closed); the caller then gives the agent no daemon
// context (never a block).
func AskFeedbackLease(ctx context.Context, endpoint string, req FeedbackRequest, budget time.Duration) (*FeedbackLease, error) {
	conn, resp, err := askFeedback(ctx, endpoint, req, budget, true)
	if err != nil {
		return nil, err
	}
	l := &FeedbackLease{
		conn: conn, hits: decodeHits(resp.Findings, MaxFeedbackFindings), ackBy: time.Now().Add(FeedbackAckWait),
		endpoint: endpoint, req: req,
	}
	if validOfferToken(resp.Offer) {
		l.offer = resp.Offer
	}
	if len(l.hits) == 0 {
		l.Close()
	}
	return l, nil
}

// AskFeedback sends one feedback request without an acknowledgement (the
// daemon marks the findings sent once its answer is written, at most once)
// and waits for the answer, bounded by ctx and budget (zero: FeedbackBudget
// plus a transport allowance). Any transport or decode failure is an
// error; the caller then gives the agent no daemon context (never a block).
func AskFeedback(ctx context.Context, endpoint string, req FeedbackRequest, budget time.Duration) ([]policy.SecurityHit, error) {
	conn, resp, err := askFeedback(ctx, endpoint, req, budget, false)
	if err != nil {
		return nil, err
	}
	_ = conn.Close()
	return decodeHits(resp.Findings, MaxFeedbackFindings), nil
}

// askFeedback is one request and its answer; on success the connection is
// returned open, on failure it is closed.
func askFeedback(ctx context.Context, endpoint string, req FeedbackRequest, budget time.Duration, ack bool) (net.Conn, feedbackWireResponse, error) {
	if budget <= 0 {
		budget = FeedbackBudget + 50*time.Millisecond
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := localipc.DefaultTransport().Dial(ctx, endpoint, time.Until(deadline))
	if err != nil {
		return nil, feedbackWireResponse{}, fmt.Errorf("secipc.AskFeedback: %w", err)
	}
	fail := func(err error) (net.Conn, feedbackWireResponse, error) {
		_ = conn.Close()
		return nil, feedbackWireResponse{}, fmt.Errorf("secipc.AskFeedback: %w", err)
	}
	_ = conn.SetDeadline(deadline)
	line, err := json.Marshal(feedbackWireRequest{V: feedbackVersion, Kind: KindFeedback, ProjectRoot: req.ProjectRoot, SessionID: req.SessionID, Ack: ack, LateAck: ack})
	if err != nil {
		return fail(err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fail(err)
	}
	raw, err := readLine(conn)
	if err != nil {
		return fail(err)
	}
	var resp feedbackWireResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fail(err)
	}
	if resp.V != feedbackVersion || resp.Kind != KindFeedback {
		return fail(errors.New("not a feedback answer"))
	}
	if resp.Reason != "" && len(resp.Findings) == 0 {
		return fail(fmt.Errorf("%w: %s", ErrFeedbackDeclined, resp.Reason))
	}
	return conn, resp, nil
}
