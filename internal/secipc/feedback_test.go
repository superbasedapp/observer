package secipc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookbudget"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

func serveFeedback(t *testing.T, f FeedbackAnswerer, allow func(string) bool) string {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no owner-only IPC transport on this platform")
	}
	dir, err := os.MkdirTemp("", "secipcfb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, ep, err := Listen(filepath.Join(dir, "security"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ServeWith(ctx, ln, nil, Options{Feedback: f, AllowRoot: allow}) }()
	return ep
}

var hits = []policy.SecurityHit{
	{Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, RuleID: "secret.github_pat", Path: "a.py", Line: 3},
	{Category: policy.FindingCIConfig, Severity: policy.FindingSeverityMedium, Confidence: policy.FindingConfidenceHigh, RuleID: "S-771", Path: ".github/workflows/ci.yml", Line: 9},
}

func TestFeedbackRoundTrip(t *testing.T) {
	t.Parallel()
	var got FeedbackRequest
	ep := serveFeedback(t, func(_ context.Context, r FeedbackRequest) (FeedbackOffer, error) {
		got = r
		return FeedbackOffer{Hits: append(hits, hits...)}, nil
	}, nil)
	res, err := AskFeedback(context.Background(), ep, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}, time.Second)
	if err != nil || len(res) != MaxFeedbackFindings || res[0] != hits[0] || res[1] != hits[1] {
		t.Fatalf("AskFeedback = %+v, %v", res, err)
	}
	if got.ProjectRoot != "/repo" || got.SessionID != "s1" {
		t.Fatalf("the daemon saw %+v", got)
	}
}

// TestFeedbackFailuresGiveNoContext: every failure is an error to the hook
// (which then gives the agent no daemon context), never a verdict.
func TestFeedbackFailuresGiveNoContext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		f     FeedbackAnswerer
		allow func(string) bool
		req   FeedbackRequest
	}{
		{"no answerer", nil, nil, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}},
		{"answerer fails", func(context.Context, FeedbackRequest) (FeedbackOffer, error) {
			return FeedbackOffer{}, errors.New("db")
		}, nil, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}},
		{"answerer panics", func(context.Context, FeedbackRequest) (FeedbackOffer, error) { panic("x") }, nil, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}},
		{"over budget", func(ctx context.Context, _ FeedbackRequest) (FeedbackOffer, error) {
			<-ctx.Done()
			time.Sleep(10 * time.Millisecond)
			return FeedbackOffer{Hits: hits}, nil
		}, nil, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}},
		{"root refused", func(context.Context, FeedbackRequest) (FeedbackOffer, error) { return FeedbackOffer{Hits: hits}, nil }, func(string) bool { return false }, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}},
		{"relative root", func(context.Context, FeedbackRequest) (FeedbackOffer, error) { return FeedbackOffer{Hits: hits}, nil }, nil, FeedbackRequest{ProjectRoot: "repo", SessionID: "s1"}},
		{"no session", func(context.Context, FeedbackRequest) (FeedbackOffer, error) { return FeedbackOffer{Hits: hits}, nil }, nil, FeedbackRequest{ProjectRoot: "/repo"}},
	}
	for _, tc := range cases {
		ep := serveFeedback(t, tc.f, tc.allow)
		res, err := AskFeedback(context.Background(), ep, tc.req, time.Second)
		if err == nil || len(res) != 0 {
			t.Errorf("%s: %+v, %v", tc.name, res, err)
		}
	}
}

// TestQuickScanServerRefusesFeedbackAsAScan: a feedback line is never read
// as a quick-scan request (a daemon that predates the kind answers
// bad_request on the quick-scan path because of the wire version).
func TestQuickScanServerRefusesFeedbackAsAScan(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"v":2,"kind":"feedback","project_root":"/repo","session_id":"s1"}`)
	r := answer(context.Background(), raw, nil, nil)
	if r.Verdict != string(policy.QuickScanUnknown) || r.Reason != "bad_request" {
		t.Fatalf("the quick-scan path took a feedback line: %+v", r)
	}
}

// TestFeedbackBudget measures the warm round trip against the budget row
// (internal/hookbudget Feedback, 50 ms p99). Under the race detector the
// round trips still run and are logged, but the p99 is not judged: the
// instrumentation, not the endpoint, sets the time on a small VM.
func TestFeedbackBudget(t *testing.T) {
	var acked atomic.Int64
	ep := serveFeedback(t, func(context.Context, FeedbackRequest) (FeedbackOffer, error) {
		return FeedbackOffer{Hits: hits, Ack: func(context.Context) { acked.Add(1) }}, nil
	}, nil)
	// The hook's own path (lane sec-polish): the leased ask, then the one
	// acknowledgement line written on the open connection. The
	// acknowledgement waits for nothing, so it is inside the measured time
	// and adds no round trip.
	samples := make([]time.Duration, 0, 200)
	for i := 0; i < 200; i++ {
		start := time.Now()
		l, err := AskFeedbackLease(context.Background(), ep, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		l.Ack()
		samples = append(samples, time.Since(start))
	}
	waitFor(t, func() bool { return acked.Load() == 200 }, "every acknowledged offer recorded")
	b, _ := hookbudget.Lookup(hookbudget.Feedback)
	s := hookbudget.Summarize(samples)
	t.Logf("feedback round trip: p50 %v p99 %v max %v", s.P50, s.P99, s.Max)
	if raceDetector {
		t.Log("race detector on: the p99 budget is not judged")
		return
	}
	if v := hookbudget.Judge(b, s); v != hookbudget.VerdictWithin {
		t.Errorf("feedback round trip p99 %v: %s the %v budget", s.P99, v, b.P99)
	}
}

// waitFor polls cond for up to 3 s (the daemon records an acknowledgement
// after the hook has moved on).
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

// countingOffer returns an answerer that takes delay (past its budget when
// delay exceeds it) and whose offers count their Ack calls.
func countingOffer(delay time.Duration) (FeedbackAnswerer, *atomic.Int64) {
	var n atomic.Int64
	return func(context.Context, FeedbackRequest) (FeedbackOffer, error) {
		time.Sleep(delay)
		return FeedbackOffer{Hits: hits, Ack: func(context.Context) { n.Add(1) }}, nil
	}, &n
}

// TestFeedbackLeaseAckRecords (lane sec-polish, audit finding F3): a
// leased answer is recorded only once the hook acknowledges the reply that
// carried it, and only once.
func TestFeedbackLeaseAckRecords(t *testing.T) {
	t.Parallel()
	f, acked := countingOffer(0)
	ep := serveFeedback(t, f, nil)
	l, err := AskFeedbackLease(context.Background(), ep, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}, time.Second)
	if err != nil || len(l.Hits()) != 2 {
		t.Fatalf("lease: %+v %v", l, err)
	}
	time.Sleep(20 * time.Millisecond)
	if acked.Load() != 0 {
		t.Fatal("recorded before the hook acknowledged the reply")
	}
	l.Ack()
	l.Ack()
	l.Close()
	waitFor(t, func() bool { return acked.Load() == 1 }, "the acknowledged offer recorded")
	time.Sleep(20 * time.Millisecond)
	if acked.Load() != 1 {
		t.Fatalf("recorded %d times", acked.Load())
	}
}

// TestFeedbackLeaseLossPathsRecordNothing (lane sec-polish, audit finding
// F3): every way the line can miss the agent leaves the offer
// unacknowledged, so its lease lapses and the daemon offers it again.
func TestFeedbackLeaseLossPathsRecordNothing(t *testing.T) {
	t.Parallel()
	req := FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}
	cases := []struct {
		name  string
		delay time.Duration
		hook  func(t *testing.T, ep string)
	}{
		{"the daemon answers over its budget", 2 * FeedbackBudget, func(t *testing.T, ep string) {
			if _, err := AskFeedbackLease(context.Background(), ep, req, time.Second); !errors.Is(err, ErrFeedbackDeclined) {
				t.Errorf("over budget: %v", err)
			}
		}},
		{"the hook stops waiting before the answer", 30 * time.Millisecond, func(t *testing.T, ep string) {
			if _, err := AskFeedbackLease(context.Background(), ep, req, 5*time.Millisecond); err == nil {
				t.Error("the hook's read deadline did not fire")
			}
		}},
		{"the host refuses the reply write", 0, func(t *testing.T, ep string) {
			l, err := AskFeedbackLease(context.Background(), ep, req, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			l.Close() // the reply write failed: no acknowledgement
			l.Ack()   // and a later Ack does nothing
		}},
		{"the reply is written after the acknowledgement window", 0, func(t *testing.T, ep string) {
			l, err := AskFeedbackLease(context.Background(), ep, req, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			l.ackBy = time.Now()
			l.Ack()
		}},
	}
	for _, tc := range cases {
		f, acked := countingOffer(tc.delay)
		ep := serveFeedback(t, f, nil)
		tc.hook(t, ep)
		time.Sleep(4 * FeedbackBudget)
		if acked.Load() != 0 {
			t.Errorf("%s: recorded %d", tc.name, acked.Load())
		}
	}
}

// TestFeedbackAckMustMatchTheReply: an acknowledgement line that does not
// name the reply's finding count, or is not an acknowledgement, records
// nothing.
func TestFeedbackAckMustMatchTheReply(t *testing.T) {
	t.Parallel()
	for _, ack := range []string{`{"v":2,"kind":"feedback_ack","n":1}`, `{"v":2,"kind":"feedback","n":2}`, `{"v":1,"kind":"feedback_ack","n":2}`, `nonsense`} {
		f, acked := countingOffer(0)
		ep := serveFeedback(t, f, nil)
		conn, err := localipc.DefaultTransport().Dial(context.Background(), ep, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte(`{"v":2,"kind":"feedback","project_root":"/repo","session_id":"s1","ack":true}` + "\n"))
		if _, err := readLine(conn); err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(ack + "\n"))
		time.Sleep(20 * time.Millisecond)
		_ = conn.Close()
		if acked.Load() != 0 {
			t.Errorf("%s recorded the offer", ack)
		}
	}
	// The matching line does record it (the control row).
	f, acked := countingOffer(0)
	ep := serveFeedback(t, f, nil)
	conn, err := localipc.DefaultTransport().Dial(context.Background(), ep, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte(`{"v":2,"kind":"feedback","project_root":"/repo","session_id":"s1","ack":true}` + "\n"))
	if _, err := readLine(conn); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte(`{"v":2,"kind":"feedback_ack","n":2}` + "\n"))
	waitFor(t, func() bool { return acked.Load() == 1 }, "the matching acknowledgement recorded")
	_ = conn.Close()
}

// TestFeedbackWithoutAckRecordsOnWrite: a request without "ack" (an older
// hook binary) is recorded once its answer was written, at most once as
// before.
func TestFeedbackWithoutAckRecordsOnWrite(t *testing.T) {
	t.Parallel()
	f, acked := countingOffer(0)
	ep := serveFeedback(t, f, nil)
	if res, err := AskFeedback(context.Background(), ep, FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}, time.Second); err != nil || len(res) != 2 {
		t.Fatalf("AskFeedback = %+v, %v", res, err)
	}
	waitFor(t, func() bool { return acked.Load() == 1 }, "the written answer recorded")
}

// TestFeedbackLateAckOnAFreshConnection (lane SEC-H2, audit finding F3): a
// token-carrying offer is marked pending once its answer is written; a
// reply written after the acknowledgement window acknowledges it late on a
// fresh connection with the token, which the answerer records; a malformed
// token is refused without reaching the answerer.
func TestFeedbackLateAckOnAFreshConnection(t *testing.T) {
	t.Parallel()
	const token = "0123456789abcdef0123456789abcdef"
	var pending, acked, lateAcked atomic.Int64
	var lateToken atomic.Value
	ep := serveFeedback(t, func(_ context.Context, r FeedbackRequest) (FeedbackOffer, error) {
		if r.AckOffer != "" {
			lateToken.Store(r.AckOffer)
			lateAcked.Add(1)
			return FeedbackOffer{}, nil
		}
		return FeedbackOffer{
			Hits: hits, Token: token,
			Ack:     func(context.Context) { acked.Add(1) },
			Pending: func(context.Context) { pending.Add(1) },
		}, nil
	}, nil)
	req := FeedbackRequest{ProjectRoot: "/repo", SessionID: "s1"}
	l, err := AskFeedbackLease(context.Background(), ep, req, time.Second)
	if err != nil || l.offer != token {
		t.Fatalf("lease %+v %v", l, err)
	}
	waitFor(t, func() bool { return pending.Load() == 1 }, "the written answer marked pending")
	l.ackBy = time.Now() // the host wrote the reply after the window
	l.Ack()
	waitFor(t, func() bool { return lateAcked.Load() == 1 }, "the late acknowledgement reached the daemon")
	if got, _ := lateToken.Load().(string); got != token || acked.Load() != 0 {
		t.Fatalf("late token %q, on-connection acks %d", got, acked.Load())
	}

	// In the window the acknowledgement rides the connection, as before.
	l2, err := AskFeedbackLease(context.Background(), ep, req, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	l2.Ack()
	waitFor(t, func() bool { return acked.Load() == 1 }, "the on-connection acknowledgement")
	if lateAcked.Load() != 1 {
		t.Fatalf("a timely acknowledgement also went late: %d", lateAcked.Load())
	}
	for _, bad := range []string{"", "ZZ", "0123456789ABCDEF", string(make([]byte, 65))} {
		if bad != "" && validOfferToken(bad) {
			t.Errorf("token %q accepted", bad)
		}
	}
	// A malformed token sent over the wire (SEC-H2 merge, audit finding 8)
	// is refused bad_request and never reaches the answerer.
	for _, bad := range []string{"ZZ", "0123456789ABCDEF", strings.Repeat("a", 65), "../../etc"} {
		resp := rawFeedbackRequest(t, ep, feedbackWireRequest{V: feedbackVersion, Kind: KindFeedback, ProjectRoot: "/repo", SessionID: "s1", AckOffer: bad})
		if resp.Reason != "bad_request" {
			t.Errorf("malformed token %q answered %+v", bad, resp)
		}
	}
	if lateAcked.Load() != 1 {
		t.Fatalf("a malformed token reached the answerer: %d late acknowledgements", lateAcked.Load())
	}
}

// rawFeedbackRequest writes one request line to the endpoint and reads the
// answer line.
func rawFeedbackRequest(t *testing.T, ep string, q feedbackWireRequest) feedbackWireResponse {
	t.Helper()
	conn, err := localipc.DefaultTransport().Dial(context.Background(), ep, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	line, _ := json.Marshal(q)
	if _, err := conn.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	raw, err := readLine(conn)
	if err != nil {
		t.Fatal(err)
	}
	var resp feedbackWireResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestFeedbackPendingHoldOnlyForLateAckHooks (SEC-H2 merge, audit finding
// 6): a hook that acknowledges on the connection but does not advertise
// late acknowledgements (an older hook) gets no offer token and no pending
// hold, so a missed acknowledgement keeps the short lease; one that
// advertises them gets both.
func TestFeedbackPendingHoldOnlyForLateAckHooks(t *testing.T) {
	t.Parallel()
	const token = "fedcba9876543210fedcba9876543210"
	var pending atomic.Int64
	ep := serveFeedback(t, func(context.Context, FeedbackRequest) (FeedbackOffer, error) {
		return FeedbackOffer{Hits: hits, Token: token, Ack: func(context.Context) {}, Pending: func(context.Context) { pending.Add(1) }}, nil
	}, nil)
	old := rawFeedbackRequest(t, ep, feedbackWireRequest{V: feedbackVersion, Kind: KindFeedback, ProjectRoot: "/repo", SessionID: "s1", Ack: true})
	if old.Offer != "" || len(old.Findings) == 0 {
		t.Fatalf("an older hook was given the offer token: %+v", old)
	}
	time.Sleep(50 * time.Millisecond)
	if pending.Load() != 0 {
		t.Fatalf("an older hook's offer was held pending (%d)", pending.Load())
	}
	cur := rawFeedbackRequest(t, ep, feedbackWireRequest{V: feedbackVersion, Kind: KindFeedback, ProjectRoot: "/repo", SessionID: "s1", Ack: true, LateAck: true})
	if cur.Offer != token {
		t.Fatalf("a late-ack hook got no offer token: %+v", cur)
	}
	waitFor(t, func() bool { return pending.Load() == 1 }, "the late-ack hook's offer held pending")
}
