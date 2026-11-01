package secipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Wire limits.
const (
	// Version is the wire version.
	Version = 1
	// MaxLineBytes caps one request or response line.
	MaxLineBytes = 64 << 10
	// MaxFindings caps the hits a response carries.
	MaxFindings = 64
	// MaxPathspecs caps the pathspecs a request carries.
	MaxPathspecs = 64
	// MaxBudget caps the scan budget a request may ask for (the floor's
	// picker tops out at 30 s).
	MaxBudget = 30 * time.Second
)

// keyName is the synthetic key the transport derives the endpoint from.
// The transport puts the socket in an attach/ directory beside the key, so
// the endpoint is <security dir>/attach/attach.sock on unix (kept short:
// a unix socket path has a 107-byte limit) and a distinct hashed pipe name
// on Windows.
const keyName = "quickscan"

// Endpoint returns the quick-scan endpoint for the security directory
// (secposture.Layout.Dir).
func Endpoint(securityDir string) (string, error) {
	if securityDir == "" {
		return "", errors.New("secipc.Endpoint: no security directory")
	}
	ep, err := localipc.DefaultTransport().Endpoint(filepath.Join(securityDir, keyName))
	if err != nil {
		return "", fmt.Errorf("secipc.Endpoint: %w", err)
	}
	return ep, nil
}

// request is the wire request.
type request struct {
	V           int      `json:"v"`
	ProjectRoot string   `json:"project_root"`
	Form        string   `json:"form"`
	Push        bool     `json:"push,omitempty"`
	All         bool     `json:"all,omitempty"`
	Amend       bool     `json:"amend,omitempty"`
	Pathspecs   []string `json:"pathspecs,omitempty"`
	Dir         string   `json:"dir,omitempty"`
	PushOps     []string `json:"push_operands,omitempty"`
	PushOpaque  bool     `json:"push_opaque,omitempty"`
	FlagOnly    bool     `json:"flag_only,omitempty"`
	DirtySeen   uint64   `json:"dirty_seen"`
	BudgetMS    int64    `json:"budget_ms"`
}

// hit is one wire finding hit.
type hit struct {
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Path       string `json:"path,omitempty"`
	Line       int    `json:"line,omitempty"`
}

// response is the wire response.
type response struct {
	V            int    `json:"v"`
	Verdict      string `json:"verdict"`
	Findings     []hit  `json:"findings,omitempty"`
	DirtyCovered uint64 `json:"dirty_covered"`
	Reason       string `json:"reason,omitempty"`
}

func encodeRequest(r hookctx.QuickScanRequest, budget time.Duration) request {
	ps := r.Form.Pathspecs
	if len(ps) > MaxPathspecs {
		ps = ps[:MaxPathspecs]
	}
	ops, opaque := r.Form.PushOperands, r.Form.PushOpaque
	if len(ops) > MaxPathspecs {
		ops, opaque = ops[:MaxPathspecs], true
	}
	return request{
		V: Version, ProjectRoot: r.ProjectRoot, Form: string(r.Form.Form), Push: r.Form.Push,
		All: r.Form.All, Amend: r.Form.Amend, Pathspecs: ps, Dir: r.Form.Dir, PushOps: ops, PushOpaque: opaque,
		FlagOnly: r.Form.FlagOnly, DirtySeen: r.DirtySeen, BudgetMS: budget.Milliseconds(),
	}
}

func (q request) decode() (hookctx.QuickScanRequest, time.Duration) {
	b := time.Duration(q.BudgetMS) * time.Millisecond
	if b <= 0 || b > MaxBudget {
		b = MaxBudget
	}
	ps := q.Pathspecs
	if len(ps) > MaxPathspecs {
		ps = ps[:MaxPathspecs]
	}
	ops, opaque := q.PushOps, q.PushOpaque
	if len(ops) > MaxPathspecs {
		ops, opaque = ops[:MaxPathspecs], true
	}
	return hookctx.QuickScanRequest{
		ProjectRoot: q.ProjectRoot, DirtySeen: q.DirtySeen,
		Form: policy.GitWrite{
			Form: policy.GitWriteForm(q.Form), Push: q.Push, All: q.All, Amend: q.Amend, Pathspecs: ps,
			Dir: q.Dir, PushOperands: ops, PushOpaque: opaque, FlagOnly: q.FlagOnly,
		},
	}, b
}

func encodeResult(res hookctx.QuickScanResult, reason string) response {
	out := response{V: Version, Verdict: string(res.Verdict), DirtyCovered: res.DirtyCovered, Reason: reason}
	for i, h := range res.Findings {
		if i >= MaxFindings {
			break
		}
		out.Findings = append(out.Findings, hit{
			Category: string(h.Category), Severity: string(h.Severity), Confidence: string(h.Confidence),
			RuleID: h.RuleID, Path: h.Path, Line: h.Line,
		})
	}
	return out
}

// verdicts is the closed verdict set a response may carry.
var verdicts = map[string]policy.QuickScanVerdict{
	string(policy.QuickScanClean):    policy.QuickScanClean,
	string(policy.QuickScanBlocking): policy.QuickScanBlocking,
	string(policy.QuickScanUnknown):  policy.QuickScanUnknown,
}

func (r response) decode() hookctx.QuickScanResult {
	v, ok := verdicts[r.Verdict]
	if !ok || r.V != Version {
		return hookctx.QuickScanResult{Verdict: policy.QuickScanUnknown}
	}
	out := hookctx.QuickScanResult{Verdict: v, DirtyCovered: r.DirtyCovered}
	for i, h := range r.Findings {
		if i >= MaxFindings {
			break
		}
		path := h.Path
		if len(path) > policy.SecurityHitPathMax {
			path = path[:policy.SecurityHitPathMax]
		}
		out.Findings = append(out.Findings, policy.SecurityHit{
			Category: policy.FindingCategory(h.Category), Severity: policy.FindingSeverity(h.Severity),
			Confidence: policy.FindingConfidence(h.Confidence), RuleID: h.RuleID, Path: path, Line: h.Line,
		})
	}
	// A clean answer carries no findings; anything else is not clean.
	if out.Verdict == policy.QuickScanClean && len(out.Findings) > 0 {
		out.Verdict = policy.QuickScanBlocking
	}
	return out
}

// Ask sends one quick-scan request and waits for the answer, bounded by
// ctx and budget (plus a small transport allowance). Any transport or
// decode failure is an error; the hook context seam then records the
// quick scan as unknown, never clean.
func Ask(ctx context.Context, endpoint string, req hookctx.QuickScanRequest, budget time.Duration) (hookctx.QuickScanResult, error) {
	if budget <= 0 || budget > MaxBudget {
		budget = MaxBudget
	}
	deadline := time.Now().Add(budget + 250*time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := localipc.DefaultTransport().Dial(ctx, endpoint, time.Until(deadline))
	if err != nil {
		return hookctx.QuickScanResult{}, fmt.Errorf("secipc.Ask: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	line, err := json.Marshal(encodeRequest(req, budget))
	if err != nil {
		return hookctx.QuickScanResult{}, fmt.Errorf("secipc.Ask: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return hookctx.QuickScanResult{}, fmt.Errorf("secipc.Ask: %w", err)
	}
	raw, err := readLine(conn)
	if err != nil {
		return hookctx.QuickScanResult{}, fmt.Errorf("secipc.Ask: %w", err)
	}
	var resp response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return hookctx.QuickScanResult{}, fmt.Errorf("secipc.Ask: %w", err)
	}
	return resp.decode(), nil
}

func readLine(conn net.Conn) ([]byte, error) {
	r := bufio.NewReaderSize(conn, 4096)
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > MaxLineBytes {
			return nil, errors.New("secipc: line over its cap")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

// Listen creates the owner-only quick-scan endpoint for the security
// directory. It refuses to take over an endpoint a live daemon serves.
func Listen(securityDir string) (net.Listener, string, error) {
	if !localipc.Supported() {
		return nil, "", fmt.Errorf("secipc.Listen: %w", localipc.ErrUnsupported)
	}
	ep, err := Endpoint(securityDir)
	if err != nil {
		return nil, "", err
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		return nil, "", fmt.Errorf("secipc.Listen: %w", err)
	}
	return ln, ep, nil
}

// DefaultMaxConns bounds the connections Serve handles at once.
const DefaultMaxConns = 8

// busyReplyTimeout bounds the reply to a connection over the cap.
const busyReplyTimeout = time.Second

// Options are Serve's limits (lane SEC-GATEFIX milestone 2h).
type Options struct {
	// MaxConns bounds the connections handled at once (zero:
	// DefaultMaxConns); one over it is answered unknown ("busy") at once
	// and closed, so a flood of connections cannot pile up goroutines or
	// scans.
	MaxConns int
	// AllowRoot reports whether a request may name projectRoot: one of
	// the node's known projects. A root it refuses is answered unknown
	// ("root_not_allowed") with no scan, so the request's DirtySeen is
	// never accepted for it. Nil allows every root.
	AllowRoot func(projectRoot string) bool
	// Feedback answers the feedback request kind (feedback.go, lane
	// sec-h); nil answers it empty ("feedback_not_available").
	Feedback FeedbackAnswerer
	// Nudge takes the commit nudge kind (nudge.go, lane sec-f2b); nil
	// drops it.
	Nudge CommitNudger
}

// Serve answers quick-scan requests on ln until ctx ends with the default
// Options (no root check). The daemon uses ServeWith.
func Serve(ctx context.Context, ln net.Listener, scan hookctx.QuickScanner) error {
	return ServeWith(ctx, ln, scan, Options{})
}

// ServeWith answers quick-scan requests on ln until ctx ends, one goroutine
// per connection up to MaxConns, each request bounded by its own budget.
// A nil scanner answers every request unknown ("quick_scan_not_available"),
// the honest answer before security Phase C supplies one.
func ServeWith(ctx context.Context, ln net.Listener, scan hookctx.QuickScanner, o Options) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	maxConns := o.MaxConns
	if maxConns <= 0 {
		maxConns = DefaultMaxConns
	}
	sem := make(chan struct{}, maxConns)
	busy := make(chan struct{}, 4*maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("secipc.Serve: %w", err)
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				serveConn(ctx, conn, scan, o)
			}()
		default:
			// Over the cap: a short busy answer off the accept loop, itself
			// bounded; past that bound the connection is just closed (the
			// hook reads either as unknown, never clean).
			select {
			case busy <- struct{}{}:
				go func() {
					defer func() { <-busy }()
					replyBusy(conn)
				}()
			default:
				_ = conn.Close()
			}
		}
	}
}

// replyBusy answers a connection over the cap unknown without scanning:
// it reads the request line (within busyReplyTimeout, so the client's
// write completes), answers "busy" and closes.
func replyBusy(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(busyReplyTimeout))
	_, _ = readLine(conn)
	line, err := json.Marshal(encodeResult(hookctx.QuickScanResult{Verdict: policy.QuickScanUnknown}, "busy"))
	if err != nil {
		return
	}
	_, _ = conn.Write(append(line, '\n'))
}

func serveConn(ctx context.Context, conn net.Conn, scan hookctx.QuickScanner, o Options) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(MaxBudget + time.Second))
	raw, err := readLine(conn)
	if err != nil {
		return
	}
	if q, ok := feedbackRequestOf(raw); ok {
		serveFeedbackConn(ctx, conn, q, o.Feedback, o.AllowRoot)
		return
	}
	if q, ok := nudgeRequestOf(raw); ok {
		serveNudgeConn(conn, q, o)
		return
	}
	resp := answer(ctx, raw, scan, o.AllowRoot)
	line, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(line, '\n'))
}

// answer decodes one request and runs the scanner under its budget. A
// scanner that fails, panics or overruns answers unknown, and so does a
// request for a root allow refuses (its DirtySeen is never accepted).
func answer(ctx context.Context, raw []byte, scan hookctx.QuickScanner, allow func(string) bool) (resp response) {
	unknown := func(reason string) response {
		return encodeResult(hookctx.QuickScanResult{Verdict: policy.QuickScanUnknown}, reason)
	}
	var q request
	if err := json.Unmarshal(raw, &q); err != nil || q.V != Version || q.ProjectRoot == "" {
		return unknown("bad_request")
	}
	if scan == nil {
		return unknown("quick_scan_not_available")
	}
	if !filepath.IsAbs(q.ProjectRoot) || (allow != nil && !allow(q.ProjectRoot)) {
		return unknown("root_not_allowed")
	}
	req, budget := q.decode()
	sctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type out struct {
		res hookctx.QuickScanResult
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- out{err: fmt.Errorf("scanner panic: %v", r)}
			}
		}()
		res, err := scan(sctx, req)
		ch <- out{res: res, err: err}
	}()
	select {
	case o := <-ch:
		if o.err != nil {
			return unknown("scan_failed")
		}
		return encodeResult(o.res, "")
	case <-sctx.Done():
		return unknown("over_budget")
	}
}
