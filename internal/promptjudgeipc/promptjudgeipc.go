package promptjudgeipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// Wire limits.
const (
	// Version is the wire version.
	Version = 1
	// MaxPromptBytes caps the prompt a request carries. A longer prompt is
	// not sent: the request says Oversize and the daemon answers with the
	// policy's not-evaluated outcome (refused under a strict enforce
	// policy), never a judgement of a truncated prefix.
	MaxPromptBytes = 512 << 10
	// MaxLineBytes caps one request line (the prompt plus its envelope).
	MaxLineBytes = MaxPromptBytes + 16<<10
	// MaxAnswerBytes caps one answer line.
	MaxAnswerBytes = 16 << 10
	// MaxBudget caps the wait a request may ask for: the node lane's relay
	// default (10 s) plus the hop.
	MaxBudget = 12 * time.Second
	// MaxConcurrent caps the asks the daemon serves at once (adm-2 fixes-1,
	// M1). An ask over the cap is answered "busy" at once, which the hook
	// maps onto the policy's strict flag like any unreachable judge. It also
	// bounds the memory a burst of oversize request lines can hold.
	MaxConcurrent = 32
)

// DirName is the endpoint directory beside the observer DB. Every sandbox
// profile hides it (adm-2 fixes-1, M1): a sandboxed process has no business
// asking the judge, and a hook inside a box reaches the daemon over the
// capture relay instead.
const DirName = "promptjudge"

// keyDir is the synthetic key the endpoint is derived from, beside the
// observer DB, so it never collides with the attach, MCP relay or security
// endpoints.
const keyDir = DirName

// reasonBusy is the error answer for an ask over MaxConcurrent.
const reasonBusy = "busy"

// maxConcurrent is MaxConcurrent, lowered by tests.
var maxConcurrent = MaxConcurrent

// Endpoint returns the prompt judge endpoint for an observer DB path.
func Endpoint(dbPath string) (string, error) {
	if dbPath == "" {
		return "", errors.New("promptjudgeipc.Endpoint: no observer DB path")
	}
	return EndpointInDir(filepath.Dir(dbPath))
}

// EndpointInDir is Endpoint for the directory that holds the observer DB
// (the sandbox layer names the daemon's sockets by that directory).
func EndpointInDir(observerDir string) (string, error) {
	if observerDir == "" {
		return "", errors.New("promptjudgeipc.Endpoint: no observer directory")
	}
	ep, err := localipc.DefaultTransport().Endpoint(filepath.Join(observerDir, keyDir, "ipc"))
	if err != nil {
		return "", fmt.Errorf("promptjudgeipc.Endpoint: %w", err)
	}
	return ep, nil
}

// Request is one prompt the hook asks about.
type Request struct {
	// Tool is the integration registry id of the tool the prompt was typed
	// into (for the audit row only; the daemon never branches on it).
	Tool string
	// SessionID is the tool's session id ("" when the payload had none).
	SessionID string
	// Prompt is the developer's prompt text, as the hook extracted it.
	Prompt string
	// Oversize is true when the hook could not read the whole prompt (a
	// size bound stopped it): the prompt is not sent and the daemon answers
	// with the policy's not-evaluated outcome. A Prompt over MaxPromptBytes
	// is marked the same way.
	Oversize bool
	// Budget is how long the hook can wait for the answer.
	Budget time.Duration
}

// Answer is the daemon's verdict.
type Answer struct {
	// Active is false when no node-lane policy applies on this node: the
	// hook then admits without a verdict (nothing was judged).
	Active bool
	// Action is "allow", "flag" or "block" (promptadmit.Action).
	Action string
	// Basis and Criterion name why (promptadmit.Basis, the criterion id).
	Basis     string
	Criterion string
	// Reason is the developer-facing reason of a block or flag.
	Reason string
}

// Block reports whether the answer refuses the prompt.
func (a Answer) Block() bool { return a.Active && a.Action == "block" }

type request struct {
	V         int    `json:"v"`
	Tool      string `json:"tool,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Prompt    string `json:"prompt,omitempty"`
	Oversize  bool   `json:"oversize,omitempty"`
	BudgetMS  int64  `json:"budget_ms"`
}

type response struct {
	V         int    `json:"v"`
	Active    bool   `json:"active"`
	Action    string `json:"action,omitempty"`
	Basis     string `json:"basis,omitempty"`
	Criterion string `json:"criterion,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ErrBadAnswer is an answer that does not decode, or names an action outside
// the closed set.
var ErrBadAnswer = errors.New("promptjudgeipc: bad answer")

// ErrNotUnderstood is a daemon that answered bad_request (an older or newer
// wire version than the hook's).
var ErrNotUnderstood = errors.New("promptjudgeipc: the daemon did not understand the ask")

// reasonBadRequest is the error of an ask the daemon could not decode.
const reasonBadRequest = "bad_request"

// actions is the closed answer vocabulary.
var actions = map[string]bool{"allow": true, "flag": true, "block": true}

// Ask asks the daemon about one prompt and waits at most req.Budget (capped
// at MaxBudget). Any transport, decode or vocabulary failure is an error.
func Ask(ctx context.Context, endpoint string, req Request) (Answer, error) {
	budget := req.Budget
	if budget <= 0 || budget > MaxBudget {
		budget = MaxBudget
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := localipc.DefaultTransport().Dial(ctx, endpoint, time.Until(deadline))
	if err != nil {
		return Answer{}, fmt.Errorf("promptjudgeipc.Ask: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	wire := request{V: Version, Tool: req.Tool, SessionID: req.SessionID, BudgetMS: time.Until(deadline).Milliseconds()}
	if req.Oversize || len(req.Prompt) > MaxPromptBytes {
		wire.Oversize = true
	} else {
		wire.Prompt = req.Prompt
	}
	line, err := json.Marshal(wire)
	if err != nil {
		return Answer{}, fmt.Errorf("promptjudgeipc.Ask: %w", err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return Answer{}, fmt.Errorf("promptjudgeipc.Ask: %w", err)
	}
	raw, err := readLine(conn, MaxAnswerBytes)
	if err != nil {
		return Answer{}, fmt.Errorf("promptjudgeipc.Ask: %w", err)
	}
	var resp response
	if err := decodeOne(raw, &resp, true); err != nil || resp.V != Version {
		return Answer{}, ErrBadAnswer
	}
	if resp.Error == reasonBadRequest {
		return Answer{}, ErrNotUnderstood
	}
	if resp.Error != "" {
		return Answer{}, fmt.Errorf("promptjudgeipc.Ask: daemon: %s", resp.Error)
	}
	if !resp.Active {
		return Answer{}, nil
	}
	if !actions[resp.Action] {
		return Answer{}, ErrBadAnswer
	}
	return Answer{Active: true, Action: resp.Action, Basis: resp.Basis, Criterion: resp.Criterion, Reason: resp.Reason}, nil
}

// Asked is what the daemon's answer function receives.
type Asked struct {
	Tool      string
	SessionID string
	Prompt    string
	// Oversize is true when the prompt was over MaxPromptBytes and not sent.
	Oversize bool
}

// Answerer answers one ask within ctx's deadline.
type Answerer func(ctx context.Context, a Asked) Answer

// Listen creates the owner-only endpoint for dbPath. It refuses to take over
// an endpoint a live daemon serves.
func Listen(dbPath string) (net.Listener, string, error) {
	if !localipc.Supported() {
		return nil, "", fmt.Errorf("promptjudgeipc.Listen: %w", localipc.ErrUnsupported)
	}
	ep, err := Endpoint(dbPath)
	if err != nil {
		return nil, "", err
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		return nil, "", fmt.Errorf("promptjudgeipc.Listen: %w", err)
	}
	return ln, ep, nil
}

// Serve answers asks on ln until ctx ends, one goroutine per connection, at
// most MaxConcurrent at once: an ask over the cap is answered "busy" without
// its request being read.
func Serve(ctx context.Context, ln net.Listener, answer Answerer) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	slots := make(chan struct{}, maxConcurrent)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("promptjudgeipc.Serve: %w", err)
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				serveConn(ctx, conn, answer)
			}()
		default:
			go refuseBusy(conn)
		}
	}
}

// refuseBusy answers an ask over the concurrency cap.
func refuseBusy(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	line, err := json.Marshal(response{V: Version, Error: reasonBusy})
	if err != nil {
		return
	}
	_, _ = conn.Write(append(line, '\n'))
}

func serveConn(ctx context.Context, conn net.Conn, answer Answerer) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(MaxBudget + time.Second))
	raw, err := readLine(conn, MaxLineBytes)
	if err != nil {
		return
	}
	line, err := json.Marshal(handle(ctx, raw, answer))
	if err != nil {
		return
	}
	_, _ = conn.Write(append(line, '\n'))
}

// handle decodes one request and runs the answerer under its budget. A panic
// or an overrun answers an error the hook maps onto the strict flag.
func handle(ctx context.Context, raw []byte, answer Answerer) response {
	resp := response{V: Version}
	var q request
	if err := decodeOne(raw, &q, false); err != nil || q.V != Version {
		resp.Error = reasonBadRequest
		return resp
	}
	if answer == nil {
		resp.Error = "not_available"
		return resp
	}
	budget := time.Duration(q.BudgetMS) * time.Millisecond
	if budget <= 0 || budget > MaxBudget {
		budget = MaxBudget
	}
	actx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ch := make(chan Answer, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- Answer{Action: "error"}
			}
		}()
		ch <- answer(actx, Asked{Tool: q.Tool, SessionID: q.SessionID, Prompt: q.Prompt, Oversize: q.Oversize})
	}()
	select {
	case a := <-ch:
		switch {
		case a.Action == "error":
			resp.Error = "panic"
		case !a.Active:
		case !actions[a.Action]:
			resp.Error = "bad_action"
		default:
			resp.Active, resp.Action, resp.Basis, resp.Criterion = true, a.Action, a.Basis, a.Criterion
			resp.Reason = clip(a.Reason, 2048)
		}
	case <-actx.Done():
		resp.Error = "over_budget"
	}
	return resp
}

// clip bounds a reason without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

func decodeOne(b []byte, v any, disallowUnknown bool) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if disallowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON value")
	}
	return nil
}

func readLine(conn net.Conn, maxBytes int) ([]byte, error) {
	r := bufio.NewReaderSize(conn, 4096)
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxBytes {
			return nil, errors.New("promptjudgeipc: line over its cap")
		}
		if !isPrefix {
			return out, nil
		}
	}
}
