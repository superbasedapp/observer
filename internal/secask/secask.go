package secask

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
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// Wire limits.
const (
	// Version is the wire version.
	Version = 1
	// MaxLineBytes caps one request or answer line (JSP-11: 16 KiB).
	MaxLineBytes = 16 << 10
	// MaxSpecs caps the packages one ask names.
	MaxSpecs = 32
	// MaxBudget caps the wait a request may ask for (the picker tops out
	// at 3 s).
	MaxBudget = 3 * time.Second
)

// keyDir is the directory under the security directory the endpoint is
// derived from, so it never collides with the quick-scan endpoint.
const keyDir = "ask"

// Endpoint returns the ask endpoint for the security directory.
func Endpoint(securityDir string) (string, error) {
	if securityDir == "" {
		return "", errors.New("secask.Endpoint: no security directory")
	}
	ep, err := localipc.DefaultTransport().Endpoint(filepath.Join(securityDir, keyDir, "endpoint"))
	if err != nil {
		return "", fmt.Errorf("secask.Endpoint: %w", err)
	}
	return ep, nil
}

// wireSpec is one asked package.
type wireSpec struct {
	Eco     secfeed.Ecosystem `json:"eco"`
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Spec    string            `json:"spec,omitempty"`
	// Private carries InstallSpec.Private (a registry flag or variable on
	// the command line, X4): the daemon then answers it private, unsent.
	Private bool `json:"private,omitempty"`
}

type request struct {
	V           int        `json:"v"`
	ProjectRoot string     `json:"project_root"`
	Specs       []wireSpec `json:"specs"`
	BudgetMS    int64      `json:"budget_ms"`
	// Dirs, DirsUnknown and Env carry the rest of the classification
	// scope (secfeed.Scope): the directories whose configuration applies
	// and the developer's source-naming variables. The daemon applies them
	// on top of its own files and environment; they only ever make a name
	// more private.
	Dirs        []string          `json:"dirs,omitempty"`
	DirsUnknown bool              `json:"dirs_unknown,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
}

type response struct {
	V       int                    `json:"v"`
	Answers []secfeed.OnlineAnswer `json:"answers"`
	Reason  string                 `json:"reason,omitempty"`
}

// ErrBadAnswer is an answer that does not decode or names another package.
var ErrBadAnswer = errors.New("secask: bad answer")

// ErrNotUnderstood is a daemon that answered "bad_request": it did not
// understand the ask (an older daemon than the hook, a wire version it
// does not speak). The hook then keeps its own offline answer rather than
// reading the ask as failed (lane SEC-DEPS3 item 11), so a daemon left
// running across an upgrade does not make every public install ask S-748
// under enforce.
var ErrNotUnderstood = errors.New("secask: the daemon did not understand the ask")

// reasonBadRequest is the answer reason for an ask the daemon could not
// decode.
const reasonBadRequest = "bad_request"

// Ask asks the daemon about specs and waits at most budget. Any transport
// or decode failure is an error (the gate's online_unknown).
func Ask(ctx context.Context, endpoint string, scope secfeed.Scope, specs []secfeed.InstallSpec, budget time.Duration) ([]secfeed.OnlineAnswer, error) {
	if budget <= 0 || budget > MaxBudget {
		budget = MaxBudget
	}
	if len(specs) > MaxSpecs {
		specs = specs[:MaxSpecs]
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	conn, err := localipc.DefaultTransport().Dial(ctx, endpoint, time.Until(deadline))
	if err != nil {
		return nil, fmt.Errorf("secask.Ask: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)
	req := request{V: Version, ProjectRoot: scope.ProjectRoot, BudgetMS: time.Until(deadline).Milliseconds(), Dirs: scope.Dirs, DirsUnknown: scope.Unknown, Env: scope.Env}
	asked := map[string]bool{}
	for _, s := range specs {
		req.Specs = append(req.Specs, wireSpec{Eco: s.Eco, Name: s.Name, Version: s.Version, Spec: s.Spec, Private: s.Private})
		asked[key(s.Eco, s.Name, s.Version)] = true
	}
	line, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("secask.Ask: %w", err)
	}
	if len(line) > MaxLineBytes {
		return nil, errors.New("secask.Ask: request over its cap")
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("secask.Ask: %w", err)
	}
	raw, err := readLine(conn)
	if err != nil {
		return nil, fmt.Errorf("secask.Ask: %w", err)
	}
	var resp response
	if err := strict(raw, &resp); err != nil || resp.V != Version {
		return nil, ErrBadAnswer
	}
	if resp.Reason == reasonBadRequest && len(resp.Answers) == 0 {
		return nil, ErrNotUnderstood
	}
	var out []secfeed.OnlineAnswer
	for _, a := range resp.Answers {
		if !asked[key(a.Eco, a.Name, a.Version)] {
			// An answer about a package that was not asked about is dropped
			// (JSP-11); the gate then reads that package as unanswered.
			continue
		}
		out = append(out, a)
	}
	if len(resp.Answers) > 0 && len(out) == 0 {
		return nil, ErrBadAnswer
	}
	return out, nil
}

func key(eco secfeed.Ecosystem, name, version string) string {
	return string(eco) + "\x00" + secfeed.Normalize(eco, name) + "\x00" + version
}

func strict(b []byte, v any) error { return decodeOne(b, v, true) }

// lenient decodes one request: a field this daemon does not know is
// ignored (lane SEC-DEPS3 item 11). Wire rule for version 1: a field added
// to the request only ever makes a name more private, and the hook applies
// it itself before it asks (it asks only about names its own full scope
// calls public), so an older daemon that ignores the field never sends a
// name the hook kept private.
func lenient(b []byte, v any) error { return decodeOne(b, v, false) }

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
			return nil, errors.New("secask: line over its cap")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

// Answerer answers one ask within ctx's deadline.
type Answerer func(ctx context.Context, scope secfeed.Scope, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer

// Listen creates the owner-only ask endpoint. It refuses to take over an
// endpoint a live daemon serves.
func Listen(securityDir string) (net.Listener, string, error) {
	if !localipc.Supported() {
		return nil, "", fmt.Errorf("secask.Listen: %w", localipc.ErrUnsupported)
	}
	ep, err := Endpoint(securityDir)
	if err != nil {
		return nil, "", err
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		return nil, "", fmt.Errorf("secask.Listen: %w", err)
	}
	return ln, ep, nil
}

// Serve answers asks on ln until ctx ends, one goroutine per connection.
func Serve(ctx context.Context, ln net.Listener, answer Answerer) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("secask.Serve: %w", err)
		}
		go serveConn(ctx, conn, answer)
	}
}

func serveConn(ctx context.Context, conn net.Conn, answer Answerer) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(MaxBudget + time.Second))
	raw, err := readLine(conn)
	if err != nil {
		return
	}
	resp := handle(ctx, raw, answer)
	line, err := json.Marshal(resp)
	for err == nil && len(line) > MaxLineBytes && len(resp.Answers) > 0 {
		// Never send an answer over the cap: shed answers from the end
		// (the hook reads those as unanswered, online_unknown).
		resp.Answers = resp.Answers[:len(resp.Answers)-1]
		line, err = json.Marshal(resp)
	}
	if err != nil {
		return
	}
	_, _ = conn.Write(append(line, '\n'))
}

// handle decodes one request and runs the answerer under its budget. A
// panic or overrun answers with no answers (the hook's online_unknown).
func handle(ctx context.Context, raw []byte, answer Answerer) (resp response) {
	resp = response{V: Version}
	var q request
	if err := lenient(raw, &q); err != nil || q.V != Version || len(q.Specs) > MaxSpecs {
		resp.Reason = reasonBadRequest
		return resp
	}
	if answer == nil {
		resp.Reason = "not_available"
		return resp
	}
	budget := time.Duration(q.BudgetMS) * time.Millisecond
	if budget <= 0 || budget > MaxBudget {
		budget = MaxBudget
	}
	actx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var specs []secfeed.InstallSpec
	for _, s := range q.Specs {
		sp := secfeed.ParseSpec(s.Eco, s.Spec)
		if s.Spec == "" {
			sp = secfeed.InstallSpec{Eco: s.Eco, Spec: s.Name, Name: s.Name, Version: s.Version}
		}
		// The daemon re-parses what the hook sent: a name and version the
		// wire claims but the spec does not say are not trusted. Private
		// is only ever honoured toward more privacy.
		sp.Private = s.Private
		specs = append(specs, sp)
	}
	ch := make(chan []secfeed.OnlineAnswer, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- nil
			}
		}()
		ch <- answer(actx, secfeed.Scope{ProjectRoot: q.ProjectRoot, Dirs: q.Dirs, Unknown: q.DirsUnknown, Env: q.Env}, specs)
	}()
	select {
	case a := <-ch:
		resp.Answers = a
	case <-actx.Done():
		resp.Reason = "over_budget"
	}
	return resp
}
