package mcprelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
)

// session.go is the stdio-framed mediation loop shared by the IPC mode and
// the stdio wrapper: frames arrive from a client (`in`), each request is
// decided, forwarded to the upstream and its reply written to `out`.

// Upstream is where a stdio session's mediated frames go.
type Upstream interface {
	// Send delivers one client frame. For a request the reply frames come
	// back through the session's reply path (a remote HTTP upstream answers
	// synchronously; a local child answers on its own stdout).
	Send(ctx context.Context, c Call, v Verdict) error
}

// sessionSpec is what a serving mode knows about the client on one stream.
type sessionSpec struct {
	target      Target
	transport   localpdp.Transport
	attestation string
	agent       string
	product     string
	corr        Correlation
	// projectHash is the relay-attested project of the stream (P11(e)).
	projectHash string
}

// session mediates one client stream.
type session struct {
	r    *Relay
	spec sessionSpec
	in   io.Reader
	out  io.Writer
	up   Upstream

	// upCompletes marks an Upstream that records completions itself
	// (the HTTP upstream sees the reply synchronously).
	upCompletes bool

	wmu sync.Mutex
	// pending maps a forwarded request id to its verdict so a child's reply
	// can complete it.
	pmu     sync.Mutex
	pending map[string]Verdict
}

func newSession(r *Relay, spec sessionSpec, in io.Reader, out io.Writer, up Upstream) *session {
	return &session{r: r, spec: spec, in: in, out: out, up: up, pending: map[string]Verdict{}}
}

// write emits one frame to the client, serialized across goroutines.
func (s *session) write(frame []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return WriteFrame(s.out, frame)
}

// call builds the Call for one raw frame.
func (s *session) call(raw []byte) Call {
	return Call{
		Target: s.spec.target, Raw: raw, Transport: s.spec.transport, Attestation: s.spec.attestation,
		Agent: s.spec.agent, Product: s.spec.product, Corr: s.spec.corr, ProjectHash: s.spec.projectHash,
	}
}

// run reads client frames until EOF/ctx, mediating each one. Every client
// request is decided BEFORE the upstream sees any byte of it.
func (s *session) run(ctx context.Context) error {
	fr := NewFrameReader(s.in, 0)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := fr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if errors.Is(err, ErrFrameTooLarge) {
				_ = s.write(ErrorFrame(nil, CodeInvalidRequest, err.Error()))
				continue
			}
			return err
		}
		c := s.call(raw)
		v := s.r.Decide(ctx, c)
		if !v.Forward {
			if len(v.Refuse) > 0 {
				if werr := s.write(v.Refuse); werr != nil {
					return werr
				}
			}
			continue
		}
		if v.Msg != nil && v.Msg.IsRequest() {
			s.pmu.Lock()
			s.pending[v.Msg.IDKey()] = v
			s.pmu.Unlock()
		}
		err = s.up.Send(ctx, c, v)
		if err == nil && v.Msg != nil && v.Msg.IsNotification() && !s.upCompletes {
			// A notification has no reply frame: the successful hand-off
			// to the child IS its completion.
			s.r.Complete(ctx, v, "ok", nil, "")
		}
		if err != nil {
			s.forget(v)
			s.r.Complete(ctx, v, "unavailable", nil, err.Error())
			if v.Msg != nil && v.Msg.IsRequest() {
				if werr := s.write(ErrorFrame(v.Msg.ID, CodeUnavailable, "relay: upstream unavailable: "+err.Error())); werr != nil {
					return werr
				}
				continue
			}
			return fmt.Errorf("mcprelay: upstream: %w", err)
		}
	}
}

func (s *session) forget(v Verdict) {
	if v.Msg == nil || !v.Msg.IsRequest() {
		return
	}
	s.pmu.Lock()
	delete(s.pending, v.Msg.IDKey())
	s.pmu.Unlock()
}

// reply handles one upstream frame: a response completes its pending
// request (catalogue filter applied when the local PDP set one); every
// frame is relayed verbatim otherwise.
func (s *session) reply(ctx context.Context, frame []byte) error {
	m, err := ParseMessage(frame)
	if err != nil || !m.IsResponse() {
		return s.write(frame)
	}
	s.pmu.Lock()
	v, ok := s.pending[m.IDKey()]
	if ok {
		delete(s.pending, m.IDKey())
	}
	s.pmu.Unlock()
	if !ok {
		return s.write(frame)
	}
	out := frame
	if len(v.Visible) > 0 || v.Visible != nil {
		out = filterCatalogue(v, m, frame)
	}
	status, errBody := "ok", ""
	if m.Error != nil {
		status = "error"
		eb, _ := json.Marshal(m.Error)
		errBody = string(eb)
	}
	s.r.Complete(ctx, v, status, out, errBody)
	return s.write(out)
}

// filterCatalogue prunes a listing result to the visible names (an absent
// or empty visible set yields an empty list, never the raw catalogue).
func filterCatalogue(v Verdict, m *Message, frame []byte) []byte {
	listKey, nameKey := catalogueKeys(v.Msg.Method)
	if listKey == "" || m.Result == nil {
		return frame
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(m.Result, &result) != nil {
		return frame
	}
	var items []json.RawMessage
	if raw, ok := result[listKey]; ok {
		_ = json.Unmarshal(raw, &items)
	}
	allow := map[string]bool{}
	for _, n := range v.Visible {
		allow[n] = true
	}
	kept := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		var named map[string]json.RawMessage
		if json.Unmarshal(it, &named) != nil {
			continue
		}
		var name string
		if json.Unmarshal(named[nameKey], &name) == nil && allow[name] {
			kept = append(kept, it)
		}
	}
	rk, _ := json.Marshal(kept)
	result[listKey] = rk
	rb, _ := json.Marshal(result)
	out, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", m.ID, rb})
	return out
}

// catalogueKeys maps a listing method to its result array + name member.
func catalogueKeys(method string) (listKey, nameKey string) {
	switch method {
	case "tools/list":
		return "tools", "name"
	case "prompts/list":
		return "prompts", "name"
	case "resources/list":
		return "resources", "uri"
	case "resources/templates/list":
		return "resourceTemplates", "uriTemplate"
	}
	return "", ""
}

// httpUpstream forwards a session's frames to the org front and writes the
// reply frames back on the session.
type httpUpstream struct{ s *session }

// Send implements Upstream.
func (u httpUpstream) Send(ctx context.Context, c Call, v Verdict) error {
	rp, err := u.s.r.ForwardHTTP(ctx, c, v)
	if err != nil {
		return err
	}
	var id json.RawMessage
	if v.Msg != nil {
		id = v.Msg.ID
	}
	frames := rp.Frames(id)
	u.s.forget(v)
	u.s.r.Complete(ctx, v, rp.Outcome(), rp.Body, "")
	for _, f := range frames {
		if err := u.s.write(f); err != nil {
			return err
		}
	}
	return nil
}
