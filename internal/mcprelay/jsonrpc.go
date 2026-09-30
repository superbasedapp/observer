package mcprelay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Stdio framing (MCP stdio transport): one JSON-RPC message per line,
// newline-delimited, no embedded newlines. The relay never re-encodes a
// frame it forwards - it carries the client's bytes to the upstream and the
// upstream's bytes back, so a client and a server that agree on a frame's
// exact bytes still agree with the relay in between (§12.2 "preserve stdio
// framing").

// MaxFrameBytes caps one stdio frame (a tools/call result may be large; an
// unbounded line would let a misbehaving peer exhaust memory).
const MaxFrameBytes = 16 << 20

// ErrFrameTooLarge is returned by a FrameReader for a line over MaxFrameBytes.
var ErrFrameTooLarge = errors.New("mcprelay: stdio frame exceeds the size cap")

// FrameReader reads newline-delimited frames from r, tolerating arbitrary
// fragmentation of the underlying stream: a frame is complete only at its
// newline, whatever the read chunking. Empty lines are skipped (the stdio
// transport allows them between messages).
type FrameReader struct {
	r   *bufio.Reader
	max int
}

// NewFrameReader wraps r. max <= 0 selects MaxFrameBytes.
func NewFrameReader(r io.Reader, max int) *FrameReader {
	if max <= 0 {
		max = MaxFrameBytes
	}
	return &FrameReader{r: bufio.NewReaderSize(r, 64<<10), max: max}
}

// Next returns the next frame WITHOUT its trailing newline (a trailing CR
// is kept: the bytes are the peer's). io.EOF ends the stream; a final
// unterminated line is returned as its own frame.
func (f *FrameReader) Next() ([]byte, error) {
	var buf []byte
	for {
		chunk, err := f.r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			buf = append(buf, chunk...)
			if len(buf) > f.max {
				return nil, ErrFrameTooLarge
			}
			continue
		}
		buf = append(buf, chunk...)
		if len(buf) > f.max {
			return nil, ErrFrameTooLarge
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(bytes.TrimSpace(buf)) > 0 {
				return bytes.TrimSuffix(buf, []byte("\n")), nil
			}
			return nil, err
		}
		line := bytes.TrimSuffix(buf, []byte("\n"))
		if len(bytes.TrimSpace(line)) == 0 {
			buf = buf[:0]
			continue
		}
		return line, nil
	}
}

// WriteFrame writes one frame followed by a newline. The frame's bytes are
// written verbatim; a frame that itself contains a newline is refused
// (it would split into two frames at the peer).
func WriteFrame(w io.Writer, frame []byte) error {
	if bytes.IndexByte(frame, '\n') >= 0 {
		return errors.New("mcprelay: frame contains a newline")
	}
	out := make([]byte, 0, len(frame)+1)
	out = append(out, frame...)
	out = append(out, '\n')
	_, err := w.Write(out)
	return err
}

// Message is the governed view of a JSON-RPC 2.0 message. Params stays raw:
// the relay forwards the ORIGINAL bytes, this is only what it decides on.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// HasID reports a non-null id.
func (m *Message) HasID() bool { return len(m.ID) > 0 && string(m.ID) != "null" }

// IsRequest reports a request (method + id).
func (m *Message) IsRequest() bool { return m.Method != "" && m.HasID() }

// IsNotification reports a notification (method, no id).
func (m *Message) IsNotification() bool { return m.Method != "" && !m.HasID() }

// IsResponse reports a response (no method; result or error).
func (m *Message) IsResponse() bool { return m.Method == "" && (m.Result != nil || m.Error != nil) }

// IDKey is the id rendered as a map key (the canonical JSON of the id).
func (m *Message) IDKey() string { return string(bytes.TrimSpace(m.ID)) }

// ErrBatch is returned for a JSON array: batches are not accepted (stock
// agentgateway and the front refuse them too, ADR-0007 §3.2).
var ErrBatch = errors.New("mcprelay: JSON-RPC batches are not accepted")

// ParseMessage decodes one message. A JSON array is ErrBatch.
func ParseMessage(raw []byte) (*Message, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return nil, errors.New("mcprelay: empty message")
	}
	if t[0] == '[' {
		return nil, ErrBatch
	}
	var m Message
	if err := json.Unmarshal(t, &m); err != nil {
		return nil, fmt.Errorf("mcprelay: parse message: %w", err)
	}
	if m.JSONRPC != "2.0" {
		return nil, errors.New("mcprelay: jsonrpc must be \"2.0\"")
	}
	return &m, nil
}

// governedParams is the params subset the relay addresses a decision by.
type governedParams struct {
	Name   string `json:"name,omitempty"`
	URI    string `json:"uri,omitempty"`
	TaskID string `json:"taskId,omitempty"`
	Ref    *struct {
		Name string `json:"name,omitempty"`
		URI  string `json:"uri,omitempty"`
	} `json:"ref,omitempty"`
	Meta *struct {
		ProtocolVersion string `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	} `json:"_meta,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// MethodClass is how the relay treats a method (the front's partition,
// doc3 §9.1: governed methods carry an effect; catalogue methods are
// list/discover; protocol methods are relayed and recorded as catalogue).
type MethodClass string

// Method classes.
const (
	ClassGoverned  MethodClass = "governed"
	ClassCatalogue MethodClass = "catalogue"
	ClassProtocol  MethodClass = "protocol"
)

// methodRow is one row of the relay's method table: the class, the
// mcpaccess action name, the event kind recorded, and how the governed
// target is read from params.
type methodRow struct {
	Class     MethodClass
	Action    string
	EventKind string
	Target    func(governedParams) string
}

func byName(p governedParams) string   { return p.Name }
func byURI(p governedParams) string    { return p.URI }
func byTaskID(p governedParams) string { return p.TaskID }
func byRef(p governedParams) string {
	if p.Ref == nil {
		return ""
	}
	if p.Ref.Name != "" {
		return p.Ref.Name
	}
	return p.Ref.URI
}

// methods is the dispatch table (the front's Methods partition transposed
// to the node; unknown methods are relayed as protocol traffic for a
// node-local server the client already owns, and refused by the front for a
// remote vserver - the front is authoritative there).
var methods = map[string]methodRow{
	"tools/call":               {ClassGoverned, "call", "mcp_call", byName},
	"prompts/get":              {ClassGoverned, "read", "mcp_prompt", byName},
	"resources/read":           {ClassGoverned, "read", "mcp_read", byURI},
	"completion/complete":      {ClassGoverned, "read", "mcp_read", byRef},
	"subscriptions/listen":     {ClassGoverned, "subscribe", "mcp_subscribe", nil},
	"resources/subscribe":      {ClassGoverned, "subscribe", "mcp_subscribe", byURI},
	"resources/unsubscribe":    {ClassGoverned, "subscribe", "mcp_subscribe", byURI},
	"tasks/get":                {ClassGoverned, "tasks_get", "mcp_task", byTaskID},
	"tasks/update":             {ClassGoverned, "tasks_update", "mcp_task", byTaskID},
	"tasks/cancel":             {ClassGoverned, "tasks_cancel", "mcp_task", byTaskID},
	"tools/list":               {ClassCatalogue, "list", "mcp_list", nil},
	"prompts/list":             {ClassCatalogue, "list", "mcp_list", nil},
	"resources/list":           {ClassCatalogue, "list", "mcp_list", nil},
	"resources/templates/list": {ClassCatalogue, "list", "mcp_list", nil},
	"server/discover":          {ClassCatalogue, "discover", "mcp_list", nil},
	"ping":                     {ClassCatalogue, "", "mcp_list", nil},
	"initialize":               {ClassProtocol, "", "mcp_list", nil},
	"logging/setLevel":         {ClassProtocol, "", "mcp_list", nil},
}

// classify resolves a request message to its row (protocol for notifications
// and unknown methods) and its governed target.
func classify(m *Message) (row methodRow, target string, protocolVersion string) {
	row, ok := methods[m.Method]
	if !ok || m.IsNotification() {
		row = methodRow{Class: ClassProtocol, EventKind: "mcp_list"}
	}
	var p governedParams
	if len(m.Params) > 0 && string(m.Params) != "null" {
		_ = json.Unmarshal(m.Params, &p)
	}
	if row.Target != nil {
		target = row.Target(p)
	}
	protocolVersion = p.ProtocolVersion
	if p.Meta != nil && p.Meta.ProtocolVersion != "" {
		protocolVersion = p.Meta.ProtocolVersion
	}
	return row, target, protocolVersion
}

// JSON-RPC error codes the relay emits itself.
const (
	// CodeInvalidRequest is the JSON-RPC invalid-request code.
	CodeInvalidRequest = -32600
	// CodeParse is the JSON-RPC parse-error code.
	CodeParse = -32700
	// CodeForbidden is the PDP deny code (the front's pdp.CodeForbidden).
	CodeForbidden = -32003
	// CodeUnavailable is the "cannot decide / cannot record" code
	// (the front's pdp.CodeUnavailable).
	CodeUnavailable = -32050
)

// ErrorFrame renders a JSON-RPC error response for id.
func ErrorFrame(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   RPCError        `json:"error"`
	}{"2.0", id, RPCError{Code: code, Message: msg}})
	return b
}

// sseEvent is one server-sent event.
type sseEvent struct {
	Event string
	Data  []byte
}

// readSSE parses a text/event-stream body into events (data lines joined
// by "\n", as the SSE spec prescribes). It stops at EOF or ctx-free read
// error and returns what it has.
func readSSE(r io.Reader, max int64) ([]sseEvent, error) {
	sc := bufio.NewScanner(io.LimitReader(r, max))
	sc.Buffer(make([]byte, 64<<10), MaxFrameBytes)
	var out []sseEvent
	var cur sseEvent
	var data []string
	flush := func() {
		if len(data) > 0 {
			cur.Data = []byte(strings.Join(data, "\n"))
			out = append(out, cur)
		}
		cur, data = sseEvent{}, nil
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			cur.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return out, sc.Err()
}
