package mcpegress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/mcpschema"
)

// ProtocolVersion is the MCP protocol revision the discovery client speaks.
const ProtocolVersion = "2025-06-18"

// maxToolPages bounds tools/list pagination so a hostile upstream cannot
// keep the poller listing forever.
const maxToolPages = 50

// Sentinel errors. Callers match with errors.Is.
var (
	// ErrDiscoveryUnsupported reports a transport this wave cannot list
	// (sse_legacy, openapi, node_local_stdio).
	ErrDiscoveryUnsupported = errors.New("mcpegress: discovery not supported for this transport")
	// ErrUpstreamStatus reports a non-2xx upstream HTTP status.
	ErrUpstreamStatus = errors.New("mcpegress: upstream HTTP status")
	// ErrUpstreamProtocol reports a malformed or unexpected JSON-RPC exchange.
	ErrUpstreamProtocol = errors.New("mcpegress: upstream protocol error")
	// ErrUpstreamRPC reports a JSON-RPC error object returned by the upstream.
	ErrUpstreamRPC = errors.New("mcpegress: upstream JSON-RPC error")
)

// DiscoverRequest describes one discovery run.
type DiscoverRequest struct {
	// URL is the server's registered upstream URL (preflight-validated).
	URL string
	// Transport is the server's registered transport.
	Transport string
	// Headers are added to every request (an upstream credential the caller
	// resolved; never logged by this package).
	Headers http.Header
	// ClientName / ClientVersion are advertised in initialize.
	ClientName    string
	ClientVersion string
	// MaxResponseBytes overrides the client config bound (0 = default).
	MaxResponseBytes int64
}

// Discovery is what a successful ListTools returns.
type Discovery struct {
	Tools           []mcpschema.Tool
	ProtocolVersion string
	ServerName      string
	ServerVersion   string
	// Pages is the number of tools/list pages fetched.
	Pages int
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
	Method  string          `json:"method"`
}

// ListTools performs the MCP handshake against req.URL through client (a
// guarded client from NewClient / Pool) and returns every advertised tool.
// It never follows redirects and never reads more than the configured bound.
func ListTools(ctx context.Context, client *http.Client, req DiscoverRequest) (Discovery, error) {
	if client == nil {
		return Discovery{}, errors.New("mcpegress.ListTools: a guarded client is required")
	}
	if req.Transport != TransportStreamableHTTP {
		return Discovery{}, fmt.Errorf("mcpegress.ListTools: %w: %s", ErrDiscoveryUnsupported, req.Transport)
	}
	limit := req.MaxResponseBytes
	if limit <= 0 {
		limit = defaultMaxResponseBytes
	}
	s := &session{ctx: ctx, client: client, req: req, limit: limit}
	defer s.close()

	name, version := req.ClientName, req.ClientVersion
	if name == "" {
		name = defaultUserAgent
	}
	if version == "" {
		version = "1"
	}
	initResult, err := s.call("initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": name, "version": version},
	})
	if err != nil {
		return Discovery{}, fmt.Errorf("mcpegress.ListTools: initialize: %w", err)
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(initResult, &init); err != nil {
		return Discovery{}, fmt.Errorf("mcpegress.ListTools: %w: initialize result: %w", ErrUpstreamProtocol, err)
	}
	if init.ProtocolVersion != "" {
		s.protocol = init.ProtocolVersion
	}
	if err := s.notify("notifications/initialized"); err != nil {
		return Discovery{}, fmt.Errorf("mcpegress.ListTools: initialized: %w", err)
	}
	out := Discovery{ProtocolVersion: init.ProtocolVersion, ServerName: init.ServerInfo.Name, ServerVersion: init.ServerInfo.Version}
	cursor := ""
	for page := 0; page < maxToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		result, err := s.call("tools/list", params)
		if err != nil {
			return Discovery{}, fmt.Errorf("mcpegress.ListTools: tools/list: %w", err)
		}
		tools, next, err := mcpschema.ParseToolsListResult(result)
		if err != nil {
			return Discovery{}, fmt.Errorf("mcpegress.ListTools: %w: %w", ErrUpstreamProtocol, err)
		}
		out.Tools = append(out.Tools, tools...)
		out.Pages++
		if next == "" || next == cursor {
			return out, nil
		}
		cursor = next
	}
	return Discovery{}, fmt.Errorf("mcpegress.ListTools: %w: more than %d tools/list pages", ErrUpstreamProtocol, maxToolPages)
}

// session is one streamable-HTTP conversation (session id carried).
type session struct {
	ctx       context.Context
	client    *http.Client
	req       DiscoverRequest
	limit     int64
	nextID    int64
	sessionID string
	protocol  string
}

func (s *session) newRequest(method string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(s.ctx, method, s.req.URL, r)
	if err != nil {
		return nil, err
	}
	for k, vs := range s.req.Headers {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	hr.Header.Set("User-Agent", defaultUserAgent)
	hr.Header.Set("Accept", "application/json, text/event-stream")
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if s.sessionID != "" {
		hr.Header.Set("Mcp-Session-Id", s.sessionID)
	}
	if s.protocol != "" {
		hr.Header.Set("MCP-Protocol-Version", s.protocol)
	}
	return hr, nil
}

// call sends one request and returns its result, reading either a JSON body
// or the first matching message of an SSE stream.
func (s *session) call(method string, params any) (json.RawMessage, error) {
	s.nextID++
	id := s.nextID
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	hr, err := s.newRequest(http.MethodPost, body)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(hr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		s.sessionID = sid
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w %d", ErrUpstreamStatus, resp.StatusCode)
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	reader := io.LimitReader(resp.Body, s.limit+1)
	var msg rpcResponse
	switch mediaType {
	case "text/event-stream":
		found, err := readSSEResponse(reader, id, s.limit)
		if err != nil {
			return nil, err
		}
		msg = found
	default:
		raw, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) > s.limit {
			return nil, fmt.Errorf("%w: response larger than %d bytes", ErrUpstreamProtocol, s.limit)
		}
		if err := json.Unmarshal(raw, &msg); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUpstreamProtocol, err)
		}
		if !idMatches(msg.ID, id) {
			return nil, fmt.Errorf("%w: response id %s does not match request %d", ErrUpstreamProtocol, string(msg.ID), id)
		}
	}
	if msg.Error != nil {
		return nil, fmt.Errorf("%w %d: %s", ErrUpstreamRPC, msg.Error.Code, msg.Error.Message)
	}
	if len(msg.Result) == 0 {
		return nil, fmt.Errorf("%w: response without result", ErrUpstreamProtocol)
	}
	return msg.Result, nil
}

// notify sends a JSON-RPC notification (no id); a 2xx of any kind is fine.
func (s *session) notify(method string) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", Method: method})
	if err != nil {
		return err
	}
	hr, err := s.newRequest(http.MethodPost, body)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(hr)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.limit))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w %d", ErrUpstreamStatus, resp.StatusCode)
	}
	return nil
}

// close ends the session upstream (best effort; a server may not support
// DELETE and answers 405, which is fine).
func (s *session) close() {
	if s.sessionID == "" {
		return
	}
	hr, err := s.newRequest(http.MethodDelete, nil)
	if err != nil {
		return
	}
	if resp, err := s.client.Do(hr); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.limit))
		_ = resp.Body.Close()
	}
}

// idMatches reports whether a JSON-RPC id (number or string form) equals want.
func idMatches(raw json.RawMessage, want int64) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed == fmt.Sprint(want) || trimmed == fmt.Sprintf("%q", fmt.Sprint(want))
}

// readSSEResponse scans an SSE stream for the JSON-RPC response with id want,
// reading at most limit bytes.
func readSSEResponse(r io.Reader, want int64, limit int64) (rpcResponse, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), int(limit))
	var data []string
	var read int64
	flush := func() (rpcResponse, bool, error) {
		if len(data) == 0 {
			return rpcResponse{}, false, nil
		}
		payload := strings.Join(data, "\n")
		data = data[:0]
		var msg rpcResponse
		if err := json.Unmarshal([]byte(payload), &msg); err != nil {
			return rpcResponse{}, false, fmt.Errorf("%w: SSE data: %w", ErrUpstreamProtocol, err)
		}
		if msg.Method != "" || !idMatches(msg.ID, want) {
			return rpcResponse{}, false, nil // a notification or another id: keep reading
		}
		return msg, true, nil
	}
	for sc.Scan() {
		line := sc.Text()
		read += int64(len(line)) + 1
		if read > limit {
			return rpcResponse{}, fmt.Errorf("%w: SSE stream larger than %d bytes", ErrUpstreamProtocol, limit)
		}
		switch {
		case line == "":
			msg, ok, err := flush()
			if err != nil {
				return rpcResponse{}, err
			}
			if ok {
				return msg, nil
			}
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return rpcResponse{}, fmt.Errorf("%w: SSE read: %w", ErrUpstreamProtocol, err)
	}
	msg, ok, err := flush()
	if err != nil {
		return rpcResponse{}, err
	}
	if ok {
		return msg, nil
	}
	return rpcResponse{}, fmt.Errorf("%w: SSE stream ended without a response for id %d", ErrUpstreamProtocol, want)
}
