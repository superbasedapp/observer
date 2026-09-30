package mcpegress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/netpolicy"
)

func TestValidateUpstreamBaseURL(t *testing.T) {
	sh := func(unlock bool) Options {
		return Options{Transport: TransportStreamableHTTP, AllowPrivateNetwork: unlock}
	}
	cases := []struct {
		name string
		url  string
		opts Options
		ok   bool
	}{
		{"public https", "https://mcp.example.com/mcp", sh(false), true},
		{"public https with port", "https://mcp.example.com:8443/mcp", sh(false), true},
		{"empty", "", sh(false), false},
		{"no host", "https:///mcp", sh(false), false},
		{"credentials embedded", "https://user:pw@mcp.example.com/mcp", sh(false), false},
		{"ftp", "ftp://mcp.example.com/", sh(false), false},
		{"plain http public", "http://mcp.example.com/mcp", sh(false), false},
		{"plain http public unlocked", "http://mcp.internal.example/mcp", sh(true), true},
		{"metadata literal", "https://169.254.169.254/latest", sh(false), false},
		{"metadata literal unlocked still refused", "http://169.254.169.254/latest", sh(true), false},
		{"ipv6 link-local", "https://[fe80::1]/mcp", sh(true), false},
		{"ipv4-mapped metadata", "https://[::ffff:169.254.169.254]/mcp", sh(true), false},
		{"ipv4-mapped private refused", "https://[::ffff:10.0.0.1]/mcp", sh(false), false},
		{"ipv4-mapped private unlocked", "https://[::ffff:10.0.0.1]/mcp", sh(true), true},
		{"nat64 metadata", "https://[64:ff9b::a9fe:a9fe]/mcp", sh(true), false},
		{"private literal refused", "https://10.1.2.3/mcp", sh(false), false},
		{"private literal unlocked", "https://10.1.2.3/mcp", sh(true), true},
		{"cgnat refused", "https://100.64.0.9/mcp", sh(false), false},
		{"loopback literal refused by default", "http://127.0.0.1:8080/mcp", sh(false), false},
		{"loopback literal unlocked", "http://127.0.0.1:8080/mcp", sh(true), true},
		{"localhost refused by default", "http://localhost:8080/mcp", sh(false), false},
		{"localhost unlocked", "http://localhost:8080/mcp", sh(true), true},
		{"ipv6 loopback unlocked", "http://[::1]:8080/mcp", sh(true), true},
		{"unspecified", "https://0.0.0.0/mcp", sh(true), false},
		{"multicast", "https://224.0.0.1/mcp", sh(true), false},
		{"sse_legacy dials too", "http://mcp.example.com/sse", Options{Transport: TransportSSELegacy}, false},
		{"openapi dials too", "https://api.example.com/openapi.json", Options{Transport: TransportOpenAPI}, true},
		{"stdio skips", "", Options{Transport: TransportNodeLocalStdio}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUpstreamBaseURL(tc.url, tc.opts)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateUpstreamBaseURL(%q, %+v) = %v, want ok=%t", tc.url, tc.opts, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrUpstreamBaseURL) {
				t.Fatalf("refusal does not wrap ErrUpstreamBaseURL: %v", err)
			}
		})
	}
}

func TestDialPolicyFor(t *testing.T) {
	if p := DialPolicyFor(Options{}); p != (netpolicy.DialPolicy{}) {
		t.Fatalf("default policy = %+v, want strict", p)
	}
	if p := DialPolicyFor(Options{AllowPrivateNetwork: true}); !p.AllowLoopback || !p.AllowPrivate {
		t.Fatalf("unlocked policy = %+v", p)
	}
}

// fakeMCP is a minimal streamable-HTTP MCP upstream: initialize ->
// notifications/initialized -> paginated tools/list, answering as JSON or as
// an SSE stream, and issuing a session id.
type fakeMCP struct {
	sse      bool
	pages    [][]map[string]any
	seen     []string
	sessions []string
	deleted  int
}

func (f *fakeMCP) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			f.deleted++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.sessions = append(f.sessions, r.Header.Get("Mcp-Session-Id"))
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		f.seen = append(f.seen, req.Method)
		var result any
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fake", "version": "0.1"}}
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
			return
		case "tools/list":
			page := 0
			if req.Params.Cursor != "" {
				fmt.Sscanf(req.Params.Cursor, "p%d", &page)
			}
			res := map[string]any{"tools": f.pages[page]}
			if page+1 < len(f.pages) {
				res["nextCursor"] = fmt.Sprintf("p%d", page+1)
			}
			result = res
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if f.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			// A notification first, then the response, to prove id matching.
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{}}\n\n")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(msg)
	}
}

func loopbackClient() *http.Client {
	return NewClient(netpolicy.DialPolicy{AllowLoopback: true}, ClientConfig{Timeout: 5 * time.Second})
}

func TestListToolsStreamableHTTP(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			f := &fakeMCP{sse: sse, pages: [][]map[string]any{
				{{"name": "a", "inputSchema": map[string]any{"type": "object"}}},
				{{"name": "b", "description": "B", "annotations": map[string]any{"destructiveHint": false}}},
			}}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			d, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: srv.URL, Transport: TransportStreamableHTTP})
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(d.Tools) != 2 || d.Tools[0].Name != "a" || d.Tools[1].Name != "b" || d.Pages != 2 {
				t.Fatalf("discovery = %+v", d)
			}
			if d.ServerName != "fake" || d.ProtocolVersion != "2025-06-18" {
				t.Fatalf("server info = %+v", d)
			}
			if strings.Join(f.seen, ",") != "initialize,notifications/initialized,tools/list,tools/list" {
				t.Fatalf("sequence = %v", f.seen)
			}
			// The session id was carried on every request after initialize
			// and the session was closed.
			if f.sessions[0] != "" || f.sessions[1] != "sess-1" || f.sessions[3] != "sess-1" || f.deleted != 1 {
				t.Fatalf("sessions = %v deleted=%d", f.sessions, f.deleted)
			}
		})
	}
}

func TestListToolsErrors(t *testing.T) {
	t.Run("unsupported transport", func(t *testing.T) {
		_, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: "https://x", Transport: TransportSSELegacy})
		if !errors.Is(err, ErrDiscoveryUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("rpc error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}`))
		}))
		defer srv.Close()
		_, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: srv.URL, Transport: TransportStreamableHTTP})
		if !errors.Is(err, ErrUpstreamRPC) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("http status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
		defer srv.Close()
		_, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: srv.URL, Transport: TransportStreamableHTTP})
		if !errors.Is(err, ErrUpstreamStatus) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("id mismatch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":99,"result":{}}`))
		}))
		defer srv.Close()
		_, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: srv.URL, Transport: TransportStreamableHTTP})
		if !errors.Is(err, ErrUpstreamProtocol) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversize body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"pad":"` + strings.Repeat("x", 5000) + `"}}`))
		}))
		defer srv.Close()
		_, err := ListTools(context.Background(), loopbackClient(), DiscoverRequest{URL: srv.URL, Transport: TransportStreamableHTTP, MaxResponseBytes: 1024})
		if !errors.Is(err, ErrUpstreamProtocol) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestDialTimeBoundary proves the Control hook is the boundary: the SAME
// loopback upstream is reachable under an unlocked policy and refused under
// the strict one, and the refusal wraps netpolicy.ErrDialRefused.
func TestDialTimeBoundary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	strict := NewClient(netpolicy.DialPolicy{}, ClientConfig{Timeout: 5 * time.Second})
	_, err := strict.Get(srv.URL)
	if err == nil || !errors.Is(err, netpolicy.ErrDialRefused) {
		t.Fatalf("strict client reached loopback: %v", err)
	}
	if resp, err := loopbackClient().Get(srv.URL); err != nil || resp.StatusCode != 200 {
		t.Fatalf("unlocked client: %v", err)
	}
}

func TestNoRedirectAndPool(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	resp, err := loopbackClient().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: status %d", resp.StatusCode)
	}
	pool := NewPool(ClientConfig{})
	a := pool.Client(netpolicy.DialPolicy{})
	b := pool.Client(netpolicy.DialPolicy{})
	c := pool.Client(netpolicy.DialPolicy{AllowLoopback: true})
	if a != b || a == c {
		t.Fatal("pool must share a client per policy and split across policies")
	}
	if pool.Config().Timeout != defaultTimeout || pool.Config().MaxResponseBytes != defaultMaxResponseBytes {
		t.Fatalf("defaults not applied: %+v", pool.Config())
	}
}
