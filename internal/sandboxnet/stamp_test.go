package sandboxnet

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The run headers, spelled here as the hosted path spells them
// (sandboxvocab.RelayRunHeader, sandboxcred.TokenHeader); this package may
// not import either, and the stamp func is the caller's.
const (
	tRunHeader   = "X-Observer-Sandbox-Run"
	tTokenHeader = "X-Observer-Sandbox-Cred"
)

// stampRig is a box loopback port forwarded (ServeForward) onto a StampHop
// for run "run-A", in front of a fake proxy that records what it saw.
type stampRig struct {
	boxAddr string
	mu      sync.Mutex
	seen    []http.Header
	hosts   []string
	hop     *StampHop
}

func newStampRig(t *testing.T, handler http.HandlerFunc) *stampRig {
	t.Helper()
	rig := &stampRig{}
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.seen = append(rig.seen, r.Header.Clone())
		rig.hosts = append(rig.hosts, r.Host)
		rig.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(proxySrv.Close)
	target := proxySrv.Listener.Addr().String()
	hop, err := NewStampHop(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}, func(h http.Header) {
		h.Set(tRunHeader, "run-A")
		h.Del(tTokenHeader)
		h.Set(tTokenHeader, "host-token-A")
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hop.Close() })
	rig.hop = hop
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ServeForward(ctx, ln, func(context.Context) (net.Conn, error) { return hop.Conn() })
	}()
	t.Cleanup(func() { cancel(); <-done })
	rig.boxAddr = ln.Addr().String()
	return rig
}

// TestStampHopReplacesBoxSentRunHeaders: whatever run and token the box
// sends, the proxy sees the host side's own, and the box's Host is kept
// (the proxy's loopback Host guard).
func TestStampHopReplacesBoxSentRunHeaders(t *testing.T) {
	rig := newStampRig(t, nil)
	cases := map[string]func(*http.Request){
		"no run headers":          func(*http.Request) {},
		"another run named":       func(r *http.Request) { r.Header.Set(tRunHeader, "run-B") },
		"another run and a token": func(r *http.Request) { r.Header.Set(tRunHeader, "run-B"); r.Header.Set(tTokenHeader, "forged") },
		"two run values":          func(r *http.Request) { r.Header.Add(tRunHeader, "run-B"); r.Header.Add(tRunHeader, "run-C") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://"+rig.boxAddr+"/v1/messages", strings.NewReader(`{}`))
			edit(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			rig.mu.Lock()
			got, host := rig.seen[len(rig.seen)-1], rig.hosts[len(rig.hosts)-1]
			rig.mu.Unlock()
			if v := got.Values(tRunHeader); len(v) != 1 || v[0] != "run-A" {
				t.Fatalf("proxy saw run %v, want only run-A", v)
			}
			if v := got.Values(tTokenHeader); len(v) != 1 || v[0] != "host-token-A" {
				t.Fatalf("proxy saw token %v", v)
			}
			if host != rig.boxAddr {
				t.Fatalf("Host %q, want the box's %q", host, rig.boxAddr)
			}
		})
	}
}

// TestStampHopKeepsAliveAndStreams: several requests on one box connection
// are each stamped, and a streamed answer reaches the box chunk by chunk.
func TestStampHopKeepsAliveAndStreams(t *testing.T) {
	rig := newStampRig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		f := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			f.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	})
	c, err := net.Dial("tcp", rig.boxAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://"+rig.boxAddr+"/x", nil)
		req.Header.Set(tRunHeader, fmt.Sprintf("run-%d", i))
		if err := req.Write(c); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+rig.boxAddr+"/stream", nil)
	if err := req.Write(c); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(b), "data: 2") {
		t.Fatalf("stream body %q", b)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	if len(rig.seen) != 4 {
		t.Fatalf("proxy saw %d requests", len(rig.seen))
	}
	for _, h := range rig.seen {
		if h.Get(tRunHeader) != "run-A" {
			t.Fatalf("a keep-alive request was not stamped: %v", h)
		}
	}
}

// TestStampHopConcurrentBoxConnections runs many box connections at once
// (run with -race).
func TestStampHopConcurrentBoxConnections(t *testing.T) {
	rig := newStampRig(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{DisableKeepAlives: true}
			req, _ := http.NewRequest(http.MethodPost, "http://"+rig.boxAddr+"/v1/messages", strings.NewReader(`{}`))
			req.Header.Set(tRunHeader, "run-B")
			resp, err := (&http.Client{Transport: tr}).Do(req)
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rig.mu.Lock()
	defer rig.mu.Unlock()
	for _, h := range rig.seen {
		if h.Get(tRunHeader) != "run-A" {
			t.Fatal("a concurrent request was not stamped")
		}
	}
}

// TestStampHopClosed: a closed hop hands out no connection, and the
// constructor refuses a missing func.
func TestStampHopClosed(t *testing.T) {
	hop, err := NewStampHop(func(context.Context) (net.Conn, error) { return nil, net.ErrClosed }, func(http.Header) {})
	if err != nil {
		t.Fatal(err)
	}
	_ = hop.Close()
	if c, err := hop.Conn(); err == nil {
		_ = c.Close()
		t.Fatal("a closed hop handed out a connection")
	}
	if _, err := NewStampHop(nil, func(http.Header) {}); err == nil {
		t.Fatal("nil dial accepted")
	}
	if _, err := NewStampHop(func(context.Context) (net.Conn, error) { return nil, nil }, nil); err == nil {
		t.Fatal("nil stamp accepted")
	}
}
