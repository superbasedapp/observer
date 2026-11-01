//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals && !sbo_omit_capture_proxy

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSandboxA1ProxiedTurnLandsAPITurnsRow is the api_turns half of
// acceptance A1 (sandbox plan v2 section 13.12) against a recorded-shape
// fixture: a model call made from "inside" a sandbox reaches the proxy only
// through the two forwarders the helpers run (the guest's in-namespace
// loopback port to the per-run unix socket, and the host helper's socket to
// the proxy port), and the turn lands an api_turns row in the real store
// with the fixture's token counts. The upstream is a fake replaying
// testdata/sandbox/anthropic-messages-response.json; the same proof with a
// real provider turn and a running daemon is owed.
func TestSandboxA1ProxiedTurnLandsAPITurnsRow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sandbox", "anthropic-messages-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	st := store.New(conn)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer upstream.Close()
	p, err := proxy.New(proxy.Options{AnthropicUpstream: upstream.URL, OpenAIUpstream: upstream.URL, Sink: st})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(p.Handler())
	defer proxySrv.Close()
	proxyAddr := proxySrv.Listener.Addr().String()

	// Host helper half: the per-run unix socket forwards to the proxy port.
	sockDir, err := os.MkdirTemp("", "sbxa1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sock := filepath.Join(sockDir, "proxy.sock")
	hostLn, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = sandboxnet.ServeForward(ctx, hostLn, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", proxyAddr)
		})
	}()
	// Guest helper half: the in-namespace loopback port forwards to the
	// socket (here an ephemeral loopback port stands in for the namespace's
	// own proxy port).
	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = sandboxnet.ServeForward(ctx, guestLn, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		})
	}()

	body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+guestLn.Addr().String()+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the turn from inside the sandbox did not reach the proxy: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status %d", resp.StatusCode)
	}

	var n, in, out int64
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MAX(input_tokens),0), COALESCE(MAX(output_tokens),0) FROM api_turns`).Scan(&n, &in, &out); err != nil {
			t.Fatal(err)
		}
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 1 || out != 56 || in <= 0 {
		t.Fatalf("api_turns: %d row(s), input %s, output %d; want one row with the fixture's usage", n, strconv.FormatInt(in, 10), out)
	}
}
