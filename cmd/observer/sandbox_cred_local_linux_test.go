//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_cred_local_linux_test.go is lane N3's proof of credential
// injection for LOCAL runs (SBX-NET-2): the host helper's lane (setup,
// box env, stamp, end) and acceptance A1 for local runs end to end, on a
// fake provider and an in-memory keystore. No real key is used anywhere.

// credLocalRig is a local run's host side as startHostServices builds it:
// the relay record, the run's socket dir with the model-proxy forward
// served on proxy.sock towards proxyAddr.
type credLocalRig struct {
	obs, run string
	h        sandbox.HostArgs
	stop     func()
}

func newCredLocalRig(t *testing.T, obs, run, proxyAddr string) *credLocalRig {
	t.Helper()
	credRelayRecord(t, obs, run)
	sockDir, err := os.MkdirTemp("", "n3l")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	h := sandbox.HostArgs{SockDir: sockDir, ProxyAddr: proxyAddr, RelayRun: run, ObserverDir: obs}
	ln, err := net.Listen("unix", filepath.Join(sockDir, sandbox.ProxySocketName))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := serveModelProxyForward(ctx, ln, h)
	rig := &credLocalRig{obs: obs, run: run, h: h, stop: func() { stop(); cancel() }}
	t.Cleanup(rig.stop)
	t.Cleanup(func() { credLocalLanes.Range(func(k, _ any) bool { credLocalLanes.Delete(k); return true }) })
	return rig
}

// credLocalHelperLive stubs the liveness lock read.
func credLocalHelperLive(t *testing.T, live *bool) {
	t.Helper()
	old := credHelperLive
	credHelperLive = func(string, string) bool { return *live }
	t.Cleanup(func() { credHelperLive = old })
}

// TestCredLocalCustodySpelling pins sandboxcred's stdlib copy of the local
// custody to the vocabulary's.
func TestCredLocalCustodySpelling(t *testing.T) {
	if sandboxcred.CustodyLocal != string(vocab.CustodyHostBound) {
		t.Fatalf("sandboxcred.CustodyLocal %q != %q", sandboxcred.CustodyLocal, vocab.CustodyHostBound)
	}
}

// TestCredLocalLane: the lane's setup puts only the sentinel in the box
// env (replacing a real key the launching env carried), the stamp names
// the run with the token the record hashes, the injector adds the key
// only for that run while its helper lives, and the lane's end removes
// the record.
func TestCredLocalLane(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	rig := newCredLocalRig(t, obs, "run-n3-lane", "127.0.0.1:1")
	env := credLocalBoxEnv(rig.h, []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=" + credTestKey})
	var sentinel string
	for _, kv := range env {
		if strings.Contains(kv, credTestKey) {
			t.Fatalf("the box env holds the real key: %q", kv)
		}
		if v, ok := strings.CutPrefix(kv, "ANTHROPIC_API_KEY="); ok {
			sentinel = v
		}
	}
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("box key variable %q, want a sentinel", sentinel)
	}
	if again := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey}); len(again) != 1 || again[0] != "ANTHROPIC_API_KEY="+sentinel {
		t.Fatalf("a second env build minted again: %v", again)
	}
	if none := credLocalBoxEnv(rig.h, []string{"PATH=/usr/bin"}); len(none) != 1 || none[0] != "PATH=/usr/bin" {
		t.Fatalf("an env build with no key variable added one: %v", none)
	}
	rec, err := credReadRecord(obs, rig.run)
	if err != nil || rec.Lane != sandboxcred.LaneLocal || rec.Custody != vocab.CustodyHostBound || rec.Provider != "anthropic" {
		t.Fatalf("record %+v, %v", rec, err)
	}
	if b, _ := os.ReadFile(credRunPath(obs, rig.run)); bytes.Contains(b, []byte(sentinel)) || bytes.Contains(b, []byte(credTestKey)) {
		t.Fatal("the record holds the sentinel or the key in clear")
	}
	h := http.Header{}
	h.Set(vocab.RelayRunHeader, "run-other")
	h.Set(sandboxcred.TokenHeader, "box-forged")
	credLocalStamp(rig.run)(h)
	token := h.Get(sandboxcred.TokenHeader)
	if h.Get(vocab.RelayRunHeader) != rig.run || token == "box-forged" || sandboxcred.Hash(token) != rec.TokenHash {
		t.Fatalf("stamp: run %q token-hash-ok %v", h.Get(vocab.RelayRunHeader), sandboxcred.Hash(token) == rec.TokenHash)
	}
	inj := &credInjector{observerDir: obs}
	good := proxy.CredentialRequest{RunID: rig.run, Token: token, Host: "api.anthropic.com", XAPIKey: sentinel}
	if hdr, val, ok := inj.Inject(context.Background(), good); !ok || hdr != "X-Api-Key" || val != credTestKey {
		t.Fatalf("inject = %q %v", hdr, ok)
	}
	refusals := map[string]proxy.CredentialRequest{
		"another run named":   {RunID: "run-other", Token: token, Host: "api.anthropic.com", XAPIKey: sentinel},
		"box-forged token":    {RunID: rig.run, Token: "box-forged", Host: "api.anthropic.com", XAPIKey: sentinel},
		"another host":        {RunID: rig.run, Token: token, Host: "evil.example.com", XAPIKey: sentinel},
		"no run header":       {Token: token, Host: "api.anthropic.com", XAPIKey: sentinel},
		"the real key itself": {RunID: rig.run, Token: token, Host: "api.anthropic.com", XAPIKey: credTestKey},
	}
	for name, r := range refusals {
		if _, _, ok := inj.Inject(context.Background(), r); ok {
			t.Fatalf("%s: injected", name)
		}
	}
	live = false
	if _, _, ok := inj.Inject(context.Background(), good); ok {
		t.Fatal("injected after the run's helper was gone")
	}
	live = true
	rig.stop()
	if _, err := credReadRecord(obs, rig.run); err == nil {
		t.Fatal("the record outlived the lane")
	}
	if credLocalStamp(rig.run) != nil {
		t.Fatal("a stamp outlived the lane")
	}
	if _, _, ok := inj.Inject(context.Background(), good); ok {
		t.Fatal("injected after the lane ended")
	}
}

// TestCredLocalNilPaths: with the component off, no stored key, no proxy
// forward or no relay run, no lane is set up: the env is unchanged (a real
// key the user passed stays as today), nothing is stamped or recorded.
func TestCredLocalNilPaths(t *testing.T) {
	in := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=user-own"}
	cases := map[string]func(t *testing.T) sandbox.HostArgs{
		"component off": func(t *testing.T) sandbox.HostArgs {
			obs, ks := credEnvForTest(t, false)
			_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
			return newCredLocalRig(t, obs, "run-n3-off", "127.0.0.1:1").h
		},
		"no stored key": func(t *testing.T) sandbox.HostArgs {
			obs, _ := credEnvForTest(t, true)
			return newCredLocalRig(t, obs, "run-n3-nokey", "127.0.0.1:1").h
		},
		"another provider's key only": func(t *testing.T) sandbox.HostArgs {
			obs, ks := credEnvForTest(t, true)
			_ = ks.Set(sandboxcred.KeyName("openai"), "sk-SENTINEL-0000")
			return newCredLocalRig(t, obs, "run-n3-other", "127.0.0.1:1").h
		},
		"no proxy forward": func(t *testing.T) sandbox.HostArgs {
			obs, ks := credEnvForTest(t, true)
			_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
			h := newCredLocalRig(t, obs, "run-n3-noproxy", "127.0.0.1:1").h
			h.ProxyAddr = ""
			return h
		},
		"no relay run": func(t *testing.T) sandbox.HostArgs {
			obs, ks := credEnvForTest(t, true)
			_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
			h := newCredLocalRig(t, obs, "run-n3-norelay", "127.0.0.1:1").h
			h.RelayRun = ""
			return h
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			h := mk(t)
			if got := credLocalBoxEnv(h, in); strings.Join(got, "\n") != strings.Join(in, "\n") {
				t.Fatalf("env changed: %v", got)
			}
			if credLocalStamp(h.RelayRun) != nil {
				t.Fatal("a stamp exists")
			}
			if _, err := os.Lstat(credRunPath(h.ObserverDir, h.RelayRun)); err == nil {
				t.Fatal("a record was written")
			}
		})
	}
}

// TestCredLocalRouteGate: a lane is set up only when the run's model
// traffic is known to go through the proxy forward (audit N3-A2), and
// only in place of a key variable the launching env already carries
// (audit N3-A9). One case per row; every other row leaves env unchanged
// and writes no record.
func TestCredLocalRouteGate(t *testing.T) {
	withKey := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=" + credTestKey}
	cases := []struct {
		name          string
		gateway       bool
		providerBlock bool
		env           []string
		wantLane      bool
	}{
		{"proxy_only tier (no gateway)", false, false, withKey, true},
		{"internet tier with the provider-host block", true, true, withKey, true},
		{"internet tier without the block (tool may go direct)", true, false, withKey, false},
		{"no key variable in env (subscription login)", false, false, []string{"PATH=/usr/bin"}, false},
		{"an empty key variable", false, false, []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY="}, false},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs, ks := credEnvForTest(t, true)
			if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
				t.Fatal(err)
			}
			h := newCredLocalRig(t, obs, fmt.Sprintf("run-n3-gate-%d", i), "127.0.0.1:1").h
			h.Gateway, h.ProviderBlock = c.gateway, c.providerBlock
			got := credLocalBoxEnv(h, c.env)
			_, recErr := os.Lstat(credRunPath(obs, h.RelayRun))
			if !c.wantLane {
				if strings.Join(got, "\n") != strings.Join(c.env, "\n") {
					t.Fatalf("env changed: %v", got)
				}
				if credLocalStamp(h.RelayRun) != nil || recErr == nil {
					t.Fatal("a lane was set up")
				}
				return
			}
			var v string
			for _, kv := range got {
				if s, ok := strings.CutPrefix(kv, "ANTHROPIC_API_KEY="); ok {
					v = s
				}
			}
			if !sandboxcred.IsSentinel(v) || credLocalStamp(h.RelayRun) == nil || recErr != nil {
				t.Fatalf("no lane: key var sentinel %v, record %v", sandboxcred.IsSentinel(v), recErr)
			}
		})
	}
}

// TestE2ELocalInjectionReachesTheUpstream is acceptance A1 for local runs
// (sandbox plan v2 section 13.12) on a fake provider: the box holds only
// the sentinel; its model turn, sent through the guest's loopback port,
// the run's proxy.sock and the host helper's stamping forward with a
// forged run header and token, reaches the real proxy, which sends the
// user's real key upstream and lands an api_turns row; the key is in no
// log, response or api_turns row; a request that reaches the proxy around
// the forward gets nothing; and a direct request from the box to the
// provider host or a literal IP is refused by the gateway's provider-host
// block.
func TestE2ELocalInjectionReachesTheUpstream(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var (
		mu         sync.Mutex
		seenKeys   []string
		seenTokens []string
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenKeys = append(seenKeys, r.Header.Get("X-Api-Key"))
		for _, name := range []string{sandboxcred.TokenHeader, vocab.RelayRunHeader} {
			if v := r.Header.Get(name); v != "" {
				seenTokens = append(seenTokens, name)
			}
		}
		mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_n3","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":7,"output_tokens":3}}`)
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	oldHost := credProviderHost
	credProviderHost = func(sandboxcred.Provider) string { return upURL.Hostname() }
	defer func() { credProviderHost = oldHost }()

	conn, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var logs credLogBuf
	p, err := proxy.New(proxy.Options{
		AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: store.New(conn),
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy.SetCredentialInjector(&credInjector{observerDir: obs})
	defer proxy.SetCredentialInjector(nil)
	proxySrv := httptest.NewServer(p.Handler())
	defer proxySrv.Close()

	// The host helper: the run's forward on proxy.sock, then the lane set
	// up where the box env is built.
	rig := newCredLocalRig(t, obs, "run-n3-e2e", proxySrv.Listener.Addr().String())
	env := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey})
	sentinel := strings.TrimPrefix(env[0], "ANTHROPIC_API_KEY=")
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("box env %v", env)
	}
	// The guest's in-namespace loopback port onto the run's socket.
	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = sandboxnet.ServeForward(ctx, guestLn, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", filepath.Join(rig.h.SockDir, sandbox.ProxySocketName))
		})
	}()

	send := func(base string) (int, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/messages", strings.NewReader(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("X-Api-Key", sentinel)
		req.Header.Set(vocab.RelayRunHeader, "run-someone-else")
		req.Header.Set(sandboxcred.TokenHeader, "box-forged-token")
		resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var hdrs strings.Builder
		_ = resp.Header.Write(&hdrs)
		return resp.StatusCode, string(b) + hdrs.String()
	}

	status, answer := send("http://" + guestLn.Addr().String())
	if status != http.StatusOK {
		t.Fatalf("the turn through the forward: status %d %s", status, answer)
	}
	mu.Lock()
	gotKey := seenKeys[len(seenKeys)-1]
	mu.Unlock()
	if gotKey != credTestKey {
		t.Fatalf("the provider saw %q, want the user's key", gotKey)
	}
	if strings.Contains(answer, credTestKey) {
		t.Fatal("the key was echoed to the box")
	}

	// The api_turns row lands, on the run's namespaced session (the box
	// cannot bind its turn to another session; design F-N3-1), and holds
	// no key.
	var n int
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 1 {
		t.Fatalf("api_turns rows: %d, want 1", n)
	}
	dump := credDumpTable(ctx, t, conn, "api_turns")
	if strings.Contains(dump, credTestKey) || strings.Contains(dump, sentinel) {
		t.Fatal("an api_turns row holds the key or the sentinel")
	}
	var sid string
	_ = conn.QueryRowContext(ctx, `SELECT COALESCE(session_id,'') FROM api_turns`).Scan(&sid)
	if !strings.HasPrefix(sid, "rsbx-"+rig.run) {
		t.Fatalf("api_turns.session_id %q, want the run's namespace", sid)
	}

	// Around the forward (straight to the proxy port): no host-side run
	// identity, so the sentinel goes upstream untouched.
	if status, _ := send(proxySrv.URL); status != http.StatusOK {
		t.Fatalf("around the forward: status %d", status)
	}
	mu.Lock()
	gotKey = seenKeys[len(seenKeys)-1]
	mu.Unlock()
	if gotKey == credTestKey || gotKey != sentinel {
		t.Fatalf("a request around the forward reached the provider with %q", gotKey)
	}
	if strings.Contains(logs.String(), credTestKey) {
		t.Fatal("the key is in the proxy log")
	}
	// The relay token (and the run header) never leave the proxy towards
	// the provider (audit N3-A5).
	mu.Lock()
	leaked := append([]string(nil), seenTokens...)
	mu.Unlock()
	if len(leaked) > 0 {
		t.Fatalf("the provider received %v", leaked)
	}

	// The box's direct routes to the provider: the gateway refuses the
	// provider's host and a literal IP (the provider-host block).
	gw := &sandboxnet.Gateway{Providers: sandboxnet.NewProviderBlock(nil), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()
	for _, target := range []string{"api.anthropic.com:443", "160.79.104.10:443"} {
		c, err := net.Dial("tcp", gwSrv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Api-Key: %s\r\n\r\n", target, target, sentinel)
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		_ = c.Close()
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a direct CONNECT to %s: status %d, want 403", target, resp.StatusCode)
		}
	}
}

// credDumpTable renders every column of every row of table as text.
func credDumpTable(ctx context.Context, t *testing.T, conn *sql.DB, table string) string {
	t.Helper()
	rows, err := conn.QueryContext(ctx, `SELECT * FROM `+table) //nolint:gosec // G202: a fixed test table name
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	var b strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if bs, ok := v.([]byte); ok {
				v = string(bs)
			}
			fmt.Fprintf(&b, "%v\t", v)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// credLogBuf is a log buffer safe for the proxy's goroutines.
type credLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *credLogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *credLogBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
