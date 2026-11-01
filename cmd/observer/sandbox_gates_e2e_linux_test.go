//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_gates_e2e_linux_test.go is lane GATES-SBX's end-to-end file: the
// pieces wired together through their real seams, on fakes for the engine,
// the keystore and the provider.

// TestE2EOCIRunSurvivesAKilledHelper: a run whose helper was killed
// (SIGKILL or the OOM killer, with the daemon still running) is found by a
// fresh reaper's sweep, kept and offered, re-adopted by a new helper (empty
// scrollback marker, the relay served again in the run's own socket dir),
// and a hook's connection reaches the new relay socket; when the agent
// exits the box and every record go. A daemon exit or restart is NOT this
// case: the daemon's hangup reaches the helper through the PTY and the
// helper removes its container (audit F2; the follow-up is the container
// helper's hangup handling).
func TestE2EOCIRunSurvivesAKilledHelper(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run00000000000000e2")
	raEnder(t)
	// The daemon's reaper (a fresh one) sweeps after the helper was killed.
	fresh := &ociReaper{}
	fresh.sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatal("the sweep reaped a re-adoptable run")
	}
	if got := readoptLiveCount(); got != 1 {
		t.Fatalf("the live-run gate does not count the offered run: %d", got)
	}
	inR, inW := io.Pipe()
	var out raBuf
	done := make(chan int, 1)
	go func() {
		code, err := readoptRunHelper(context.Background(), ra.obs, ra.runID, ociTerm{in: inR, out: &out, size: func() (uint16, uint16) { return 30, 100 }})
		if err != nil {
			t.Errorf("re-adopt: %v", err)
		}
		done <- code
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "agent$") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// A hook in the box dials the relay socket in the run's socket dir (the
	// box sees that directory through its bind): the new helper answers.
	c, err := net.DialTimeout("unix", filepath.Join(ra.sockDir, sandboxrelayd.RelaySocketName), 2*time.Second)
	if err != nil {
		t.Fatalf("the re-adopted run's relay socket: %v", err)
	}
	_ = c.Close()
	_, _ = io.WriteString(inW, "hello\n")
	for !strings.Contains(out.String(), "echo:hello") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	_, _ = io.WriteString(inW, "exit\n")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the re-adopted run did not end")
	}
	if !strings.HasPrefix(out.String(), sandboxadopt.RingMarker) || !strings.Contains(out.String(), "echo:hello") {
		t.Fatalf("terminal: %q", out.String())
	}
	if len(f.removed) != 1 {
		t.Fatalf("removed %v", f.removed)
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the relay record outlived the run")
	}
}

// TestE2EHostedInjectionReachesTheUpstream: a hosted run with home_relay
// custody: the helper's setup puts only a sentinel in the box, the box's
// model request (carrying the sentinel and a forged relay token) goes
// through the home side's stamping reverse proxy into the real proxy, and
// the fake provider receives the user's real key; the box's answer never
// carries it, and a request sent around the relay gets nothing.
func TestE2EHostedInjectionReachesTheUpstream(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	run := "run-e2e-cred"
	credRelayRecord(t, obs, run)
	plan := credPlan(obs, run)
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	defer credTeardown(plan)
	env := map[string]string{}
	credEnv(plan, env)
	sentinel := env["ANTHROPIC_API_KEY"]
	for k, v := range env {
		if strings.Contains(v, credTestKey) {
			t.Fatalf("the box env %s holds the key", k)
		}
	}

	var seenKey string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"m1","model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	defer up.Close()
	upURL, _ := url.Parse(up.URL)
	oldHost := credProviderHost
	credProviderHost = func(sandboxcred.Provider) string { return upURL.Hostname() }
	defer func() { credProviderHost = oldHost }()

	p, err := proxy.New(proxy.Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: &e2eSink{}})
	if err != nil {
		t.Fatal(err)
	}
	proxy.SetCredentialInjector(&credInjector{observerDir: obs})
	defer proxy.SetCredentialInjector(nil)
	sockDir, err := os.MkdirTemp("", "e2ep")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	sock := filepath.Join(sockDir, "proxy.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: p.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	send := func(conn io.ReadWriter, token string) string {
		req, _ := http.NewRequest(http.MethodPost, "http://observer-proxy/v1/messages", strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Api-Key", sentinel)
		if token != "" {
			req.Header.Set(sandboxcred.TokenHeader, token)
		}
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}
	// Through the run's relay: the home side stamps the run and its token.
	box, err := dialHostedProxyStamped(sock, run)
	if err != nil {
		t.Fatal(err)
	}
	body := send(box.(io.ReadWriter), "box-forged-token")
	_ = box.Close()
	if seenKey != credTestKey {
		t.Fatalf("the provider saw %q, want the user's key", seenKey)
	}
	if strings.Contains(body, credTestKey) {
		t.Fatal("the key was echoed to the box")
	}
	// Around the relay (straight to the proxy, as a box-side process that
	// reached the port could): no run identity, so no key.
	seenKey = ""
	direct, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = send(direct, "box-forged-token")
	_ = direct.Close()
	if seenKey == credTestKey {
		t.Fatal("a request around the relay got the key")
	}
}

// e2eSink is a no-op api_turns sink.
type e2eSink struct{}

func (e2eSink) InsertAPITurn(context.Context, models.APITurn) (int64, error) { return 1, nil }
