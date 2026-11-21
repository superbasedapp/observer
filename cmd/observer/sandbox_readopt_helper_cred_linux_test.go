//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_readopt_helper_cred_linux_test.go proves that a re-adopted local
// oci run keeps credential injection (tracker row F-004, finding F-N3-2):
// its new helper re-opens the run's lane from the injection record and
// serves the stamping forward, and with the key no longer stored the lane
// stays closed (the sentinel is refused, fail closed) and the reason is
// noted for the terminal.

// readoptCredProxy is a fake proxy that records the run and token headers
// each request carried.
type readoptCredProxy struct {
	mu   sync.Mutex
	seen []http.Header
	srv  *httptest.Server
}

func newReadoptCredProxy(t *testing.T) *readoptCredProxy {
	t.Helper()
	p := &readoptCredProxy{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.Header.Clone())
		p.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *readoptCredProxy) last(t *testing.T) http.Header {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		t.Fatal("the proxy saw no request")
	}
	return p.seen[len(p.seen)-1]
}

// readoptCredSend sends one request with box-forged run headers through the
// run's model-proxy socket.
func readoptCredSend(t *testing.T, sockDir string) {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", filepath.Join(sockDir, sandbox.ProxySocketName))
	}}
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:8820/v1/messages", strings.NewReader(`{}`))
	req.Header.Set(vocab.RelayRunHeader, "run-forged")
	req.Header.Set(sandboxcred.TokenHeader, "box-forged")
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// readoptCredRun launches a local run's first helper (its lane open and its
// sentinel in the box env), then lets that helper die without ending its
// lane (a SIGKILL: the record stays), and returns the re-adoption's host
// args (the same socket dir, as readoptHostArgs gives) and the sentinel.
func readoptCredRun(t *testing.T, obs, run, proxyAddr string) (sandbox.HostArgs, string, credRunRecord) {
	t.Helper()
	rig := newCredLocalRig(t, obs, run, proxyAddr)
	env := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey})
	sentinel := strings.TrimPrefix(env[0], "ANTHROPIC_API_KEY=")
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("no lane at launch: %v", env)
	}
	first, err := credReadRecord(obs, run)
	if err != nil {
		t.Fatal(err)
	}
	credLocalLanes.Delete(run) // the helper's memory is gone; its record is not
	rig.stop()
	_ = os.Remove(filepath.Join(rig.h.SockDir, sandbox.ProxySocketName))
	if _, err := credReadRecord(obs, run); err != nil {
		t.Fatalf("the record did not survive the helper: %v", err)
	}
	return rig.h, sentinel, first
}

// TestReadoptKeepsLocalInjection: with the key still stored, the re-adopted
// run's forward stamps the run and a fresh token (replacing what the box
// sent), the record's sentinel hash is kept and its token hash is the new
// token's, and the daemon's injector swaps the box's sentinel again.
func TestReadoptKeepsLocalInjection(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	fp := newReadoptCredProxy(t)
	h, sentinel, first := readoptCredRun(t, obs, "run-readopt-cred", fp.srv.Listener.Addr().String())

	stop, err := readoptHostServices(h)
	defer stop()
	if err != nil {
		t.Fatal(err)
	}
	if why, ok := readoptCredNotes.Load(h.RelayRun); ok {
		t.Fatalf("lane not re-opened: %v", why)
	}
	readoptCredSend(t, h.SockDir)
	got := fp.last(t)
	token := got.Get(sandboxcred.TokenHeader)
	rec, err := credReadRecord(obs, h.RelayRun)
	if err != nil {
		t.Fatal(err)
	}
	if got.Get(vocab.RelayRunHeader) != h.RelayRun || token == "box-forged" || sandboxcred.Hash(token) != rec.TokenHash {
		t.Fatalf("the re-adopted forward did not stamp the run: run %q", got.Get(vocab.RelayRunHeader))
	}
	if rec.SentinelHash != first.SentinelHash || rec.TokenHash == first.TokenHash || rec.Lane != sandboxcred.LaneLocal {
		t.Fatal("the record lost the sentinel hash or kept the dead helper's token")
	}
	inj := &credInjector{observerDir: obs}
	req := proxy.CredentialRequest{RunID: h.RelayRun, Token: token, Host: "api.anthropic.com", XAPIKey: sentinel}
	if hdr, val, ok := inj.Inject(context.Background(), req); !ok || hdr != "X-Api-Key" || val != credTestKey {
		t.Fatalf("no injection for the re-adopted run: %q %v", hdr, ok)
	}
	stop()
	if _, err := credReadRecord(obs, h.RelayRun); err == nil {
		t.Fatal("the record outlived the re-adopted run's lane")
	}
}

// TestReadoptWithoutTheKeyFailsClosed: with the key removed while the run's
// helper was gone, the lane stays closed: the forward is the raw pipe (no
// host-set token reaches the proxy, so the sentinel goes upstream
// unswapped and the provider refuses it), and the reason is noted.
func TestReadoptWithoutTheKeyFailsClosed(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	fp := newReadoptCredProxy(t)
	h, sentinel, _ := readoptCredRun(t, obs, "run-readopt-nokey", fp.srv.Listener.Addr().String())
	if err := ks.Delete(sandboxcred.KeyName("anthropic")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { readoptCredNotes.Delete(h.RelayRun) })

	stop, err := readoptHostServices(h)
	defer stop()
	if err != nil {
		t.Fatal(err)
	}
	why, ok := readoptCredNotes.Load(h.RelayRun)
	if !ok || !strings.Contains(why.(string), "no anthropic key is stored") {
		t.Fatalf("reason %v", why)
	}
	if credLocalStamp(h.RelayRun) != nil {
		t.Fatal("a lane was opened without the key")
	}
	readoptCredSend(t, h.SockDir)
	got := fp.last(t)
	if got.Get(sandboxcred.TokenHeader) != "box-forged" {
		t.Fatal("the raw forward changed the request")
	}
	inj := &credInjector{observerDir: obs}
	req := proxy.CredentialRequest{RunID: h.RelayRun, Token: got.Get(sandboxcred.TokenHeader), Host: "api.anthropic.com", XAPIKey: sentinel}
	if _, _, ok := inj.Inject(context.Background(), req); ok {
		t.Fatal("injected without a re-opened lane")
	}
}

// TestReadoptReopenRules: one case per row of credLocalReopenRules, plus
// the run that never had a local lane (no reason, nothing opened).
func TestReadoptReopenRules(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	h := sandbox.HostArgs{RelayRun: "run-reopen-rules", ObserverDir: obs, ProxyAddr: "127.0.0.1:1"}
	base := credRunRecord{
		V: credRecordVersion, RunID: h.RelayRun, Provider: "anthropic", Custody: vocab.CustodyHostBound, Lane: sandboxcred.LaneLocal,
		SentinelHash: sandboxcred.Hash("s"), TokenHash: sandboxcred.Hash("t"), CreatedAt: credNow(), Expires: credNow().Add(time.Hour),
	}
	active := true
	oldActive := credActive
	credActive = func(context.Context) bool { return active }
	t.Cleanup(func() { credActive = oldActive })
	for _, tc := range []struct {
		name string
		rec  func(credRunRecord) credRunRecord
		h    func(sandbox.HostArgs) sandbox.HostArgs
		pre  func()
		want string
	}{
		{"hosted record: not a local lane", func(r credRunRecord) credRunRecord { r.Lane = sandboxcred.LaneHosted; return r }, nil, nil, ""},
		{"wrong custody", func(r credRunRecord) credRunRecord { r.Custody = vocab.CustodyHomeRelay; return r }, nil, nil, "not a local run's"},
		{"expired", func(r credRunRecord) credRunRecord { r.Expires = credNow().Add(-time.Second); return r }, nil, nil, "expired"},
		{"not routed", nil, func(a sandbox.HostArgs) sandbox.HostArgs { a.Gateway = true; return a }, nil, "no longer goes through"},
		{"component off", nil, nil, func() { active = false }, "is not selected"},
		{"unreadable key list", nil, nil, func() { _ = os.Chmod(credProvidersFile(obs), 0o644) }, "cannot be read"},
		{"no key", nil, nil, func() { _ = ks.Delete(sandboxcred.KeyName("anthropic")) }, "no anthropic key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active = true
			_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
			_ = os.Chmod(credProvidersFile(obs), 0o600)
			rec := base
			if tc.rec != nil {
				rec = tc.rec(rec)
			}
			if err := credWriteRecord(obs, rec); err != nil {
				t.Fatal(err)
			}
			args := h
			if tc.h != nil {
				args = tc.h(args)
			}
			if tc.pre != nil {
				tc.pre()
			}
			got := credLocalReopen(args)
			if (tc.want == "" && got != "") || !strings.Contains(got, tc.want) {
				t.Fatalf("reopen = %q, want %q", got, tc.want)
			}
			if credLocalStamp(h.RelayRun) != nil {
				t.Fatal("a refused re-open stamped the run")
			}
		})
	}
	if len(credLocalReopenRules) != 6 {
		t.Fatalf("credLocalReopenRules has %d rows; add a case per new row and update this count", len(credLocalReopenRules))
	}
}

// TestReadoptNoRecordNotes (audit FU3-A5): a re-adopted run whose injection
// record cannot be read gets a note; one with no record gets a note only
// when it could have had a lane (component selected, a tool with one
// provider, model traffic through the forward), and none otherwise.
func TestReadoptNoRecordNotes(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	active := true
	oldActive := credActive
	credActive = func(context.Context) bool { return active }
	t.Cleanup(func() { credActive = oldActive })
	credRelayRecord(t, obs, "run-norec") // tool claude-code: provider anthropic
	h := sandbox.HostArgs{RelayRun: "run-norec", ObserverDir: obs, ProxyAddr: "127.0.0.1:1"}
	if got := credLocalReopen(h); !strings.Contains(got, "no injection record") {
		t.Fatalf("absent record, could have had a lane: %q", got)
	}
	active = false
	if got := credLocalReopen(h); got != "" {
		t.Fatalf("absent record, component off: %q", got)
	}
	active = true
	if got := credLocalReopen(sandbox.HostArgs{RelayRun: "run-norec", ObserverDir: obs}); got != "" {
		t.Fatalf("absent record, no proxy forward: %q", got)
	}
	if got := credLocalReopen(sandbox.HostArgs{RelayRun: "run-norelay", ObserverDir: obs, ProxyAddr: "127.0.0.1:1"}); got != "" {
		t.Fatalf("absent record, no relay run: %q", got)
	}
	rec := credRunRecord{V: credRecordVersion, RunID: "run-norec", Provider: "anthropic", Custody: vocab.CustodyHostBound, Lane: sandboxcred.LaneLocal, Expires: credNow().Add(time.Hour)}
	if err := credWriteRecord(obs, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credRunPath(obs, "run-norec"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := credLocalReopen(h); !strings.Contains(got, "cannot be read") {
		t.Fatalf("refused record: %q", got)
	}
}

// TestReadoptHelperPrintsTheCredNote (audit FU3-A6): the note a re-adopted
// run's lane re-open returns is printed on the terminal by
// readoptRunHelper itself, beside the re-adoption marker.
func TestReadoptHelperPrintsTheCredNote(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000777")
	raEnder(t)
	// The run's model traffic went through the proxy forward: give the
	// kept launch a proxy address that answers.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })
	e := readoptRead(ra.obs, ra.runID)
	var wrap []string
	for _, a := range e.kept.Wrap {
		if a == "--relay-run" {
			wrap = append(wrap, "--proxy-addr", proxyLn.Addr().String())
		}
		wrap = append(wrap, a)
	}
	e.kept.Wrap = wrap
	if err := readoptWriteFile(readoptRunDir(ra.obs, ra.runID), readoptKeptFile, e.kept); err != nil {
		t.Fatal(err)
	}
	var seen string
	old := localCredReopenHook
	localCredReopenHook = func(h sandbox.HostArgs) string { seen = h.RelayRun; return "TEST-NOTE-0001" }
	t.Cleanup(func() { localCredReopenHook = old })
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	inR, inW := io.Pipe()
	var out raBuf
	term := ociTerm{in: inR, out: &out, size: func() (uint16, uint16) { return 24, 80 }}
	done := make(chan int, 1)
	go func() {
		code, _ := readoptRunHelper(context.Background(), ra.obs, ra.runID, term)
		done <- code
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "agent$") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	_, _ = io.WriteString(inW, "exit\n")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the re-adopted run did not end")
	}
	if seen != ra.runID {
		t.Fatalf("the re-open was asked for %q, want %q", seen, ra.runID)
	}
	if !strings.Contains(out.String(), "credential injection not restored: TEST-NOTE-0001") {
		t.Fatalf("the note was not printed: %q", out.String())
	}
	if _, ok := readoptCredNotes.Load(ra.runID); ok {
		t.Fatal("the note outlived its print")
	}
}
