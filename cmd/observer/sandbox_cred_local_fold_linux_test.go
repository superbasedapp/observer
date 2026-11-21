//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
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
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_cred_local_fold_linux_test.go proves the session fold of an
// injected local run's model turns (tracker row F-003, F-N3-1, OSH-R-150).

// credFoldClaims stubs the relay daemon's claim table with claims (run +
// "\x00" + session -> whether the claim was fresh).
func credFoldClaims(t *testing.T, claims map[string]bool) {
	t.Helper()
	old := credFoldClaimed
	credFoldClaimed = func(run, sid string) (bool, bool) {
		fresh, ok := claims[run+"\x00"+sid]
		return ok, ok && fresh
	}
	t.Cleanup(func() { credFoldClaimed = old })
}

// credFoldLane sets up a local lane for run and returns its relay token.
func credFoldLane(t *testing.T, obs, run, proxyAddr string) (*credLocalRig, string, string) {
	t.Helper()
	rig := newCredLocalRig(t, obs, run, proxyAddr)
	env := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey})
	sentinel := strings.TrimPrefix(env[0], "ANTHROPIC_API_KEY=")
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("no lane: box env %v", env)
	}
	h := http.Header{}
	credLocalStamp(run)(h)
	return rig, h.Get(sandboxcred.TokenHeader), sentinel
}

// TestCredFoldRunSession: the daemon's folder folds a local run's turn onto
// the session the run's hooks claim, and keeps it in the run's namespace
// for every other fact: a forged token, a gone helper, an unclaimed or
// another run's session, no session, an ended lane, and a hosted run.
func TestCredFoldRunSession(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	credFoldClaims(t, map[string]bool{"run-fold\x00native-1": true, "run-other\x00native-2": true, "run-fold\x00host-resumed": false})
	var logs syncBuffer // the default logger is process-wide: a relay goroutine from another test may write it (L-4)
	oldLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLog) })
	rig, token, _ := credFoldLane(t, obs, "run-fold", "127.0.0.1:1")
	inj := &credInjector{observerDir: obs}
	fold := func(run, tok, sid string) (string, bool) {
		return inj.FoldRunSession(context.Background(), proxy.RunSessionRequest{RunID: run, Token: tok, Session: sid})
	}
	for _, tc := range []struct {
		name, run, token, sid, want string
	}{
		{"claimed by the run's hooks", "run-fold", token, "native-1", "native-1"},
		{"forged token", "run-fold", "box-forged", "native-1", ""},
		{"no token", "run-fold", "", "native-1", ""},
		{"not claimed", "run-fold", token, "native-9", ""},
		{"another run's session", "run-fold", token, "native-2", ""},
		{"a session recorded before the run claimed it", "run-fold", token, "host-resumed", ""},
		{"no session", "run-fold", token, "", ""},
		{"no record for the run", "run-nobody", token, "native-1", ""},
	} {
		got, ok := fold(tc.run, tc.token, tc.sid)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: fold = %q %v, want %q", tc.name, got, ok, tc.want)
		}
	}
	if n := strings.Count(logs.String(), "relay_session_mismatch"); n != 2 {
		t.Errorf("mismatch lines: %d, want 2 (native-9 and native-2, once each; a resumed session is no mismatch): %s", n, logs.String())
	}
	if strings.Contains(logs.String(), "native-9") || !strings.Contains(logs.String(), "session_hash="+credFoldSessionRef("native-9")) {
		t.Errorf("a mismatch line must name the session by hash only: %s", logs.String())
	}
	if _, ok := fold("run-fold", token, "native-9"); ok || strings.Count(logs.String(), "relay_session_mismatch") != 2 {
		t.Error("a repeated mismatch logged again")
	}
	live = false
	if _, ok := fold("run-fold", token, "native-1"); ok {
		t.Error("folded after the run's helper was gone")
	}
	live = true
	rig.stop()
	if _, ok := fold("run-fold", token, "native-1"); ok {
		t.Error("folded after the lane ended")
	}

	// A hosted run keeps the run namespace its pulled transcripts use.
	credRelayRecord(t, obs, "run-hosted")
	if err := credSetup(context.Background(), credPlan(obs, "run-hosted")); err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	credStamp(h, "run-hosted")
	credFoldClaims(t, map[string]bool{"run-hosted\x00native-3": true})
	if _, ok := fold("run-hosted", h.Get(sandboxcred.TokenHeader), "native-3"); ok {
		t.Error("a hosted run's turn was folded")
	}
}

// TestE2ELocalRunTurnFoldsOntoItsSession: a local run's turn sent through
// its forward lands in api_turns on the session the run's hooks claim (the
// id its transcript and hooks use), and on the run's namespace when the
// hooks claim no such session.
func TestE2ELocalRunTurnFoldsOntoItsSession(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"msg_fold","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":7,"output_tokens":3}}`)
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
	p, err := proxy.New(proxy.Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: store.New(conn), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	proxy.SetCredentialInjector(&credInjector{observerDir: obs})
	defer proxy.SetCredentialInjector(nil)
	proxySrv := httptest.NewServer(p.Handler())
	defer proxySrv.Close()
	rig, _, sentinel := credFoldLane(t, obs, "run-fold-e2e", proxySrv.Listener.Addr().String())
	credFoldClaims(t, map[string]bool{rig.run + "\x00native-claimed": true})
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
	send := func(sid string) string {
		body := `{"model":"claude-sonnet-4-5","max_tokens":16,"metadata":{"user_id":"{\"session_id\":\"` + sid + `\"}"},"messages":[{"role":"user","content":"hi"}]}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+guestLn.Addr().String()+"/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("X-Api-Key", sentinel)
		req.Header.Set(vocab.RelayRunHeader, "run-someone-else")
		resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			var got string
			_ = conn.QueryRowContext(ctx, `SELECT COALESCE(session_id,'') FROM api_turns ORDER BY id DESC LIMIT 1`).Scan(&got)
			if got == sid || strings.HasSuffix(got, "-"+sid) || time.Now().After(deadline) {
				return got
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if got := send("native-claimed"); got != "native-claimed" {
		t.Fatalf("a claimed session's turn landed on %q, want native-claimed", got)
	}
	if got := send("native-unclaimed"); got != vocab.RelaySessionID(rig.run, "native-unclaimed") {
		t.Fatalf("an unclaimed session's turn landed on %q, want the run's namespace", got)
	}
}

// TestCredFoldMismatchLogBounded (audit FU3-A3): a box naming ever new
// sessions logs at most credFoldMismatchCap lines and one suppression line
// for its run, and the run's state goes when the relay ends the run.
func TestCredFoldMismatchLogBounded(t *testing.T) {
	var logs syncBuffer // the default logger is process-wide: a relay goroutine from another test may write it (L-4)
	oldLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLog) })
	t.Cleanup(func() { credFoldRunEnded("run-flood") })
	for i := 0; i < 3*credFoldMismatchCap; i++ {
		credFoldLogMismatch("run-flood", fmt.Sprintf("box-chosen-%d", i), sandboxcred.FoldNotRunSession)
	}
	if n := strings.Count(logs.String(), "named a session its hooks do not speak for"); n != credFoldMismatchCap {
		t.Fatalf("mismatch lines %d, want %d", n, credFoldMismatchCap)
	}
	if n := strings.Count(logs.String(), "further mismatches of this run are suppressed"); n != 1 {
		t.Fatalf("suppression lines %d, want 1", n)
	}
	v, ok := credFoldMismatches.Load("run-flood")
	if !ok || len(v.(*credFoldMismatch).seen) != credFoldMismatchCap {
		t.Fatal("the run's state is not bounded")
	}
	relayRunEnded("run-flood")
	if _, ok := credFoldMismatches.Load("run-flood"); ok {
		t.Fatal("the run's mismatch state outlived the run")
	}
}

// TestCredFoldWithTheRelayDaemon (audit FU3-A1): with the real relay
// daemon's claim table, a session the run's box starts folds, and a session
// the node recorded under the run's project before the run started (the
// developer's unsandboxed session, which the relay lets the box resume)
// stays in the run's namespace although the box's hook claimed it.
func TestCredFoldWithTheRelayDaemon(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	run := "run-fold-daemon"
	_, token, _ := credFoldLane(t, obs, run, "127.0.0.1:1")
	rec, err := sandboxrelayd.ReadRun(obs, run)
	if err != nil {
		t.Fatal(err)
	}
	// The node already records the host session under the run's project.
	recorded := map[string]string{"host-session": rec.ProjectRoot}
	link := filepath.Join(relayShortDir(t), "link.sock")
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, SweepInterval: -1,
		SessionOwner: func(_ context.Context, id string) (string, error) { return recorded[id], nil },
		Exec: func(context.Context, sandboxrelayd.RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			return sandboxrelay.HookResponse{}, nil
		},
	}
	ln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, ln) }()
	prev := relaySessionClaims.Load()
	relaySessionClaims.Store(d)
	t.Cleanup(func() { relaySessionClaims.Store(prev) })
	hook := func(sid string) {
		msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{
			Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "UserPromptSubmit"},
			Stdin: []byte(`{"session_id":"` + sid + `"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		out, err := sandboxrelayd.LinkRoundTrip(rctx, func(ctx context.Context) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", link)
		}, rec, msg, sandboxrelay.DefaultConnLimits)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := sandboxrelay.DecodeHookResponse(out)
		if err != nil || resp.Refused != "" {
			t.Fatalf("hook for %s: %v refused %q", sid, err, resp.Refused)
		}
	}
	hook("box-session")
	hook("host-session")
	inj := &credInjector{observerDir: obs}
	fold := func(sid string) (string, bool) {
		return inj.FoldRunSession(context.Background(), proxy.RunSessionRequest{RunID: run, Token: token, Session: sid})
	}
	if got, ok := fold("box-session"); !ok || got != "box-session" {
		t.Fatalf("the box's own session: %q %v", got, ok)
	}
	if got, ok := fold("host-session"); ok || got != "" {
		t.Fatalf("a session recorded before the run folded: %q %v", got, ok)
	}
}

// foldRelay starts a real relay daemon for obs with owner as its
// SessionOwner and the credentials FreshStore, installs it as this
// process's claim table, and returns it and a func that sends one hook
// naming a session for rec.
func foldRelay(t *testing.T, obs string, owner func(context.Context, string) (string, error)) (*sandboxrelayd.Daemon, func(rec sandboxrelayd.RunRecord, sid string)) {
	t.Helper()
	link := filepath.Join(relayShortDir(t), "link.sock")
	d := &sandboxrelayd.Daemon{
		ObserverDir: obs, Rules: relayRules, Peer: sandboxrelayd.PeerSameUser, SweepInterval: -1,
		SessionOwner: owner, FreshStore: relayFreshStoreFor(obs),
		Exec: func(context.Context, sandboxrelayd.RunRecord, sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
			return sandboxrelay.HookResponse{}, nil
		},
	}
	ln, err := net.Listen("unix", link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Serve(ctx, ln) }()
	prev := relaySessionClaims.Load()
	relaySessionClaims.Store(d)
	t.Cleanup(func() { relaySessionClaims.Store(prev) })
	hook := func(rec sandboxrelayd.RunRecord, sid string) {
		t.Helper()
		msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{
			Kind: sandboxrelay.KindHook, Args: []string{"claude-code", "UserPromptSubmit"},
			Stdin: []byte(`{"session_id":"` + sid + `"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		out, err := sandboxrelayd.LinkRoundTrip(rctx, func(ctx context.Context) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", link)
		}, rec, msg, sandboxrelay.DefaultConnLimits)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := sandboxrelay.DecodeHookResponse(out)
		if err != nil || resp.Refused != "" {
			t.Fatalf("hook for %s: %v refused %q", sid, err, resp.Refused)
		}
	}
	return d, hook
}

// TestCredFoldFreshnessSurvivesClaimDrops (audit FU3-R1): the run's own
// session, fresh at its first claim and recorded by the node since, still
// folds after the relay dropped the run's claims, one case per way: the
// run swept and re-adopted under the same id (its re-keyed relay record),
// and a daemon restart; a session recorded before the run never folds, in
// either case.
func TestCredFoldFreshnessSurvivesClaimDrops(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop func(t *testing.T, obs, run string, d *sandboxrelayd.Daemon, owner func(context.Context, string) (string, error)) func(sandboxrelayd.RunRecord, string)
	}{
		{"re-adoption: claims dropped, relay record re-keyed, same run id", func(t *testing.T, obs, run string, d *sandboxrelayd.Daemon, _ func(context.Context, string) (string, error)) func(sandboxrelayd.RunRecord, string) {
			d.EndRun(run)
			rec, err := sandboxrelayd.ReadRun(obs, run)
			if err != nil {
				t.Fatal(err)
			}
			// What readoptRekey does: a fresh relay record (new secrets)
			// for the same run id and facts.
			fresh, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: run, Tool: rec.Tool, ProjectRoot: rec.ProjectRoot, WorkspaceDir: rec.WorkspaceDir, Roots: rec.Roots})
			if err != nil {
				t.Fatal(err)
			}
			if err := sandboxrelayd.RemoveRun(obs, run); err != nil {
				t.Fatal(err)
			}
			if err := sandboxrelayd.WriteRun(obs, fresh); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		{"daemon restart: a new relay daemon over the same files", func(t *testing.T, obs, _ string, _ *sandboxrelayd.Daemon, owner func(context.Context, string) (string, error)) func(sandboxrelayd.RunRecord, string) {
			_, hook := foldRelay(t, obs, owner)
			return hook
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs, ks := credEnvForTest(t, true)
			if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
				t.Fatal(err)
			}
			live := true
			credLocalHelperLive(t, &live)
			run := "run-r1-" + map[bool]string{true: "readopt", false: "restart"}[strings.HasPrefix(tc.name, "re-adoption")]
			_, token, _ := credFoldLane(t, obs, run, "127.0.0.1:1")
			rec, err := sandboxrelayd.ReadRun(obs, run)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			recorded := map[string]string{"host-session": rec.ProjectRoot}
			owner := func(_ context.Context, id string) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				return recorded[id], nil
			}
			d, hook := foldRelay(t, obs, owner)
			hook(rec, "box-session")
			hook(rec, "host-session")
			mu.Lock()
			recorded["box-session"] = rec.ProjectRoot // the run's own hook recorded it
			mu.Unlock()
			inj := &credInjector{observerDir: obs}
			fold := func(sid string) bool {
				_, ok := inj.FoldRunSession(context.Background(), proxy.RunSessionRequest{RunID: run, Token: token, Session: sid})
				return ok
			}
			if !fold("box-session") || fold("host-session") {
				t.Fatal("before the drop: the box's session must fold and the host session must not")
			}
			if again := tc.drop(t, obs, run, d, owner); again != nil {
				hook = again
			}
			rec, err = sandboxrelayd.ReadRun(obs, run) // a re-keyed record carries new secrets
			if err != nil {
				t.Fatal(err)
			}
			hook(rec, "box-session")
			hook(rec, "host-session")
			if !fold("box-session") {
				t.Fatal("after the drop: the run's own session no longer folds")
			}
			if fold("host-session") {
				t.Fatal("after the drop: a session recorded before the run folds")
			}
		})
	}
}

// TestCredFreshStore (audit FU3-R1): the kept fresh ids are written only
// for a run with a local injection record, deduplicated, bounded at
// credFreshCap, owner-only, and removed with the record at the lane's end.
func TestCredFreshStore(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	s := relayFreshStoreFor(obs)
	s.AddFresh("run-no-record", []string{"s1"})
	if _, err := os.Lstat(credFreshPath(obs, "run-no-record")); err == nil {
		t.Fatal("kept ids for a run with no injection record")
	}
	rig, _, _ := credFoldLane(t, obs, "run-r1-store", "127.0.0.1:1")
	var many []string
	for i := 0; i < 2*credFreshCap; i++ {
		many = append(many, fmt.Sprintf("s%d", i))
	}
	s.AddFresh(rig.run, []string{"s0", "s0"})
	s.AddFresh(rig.run, many)
	got := s.Fresh(rig.run)
	if len(got) != credFreshCap || got[0] != "s0" {
		t.Fatalf("kept %d ids (%v), want %d starting with s0", len(got), got, credFreshCap)
	}
	fi, err := os.Lstat(credFreshPath(obs, rig.run))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept file: %v %v", fi, err)
	}
	rig.stop()
	if _, err := os.Lstat(credFreshPath(obs, rig.run)); err == nil {
		t.Fatal("the kept ids outlived the lane")
	}
}
