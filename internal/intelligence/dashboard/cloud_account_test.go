package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// fakeCloudRunner is a controllable CloudCommandRunner: it records each
// verb+args, writes a scripted output, then blocks until released or returns
// immediately. When blockVerb is set, only THAT verb blocks on release — every
// other verb returns immediately even though a release channel is configured,
// so a test can hold one action (e.g. "login") in flight while exercising a
// second, unrelated action (e.g. "preview") through the SAME seams/runner
// pair. blockVerb == "" (the zero value) preserves the original behavior:
// every call blocks when a release channel is set.
type fakeCloudRunner struct {
	mu        sync.Mutex
	verbs     []string
	argvs     [][]string
	release   chan error // the blocking verb(s) block on this; nil ⇒ never block
	blockVerb string
	output    string
}

func (f *fakeCloudRunner) run(ctx context.Context, verb string, args []string, out io.Writer) error {
	f.mu.Lock()
	f.verbs = append(f.verbs, verb)
	f.argvs = append(f.argvs, append([]string(nil), args...))
	rel, output, blockVerb := f.release, f.output, f.blockVerb
	f.mu.Unlock()
	if output != "" {
		_, _ = io.WriteString(out, output)
	}
	if rel == nil {
		return nil
	}
	if blockVerb != "" && verb != blockVerb {
		return nil
	}
	select {
	case err := <-rel:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeCloudRunner) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.verbs...)
}

// argsFor returns the args recorded for the i-th run() call (0-indexed) — nil
// when out of range — for tests that need to assert the exact argv rather
// than just the verb.
func (f *fakeCloudRunner) argsFor(i int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < 0 || i >= len(f.argvs) {
		return nil
	}
	return append([]string(nil), f.argvs[i]...)
}

// fakeCloudProbe is a mutable CloudSignInProbe.
type fakeCloudProbe struct {
	mu  sync.Mutex
	st  CloudSignInState
	err error
}

func (p *fakeCloudProbe) probe() (CloudSignInState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st, p.err
}

func (p *fakeCloudProbe) set(st CloudSignInState) {
	p.mu.Lock()
	p.st = st
	p.mu.Unlock()
}

func newCloudAccountTestServer(t *testing.T, probe *fakeCloudProbe, runner *fakeCloudRunner) *Server {
	t.Helper()
	srv, _ := newCloudTestServer(t)
	var pf CloudSignInProbe
	if probe != nil {
		pf = probe.probe
	}
	var rf CloudCommandRunner
	if runner != nil {
		rf = runner.run
	}
	srv.opts.CloudAccount = NewCloudAccountSeams(pf, rf, nil)
	return srv
}

func cloudDoJSON[T any](t *testing.T, h http.HandlerFunc, method, path string) (int, T) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	var v T
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("decode %s %s: %v\n%s", method, path, err, rec.Body.String())
		}
	}
	return rec.Code, v
}

// cloudWaitFor polls until cond holds or the deadline passes.
func cloudWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestCloudStatusSignInShape pins the `sign_in` block on GET /api/cloud/status:
// present with the probe's fields when the seam is wired, absent when not.
func TestCloudStatusSignInShape(t *testing.T) {
	t.Run("unwired omits sign_in", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		code, body := cloudDoJSON[map[string]json.RawMessage](t, srv.handleCloudStatus, http.MethodGet, "/api/cloud/status")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		if _, ok := body["sign_in"]; ok {
			t.Fatalf("sign_in must be omitted when Options.CloudAccount is nil, got %s", body["sign_in"])
		}
	})
	t.Run("wired reports presence + backend + client id", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{
			APITokenPresent: true, WorkOSSignInPresent: true, CredentialBackend: "keychain", ClientIDConfigured: true,
		}}
		srv := newCloudAccountTestServer(t, probe, &fakeCloudRunner{})
		code, body := cloudDoJSON[CloudStatusResponse](t, srv.handleCloudStatus, http.MethodGet, "/api/cloud/status")
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
		si := body.SignIn
		if si == nil || !si.Known || !si.SignedIn || !si.APITokenPresent || !si.WorkOSSignInPresent ||
			si.CredentialBackend != "keychain" || !si.ClientIDConfigured || !si.ActionsAvailable || si.LoginRunning {
			t.Fatalf("sign_in = %+v", si)
		}
		// JSON key spellings are the wire contract the page + header chip read.
		raw, _ := json.Marshal(si)
		for _, key := range []string{`"api_token_present"`, `"workos_sign_in_present"`, `"credential_backend"`, `"client_id_configured"`, `"signed_in"`, `"login_running"`} {
			if !strings.Contains(string(raw), key) {
				t.Errorf("sign_in JSON lacks %s: %s", key, raw)
			}
		}
	})
	t.Run("probe error is honest", func(t *testing.T) {
		probe := &fakeCloudProbe{err: errors.New("keychain locked")}
		srv := newCloudAccountTestServer(t, probe, &fakeCloudRunner{})
		_, body := cloudDoJSON[CloudStatusResponse](t, srv.handleCloudStatus, http.MethodGet, "/api/cloud/status")
		if body.SignIn == nil || body.SignIn.Known || body.SignIn.SignedIn || !strings.Contains(body.SignIn.Error, "keychain locked") {
			t.Fatalf("sign_in = %+v", body.SignIn)
		}
	})
}

// TestCloudLoginStateMachine drives POST /api/cloud/login through: running →
// auth URL captured from the child's output → child exits 0 + probe flips →
// finished ok. A second POST while running returns the running state without a
// second spawn.
func TestCloudLoginStateMachine(t *testing.T) {
	probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true, CredentialBackend: "file"}}
	runner := &fakeCloudRunner{
		release: make(chan error, 1),
		output: "Opening your browser to sign in with WorkOS...\n" +
			"If it does not open, visit this URL:\n\n" +
			"  https://auth.example.com/authorize?client_id=abc&state=xyz\n\n",
	}
	srv := newCloudAccountTestServer(t, probe, runner)

	// Before any login: idle state.
	code, st := cloudDoJSON[CloudLoginState](t, srv.handleCloudLoginState, http.MethodGet, "/api/cloud/login/state")
	if code != http.StatusOK || st.Running || st.Finished {
		t.Fatalf("idle state = %d %+v", code, st)
	}

	code, st = cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
	if code != http.StatusOK || !st.Running || st.Finished {
		t.Fatalf("first POST = %d %+v", code, st)
	}
	// The authorize URL is captured from the child's output.
	cloudWaitFor(t, "auth_url capture", func() bool { return srv.opts.CloudAccount.state().AuthURL != "" })
	_, st = cloudDoJSON[CloudLoginState](t, srv.handleCloudLoginState, http.MethodGet, "/api/cloud/login/state")
	if st.AuthURL != "https://auth.example.com/authorize?client_id=abc&state=xyz" || !st.Running {
		t.Fatalf("running state = %+v", st)
	}

	// Second POST while running: current state, no second spawn.
	code, st2 := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
	if code != http.StatusOK || !st2.Running || st2.AuthURL != st.AuthURL {
		t.Fatalf("second POST = %d %+v", code, st2)
	}
	if got := runner.calls(); len(got) != 1 {
		t.Fatalf("second POST must not spawn again, calls = %v", got)
	}
	// Status poll mirrors the running flag.
	_, status := cloudDoJSON[CloudStatusResponse](t, srv.handleCloudStatus, http.MethodGet, "/api/cloud/status")
	if status.SignIn == nil || !status.SignIn.LoginRunning {
		t.Fatalf("status.sign_in.login_running = %+v", status.SignIn)
	}

	// Child finishes cleanly and the credential appears.
	probe.set(CloudSignInState{ClientIDConfigured: true, APITokenPresent: true, WorkOSSignInPresent: true})
	runner.release <- nil
	cloudWaitFor(t, "login finish", func() bool { return srv.opts.CloudAccount.state().Finished })
	_, st = cloudDoJSON[CloudLoginState](t, srv.handleCloudLoginState, http.MethodGet, "/api/cloud/login/state")
	if st.Running || !st.Finished || !st.OK || !strings.Contains(st.Message, "Signed in") || st.FinishedAt == "" {
		t.Fatalf("finished state = %+v", st)
	}
	_, status = cloudDoJSON[CloudStatusResponse](t, srv.handleCloudStatus, http.MethodGet, "/api/cloud/status")
	if !status.SignIn.SignedIn || status.SignIn.LoginRunning {
		t.Fatalf("status after login = %+v", status.SignIn)
	}
}

// TestCloudLoginFailureModes pins the two "finished, not ok" shapes: the child
// exits non-zero (its last output line is carried), and the child exits 0 but
// no credential was stored (the CLI's "how to configure" exit — never a
// sign-in).
func TestCloudLoginFailureModes(t *testing.T) {
	t.Run("child error", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "Opening your browser...\nError: state mismatch (possible CSRF) — sign-in aborted\n"}
		srv := newCloudAccountTestServer(t, probe, runner)
		if code, _ := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login"); code != http.StatusOK {
			t.Fatalf("POST = %d", code)
		}
		runner.release <- errors.New("exit status 1")
		cloudWaitFor(t, "finish", func() bool { return srv.opts.CloudAccount.state().Finished })
		st := srv.opts.CloudAccount.state()
		if st.OK || !strings.Contains(st.Message, "exit status 1") || !strings.Contains(st.Message, "state mismatch") {
			t.Fatalf("state = %+v", st)
		}
	})
	t.Run("exit 0 without a credential", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv := newCloudAccountTestServer(t, probe, runner)
		if code, _ := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login"); code != http.StatusOK {
			t.Fatalf("POST = %d", code)
		}
		runner.release <- nil
		cloudWaitFor(t, "finish", func() bool { return srv.opts.CloudAccount.state().Finished })
		st := srv.opts.CloudAccount.state()
		if st.OK || !strings.Contains(st.Message, "did not complete") {
			t.Fatalf("state = %+v", st)
		}
	})
	t.Run("a finished run can be retried", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 2)}
		srv := newCloudAccountTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		runner.release <- errors.New("boom")
		cloudWaitFor(t, "finish", func() bool { return srv.opts.CloudAccount.state().Finished })
		code, st := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		if code != http.StatusOK || !st.Running || st.Finished {
			t.Fatalf("retry POST = %d %+v", code, st)
		}
		// The spawn happens on the goroutine; wait for it rather than racing it.
		cloudWaitFor(t, "second spawn", func() bool { return len(runner.calls()) == 2 })
		runner.release <- nil
	})
}

// TestCloudLoginRefusals pins the up-front refusals: no client id (409 naming
// both knobs), no runner wired (503), wrong method (405).
func TestCloudLoginRefusals(t *testing.T) {
	t.Run("missing client id", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: false}}
		runner := &fakeCloudRunner{}
		srv := newCloudAccountTestServer(t, probe, runner)
		req := httptest.NewRequest(http.MethodPost, "/api/cloud/login", nil)
		rec := httptest.NewRecorder()
		srv.handleCloudLogin(rec, req)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "[cloud].workos_client_id") || !strings.Contains(rec.Body.String(), "WORKOS_CLIENT_ID") {
			t.Fatalf("missing client id → %d %q", rec.Code, rec.Body.String())
		}
		if len(runner.calls()) != 0 {
			t.Fatalf("must not spawn without a client id")
		}
	})
	t.Run("unwired", func(t *testing.T) {
		srv, _ := newCloudTestServer(t)
		for _, tc := range []struct {
			method string
			h      http.HandlerFunc
		}{
			{http.MethodPost, srv.handleCloudLogin},
			{http.MethodGet, srv.handleCloudLoginState},
			{http.MethodPost, srv.handleCloudLogout},
			{http.MethodPost, srv.handleCloudSync},
			{http.MethodGet, srv.handleCloudSyncState},
		} {
			rec := httptest.NewRecorder()
			tc.h(rec, httptest.NewRequest(tc.method, "/api/cloud/x", nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s unwired → %d, want 503", tc.method, rec.Code)
			}
		}
	})
	t.Run("method", func(t *testing.T) {
		srv := newCloudAccountTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudLogin(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/login", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET login → %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		srv.handleCloudLogout(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/logout", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET logout → %d", rec.Code)
		}
	})
}

// TestCloudLoginOrgEnrolledRefusal pins the enterprise-first gate: an
// org-enrolled node refuses POST /api/cloud/login with 409 BEFORE spawning the
// `observer cloud login` subprocess, even though the seams are fully wired and
// a client id is configured. Not-enrolled (and a Status error, which must not
// block a legitimate personal sign-in) still reach the runner.
func TestCloudLoginOrgEnrolledRefusal(t *testing.T) {
	t.Run("enrolled refuses without spawning", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{}
		srv := newCloudAccountTestServer(t, probe, runner)
		srv.opts.OrgClient = &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: true, OrgName: "Acme Corp"}}

		rec := httptest.NewRecorder()
		srv.handleCloudLogin(rec, httptest.NewRequest(http.MethodPost, "/api/cloud/login", nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("org-enrolled login → %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "org-enrolled") || !strings.Contains(rec.Body.String(), "managed by your organization") {
			t.Fatalf("body = %q", rec.Body.String())
		}
		if got := runner.calls(); len(got) != 0 {
			t.Fatalf("must not spawn a subprocess when org-enrolled, calls = %v", got)
		}
	})
	t.Run("not enrolled still proceeds", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{}
		srv := newCloudAccountTestServer(t, probe, runner)
		srv.opts.OrgClient = &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: false}}

		code, _ := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		if code != http.StatusOK {
			t.Fatalf("not-enrolled login → %d", code)
		}
		cloudWaitFor(t, "spawn when not enrolled", func() bool { return len(runner.calls()) == 1 })
	})
	t.Run("status error does not block sign-in", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{}
		srv := newCloudAccountTestServer(t, probe, runner)
		srv.opts.OrgClient = &fakeEnrolment{statusErr: errors.New("keychain locked")}

		code, _ := cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		if code != http.StatusOK {
			t.Fatalf("status-error login → %d", code)
		}
		cloudWaitFor(t, "spawn when the enrolment probe errors", func() bool { return len(runner.calls()) == 1 })
	})
}

// TestCloudLogout pins POST /api/cloud/logout: runs `cloud logout`
// synchronously and reports its output; refused (409) while a login runs.
func TestCloudLogout(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		runner := &fakeCloudRunner{output: "Logged out — credentials cleared. Local enrichment results are kept.\n"}
		srv := newCloudAccountTestServer(t, &fakeCloudProbe{}, runner)
		code, resp := cloudDoJSON[CloudLogoutResponse](t, srv.handleCloudLogout, http.MethodPost, "/api/cloud/logout")
		if code != http.StatusOK || !resp.OK || !strings.Contains(resp.Message, "Logged out") {
			t.Fatalf("logout = %d %+v", code, resp)
		}
		if got := runner.calls(); len(got) != 1 || got[0] != "logout" {
			t.Fatalf("calls = %v", got)
		}
	})
	t.Run("child error", func(t *testing.T) {
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "clear credentials: permission denied\n"}
		runner.release <- errors.New("exit status 1")
		srv := newCloudAccountTestServer(t, &fakeCloudProbe{}, runner)
		code, resp := cloudDoJSON[CloudLogoutResponse](t, srv.handleCloudLogout, http.MethodPost, "/api/cloud/logout")
		if code != http.StatusOK || resp.OK || !strings.Contains(resp.Message, "exit status 1") || !strings.Contains(resp.Message, "permission denied") {
			t.Fatalf("logout = %d %+v", code, resp)
		}
	})
	t.Run("refused while login runs", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv := newCloudAccountTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })
		rec := httptest.NewRecorder()
		srv.handleCloudLogout(rec, httptest.NewRequest(http.MethodPost, "/api/cloud/logout", nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("logout during login → %d", rec.Code)
		}
		if got := runner.calls(); len(got) != 1 {
			t.Fatalf("logout must not spawn during login, calls = %v", got)
		}
		runner.release <- nil
	})
}

// TestCloudSync pins the POST /api/cloud/sync + GET /api/cloud/sync/state
// state machine: idle → running → finished ok, a second POST while running
// returns the same run (no second spawn), a runner error finishes with
// ExitError set, and the two up-front refusals (not signed in; a login is
// running) never spawn a subprocess.
func TestCloudSync(t *testing.T) {
	t.Run("start -> running -> finished ok", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "draining outbox...\nsynced 3 items\n"}
		srv := newCloudAccountTestServer(t, probe, runner)

		code, st := cloudDoJSON[CloudSyncState](t, srv.handleCloudSyncState, http.MethodGet, "/api/cloud/sync/state")
		if code != http.StatusOK || st.Running || st.OK != nil {
			t.Fatalf("idle state = %d %+v", code, st)
		}

		code, st = cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		if code != http.StatusOK || !st.Running || st.OK != nil {
			t.Fatalf("first POST = %d %+v", code, st)
		}
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })
		if got := runner.calls(); got[0] != "sync" {
			t.Fatalf("calls = %v", got)
		}

		runner.release <- nil
		cloudWaitFor(t, "sync finish", func() bool {
			_, st := cloudDoJSON[CloudSyncState](t, srv.handleCloudSyncState, http.MethodGet, "/api/cloud/sync/state")
			return !st.Running && st.OK != nil
		})
		_, st = cloudDoJSON[CloudSyncState](t, srv.handleCloudSyncState, http.MethodGet, "/api/cloud/sync/state")
		if st.Running || st.OK == nil || !*st.OK || st.ExitError != "" || !strings.Contains(st.Tail, "synced 3 items") {
			t.Fatalf("finished state = %+v", st)
		}
	})

	t.Run("runner error finishes with exit_error", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{WorkOSSignInPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1), output: "upload failed: 500\n"}
		srv := newCloudAccountTestServer(t, probe, runner)

		cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		runner.release <- errors.New("exit status 1")
		cloudWaitFor(t, "sync finish", func() bool {
			_, st := cloudDoJSON[CloudSyncState](t, srv.handleCloudSyncState, http.MethodGet, "/api/cloud/sync/state")
			return !st.Running && st.OK != nil
		})
		_, st := cloudDoJSON[CloudSyncState](t, srv.handleCloudSyncState, http.MethodGet, "/api/cloud/sync/state")
		if st.OK == nil || *st.OK || !strings.Contains(st.ExitError, "exit status 1") || !strings.Contains(st.Tail, "upload failed") {
			t.Fatalf("failed state = %+v", st)
		}
	})

	t.Run("second POST while running returns the same run", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv := newCloudAccountTestServer(t, probe, runner)

		code, st1 := cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		if code != http.StatusOK || !st1.Running {
			t.Fatalf("first POST = %d %+v", code, st1)
		}
		cloudWaitFor(t, "sync spawn", func() bool { return len(runner.calls()) == 1 })
		code, st2 := cloudDoJSON[CloudSyncState](t, srv.handleCloudSync, http.MethodPost, "/api/cloud/sync")
		if code != http.StatusOK || !st2.Running || st1.StartedAt != st2.StartedAt {
			t.Fatalf("second POST = %d %+v", code, st2)
		}
		if got := runner.calls(); len(got) != 1 {
			t.Fatalf("second POST must not spawn again, calls = %v", got)
		}
		runner.release <- nil
	})

	t.Run("409 when not signed in", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{}}
		runner := &fakeCloudRunner{}
		srv := newCloudAccountTestServer(t, probe, runner)
		rec := httptest.NewRecorder()
		srv.handleCloudSync(rec, httptest.NewRequest(http.MethodPost, "/api/cloud/sync", nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("not signed in → %d, want 409: %s", rec.Code, rec.Body.String())
		}
		if len(runner.calls()) != 0 {
			t.Fatalf("must not spawn without a sign-in")
		}
	})

	t.Run("409 while a login is running", func(t *testing.T) {
		probe := &fakeCloudProbe{st: CloudSignInState{APITokenPresent: true, ClientIDConfigured: true}}
		runner := &fakeCloudRunner{release: make(chan error, 1)}
		srv := newCloudAccountTestServer(t, probe, runner)
		cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
		cloudWaitFor(t, "login spawn", func() bool { return len(runner.calls()) == 1 })

		rec := httptest.NewRecorder()
		srv.handleCloudSync(rec, httptest.NewRequest(http.MethodPost, "/api/cloud/sync", nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("sync during login → %d", rec.Code)
		}
		if got := runner.calls(); len(got) != 1 {
			t.Fatalf("sync must not spawn during login, calls = %v", got)
		}
		runner.release <- nil
	})

	t.Run("method", func(t *testing.T) {
		srv := newCloudAccountTestServer(t, &fakeCloudProbe{}, &fakeCloudRunner{})
		rec := httptest.NewRecorder()
		srv.handleCloudSync(rec, httptest.NewRequest(http.MethodGet, "/api/cloud/sync", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET sync → %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		srv.handleCloudSyncState(rec, httptest.NewRequest(http.MethodPost, "/api/cloud/sync/state", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST sync/state → %d", rec.Code)
		}
	})
}

// TestCloudLoginTimeout pins the daemon-side bound: a child that never exits is
// killed via ctx and the run finishes not-ok.
func TestCloudLoginTimeout(t *testing.T) {
	probe := &fakeCloudProbe{st: CloudSignInState{ClientIDConfigured: true}}
	runner := &fakeCloudRunner{release: make(chan error)} // never released
	srv := newCloudAccountTestServer(t, probe, runner)
	srv.opts.CloudAccount.loginTimeout = 30 * time.Millisecond
	cloudDoJSON[CloudLoginState](t, srv.handleCloudLogin, http.MethodPost, "/api/cloud/login")
	cloudWaitFor(t, "timeout finish", func() bool { return srv.opts.CloudAccount.state().Finished })
	st := srv.opts.CloudAccount.state()
	if st.OK || !strings.Contains(st.Message, "deadline") {
		t.Fatalf("timeout state = %+v", st)
	}
}

// TestCloudLooksLikeAuthURL pins the URL line test (whole-line absolute URL).
func TestCloudLooksLikeAuthURL(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"https://x.example/authorize?a=b", true},
		{"http://127.0.0.1:9797/callback", true},
		{"If it does not open, visit this URL:", false},
		{"visit https://x.example now", false},
		{"", false},
	} {
		if got := cloudLooksLikeAuthURL(tc.line); got != tc.want {
			t.Errorf("%q → %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestCloudSectionWrite pins the [cloud] section on PUT /api/config/section:
// a partial body preserves omitted keys (login_port), restart_required is true
// only when the background-sync schedule changed.
func TestCloudSectionWrite(t *testing.T) {
	srv, _ := newCloudTestServer(t)
	dir := t.TempDir()
	cfgPath := dir + "/config.toml"
	if err := os.WriteFile(cfgPath, []byte("[cloud]\nlogin_port = 9898\nbase_url = \"https://old.example\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.opts.ConfigPath = cfgPath

	put := func(body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPut, "/api/config/section/cloud", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handleConfigSection(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := put(`{"BaseURL":"https://new.example","WorkOSClientID":" client_abc ","AutoEnrich":true}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d %v", code, out)
	}
	if out["restart_required"] != false {
		t.Errorf("base_url/client id/auto_enrich save must not require a restart: %v", out)
	}
	cfg, err := loadConfigForDashboard(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cloud.BaseURL != "https://new.example" || cfg.Cloud.WorkOSClientID != "client_abc" || !cfg.Cloud.AutoEnrich || cfg.Cloud.LoginPort != 9898 {
		t.Fatalf("cloud after PUT = %+v", cfg.Cloud)
	}

	code, out = put(`{"AutoSync":true,"AutoSyncIntervalMinutes":15}`)
	if code != http.StatusOK || out["restart_required"] != true {
		t.Fatalf("auto_sync save = %d %v (want restart_required=true)", code, out)
	}
	cfg, _ = loadConfigForDashboard(cfgPath)
	if !cfg.Cloud.AutoSync || cfg.Cloud.AutoSyncIntervalMinutes != 15 || cfg.Cloud.BaseURL != "https://new.example" {
		t.Fatalf("cloud after second PUT = %+v", cfg.Cloud)
	}

	// Validation still gates the write (interval below the floor).
	if code, _ = put(`{"AutoSyncIntervalMinutes":1}`); code != http.StatusBadRequest {
		t.Fatalf("interval below floor → %d, want 400", code)
	}
	if code, _ = put(`{"BaseURL":"not a url"}`); code != http.StatusBadRequest {
		t.Fatalf("bad base_url → %d, want 400", code)
	}
}
