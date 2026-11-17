package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

// TestApplyConnectLine pins connectLineRules: one case per row, plus the
// lines that must never move the progress.
func TestApplyConnectLine(t *testing.T) {
	approved := ConnectProgress{State: connectStateApproved, Target: &ConnectTarget{Kind: "team", DisplayName: "Acme Dev", ShareLevel: "full"}}
	cases := []struct {
		name    string
		from    ConnectProgress
		line    string
		ok      bool
		want    ConnectProgress
		expires time.Duration
	}{
		{
			name: "waiting_approval",
			from: ConnectProgress{State: connectStateStarting},
			line: `{"state":"waiting_approval","approve_url":"https://cloud.superbased.app/connect/r1","verify_url":"https://cloud.superbased.app/connect","user_code":"ktrw-4821"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateWaiting, ApproveURL: "https://cloud.superbased.app/connect/r1", VerifyURL: "https://cloud.superbased.app/connect", UserCode: "KTRW-4821"},
		},
		{
			name:    "waiting with expires_in",
			from:    ConnectProgress{State: connectStateStarting},
			line:    `{"state":"waiting_approval","approve_url":"https://x.example/a","expires_in":600}`,
			ok:      true,
			want:    ConnectProgress{State: connectStateWaiting, ApproveURL: "https://x.example/a"},
			expires: 600 * time.Second,
		},
		{
			name:    "expires_in is capped",
			from:    ConnectProgress{State: connectStateStarting},
			line:    `{"state":"waiting_approval","expires_in":999999}`,
			ok:      true,
			want:    ConnectProgress{State: connectStateWaiting},
			expires: connectMaxExpiry,
		},
		{
			name: "unsafe approve url is dropped",
			from: ConnectProgress{State: connectStateStarting},
			line: `{"state":"waiting_approval","approve_url":"javascript:alert(1)","verify_url":"http://evil.example/x","user_code":"<b>"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateWaiting},
		},
		{
			name: "approved",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"approved","target":{"org_id":"o1","slug":"acme-dev","kind":"team","display_name":"Acme Dev","share_level":"full"}}`,
			ok:   true,
			want: ConnectProgress{State: connectStateApproved, Target: &ConnectTarget{OrgID: "o1", Slug: "acme-dev", Kind: "team", DisplayName: "Acme Dev", ShareLevel: "full"}},
		},
		{
			name: "approved with unknown kind and share level keeps them empty",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"approved","target":{"kind":"org","share_level":"everything","display_name":"X"}}`,
			ok:   true,
			want: ConnectProgress{State: connectStateApproved, Target: &ConnectTarget{DisplayName: "X"}},
		},
		{
			name: "attaching",
			from: approved,
			line: `{"state":"attaching"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateAttaching, Target: approved.Target},
		},
		{
			name: "connected falls back to the target's name and kind",
			from: approved,
			line: `{"state":"connected","online_url":"https://acme-dev.superbased.app/"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateConnected, Target: approved.Target, DisplayName: "Acme Dev", Kind: "team", OnlineURL: "https://acme-dev.superbased.app/"},
		},
		{
			name: "connected names its own target",
			from: ConnectProgress{State: connectStateAttaching},
			line: `{"state":"connected","display_name":"Personal dashboard","kind":"personal","online_url":"https://u-abc.superbased.app/"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateConnected, DisplayName: "Personal dashboard", Kind: "personal", OnlineURL: "https://u-abc.superbased.app/"},
		},
		{
			name: "signed_in_only",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"signed_in_only"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateSignedInOnly},
		},
		{
			name: "error",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"error","code":"declined","message":"The request was declined."}`,
			ok:   true,
			want: ConnectProgress{State: connectStateError, Code: "declined", Message: "The request was declined."},
		},
		{
			name: "error without a message gets one",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"error","code":"x"}`,
			ok:   true,
			want: ConnectProgress{State: connectStateError, Code: "x", Message: "Connecting did not finish."},
		},
		{
			name: "unknown state is ignored",
			from: ConnectProgress{State: connectStateWaiting},
			line: `{"state":"teleporting"}`,
			want: ConnectProgress{State: connectStateWaiting},
		},
		{
			name: "plain text is ignored",
			from: ConnectProgress{State: connectStateWaiting},
			line: `Waiting for approval...`,
			want: ConnectProgress{State: connectStateWaiting},
		},
		{
			name: "nothing moves a finished flow",
			from: ConnectProgress{State: connectStateConnected, DisplayName: "Acme"},
			line: `{"state":"error","message":"late"}`,
			want: ConnectProgress{State: connectStateConnected, DisplayName: "Acme"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, exp, ok := applyConnectLine(c.from, []byte(c.line))
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("progress = %+v (target %+v), want %+v (target %+v)", got, got.Target, c.want, c.want.Target)
			}
			if exp != c.expires {
				t.Fatalf("expires = %v, want %v", exp, c.expires)
			}
		})
	}
}

// TestConnectLineRulesCoverContractB pins the table against contract B's
// six states, and which of them end the flow.
func TestConnectLineRulesCoverContractB(t *testing.T) {
	want := map[string]bool{
		connectStateWaiting:      false,
		connectStateApproved:     false,
		connectStateAttaching:    false,
		connectStateConnected:    true,
		connectStateSignedInOnly: true,
		connectStateError:        true,
	}
	if len(connectLineRules) != len(want) {
		t.Fatalf("%d rules, want %d", len(connectLineRules), len(want))
	}
	for _, r := range connectLineRules {
		term, ok := want[r.state]
		if !ok || term != r.terminal {
			t.Errorf("rule %q terminal=%v, want present with terminal=%v", r.state, r.terminal, term)
		}
	}
}

func TestSafeConnectURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://cloud.superbased.app/connect/r1": "https://cloud.superbased.app/connect/r1",
		"http://127.0.0.1:9800/connect/r1":        "http://127.0.0.1:9800/connect/r1",
		"http://localhost:9800/x":                 "http://localhost:9800/x",
		"http://cloud.superbased.app/connect":     "",
		"javascript:alert(1)":                     "",
		"/connect/r1":                             "",
		"https://user:pw@cloud.superbased.app/":   "",
		"":                                        "",
	} {
		if got := safeConnectURL(in); got != want {
			t.Errorf("safeConnectURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeTeamSlug(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"  ", "", true},
		{"acme-dev", "acme-dev", true},
		{"Acme-Dev ", "acme-dev", true},
		{"a", "a", true},
		{"-acme", "", false},
		{"--config", "", false},
		{"acme-", "", false},
		{"acme dev", "", false},
		{"acme/dev", "", false},
		{"https://org.example", "", false},
		{strings.Repeat("a", 65), "", false},
	}
	for _, c := range cases {
		got, ok := normalizeTeamSlug(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("normalizeTeamSlug(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestConnectArgs(t *testing.T) {
	cases := []struct {
		config, team string
		want         []string
	}{
		{"", "", []string{"connect", "--json", "--no-browser"}},
		{"/c.toml", "", []string{"connect", "--json", "--no-browser", "--config", "/c.toml"}},
		{"/c.toml", "acme", []string{"connect", "--json", "--no-browser", "--config", "/c.toml", "acme"}},
	}
	for _, c := range cases {
		if got := connectArgs(c.config, c.team); !reflect.DeepEqual(got, c.want) {
			t.Errorf("connectArgs(%q,%q) = %v, want %v", c.config, c.team, got, c.want)
		}
	}
}

// TestDecideConnectRefusal pins connectRefusals, one case per row.
func TestDecideConnectRefusal(t *testing.T) {
	cases := []struct {
		name  string
		facts connectFacts
		want  string
	}{
		{"locked wins", connectFacts{locked: true, enrolled: true, orgName: "Acme"}, "locked"},
		{"already connected", connectFacts{enrolled: true, orgName: "Acme"}, "already_connected"},
		{"free to connect", connectFacts{}, ""},
	}
	if len(connectRefusals) != len(cases)-1 {
		t.Fatalf("%d refusal rows, %d refusing cases", len(connectRefusals), len(cases)-1)
	}
	for _, c := range cases {
		got := decideConnectRefusal(c.facts)
		name := ""
		if got != nil {
			name = got.name
			if msg := got.message(c.facts); msg == "" {
				t.Errorf("%s: empty message", c.name)
			}
		}
		if name != c.want {
			t.Errorf("%s: refusal %q, want %q", c.name, name, c.want)
		}
	}
	if msg := connectRefusals[1].message(connectFacts{enrolled: true, orgName: "Acme"}); !strings.Contains(msg, "Acme") || !strings.Contains(msg, "Settings > Account") {
		t.Errorf("already-connected message = %q", msg)
	}
}

// fakeConnectChild is a scripted `observer connect`: it prints lines, then
// waits for release (or ctx) and exits with code.
type fakeConnectChild struct {
	lines   []string
	stderr  string
	release chan struct{}
	code    int
	err     error
	args    chan []string
}

func newFakeConnectChild(lines ...string) *fakeConnectChild {
	return &fakeConnectChild{lines: lines, release: make(chan struct{}), args: make(chan []string, 4)}
}

func (c *fakeConnectChild) exec(ctx context.Context, args []string, onLine func([]byte), errOut io.Writer) (int, error) {
	c.args <- args
	for _, l := range c.lines {
		onLine([]byte(l))
	}
	if c.stderr != "" {
		_, _ = io.WriteString(errOut, c.stderr)
	}
	select {
	case <-c.release:
		return c.code, c.err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

func waitConnect(t *testing.T, f *connectFlow, what string, ok func(ConnectProgress) bool) ConnectProgress {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := f.snapshot(); ok(p) {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %+v", what, f.snapshot())
	return ConnectProgress{}
}

// TestConnectFlowLifecycle drives the one child: start, the lines, one at a
// time, and each way it ends (connected, cancel, exit with no end line).
func TestConnectFlowLifecycle(t *testing.T) {
	t.Run("connected", func(t *testing.T) {
		child := newFakeConnectChild(
			`{"state":"waiting_approval","approve_url":"https://cloud.superbased.app/connect/r1","user_code":"KTRW-4821","expires_in":900}`,
			`{"state":"approved","target":{"kind":"personal","display_name":"Personal dashboard","share_level":"summary"}}`,
			`{"state":"attaching"}`,
			`{"state":"connected","online_url":"https://u-abc.superbased.app/"}`,
		)
		f := &connectFlow{exec: child.exec}
		if p := f.snapshot(); p.State != connectStateIdle {
			t.Fatalf("before start = %+v", p)
		}
		p, started := f.start("/c.toml", "")
		if !started || !p.Running || p.State != connectStateStarting {
			t.Fatalf("start = %+v %v", p, started)
		}
		if got := <-child.args; !reflect.DeepEqual(got, []string{"connect", "--json", "--no-browser", "--config", "/c.toml"}) {
			t.Fatalf("args = %v", got)
		}
		waitConnect(t, f, "connected line", func(p ConnectProgress) bool { return p.State == connectStateConnected })
		// One child at a time: a second start returns the run in flight.
		if again, started := f.start("/c.toml", "other"); started || again.Team != "" {
			t.Fatalf("second start = %+v started=%v", again, started)
		}
		close(child.release)
		p = waitConnect(t, f, "exit", func(p ConnectProgress) bool { return !p.Running })
		if p.State != connectStateConnected || p.DisplayName != "Personal dashboard" || p.Kind != "personal" || p.OnlineURL != "https://u-abc.superbased.app/" || p.FinishedAt == "" {
			t.Fatalf("final = %+v", p)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		child := newFakeConnectChild(`{"state":"waiting_approval","user_code":"KTRW-4821"}`)
		f := &connectFlow{exec: child.exec}
		f.start("", "")
		waitConnect(t, f, "waiting", func(p ConnectProgress) bool { return p.State == connectStateWaiting })
		if _, stopped := f.stop(); !stopped {
			t.Fatal("stop reported nothing running")
		}
		p := waitConnect(t, f, "canceled", func(p ConnectProgress) bool { return !p.Running })
		if p.State != connectStateCanceled {
			t.Fatalf("final = %+v", p)
		}
		if _, stopped := f.stop(); stopped {
			t.Fatal("a second stop must find nothing running")
		}
	})
	t.Run("exit without an end line is an error with the stderr tail", func(t *testing.T) {
		child := newFakeConnectChild(`{"state":"waiting_approval"}`)
		child.stderr = "noise\nobserver connect: cannot reach cloud.superbased.app\n"
		child.code = 1
		f := &connectFlow{exec: child.exec}
		f.start("", "")
		close(child.release)
		p := waitConnect(t, f, "exit", func(p ConnectProgress) bool { return !p.Running })
		if p.State != connectStateError || p.Code != "exited" || p.Message != "observer connect: cannot reach cloud.superbased.app" {
			t.Fatalf("final = %+v", p)
		}
	})
	t.Run("exit error without output", func(t *testing.T) {
		child := newFakeConnectChild()
		child.err = errors.New("locate observer binary: gone")
		f := &connectFlow{exec: child.exec}
		f.start("", "")
		close(child.release)
		p := waitConnect(t, f, "exit", func(p ConnectProgress) bool { return !p.Running })
		if p.State != connectStateError || !strings.Contains(p.Message, "gone") {
			t.Fatalf("final = %+v", p)
		}
	})
	t.Run("expiry", func(t *testing.T) {
		child := newFakeConnectChild(`{"state":"waiting_approval"}`)
		f := &connectFlow{exec: child.exec}
		f.start("", "")
		waitConnect(t, f, "waiting", func(p ConnectProgress) bool { return p.State == connectStateWaiting })
		f.mu.Lock()
		run := f.run
		f.mu.Unlock()
		f.expire(run)
		p := waitConnect(t, f, "expired", func(p ConnectProgress) bool { return !p.Running })
		if p.State != connectStateExpired {
			t.Fatalf("final = %+v", p)
		}
	})
}

// TestConnectExitRulesOrder pins connectExitRules' order: the child's own
// end line wins over a cancel, a cancel over an expiry.
func TestConnectExitRulesOrder(t *testing.T) {
	want := []string{"child_reported_end", "canceled", "expired", "exited_without_end"}
	var got []string
	for _, r := range connectExitRules {
		got = append(got, r.name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
}

func connectPost(t *testing.T, srv *Server, path, body string, armed bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if armed {
		req = armLocalWrite(req)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	return rr
}

// TestConnectRoutes pins the three routes: the confirm token, the slug
// check, the refusals (nothing spawned), a start, progress and cancel.
func TestConnectRoutes(t *testing.T) {
	newSrv := func(t *testing.T, child *fakeConnectChild) *Server {
		t.Helper()
		srv, _ := newCloudTestServer(t)
		srv.connectFlow.exec = child.exec
		return srv
	}
	t.Run("start needs the confirm token", func(t *testing.T) {
		child := newFakeConnectChild()
		srv := newSrv(t, child)
		if rr := connectPost(t, srv, "/api/connect/start", `{}`, false); rr.Code != http.StatusForbidden {
			t.Fatalf("unarmed start = %d", rr.Code)
		}
		if len(child.args) != 0 {
			t.Fatal("spawned without a confirm token")
		}
	})
	t.Run("bad team", func(t *testing.T) {
		child := newFakeConnectChild()
		srv := newSrv(t, child)
		rr := connectPost(t, srv, "/api/connect/start", `{"team":"--config"}`, true)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bad_team") {
			t.Fatalf("bad team = %d %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("already connected refuses without spawning", func(t *testing.T) {
		child := newFakeConnectChild()
		srv := newSrv(t, child)
		srv.opts.OrgClient = &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: true, OrgName: "Acme"}}
		rr := connectPost(t, srv, "/api/connect/start", `{}`, true)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "already_connected") {
			t.Fatalf("enrolled start = %d %s", rr.Code, rr.Body.String())
		}
		if len(child.args) != 0 {
			t.Fatal("spawned on a connected machine")
		}
	})
	t.Run("locked refuses without spawning", func(t *testing.T) {
		child := newFakeConnectChild()
		srv := newSrv(t, child)
		srv.opts.ConnectStatus = func(context.Context, frontdoor.Identity) frontdoor.Status {
			return frontdoor.Status{Locked: true}
		}
		rr := connectPost(t, srv, "/api/connect/start", `{}`, true)
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), `"locked"`) {
			t.Fatalf("locked start = %d %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("start, progress, cancel", func(t *testing.T) {
		child := newFakeConnectChild(`{"state":"waiting_approval","approve_url":"https://cloud.superbased.app/connect/r1","user_code":"KTRW-4821"}`)
		srv := newSrv(t, child)
		rr := connectPost(t, srv, "/api/connect/start", `{"team":"Acme-Dev"}`, true)
		if rr.Code != http.StatusOK {
			t.Fatalf("start = %d %s", rr.Code, rr.Body.String())
		}
		if args := <-child.args; args[len(args)-1] != "acme-dev" {
			t.Fatalf("args = %v", args)
		}
		waitConnect(t, &srv.connectFlow, "waiting", func(p ConnectProgress) bool { return p.State == connectStateWaiting })
		prr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(prr, httptest.NewRequest(http.MethodGet, "/api/connect/progress", nil))
		var p ConnectProgress
		if err := json.Unmarshal(prr.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if p.State != connectStateWaiting || p.UserCode != "KTRW-4821" || p.Team != "acme-dev" || !p.Running {
			t.Fatalf("progress = %+v", p)
		}
		if rr := connectPost(t, srv, "/api/connect/cancel", `{}`, false); rr.Code != http.StatusForbidden {
			t.Fatalf("unarmed cancel = %d", rr.Code)
		}
		if rr := connectPost(t, srv, "/api/connect/cancel", `{}`, true); rr.Code != http.StatusOK {
			t.Fatalf("cancel = %d", rr.Code)
		}
		waitConnect(t, &srv.connectFlow, "canceled", func(p ConnectProgress) bool { return p.State == connectStateCanceled })
	})
	t.Run("progress is GET only", func(t *testing.T) {
		srv := newSrv(t, newFakeConnectChild())
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/connect/progress", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST progress = %d", rr.Code)
		}
	})
}
