package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// signInFakeValue is a FAKE sign-in value; no response may carry it.
const signInFakeValue = "sbo-fake-signin-value-7f3c"

// signInLaunchManager answers the first sandboxed launch with the consent
// question and records the retried launch's answer.
type signInLaunchManager struct {
	*fakeLaunchManager
	asked bool
}

func (m *signInLaunchManager) CreateFresh(spec FreshLaunchSpec) (string, error) {
	if spec.SignInSeed == nil {
		m.asked = spec.SignInAsk
		return "", &termcore.SignInConsentError{
			Tool:  "claude-code",
			Files: []string{".claude/.credentials.json"},
			Text:  "Copy claude-code's sign-in into this sandbox for this run? File copied: ~/.claude/.credentials.json.",
		}
	}
	return m.fakeLaunchManager.CreateFresh(spec)
}

// TestTerminalLaunchSignInConsentIs409 (lane BOXSIGNIN audit finding 7):
// the launch route answers the sign-in question as 409 sign_in_consent
// naming the tool and the file, never a value, and the retried launch
// carries the answer to the launch service.
func TestTerminalLaunchSignInConsentIs409(t *testing.T) {
	lm := &signInLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	s := newLaunchTestServerWithSandbox(t, lm, &fakeSandboxProber{avail: availableProbe()})
	req := terminalLaunchRequest{Tool: "claude-code", Sandbox: true, WorkspaceSource: "clone-remote", WorkspaceRemote: "https://example.com/repo.git", SignInAsk: true}
	rec := postTerminalLaunchSandbox(t, s.Handler(), req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 (body %s)", rec.Code, rec.Body)
	}
	var got signInConsentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != "sign_in_consent" || got.Tool != "claude-code" || len(got.Files) != 1 || got.Files[0] != ".claude/.credentials.json" || !strings.Contains(got.Text, "~/.claude/.credentials.json") {
		t.Fatalf("body %+v", got)
	}
	if !lm.asked {
		t.Fatal("sign_in_ask did not reach the launch service")
	}
	if strings.Contains(rec.Body.String(), signInFakeValue) {
		t.Fatal("the 409 body carries the value")
	}
	yes := true
	req.SignInSeed, req.SignInAsk = &yes, false
	if rec := postTerminalLaunchSandbox(t, s.Handler(), req); rec.Code != http.StatusOK {
		t.Fatalf("the answered launch: %d %s", rec.Code, rec.Body)
	}
	if lm.lastFreshSpec.SignInSeed == nil || !*lm.lastFreshSpec.SignInSeed {
		t.Fatalf("the answer did not reach the launch service: %+v", lm.lastFreshSpec)
	}
}

// TestTerminalSandboxConfigShowsTheComposedForbid (audit finding 3): the
// Settings card's org forbid comes from the composed managed view
// (Options.SandboxSignInForbidden), not from the file.
func TestTerminalSandboxConfigShowsTheComposedForbid(t *testing.T) {
	for _, forbid := range []bool{false, true} {
		var opts Options
		if forbid {
			opts.SandboxSignInForbidden = func() bool { return true }
		}
		h := newManageServerOpts(t, opts).Handler()
		req := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/config", nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", rec.Code, rec.Body)
		}
		var got struct {
			Sandbox struct {
				SignInSeedForbidden bool `json:"sign_in_seed_forbidden"`
			} `json:"sandbox"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Sandbox.SignInSeedForbidden != forbid {
			t.Fatalf("forbid %v: the card reads %v", forbid, got.Sandbox.SignInSeedForbidden)
		}
	}
}
