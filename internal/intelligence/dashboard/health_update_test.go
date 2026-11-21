package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubRunningUpdatePlan stands a plan in for the running executable's.
func stubRunningUpdatePlan(t *testing.T, p updateTerminalPlan) {
	t.Helper()
	prev := runningUpdatePlan
	runningUpdatePlan = func() updateTerminalPlan { return p }
	t.Cleanup(func() { runningUpdatePlan = prev })
}

// updateTerminalRequest sends one request to /api/health/update-terminal on
// the loopback host, with the confirm token when confirm is true.
func updateTerminalRequest(t *testing.T, h http.Handler, method string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/health/update-terminal", strings.NewReader("{}"))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	if confirm {
		ck, tok := getConfirm(t, h)
		req.AddCookie(ck)
		req.Header.Set(remoteConfirmHeader, tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestHandleHealthUpdateTerminal walks the route's outcomes: GET shows the
// plan without its argv, POST needs the confirm token, refuses an
// unavailable plan with its reason, says so when the daemon has no
// terminals, and otherwise spawns exactly the plan's fixed argv.
func TestHandleHealthUpdateTerminal(t *testing.T) {
	npmPlan := updateTerminalPlan{
		Available: true, Method: "npm",
		Command: "npm i -g @superbased/observer@latest",
		argv:    []string{"npm", "i", "-g", "@superbased/observer@latest"},
	}
	refused := updateTerminalPlan{Method: "brew", Reason: "Update it with: brew upgrade superbased-observer."}

	t.Run("GET returns the plan", func(t *testing.T) {
		stubRunningUpdatePlan(t, npmPlan)
		rec := updateTerminalRequest(t, newManageServerWithLaunch(t, &fakeLaunchManager{}), http.MethodGet, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got["available"] != true || got["command"] != npmPlan.Command || got["method"] != "npm" {
			t.Fatalf("GET body = %v", got)
		}
		if _, leaked := got["argv"]; leaked {
			t.Errorf("GET must not carry the argv field: %v", got)
		}
	})

	t.Run("POST without the confirm token is refused", func(t *testing.T) {
		stubRunningUpdatePlan(t, npmPlan)
		lm := &fakeLaunchManager{}
		rec := updateTerminalRequest(t, newManageServerWithLaunch(t, lm), http.MethodPost, false)
		if rec.Code == http.StatusOK {
			t.Fatalf("POST without confirm = 200: %s", rec.Body.String())
		}
		if lm.lastSetupSpec.Argv != nil {
			t.Fatalf("spawned without confirm: %v", lm.lastSetupSpec.Argv)
		}
	})

	t.Run("POST on an unavailable plan is 409 with its reason", func(t *testing.T) {
		stubRunningUpdatePlan(t, refused)
		lm := &fakeLaunchManager{}
		rec := updateTerminalRequest(t, newManageServerWithLaunch(t, lm), http.MethodPost, true)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "brew upgrade") {
			t.Fatalf("POST refused plan = %d %s, want 409 with the reason", rec.Code, rec.Body.String())
		}
		if lm.lastSetupSpec.Argv != nil {
			t.Fatalf("spawned an unavailable plan: %v", lm.lastSetupSpec.Argv)
		}
	})

	t.Run("POST with no terminal manager is 503", func(t *testing.T) {
		stubRunningUpdatePlan(t, npmPlan)
		rec := updateTerminalRequest(t, newManageServerOpts(t, Options{}).Handler(), http.MethodPost, true)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("POST without terminals = %d %s, want 503", rec.Code, rec.Body.String())
		}
	})

	t.Run("POST spawns the fixed argv", func(t *testing.T) {
		stubRunningUpdatePlan(t, npmPlan)
		lm := &fakeLaunchManager{}
		rec := updateTerminalRequest(t, newManageServerWithLaunch(t, lm), http.MethodPost, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
		}
		if strings.Join(lm.lastSetupSpec.Argv, " ") != npmPlan.Command || lm.lastSetupSpec.Label != "update" {
			t.Fatalf("spawned %q label %q", lm.lastSetupSpec.Argv, lm.lastSetupSpec.Label)
		}
		var got struct {
			Handle  string `json:"handle"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Handle != "SETUP-abc" || got.Command != npmPlan.Command {
			t.Fatalf("POST body = %s (%v)", rec.Body.String(), err)
		}
	})

	t.Run("other methods are 405", func(t *testing.T) {
		stubRunningUpdatePlan(t, npmPlan)
		rec := updateTerminalRequest(t, newManageServerWithLaunch(t, &fakeLaunchManager{}), http.MethodDelete, false)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("DELETE = %d, want 405", rec.Code)
		}
	})
}
