//go:build !sbo_omit_remote

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// launch_sandbox_readopt_test.go pins POST /api/terminal/sandbox/readopt/attach
// (dashboard CLI parity plan item B-G3, decision P-3): the route opens a
// dashboard terminal running the fixed `observer sandbox readopt <run>`, and
// only after the confirm token, the piece's presence, the terminal stack, the
// run id's shape and the piece's own offer check.

// postReadoptAttach issues the route's POST; confirm false sends no token.
func postReadoptAttach(t *testing.T, h http.Handler, body string, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox/readopt/attach", bytes.NewReader([]byte(body)))
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

// withReadoptCheck installs check for the test and restores the previous one.
func withReadoptCheck(t *testing.T, check func(context.Context, string) error) {
	t.Helper()
	prev := sandboxReadoptCheck.Load()
	SetSandboxReadoptCheck(check)
	t.Cleanup(func() { sandboxReadoptCheck.Store(prev) })
}

func TestSandboxReadoptTerminalGates(t *testing.T) {
	const run = "run0000000000000301"
	offered := func(_ context.Context, r string) error {
		if r != run {
			return errors.New("run " + r + " is not offered for re-adoption")
		}
		return nil
	}
	cases := []struct {
		name       string
		check      func(context.Context, string) error
		lm         LaunchManager
		body       string
		confirm    bool
		wantStatus int
		wantText   string
	}{
		{"no confirm token", offered, &fakeLaunchManager{}, `{"run":"` + run + `"}`, false, http.StatusForbidden, ""},
		{"piece not in this build", nil, &fakeLaunchManager{}, `{"run":"` + run + `"}`, true, http.StatusNotFound, "not in this build"},
		{"terminal stack off", offered, nil, `{"run":"` + run + `"}`, true, http.StatusServiceUnavailable, "Settings > Session attach"},
		{"malformed run id", offered, &fakeLaunchManager{}, `{"run":"../x; rm -rf /"}`, true, http.StatusBadRequest, "run id"},
		{"run not offered", offered, &fakeLaunchManager{}, `{"run":"run0000000000000399"}`, true, http.StatusConflict, "not offered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withReadoptCheck(t, tc.check)
			h := newInstallServer(t, tc.lm, nil, nil)
			rec := postReadoptAttach(t, h, tc.body, tc.confirm)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantText != "" && !strings.Contains(decodeErrBody(t, rec), tc.wantText) {
				t.Fatalf("error does not say %q: %s", tc.wantText, rec.Body.String())
			}
		})
	}
}

func TestSandboxReadoptTerminalSpawnsTheFixedCommand(t *testing.T) {
	const run = "run0000000000000301"
	withReadoptCheck(t, func(context.Context, string) error { return nil })
	prevExe := osExecutable
	osExecutable = func() (string, error) { return "/opt/observer/bin/observer", nil }
	t.Cleanup(func() { osExecutable = prevExe })
	lm := &fakeLaunchManager{}
	h := newInstallServer(t, lm, nil, nil)
	rec := postReadoptAttach(t, h, `{"run":"`+run+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	want := []string{"/opt/observer/bin/observer", "sandbox", "readopt", run}
	if !reflect.DeepEqual(lm.lastSetupSpec.Argv, want) {
		t.Fatalf("argv = %q, want %q", lm.lastSetupSpec.Argv, want)
	}
	if lm.lastSetupSpec.Label != "sandbox-readopt:"+run {
		t.Fatalf("label = %q", lm.lastSetupSpec.Label)
	}
	var out struct {
		Handle  string `json:"handle"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Handle != "SETUP-abc" || out.Command != "observer sandbox readopt "+run {
		t.Fatalf("response = %s (%v)", rec.Body.String(), err)
	}
}

// TestGuidedInstallOffNamesTheControl: the install route's 403 names the
// dashboard checkbox first and keeps the config key (plan section 3).
func TestGuidedInstallOffNamesTheControl(t *testing.T) {
	for _, want := range []string{"Allow guided install and uninstall", "Terminals > Settings", "[terminal.launch].allow_install"} {
		if !strings.Contains(errGuidedInstallOff, want) {
			t.Errorf("guided install refusal does not name %q: %s", want, errGuidedInstallOff)
		}
	}
	for _, want := range []string{"Settings > Session attach", "[handoff].allow_dashboard_launch"} {
		if !strings.Contains(errTerminalUnavailable, want) {
			t.Errorf("terminal refusal does not name %q: %s", want, errTerminalUnavailable)
		}
	}
}
