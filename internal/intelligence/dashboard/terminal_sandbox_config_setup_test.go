package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// terminal_sandbox_config_setup_test.go pins the Settings card's save path
// for [terminal.sandbox.setup] (P-254): a save without a setup field keeps
// the saved allow_elevated, and one that sends setup writes it.

// TestTerminalSandboxConfigPutSetup is one case per row.
func TestTerminalSandboxConfigPutSetup(t *testing.T) {
	const base = `"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300`
	cases := []struct {
		name string
		body string
		want bool
	}{
		{name: "a save without setup keeps allow_elevated", body: `{` + base + `}`, want: true},
		{name: "a save with setup.allow_elevated false turns it off", body: `{` + base + `,"setup":{"allow_elevated":false}}`, want: false},
		{name: "a save with setup.allow_elevated true keeps it on", body: `{` + base + `,"setup":{"allow_elevated":true}}`, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, h := newManageServer(t)
			writeSandboxTOML(t, s, "\n[terminal.sandbox.setup]\nallow_elevated = true\n")
			if !loadSandbox(t, s).Setup.AllowElevated {
				t.Fatal("fixture: allow_elevated is not true before the save")
			}
			code, out := putSandboxConfig(t, h, tc.body)
			if code != http.StatusOK {
				t.Fatalf("PUT = %d: %v", code, out)
			}
			if got := loadSandbox(t, s).Setup.AllowElevated; got != tc.want {
				t.Fatalf("allow_elevated after the save = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTerminalSandboxConfigGetServesSetup: the GET carries the setup block
// the card edits.
func TestTerminalSandboxConfigGetServesSetup(t *testing.T) {
	s, h := newManageServer(t)
	writeSandboxTOML(t, s, "\n[terminal.sandbox.setup]\nallow_elevated = true\n")
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/config", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var get struct {
		Sandbox terminalSandboxConfigPayload `json:"sandbox"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &get); err != nil {
		t.Fatal(err)
	}
	if get.Sandbox.Setup == nil || !get.Sandbox.Setup.AllowElevated {
		t.Fatalf("GET setup = %+v", get.Sandbox.Setup)
	}
}
