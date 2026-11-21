package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_config_openshell_test.go pins the Settings card's save
// path for the keys lanes N2 (seccomp) and O1A/O2 (the openshell block)
// added (lane O4): a client that sends neither keeps the saved values, and
// one that sends them writes them through the one config validation.

// writeSandboxTOML appends a [terminal.sandbox] block to the server's config.
func writeSandboxTOML(t *testing.T, s *Server, block string) {
	t.Helper()
	f, err := os.OpenFile(s.opts.ConfigPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(block); err != nil {
		t.Fatal(err)
	}
}

func loadSandbox(t *testing.T, s *Server) config.TerminalSandboxConfig {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Terminal.Sandbox
}

// TestTerminalSandboxConfigPutKeepsUnsentBlocks: a save from a client that
// does not send seccomp or the openshell block (every older dashboard)
// keeps both, so a Settings save never resets them.
func TestTerminalSandboxConfigPutKeepsUnsentBlocks(t *testing.T) {
	s, h := newManageServer(t)
	writeSandboxTOML(t, s, "\n[terminal.sandbox]\nseccomp = true\n\n[terminal.sandbox.openshell]\ngateway_mode = \"external\"\nendpoint = \"https://127.0.0.1:17670\"\nversion = \"0.1.6\"\n")
	code, out := putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	got := loadSandbox(t, s)
	if !got.Seccomp {
		t.Fatal("a save that did not send seccomp reset it")
	}
	if got.OpenShell.GatewayMode != "external" || got.OpenShell.Endpoint != "https://127.0.0.1:17670" || got.OpenShell.Version != "0.1.6" {
		t.Fatalf("a save that did not send the openshell block reset it: %+v", got.OpenShell)
	}
}

// TestTerminalSandboxConfigOpenShellRoundTrip: the GET serves the block and
// seccomp, and a PUT that sends them writes them.
func TestTerminalSandboxConfigOpenShellRoundTrip(t *testing.T) {
	s, h := newManageServer(t)
	code, out := putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,
		"seccomp":true,"openshell":{"gateway_mode":"external","endpoint":"https://localhost:17670","version":"0.1.6","state_dir":"/var/lib/observer-openshell"}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	got := loadSandbox(t, s)
	if !got.Seccomp || got.OpenShell.GatewayMode != "external" || got.OpenShell.Endpoint != "https://localhost:17670" || got.OpenShell.StateDir != "/var/lib/observer-openshell" {
		t.Fatalf("persisted = seccomp %v openshell %+v", got.Seccomp, got.OpenShell)
	}
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
	if get.Sandbox.Seccomp == nil || !*get.Sandbox.Seccomp || get.Sandbox.OpenShell == nil || get.Sandbox.OpenShell.GatewayMode != "external" {
		t.Fatalf("GET = %+v", get.Sandbox)
	}
}

// TestTerminalSandboxConfigOpenShellRefusesBadValues: the one config
// validation refuses a managed mode with an endpoint and a remote gateway.
func TestTerminalSandboxConfigOpenShellRefusesBadValues(t *testing.T) {
	_, h := newManageServer(t)
	for _, tc := range []struct{ name, block string }{
		{"managed with an endpoint", `{"gateway_mode":"managed","endpoint":"https://127.0.0.1:17670"}`},
		{"remote endpoint", `{"gateway_mode":"external","endpoint":"https://gw.example.com"}`},
		{"unknown mode", `{"gateway_mode":"shared"}`},
		{"relative state dir", `{"state_dir":"relative/dir"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"openshell":` + tc.block + `}`
			code, out := putSandboxConfig(t, h, body)
			if code != http.StatusBadRequest {
				t.Fatalf("PUT = %d, want 400: %v", code, out)
			}
		})
	}
}
