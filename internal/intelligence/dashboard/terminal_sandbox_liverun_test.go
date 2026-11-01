package dashboard

import (
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestTerminalSandboxConfigLiveRunPolicyRoundTrip pins the Card row of
// live_run_update_policy (lane SBX-UPD): the GET reports "defer" for the
// default, an explicit PUT persists ask_immediately, a PUT from a client
// that predates the field keeps the saved value, and an unknown value is
// refused.
func TestTerminalSandboxConfigLiveRunPolicyRoundTrip(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox
	}
	if p := sandboxConfigPayload(config.Default().Terminal.Sandbox); p.LiveRunUpdatePolicy == nil || *p.LiveRunUpdatePolicy != "defer" {
		t.Fatalf("default payload policy = %v, want defer", p.LiveRunUpdatePolicy)
	}
	code, out := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"live_run_update_policy":"ask_immediately"}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load(); got.LiveRunUpdatePolicy != "ask_immediately" {
		t.Fatalf("explicit PUT persisted %q", got.LiveRunUpdatePolicy)
	}
	code, out = putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load(); got.LiveRunUpdatePolicy != "ask_immediately" {
		t.Fatalf("a PUT omitting the field reset it: %q", got.LiveRunUpdatePolicy)
	}
	if code, _ := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"live_run_update_policy":"end_now"}`); code == http.StatusOK {
		t.Fatal("an unknown policy was saved")
	}
}

// TestTerminalSandboxConfigKeepsTheE2BEndpoint (lane SBX-UPD): a save from
// a client that predates the hosted endpoint keys keeps the saved values,
// and an explicit one sets them.
func TestTerminalSandboxConfigKeepsTheE2BEndpoint(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxHostedProviderConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox.Hosted.E2B
	}
	hosted := `"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,`
	code, out := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,`+hosted+`"e2b":{"region":"","template":"","box_binary":"","endpoint":"https://eu.api.e2b.app"},"modal":{"region":"","template":"","box_binary":""},"vercel":{"region":"","template":"","box_binary":""}}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load(); got.Endpoint != "https://eu.api.e2b.app" {
		t.Fatalf("explicit endpoint = %q", got.Endpoint)
	}
	code, out = putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,`+hosted+`"e2b":{"region":"","template":"","box_binary":""},"modal":{"region":"","template":"","box_binary":""},"vercel":{"region":"","template":"","box_binary":""}}}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load(); got.Endpoint != "https://eu.api.e2b.app" {
		t.Fatalf("a save omitting the endpoint reset it: %q", got.Endpoint)
	}
}
