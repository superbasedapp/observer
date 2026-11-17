package dashboard

import (
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestTerminalSandboxConfigKeepsTheInstaBoxTable: a save carrying the
// InstaBox table sets it, and a save from a client that predates the row
// (no instabox key) keeps the saved table rather than emptying it.
func TestTerminalSandboxConfigKeepsTheInstaBoxTable(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxHostedProviderConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox.Hosted.InstaBox
	}
	hosted := `"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,` +
		`"e2b":{"region":"","template":"","box_binary":""},"modal":{"region":"","template":"","box_binary":""},"vercel":{"region":"","template":"","box_binary":""}`
	code, out := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,`+hosted+`,"instabox":{"region":"","template":" ci ","box_binary":""}}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load(); got.Template != "ci" {
		t.Fatalf("explicit template = %q", got.Template)
	}
	code, out = putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,`+hosted+`}}`)
	if code != http.StatusOK {
		t.Fatalf("older-client PUT = %d: %v", code, out)
	}
	if got := load(); got.Template != "ci" {
		t.Fatalf("a save omitting the table reset it: %q", got.Template)
	}
}
