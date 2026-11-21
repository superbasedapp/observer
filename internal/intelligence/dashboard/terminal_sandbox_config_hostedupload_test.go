package dashboard

import (
	"net/http"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestTerminalSandboxConfigHostedUpload (decision SBXD-8): the Hosted
// sandboxes panel reads and saves upload_non_git and upload_ignore; a save
// from a client that predates them keeps the saved values; a bad pattern is
// refused by the one config validation.
func TestTerminalSandboxConfigHostedUpload(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxHostedConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox.Hosted
	}
	if p := sandboxConfigPayload(config.Default().Terminal.Sandbox); p.Hosted == nil || p.Hosted.UploadNonGit == nil || !*p.Hosted.UploadNonGit || p.Hosted.UploadIgnore == nil {
		t.Fatalf("default payload %+v", p.Hosted)
	}
	hosted := `"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,"e2b":{"region":"","template":"","box_binary":""},"modal":{"region":"","template":"","box_binary":""},"vercel":{"region":"","template":"","box_binary":""}`
	base := `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,`
	code, out := putSandboxConfig(t, h, base+hosted+`,"upload_non_git":false,"upload_ignore":["*.log"," data/raw/ ",""]}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load(); got.UploadNonGit || !slices.Equal(got.UploadIgnore, []string{"*.log", "data/raw/"}) {
		t.Fatalf("explicit PUT persisted %v %q", got.UploadNonGit, got.UploadIgnore)
	}
	code, out = putSandboxConfig(t, h, base+hosted+`}}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load(); got.UploadNonGit || !slices.Equal(got.UploadIgnore, []string{"*.log", "data/raw/"}) {
		t.Fatalf("a save omitting the keys reset them: %v %q", got.UploadNonGit, got.UploadIgnore)
	}
	if code, _ := putSandboxConfig(t, h, base+hosted+`,"upload_ignore":["# a comment"]}}`); code == http.StatusOK {
		t.Fatal("a comment pattern was saved")
	}
}
