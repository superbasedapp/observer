package dashboard

import (
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestTerminalSandboxConfigCopiesKeysRoundTrip pins the two keys of lane
// COPIES on the Settings save: the GET reports the defaults (30 days,
// baseline), an explicit PUT persists them, a PUT that omits them keeps the
// saved values, and a bad value is a 400.
func TestTerminalSandboxConfigCopiesKeysRoundTrip(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox
	}
	base := `"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300`
	code, out := putSandboxConfig(t, h, `{`+base+`}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	sb, _ := out["sandbox"].(map[string]any)
	hosted, _ := sb["hosted"].(map[string]any)
	if sb["returned_copy_retention_days"] != float64(30) || hosted["diff_against"] != "baseline" {
		t.Fatalf("defaults in the response: %v / %v", sb["returned_copy_retention_days"], hosted["diff_against"])
	}

	code, out = putSandboxConfig(t, h, `{`+base+`,"returned_copy_retention_days":0,"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,"e2b":{},"modal":{},"vercel":{},"diff_against":"head"}}`)
	if code != http.StatusOK {
		t.Fatalf("explicit PUT = %d: %v", code, out)
	}
	if got := load(); got.ReturnedCopyRetentionDays != 0 || got.Hosted.DiffAgainst != config.HostedDiffAgainstHead {
		t.Fatalf("explicit PUT persisted %d / %q", got.ReturnedCopyRetentionDays, got.Hosted.DiffAgainst)
	}

	// A client that predates the keys keeps them.
	code, out = putSandboxConfig(t, h, `{`+base+`,"enabled":true,"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,"e2b":{},"modal":{},"vercel":{}}}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load(); got.ReturnedCopyRetentionDays != 0 || got.Hosted.DiffAgainst != config.HostedDiffAgainstHead || !got.Enabled {
		t.Fatalf("a PUT omitting the keys reset them: %d / %q", got.ReturnedCopyRetentionDays, got.Hosted.DiffAgainst)
	}

	for _, bad := range []string{
		`{` + base + `,"returned_copy_retention_days":-1}`,
		`{` + base + `,"returned_copy_retention_days":3651}`,
		`{` + base + `,"hosted":{"min_session_minutes":30,"key_custody":"home_relay","memory_images":"avoid","checkpoint_minutes":5,"max_run_minutes":60,"daily_box_minutes":240,"e2b":{},"modal":{},"vercel":{},"diff_against":"tip"}}`,
	} {
		if code, out := putSandboxConfig(t, h, bad); code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d: %v", bad, code, out)
		}
	}
}
