package diag

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestHookTrustFor: only a mechanism with a host-side trust step is
// applicable; the Codex reader returns the per-event state the
// codex.hook_trust check is built from.
func TestHookTrustFor(t *testing.T) {
	home := t.TempDir()
	if tr := HookTrustFor(integration.HookClaudeSettings, home); tr.Applicable {
		t.Errorf("claude settings has no trust step: %+v", tr)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	hooks := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/bin/observer hook codex PreToolUse"}]}],` +
		`"Stop":[{"hooks":[{"type":"command","command":"/bin/observer hook codex Stop"}]}]}}`
	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(hooks), 0o600); err != nil {
		t.Fatal(err)
	}
	// strconv.Quote keeps a Windows temp path (backslashes) a valid TOML
	// quoted key; a POSIX path quotes to the same bytes as before.
	cfg := "[hooks.state." + strconv.Quote(hooksPath+":pre_tool_use:0:0") + "]\ntrusted_hash = \"h\"\n"
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := HookTrustFor(integration.HookCodexConfig, home)
	if !tr.Applicable || tr.Err != "" || !tr.Trusted["PreToolUse"] || tr.Trusted["Stop"] || len(tr.Registered) != 2 || tr.Remedy == "" {
		t.Errorf("codex trust = %+v", tr)
	}
}
