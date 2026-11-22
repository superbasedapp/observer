package hook

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestToolGatePatchRenameOntoStartupFile pins FR-SEC-11 (review
// 2026-11-22) end to end: a Codex apply_patch that renames a scratch file
// onto a startup file the guard reads for OBSERVER_GUARD_ overrides, and
// that R-154 does not deny by path (~/.pam_environment,
// ~/.config/environment.d), reaches R-165's file row through the shared
// tool gate and is denied, as writing the same override directly is.
func TestToolGatePatchRenameOntoStartupFile(t *testing.T) {
	proj := t.TempDir()
	home := t.TempDir()
	cfg := config.Default().Guard
	cfg.Enabled, cfg.Mode = true, "enforce"
	cfg.Rules.UserPolicy = ""
	cfg.Rules.OrgBundle = filepath.Join(proj, "no-org-bundle.json")
	g, err := guard.New(guard.Options{Config: cfg, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{
		filepath.Join(home, ".pam_environment"),
		filepath.Join(home, ".config", "environment.d", "x.conf"),
	} {
		t.Run(filepath.Base(dst), func(t *testing.T) {
			patch := "*** Begin Patch\n*** Update File: notes.txt\n*** Move to: " + dst + "\n*** End Patch\n"
			rec := &recordingEvaluator{inner: g}
			HandleToolGate(ToolGateRequest{
				Tool: models.ToolCodex, Dialect: ToolGateDialectClaudeJSON, NativeEvent: "PreToolUse", Label: "codex:PreToolUse",
				Body: toolPayload("s1", "apply_patch", map[string]any{"command": patch}),
			}, rec, nil, &bytes.Buffer{}, &bytes.Buffer{})
			v, ok := rec.byTarget[dst]
			if !ok {
				t.Fatalf("no event for the destination %s; saw %v", dst, rec.byTarget)
			}
			if v.RuleID != "R-165" || v.Decision != policy.DecisionDeny {
				t.Fatalf("destination verdict = %s/%s (%q), want R-165/deny", v.RuleID, v.Decision, v.Reason)
			}
		})
	}
}
