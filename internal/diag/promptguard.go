package diag

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// checkPromptGuardWiring surfaces the prompt-submit intervention hook
// lane's on/off state (docs/guard-prompt.md, Part B of
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md):
// whether the developer's own prompts are being scanned for secrets/
// PII before they reach the model, and which knob is responsible when
// they aren't.
//
// Deliberately config-only: diag does not import internal/guard or
// internal/hook (the same boundary discipline internal/obs's wiring
// keeps out of diag). The reconsider-once persistence seam
// (guard.SetPromptReconsiderStore) is unconditionally wired at
// hook-construction time (cmd/observer/hook.go::buildHookGuard) — a
// contract item this build closed (previously the zero value, which
// fails every ask-once/redact finding closed to a hard block) — so
// there is nothing store-side left to probe from a config-only check.
func checkPromptGuardWiring(cfg config.Config) Check {
	const name = "guard.prompt"
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" {
		return Check{Name: name, Status: StatusOK, Message: "off ([guard] disabled or mode=off)"}
	}
	if !cfg.Guard.Prompt.Enabled {
		return Check{
			Name: name, Status: StatusWarn,
			Message: "prompt-submit intervention disabled ([guard.prompt].enabled = false) — secrets/PII typed into a prompt are forwarded unexamined",
		}
	}
	if !cfg.Guard.Prompt.HookLane {
		return Check{
			Name: name, Status: StatusWarn,
			Message: "hook lane disabled ([guard.prompt].hook_lane = false) — prompt-submit hooks are registered but do not evaluate; only the proxy lane (if enabled) sees the prompt",
		}
	}
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("hook lane active, mode=%s", cfg.Guard.Prompt.Mode)}
}
