package hook

import (
	"bytes"
	"encoding/json"
)

// --- Cortex Code (surface-gap W-2a) --------------------------------------

// Cortex Code merges its own global hooks file, ~/.snowflake/cortex/
// hooks.json ({"hooks": {...}}, the settings shape; CORTEX_HOME and
// SNOWFLAKE_HOME relocate it, the cortex-code/user-hooks artifact), with
// Claude Code's ~/.claude/settings.json hooks. Until this writer Cortex was
// gated only through Observer's Claude Code registration, which exists only
// when ~/.claude does and Observer's Claude Code plugin is not active
// (review W-2). This writer gives the Cortex Code CLI its own entries.
//
// The entries run the cortex-code receiver (`observer hook cortex-code
// <event>`, FU-141), not Observer's Claude Code command. Cortex merges this
// file with ~/.claude/settings.json and runs both, so with Observer's Claude
// Code hooks there too one call reaches Observer twice. Were both entries
// the same claude-code command, the receiver could not tell them apart:
// either both are judged (a double evaluation) or both stand down (no
// judgement). With its own command the entry from this file is the call
// Observer judges, as cortex-code, and the replay of the same call through
// the Claude settings answers neutral while this registration holds the
// gate (foreignhost.go, the copilot-cli G2 rule). Whether Cortex runs this
// file at all, and whether the Desktop sidecar and the VS Code ACP path
// do, is live check LC18 (the Cortex Code IDE runs neither file,
// 2026-10-26, so the IDE stays recorded as ungated, W-7). The writer is
// built switched off behind that check (integration.HookSpec.LiveGate,
// DEC-12), and the replay keeps judging until it switches on
// (OwnGateRegistered answers false for a gated writer).
//
// The file is a dedicated hooks file (connections.toml holds the Snowflake
// credentials), so it is not under the credential-file exception. Only the
// CLI's user-level file is written; the project .cortex/ files and
// ~/.cortex/settings.json are never touched.

// cortexHookTimeoutSeconds is the timeout Observer registers.
const cortexHookTimeoutSeconds = 30

// The Cortex row joins the hook dispatch table here rather than in
// register_core.go (another lane owns that file in this batch); fold it into
// the table when the lanes merge.
func init() {
	hookTargetWriters["cortex-code"] = struct {
		register   func(*Registry) RegistrationResult
		unregister func(*Registry) UnregistrationResult
	}{(*Registry).registerCortexCode, (*Registry).unregisterCortexCode}
}

// cortexHooksTarget is the native Cortex Code target.
func (r *Registry) cortexHooksTarget() jsonHooksTarget {
	dir, err := r.artifactDir("cortex-code/user-hooks")
	return jsonHooksTarget{
		tool: "cortex-code", dir: dir, file: "hooks.json", dirErr: err,
		eventsPath: []string{"hooks"}, events: eventsOr("cortex-code", "PreToolUse", "UserPromptSubmit"),
		grouped: true, handler: commandHandler("timeout", cortexHookTimeoutSeconds), commandKey: "command",
		// Cortex runs every entry of an event's list, so Observer's group
		// sits beside the user's own, as in ~/.claude/settings.json.
		coexist: true,
		skip:    cortexSkip, errPrefix: "hook.registerCortexCode", restore: true,
	}
}

// cortexSkip leaves a hooks.json that turns every hook off alone: Cortex
// would run no hook from it, and the switch is the user's. Only the one
// top-level member is decoded.
func cortexSkip(raw []byte, removing bool) string {
	if removing || len(bytes.TrimSpace(raw)) == 0 {
		return ""
	}
	var top struct {
		DisableAllHooks bool `json:"disableAllHooks"`
	}
	if json.Unmarshal(raw, &top) == nil && top.DisableAllHooks {
		return "Cortex Code's hooks.json sets disableAllHooks: true, so Cortex would run no hook from it; Observer leaves the switch as you set it and writes nothing"
	}
	return ""
}

func (r *Registry) registerCortexCode() RegistrationResult {
	if res, gated := r.liveGateRefusal("cortex-code"); gated {
		return res
	}
	return r.registerJSONHooks(r.cortexHooksTarget())
}

// unregisterCortexCode is a no-op while the writer waits on its live check:
// no build has written the file, so there is nothing of Observer's in it, and
// a removal would otherwise read a file a user controls (a FIFO there would
// hang `observer uninstall`). Once the gate is cleared it removes only
// Observer's own entries.
func (r *Registry) unregisterCortexCode() UnregistrationResult {
	if hookLiveGateFor("cortex-code").Waiting() && !runLiveGatedHookWriters {
		return UnregistrationResult{Tool: "cortex-code", DryRun: r.opts.DryRun, Skipped: true}
	}
	return r.unregisterJSONHooks(r.cortexHooksTarget())
}
