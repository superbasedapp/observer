package main

import (
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// SURFACES SHARING ONE REGISTRATION (surface-gap W-2c / IDE-10).
//
// One vendor hook file can be read by several surfaces: the Antigravity App
// and IDE run the hooks the antigravity-cli registration writes into
// ~/.gemini/config/hooks.json. The payload says which surface sent it
// (hook.SurfaceTool); the call is then served, recorded and counted under
// that surface's tool, with the surface's own binding for the event. That
// binding must be wired, declare that it rides the registered tool's file
// (HookBinding.ReplayedVia), and speak the registered binding's capability
// and dialect (one file, one payload, one reply shape), so a surface the
// registry does not wire keeps the registered tool and nothing changes.

// hookSurfaceBinding resolves the surface that ran tool's registration of
// binding b from the payload. ok is false (the caller keeps tool and b)
// unless a surface row names another tool whose binding for b's event
// passes the rules above.
func hookSurfaceBinding(tool string, b integration.HookBinding, body []byte) (string, integration.HookBinding, bool) {
	surface, ok := hook.SurfaceTool(tool, body)
	if !ok {
		return tool, b, false
	}
	sb, ok := resolveHookBinding(surface, b.NativeEvent)
	if !ok || !sb.Wired || sb.ReplayedVia != tool || sb.Cap != b.Cap || sb.Dialect != b.Dialect {
		return tool, b, false
	}
	noteHookActivityTool(surface, sb.NativeEvent)
	return surface, sb, true
}

// noteForeignHookActivity is the liveness side of a foreign Claude Code
// payload (surface-gap FU-53): a host the receiver serves as its own call
// (ForeignReroute, ForeignDispatch: the host has no Observer hook of its own
// seeing it) is counted under the host's tool, event and session; a host
// whose own Observer hook already counts the call (ForeignNeutral) and an
// unidentified host (ForeignNoop) are not counted at all, and neither is a
// reroute no host binding serves (foreignReroute: the host's neutral reply,
// nothing judged, e.g. a Copilot runtime UserPromptSubmit replay). It lives here, not
// in hook_activity.go, which imports nothing that reaches a database.
func noteForeignHookActivity(v hook.ForeignVerdict, body []byte) {
	served := v.Action == hook.ForeignDispatch
	if v.Action == hook.ForeignReroute {
		kind, _ := foreignReroute(v)
		served = kind != rerouteUnserved
	}
	if v.Tool != "" && served {
		noteHookActivityTool(v.Tool, v.Step)
		noteHookPayload(body)
		return
	}
	noteHookForeign()
}
