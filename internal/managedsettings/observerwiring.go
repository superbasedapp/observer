package managedsettings

// Observer's own route and hooks in each managed layer (surface-gap
// CLI-10). Lever A renders the org's settings; Observer's own wiring (the
// proxy route and its hook entries) is emitted only where the vendor
// enforces the key AND the per-node writer stands down for it, or every
// event would fire twice. This table says, for every layer, which of the
// two holds, so the README never implies the layer carries Observer's
// wiring when it does not. A layer row without an entry fails
// TestObserverWiringCoversEveryLayer.
var observerWiring = map[string]string{
	"claude-code/managed-settings": "The route (env.ANTHROPIC_BASE_URL) and Observer's MCP entry are enforced here; generate them with " +
		"`observer org emit-managed-settings --provider claude-code`. Hooks stay per node.",
	"codex/system-config":  "A default layer: Observer's route and hooks are not placed here.",
	"codex/managed-config": "The route (openai_base_url) is a default here, re-applied each launch; generate it with `--provider codex`.",
	"codex/requirements": "Enforced: `--provider codex --enforce-proxy-provider` pins Observer's provider (it binds Open Interpreter too) and " +
		"`--enforce-managed-hooks` declares Observer's hooks as managed hooks.",
	"gemini-cli/system-settings": "Not emitted: the file can hold hooks, but a user can relocate it with GEMINI_CLI_SYSTEM_SETTINGS_PATH and the " +
		"per-node registration does not stand down for system-file hooks yet, so both would fire. Observer's hooks stay per node.",
	"gemini-cli/system-defaults": "A default layer: Observer's route and hooks are not placed here.",
	"qwen-code/system-settings": "Not emitted: a user can relocate the file with QWEN_CODE_SYSTEM_SETTINGS_PATH, the per-node registration does " +
		"not stand down for system-file hooks yet, and the model.baseUrl route is not live-verified (LC21). Observer's wiring stays per node.",
	"qwen-code/system-defaults": "A default layer: Observer's route and hooks are not placed here.",
	"opencode/managed-config": "Not emitted: Observer's route is each node's provider options and its hook is a per-node plugin; no managed " +
		"key that enforces either is grounded.",
	"kilo-code-cli/managed-dir": "Not emitted: Observer's route is each node's provider options and its hook is a per-node plugin; no managed " +
		"key that enforces either is grounded.",
	"devin/system-config": "Not a route: the proxy block is an HTTP proxy. Devin Desktop's hooks go to the system hooks.json " +
		"(`--provider devin`).",
	"droid/system-settings":      "Not emitted: no org-level key that enforces Observer's route or hooks is grounded; they stay per node.",
	"kiro-cli/managed-settings":  "Restrict-only rules: Observer's route and hooks cannot be placed here.",
	"grok/system-managed-config": "Not emitted: [model.\"<id>\"] base_url here is only a default, and no proxy route for grok is grounded.",
	"grok/system-requirements":   "Not emitted: requirements.toml cannot pin hooks or a route.",
	"deepagents-code/managed-config": "Not emitted: no hooks or MCP keys are documented for the managed file, and a [models.providers] " +
		"base_url route through Observer is not grounded.",
	"cowork/managed-policy": "The gateway route is enforced here: `--provider claude-desktop --desktop-gateway-route` (not live-verified, " +
		"LC2). Hooks do not fire in Cowork agent mode.",
	"cursor/policy":                "Policy keys carry no hooks: Observer's hooks go to the enterprise hooks.json (`--provider cursor`).",
	"copilot/policy":               "Not emitted: no VS Code policy key carries Observer's route or hooks.",
	"copilot-cli/managed-settings": "A default layer: Observer's route and hooks are not placed here; they stay per node.",
}

// ObserverWiring returns the sentence for a layer ("" for none).
func ObserverWiring(fileID string) string { return observerWiring[fileID] }
