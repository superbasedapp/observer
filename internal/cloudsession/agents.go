package cloudsession

import (
	"fmt"
	"sort"
	"strings"
)

// ExecutionLocation is where a session ran (decision CA-D1). The closed
// vocabulary mirrors the one lane CA-A1 adds to internal/models; until that
// lands this package owns the spelling, and TestExecutionLocationVocabulary
// pins it.
type ExecutionLocation string

// The execution locations a cloud marker can resolve to. The zero value is
// "unknown", never "local".
const (
	ExecutionLocal          ExecutionLocation = "local"
	ExecutionVendorCloud    ExecutionLocation = "vendor_cloud"
	ExecutionCustomerWorker ExecutionLocation = "customer_worker"
)

// FileFormat is how one repository file is rendered and removed. Each format
// is one row of the renderer table in plan.go.
type FileFormat string

// The repository file formats.
const (
	// FormatClaudeSettings merges hook groups into the repository's shared
	// .claude/settings.json (the file may already hold the team's own
	// settings). Edited structurally with key order kept, so a remove
	// restores the original bytes exactly; refused when the existing file
	// does not round-trip byte-for-byte (see jsonedit.go).
	FormatClaudeSettings FileFormat = "claude-settings-json"
	// FormatCopilotHooks is a dedicated Copilot hooks file
	// (.github/hooks/<name>.json, version 1): the agent loads every file in
	// that directory, so Observer owns one file outright.
	FormatCopilotHooks FileFormat = "copilot-hooks-json"
	// FormatSetupScript is the dedicated POSIX sh installer every agent's
	// setup step runs (setup.go).
	FormatSetupScript FileFormat = "setup-script"
	// FormatCopilotSetupSteps is the dedicated
	// .github/workflows/copilot-setup-steps.yml workflow. Written only when
	// absent; an existing workflow is never edited (YAML has no structure
	// this package can keep byte-exact), the step to add is reported instead.
	FormatCopilotSetupSteps FileFormat = "copilot-setup-steps-yml"
	// FormatPolicyFile is the dedicated signed sandbox policy file
	// (policy.go, lane CA-C2): written verbatim as init fetched it.
	FormatPolicyFile FileFormat = "cloud-session-policy-json"
	// FormatClaudeMCP merges Observer's MCP server into the repository's
	// shared .mcp.json (mcp.go, lane CA-C2), edited structurally like
	// FormatClaudeSettings so a remove restores the original bytes.
	FormatClaudeMCP FileFormat = "claude-mcp-json"
)

// Feature is an opt-in part of the setup (lane CA-C2). A hook entry or a
// repository file with a Feature is planned only when init turned that
// feature on, and init takes it back out when the feature is off; the zero
// value is always planned. With no feature on, init writes exactly what it
// wrote before the features existed.
type Feature string

// The features.
const (
	// FeatureGuard: the signed policy file and the gate hooks (--guard).
	FeatureGuard Feature = "guard"
	// FeatureMCP: Observer's MCP server in the repository MCP config (--mcp).
	FeatureMCP Feature = "mcp"
)

// HookAction is what one committed hook entry does.
type HookAction string

// The hook actions.
const (
	// ActionCapture runs the existing `observer hook <tool> <event>`.
	ActionCapture HookAction = "capture"
	// ActionFlush runs `observer cloud-session flush --trigger <Trigger>`
	// (the trigger table in flush.go says how each trigger behaves).
	ActionFlush HookAction = "flush"
	// ActionGate runs `observer cloud-session gate` (gate.go): the sandbox
	// guard, evaluated from the committed policy file with no network call.
	ActionGate HookAction = "gate"
)

// HookBinding is one vendor event wired to one action.
type HookBinding struct {
	// Event is the vendor's own event name, verbatim.
	Event string
	// Action is what the entry runs.
	Action HookAction
	// Trigger is the flush trigger of an ActionFlush entry.
	Trigger Trigger
	// Matcher is the tool matcher for a tool event; empty for an event
	// that takes none.
	Matcher string
	// TimeoutSeconds is the vendor timeout written on the entry (0 = the
	// vendor default; a flush entry takes its trigger's HookTimeoutSeconds).
	TimeoutSeconds int
	// Gate is what an ActionGate entry judges.
	Gate GateKind
	// Dialect is an ActionGate entry's internal/hook reply dialect (a row of
	// the gate dialect table, cross-checked against the integration
	// registry).
	Dialect string
	// Feature, when set, plans the entry only while that feature is on.
	Feature Feature
}

// Marker is one row of an agent's cloud-marker table: every condition must
// hold for the row to match, and the first matching row wins. Only variable
// NAMES live here; a value is compared, never logged or stored.
type Marker struct {
	// Env must be set; when Equals is non-empty it must equal it.
	Env    string
	Equals string
	// AlsoEnv / AlsoEquals is an optional second condition refining the
	// location (Copilot: a self-hosted runner is customer compute).
	AlsoEnv    string
	AlsoEquals string
	// Location is where the session ran when this row matches.
	Location ExecutionLocation
}

// RepoFile is one repository file an agent's init writes.
type RepoFile struct {
	Path   string // slash-separated, relative to the repository root
	Format FileFormat
	// Feature, when set, plans the file only while that feature is on.
	Feature Feature
}

// Agent is one row of the agent table: everything `init` and `flush` need
// to know about one managed cloud agent.
type Agent struct {
	// ID is the --agent value.
	ID string
	// DisplayName is the vendor product name shown in messages.
	DisplayName string
	// HookTool is the `observer hook <tool>` receiver id (an
	// internal/integration registry tool); empty when the agent has none.
	HookTool string
	// ScanAdapters are the adapter names flush scans: the adapters whose
	// store the agent writes inside its VM.
	ScanAdapters []string
	// Markers is the cloud-marker table, walked top-down.
	Markers []Marker
	// VendorRefEnv names the variable carrying the vendor's cloud session
	// reference (CA-D2 vendor_session_ref); empty when none is established.
	VendorRefEnv string
	// ProjectDirEnv names the variable the vendor sets for its hooks to the
	// project (repository) directory; the sandbox gate judges a tool call's
	// project against it when the payload carries no working directory.
	// Empty when none is documented.
	ProjectDirEnv string
	// Hooks are the committed hook entries.
	Hooks []HookBinding
	// Files are the repository files init writes, in write order.
	Files []RepoFile
	// ManualSteps are setup steps that live outside the repository (a
	// vendor environment setting), printed for the developer to do once.
	ManualSteps []string
	// EgressSetting, when set, names the vendor setting that allow-lists
	// the sandbox's outbound hosts (the plan prints which hosts to allow for
	// the chosen install source and destination). Empty when the sandbox's
	// egress is not allow-listed by default.
	EgressSetting string
	// Egress is how EgressSetting names its levels, for the printed step
	// (meaningful only with EgressSetting).
	Egress EgressVocabulary
	// MCPSettings, when set, names the vendor settings page that holds the
	// agent's MCP config (outside the repository): --mcp then prints the
	// JSON to paste there instead of writing a file.
	MCPSettings string
	// Unsupported, when set, is why init refuses this agent today.
	Unsupported string
	// Grounding records what is verified live and what is not.
	Grounding string
}

// Supported reports whether init may plan files for the agent.
func (a Agent) Supported() bool { return a.Unsupported == "" }

// EgressVocabulary is how a vendor's environment network setting names its
// levels, so every printed step says it the vendor's way. %s in AddHost and
// Summary is the host to allow.
type EgressVocabulary struct {
	// Packages says which level lets the setup script reach the npm
	// registry.
	Packages string
	// AddHost says how to let one more host through.
	AddHost string
	// Summary is the one-line form ("Network access: " + Summary).
	Summary string
}

// ClaudeCodeNetwork is the Claude Code cloud environment's network access
// vocabulary, as the environment form at claude.ai/code offers it (observed
// live 2026-11-03): three levels, None, Limited (an "Allowed domains" list,
// one per line, *.example.com for subdomains, plus an "Allow package
// managers" checkbox) and Full. There is no Trusted or Custom level any
// more. The Rail T text (internal/telemetrywire) reads it too, so the
// wording has one owner.
var ClaudeCodeNetwork = EgressVocabulary{
	Packages: `the Limited level with "Allow package managers" on reaches the npm registry`,
	AddHost:  "choose Limited and add %s under Allowed domains (one per line; *.example.com covers subdomains), or choose Full",
	Summary:  "Limited, with %s under Allowed domains (or Full)",
}

// Repository paths shared across agents.
const (
	// SetupScriptPath is the one installer every agent's setup step runs.
	SetupScriptPath = ".superbased/cloud-session/setup.sh"
	// ClaudeSettingsPath is Claude Code's repository settings file.
	ClaudeSettingsPath = ".claude/settings.json"
	// CopilotHooksPath is Observer's dedicated Copilot hooks file.
	CopilotHooksPath = ".github/hooks/superbased-observer.json"
	// CopilotSetupStepsPath is the Copilot cloud agent's setup workflow.
	CopilotSetupStepsPath = ".github/workflows/copilot-setup-steps.yml"
)

// agents is THE agent table. Rows for agents whose sandbox hook surface is
// documented but not yet usable by Observer carry an Unsupported reason so
// `init --agent` answers honestly instead of writing files that do nothing.
var agents = []Agent{
	{
		ID:           "claude-code",
		DisplayName:  "Claude Code on the web",
		HookTool:     "claude-code",
		ScanAdapters: []string{"claude-code"},
		Markers: []Marker{
			// CLAUDE_CODE_REMOTE=true is set in every cloud session and
			// never locally (reference "Claude Code: session surfaces").
			// Lane CA-C4: the Anthropic-hosted value is matched first, so
			// the self-hosted attestation (worker.go WorkerAttestEnv) can
			// never relabel an Anthropic-hosted session customer compute.
			{Env: "CLAUDE_CODE_REMOTE", Equals: "true", AlsoEnv: "CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE", AlsoEquals: "cloud_default", Location: ExecutionVendorCloud},
			{Env: "CLAUDE_CODE_REMOTE", Equals: "true", AlsoEnv: WorkerAttestEnv, AlsoEquals: "claude-code-self-hosted", Location: ExecutionCustomerWorker},
			{Env: "CLAUDE_CODE_REMOTE", Equals: "true", Location: ExecutionVendorCloud},
		},
		// ccr.session.id equals CLAUDE_CODE_REMOTE_SESSION_ID and survives
		// /clear, unlike session.id.
		VendorRefEnv: "CLAUDE_CODE_REMOTE_SESSION_ID",
		// Claude Code sets CLAUDE_PROJECT_DIR for hook commands to the
		// project root (the vendor hooks reference; cloud-environments
		// docs: it "resolves to the repository root").
		ProjectDirEnv: "CLAUDE_PROJECT_DIR",
		Hooks: []HookBinding{
			{Event: "SessionStart", Action: ActionCapture},
			{Event: "UserPromptSubmit", Action: ActionCapture},
			{Event: "PostToolUse", Action: ActionCapture, Matcher: "*"},
			{Event: "PostToolUseFailure", Action: ActionCapture, Matcher: "*"},
			{Event: "SubagentStop", Action: ActionCapture},
			{Event: "Stop", Action: ActionCapture},
			{Event: "SessionEnd", Action: ActionCapture},
			// Stop and SessionEnd were not seen to fire from repository
			// hooks (CA-A2), so the cadence rests on start, prompt and
			// periodic; the final flushes are a bonus when they do fire.
			{Event: "SessionStart", Action: ActionFlush, Trigger: TriggerStart},
			{Event: "UserPromptSubmit", Action: ActionFlush, Trigger: TriggerPrompt},
			{Event: "PostToolUse", Action: ActionFlush, Trigger: TriggerPeriodic, Matcher: "*"},
			{Event: "Stop", Action: ActionFlush, Trigger: TriggerFinal},
			{Event: "SessionEnd", Action: ActionFlush, Trigger: TriggerFinal},
			// The sandbox guard (lane CA-C2). PreToolUse has no capture
			// entry, so the gate is its only hook; UserPromptSubmit keeps
			// its capture entry (which runs the guard's prompt lane) and
			// the gate adds the soft budget stop and the policy check.
			{Event: "PreToolUse", Action: ActionGate, Gate: GateTool, Dialect: "claude-code-pretool", Matcher: "*", Feature: FeatureGuard},
			{Event: "UserPromptSubmit", Action: ActionGate, Gate: GatePrompt, Dialect: "claude-code", Feature: FeatureGuard},
		},
		Files: []RepoFile{
			{Path: ClaudeSettingsPath, Format: FormatClaudeSettings},
			{Path: SetupScriptPath, Format: FormatSetupScript},
			{Path: PolicyPath, Format: FormatPolicyFile, Feature: FeatureGuard},
			{Path: ClaudeMCPPath, Format: FormatClaudeMCP, Feature: FeatureMCP},
		},
		ManualSteps: []string{
			"In the Claude Code cloud environment's settings, add these lines to the setup script (it does not run in the repository, so they find the committed installer and run it from the repository):\n" + ClaudeSetupScriptLines,
		},
		EgressSetting: "the Claude Code cloud environment's network access",
		Egress:        ClaudeCodeNetwork,
		Grounding:     "Live-grounded by lane CA-A2 (Claude Code 2.1.316): repository hooks for SessionStart, UserPromptSubmit, PreToolUse and PostToolUse fire and hot-reload mid-session; Stop and SessionEnd were not observed; the transcript is the ordinary ~/.claude/projects/<slug>/<session>.jsonl; CLAUDE_CODE_REMOTE=true and CLAUDE_CODE_REMOTE_SESSION_ID reach every hook; a failed setup script does not stop the session; npm installs, GitHub release assets and arbitrary hosts are refused at the default network level.",
	},
	{
		ID:           "copilot",
		DisplayName:  "GitHub Copilot cloud agent",
		HookTool:     "copilot-cli",
		ScanAdapters: []string{"copilot-cli"},
		Markers: []Marker{
			// The agent runs in a GitHub Actions job; repository hooks under
			// .github/hooks fire only for the agent, so GITHUB_ACTIONS is the
			// cloud marker and RUNNER_ENVIRONMENT tells customer compute.
			{Env: "GITHUB_ACTIONS", Equals: "true", AlsoEnv: "RUNNER_ENVIRONMENT", AlsoEquals: "self-hosted", Location: ExecutionCustomerWorker},
			{Env: "GITHUB_ACTIONS", Equals: "true", Location: ExecutionVendorCloud},
		},
		// VendorRefEnv stays empty: no variable carrying the cloud agent's
		// session reference is grounded for the agent's own process (the
		// GitHub Actions run variables are documented for workflow steps,
		// not live-checked in the agent's hooks). Each job is a fresh VM, so
		// a per-job reference would not stop a hook edit committed in one
		// job becoming the next job's HEAD baseline either; R-160 denying
		// the edit is what closes that (ledger CLOUDSESS-5).
		Hooks: []HookBinding{
			{Event: "userPromptSubmitted", Action: ActionCapture},
			{Event: "sessionStart", Action: ActionFlush, Trigger: TriggerStart},
			{Event: "userPromptSubmitted", Action: ActionFlush, Trigger: TriggerPrompt},
			{Event: "postToolUse", Action: ActionFlush, Trigger: TriggerPeriodic},
			{Event: "agentStop", Action: ActionFlush, Trigger: TriggerFinal},
			{Event: "sessionEnd", Action: ActionFlush, Trigger: TriggerFinal},
			// The sandbox guard (lane CA-C2): the vendor hooks reference
			// documents a preToolUse deny for the cloud agent; not yet
			// live-checked there.
			{Event: "preToolUse", Action: ActionGate, Gate: GateTool, Dialect: "copilot-cli-pretool", Feature: FeatureGuard},
			{Event: "userPromptSubmitted", Action: ActionGate, Gate: GatePrompt, Dialect: "copilot-cli-prompt", Feature: FeatureGuard},
		},
		Files: []RepoFile{
			{Path: CopilotHooksPath, Format: FormatCopilotHooks},
			{Path: SetupScriptPath, Format: FormatSetupScript},
			{Path: CopilotSetupStepsPath, Format: FormatCopilotSetupSteps},
			{Path: PolicyPath, Format: FormatPolicyFile, Feature: FeatureGuard},
		},
		MCPSettings: "the repository's Settings > Copilot > Coding agent > MCP configuration",
		ManualSteps: []string{
			"If the repository uses the Copilot agent firewall, allow your destination host (the firewall does not cover setup steps, so the install itself is not blocked).",
		},
		Grounding: "Hook file shape and event names follow the vendor hooks docs; that the cloud agent writes the copilot-cli session store in its VM, and its marker variables, are not yet live-grounded.",
	},
	{
		ID:          "openhands",
		DisplayName: "OpenHands Cloud",
		Unsupported: "Observer has no OpenHands adapter or hook receiver yet, so in-sandbox capture would record nothing; use the Rail P connector (lane CA-B2) instead.",
	},
	{
		ID:          "cursor",
		DisplayName: "Cursor Cloud Agents",
		Unsupported: "Cursor cloud agents run only command hooks (sessionStart/sessionEnd do not fire), so there is no reliable flush point; scheduled for wave C after a live check.",
	},
	{
		ID:          "augment",
		DisplayName: "Augment Cosmos",
		Unsupported: "Observer has no Auggie adapter or hook receiver yet; scheduled for wave C.",
	},
}

// Agents returns a copy of the agent table, in table order.
func Agents() []Agent {
	out := make([]Agent, len(agents))
	copy(out, agents)
	return out
}

// AgentIDs returns every agent id, sorted.
func AgentIDs() []string {
	ids := make([]string, 0, len(agents))
	for _, a := range agents {
		ids = append(ids, a.ID)
	}
	sort.Strings(ids)
	return ids
}

// AgentByID returns the agent row for id.
func AgentByID(id string) (Agent, error) {
	for _, a := range agents {
		if a.ID == id {
			return a, nil
		}
	}
	return Agent{}, fmt.Errorf("cloudsession: unknown agent %q (known: %s)", id, strings.Join(AgentIDs(), ", "))
}
