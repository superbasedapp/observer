package componentsvc

import (
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/components"
)

// StepKind is one kind of teardown step.
type StepKind string

// The closed StepKind vocabulary.
const (
	// StepToolWiring removes Observer's entries from one AI tool's own
	// config (hooks, MCP server entry, proxy route, telemetry exporter)
	// through internal/clientwire.Remover. Tool "" means every tool the
	// removers detect.
	StepToolWiring StepKind = "tool_wiring"
	// StepBrowserHost removes the browser native-messaging host manifests,
	// the Windows registry keys and the host files Observer wrote.
	StepBrowserHost StepKind = "browser_host"
	// StepManual is a write Observer made that this service does not undo
	// itself yet; Command is the existing verb that does.
	StepManual StepKind = "manual"
)

// Wiring parts, in the order a removal runs them: the proxy route first, so
// no tool is left pointed at a proxy that is about to stop (CLAUDE.md
// "never stop the daemon while the proxy route is active").
const (
	PartRoute     = "route"
	PartHooks     = "hooks"
	PartMCP       = "mcp"
	PartTelemetry = "telemetry"
)

// Step is one ordered teardown step of one deactivated component.
type Step struct {
	Component string   `json:"component"`
	Kind      StepKind `json:"kind"`
	// Tool is the AI tool a StepToolWiring step targets ("" = every
	// detected tool).
	Tool string `json:"tool,omitempty"`
	// Parts are the wiring parts a StepToolWiring step removes.
	Parts []string `json:"parts,omitempty"`
	// Command is the verb that undoes a StepManual step.
	Command string `json:"command,omitempty"`
	// What is the honest one-line description shown in the preview.
	What string `json:"what"`
}

// teardownRule is one row of the teardown table: the first row whose match
// returns true for a deactivated component decides its steps (CLAUDE.md
// rule 5: decision logic is a data table).
type teardownRule struct {
	name  string
	match func(id string) bool
	steps func(id string) []Step
}

func exact(want string) func(string) bool { return func(id string) bool { return id == want } }

// teardownRules is the ordered teardown table. A component with no row
// wrote nothing outside Observer's own state, so it has no teardown.
var teardownRules = []teardownRule{
	{
		name:  "adapter",
		match: func(id string) bool { return strings.HasPrefix(id, "adapter.") },
		steps: func(id string) []Step {
			tool := strings.TrimPrefix(id, "adapter.")
			// Only the parts Observer can write for this tool at all (the
			// clientwire capability answer, never a tool-name branch). A
			// capture-only adapter (zed, the browser-chat sites) wrote
			// nothing into its tool's config, so it has no step.
			var parts []string
			for _, p := range []string{PartRoute, PartHooks, PartMCP, PartTelemetry} {
				if clientwire.Removable(tool, clientwire.Part(p)) {
					parts = append(parts, p)
				}
			}
			if len(parts) == 0 {
				return nil
			}
			return []Step{{
				Component: id, Kind: StepToolWiring, Tool: tool, Parts: parts,
				What: "Removes Observer's " + strings.Join(parts, ", ") + " entries from " + tool + "'s own config (its cross-OS Windows target too); a file you edited since is left in place and reported.",
			}}
		},
	},
	{
		name: "hooks", match: exact("integration.hooks"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepToolWiring, Parts: []string{PartHooks},
				What: "Removes Observer's hook entries from every AI tool's config, and `observer start` stops registering them.",
			}}
		},
	},
	{
		name: "mcp", match: exact("integration.mcp-server"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepToolWiring, Parts: []string{PartMCP},
				What: "Removes Observer's MCP server entry from every AI tool's config.",
			}}
		},
	},
	{
		name: "route", match: exact("integration.proxy-route"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepToolWiring, Parts: []string{PartRoute},
				What: "Removes the proxy route (ANTHROPIC_BASE_URL, codex base_url) Observer wrote, before the proxy stops.",
			}}
		},
	},
	{
		name: "otlp", match: exact("ingest.otlp"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepToolWiring, Parts: []string{PartTelemetry},
				What: "Removes the OpenTelemetry exporter entries Observer wrote into AI tools' configs.",
			}}
		},
	},
	{
		name: "browser", match: exact("capture.browser"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepBrowserHost,
				What: "Removes the browser native-messaging host manifests, the Windows registry keys and the host files. The browser extension itself keeps running in the browser until you remove it there.",
			}}
		},
	},
	{
		name: "statusline", match: exact("integration.statusline"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer init --statusline --uninstall",
				What: "Removes the Claude Code statusLine entry.",
			}}
		},
	},
	{
		name: "shell-wrap", match: exact("integration.shell-wrap"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer shell-wrap disable",
				What: "Removes the PATH shims and the marked shell start-up blocks byte-exactly.",
			}}
		},
	},
	{
		name: "mcp-relay", match: exact("agentaccess.relay"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer mcp unwrap",
				What: "Restores the original MCP client entries the relay wrapped.",
			}}
		},
	},
	{
		name: "routing", match: exact("proxy.routing"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer routing apply --tool claude-code --revert",
				What: "Restores the AI tool config backups `observer routing apply` wrote (only if you ran it).",
			}}
		},
	},
	{
		name: "agent-config", match: exact("integration.agent-config"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual,
				What: "Nothing to undo: the AI tool settings you edited through the dashboard are your own edits and stay as you left them.",
			}}
		},
	},
	{
		name: "security-githooks", match: exact("security.githooks"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer security githooks uninstall --project <repository>",
				What: "Removes Observer's block from the pre-commit and pre-push hooks of each repository you installed it in (byte-exact; a hook you wrote stays). While the component is off the block skips itself.",
			}}
		},
	},
	{
		name: "security-provenance", match: exact("security.provenance"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer security provenance consent --withdraw-all",
				What: "Withdraws your consent in every repository and removes the prepare-commit-msg trailer block byte-exactly; git notes already written stay. While the component is off the block adds nothing.",
			}}
		},
	},
	{
		name: "service", match: exact("integration.service"),
		steps: func(id string) []Step {
			return []Step{{
				Component: id, Kind: StepManual, Command: "observer service uninstall",
				What: serviceTeardownWhat(teardownGOOS),
			}}
		},
	},
}

// serviceTeardownWords is how the service step's text names what
// `observer service uninstall` removes on each host's service manager
// (N4, live Mac 2026-10-29: macOS read "the systemd unit"); a GOOS with no
// row reads the generic line.
var serviceTeardownWords = map[string]string{
	"linux":   "Stops and removes the systemd unit.",
	"darwin":  "Unloads and removes the LaunchAgent (~/Library/LaunchAgents/app.superbased.observer.plist).",
	"windows": "Windows has no `observer service` unit to remove; the start at sign-in is removed with `observer setup autostart off`.",
}

// teardownGOOS is the host the teardown text is worded for (a var so a
// test can word another OS).
var teardownGOOS = runtime.GOOS

// serviceTeardownWhat words the service step for goos.
func serviceTeardownWhat(goos string) string {
	if w, ok := serviceTeardownWords[goos]; ok {
		return w
	}
	return "Stops and removes the service unit."
}

// TeardownFor returns the ordered teardown steps of one component (none
// when it wrote nothing outside Observer's own state).
func TeardownFor(id string) []Step {
	for _, r := range teardownRules {
		if r.match(id) {
			return r.steps(id)
		}
	}
	return nil
}

// omittedComponents is the seam over components.Omitted (the running
// binary's own record of what it was built without); tests swap it.
var omittedComponents = components.Omitted

// missingVerb reports whether a manual step names a verb this binary does
// not carry: the step's component is compiled out of this build, so its
// undo subcommand is not registered here (T-726). The answer comes from
// the binary's omission record, never a component or verb name.
func missingVerb(st Step) bool {
	if st.Kind != StepManual || st.Command == "" {
		return false
	}
	for _, o := range omittedComponents() {
		if o == st.Component {
			return true
		}
	}
	return false
}

// standIn is the instruction a manual step carries when its verb is not in
// this build: the command still undoes the write, but it has to run from a
// build that includes the component.
func standIn(st Step) string {
	return "this build does not include " + st.Component + ", so `" + st.Command +
		"` is not available here: run it with a build that includes " + st.Component +
		" (" + components.BuildsHaving(st.Component) + ")"
}

// teardownPlan returns the steps for a set of deactivated components, in
// execution order: every route removal first, then the rest by component.
// A manual step whose verb this build lacks keeps its command (it still
// names the undo) and its description says where to run it.
func teardownPlan(deactivated []string) []Step {
	var steps []Step
	for _, id := range deactivated {
		if _, ok := components.Get(id); !ok {
			continue
		}
		for _, st := range TeardownFor(id) {
			if missingVerb(st) {
				st.What += " Note: " + standIn(st) + "."
			}
			steps = append(steps, st)
		}
	}
	rank := func(s Step) int {
		if s.Kind == StepToolWiring && len(s.Parts) > 0 && s.Parts[0] == PartRoute {
			return 0
		}
		return 1
	}
	sort.SliceStable(steps, func(i, j int) bool { return rank(steps[i]) < rank(steps[j]) })
	return steps
}
