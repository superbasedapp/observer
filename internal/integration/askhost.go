package integration

import "github.com/marmutapp/superbased-observer/internal/models"

// The ask host table (security pillar plan section 4.7, "the observe-mode
// ask per channel", revision 2.5 [JSP-6 live half] and D-791 Q27): for the
// hosts whose tool gate can show a native ask, what the host does with an
// ask when no terminal is attached, and how the hook process can tell, per
// call, that this invocation is headless.
//
// A headless ask is never a prompt: Claude Code turns it into a deny (also
// under bypassPermissions), Qoder fails closed, Gemini CLI hangs until the
// run is killed, Codex fails open (the command runs) and Kilo has no ask
// path. So the hook withdraws the ask for a headless invocation and the
// guard emission layer answers with its deny that names `observer guard
// approve` (guard.ExplainDegradedAsk), which is the D-791 outcome on every
// host. The per-call check reads the hook's ancestor chain (the agy probe
// precedent, internal/hook/agyhost.go); the decision code branches on the
// fields below, never on the tool id.

// HeadlessAsk is what a host does with a native ask when no terminal is
// attached (measured live where the row says so).
type HeadlessAsk string

const (
	// HeadlessAskUnmeasured: no headless turn was measured.
	HeadlessAskUnmeasured HeadlessAsk = ""
	// HeadlessAskDeny: the host turns the ask into a deny.
	HeadlessAskDeny HeadlessAsk = "deny"
	// HeadlessAskFailClosed: the host refuses the call because no
	// interactive handler is available.
	HeadlessAskFailClosed HeadlessAsk = "fail_closed"
	// HeadlessAskHang: nothing answers the forced confirmation and the run
	// stalls until it is killed.
	HeadlessAskHang HeadlessAsk = "hang"
	// HeadlessAskFailOpen: the hook is marked failed and the call runs.
	HeadlessAskFailOpen HeadlessAsk = "fail_open"
	// HeadlessAskAbsent: the host has no ask path at all.
	HeadlessAskAbsent HeadlessAsk = "absent"
)

// AskHost is one host's ask row.
type AskHost struct {
	// Binaries are the host executable base names (with and without
	// ".exe"; for a Node-hosted CLI, the script base name, without its
	// .js/.mjs/.cjs extension). An entry with a slash matches the end of
	// the script path instead ("claude-code/cli" for an npm install).
	Binaries []string
	// HeadlessFlags are the host arguments that run it headless (alone or
	// as flag=value).
	HeadlessFlags []string
	// HeadlessSubcommands are the host subcommands that run it headless
	// (the first operand after the binary).
	HeadlessSubcommands []string
	// PositionalHeadless: a positional operand on the host's argv is a
	// prompt that runs the host one-shot (headless) even with a terminal
	// attached, unless one of InteractiveFlags is present.
	PositionalHeadless bool
	// InteractiveFlags keep a run with a positional prompt interactive.
	InteractiveFlags []string
	// ValueFlags are the host options that take the next argument as
	// their value, so it is not read as a positional prompt.
	ValueFlags []string
	// Headless is the measured headless behaviour of a native ask.
	Headless HeadlessAsk
	// AskNeedsTerminal: the host may receive a native ask only when the
	// per-call probe finds the host process AND sees a terminal on its
	// standard input; anywhere else (headless, unknown ancestry, an OS
	// without the probe) the ask is withdrawn. Set where a headless ask
	// hangs. Without it, the ask is withdrawn only on positive headless
	// evidence (a flag, a subcommand, a CI environment), because the host
	// itself refuses a headless ask.
	AskNeedsTerminal bool
	// Grounding is the evidence behind the row.
	Grounding string
}

// CIEnvironment lists the environment variables whose truthy value marks a
// CI run (headless on every host).
var CIEnvironment = []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD"}

// askHosts is THE ask host table, one test row per host and column.
var askHosts = map[string]AskHost{
	models.ToolClaudeCode: {
		Binaries:      []string{"claude", "claude.exe", "claude-code/cli"},
		HeadlessFlags: []string{"-p", "--print"},
		Headless:      HeadlessAskDeny,
		Grounding:     "live 2.1.304 (JSP-6 live half): under -p an ask is listed in permission_denials, also under --permission-mode bypassPermissions",
	},
	models.ToolQoder: {
		Binaries:      []string{"qodercli", "qodercli.exe"},
		HeadlessFlags: []string{"-p", "--print"},
		Headless:      HeadlessAskFailClosed,
		Grounding:     "live 1.1.5 (JSP-6 live half): \"Permission confirmation required but no interactive handler is available\", also under --dangerously-skip-permissions; 1.1.5 is OLDER than the binding's 1.1.65 --yolo record (the ask ran the command), so the binding lists no ask and a current build is not re-grounded",
	},
	models.ToolGeminiCLI: {
		Binaries:         []string{"gemini", "gemini.exe"},
		HeadlessFlags:    []string{"-p", "--prompt"},
		Headless:         HeadlessAskHang,
		AskNeedsTerminal: true,
		// `gemini "do x"` from a terminal runs one-shot (non-interactive
		// unless -i): an ask there would hang like one under -p.
		PositionalHeadless: true,
		InteractiveFlags:   []string{"-i", "--prompt-interactive"},
		ValueFlags: []string{
			"-m", "--model", "--approval-mode", "-o", "--output-format", "-e", "--extensions",
			"--allowed-mcp-server-names", "--allowed-tools", "--include-directories", "--sandbox-image",
			"--proxy", "--telemetry-target", "--telemetry-otlp-endpoint", "--telemetry-otlp-protocol",
			"--telemetry-outfile", "-r", "--resume", "--session-summary",
		},
		Grounding: "live 0.53.1, source the same at 0.64.0 (JSP-6 live half): decision ask forces a confirmation even under YOLO; under -p --yolo nothing answers it and the run stalled until killed at 180 s",
	},
	models.ToolCopilotCLI: {
		Binaries:      []string{"copilot", "copilot.exe"},
		HeadlessFlags: []string{"-p", "--prompt"},
		Headless:      HeadlessAskDeny,
		Grounding:     "headless refusal recorded in the binding; not measured live (repository hooks did not load under -p, JSP-6 live half)",
	},
	models.ToolCodex: {
		Binaries:            []string{"codex", "codex.exe"},
		HeadlessSubcommands: []string{"exec"},
		Headless:            HeadlessAskFailOpen,
		Grounding:           "live 0.144.4 (JSP-6 live half): ask is unsupported; the hook is marked Failed and the command runs",
	},
	models.ToolKiloCodeCLI: {
		Binaries:  []string{"kilo", "kilo.exe"},
		Headless:  HeadlessAskAbsent,
		Grounding: "live 7.3.54 (JSP-6 live half): a plugin has no ask; a throw becomes the tool result the model sees",
	},
}

// AskHostFor returns tool's ask host row.
func AskHostFor(tool string) (AskHost, bool) {
	h, ok := askHosts[tool]
	return h, ok
}

// AskHostTools returns the tools with an ask host row (unsorted).
func AskHostTools() []string {
	out := make([]string, 0, len(askHosts))
	for t := range askHosts {
		out = append(out, t)
	}
	return out
}
