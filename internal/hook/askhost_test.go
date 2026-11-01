package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// askColumn is one column of the security plan's section 4.7 per-host
// table: how the host was started for this hook call.
type askColumn struct {
	name     string
	argv     []string // the host process argv ("" first word: no host found)
	env      map[string]string
	terminal bool // the host process's stdin is a terminal
	chainOK  bool // the ancestry could be read at all
}

// TestHostCanAskPerHostTable is one row per host and column (D-791 Q27):
// interactive with a terminal, headless, CI, and unknown ancestry.
func TestHostCanAskPerHostTable(t *testing.T) {
	type row struct {
		tool string
		// interactive argv (the headless argv adds the row's flag).
		interactive []string
		headless    []string
		want        map[string]bool // column -> can ask
	}
	rows := []row{
		{
			tool: models.ToolClaudeCode, interactive: []string{"/usr/local/bin/claude"}, headless: []string{"claude", "-p", "commit it"},
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": true, "no-terminal": true},
		},
		{
			tool: models.ToolClaudeCode, interactive: []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"}, headless: []string{"node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js", "--print", "x"},
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": true, "no-terminal": true},
		},
		{
			tool: models.ToolQoder, interactive: []string{"qodercli"}, headless: []string{"qodercli", "-p", "x"},
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": true, "no-terminal": true},
		},
		{
			tool: models.ToolGeminiCLI, interactive: []string{"node", "/usr/bin/gemini"}, headless: []string{"node", "/usr/bin/gemini", "-p", "x", "--yolo"},
			// Gemini: an ask only with the host found AND a terminal.
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": false, "no-terminal": false},
		},
		{
			tool: models.ToolCopilotCLI, interactive: []string{"copilot"}, headless: []string{"copilot", "--prompt=x"},
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": true, "no-terminal": true},
		},
		{
			tool: models.ToolCodex, interactive: []string{"codex"}, headless: []string{"codex", "exec", "x"},
			want: map[string]bool{"interactive": true, "headless": false, "ci": true, "ci-no-terminal": false, "ci-unknown": false, "unknown": true, "no-terminal": true},
		},
	}
	for _, r := range rows {
		h, ok := integration.AskHostFor(r.tool)
		if !ok {
			t.Fatalf("%s: no ask host row", r.tool)
		}
		cols := []askColumn{
			{name: "interactive", argv: r.interactive, terminal: true, chainOK: true},
			{name: "headless", argv: r.headless, terminal: true, chainOK: true},
			// P-008: a CI variable withdraws the ask only with no terminal.
			{name: "ci", argv: r.interactive, env: map[string]string{"CI": "true"}, terminal: true, chainOK: true},
			{name: "ci-no-terminal", argv: r.interactive, env: map[string]string{"CI": "true"}, terminal: false, chainOK: true},
			{name: "ci-unknown", env: map[string]string{"CI": "true"}, chainOK: false},
			{name: "unknown", chainOK: false},
			{name: "no-terminal", argv: r.interactive, terminal: false, chainOK: true},
		}
		for _, c := range cols {
			in := askProbeInput{
				chainOK:  c.chainOK,
				getenv:   func(k string) string { return c.env[k] },
				terminal: func(int) bool { return c.terminal },
			}
			if c.chainOK && len(c.argv) > 0 {
				in.chain = []procInfo{{PID: 100, Argv: []string{"/bin/sh", "-c", "observer hook"}}, {PID: 99, Argv: c.argv}}
			}
			if got := hostCanAsk(h, in); got != r.want[c.name] {
				t.Errorf("%s %v / %s: can ask = %v, want %v", r.tool, r.interactive, c.name, got, r.want[c.name])
			}
		}
	}
}

// TestCIVariableWithdrawsOnlyWithoutTerminal is one row per CI variable
// (P-008): truthy with no terminal attached withdraws the ask; truthy with
// the host found holding a terminal keeps it; falsy keeps it.
func TestCIVariableWithdrawsOnlyWithoutTerminal(t *testing.T) {
	h, _ := integration.AskHostFor(models.ToolClaudeCode)
	if len(integration.CIEnvironment) != 6 {
		t.Fatalf("CI variables = %v; add a row here for a new one", integration.CIEnvironment)
	}
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TF_BUILD"} {
		for _, tc := range []struct {
			value    string
			terminal bool
			want     bool
		}{
			{"true", false, false},
			{"true", true, true},
			{"false", false, true},
		} {
			env := map[string]string{k: tc.value}
			if k == "JENKINS_URL" && tc.value == "true" {
				env[k] = "https://ci.example.invalid/"
			}
			in := askProbeInput{
				chainOK:  true,
				chain:    []procInfo{{PID: 100, Argv: []string{"/bin/sh", "-c", "observer hook"}}, {PID: 99, Argv: []string{"claude"}}},
				getenv:   func(key string) string { return env[key] },
				terminal: func(int) bool { return tc.terminal },
			}
			if got := hostCanAsk(h, in); got != tc.want {
				t.Errorf("%s=%q terminal=%v: can ask = %v, want %v", k, env[k], tc.terminal, got, tc.want)
			}
		}
	}
}

// TestGeminiPositionalPromptIsHeadless: `gemini "do x"` from a terminal
// runs one-shot, so an ask would hang; -i keeps it interactive, and an
// option's value is not a prompt.
func TestGeminiPositionalPromptIsHeadless(t *testing.T) {
	h, _ := integration.AskHostFor(models.ToolGeminiCLI)
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"node", "/usr/bin/gemini"}, true},
		{[]string{"node", "/usr/bin/gemini", "commit the change"}, false},
		{[]string{"gemini", "--yolo", "commit the change"}, false},
		{[]string{"gemini", "-m", "gemini-2.5-pro"}, true},
		{[]string{"gemini", "--model=gemini-2.5-pro", "fix it"}, false},
		{[]string{"gemini", "-i", "start here"}, true},
		{[]string{"gemini", "--prompt-interactive=start here"}, true},
		{[]string{"gemini", "--", "fix it"}, false},
		{[]string{"gemini", "--yolo"}, true},
	}
	for _, tc := range cases {
		in := askProbeInput{
			chainOK:  true,
			chain:    []procInfo{{PID: 100, Argv: []string{"/bin/sh", "-c", "observer hook"}}, {PID: 99, Argv: tc.argv}},
			getenv:   func(string) string { return "" },
			terminal: func(int) bool { return true },
		}
		if got := hostCanAsk(h, in); got != tc.want {
			t.Errorf("%v: can ask = %v, want %v", tc.argv, got, tc.want)
		}
	}
	// Claude Code has no positional rule: `claude "x"` is interactive.
	c, _ := integration.AskHostFor(models.ToolClaudeCode)
	in := askProbeInput{chainOK: true, chain: []procInfo{{PID: 99, Argv: []string{"claude", "fix it"}}}, terminal: func(int) bool { return true }}
	if !hostCanAsk(c, in) {
		t.Error("claude with a positional prompt lost its ask")
	}
}

// TestAskHostRowsCoverThePlanTable pins the measured headless column.
func TestAskHostRowsCoverThePlanTable(t *testing.T) {
	want := map[string]integration.HeadlessAsk{
		models.ToolClaudeCode:  integration.HeadlessAskDeny,
		models.ToolQoder:       integration.HeadlessAskFailClosed,
		models.ToolGeminiCLI:   integration.HeadlessAskHang,
		models.ToolCodex:       integration.HeadlessAskFailOpen,
		models.ToolKiloCodeCLI: integration.HeadlessAskAbsent,
		models.ToolCopilotCLI:  integration.HeadlessAskDeny,
	}
	for tool, h := range want {
		row, ok := integration.AskHostFor(tool)
		if !ok || row.Headless != h {
			t.Errorf("%s: headless = %q, want %q", tool, row.Headless, h)
		}
		if row.Headless == integration.HeadlessAskHang && !row.AskNeedsTerminal {
			t.Errorf("%s: a hanging headless ask must be terminal-gated", tool)
		}
	}
}

func TestCIRun(t *testing.T) {
	cases := map[string]bool{"": false, "0": false, "false": false, "true": true, "1": true, "yes": true}
	for v, want := range cases {
		if got := ciRun(func(k string) string {
			if k == "CI" {
				return v
			}
			return ""
		}); got != want {
			t.Errorf("CI=%q: %v, want %v", v, got, want)
		}
	}
}

func TestProcTerminal(t *testing.T) {
	links := map[string]string{"/proc/7/fd/0": "/dev/pts/3", "/proc/8/fd/0": "pipe:[123]", "/proc/9/fd/0": "/dev/tty1"}
	r := procReader{root: "/proc", readlink: func(n string) (string, error) {
		if v, ok := links[n]; ok {
			return v, nil
		}
		return "", errFake
	}}
	for pid, want := range map[int]bool{7: true, 8: false, 9: true, 10: false, 1: false} {
		if got := procTerminal(r, pid); got != want {
			t.Errorf("pid %d: %v, want %v", pid, got, want)
		}
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "fake" }

var errFake = fakeErr{}

// commitAskEvaluator answers every event with an observe-mode ask, the
// shape of the commit-gate rules S-791 to S-794 (Observe: ask).
type commitAskEvaluator struct{ guard.Evaluator }

func (commitAskEvaluator) EvaluateHook(ev policy.Event) (guard.ActionVerdict, bool) {
	return guard.ActionVerdict{Verdict: policy.Verdict{
		RuleID: "S-791", Decision: policy.DecisionAsk, Severity: policy.SeverityHigh,
		Reason: "agent commit while a new high-confidence finding is open in this project",
	}}, true
}

// TestToolGateQ27Emission drives the real HandleToolGate with recorded
// live payload shapes (_spikes/jsp-6/live/) and an S-791-shaped ask, per
// host and column: a native ask only where the host can show it, a deny
// naming `observer guard approve` everywhere else.
func TestToolGateQ27Emission(t *testing.T) {
	commit := map[string]any{"command": "git commit -m wip"}
	claudeBody := mustJSON(t, map[string]any{"session_id": "s", "cwd": "/tmp/r", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": commit})
	geminiBody := mustJSON(t, map[string]any{"session_id": "s", "cwd": "/tmp/r", "hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": commit})
	qoderBody := mustJSON(t, map[string]any{"session_id": "s", "cwd": "/tmp/r", "hook_event_name": "PreToolUse", "permission_mode": "bypassPermissions", "tool_name": "Bash", "tool_input": commit})
	codexBody := mustJSON(t, map[string]any{"session_id": "s", "cwd": "/tmp/r", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": commit})
	cases := []struct {
		name    string
		req     ToolGateRequest
		canAsk  bool
		wantAsk bool
	}{
		{"claude interactive", ToolGateRequest{Tool: models.ToolClaudeCode, Dialect: ToolGateDialectClaudeCode, NativeEvent: "PreToolUse", Body: claudeBody}, true, true},
		{"claude headless", ToolGateRequest{Tool: models.ToolClaudeCode, Dialect: ToolGateDialectClaudeCode, NativeEvent: "PreToolUse", Body: claudeBody}, false, false},
		// Qoder's binding lists no ask (1.1.65 ran an ask under --yolo; no
		// interactive turn measured on a current build): a deny either way.
		{"qoder interactive", ToolGateRequest{Tool: models.ToolQoder, Dialect: ToolGateDialectClaudeJSON, NativeEvent: "PreToolUse", Body: qoderBody}, true, false},
		{"qoder headless", ToolGateRequest{Tool: models.ToolQoder, Dialect: ToolGateDialectClaudeJSON, NativeEvent: "PreToolUse", Body: qoderBody}, false, false},
		{"gemini terminal", ToolGateRequest{Tool: models.ToolGeminiCLI, Dialect: ToolGateDialectGemini, NativeEvent: "BeforeTool", Body: geminiBody}, true, true},
		{"gemini headless", ToolGateRequest{Tool: models.ToolGeminiCLI, Dialect: ToolGateDialectGemini, NativeEvent: "BeforeTool", Body: geminiBody}, false, false},
		// Codex cannot ask at all: a deny whatever the probe says.
		{"codex", ToolGateRequest{Tool: models.ToolCodex, Dialect: ToolGateDialectClaudeJSON, NativeEvent: "PreToolUse", Body: codexBody}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := askHostProbeFn
			askHostProbeFn = func(string) (bool, bool) { return tc.canAsk, true }
			defer func() { askHostProbeFn = old }()
			var out, errb bytes.Buffer
			res := HandleToolGate(tc.req, commitAskEvaluator{}, nil, &out, &errb)
			if !res.Replied {
				t.Fatalf("no block reply (stdout %q, stderr %q)", out.String(), errb.String())
			}
			reply := out.String()
			isAsk := strings.Contains(reply, `"ask"`)
			if isAsk != tc.wantAsk {
				t.Fatalf("reply %s: ask=%v, want %v", reply, isAsk, tc.wantAsk)
			}
			if !tc.wantAsk && !strings.Contains(reply, "observer guard approve") {
				t.Fatalf("deny does not name observer guard approve: %s", reply)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
