package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Guard-enforcement fix (2026-10-15) lane C tests: agy host detection,
// agy PreToolUse force_ask, the tool-gate flag notice field, the ask that
// can only be stopped, and the droid writer's equivalence keep.

// fakeProc is an in-memory /proc for walkAncestry.
type fakeProc map[string]string

func (f fakeProc) reader() procReader {
	return procReader{
		root: "/proc",
		readFile: func(name string) ([]byte, error) {
			v, ok := f[name]
			if !ok {
				return nil, errors.New("no such file")
			}
			return []byte(v), nil
		},
		readlink: func(name string) (string, error) {
			v, ok := f[name]
			if !ok {
				return "", errors.New("no such link")
			}
			return v, nil
		},
	}
}

func TestWalkAncestry(t *testing.T) {
	t.Parallel()
	procs := fakeProc{
		"/proc/300/cmdline": "/bin/sh\x00-c\x00observer hook antigravity-cli PreToolUse\x00",
		"/proc/300/exe":     "/usr/bin/dash",
		"/proc/300/status":  "Name:\tsh\nPPid:\t200\n",
		"/proc/200/cmdline": "agy\x00--dangerously-skip-permissions\x00",
		"/proc/200/exe":     "/home/u/.local/bin/agy (deleted)",
		"/proc/200/status":  "Name:\tagy\nPPid:\t1\n",
	}
	cases := []struct {
		name    string
		start   int
		wantOK  bool
		wantPID []int
		wantExe string
	}{
		{"walks to init", 300, true, []int{300, 200}, "/home/u/.local/bin/agy"},
		{"unreadable start is unknown", 999, false, nil, ""},
		{"init itself is never walked", 1, false, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, ok := walkAncestry(procs.reader(), tc.start)
			if ok != tc.wantOK || len(chain) != len(tc.wantPID) {
				t.Fatalf("walkAncestry = %+v ok=%v", chain, ok)
			}
			for i, p := range chain {
				if p.PID != tc.wantPID[i] {
					t.Fatalf("chain[%d].PID = %d, want %d", i, p.PID, tc.wantPID[i])
				}
			}
			if tc.wantExe != "" && chain[len(chain)-1].Exe != tc.wantExe {
				t.Fatalf("agy exe = %q, want %q (the (deleted) suffix trimmed)", chain[len(chain)-1].Exe, tc.wantExe)
			}
		})
	}
}

func TestAgyNativeAskAvailable(t *testing.T) {
	t.Parallel()
	shell := procInfo{PID: 300, Argv: []string{"/bin/sh", "-c", "observer hook antigravity-cli PreToolUse"}}
	agy := func(args ...string) procInfo {
		return procInfo{PID: 200, Argv: append([]string{"agy"}, args...), Exe: "/home/u/.local/bin/agy"}
	}
	cases := []struct {
		name  string
		chain []procInfo
		ok    bool
		want  bool
	}{
		{"interactive agy", []procInfo{shell, agy()}, true, true},
		{"interactive agy with a model flag", []procInfo{shell, agy("--model", "gemini-3.6-flash")}, true, true},
		{"--dangerously-skip-permissions runs force_ask", []procInfo{shell, agy("--dangerously-skip-permissions")}, true, false},
		{"headless -p auto-denies force_ask", []procInfo{shell, agy("-p", "do it")}, true, false},
		{"--print", []procInfo{shell, agy("--print=do it")}, true, false},
		{"--yolo", []procInfo{shell, agy("--yolo")}, true, false},
		{"agy found by exe only", []procInfo{shell, {PID: 200, Argv: []string{"/opt/agy/bin/agy-linux"}, Exe: "/opt/agy/bin/agy"}}, true, true},
		{"no agy ancestor (desktop app, IDE)", []procInfo{shell, {PID: 10, Argv: []string{"/opt/Antigravity/antigravity"}}}, true, false},
		{"ancestry unreadable", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agyNativeAskAvailable(tc.chain, tc.ok); got != tc.want {
				t.Fatalf("agyNativeAskAvailable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAgyAbortSupported(t *testing.T) {
	t.Parallel()
	chain := []procInfo{{PID: 200, Argv: []string{"agy"}, Exe: "/home/u/.local/bin/agy"}}
	cases := []struct {
		name    string
		chain   []procInfo
		ok      bool
		version string
		want    bool
	}{
		{"proven version", chain, true, "agy 1.3.5", true},
		{"newer version", chain, true, "1.10.0", true},
		{"older version", chain, true, "1.3.0", false},
		{"unparseable version", chain, true, "dev build", false},
		{"probe failed", chain, true, "", false},
		{"no agy ancestor", []procInfo{{PID: 5, Argv: []string{"bash"}}}, true, "1.3.5", false},
		{"ancestry unreadable", nil, false, "1.3.5", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked string
			got := agyAbortSupported(tc.chain, tc.ok, func(exe string) (string, bool) {
				asked = exe
				return tc.version, tc.version != ""
			})
			if got != tc.want {
				t.Fatalf("agyAbortSupported = %v, want %v", got, tc.want)
			}
			if tc.want && asked != "/home/u/.local/bin/agy" {
				t.Fatalf("version probed on %q, want the agy executable", asked)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	t.Parallel()
	cases := []struct {
		have, want string
		ok         bool
	}{
		{"1.3.5", "1.3.5", true},
		{"1.3.6", "1.3.5", true},
		{"2.0.0", "1.3.5", true},
		{"1.3.4", "1.3.5", false},
		{"1.2.16", "1.3.5", false},
		{"agy version 1.3.5 (abc)", "1.3.5", true},
		{"none", "1.3.5", false},
	}
	for _, tc := range cases {
		if got := versionAtLeast(tc.have, tc.want); got != tc.ok {
			t.Errorf("versionAtLeast(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}

// TestAgyToolGateAskFollowsHost pins agy's PreToolUse ask: force_ask with
// the reason under an interactive agy, and a deny that says how to confirm
// wherever force_ask would not reach a developer. Not parallel: it replaces
// the host probe.
func TestAgyToolGateAskFollowsHost(t *testing.T) {
	body := []byte(`{"conversationId":"s1","workspacePaths":["/home/u/proj"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"/home/u/.ssh/x","CodeContent":"k"}}}`)
	denyReply := fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", confirmLine("this file access")+ruleReason)
	cases := []struct {
		name  string
		chain []procInfo
		want  string
	}{
		{"interactive agy gets the native force_ask", interactiveAgy, fmt.Sprintf(`{"decision":"force_ask","reason":%q}`+"\n", ruleReason)},
		{"--dangerously-skip-permissions denies", []procInfo{{PID: 2, Argv: []string{"agy", "--dangerously-skip-permissions"}}}, denyReply},
		{"headless -p denies", []procInfo{{PID: 2, Argv: []string{"agy", "-p", "x"}}}, denyReply},
		{"unknown host denies", nil, denyReply},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withAgyHost(t, tc.chain, "1.3.5")
			var out bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: models.ToolAntigravityCLI, Dialect: ToolGateDialectAntigravity, NativeEvent: "PreToolUse",
				Label: "antigravity-cli:PreToolUse", Body: body,
			}, &targetEvaluator{askOn: ".ssh"}, nil, &out, &bytes.Buffer{})
			if !res.Replied || out.String() != tc.want {
				t.Fatalf("reply = %q (replied %v), want %q", out.String(), res.Replied, tc.want)
			}
		})
	}
}

// flagEvaluator flags every event.
type flagEvaluator struct{}

func (flagEvaluator) EvaluateHook(ev policy.Event) (guard.ActionVerdict, bool) {
	return guard.ActionVerdict{
		Input: guard.ActionInput{SessionID: ev.SessionID, Tool: ev.Tool, Target: ev.Target},
		Kind:  ev.Kind,
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag, RuleID: "R-150", Severity: policy.SeverityWarn,
			Reason: "flagged thing.", Source: "builtin",
		},
	}, true
}

// TestToolGateFlagWarnField pins the flag notice: a tool gate whose binding
// declares a developer-visible WarnField carries the humanized reason in its
// allow; one that declares none stays silent (and still records).
func TestToolGateFlagWarnField(t *testing.T) {
	t.Parallel()
	const notice = "SuperBased Observer flagged this tool call (R-150): flagged thing."
	cases := []struct {
		name      string
		tool      string
		dialect   string
		event     string
		body      []byte
		wantField string
		wantAllow string // WriteToolGateAllowWarn output
	}{
		{
			"claude-code systemMessage", models.ToolClaudeCode, ToolGateDialectClaudeCode, "PreToolUse",
			toolPayload("s1", "Bash", map[string]any{"command": "ls"}), "systemMessage", "",
		},
		{
			"codex systemMessage on the empty-object allow", models.ToolCodex, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "Bash", map[string]any{"command": "ls"}), "systemMessage", `{"systemMessage":"` + notice + `"}` + "\n",
		},
		{
			"droid systemMessage", models.ToolDroid, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "Bash", map[string]any{"command": "ls"}), "systemMessage", `{"systemMessage":"` + notice + `"}` + "\n",
		},
		{
			"qwen-code systemMessage", models.ToolQwenCode, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "run_shell_command", map[string]any{"command": "ls"}), "systemMessage", `{"systemMessage":"` + notice + `"}` + "\n",
		},
		{
			"gemini-cli systemMessage", models.ToolGeminiCLI, ToolGateDialectGemini, "BeforeTool",
			toolPayload("s1", "run_shell_command", map[string]any{"command": "ls"}), "systemMessage", `{"systemMessage":"` + notice + `"}` + "\n",
		},
		{
			"qoder declares none: silent", models.ToolQoder, ToolGateDialectClaudeJSON, "PreToolUse",
			toolPayload("s1", "Bash", map[string]any{"command": "ls"}), "", "{}\n",
		},
		{
			"antigravity allow is silence: no field", models.ToolAntigravityCLI, ToolGateDialectAntigravity, "PreToolUse",
			[]byte(`{"conversationId":"s1","toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}`), "", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: tc.tool, Dialect: tc.dialect, NativeEvent: tc.event, Label: tc.tool, Body: tc.body,
			}, flagEvaluator{}, nil, &out, &bytes.Buffer{})
			if res.Replied || out.Len() != 0 {
				t.Fatalf("a flag must not reply (got %q)", out.String())
			}
			if res.RecordAfterReply == nil {
				t.Fatalf("a flag must still record")
			}
			if res.WarnField != tc.wantField || (tc.wantField != "" && res.Warn != notice) || (tc.wantField == "" && res.Warn != "") {
				t.Fatalf("warn = %q/%q, want field %q", res.WarnField, res.Warn, tc.wantField)
			}
			var allow bytes.Buffer
			WriteToolGateAllowWarn(tc.dialect, res.WarnField, res.Warn, &allow)
			if allow.String() != tc.wantAllow {
				t.Fatalf("allow = %q, want %q", allow.String(), tc.wantAllow)
			}
		})
	}
}

func TestWithWarnField(t *testing.T) {
	t.Parallel()
	type approve struct {
		Decision string `json:"decision"`
		Continue bool   `json:"continue"`
	}
	base := approve{Decision: "approve", Continue: true}
	cases := []struct {
		name, field, warn, want string
	}{
		{"no notice keeps the reply", "", "", `{"decision":"approve","continue":true}`},
		{"no field keeps the reply", "", "x", `{"decision":"approve","continue":true}`},
		{"notice added", "systemMessage", "x", `{"continue":true,"decision":"approve","systemMessage":"x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(WithWarnField(base, tc.field, tc.warn))
			if string(b) != tc.want {
				t.Fatalf("got %s, want %s", b, tc.want)
			}
		})
	}
}

// TestPromptHouseMessageAskStopped pins the ask a seam could only stop: no
// "send it again" story.
func TestPromptHouseMessageAskStopped(t *testing.T) {
	t.Parallel()
	pv := guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-172", Reason: "detected github_pat_fine in the prompt text"},
		Outcome: guard.PromptOutcomeBlocked, Action: guard.PromptActionBlock, Detectors: "github_pat_fine",
	}
	got := promptHouseMessage(pv, "conv-1")
	if !strings.HasSuffix(got, promptAskStoppedSuffix) || strings.Contains(got, "Send it again") {
		t.Fatalf("house message = %q", got)
	}
	pv.Action = guard.PromptActionReenter
	if got := promptHouseMessage(pv, "conv-1"); !strings.Contains(got, "Send it again unchanged to confirm") {
		t.Fatalf("re-enter house message = %q", got)
	}
	tainted := guard.TaintedSessionPromptVerdict(guard.PromptSessionStop{RuleID: "R-172", Severity: "critical"})
	tainted.Action = guard.PromptActionBlock
	if got := promptHouseMessage(tainted, "conv-1"); !strings.HasSuffix(got, "Start a new conversation.") {
		t.Fatalf("tainted house message = %q", got)
	}
}

// TestDroidRegisterKeepsEquivalentEntry pins the droid writer's T-725 keep:
// an Observer entry from another (working) install path counts as set, so
// the doctor / `observer guard prompt status` probe no longer reports NOT
// REGISTERED for a UserPromptSubmit entry `observer start` never refreshed.
func TestDroidRegisterKeepsEquivalentEntry(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".factory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := "/old/install/observer"
	seed := `{"UserPromptSubmit":[{"matcher":"*","hooks":[{"type":"command","command":"` + old + ` hook droid UserPromptSubmit"}]}],` +
		`"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + old + ` hook droid PreToolUse"}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	works := func(p string) bool { return p == old || p == "/new/observer" }
	cases := []struct {
		name        string
		keep        bool
		works       func(string) bool
		wantAlready string
	}{
		{"equivalent entry kept and counted as set", true, works, "PreToolUse,UserPromptSubmit"},
		{"broken entry is rewritten", true, func(string) bool { return false }, ""},
		{"without the keep option the drift is rewritten", false, works, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRegistry(Options{BinaryPath: "/new/observer", HomeDir: home, DryRun: true, KeepEquivalentHooks: tc.keep})
			if err != nil {
				t.Fatal(err)
			}
			r.opts.binaryWorks = tc.works
			res := r.Register("droid")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			already := append([]string(nil), res.AlreadySet...)
			sortStrings(already)
			if strings.Join(already, ",") != tc.wantAlready {
				t.Fatalf("AlreadySet = %v, want %q (added %v)", res.AlreadySet, tc.wantAlready, res.HooksAdded)
			}
		})
	}
}

// sortStrings sorts in place (a tiny local helper, keeps the import set
// small).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
