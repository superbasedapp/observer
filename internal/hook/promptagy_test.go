package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// agyTranscript writes a transcript.jsonl shaped like the one grounded on
// demo node 1 (a USER_INPUT step wrapped in <USER_REQUEST>, then model
// steps) and returns its path.
func agyTranscript(t *testing.T, prompts ...string) string {
	t.Helper()
	return agyTranscriptNamed(t, "transcript.jsonl", prompts...)
}

// agyTranscriptNamed is agyTranscript with the file name agy chose: agy
// 1.2.16 wrote transcript.jsonl, agy 1.3.0 points PreInvocation at
// transcript_full.jsonl (demo node 1, 2026-10-06, T-476).
func agyTranscriptNamed(t *testing.T, name string, prompts ...string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "brain", "conv-1", ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i, p := range prompts {
		user, _ := json.Marshal(map[string]any{"step_index": i * 2, "source": "USER_EXPLICIT", "type": "USER_INPUT", "status": "DONE", "content": "<USER_REQUEST>\n" + p + "\n</USER_REQUEST>"})
		model, _ := json.Marshal(map[string]any{"step_index": i*2 + 1, "source": "MODEL", "type": "PLANNER_RESPONSE", "status": "DONE"})
		b.Write(user)
		b.WriteByte('\n')
		b.Write(model)
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func agyPayload(t *testing.T, transcript string) []byte {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"invocationNum": 0, "conversationId": "conv-1", "transcriptPath": transcript, "modelName": "gemini-3.6-flash"})
	return body
}

func TestExtractAntigravityPreInvocationPrompt(t *testing.T) {
	t.Parallel()
	path := agyTranscript(t, "first prompt", "push with the token please")
	prompt, sid, ok, missing := extractAntigravityPreInvocationPrompt(agyPayload(t, path))
	if !ok || missing || sid != "conv-1" || prompt != "push with the token please" {
		t.Fatalf("got (%q, %q, ok=%v, missing=%v), want the LATEST user input unwrapped", prompt, sid, ok, missing)
	}
	full := agyTranscriptNamed(t, "transcript_full.jsonl", "a prompt agy 1.3.0 wrote")
	if prompt, _, ok, _ := extractAntigravityPreInvocationPrompt(agyPayload(t, full)); !ok || prompt != "a prompt agy 1.3.0 wrote" {
		t.Fatalf("transcript_full.jsonl: got (%q, ok=%v), want the agy 1.3.0 prompt", prompt, ok)
	}
	cases := map[string]string{
		"no transcript path":  "",
		"not transcript.json": filepath.Join(filepath.Dir(path), "other.jsonl"),
		"missing file":        filepath.Join(t.TempDir(), "transcript.jsonl"),
	}
	for name, p := range cases {
		if _, _, ok, _ := extractAntigravityPreInvocationPrompt(agyPayload(t, p)); ok {
			t.Errorf("%s: want ok=false (no scan, capture lane covers it)", name)
		}
	}
}

// judgedEvaluator is a stubPromptEvaluator that also answers
// PromptAlreadyJudged and PromptSessionStopped.
type judgedEvaluator struct {
	stubPromptEvaluator
	judged bool
	calls  int
	// stop, when non-empty, is the conversation's earlier stopped prompt.
	stop       guard.PromptSessionStop
	stopChecks int
}

func (j *judgedEvaluator) PromptAlreadyJudged(string, string, time.Time) bool {
	j.calls++
	return j.judged
}

func (j *judgedEvaluator) PromptSessionStopped(tool, sessionID string) (guard.PromptSessionStop, bool) {
	j.stopChecks++
	return j.stop, j.stop.RuleID != "" && tool == models.ToolAntigravityCLI && sessionID == "conv-1"
}

// withAgyHost runs fn with the agy host probes replaced: chain is the
// hook's ancestor chain (nil: unreadable) and version what `agy --version`
// answers ("" unknown). Not parallel-safe: callers do not t.Parallel().
func withAgyHost(t *testing.T, chain []procInfo, version string) {
	t.Helper()
	oldAnc, oldVer := hostAncestry, agyVersionProbe
	hostAncestry = func() ([]procInfo, bool) { return chain, chain != nil }
	agyVersionProbe = func(string) (string, bool) { return version, version != "" }
	t.Cleanup(func() { hostAncestry, agyVersionProbe = oldAnc, oldVer })
}

// interactiveAgy is an ancestor chain whose agy runs the interactive TUI.
var interactiveAgy = []procInfo{
	{PID: 300, Argv: []string{"/bin/sh", "-c", "observer hook antigravity-cli PreInvocation"}, Exe: "/bin/dash"},
	{PID: 200, Argv: []string{"agy"}, Exe: "/home/u/.local/bin/agy"},
}

// TestHandlePromptSubmitGuarded_AntigravityPreInvocation pins the agy
// seam (guard-enforcement fix, 2026-10-15): a flag warns the DEVELOPER (a
// userMessage step) and the model (an ephemeralMessage), with no toast; a
// deny or an ask on an agy proven to abort is the abort {"injectSteps":[{}]}
// with a silent-block toast (ask has no confirm or resend here, so its
// ladder lands on block); an older or unidentified agy degrades the block
// to the warning; a prompt already judged is skipped; a clean prompt replies
// {} with no lookup; and a conversation that already carries a stopped
// prompt is aborted again whatever its new prompt says.
func TestHandlePromptSubmitGuarded_AntigravityPreInvocation(t *testing.T) {
	path := agyTranscript(t, "push with the token please")
	finding := []policy.SecretFinding{{Type: "github_pat_fine", Hash: "h"}}
	verdict := func(d policy.Decision, o guard.PromptOutcome) guard.PromptVerdict {
		return guard.PromptVerdict{
			Verdict: policy.Verdict{Decision: d, RuleID: "R-172", Severity: policy.SeverityCritical, Reason: "detected github_pat_fine in the prompt text"},
			Outcome: o,
		}
	}
	ask := verdict(policy.DecisionAsk, guard.PromptOutcomeBlocked)
	deny := verdict(policy.DecisionDeny, guard.PromptOutcomeBlocked)
	flag := verdict(policy.DecisionFlag, guard.PromptOutcomeWarned)
	const abort = `{"injectSteps":[{}]}` + "\n"
	cases := []struct {
		name        string
		chain       []procInfo
		version     string
		ev          *judgedEvaluator
		wantAction  guard.PromptAction
		wantWanted  guard.PromptAction
		wantStdout  string // exact, when set
		wantNotice  bool   // a userMessage + ephemeralMessage warning
		wantPersist bool
		wantSilent  bool
		wantLookups int
		wantDegrade string
	}{
		{
			name: "flag warns the developer and the model", chain: interactiveAgy, version: "1.3.5",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: flag}},
			wantAction: guard.PromptActionWarn, wantNotice: true, wantPersist: true, wantLookups: 1,
		},
		{
			name: "deny aborts the turn on agy 1.3.5", chain: interactiveAgy, version: "1.3.5",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: deny}},
			wantAction: guard.PromptActionBlock, wantStdout: abort, wantPersist: true, wantSilent: true, wantLookups: 1,
		},
		{
			name: "ask lands on block (no confirm, no resend)", chain: interactiveAgy, version: "1.4.0",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: ask}},
			wantAction: guard.PromptActionBlock, wantWanted: guard.PromptActionConfirm, wantStdout: abort, wantPersist: true, wantSilent: true, wantLookups: 1,
		},
		{
			name: "older agy degrades the block to the warning", chain: interactiveAgy, version: "1.3.0",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: deny}},
			wantAction: guard.PromptActionWarn, wantWanted: guard.PromptActionBlock, wantNotice: true, wantPersist: true, wantLookups: 1,
		},
		{
			name: "no agy ancestor degrades the block to the warning", chain: nil, version: "1.3.5",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: deny}},
			wantAction: guard.PromptActionWarn, wantWanted: guard.PromptActionBlock, wantNotice: true, wantPersist: true, wantLookups: 1,
		},
		{
			name: "already judged: skipped", chain: interactiveAgy, version: "1.3.5",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{secrets: finding, verdict: deny}, judged: true},
			wantStdout: "{}\n", wantLookups: 1,
		},
		{
			name: "clean prompt: no lookup", chain: interactiveAgy, version: "1.3.5",
			ev:         &judgedEvaluator{stubPromptEvaluator: stubPromptEvaluator{verdict: allowVerdict()}},
			wantStdout: "{}\n",
		},
		{
			name: "tainted conversation aborts a clean prompt", chain: interactiveAgy, version: "1.3.5",
			ev: &judgedEvaluator{
				stubPromptEvaluator: stubPromptEvaluator{verdict: allowVerdict()},
				stop:                guard.PromptSessionStop{RuleID: "R-172", Severity: "critical"},
			},
			wantAction: guard.PromptActionBlock, wantStdout: abort, wantPersist: true, wantSilent: true,
			wantDegrade: guard.DegradedFromTaintedSession,
		},
		{
			name: "tainted conversation on an older agy is judged on its own prompt", chain: interactiveAgy, version: "1.2.16",
			ev: &judgedEvaluator{
				stubPromptEvaluator: stubPromptEvaluator{verdict: allowVerdict()},
				stop:                guard.PromptSessionStop{RuleID: "R-172", Severity: "critical"},
			},
			wantStdout: "{}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withAgyHost(t, tc.chain, tc.version)
			var stdout bytes.Buffer
			var got guard.PromptVerdict
			var gotEm guard.Emission
			persisted := false
			handled, after, exit := HandlePromptSubmitGuarded(models.ToolAntigravityCLI, PromptDialectAntigravityPreInvocation, "PreInvocation",
				agyPayload(t, path), false, tc.ev,
				func(pv guard.PromptVerdict, em guard.Emission, _ string) { got, gotEm, persisted = pv, em, true }, &stdout, io.Discard)
			if !handled || exit != 0 {
				t.Fatalf("handled=%v exit=%d, want handled with exit 0 (the reply carries the block)", handled, exit)
			}
			if after != nil {
				after()
			}
			if persisted != tc.wantPersist || tc.ev.calls != tc.wantLookups || tc.ev.stopChecks != 1 {
				t.Fatalf("persisted=%v lookups=%d stopChecks=%d, want %v/%d/1", persisted, tc.ev.calls, tc.ev.stopChecks, tc.wantPersist, tc.wantLookups)
			}
			out := stdout.String()
			if tc.wantStdout != "" && out != tc.wantStdout {
				t.Fatalf("stdout = %q, want %q", out, tc.wantStdout)
			}
			if tc.wantNotice {
				var r agyPreInvocationReply
				if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.InjectSteps) != 2 ||
					!strings.HasPrefix(r.InjectSteps[0].UserMessage, "SuperBased Observer: detected github_pat_fine") ||
					r.InjectSteps[0].EphemeralMessage != "" || r.InjectSteps[1].UserMessage != "" ||
					!strings.Contains(r.InjectSteps[1].EphemeralMessage, "Do not repeat, store, or use the flagged value") {
					t.Fatalf("warning reply = %q (err %v)", out, err)
				}
			}
			if !tc.wantPersist {
				return
			}
			if got.Action != tc.wantAction || got.ActionDegradedFrom != tc.wantWanted || got.Lane != "hook" ||
				got.WarnIndirect || (tc.wantSilent && !got.BlockSilent) || got.DegradedFrom != tc.wantDegrade {
				t.Errorf("verdict = action %q wanted %q lane %q indirect %v silent %v degraded %q, want %q/%q/hook/false/%v/%q",
					got.Action, got.ActionDegradedFrom, got.Lane, got.WarnIndirect, got.BlockSilent, got.DegradedFrom,
					tc.wantAction, tc.wantWanted, tc.wantSilent, tc.wantDegrade)
			}
			if wantPerm := map[bool]string{true: "deny", false: "allow"}[tc.wantAction == guard.PromptActionBlock]; gotEm.Permission != wantPerm {
				t.Errorf("emission permission = %q, want %q", gotEm.Permission, wantPerm)
			}
			if strings.Contains(out, "github_pat_11") {
				t.Errorf("reply leaks the value: %q", out)
			}
		})
	}
}

// TestBuildAntigravityPreInvocationReply pins each outcome's wire shape.
func TestBuildAntigravityPreInvocationReply(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		out  promptReplyOutcome
		want string
	}{
		{"allow", promptReplyOutcome{}, `{}`},
		{"block is the empty step", promptReplyOutcome{Blocking: true, Reason: "observer: x"}, `{"injectSteps":[{}]}`},
		{
			"warn is a userMessage then an ephemeralMessage",
			promptReplyOutcome{Warn: true, Reason: "observer: found y (forwarded)"},
			`{"injectSteps":[{"userMessage":"SuperBased Observer: found y (forwarded)"},` +
				`{"ephemeralMessage":"SuperBased Observer guard notice for the user: observer: found y (forwarded) The user has been shown this notice. Do not repeat, store, or use the flagged value."}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(buildAntigravityPreInvocationReply(tc.out))
			if err != nil || string(b) != tc.want {
				t.Fatalf("reply = %s (err %v), want %s", b, err, tc.want)
			}
		})
	}
}

func TestRegisterAntigravityCLI(t *testing.T) {
	t.Parallel()
	r := genericSettingsRegistry(t, filepath.Join(".gemini", "config"))
	path := filepath.Join(r.opts.HomeDir, ".gemini", "config", "hooks.json")
	// A foreign hook name plus a stale observer PreInvocation entry an
	// earlier version wrote (timeout 10): it is refreshed to the current
	// entry (T-476 restored PreInvocation on agy 1.3.0).
	seed := `{"reminder":{"PreInvocation":[{"type":"command","command":"./r.sh"}]},` +
		`"superbased-observer":{"enabled":true,"PreInvocation":[{"type":"command","command":"/opt/observer/bin/observer hook antigravity-cli PreInvocation","timeout":10}]}}`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("antigravity-cli")
	if res.Error != nil || strings.Join(res.HooksAdded, ",") != "PreToolUse,PreInvocation" {
		t.Fatalf("Register = %+v", res)
	}
	raw, _ := os.ReadFile(path)
	var top map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("hooks.json not valid: %v\n%s", err, raw)
	}
	mine := top[agyObserverHookName]
	var pre []agyHookHandler
	if err := json.Unmarshal(mine["PreInvocation"], &pre); err != nil || len(pre) != 1 ||
		pre[0].Command != "/opt/observer/bin/observer hook antigravity-cli PreInvocation" ||
		pre[0].Timeout != agyToolGateTimeoutSeconds {
		t.Fatalf("PreInvocation entry not refreshed: %v\n%s", err, raw)
	}
	var groups []agyHookGroup
	if err := json.Unmarshal(mine["PreToolUse"], &groups); err != nil {
		t.Fatalf("PreToolUse not matcher groups: %v\n%s", err, raw)
	}
	want := "/opt/observer/bin/observer hook antigravity-cli PreToolUse"
	if string(mine["enabled"]) != "true" || len(groups) != 1 || groups[0].Matcher != "*" ||
		len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != want ||
		groups[0].Hooks[0].Timeout != agyToolGateTimeoutSeconds {
		t.Fatalf("observer hook = %s", raw)
	}
	if !strings.Contains(string(raw), `"./r.sh"`) {
		t.Fatalf("foreign hook name not preserved: %s", raw)
	}
	if again := r.Register("antigravity-cli"); again.Error != nil || len(again.AlreadySet) != 2 {
		t.Fatalf("re-register = %+v, want AlreadySet", again)
	}
	un := r.Unregister("antigravity-cli")
	if un.Error != nil || len(un.HooksRemoved) != 2 {
		t.Fatalf("Unregister = %+v", un)
	}
	raw, _ = os.ReadFile(path)
	if strings.Contains(string(raw), agyObserverHookName) || !strings.Contains(string(raw), "./r.sh") {
		t.Fatalf("after unregister: %s", raw)
	}
}

// TestInstalledDetectsAntigravityCLI pins the auto-register signal for the
// agy hook (demo node 1, 2026-10-03: it was never written
// because Installed() did not list the tool).
func TestInstalledDetectsAntigravityCLI(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "antigravity-cli"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{BinaryPath: "/x", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range r.Installed() {
		if tool == "antigravity-cli" {
			return
		}
	}
	t.Errorf("Installed()=%v does not include antigravity-cli", r.Installed())
}
