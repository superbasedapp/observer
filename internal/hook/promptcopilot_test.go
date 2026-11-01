package hook

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestExtractCopilotCLIPrompt pins the live userPromptSubmitted payload
// (copilot 1.0.96, 2026-10-15): {sessionId, timestamp, cwd, prompt}.
func TestExtractCopilotCLIPrompt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body, prompt, sid string
		ok, missing             bool
	}{
		{"live payload", `{"sessionId":"eb75b827-c4cb","timestamp":1792012516047,"cwd":"/p","prompt":"plain hello"}`, "plain hello", "eb75b827-c4cb", true, false},
		{"snake session fallback", `{"session_id":"s1","prompt":"x"}`, "x", "s1", true, false},
		{"no session still parses", `{"prompt":"x"}`, "x", "", true, false},
		{"prompt field missing", `{"sessionId":"s1","text":"x"}`, "", "s1", true, true},
		{"not json", `nope`, "", "", false, false},
	}
	for _, c := range cases {
		p, sid, ok, missing := extractCopilotCLIPrompt([]byte(c.body))
		if p != c.prompt || sid != c.sid || ok != c.ok || missing != c.missing {
			t.Errorf("%s: got (%q, %q, %v, %v)", c.name, p, sid, ok, missing)
		}
	}
}

// TestHandlePromptSubmitGuarded_GuardFixLaneB walks the two new prompt
// dialects through the one decision x capability table: Copilot CLI can
// re-enter, block, redact and warn the model; the Cline plugin can block
// and redact only (a stop reason is shown nowhere).
func TestHandlePromptSubmitGuarded_GuardFixLaneB(t *testing.T) {
	t.Parallel()
	denyVerdict := guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-172", Reason: "secret-shaped content in a prompt"},
		Outcome: guard.PromptOutcomeBlocked,
	}
	cases := []struct {
		name       string
		tool       string
		dialect    string
		body       string
		verdict    guard.PromptVerdict
		wantAction guard.PromptAction
		wantOut    string // exact stdout
	}{
		{
			"copilot ask re-enters through handled + responseContent", models.ToolCopilotCLI, PromptDialectCopilotCLI,
			`{"sessionId":"s1","prompt":"use ` + laneBSecret + `"}`, askVerdict("detected github_pat"), guard.PromptActionReenter,
			"COPILOT_ASK",
		},
		{
			"copilot deny blocks and withholds the prompt from the history", models.ToolCopilotCLI, PromptDialectCopilotCLI,
			`{"sessionId":"s1","prompt":"use ` + laneBSecret + `"}`, denyVerdict, guard.PromptActionBlock,
			`{"handled":true,"responseContent":"observer: secret-shaped content in a prompt. Edit it out before sending. mode=\"block\" has no resend override.","modifiedPrompt":"[SuperBased Observer withheld this message from the model]"}` + "\n",
		},
		{
			"copilot flag warns the model (additionalContext)", models.ToolCopilotCLI, PromptDialectCopilotCLI,
			`{"sessionId":"s1","prompt":"x"}`, warnVerdict("detected github_pat"), guard.PromptActionWarn,
			`{"additionalContext":"observer: detected github_pat (forwarded; see ` + "`observer guard prompt status`" + `)."}` + "\n",
		},
		{
			"copilot clean prompt: the empty object", models.ToolCopilotCLI, PromptDialectCopilotCLI,
			`{"sessionId":"s1","prompt":"hello"}`, allowVerdict(), guard.PromptActionNone, "{}\n",
		},
		{
			"cline plugin ask cannot re-enter: block", models.ToolClineCLI, PromptDialectClinePlugin,
			`{"host":"cline-cli","event":"beforeModel","session_id":"s1","prompt":"use ` + laneBSecret + `"}`, askVerdict("detected github_pat"), guard.PromptActionBlock,
			"DENY",
		},
		{
			"cline plugin flag: recorded after (no developer channel)", models.ToolClineCLI, PromptDialectClinePlugin,
			`{"session_id":"s1","prompt":"x"}`, warnVerdict("detected github_pat"), guard.PromptActionFlagAfter,
			`{"decision":"allow"}` + "\n",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			var got guard.PromptVerdict
			handled, after, exit := HandlePromptSubmitGuarded(tc.tool, tc.dialect, "E", []byte(tc.body), false,
				&stubPromptEvaluator{verdict: tc.verdict},
				func(pv guard.PromptVerdict, _ guard.Emission, _ string) { got = pv }, &out, io.Discard)
			if !handled || exit != 0 {
				t.Fatalf("handled=%v exit=%d: neither host blocks on an exit code", handled, exit)
			}
			if after != nil {
				after()
				if got.Action != tc.wantAction {
					t.Errorf("action = %q, want %q", got.Action, tc.wantAction)
				}
			}
			switch tc.wantOut {
			case "COPILOT_ASK":
				for _, w := range []string{
					`{"handled":true,"responseContent":"observer: detected github_pat. Send it again unchanged to confirm, or edit it out.`,
					`--session s1`,
					`"modifiedPrompt":"[SuperBased Observer withheld this message from the model]"}`,
				} {
					if !strings.Contains(out.String(), w) {
						t.Errorf("stdout = %q, want it to contain %q", out.String(), w)
					}
				}
			case "DENY":
				if !strings.HasPrefix(out.String(), `{"decision":"deny","reason":"observer: `) {
					t.Errorf("stdout = %q, want a plugin deny", out.String())
				}
			default:
				if out.String() != tc.wantOut {
					t.Errorf("stdout\n got %q\nwant %q", out.String(), tc.wantOut)
				}
			}
			// responseContent and every other reply field reach the model on
			// later turns: none may carry the matched value.
			if strings.Contains(out.String(), laneBSecret) {
				t.Errorf("reply carries the prompt's secret: %q", out.String())
			}
		})
	}
}

// TestHandlePromptSubmitGuarded_GuardFixLaneBRedact: both new dialects
// rewrite a fully maskable prompt in redact mode.
func TestHandlePromptSubmitGuarded_GuardFixLaneBRedact(t *testing.T) {
	t.Parallel()
	secretFinding := []policy.SecretFinding{{Type: "github_pat", Certain: true, SpanLen: 40, Hash: "h"}}
	cases := []struct {
		dialect, body, want string
	}{
		{
			PromptDialectCopilotCLI, `{"sessionId":"s1","prompt":"use ` + laneBSecret + `"}`,
			`{"modifiedPrompt":"use [REDACTED:github_pat]","additionalContext":"observer: secret-shaped content in a prompt. The value was replaced with a [REDACTED] marker before the prompt reached the model."}` + "\n",
		},
		{
			PromptDialectClinePlugin, `{"session_id":"s1","prompt":"use ` + laneBSecret + `"}`,
			`{"decision":"modify","reason":"observer: secret-shaped content in a prompt. The value was replaced with a [REDACTED] marker before the prompt reached the model.","prompt":"use [REDACTED:github_pat]"}` + "\n",
		},
	}
	for _, tc := range cases {
		stub := &redactingStub{
			stubPromptEvaluator: stubPromptEvaluator{secrets: secretFinding, verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionAsk)},
			masked:              "use [REDACTED:github_pat]", ok: true,
		}
		var out bytes.Buffer
		handled, after, exit := HandlePromptSubmitGuarded("tool", tc.dialect, "E", []byte(tc.body), false, stub, nil, &out, io.Discard)
		if after != nil {
			after()
		}
		if !handled || exit != 0 || out.String() != tc.want {
			t.Errorf("%s: handled=%v exit=%d stdout\n got %q\nwant %q", tc.dialect, handled, exit, out.String(), tc.want)
		}
	}
}

// TestGuardFixLaneBFailClosedReplies: under enforcement a failed hook
// answers with the dialect's own block (no exit code on either host).
func TestGuardFixLaneBFailClosedReplies(t *testing.T) {
	t.Parallel()
	for dialect, want := range map[string]string{
		PromptDialectCopilotCLI:    `{"handled":true,"responseContent":"R","modifiedPrompt":"[SuperBased Observer withheld this message from the model]"}` + "\n",
		PromptDialectClinePlugin:   `{"decision":"deny","reason":"R"}` + "\n",
		ToolGateDialectClinePlugin: `{"decision":"deny","reason":"R"}` + "\n",
	} {
		r, ok := BuildFailClosedReply(dialect, "R")
		if !ok || string(r.Stdout) != want || r.ExitCode != 0 {
			t.Errorf("%s: fail-closed = %+v ok=%v (stdout %q), want %q exit 0", dialect, r, ok, r.Stdout, want)
		}
	}
}
