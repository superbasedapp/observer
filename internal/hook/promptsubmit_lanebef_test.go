package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Hook-parity Lane B (2026-10-03): the redact outcome on the two seams that
// can rewrite a prompt (Poolside updated_prompt, commandcode transform),
// and the Kimi Code / Devin CLI prompt dialects. Each row pins the exact
// reply bytes and exit code the vendor's documented contract expects.

// redactingStub is a stubPromptEvaluator that can also mask a prompt (the
// guard.Guard RedactPromptText capability).
type redactingStub struct {
	stubPromptEvaluator
	masked string
	ok     bool
	calls  int
}

func (r *redactingStub) RedactPromptText(string) (string, bool) {
	r.calls++
	return r.masked, r.ok
}

const laneBSecret = "github_pat_11AAAAAAAAAAAAAAAAAAAAAA_xxxxxxxx"

func redactRequestedVerdict(outcome guard.PromptOutcome, d policy.Decision) guard.PromptVerdict {
	return guard.PromptVerdict{
		Verdict:       policy.Verdict{Decision: d, RuleID: "R-172", Reason: "secret-shaped content in a prompt"},
		Outcome:       outcome,
		RequestedMode: guard.PromptModeRedact,
	}
}

func TestHandlePromptSubmitGuarded_RedactDialects(t *testing.T) {
	t.Parallel()
	secretFinding := []policy.SecretFinding{{Type: "github_pat", Certain: true, SpanLen: 40, Hash: "h"}}
	cases := []struct {
		name      string
		dialect   string
		body      string
		stub      *redactingStub
		wantOut   string // exact stdout ("" = nothing)
		wantExit  int
		wantRedac int // RedactPromptText calls
	}{
		{
			name:    "poolside redact-mode secret -> updated_prompt",
			dialect: PromptDialectPoolside,
			body:    `{"session_id":"s1","prompt":"use ` + laneBSecret + `"}`,
			stub: &redactingStub{
				stubPromptEvaluator: stubPromptEvaluator{secrets: secretFinding, verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionAsk)},
				masked:              "use [REDACTED:github_pat]", ok: true,
			},
			wantOut:   `{"hook_specific_output":{"updated_prompt":"use [REDACTED:github_pat]","additional_context":"observer: secret-shaped content in a prompt. The value was replaced with a [REDACTED] marker before the prompt reached the model."}}` + "\n",
			wantRedac: 1,
		},
		{
			name:    "commandcode redact-mode secret, no session id -> transform",
			dialect: PromptDialectCommandCode,
			body:    `{"text":"use ` + laneBSecret + `"}`,
			stub: &redactingStub{
				// No session id: the engine degrades the ask-once to a
				// no_session DENY, which a redact needs no key for.
				stubPromptEvaluator: stubPromptEvaluator{secrets: secretFinding, verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionDeny)},
				masked:              "use [REDACTED:github_pat]", ok: true,
			},
			wantOut:   `{"action":"transform","text":"use [REDACTED:github_pat]"}` + "\n",
			wantRedac: 1,
		},
		{
			name:    "poolside masking incomplete -> falls back to the block",
			dialect: PromptDialectPoolside,
			body:    `{"session_id":"s1","prompt":"use ` + laneBSecret + `"}`,
			stub: &redactingStub{
				stubPromptEvaluator: stubPromptEvaluator{secrets: secretFinding, verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionAsk)},
				ok:                  false,
			},
			wantOut:   "BLOCK",
			wantExit:  2,
			wantRedac: 1,
		},
		{
			name:    "poolside PII present -> no redact offered, block",
			dialect: PromptDialectPoolside,
			body:    `{"session_id":"s1","prompt":"card"}`,
			stub: &redactingStub{
				stubPromptEvaluator: stubPromptEvaluator{
					secrets: secretFinding, pii: []policy.PIIFinding{{Type: "credit_card", Hash: "p"}},
					verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionAsk),
				},
				masked: "x", ok: true,
			},
			wantOut:  "BLOCK",
			wantExit: 2,
		},
		{
			name:    "poolside ask-once mode (no redact requested) still blocks",
			dialect: PromptDialectPoolside,
			body:    `{"session_id":"s1","prompt":"use ` + laneBSecret + `"}`,
			stub: &redactingStub{
				stubPromptEvaluator: stubPromptEvaluator{secrets: secretFinding, verdict: askVerdict("secret")},
				masked:              "use [REDACTED:github_pat]", ok: true,
			},
			wantOut:   "BLOCK",
			wantExit:  2,
			wantRedac: 1,
		},
		{
			name:    "commandcode clean prompt -> continue",
			dialect: PromptDialectCommandCode,
			body:    `{"text":"hello"}`,
			stub:    &redactingStub{stubPromptEvaluator: stubPromptEvaluator{verdict: allowVerdict()}},
			wantOut: `{"action":"continue"}` + "\n",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			var persisted []guard.Emission
			handled, after, code := HandlePromptSubmitGuarded("tool", tc.dialect, "E", []byte(tc.body), false, tc.stub,
				func(_ guard.PromptVerdict, em guard.Emission, _ string) { persisted = append(persisted, em) }, &out, io.Discard)
			if !handled {
				t.Fatal("not handled")
			}
			if after != nil {
				after()
			}
			got := out.String()
			if tc.wantOut == "BLOCK" {
				if !strings.Contains(got, `"decision":"block"`) {
					t.Fatalf("want a block reply, got %q", got)
				}
			} else if got != tc.wantOut {
				t.Fatalf("stdout\n got %q\nwant %q", got, tc.wantOut)
			}
			if code != tc.wantExit {
				t.Fatalf("exit %d, want %d", code, tc.wantExit)
			}
			if tc.stub.calls != tc.wantRedac {
				t.Fatalf("RedactPromptText calls %d, want %d", tc.stub.calls, tc.wantRedac)
			}
			if tc.wantRedac == 1 && tc.stub.ok && tc.wantExit == 0 {
				if len(persisted) != 1 || persisted[0].Permission != "allow" || !persisted[0].Enforced {
					t.Fatalf("a redact persists one enforced allow, got %+v", persisted)
				}
			}
		})
	}
}

// TestHandlePromptSubmitGuarded_RedactNeedsCapability: a dialect without a
// redact builder never asks the guard to mask, even when redact mode is
// requested (Claude Code has no documented prompt rewrite).
func TestHandlePromptSubmitGuarded_RedactNeedsCapability(t *testing.T) {
	t.Parallel()
	stub := &redactingStub{
		stubPromptEvaluator: stubPromptEvaluator{
			secrets: []policy.SecretFinding{{Type: "github_pat", Certain: true, Hash: "h"}},
			verdict: redactRequestedVerdict(guard.PromptOutcomeBlocked, policy.DecisionAsk),
		},
		masked: "m", ok: true,
	}
	var out bytes.Buffer
	_, _, code := HandlePromptSubmitGuarded("tool", PromptDialectClaudeCode, "UserPromptSubmit",
		[]byte(`{"session_id":"s","prompt":"p"}`), false, stub, nil, &out, io.Discard)
	if stub.calls != 0 || code != 2 {
		t.Fatalf("claude-code must block (exit 2) without masking: calls=%d code=%d", stub.calls, code)
	}
}

// TestHandlePromptSubmitGuarded_KimiCode pins Kimi Code's exit-code
// dialect: a block is exit 2 with the reason on stderr and NOTHING on
// stdout; an allow is an empty stdout (any stdout would be appended to the
// model context as a <hook_result> message).
func TestHandlePromptSubmitGuarded_KimiCode(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"k1","session_title":"t","cwd":"/w","prompt":"use x","is_steer":false}`)

	stub := &stubPromptEvaluator{verdict: askVerdict("secret-shaped content")}
	var out, errb bytes.Buffer
	handled, _, code := HandlePromptSubmitGuarded("kimi-code", PromptDialectKimiCode, "UserPromptSubmit", body, false, stub, nil, &out, &errb)
	if !handled || code != 2 {
		t.Fatalf("block: handled=%v code=%d", handled, code)
	}
	if out.Len() != 0 {
		t.Fatalf("a Kimi block writes nothing to stdout, got %q", out.String())
	}
	if !strings.HasPrefix(errb.String(), "Blocked by Observer guard: observer: secret-shaped content") || strings.Contains(errb.String(), "observer-hook:") {
		t.Fatalf("stderr must be the house reason only, got %q", errb.String())
	}
	if stub.lastEvent.SessionID != "k1" {
		t.Fatalf("session id %q", stub.lastEvent.SessionID)
	}

	out.Reset()
	errb.Reset()
	handled, _, code = HandlePromptSubmitGuarded("kimi-code", PromptDialectKimiCode, "UserPromptSubmit", body, false,
		&stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, &errb)
	if !handled || code != 0 || out.Len() != 0 {
		t.Fatalf("allow: handled=%v code=%d stdout=%q", handled, code, out.String())
	}

	// A flag cannot be shown in band on Kimi (stdout would reach the model):
	// it goes through silently and is flagged after.
	out.Reset()
	handled, _, code = HandlePromptSubmitGuarded("kimi-code", PromptDialectKimiCode, "UserPromptSubmit", body, false,
		&stubPromptEvaluator{verdict: warnVerdict("pii")}, nil, &out, io.Discard)
	if !handled || code != 0 || out.Len() != 0 {
		t.Fatalf("flag: handled=%v code=%d stdout=%q", handled, code, out.String())
	}

	// HandlePromptAllow (the receiver's no-verdict path) is an empty stdout.
	out.Reset()
	HandlePromptAllow(PromptDialectKimiCode, "kimi-code:UserPromptSubmit", strings.NewReader("{}"), &out, io.Discard)
	if out.Len() != 0 {
		t.Fatalf("kimi allow must be empty, got %q", out.String())
	}
	if PromptDialectWritesStdout(PromptDialectKimiCode) {
		t.Fatal("kimi writes no stdout")
	}

	// T-378 live shape (kimi 2.1.1, demo node 1): prompt is a list of
	// content parts. Before the fix the string-only decode failed and the
	// receiver fell through to an unguarded allow.
	live := []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"session_a8","cwd":"/w","client_type":"kimi_code_cli","prompt":[{"type":"text","text":"Here is my token"}],"is_steer":false}`)
	stub = &stubPromptEvaluator{verdict: askVerdict("secret-shaped content")}
	out.Reset()
	errb.Reset()
	handled, _, code = HandlePromptSubmitGuarded("kimi-code", PromptDialectKimiCode, "UserPromptSubmit", live, false, stub, nil, &out, &errb)
	if !handled || code != 2 || out.Len() != 0 || stub.lastEvent.SessionID != "session_a8" {
		t.Fatalf("live list-shaped prompt: handled=%v code=%d stdout=%q session=%q", handled, code, out.String(), stub.lastEvent.SessionID)
	}
}

// TestExtractKimiCodePrompt walks the prompt shapes Kimi Code can send.
func TestExtractKimiCodePrompt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, want string
		ok, missing      bool
	}{
		{"live content parts", `{"session_id":"s","prompt":[{"type":"text","text":"a"}]}`, "a", true, false},
		{"several parts, an image skipped", `{"session_id":"s","prompt":[{"type":"text","text":"a"},{"type":"image","url":"x"},{"type":"text","text":"b"}]}`, "a\nb", true, false},
		{"plain string", `{"session_id":"s","prompt":"use x"}`, "use x", true, false},
		{"no prompt key", `{"session_id":"s"}`, "", true, true},
		{"null prompt", `{"session_id":"s","prompt":null}`, "", true, true},
		{"prompt of another shape", `{"session_id":"s","prompt":42}`, "", true, true},
		{"not json", `{"prompt":`, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ok, missing := extractKimiCodePrompt([]byte(tc.body))
			if got != tc.want || ok != tc.ok || missing != tc.missing {
				t.Errorf("got (%q, ok=%v, missing=%v), want (%q, %v, %v)", got, ok, missing, tc.want, tc.ok, tc.missing)
			}
		})
	}
}

// TestHandlePromptSubmitGuarded_DevinCLI pins Devin CLI's context-only
// dialect: a warning rides hookSpecificOutput.additionalContext (the
// agent's context), an ask or deny cannot stop the prompt and is flagged
// after, an allow is {}.
func TestHandlePromptSubmitGuarded_DevinCLI(t *testing.T) {
	t.Parallel()
	body := []byte(`{"session_id":"d1","prompt":"use x"}`)
	cases := []struct {
		name    string
		verdict guard.PromptVerdict
		want    string
	}{
		{"warn", warnVerdict("pii"), `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"observer: pii (forwarded; see ` + "`observer guard prompt status`" + `)."}}` + "\n"},
		{"ask degrades to a model warning", askVerdict("secret"), `{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalContext":"observer: secret (forwarded; see ` + "`observer guard prompt status`" + `)."}}` + "\n"},
		{"allow", allowVerdict(), "{}\n"},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		handled, _, code := HandlePromptSubmitGuarded("devin", PromptDialectDevinCLI, "UserPromptSubmit", body, false,
			&stubPromptEvaluator{verdict: tc.verdict}, nil, &out, io.Discard)
		if !handled || code != 0 {
			t.Fatalf("%s: handled=%v code=%d", tc.name, handled, code)
		}
		if out.String() != tc.want {
			t.Fatalf("%s:\n got %q\nwant %q", tc.name, out.String(), tc.want)
		}
	}
}

// TestLaneBDialectsFailureSemantics pins the failure contract of the new
// rows: garbage and truncated payloads, and the fail-closed reply the
// watchdog / panic guard would use under enforcement.
func TestLaneBDialectsFailureSemantics(t *testing.T) {
	t.Parallel()
	for _, d := range []string{PromptDialectKimiCode, PromptDialectDevinCLI} {
		var out bytes.Buffer
		// Garbage: not this dialect's JSON -> unhandled (the receiver's
		// own unparseable / fail-closed path decides).
		handled, _, _ := HandlePromptSubmitGuarded("t", d, "UserPromptSubmit", []byte(`not json`), false,
			&stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if handled {
			t.Fatalf("%s: garbage must not be handled", d)
		}
		// Truncated: stays in the guarded path with PromptTruncated set.
		stub := &stubPromptEvaluator{verdict: allowVerdict()}
		handled, _, _ = HandlePromptSubmitGuarded("t", d, "UserPromptSubmit", []byte(`{"session_id":"s","prompt":"ab`), true,
			stub, nil, &out, io.Discard)
		if !handled || !stub.lastEvent.PromptTruncated {
			t.Fatalf("%s: truncated body must reach the engine as truncated", d)
		}
	}
	// Kimi can fail closed: exit 2, reason on stderr, nothing on stdout.
	r, ok := BuildFailClosedReply(PromptDialectKimiCode, FailClosedTimeoutReason)
	if !ok || r.ExitCode != 2 || !r.StderrReason || r.Stdout != nil {
		t.Fatalf("kimi fail-closed reply %+v ok=%v", r, ok)
	}
	// Devin CLI cannot block, so it can never fail closed.
	if CanFailClosed(PromptDialectDevinCLI) {
		t.Fatal("devin-cli is warn-only and must stay fail-open")
	}
	// Redact-capable dialects keep their block as the fail-closed reply.
	r, ok = BuildFailClosedReply(PromptDialectCommandCode, FailClosedErrorReason)
	if !ok || !bytes.Contains(r.Stdout, []byte(`"action":"handled"`)) {
		t.Fatalf("commandcode fail-closed reply %+v ok=%v", r, ok)
	}
	var m map[string]any
	if err := json.Unmarshal(r.Stdout, &m); err != nil {
		t.Fatal(err)
	}
}
