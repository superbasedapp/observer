package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// stubPromptEvaluator is a fake PromptEvaluator for unit-testing the
// dialect table + reply-shaping without a real *guard.Guard.
type stubPromptEvaluator struct {
	secrets   []policy.SecretFinding
	pii       []policy.PIIFinding
	truncated bool
	verdict   guard.PromptVerdict
	// lastEvent captures the Event EvaluatePrompt was called with, so
	// tests can assert the extraction/session-id wiring.
	lastEvent policy.Event
}

func (s *stubPromptEvaluator) BuildPromptFindings(text string) ([]policy.SecretFinding, []policy.PIIFinding, bool) {
	return s.secrets, s.pii, s.truncated
}

func (s *stubPromptEvaluator) EvaluatePrompt(ev policy.Event) guard.PromptVerdict {
	s.lastEvent = ev
	return s.verdict
}

func allowVerdict() guard.PromptVerdict {
	return guard.PromptVerdict{Verdict: policy.Verdict{Decision: policy.DecisionAllow}, Outcome: guard.PromptOutcomeAllowed}
}

func askVerdict(reason string) guard.PromptVerdict {
	return guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-190", Reason: reason},
		Outcome: guard.PromptOutcomeBlocked,
	}
}

func warnVerdict(reason string) guard.PromptVerdict {
	return guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionFlag, RuleID: "R-190", Reason: reason},
		Outcome: guard.PromptOutcomeWarned,
	}
}

// TestHandlePromptSubmitGuarded_UnknownDialectFallsThrough pins the
// fail-open contract: an unrecognized dialect or a nil evaluator
// returns handled=false so the caller's normal unguarded reply runs.
func TestHandlePromptSubmitGuarded_UnknownDialectFallsThrough(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	handled, after, _ := HandlePromptSubmitGuarded("claude-code", "bogus-dialect", "UserPromptSubmit",
		[]byte(`{"session_id":"s1","user_prompt":"hi"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
	if handled {
		t.Fatalf("unknown dialect must not be handled")
	}
	if after != nil {
		t.Fatalf("unknown dialect must not return a persist callback")
	}
	if out.Len() != 0 {
		t.Fatalf("unknown dialect must write nothing to stdout, got %q", out.String())
	}

	handled, _, _ = HandlePromptSubmitGuarded("claude-code", PromptDialectClaudeCode, "UserPromptSubmit",
		[]byte(`{"session_id":"s1","user_prompt":"hi"}`), false, nil, nil, &out, io.Discard)
	if handled {
		t.Fatalf("a nil evaluator must not be handled (fail-open)")
	}
}

// TestHandlePromptSubmitGuarded_BodyTruncatedDegradesInsteadOfBypass
// pins B2 (final-fix review): a body whose JSON was cut off mid-object
// by the CALLER's own stdin read limit (bodyTruncated=true) must fail
// d.extract's json.Unmarshal exactly like a genuinely unrecognized
// payload — but unlike that case, it must NOT fall through to
// handled=false (the caller's plain, unaudited approve reply). Before
// this fix, a >2 MB payload with a real secret anywhere past the read
// bound sailed through with zero findings, zero warning, and zero
// audit trail — see cmd/observer's readHookBodyDetectTruncation and
// the probe in the FINAL-FIX brief ("2.2 MB payload with sk-ant- in
// the first 100 bytes" silently produced {"decision":"approve"}).
func TestHandlePromptSubmitGuarded_BodyTruncatedDegradesInsteadOfBypass(t *testing.T) {
	t.Parallel()

	t.Run("truncated body stays handled and reaches the engine as PromptTruncated", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: warnVerdict("prompt exceeds the guard scan size limit")}
		var out bytes.Buffer
		// A body cut off mid-object — no dialect's json.Unmarshal will
		// parse this successfully.
		truncatedBody := []byte(`{"session_id":"s1","user_prompt":"my key is sk-ant-abc, and much more tex`)
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			truncatedBody, true, ev, nil, &out, io.Discard)
		if !handled {
			t.Fatalf("a body-truncated payload must stay handled (never the unguarded fallback), got handled=false")
		}
		if !ev.lastEvent.PromptTruncated {
			t.Errorf("PromptTruncated = false, want true for a caller-reported truncated body")
		}
		if ev.lastEvent.SessionID != "" {
			t.Errorf("SessionID = %q, want empty (extraction failed — the JSON never parsed)", ev.lastEvent.SessionID)
		}
		if after == nil {
			t.Fatalf("expected a non-nil recordAfterReply for a record-worthy (warn) verdict — the guard_events audit trail this fix restores")
		}
	})

	t.Run("non-truncated malformed body still falls through unguarded (unrelated bug, unchanged)", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: allowVerdict()}
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`not json at all`), false, ev, nil, &out, io.Discard)
		if handled {
			t.Fatalf("a genuinely malformed (not truncated) payload must still fall through to the caller's unguarded reply")
		}
	})

	t.Run("extraction succeeds but body was still truncated: real findings still drive the verdict, PromptTruncated still set", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")}
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","user_prompt":"card 4532015112830366"}`), true, ev, nil, &out, io.Discard)
		if !handled {
			t.Fatalf("expected handled=true")
		}
		if !ev.lastEvent.PromptTruncated {
			t.Errorf("PromptTruncated = false, want true even though extraction itself succeeded")
		}
		if ev.lastEvent.SessionID != "s1" {
			t.Errorf("SessionID = %q, want s1 (extraction succeeded, so the real session id must still be used)", ev.lastEvent.SessionID)
		}
		if after == nil {
			t.Fatalf("expected a non-nil recordAfterReply for the real credit_card finding")
		}
	})
}

// TestHandlePromptSubmitGuarded_BodyTruncatedRealEngineNeverSilentlyApproves
// is the end-to-end probe from the FINAL-FIX brief, run against a REAL
// guard.Guard (not a stub) with the shipped default posture
// (mode="ask-once"): a truncated body must never reply with the bare
// unguarded approve shape, and must still record a guard_events row.
func TestHandlePromptSubmitGuarded_BodyTruncatedRealEngineNeverSilentlyApproves(t *testing.T) {
	t.Parallel()
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{
			Enabled: true, Mode: "enforce",
			Prompt: config.GuardPromptConfig{
				Enabled: true, Mode: "ask-once", HookLane: true,
				EnforceIndependent: true, ReconsiderTTL: "30m", MaxFindings: 64,
			},
		},
		Home:     "/home/dev",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}

	var recorded []guard.PromptVerdict
	persist := func(pv guard.PromptVerdict, em guard.Emission, sessionID string) {
		recorded = append(recorded, pv)
	}
	var out bytes.Buffer
	// Simulates a >2 MiB payload cut off by the caller's read limit —
	// a real secret sits well inside the surviving prefix, but the
	// JSON never closes.
	truncatedBody := []byte(`{"session_id":"s1","user_prompt":"key sk-ant-abc123, and then megabytes more tex`)
	handled, after, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
		truncatedBody, true, g, persist, &out, io.Discard)
	if !handled {
		t.Fatalf("truncated body must stay handled, not fall through to the bare unguarded approve")
	}
	if bytes.Contains(out.Bytes(), []byte(`"decision":"approve"`)) {
		t.Fatalf("reply must not be the bare unguarded-fallback approve shape, got %s", out.String())
	}
	if after == nil {
		t.Fatalf("expected a non-nil recordAfterReply (RecordWorthy) for the degraded warn verdict")
	}
	after()
	if len(recorded) != 1 {
		t.Fatalf("expected exactly one recorded guard_events verdict, got %d", len(recorded))
	}
	if recorded[0].Outcome != guard.PromptOutcomeWarned {
		t.Errorf("Outcome = %v, want Warned (ask-once degrades an unscanned body to warn, never a silent allow)", recorded[0].Outcome)
	}
}

// TestHandlePromptSubmitGuarded_MissingIdentityFailsClosed pins B1
// (phase-3a review): a payload that parses fine for its dialect but
// carries no identity field (session_id / conversation_id /
// trajectory_id) at all must still reach the evaluator — NOT bounce
// to handled=false, which every real `observer hook` receiver treats
// as "fall through to the normal unguarded reply" (a silent, total
// scan bypass; probe repro: `{"prompt":"key sk-ant-…"}`). The engine
// itself already fails CLOSED on an empty SessionID
// (guard.EvaluatePrompt's "no_session" degrade, pinned by
// TestEvaluatePrompt_AskOnce_EmptySessionFailsClosedToBlock in
// internal/guard) — this test pins the hook-layer half: every
// affected dialect's extractor must hand that empty SessionID to the
// engine instead of eating the payload first.
func TestHandlePromptSubmitGuarded_MissingIdentityFailsClosed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		dialect string
		body    string
	}{
		{"claude-code", PromptDialectClaudeCode, `{"user_prompt":"key sk-ant-abc123"}`},
		{"top-level-block (droid/qwen-code/codex)", PromptDialectTopLevelBlock, `{"prompt":"key sk-ant-abc123"}`},
		{"cursor", PromptDialectCursor, `{"prompt":"key sk-ant-abc123"}`},
		{"gemini-cli", PromptDialectGemini, `{"prompt":"key sk-ant-abc123"}`},
		{"qoder", PromptDialectQoder, `{"prompt":"key sk-ant-abc123"}`},
		{"poolside", PromptDialectPoolside, `{"prompt":"key sk-ant-abc123"}`},
		{"zcode", PromptDialectZcode, `{"prompt":"key sk-ant-abc123"}`},
		{"cascade", PromptDialectCascade, `{"tool_info":{"user_prompt":"key sk-ant-abc123"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := &stubPromptEvaluator{verdict: allowVerdict()}
			var out bytes.Buffer
			handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, tc.dialect, "UserPromptSubmit",
				[]byte(tc.body), false, ev, nil, &out, io.Discard)
			if !handled {
				t.Fatalf("dialect %s: a missing identity field must NOT fall through unguarded (handled=false is a total bypass)", tc.dialect)
			}
			if ev.lastEvent.SessionID != "" {
				t.Errorf("dialect %s: SessionID = %q, want empty (engine degrades that, this extractor must not swallow it)", tc.dialect, ev.lastEvent.SessionID)
			}
			if ev.lastEvent.Kind != policy.KindUserPrompt {
				t.Errorf("dialect %s: the prompt must still reach the engine as a KindUserPrompt event", tc.dialect)
			}
		})
	}
}

// TestHandlePromptSubmitGuarded_ClaudeCode pins the exact wire shape
// after the 2026-09-07 LIVE CORRECTION: a block is exit code 2 with the
// house reason on stderr and NOTHING on stdout (Claude Code ignores
// permissionDecision on UserPromptSubmit — it is PreToolUse-only);
// allow/warn reply with the bare hookSpecificOutput envelope
// (+ additionalContext on warn); field name is user_prompt.
func TestHandlePromptSubmitGuarded_ClaudeCode(t *testing.T) {
	t.Parallel()

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")}
		var out, errOut bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","user_prompt":"my card is 4532015112830366"}`), false, ev, nil, &out, &errOut)
		if !handled {
			t.Fatalf("expected handled=true")
		}
		if after == nil {
			t.Fatalf("expected a non-nil recordAfterReply for a record-worthy verdict")
		}
		if exitCode != 2 {
			t.Errorf("exitCode = %d, want 2 (Claude Code blocks UserPromptSubmit via the process exit code only)", exitCode)
		}
		if out.Len() != 0 {
			t.Errorf("a block must write NOTHING to stdout — permissionDecision is PreToolUse-only and was ignored live: %q", out.String())
		}
		if errOut.Len() == 0 {
			t.Errorf("a block must carry the user-visible house reason on stderr (Claude Code shows exit-2 stderr to the user)")
		}
		if bytes.Contains(errOut.Bytes(), []byte("4532015112830366")) {
			t.Errorf("stderr leaked the matched value: %q", errOut.String())
		}
		if ev.lastEvent.SessionID != "s1" {
			t.Errorf("SessionID = %q, want s1", ev.lastEvent.SessionID)
		}
	})

	t.Run("allowed: writes an allow reply, no persist callback", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","user_prompt":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if !handled {
			t.Fatalf("expected handled=true")
		}
		if after != nil {
			t.Fatalf("expected a nil recordAfterReply for an allow verdict")
		}
		if exitCode != 0 {
			t.Errorf("exitCode = %d, want 0 on allow", exitCode)
		}
		var reply claudeCodePromptReply
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply did not parse: %v", err)
		}
		if reply.HookSpecificOutput.HookEventName != "UserPromptSubmit" {
			t.Errorf("hookEventName = %q, want UserPromptSubmit", reply.HookSpecificOutput.HookEventName)
		}
		if bytes.Contains(out.Bytes(), []byte(`permissionDecision`)) {
			t.Errorf("allow reply must not carry the PreToolUse-only permissionDecision field: %q", out.String())
		}
	})

	t.Run("warn: additionalContext carries the notice, still allowed", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","user_prompt":"my email is a@b.com"}`), false,
			&stubPromptEvaluator{verdict: warnVerdict("detected email×1 in the prompt text")}, nil, &out, io.Discard)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback for a warn (record-worthy) verdict")
		}
		var reply claudeCodePromptReply
		_ = json.Unmarshal(out.Bytes(), &reply)
		if bytes.Contains(out.Bytes(), []byte(`permissionDecision`)) {
			t.Errorf("a warn reply must not carry the PreToolUse-only permissionDecision field: %q", out.String())
		}
		if reply.HookSpecificOutput.AdditionalContext == "" {
			t.Errorf("a warn must carry a non-empty additionalContext notice")
		}
	})

	t.Run("unparseable payload falls through", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`not json`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if handled {
			t.Fatalf("unparseable payload must not be handled")
		}
	})

	t.Run("accepts the legacy prompt field this repo's own capture builder uses", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: allowVerdict()}
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","prompt":"hi via the legacy field"}`), false, ev, nil, &out, io.Discard)
		if !handled {
			t.Fatalf("expected handled=true for the legacy prompt field")
		}
	})

	t.Run("missing session_id still reaches the engine (B1)", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: allowVerdict()}
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
			[]byte(`{"user_prompt":"hi"}`), false, ev, nil, &out, io.Discard)
		// B1 (phase-3a review): a missing identity field must NOT make
		// this dialect fall through unguarded — that was a total scan
		// bypass. The engine (not this extractor) is the one that
		// fails closed on an empty SessionID; see
		// TestHandlePromptSubmitGuarded_MissingIdentityFailsClosed.
		if !handled {
			t.Fatalf("a payload with no session_id must still be handled (fail-closed lives in the engine, not here)")
		}
		if ev.lastEvent.SessionID != "" {
			t.Errorf("SessionID = %q, want empty", ev.lastEvent.SessionID)
		}
	})
}

// TestHandlePromptSubmitGuarded_TopLevelBlock pins the Codex/Droid/
// Qwen shared dialect (contract §6.2/§6.5/§6.6): the `prompt` field
// name, and the legacy {"decision":"block","reason":…} shape.
func TestHandlePromptSubmitGuarded_TopLevelBlock(t *testing.T) {
	t.Parallel()

	for _, tool := range []string{models.ToolCodex, models.ToolDroid, models.ToolQwenCode} {
		t.Run(tool, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			handled, after, _ := HandlePromptSubmitGuarded(tool, PromptDialectTopLevelBlock, "UserPromptSubmit",
				[]byte(`{"session_id":"s1","prompt":"my ssn is 245-11-1234"}`), false,
				&stubPromptEvaluator{verdict: askVerdict("detected us_ssn×1 in the prompt text")}, nil, &out, io.Discard)
			if !handled || after == nil {
				t.Fatalf("expected handled=true with a persist callback")
			}
			var reply promptTopLevelBlockOut
			if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
				t.Fatalf("reply did not parse: %v (%q)", err, out.String())
			}
			if reply.Decision != "block" {
				t.Errorf("decision = %q, want block", reply.Decision)
			}
			if reply.Reason == "" {
				t.Errorf("reason must be non-empty on a block")
			}
		})
	}

	t.Run("allowed: no decision field at all", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolCodex, PromptDialectTopLevelBlock, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","prompt":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if !handled || after != nil {
			t.Fatalf("expected handled=true with NO persist callback for an allow")
		}
		if bytes.Contains(out.Bytes(), []byte(`"decision"`)) {
			t.Errorf("an allow reply must carry no decision field: %q", out.String())
		}
	})
}

// TestHandlePromptSubmitGuarded_Cursor pins the wire-shape trap
// (contract §6.3): continue/user_message, NOT permission; session id
// comes from conversation_id.
func TestHandlePromptSubmitGuarded_Cursor(t *testing.T) {
	t.Parallel()

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")}
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolCursor, PromptDialectCursor, "beforeSubmitPrompt",
			[]byte(`{"conversation_id":"c1","prompt":"card 4532015112830366"}`), false, ev, nil, &out, io.Discard)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback")
		}
		var reply promptCursorReply
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply did not parse: %v", err)
		}
		if reply.Continue {
			t.Errorf("Continue = true, want false on a block")
		}
		if reply.UserMessage == "" {
			t.Errorf("user_message must be non-empty on a block")
		}
		if bytes.Contains(out.Bytes(), []byte(`"permission"`)) {
			t.Errorf("cursor's prompt-submit reply must never carry the shell/MCP permission field: %q", out.String())
		}
		if ev.lastEvent.SessionID != "c1" {
			t.Errorf("SessionID = %q, want c1 (from conversation_id)", ev.lastEvent.SessionID)
		}
	})

	t.Run("allowed", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolCursor, PromptDialectCursor, "beforeSubmitPrompt",
			[]byte(`{"conversation_id":"c1","prompt":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if !handled || after != nil {
			t.Fatalf("expected handled=true, no persist callback")
		}
		var reply promptCursorReply
		_ = json.Unmarshal(out.Bytes(), &reply)
		if !reply.Continue {
			t.Errorf("Continue = false, want true on allow")
		}
	})
}

// TestHandlePromptSubmitGuarded_Gemini pins the decision+systemMessage
// dual-field shape (contract §6.4 — "set both").
func TestHandlePromptSubmitGuarded_Gemini(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	handled, after, _ := HandlePromptSubmitGuarded(models.ToolGeminiCLI, PromptDialectGemini, "BeforeAgent",
		[]byte(`{"session_id":"s1","prompt":"my ssn is 245-11-1234"}`), false,
		&stubPromptEvaluator{verdict: askVerdict("detected us_ssn×1 in the prompt text")}, nil, &out, io.Discard)
	if !handled || after == nil {
		t.Fatalf("expected handled=true with a persist callback")
	}
	var reply promptGeminiReply
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("reply did not parse: %v", err)
	}
	if reply.Decision != "deny" {
		t.Errorf("decision = %q, want deny", reply.Decision)
	}
	if reply.Reason == "" || reply.SystemMessage == "" {
		t.Errorf("both reason AND systemMessage must be set on a deny: reason=%q systemMessage=%q", reply.Reason, reply.SystemMessage)
	}
}

// TestHandlePromptSubmitGuarded_TruncatedFlowsThrough pins that the
// FIX-2 truncated signal from BuildPromptFindings reaches
// EvaluatePrompt via policy.Event.PromptTruncated.
func TestHandlePromptSubmitGuarded_TruncatedFlowsThrough(t *testing.T) {
	t.Parallel()
	ev := &stubPromptEvaluator{truncated: true, verdict: allowVerdict()}
	var out bytes.Buffer
	HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
		[]byte(`{"session_id":"s1","user_prompt":"hi"}`), false, ev, nil, &out, io.Discard)
	if !ev.lastEvent.PromptTruncated {
		t.Errorf("PromptTruncated did not flow through to the Event EvaluatePrompt received")
	}
}

// TestHandlePromptSubmitGuarded_FieldMissingFlowsThrough pins FIX-2
// (phase-2 review): every dialect's extractor must correctly
// distinguish "the prompt field is absent from the payload entirely"
// (schema drift — fieldMissing=true) from "the field is present with
// a genuinely empty value" (fieldMissing=false) — and the signal must
// reach EvaluatePrompt via policy.Event.PromptFieldMissing.
func TestHandlePromptSubmitGuarded_FieldMissingFlowsThrough(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		dialect       string
		body          string
		wantMissing   bool
		wantSessionID string
	}{
		{"claude-code: user_prompt and prompt both absent", PromptDialectClaudeCode, `{"session_id":"s1"}`, true, "s1"},
		{"claude-code: user_prompt present but empty is NOT missing", PromptDialectClaudeCode, `{"session_id":"s1","user_prompt":""}`, false, "s1"},
		{"claude-code: legacy prompt field present but empty is NOT missing", PromptDialectClaudeCode, `{"session_id":"s1","prompt":""}`, false, "s1"},
		{"top-level-block: prompt absent", PromptDialectTopLevelBlock, `{"session_id":"s1"}`, true, "s1"},
		{"top-level-block: prompt present but empty is NOT missing", PromptDialectTopLevelBlock, `{"session_id":"s1","prompt":""}`, false, "s1"},
		{"gemini: prompt absent", PromptDialectGemini, `{"session_id":"s1"}`, true, "s1"},
		{"cursor: prompt absent", PromptDialectCursor, `{"conversation_id":"c1"}`, true, "c1"},
		{"cursor: prompt present but empty is NOT missing", PromptDialectCursor, `{"conversation_id":"c1","prompt":""}`, false, "c1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := &stubPromptEvaluator{verdict: allowVerdict()}
			var out bytes.Buffer
			handled, _, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, tc.dialect, "UserPromptSubmit",
				[]byte(tc.body), false, ev, nil, &out, io.Discard)
			if !handled {
				t.Fatalf("expected handled=true")
			}
			if ev.lastEvent.PromptFieldMissing != tc.wantMissing {
				t.Errorf("PromptFieldMissing = %v, want %v", ev.lastEvent.PromptFieldMissing, tc.wantMissing)
			}
			if ev.lastEvent.SessionID != tc.wantSessionID {
				t.Errorf("SessionID = %q, want %q", ev.lastEvent.SessionID, tc.wantSessionID)
			}
		})
	}
}

// TestHandlePromptSubmitGuarded_PersistCallbackReceivesVerdict pins
// that recordAfterReply, when called, forwards the exact verdict/
// emission EvaluatePrompt/ResolveEmission produced.
func TestHandlePromptSubmitGuarded_PersistCallbackReceivesVerdict(t *testing.T) {
	t.Parallel()
	want := askVerdict("detected credit_card×1 in the prompt text")
	var out bytes.Buffer
	var gotPV guard.PromptVerdict
	var gotEm guard.Emission
	var gotSessionID string
	called := false
	_, after, _ := HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
		[]byte(`{"session_id":"s1","user_prompt":"card 4532015112830366"}`), false,
		&stubPromptEvaluator{verdict: want},
		func(pv guard.PromptVerdict, em guard.Emission, sessionID string) {
			called = true
			gotPV = pv
			gotEm = em
			gotSessionID = sessionID
		}, &out, io.Discard)
	if after == nil {
		t.Fatalf("expected a persist callback")
	}
	after()
	if !called {
		t.Fatalf("persist callback was never invoked")
	}
	if gotPV.Verdict.RuleID != "R-190" {
		t.Errorf("persisted verdict RuleID = %q, want R-190", gotPV.Verdict.RuleID)
	}
	if gotEm.Permission == "" {
		t.Errorf("persisted emission Permission is empty")
	}
	if gotSessionID != "s1" {
		t.Errorf("persisted sessionID = %q, want s1", gotSessionID)
	}
}

// TestPromptHouseMessage_BlockReasonsAreHonest pins FIX-5 (phase-2
// review): a Blocked+non-Ask verdict must render DIFFERENT,
// case-specific text depending on WHY it blocked unconditionally —
// previously every case rendered the same "you configured mode=block"
// suffix even when the real cause was an unhashable finding, a
// missing session id, an unwired reconsider store, or an oversize/
// schema-drift-degraded scan.
func TestPromptHouseMessage_BlockReasonsAreHonest(t *testing.T) {
	t.Parallel()
	base := func(degradedFrom string) guard.PromptVerdict {
		return guard.PromptVerdict{
			Verdict: policy.Verdict{Decision: policy.DecisionDeny, Reason: "detected credit_card×1 in the prompt text"},
			Outcome: guard.PromptOutcomeBlocked, DegradedFrom: degradedFrom,
		}
	}

	cases := []struct {
		name           string
		degradedFrom   string
		wantSubstrings []string
		wantAbsent     string
	}{
		{"genuine mode=block", "", []string{"mode=\"block\" has no resend override"}, ""},
		{"unhashable finding", "unhashable", []string{"can't be fingerprinted for a resend override"}, "mode=\"block\""},
		{"empty session id", "no_session", []string{"No session id was available"}, "mode=\"block\""},
		{"unwired reconsider store", "store_unwired", []string{"reconsider-once store isn't available"}, "mode=\"block\""},
		{"unscanned (oversize/field-missing)", "unscanned", nil, "mode=\"block\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := promptHouseMessage(base(tc.degradedFrom), "s1")
			if !strings.Contains(got, "detected credit_card") {
				t.Errorf("message = %q, want it to still contain the underlying Reason", got)
			}
			for _, want := range tc.wantSubstrings {
				if !strings.Contains(got, want) {
					t.Errorf("message = %q, want it to contain %q", got, want)
				}
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("message = %q, must NOT contain the generic %q text for this cause", got, tc.wantAbsent)
			}
		})
	}
}

// TestPromptHouseMessage_AskOnceRemediationInterpolatesDetectorAndSession
// pins F6 (phase-3a review): the ask-once in-band remediation text
// must contain the ACTUAL detector id and session id, not the literal,
// non-functional placeholder text "<detector>"/"<session>" (and a
// missing --session argument entirely) it used to render, and must
// state that the grant covers the whole rule class, not just the one
// detector named in the copy-pasteable command.
func TestPromptHouseMessage_AskOnceRemediationInterpolatesDetectorAndSession(t *testing.T) {
	t.Parallel()
	pv := guard.PromptVerdict{
		Verdict:   policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-172", Reason: "detected github_pat×1 in the prompt text"},
		Outcome:   guard.PromptOutcomeBlocked,
		Detectors: "github_pat",
	}
	got := promptHouseMessage(pv, "sess-42")
	if want := "observer guard prompt allow github_pat --session sess-42"; !strings.Contains(got, want) {
		t.Errorf("message = %q, want it to contain the copy-pasteable command %q", got, want)
	}
	if !strings.Contains(got, "rule class") {
		t.Errorf("message = %q, want a clause explaining the grant covers the whole rule class", got)
	}
	if strings.Contains(got, "<detector>") || strings.Contains(got, "<session>") {
		t.Errorf("message = %q, must not contain literal placeholder text when real values are available", got)
	}
}

// TestPromptHouseMessage_AskOnceRemediationFallsBackWhenEmpty is the
// defensive counterpart: Detectors/sessionID should never actually be
// empty on a fresh ask-once interrupt (the engine fails closed to
// block on an empty session id before it ever reaches Decision=Ask),
// but the rendering must not produce a malformed command (e.g. a
// trailing "--session " with nothing after it) if that invariant is
// ever violated.
func TestPromptHouseMessage_AskOnceRemediationFallsBackWhenEmpty(t *testing.T) {
	t.Parallel()
	pv := guard.PromptVerdict{
		Verdict: policy.Verdict{Decision: policy.DecisionAsk, RuleID: "R-172", Reason: "detected github_pat×1 in the prompt text"},
		Outcome: guard.PromptOutcomeBlocked,
	}
	got := promptHouseMessage(pv, "")
	if !strings.Contains(got, "<detector>") || !strings.Contains(got, "<session>") {
		t.Errorf("message = %q, want the placeholder fallback when Detectors/sessionID are empty", got)
	}
}

// TestPromptRemediationDetector_PicksFirstOfMultiple pins the
// multi-detector tie-break: a copy-pasteable command can only name one
// detector, so the first (alphabetically earliest, per
// promptDetectorsCSV's sort) wins.
func TestPromptRemediationDetector_PicksFirstOfMultiple(t *testing.T) {
	t.Parallel()
	if got := promptRemediationDetector("credit_card,us_ssn"); got != "credit_card" {
		t.Errorf("promptRemediationDetector(%q) = %q, want %q", "credit_card,us_ssn", got, "credit_card")
	}
	if got := promptRemediationDetector("github_pat"); got != "github_pat" {
		t.Errorf("promptRemediationDetector(%q) = %q, want %q", "github_pat", got, "github_pat")
	}
}

// TestHandlePromptSubmitGuarded_BlockedWritesForensics pins the
// phase-2-review NIT: a blocking verdict (deny or degraded-ask) must
// leave a crash-window forensics trail — a stderr line AND a
// hook-events.jsonl row — exactly like every other guarded channel
// (HandleGuarded, handleCursorPromptSubmit's logForensics). Before
// this fix, a prompt-submit block left NO trace at all if the process
// died between the stdout reply and the async DB persist.
func TestHandlePromptSubmitGuarded_BlockedWritesForensics(t *testing.T) {
	t.Parallel()
	// Pinned on the Cursor dialect (a JSON-reply dialect): since the
	// 2026-09-07 live correction Claude Code's stderr on a block IS the
	// user-visible house message (exit-2 stderr is shown to the user),
	// so the rule-ID forensic line is deliberately NOT written there —
	// its forensic record is the hook-events.jsonl row instead (see
	// TestHandlePromptSubmitGuarded_ClaudeCode/blocked).
	var out, errOut bytes.Buffer
	handled, _, _ := HandlePromptSubmitGuarded(models.ToolCursor, PromptDialectCursor, "beforeSubmitPrompt",
		[]byte(`{"conversation_id":"s1","prompt":"card 4532015112830366"}`), false,
		&stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")},
		nil, &out, &errOut)
	if !handled {
		t.Fatalf("expected handled=true")
	}
	if errOut.Len() == 0 {
		t.Errorf("expected a stderr forensics line on a blocking verdict, got none")
	}
	if !strings.Contains(errOut.String(), "R-190") {
		t.Errorf("stderr forensics line = %q, want it to name the rule ID", errOut.String())
	}
}

// TestHandlePromptSubmitGuarded_AllowedWritesNoForensics pins the
// converse: an allow (or a non-record-worthy) verdict must not spam
// stderr — forensics logging is reserved for the blocking case, same
// as HandleGuarded.
func TestHandlePromptSubmitGuarded_AllowedWritesNoForensics(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	HandlePromptSubmitGuarded(models.ToolClaudeCode, PromptDialectClaudeCode, "UserPromptSubmit",
		[]byte(`{"session_id":"s1","user_prompt":"hi"}`), false,
		&stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, &errOut)
	if errOut.Len() != 0 {
		t.Errorf("expected no stderr forensics on an allow verdict, got %q", errOut.String())
	}
}

// --- Part B item 2: the documented long-tail vendors (Qoder,
// Poolside, zcode, Devin/Cascade, commandcode).

// TestHandlePromptSubmitGuarded_Qoder pins Qoder's exit-code-only
// wire shape: NO JSON stdout reply, the house message on stderr
// verbatim (no forensics-line mixing — stderrReason suppresses it),
// and exitCode=2 on a block.
func TestHandlePromptSubmitGuarded_Qoder(t *testing.T) {
	t.Parallel()

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected api_key_prefixed×1 in the prompt text")}
		var out, errOut bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolQoder, PromptDialectQoder, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","prompt":"key sk-ant-xxx","hook_event_name":"UserPromptSubmit"}`), false, ev, nil, &out, &errOut)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback")
		}
		if exitCode != 2 {
			t.Errorf("exitCode = %d, want 2", exitCode)
		}
		if out.Len() != 0 {
			t.Errorf("expected NO stdout reply for Qoder, got %q", out.String())
		}
		if errOut.Len() == 0 {
			t.Errorf("expected the house message on stderr")
		}
		if bytes.Contains(errOut.Bytes(), []byte("observer-hook:")) {
			t.Errorf("forensics debug line must not leak into Qoder's user-visible stderr: %q", errOut.String())
		}
		if ev.lastEvent.SessionID != "s1" {
			t.Errorf("SessionID = %q, want s1", ev.lastEvent.SessionID)
		}
	})

	t.Run("allowed: no output at all", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolQoder, PromptDialectQoder, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","prompt":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, &errOut)
		if !handled || after != nil {
			t.Fatalf("expected handled=true with NO persist callback for an allow")
		}
		if exitCode != 0 {
			t.Errorf("exitCode = %d, want 0 on allow", exitCode)
		}
		if out.Len() != 0 || errOut.Len() != 0 {
			t.Errorf("expected no output at all on allow, got stdout=%q stderr=%q", out.String(), errOut.String())
		}
	})
}

// TestHandlePromptSubmitGuarded_Poolside pins Poolside's snake_case
// JSON decision shape (unlike every other JSON dialect here) and the
// redact fields staying unpopulated (not wired).
func TestHandlePromptSubmitGuarded_Poolside(t *testing.T) {
	t.Parallel()

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolPoolside, PromptDialectPoolside, "UserPromptSubmit",
			[]byte(`{"hook_api_version":"1.0","hook_event_name":"UserPromptSubmit","event_id":"e1","session_id":"s1","cwd":"/x","trajectory_path":"/t","prompt":"card 4532015112830366"}`), false,
			&stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")}, nil, &out, io.Discard)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback")
		}
		// F3 (phase-3a review): Poolside now dual-signals a block — the
		// JSON decision reply (checked below) is the primary signal,
		// and exit code 2 is a fail-closed, defense-in-depth fallback
		// (Poolside's own docs also document exit-2 blocking; see
		// promptPoolsideReply's doc comment and the promptDialects
		// table's PromptDialectPoolside row).
		if exitCode != 2 {
			t.Errorf("exitCode = %d, want 2 (Poolside dual-signals: JSON decision + exit-2 fallback)", exitCode)
		}
		var reply promptPoolsideReply
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply did not parse: %v (%q)", err, out.String())
		}
		if reply.Decision != "block" {
			t.Errorf("decision = %q, want block", reply.Decision)
		}
		if reply.Reason == "" {
			t.Errorf("reason must be non-empty on a block")
		}
		if bytes.Contains(out.Bytes(), []byte("updated_prompt")) {
			t.Errorf("redact lane must not be populated (not wired): %q", out.String())
		}
	})

	t.Run("allowed", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolPoolside, PromptDialectPoolside, "UserPromptSubmit",
			[]byte(`{"session_id":"s1","prompt":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if !handled || after != nil {
			t.Fatalf("expected handled=true with NO persist callback for an allow")
		}
		if bytes.Contains(out.Bytes(), []byte(`"decision"`)) {
			t.Errorf("an allow reply must carry no decision field: %q", out.String())
		}
	})
}

// TestHandlePromptSubmitGuarded_Zcode pins zcode's Claude-Code-shaped
// continue:false reply (camelCase hookSpecificOutput, unlike Poolside).
func TestHandlePromptSubmitGuarded_Zcode(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolZcode, PromptDialectZcode, "UserPromptSubmit",
		[]byte(`{"session_id":"s1","prompt":"my ssn is 245-11-1234","transcript_path":"/t","cwd":"/x","permission_mode":"default"}`), false,
		&stubPromptEvaluator{verdict: askVerdict("detected us_ssn×1 in the prompt text")}, nil, &out, io.Discard)
	if !handled || after == nil {
		t.Fatalf("expected handled=true with a persist callback")
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0 (zcode blocks via continue:false)", exitCode)
	}
	var reply promptZcodeOut
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("reply did not parse: %v (%q)", err, out.String())
	}
	if reply.Continue {
		t.Errorf("continue = true, want false on a block")
	}
	if reply.HookSpecificOutput == nil || reply.HookSpecificOutput.HookEventName != "UserPromptSubmit" {
		t.Errorf("hookSpecificOutput.hookEventName must be set: %+v", reply.HookSpecificOutput)
	}
}

// TestHandlePromptSubmitGuarded_Cascade pins Windsurf/Devin Desktop
// Cascade's pre_user_prompt shape: nested tool_info.user_prompt,
// trajectory_id as the session-scoping key, exit-code-only block with
// NO output written anywhere at all (unlike Qoder, which at least
// writes stderr).
func TestHandlePromptSubmitGuarded_Cascade(t *testing.T) {
	t.Parallel()

	t.Run("blocked: no output anywhere, exit 2", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected api_key_prefixed×1 in the prompt text")}
		var out, errOut bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolDevin, PromptDialectCascade, "pre_user_prompt",
			[]byte(`{"agent_action_name":"pre_user_prompt","trajectory_id":"t1","execution_id":"e1","tool_info":{"user_prompt":"key sk-ant-xxx"}}`), false,
			ev, nil, &out, &errOut)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback")
		}
		if exitCode != 2 {
			t.Errorf("exitCode = %d, want 2", exitCode)
		}
		if out.Len() != 0 {
			t.Errorf("expected NO stdout reply for Cascade, got %q", out.String())
		}
		if ev.lastEvent.SessionID != "t1" {
			t.Errorf("SessionID = %q, want t1 (from trajectory_id)", ev.lastEvent.SessionID)
		}
	})

	t.Run("missing trajectory_id still reaches the engine (B1)", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: allowVerdict()}
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolDevin, PromptDialectCascade, "pre_user_prompt",
			[]byte(`{"tool_info":{"user_prompt":"hi"}}`), false, ev, nil, &out, io.Discard)
		// B1 (phase-3a review): no trajectory_id must not fall through
		// unguarded — the engine fails closed on an empty SessionID
		// (see TestHandlePromptSubmitGuarded_MissingIdentityFailsClosed).
		if !handled {
			t.Errorf("expected handled=true even with no trajectory_id (fail-closed lives in the engine, not here)")
		}
		if ev.lastEvent.SessionID != "" {
			t.Errorf("SessionID = %q, want empty", ev.lastEvent.SessionID)
		}
	})
}

// TestHandlePromptSubmitGuarded_CommandCode pins the Mods SDK
// transformInput shape: the {text} input, no session id at all
// (sessionID always ""), and the action:'handled'/action:'continue'
// reply verbs.
func TestHandlePromptSubmitGuarded_CommandCode(t *testing.T) {
	t.Parallel()

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		ev := &stubPromptEvaluator{verdict: askVerdict("detected credit_card×1 in the prompt text")}
		var out bytes.Buffer
		handled, after, exitCode := HandlePromptSubmitGuarded(models.ToolCommandCode, PromptDialectCommandCode, "transformInput",
			[]byte(`{"text":"card 4532015112830366"}`), false, ev, nil, &out, io.Discard)
		if !handled || after == nil {
			t.Fatalf("expected handled=true with a persist callback")
		}
		if exitCode != 0 {
			t.Errorf("exitCode = %d, want 0 (commandcode blocks via action:'handled')", exitCode)
		}
		var reply promptCommandCodeOut
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply did not parse: %v (%q)", err, out.String())
		}
		if reply.Action != "handled" {
			t.Errorf("action = %q, want handled", reply.Action)
		}
		if reply.Message == "" {
			t.Errorf("message must be non-empty on a block")
		}
		if ev.lastEvent.SessionID != "" {
			t.Errorf("SessionID = %q, want empty — transformInput carries no session/conversation id at all", ev.lastEvent.SessionID)
		}
	})

	t.Run("allowed: explicit continue action", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, after, _ := HandlePromptSubmitGuarded(models.ToolCommandCode, PromptDialectCommandCode, "transformInput",
			[]byte(`{"text":"hello"}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if !handled || after != nil {
			t.Fatalf("expected handled=true with NO persist callback for an allow")
		}
		var reply promptCommandCodeOut
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatalf("reply did not parse: %v", err)
		}
		if reply.Action != "continue" {
			t.Errorf("action = %q, want continue", reply.Action)
		}
	})

	t.Run("no text key at all falls through unhandled", func(t *testing.T) {
		t.Parallel()
		var out bytes.Buffer
		handled, _, _ := HandlePromptSubmitGuarded(models.ToolCommandCode, PromptDialectCommandCode, "transformInput",
			[]byte(`{}`), false, &stubPromptEvaluator{verdict: allowVerdict()}, nil, &out, io.Discard)
		if handled {
			t.Errorf("expected handled=false with no text key present at all")
		}
	})
}
