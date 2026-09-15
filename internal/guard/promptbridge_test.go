package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestActionVerdictFromPrompt_NeverLeaksRawValue is the Part B item 4
// canary: the matched value, any prefix/suffix of it, the raw prompt
// text, or a per-span hash must NEVER reach Reason, Verdict.Reason
// (which store.PersistGuardVerdicts copies verbatim into both
// guard_events.reason AND, via sha256Hex(Target)/Target itself,
// target_hash/target_excerpt). Only detector type/count summaries
// (already content-free by construction — SummarizePIIFindings/
// SummarizeSecretFindings never touch f.Value) and the opaque
// whole-finding-set fingerprint may appear.
func TestActionVerdictFromPrompt_NeverLeaksRawValue(t *testing.T) {
	t.Parallel()
	const secretValue = "sk-ant-api03-SUPERSECRETVALUENEVERSTORED"
	const rawPrompt = "please use this key: " + secretValue + " to call the API"

	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(newMemPromptStore().funcs())

	secrets, pii, _ := g.BuildPromptFindings(rawPrompt)
	if len(secrets) == 0 {
		t.Fatalf("test setup: expected a secret finding in %q", rawPrompt)
	}
	ev := promptEvent("s1", secrets, pii)
	pv := g.EvaluatePrompt(ev)
	if pv.Fingerprint == "" {
		t.Fatalf("test setup: expected a fingerprint on the first interrupt, got %+v", pv)
	}

	em := ResolveEmission(pv.Verdict, ev.Caps)
	av := g.ActionVerdictFromPrompt(pv, em, ActionInput{
		SessionID: "s1", Tool: "claude-code",
		ActionType: "user_prompt",
		// Deliberately populate Target with the RAW PROMPT the way a
		// generic hook/watcher-path Input would carry a command or file
		// path — ActionVerdictFromPrompt must OVERWRITE this with the
		// fingerprint, never let the caller's raw text survive through.
		Target: rawPrompt,
	})

	if av.Input.Target != pv.Fingerprint {
		t.Fatalf("Input.Target = %q, want the fingerprint %q (never the raw prompt)", av.Input.Target, pv.Fingerprint)
	}
	if strings.Contains(av.Input.Target, secretValue) {
		t.Fatalf("Input.Target leaked the secret value: %q", av.Input.Target)
	}
	if strings.Contains(av.Verdict.Reason, secretValue) {
		t.Fatalf("Verdict.Reason leaked the secret value: %q", av.Verdict.Reason)
	}
	if strings.Contains(av.Verdict.Reason, rawPrompt) {
		t.Fatalf("Verdict.Reason leaked the raw prompt: %q", av.Verdict.Reason)
	}
	// The reason must still be USEFUL: it names the detector type, not
	// just "something happened".
	if !strings.Contains(av.Verdict.Reason, "api_key_prefixed") {
		t.Errorf("Verdict.Reason = %q, want it to name the detector type", av.Verdict.Reason)
	}
	if !strings.Contains(av.Verdict.Reason, "[outcome=") {
		t.Errorf("Verdict.Reason = %q, want the item-4 outcome disambiguation suffix", av.Verdict.Reason)
	}
	if av.Kind != policy.KindUserPrompt {
		t.Errorf("Kind = %q, want KindUserPrompt", av.Kind)
	}
}

// TestActionVerdictFromPrompt_SuppressAlert pins FIX-3 (phase-2
// review): SuppressAlert is keyed on the RESOLVED wire permission
// (em.Permission), not on Severity — a fresh ask-once secret
// interrupt (R-172, SeverityCritical) must not double-toast, but a
// genuine hard deny (mode=block, or an ask degraded to deny by a
// CanAsk:false channel like Devin) must still alert.
func TestActionVerdictFromPrompt_SuppressAlert(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)

	cases := []struct {
		name           string
		permission     string
		wantSuppressed bool
	}{
		{"ask: routine ask-once already shown in-band", "ask", true},
		{"allow: warn/confirmed/approved, non-blocking", "allow", true},
		{"deny: genuine hard block toasts", "deny", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pv := PromptVerdict{
				Verdict: policy.Verdict{RuleID: "R-172", Severity: policy.SeverityCritical, Decision: policy.DecisionAsk, Reason: "detected github_pat×1"},
				Outcome: PromptOutcomeBlocked,
			}
			em := Emission{Permission: tc.permission}
			av := g.ActionVerdictFromPrompt(pv, em, ActionInput{SessionID: "s1", Tool: "claude-code"})
			if av.SuppressAlert != tc.wantSuppressed {
				t.Errorf("SuppressAlert = %v, want %v for permission=%q", av.SuppressAlert, tc.wantSuppressed, tc.permission)
			}
		})
	}
}

// TestActionVerdictFromPrompt_CombinesDegradedFrom pins the DegradedFrom
// OR logic: the reconsider engine's own marker and ResolveEmission's
// channel-capability marker are independent sources that must not
// silently clobber one another.
func TestActionVerdictFromPrompt_CombinesDegradedFrom(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		pvFrom, emFrom string
		want           string
	}{
		{"neither", "", "", ""},
		{"pv only", "ask", "", "ask"},
		{"em only", "", "deny", "deny"},
		{"both same", "ask", "ask", "ask"},
		{"both different", "ask", "deny", "ask+deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := combineDegradedFrom(c.pvFrom, c.emFrom)
			if got != c.want {
				t.Errorf("combineDegradedFrom(%q, %q) = %q, want %q", c.pvFrom, c.emFrom, got, c.want)
			}
		})
	}
}
