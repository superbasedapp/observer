package guard

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// promptCfg builds an enforce-mode GuardConfig with [guard.prompt]
// enabled and a caller-supplied mode/detector map — the shared starting
// point for every EvaluatePrompt test below.
func promptCfg(globalMode, promptMode string, detectors map[string]string) config.GuardConfig {
	cfg := guardCfg()
	cfg.Mode = globalMode
	cfg.Prompt = config.GuardPromptConfig{
		Enabled:   true,
		Mode:      promptMode,
		HookLane:  true,
		ProxyLane: true,
		// Matches the production default (config.Default()) — FIX-8,
		// phase-2 review: the prompt lane acts on its own mode
		// regardless of the global [guard].mode observe/enforce gate.
		// A test exercising the OPT-OUT path sets this false directly
		// after calling promptCfg.
		EnforceIndependent: true,
		ReconsiderTTL:      "30m",
		MaxFindings:        64,
		Detectors:          detectors,
	}
	return cfg
}

// memPromptStore is an in-memory PromptReconsiderFuncs backing store
// for tests — a tiny stand-in for internal/store's real seam.
type memPromptStore struct {
	rows map[string]memPromptRow
}

type memPromptRow struct {
	sessionID, tool, detectors string
	warnedAt, expiresAt        time.Time
	confirmed                  bool
}

func newMemPromptStore() *memPromptStore {
	return &memPromptStore{rows: map[string]memPromptRow{}}
}

func (m *memPromptStore) funcs() PromptReconsiderFuncs {
	return PromptReconsiderFuncs{
		Lookup: func(fp string, now time.Time) (time.Time, bool, error) {
			r, ok := m.rows[fp]
			if !ok || !r.expiresAt.After(now) {
				return time.Time{}, false, nil
			}
			return r.warnedAt, true, nil
		},
		Record: func(fp, sessionID, tool, detectors string, warnedAt, expiresAt time.Time) error {
			m.rows[fp] = memPromptRow{sessionID: sessionID, tool: tool, detectors: detectors, warnedAt: warnedAt, expiresAt: expiresAt}
			return nil
		},
		Confirm: func(fp string, now time.Time) (bool, error) {
			r, ok := m.rows[fp]
			if !ok || !r.expiresAt.After(now) {
				return false, nil
			}
			r.confirmed = true
			m.rows[fp] = r
			return true, nil
		},
	}
}

// errPromptStore lets a test force a genuine store ERROR from any of
// the three reconsider-once seam funcs (round-2 review F3) — distinct
// from memPromptStore's ordinary miss/hit behavior.
type errPromptStore struct {
	lookupErr, recordErr, confirmErr error
}

func (e errPromptStore) funcs() PromptReconsiderFuncs {
	return PromptReconsiderFuncs{
		Lookup:  func(fp string, now time.Time) (time.Time, bool, error) { return time.Time{}, false, e.lookupErr },
		Record:  func(fp, sessionID, tool, detectors string, warnedAt, expiresAt time.Time) error { return e.recordErr },
		Confirm: func(fp string, now time.Time) (bool, error) { return false, e.confirmErr },
	}
}

func promptEvent(sessionID string, secrets []policy.SecretFinding, pii []policy.PIIFinding) policy.Event {
	return policy.Event{
		Kind:        policy.KindUserPrompt,
		Tool:        "claude-code",
		SessionID:   sessionID,
		ProjectRoot: "/home/u/proj",
		Secrets:     secrets,
		PIIFindings: pii,
		Caps:        policy.Capabilities{PreExecution: true, CanBlock: true},
		Now:         time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}
}

func creditCardFinding(hash string) policy.PIIFinding {
	return policy.PIIFinding{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: hash}
}

func TestEvaluatePrompt_NoFindings_Allowed(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, nil))
	if pv.Outcome != PromptOutcomeAllowed || pv.Verdict.Decision != policy.DecisionAllow {
		t.Fatalf("got %+v, want allowed/allow", pv)
	}
	if pv.RecordWorthy() {
		t.Errorf("a no-finding verdict must not be RecordWorthy")
	}
}

func TestEvaluatePrompt_GuardDisabled_Allowed(t *testing.T) {
	t.Parallel()
	cfg := promptCfg("enforce", "block", nil)
	cfg.Enabled = false
	g := newTestGuard(t, cfg, nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeAllowed {
		t.Fatalf("guard disabled: got %+v, want allowed", pv)
	}
}

func TestEvaluatePrompt_PromptFeatureDisabled_Allowed(t *testing.T) {
	t.Parallel()
	cfg := promptCfg("enforce", "block", nil)
	cfg.Prompt.Enabled = false
	g := newTestGuard(t, cfg, nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeAllowed {
		t.Fatalf("[guard.prompt].enabled=false: got %+v, want allowed", pv)
	}
}

func TestEvaluatePrompt_WarnMode(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "warn", nil), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("got %+v, want warned/flag", pv)
	}
	if !pv.RecordWorthy() {
		t.Errorf("a warn verdict must be RecordWorthy (decision=flag)")
	}
}

// TestEvaluatePrompt_ObserveModeStillActsByDefault pins FIX-8 (phase-2
// review): [guard.prompt].enforce_independent defaults true, so the
// prompt-submit lane acts on its OWN mode even when the global
// [guard].mode is "observe" (the fresh-install default everywhere
// else in guard) — the operator-friendly resolution of D2's "never
// blocks outside enforce" for this one feature specifically. Without
// this, [guard.prompt]'s own ask-once-by-default config would be
// silently inert on a fresh install.
func TestEvaluatePrompt_ObserveModeStillActsByDefault(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("observe", "block", nil), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("observe mode + EnforceIndependent (default true): got %+v, want blocked/deny per [guard.prompt].mode=block", pv)
	}
}

// TestEvaluatePrompt_ObserveModeCapsAtWarn_WhenEnforceIndependentFalse
// pins the OPT-OUT path: an operator who sets
// [guard.prompt].enforce_independent=false gets the SAME D2 behavior
// as every other guard channel — observe mode caps every outcome at
// warned, regardless of [guard.prompt].mode.
func TestEvaluatePrompt_ObserveModeCapsAtWarn_WhenEnforceIndependentFalse(t *testing.T) {
	t.Parallel()
	cfg := promptCfg("observe", "block", nil)
	cfg.Prompt.EnforceIndependent = false
	g := newTestGuard(t, cfg, nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("observe mode + EnforceIndependent=false: got %+v, want warned/flag even though [guard.prompt].mode=block", pv)
	}
}

func TestEvaluatePrompt_BlockMode(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("got %+v, want blocked/deny", pv)
	}
	if pv.Fingerprint != "" {
		t.Errorf("block mode never needs a fingerprint (no override channel), got %q", pv.Fingerprint)
	}
}

func TestEvaluatePrompt_AskOnce_FreshThenConfirmed(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(store.funcs())

	ev := promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")})

	first := g.EvaluatePrompt(ev)
	if first.Outcome != PromptOutcomeBlocked || first.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("first occurrence: got %+v, want blocked/ask", first)
	}
	if first.Fingerprint == "" {
		t.Fatalf("first occurrence must carry a fingerprint")
	}
	if len(store.rows) != 1 {
		t.Fatalf("expected exactly one reconsider row recorded, got %d", len(store.rows))
	}

	// Identical resend (same session, same finding set) within the TTL.
	second := g.EvaluatePrompt(ev)
	if second.Outcome != PromptOutcomeConfirmed || second.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("resend: got %+v, want confirmed/flag", second)
	}
	if second.DegradedFrom != "ask" {
		t.Errorf("resend DegradedFrom = %q, want %q", second.DegradedFrom, "ask")
	}
	if second.Fingerprint != first.Fingerprint {
		t.Errorf("resend fingerprint %q != first %q — identical findings must fingerprint identically", second.Fingerprint, first.Fingerprint)
	}
}

// TestEvaluatePrompt_AskOnce_EditedFindingDoesNotReuseGrant pins §5.2:
// a DIFFERENT finding set (the developer edited the value) must not
// be treated as a confirmation of the unrelated prior grant — it gets
// its own fresh interrupt.
func TestEvaluatePrompt_AskOnce_EditedFindingDoesNotReuseGrant(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(store.funcs())

	first := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if first.Outcome != PromptOutcomeBlocked {
		t.Fatalf("first: got %+v, want blocked", first)
	}

	edited := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h2-different-value")}))
	if edited.Outcome != PromptOutcomeBlocked || edited.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("edited value: got %+v, want a FRESH blocked/ask, not a reuse of the prior grant", edited)
	}
	if edited.Fingerprint == first.Fingerprint {
		t.Errorf("edited value produced the SAME fingerprint as the original — the state machine cannot distinguish edited from confirmed")
	}
}

func TestEvaluatePrompt_AskOnce_EmptySessionFailsClosedToBlock(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(store.funcs())

	pv := g.EvaluatePrompt(promptEvent("", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("empty session_id: got %+v, want a hard blocked/deny (fail-closed), never ask", pv)
	}
	if len(store.rows) != 0 {
		t.Errorf("empty session_id must never write a reconsider row (nothing to scope it to)")
	}
	// FIX-5 (phase-2 review): distinct marker from the unwired-store
	// case below, so the house message names the ACTUAL cause.
	if pv.DegradedFrom != "no_session" {
		t.Errorf("DegradedFrom = %q, want %q", pv.DegradedFrom, "no_session")
	}
}

func TestEvaluatePrompt_AskOnce_UnwiredStoreFailsClosedToBlock(t *testing.T) {
	t.Parallel()
	// No SetPromptReconsiderStore call — zero value.
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("unwired store: got %+v, want a hard blocked/deny (fail-closed), never ask", pv)
	}
	if pv.DegradedFrom != "store_unwired" {
		t.Errorf("DegradedFrom = %q, want %q", pv.DegradedFrom, "store_unwired")
	}
}

// TestEvaluatePrompt_SecretAskOnce_FreshConfirmedThenEdited pins the
// round-2 review B1 fix end-to-end: a hashable secret finding (an
// `sk-ant-…`-shaped API token, BuildPromptFindings' real output shape)
// behaves EXACTLY like a PII finding under ask-once — first submit
// asks with a reconsider row written, the identical resend confirms
// (DegradedFrom "ask"), and an edited value asks again with a fresh
// fingerprint. This replaces the old
// TestEvaluatePrompt_SecretFindingDegradesAskOnceToBlock, which pinned
// the phase-1 limitation this fix closes.
func TestEvaluatePrompt_SecretAskOnce_FreshConfirmedThenEdited(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(store.funcs())

	secrets, pii, _ := g.BuildPromptFindings("paste: sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz")
	if len(pii) != 0 {
		t.Fatalf("unexpected PII findings from an API-token-only prompt: %+v", pii)
	}
	found := false
	for _, s := range secrets {
		if s.Type == "api_key_prefixed" {
			found = true
			if s.Hash == "" {
				t.Fatal("BuildPromptFindings left Hash empty for a secret finding — B1 fix requires it populated")
			}
		}
	}
	if !found {
		t.Fatalf("BuildPromptFindings did not find the sk-ant- token: %+v", secrets)
	}

	first := g.EvaluatePrompt(promptEvent("s1", secrets, pii))
	if first.Outcome != PromptOutcomeBlocked || first.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("first sk-ant submit: got %+v, want blocked/ask (NOT degraded to a hard deny)", first)
	}
	if first.Fingerprint == "" {
		t.Fatal("first occurrence must carry a fingerprint")
	}
	if len(store.rows) != 1 {
		t.Fatalf("expected exactly one reconsider row recorded, got %d", len(store.rows))
	}

	// Identical resend confirms.
	second := g.EvaluatePrompt(promptEvent("s1", secrets, pii))
	if second.Outcome != PromptOutcomeConfirmed || second.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("resend: got %+v, want confirmed/flag", second)
	}
	if second.DegradedFrom != "ask" {
		t.Errorf("resend DegradedFrom = %q, want %q", second.DegradedFrom, "ask")
	}
	if second.Fingerprint != first.Fingerprint {
		t.Errorf("resend fingerprint %q != first %q", second.Fingerprint, first.Fingerprint)
	}

	// An edited key (different value) asks again — a FRESH interrupt,
	// not a reuse of the prior grant.
	editedSecrets, editedPII, _ := g.BuildPromptFindings("paste: sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
	edited := g.EvaluatePrompt(promptEvent("s1", editedSecrets, editedPII))
	if edited.Outcome != PromptOutcomeBlocked || edited.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("edited key: got %+v, want a FRESH blocked/ask", edited)
	}
	if edited.Fingerprint == first.Fingerprint {
		t.Errorf("edited key produced the SAME fingerprint as the original")
	}
}

// TestEvaluatePrompt_SecretWithEmptyHashDegradesToBlock pins the ONE
// remaining degrade-to-block case post round-2 review B1: a secret
// finding whose Hash the boundary left empty (e.g. a hand-built Event
// in a test, or a future boundary that can't compute one) still can't
// participate in the identical-resend refinement — this is now a
// general "unhashable finding" rule, not a secret-specific one.
func TestEvaluatePrompt_SecretWithEmptyHashDegradesToBlock(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(store.funcs())

	ev := promptEvent("s1", []policy.SecretFinding{{Type: "github_pat", Certain: true}}, nil)
	first := g.EvaluatePrompt(ev)
	if first.Outcome != PromptOutcomeBlocked || first.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("unhashable secret at ask-once: got %+v, want a hard blocked/deny (degraded), not ask", first)
	}
	if first.DegradedFrom != "unhashable" {
		t.Errorf("DegradedFrom = %q, want %q (FIX-5, phase-2 review)", first.DegradedFrom, "unhashable")
	}
	second := g.EvaluatePrompt(ev)
	if second.Outcome != PromptOutcomeBlocked || second.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("resend: got %+v, want block-every-time (no confirm path)", second)
	}
	if len(store.rows) != 0 {
		t.Errorf("an unhashable finding must never write a reconsider row (it cannot fingerprint)")
	}
}

// TestEvaluatePrompt_ReconsiderLookupError_DegradesToWarn pins round-2
// review F3: a genuine store ERROR (not a miss) degrades the whole
// decision to warn (forward + flag), never to block — a transient DB
// hiccup must not stop a developer's work — and surfaces via
// LoadIssues.
func TestEvaluatePrompt_ReconsiderLookupError_DegradesToWarn(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(errPromptStore{lookupErr: errors.New("db closed")}.funcs())

	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("lookup error: got %+v, want warned/flag (fail-OPEN on a store error, unlike the fail-closed miss/unwired cases)", pv)
	}
	if pv.DegradedFrom != "store_error" {
		t.Errorf("DegradedFrom = %q, want %q", pv.DegradedFrom, "store_error")
	}
	if len(g.LoadIssues()) == 0 {
		t.Error("a reconsider-store error must surface via LoadIssues")
	}
}

// TestEvaluatePrompt_ReconsiderRecordError_DegradesToWarn mirrors the
// lookup-error test for the Record step (a fresh miss that fails to
// persist).
func TestEvaluatePrompt_ReconsiderRecordError_DegradesToWarn(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	g.SetPromptReconsiderStore(errPromptStore{recordErr: errors.New("disk full")}.funcs())

	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("record error: got %+v, want warned/flag", pv)
	}
	if pv.DegradedFrom != "store_error" {
		t.Errorf("DegradedFrom = %q, want %q", pv.DegradedFrom, "store_error")
	}
}

// TestEvaluatePrompt_ReconsiderConfirmError_DegradesToWarn mirrors the
// lookup-error test for the Confirm step (an active row that fails to
// confirm).
func TestEvaluatePrompt_ReconsiderConfirmError_DegradesToWarn(t *testing.T) {
	t.Parallel()
	store := newMemPromptStore()
	g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
	funcs := store.funcs()
	funcs.Confirm = func(fp string, now time.Time) (bool, error) { return false, errors.New("db closed") }
	g.SetPromptReconsiderStore(funcs)

	ev := promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")})
	first := g.EvaluatePrompt(ev)
	if first.Outcome != PromptOutcomeBlocked {
		t.Fatalf("first: got %+v, want blocked (fresh ask-once)", first)
	}
	second := g.EvaluatePrompt(ev)
	if second.Outcome != PromptOutcomeWarned || second.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("confirm error on resend: got %+v, want warned/flag", second)
	}
	if second.DegradedFrom != "store_error" {
		t.Errorf("DegradedFrom = %q, want %q", second.DegradedFrom, "store_error")
	}
}

// TestEvaluatePrompt_PerDetectorModeEscalatesPastGlobal pins F7
// (phase-3a review, stricter-wins semantics): a per-detector override
// stricter than the global mode is HONORED, not clamped down to the
// global mode. This supersedes the original "never escalate past
// global" behavior (renamed from
// TestEvaluatePrompt_PerDetectorModeNeverEscalatesPastGlobal).
func TestEvaluatePrompt_PerDetectorModeEscalatesPastGlobal(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "warn", map[string]string{"credit_card": "block"}), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("global=warn, detector override=block: got %+v, want honored at blocked/deny", pv)
	}
}

// TestEvaluatePrompt_PerDetectorModeCannotRelaxBelowNonOffGlobal pins
// F7 (phase-3a review, stricter-wins semantics): the global mode is a
// FLOOR — a per-detector override LOOSER-BUT-NON-OFF than a non-off
// global mode clamps UP to that floor, it does not relax below it.
func TestEvaluatePrompt_PerDetectorModeCannotRelaxBelowNonOffGlobal(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "block", map[string]string{"credit_card": "warn"}), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("detector=warn but global=block: got %+v, want clamped up to blocked/deny", pv)
	}
}

// TestEvaluatePrompt_PerDetectorOffIsAnExemptionNotClampedToFloor pins
// B1 (final-fix review): an explicit per-detector "off" is an
// EXEMPTION the floor clamp never applies to. promptFindingRefFor
// resolves that finding's ref.mode to PromptModeOff (rank 0), which
// the worst-of-refs reduction in evaluatePromptDecide then ignores —
// so a prompt whose ONLY finding is an off-exempted detector allows
// outright, even under a strict global floor. This replaces the
// pre-fix behavior (this test used to be named
// TestEvaluatePrompt_PerDetectorModeCannotRelaxBelowNonOffGlobal and
// asserted credit_card="off" under global="block" clamped UP to
// blocked/deny — that silently made the shipped default's
// email/phone_e164/phone_nanp="off" overrides unreachable, see B1's
// finding: pure defaults blocked "email me at a@b.com").
func TestEvaluatePrompt_PerDetectorOffIsAnExemptionNotClampedToFloor(t *testing.T) {
	t.Parallel()
	if got := EffectivePromptMode("block", map[string]string{"credit_card": "off"}, "credit_card"); got != PromptModeOff {
		t.Fatalf("EffectivePromptMode = %q, want off (exemption, not clamped to the block floor)", got)
	}
	g := newTestGuard(t, promptCfg("enforce", "block", map[string]string{"credit_card": "off"}), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeAllowed || pv.Verdict.Decision != policy.DecisionAllow {
		t.Fatalf("credit_card=off exempted under global=block: got %+v, want allowed (not clamped to blocked)", pv)
	}
}

// TestEvaluatePrompt_PerDetectorOffCannotEscalatePastGlobalOff pins
// F7's one true exception: when the global mode itself is "off", a
// per-detector override can never turn that detector back on — off is
// this feature's kill switch, not just another rank on the mode
// ladder a stricter per-detector value can climb past.
func TestEvaluatePrompt_PerDetectorOffCannotEscalatePastGlobalOff(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "off", map[string]string{"credit_card": "block"}), nil)
	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeAllowed {
		t.Fatalf("global=off, detector override=block: got %+v, want allowed (off is a kill switch)", pv)
	}
}

// TestEvaluatePrompt_DashboardApprovalDowngrades pins §5.5 override
// channel 2: an active guard_approvals-style grant (via
// SetApprovalLookup, reused unmodified) downgrades a blocking verdict.
func TestEvaluatePrompt_DashboardApprovalDowngrades(t *testing.T) {
	t.Parallel()
	g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
	g.SetApprovalLookup(func(ruleID, sessionID, projectRootHash string) bool { return true })

	pv := g.EvaluatePrompt(promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")}))
	if pv.Outcome != PromptOutcomeApproved || pv.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("approved grant: got %+v, want approved/flag", pv)
	}
	if pv.DegradedFrom != "approved" {
		t.Errorf("DegradedFrom = %q, want %q", pv.DegradedFrom, "approved")
	}
}

// TestBuildPromptFindings_AllowlistDropsMatchedValue pins §4.3 item 3:
// a finding whose VALUE matches [guard.prompt].allow never reaches the
// returned Secrets/PIIFindings slices.
func TestBuildPromptFindings_AllowlistDropsMatchedValue(t *testing.T) {
	t.Parallel()
	cfg := promptCfg("enforce", "ask-once", nil)
	cfg.Prompt.Allow = []string{`^4242[- ]?4242[- ]?4242[- ]?4242$`}
	g := newTestGuard(t, cfg, nil)

	secrets, pii, _ := g.BuildPromptFindings("my card is 4242 4242 4242 4242, ssn 219-09-9999 aadhaar context")
	for _, f := range pii {
		if f.Type == "credit_card" {
			t.Errorf("allowlisted card value leaked through as a finding: %+v", f)
		}
	}
	_ = secrets
}

func TestPromptFingerprint_SessionScoped(t *testing.T) {
	t.Parallel()
	findings := []promptFindingHash{{Type: "credit_card", Hash: "abc"}}
	fp1 := promptFingerprint("s1", findings)
	fp2 := promptFingerprint("s2", findings)
	if fp1 == fp2 {
		t.Errorf("fingerprint must be session-scoped: got the same value for s1 and s2")
	}
	if fp1 != promptFingerprint("s1", findings) {
		t.Errorf("fingerprint must be deterministic for the same inputs")
	}
}

func TestPromptFingerprint_OrderIndependent(t *testing.T) {
	t.Parallel()
	a := []promptFindingHash{{Type: "credit_card", Hash: "h1"}, {Type: "us_ssn", Hash: "h2"}}
	b := []promptFindingHash{{Type: "us_ssn", Hash: "h2"}, {Type: "credit_card", Hash: "h1"}}
	if promptFingerprint("s1", a) != promptFingerprint("s1", b) {
		t.Errorf("fingerprint must be order-independent over the finding SET")
	}
}

// TestPromptFingerprint_CoversSecretsAndPIITogether pins round-2
// review B1: the fingerprint now covers the WHOLE finding set —
// secrets and PII alike — not just the PII half. A prompt with both a
// secret and a PII finding fingerprints differently from either one
// alone.
func TestPromptFingerprint_CoversSecretsAndPIITogether(t *testing.T) {
	t.Parallel()
	secretOnly := []promptFindingHash{{Type: "github_pat", Hash: "s1hash"}}
	both := []promptFindingHash{{Type: "github_pat", Hash: "s1hash"}, {Type: "credit_card", Hash: "p1hash"}}
	if promptFingerprint("s1", secretOnly) == promptFingerprint("s1", both) {
		t.Errorf("adding a PII finding alongside a secret finding must change the fingerprint")
	}
}

// TestEffectivePromptMode pins F7 (phase-3a review) plus the B1
// final-fix: stricter-wins semantics — a per-detector override that is
// STRICTER than the global mode is honored (max(global, detector) by
// promptModeRank); a LOOSER non-off override still clamps UP to the
// global floor. An explicit per-detector "off" is instead an EXEMPTION
// the floor never applies to (B1) — it is honored unconditionally
// whenever the global mode is itself not off. The one remaining
// exception is global="off", which no per-detector override (off or
// otherwise) can ever escalate past (the feature's kill switch).
func TestEffectivePromptMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		global    string
		overrides map[string]string
		detector  string
		want      PromptMode
	}{
		{"no override uses global", "ask-once", nil, "credit_card", PromptModeAskOnce},
		{"stricter override wins over global", "warn", map[string]string{"credit_card": "block"}, "credit_card", PromptModeBlock},
		{"stricter override wins: shipped github_pat default", "ask-once", map[string]string{"github_pat": "block"}, "github_pat", PromptModeBlock},
		{"looser non-off override still clamps up to global floor", "block", map[string]string{"credit_card": "warn"}, "credit_card", PromptModeBlock},
		{"explicit per-detector off is an exemption, not clamped to the floor: shipped email default", "ask-once", map[string]string{"email": "off"}, "email", PromptModeOff},
		{"explicit per-detector off is an exemption under a stricter floor too", "block", map[string]string{"credit_card": "off"}, "credit_card", PromptModeOff},
		{"global off is a no-op override", "off", map[string]string{"credit_card": "off"}, "credit_card", PromptModeOff},
		{"global off cannot be escalated past by any override", "off", map[string]string{"credit_card": "block"}, "credit_card", PromptModeOff},
		{"equal override matches global", "ask-once", map[string]string{"credit_card": "ask-once"}, "credit_card", PromptModeAskOnce},
		{"unparseable global falls back to off", "bogus", nil, "credit_card", PromptModeOff},
		{"unparseable override falls back to global", "warn", map[string]string{"credit_card": "bogus"}, "credit_card", PromptModeWarn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := effectivePromptMode(c.global, c.overrides, c.detector)
			if got != c.want {
				t.Errorf("effectivePromptMode(%q, %v, %q) = %q, want %q", c.global, c.overrides, c.detector, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Round-2 re-review fixes (FIX-1, FIX-2, FIX-4) and BLOCK-2's
// guard-layer integration (BuildPromptFindings threading the active
// detector set through).
// ---------------------------------------------------------------------

// TestEvaluatePrompt_DenyBranchesRaiseSeverityToHigh pins FIX-1: R-190's
// own table row stays SeverityWarn, but every branch that actually
// resolves to policy.DecisionDeny is raised to SeverityHigh by the
// EvaluatePrompt wrapper - mode=block, an unhashable finding (empty
// Hash) degrading to block, and an empty session_id.
func TestEvaluatePrompt_DenyBranchesRaiseSeverityToHigh(t *testing.T) {
	t.Parallel()

	t.Run("mode=block", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		pii := []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: "h1"}}
		pv := g.EvaluatePrompt(promptEvent("s1", nil, pii))
		if pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("expected a deny verdict, got %+v", pv)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh on a deny verdict", pv.Verdict.Severity)
		}
	})

	t.Run("unhashable finding degrades to block", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		g.SetPromptReconsiderStore(newMemPromptStore().funcs())
		pii := []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: ""}}
		pv := g.EvaluatePrompt(promptEvent("s1", nil, pii))
		if pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("expected a deny verdict for an unhashable finding, got %+v", pv)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh", pv.Verdict.Severity)
		}
	})

	t.Run("empty session_id fails closed to deny", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		g.SetPromptReconsiderStore(newMemPromptStore().funcs())
		pii := []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: "h1"}}
		pv := g.EvaluatePrompt(promptEvent("", nil, pii))
		if pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("expected a deny verdict for an empty session_id, got %+v", pv)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh", pv.Verdict.Severity)
		}
	})

	t.Run("warn stays SeverityWarn, never raised", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "warn", nil), nil)
		pii := []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: "h1"}}
		pv := g.EvaluatePrompt(promptEvent("s1", nil, pii))
		if pv.Verdict.Decision != policy.DecisionFlag {
			t.Fatalf("expected a flag verdict, got %+v", pv)
		}
		if pv.Verdict.Severity == policy.SeverityHigh {
			t.Errorf("a warn-mode flag must NOT be raised to SeverityHigh")
		}
	})

	// BLOCK-2 (phase-2 review): raisePromptSeverityOnDeny must be a
	// FLOOR, not an unconditional assignment. R-172 (secret-shaped
	// content) is SeverityCritical on its own rule row; a secret
	// finding that resolves to deny (mode=block) must stay Critical —
	// an unconditional "= SeverityHigh" would silently DOWNGRADE a
	// leaked API token below a mere destructive-command ask, which is
	// the opposite of what this feature exists to do.
	t.Run("secret finding (R-172) stays SeverityCritical, never downgraded", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		secrets := []policy.SecretFinding{{Type: "github_pat", Certain: true, SpanLen: 40, Hash: "h1"}}
		pv := g.EvaluatePrompt(promptEvent("s1", secrets, nil))
		if pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("expected a deny verdict, got %+v", pv)
		}
		if pv.Verdict.RuleID != "R-172" {
			t.Fatalf("expected R-172, got %q", pv.Verdict.RuleID)
		}
		if pv.Verdict.Severity != policy.SeverityCritical {
			t.Errorf("Severity = %v, want SeverityCritical (must not be downgraded to High)", pv.Verdict.Severity)
		}
	})

	// PII (R-190) starts at SeverityWarn — a PII deny IS the floor's
	// intended raise, confirming the floor still raises when the
	// underlying severity is genuinely below High.
	t.Run("PII finding (R-190) raised from SeverityWarn to SeverityHigh", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		pii := []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: "h1"}}
		pv := g.EvaluatePrompt(promptEvent("s1", nil, pii))
		if pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("expected a deny verdict, got %+v", pv)
		}
		if pv.Verdict.RuleID != "R-190" {
			t.Fatalf("expected R-190, got %q", pv.Verdict.RuleID)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh", pv.Verdict.Severity)
		}
	})
}

// TestEvaluatePrompt_OversizeBodyDegradesToWarnOrBlock pins FIX-2: a
// prompt whose PII detection was skipped for being over
// scrub.MaxRawInputBytes (BuildPromptFindings' truncated return
// threaded onto ev.PromptTruncated) must never be silently treated
// the same as "scanned clean" - it degrades to warn under every mode
// except block, where it degrades to a hard deny.
func TestEvaluatePrompt_OversizeBodyDegradesToWarnOrBlock(t *testing.T) {
	t.Parallel()

	t.Run("ask-once mode degrades to warn, not ask", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptTruncated = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
			t.Fatalf("got %+v, want warned/flag (never ask-once for an unscanned body)", pv)
		}
	})

	t.Run("block mode degrades to a hard deny", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptTruncated = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("got %+v, want blocked/deny under mode=block", pv)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh (FIX-1 applies here too)", pv.Verdict.Severity)
		}
	})

	t.Run("mode=off ignores truncation entirely", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "off", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptTruncated = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeAllowed {
			t.Fatalf("got %+v, want allowed when [guard.prompt].mode is off", pv)
		}
	})

	t.Run("not truncated: ordinary clean-scan allow, unaffected", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		pv := g.EvaluatePrompt(promptEvent("s1", nil, nil))
		if pv.Outcome != PromptOutcomeAllowed {
			t.Fatalf("got %+v, want allowed for a genuinely clean, non-truncated scan", pv)
		}
	})

	t.Run("a real finding on a truncated prompt still drives its own verdict", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		ev := promptEvent("s1", nil, []policy.PIIFinding{{Type: "credit_card", Class: "pii", SpanLen: 16, Hash: "h1"}})
		ev.PromptTruncated = true
		pv := g.EvaluatePrompt(ev)
		if pv.Verdict.RuleID != "R-190" || pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("a genuine finding must still drive R-190 normally even on a truncated prompt: %+v", pv)
		}
	})
}

// TestEvaluatePrompt_FieldMissingDegradesToWarnOrBlock pins FIX-2
// (phase-2 review): a dialect extractor that found NONE of its known
// prompt-field names in the raw hook payload at all (schema drift)
// must never be silently treated as "prompt scanned, nothing found" —
// same warn-everywhere/block-under-mode=block degrade as the
// oversize/truncated case above, mirrored here for the field-missing
// signal.
func TestEvaluatePrompt_FieldMissingDegradesToWarnOrBlock(t *testing.T) {
	t.Parallel()

	t.Run("ask-once mode degrades to warn, not ask", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptFieldMissing = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeWarned || pv.Verdict.Decision != policy.DecisionFlag {
			t.Fatalf("got %+v, want warned/flag (never ask-once for an unscanned body)", pv)
		}
	})

	t.Run("block mode degrades to a hard deny", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptFieldMissing = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeBlocked || pv.Verdict.Decision != policy.DecisionDeny {
			t.Fatalf("got %+v, want blocked/deny under mode=block", pv)
		}
		if pv.Verdict.Severity != policy.SeverityHigh {
			t.Errorf("Severity = %v, want SeverityHigh (FIX-1 floor applies here too)", pv.Verdict.Severity)
		}
	})

	t.Run("mode=off ignores field-missing entirely", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "off", nil), nil)
		ev := promptEvent("s1", nil, nil)
		ev.PromptFieldMissing = true
		pv := g.EvaluatePrompt(ev)
		if pv.Outcome != PromptOutcomeAllowed {
			t.Fatalf("got %+v, want allowed when [guard.prompt].mode is off", pv)
		}
	})

	t.Run("neither signal set: ordinary clean-scan allow, unaffected", func(t *testing.T) {
		t.Parallel()
		g := newTestGuard(t, promptCfg("enforce", "ask-once", nil), nil)
		pv := g.EvaluatePrompt(promptEvent("s1", nil, nil))
		if pv.Outcome != PromptOutcomeAllowed {
			t.Fatalf("got %+v, want allowed for a genuinely clean scan", pv)
		}
	})
}

// TestNormalizedSpanHash_ClassAwareCaseFolding pins FIX-4: a secret's
// fingerprint hash is CASE-SENSITIVE (two keys differing only in case
// are two different keys - folding them together would let a resend
// of a genuinely NEW key silently confirm an old grant), while a PII
// value's hash stays case-INSENSITIVE (a credit card/SSN has no case
// identity; separators are stripped for both classes).
func TestNormalizedSpanHash_ClassAwareCaseFolding(t *testing.T) {
	t.Parallel()
	if got := normalizedSpanHash("secret", "AbCdEf123456"); got == normalizedSpanHash("secret", "abcdef123456") {
		t.Errorf("a secret's hash must be case-sensitive: got the same hash for %q and its lowercased form", "AbCdEf123456")
	}
	if got := normalizedSpanHash("pii", "4242-4242-4242-4242"); got != normalizedSpanHash("pii", "4242 4242 4242 4242") {
		t.Errorf("a PII value's hash must be separator-insensitive: %q != %q", got, normalizedSpanHash("pii", "4242 4242 4242 4242"))
	}
	if got := normalizedSpanHash("pii", "AbCdEf"); got != normalizedSpanHash("pii", "abcdef") {
		t.Errorf("a PII value's hash must stay case-insensitive")
	}
}

// TestBuildPromptFindings_HighVolumeDetectorNeverStarvesAnother is the
// guard-layer integration test for BLOCK-2's per-detector budget: 70
// email-shaped strings must not prevent a real credit card + SSN pair
// from being found and driving an interrupt, because MaxFindings caps
// each detector's OWN budget independently (round-2 re-review BLOCK-2)
// — an unrelated detector's volume can never starve another's.
//
// NOTE (B1, final-fix review): an earlier revision of this test (under
// the since-reverted F7 reading that a per-detector "off" clamped UP
// to a non-off global floor) configured email as active alongside
// credit_card/us_ssn to exercise MaxFindings starvation directly. B1
// restored "off means off" as a genuine per-detector exemption
// (activePromptDetectors excludes an off detector from scanning
// entirely — see effectivePromptMode's doc comment), so this test uses
// no overrides at all: with the global mode "ask-once" and no
// per-detector override, email is simply an ACTIVE detector like any
// other, and the same per-detector MaxFindings budget still prevents
// its 70-string volume from starving credit_card/us_ssn detection.
func TestBuildPromptFindings_HighVolumeDetectorNeverStarvesAnother(t *testing.T) {
	t.Parallel()
	cfg := promptCfg("enforce", "ask-once", nil)
	g := newTestGuard(t, cfg, nil)
	g.SetPromptReconsiderStore(newMemPromptStore().funcs())

	var b strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&b, "contact%d@example.com ", i)
	}
	b.WriteString("card on file: 4532015112830366, ssn 245-11-1234 on file")

	secrets, pii, truncated := g.BuildPromptFindings(b.String())
	if truncated {
		t.Fatalf("body is well under the raw-input bound, must not report truncated")
	}
	_ = secrets
	var sawCard, sawSSN bool
	for _, f := range pii {
		switch f.Type {
		case "credit_card":
			sawCard = true
		case "us_ssn":
			sawSSN = true
		}
	}
	if !sawCard || !sawSSN {
		t.Fatalf("high email volume must not starve credit_card/us_ssn detection (per-detector budget), got pii=%+v", pii)
	}

	pv := g.EvaluatePrompt(promptEvent("s1", secrets, pii))
	if pv.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("expected the PAN+SSN pass to interrupt (ask), got %+v", pv)
	}
}
