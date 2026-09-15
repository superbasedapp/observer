package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Part B item 4 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §8.3 / FIX-4 of the phase-2 review): `observer guard prompt` CLI
// group tests.

func TestGuardPromptStatusCmd(t *testing.T) {
	// Not t.Parallel(): probeHookSetupHome mutates process-wide env vars
	// (HOME/USERPROFILE) — same isolation requirement as
	// TestRunProbeHook_EndToEnd, since F4 wired `status` through the
	// SAME checkHookRegistration probe that reads the real home
	// directory's vendor config files when not isolated.
	probeHookSetupHome(t) // fresh HOME — nothing registered anywhere
	cfgPath, _ := writeGuardTestConfig(t)
	out, err := runGuardCmd(t, "prompt", "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("prompt status: %v (%s)", err, out)
	}
	for _, want := range []string{
		"guard.enabled",
		"guard.prompt.enabled     = true",
		"guard.prompt.mode        = ask-once",
		"guard.prompt.enforce_independent = true",
		"effective hook-lane state",
		// F4/F7 (phase-3a review): the per-detector section now shows
		// the EFFECTIVE mode (after the stricter-wins-with-floor clamp),
		// not just the raw config value — github_pat's shipped
		// "block" override must be honored (not clamped down to
		// ask-once), and marked as overridden.
		"per-detector effective mode",
		"*github_pat           block",
		// F4: "wired clients" is now a REAL per-tool registration probe
		// (checkHookRegistration), not a bare registry listing — a
		// fresh, isolated HOME with nothing registered must report NOT
		// REGISTERED for a normally-auto-wired tool and the honest
		// "documented, not auto-wired" line for zcode.
		"claude-code", "codex", "cursor", "gemini-cli", "qwen-code", "droid",
		"NOT REGISTERED",
		"zcode            documented, not auto-wired",
		"reconsider-once grants: 0 total, 0 expired",
		// F4: no approvals seeded, must report that honestly.
		"active prompt-submit approvals (R-172/R-190): none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt status output missing %q:\n%s", want, out)
		}
	}
}

// TestGuardPromptStatusCmd_SurfacesGlobalApproval pins F4's approvals
// section: an active --global, never-expiring (ttl=0) grant on a
// prompt-submit rule must render with the loud warning callout, not
// buried in a generic list a busy operator could scroll past.
func TestGuardPromptStatusCmd_SurfacesGlobalApproval(t *testing.T) {
	probeHookSetupHome(t)
	cfgPath, _ := writeGuardTestConfig(t)

	if out, err := runGuardCmd(t, "prompt", "allow", "github_pat", "--global", "--ttl", "0", "--config", cfgPath); err != nil {
		t.Fatalf("seed global allow: %v (%s)", err, out)
	}

	out, err := runGuardCmd(t, "prompt", "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("prompt status: %v (%s)", err, out)
	}
	if !strings.Contains(out, "rule=R-172 scope=global") {
		t.Errorf("status output missing the global R-172 grant:\n%s", out)
	}
	if !strings.Contains(out, "GLOBAL, NEVER EXPIRES") {
		t.Errorf("status output missing the loud global/never-expires callout:\n%s", out)
	}
}

func TestGuardPromptAllowCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	// A PII detector must map to R-190.
	out, err := runGuardCmd(t, "prompt", "allow", "credit_card", "--session", "s1", "--config", cfgPath)
	if err != nil {
		t.Fatalf("allow credit_card: %v (%s)", err, out)
	}
	if !strings.Contains(out, "detector=credit_card -> R-190 scope=session") {
		t.Errorf("allow credit_card output: %s", out)
	}

	// A secret detector must map to R-172.
	out, err = runGuardCmd(t, "prompt", "allow", "github_pat", "--global", "--config", cfgPath)
	if err != nil {
		t.Fatalf("allow github_pat: %v (%s)", err, out)
	}
	if !strings.Contains(out, "detector=github_pat -> R-172 scope=global") {
		t.Errorf("allow github_pat output: %s", out)
	}

	// entropy (the dynamically-emitted secret heuristic) also maps to
	// R-172 — it has no table row of its own in internal/scrub.
	out, err = runGuardCmd(t, "prompt", "allow", "entropy", "--project", "--config", cfgPath)
	if err != nil {
		t.Fatalf("allow entropy: %v (%s)", err, out)
	}
	if !strings.Contains(out, "detector=entropy -> R-172 scope=project") {
		t.Errorf("allow entropy output: %s", out)
	}

	// Unknown detector: honest error, no fabricated rule id.
	if out, err := runGuardCmd(t, "prompt", "allow", "not-a-real-detector", "--global", "--config", cfgPath); err == nil {
		t.Errorf("allow accepted an unknown detector, got: %s", out)
	}

	// Scope validation mirrors `guard approve`: zero or two scopes rejected.
	if _, err := runGuardCmd(t, "prompt", "allow", "credit_card", "--config", cfgPath); err == nil {
		t.Error("allow without a scope accepted")
	}
	if _, err := runGuardCmd(t, "prompt", "allow", "credit_card", "--global", "--session", "s1", "--config", cfgPath); err == nil {
		t.Error("allow with two scopes accepted")
	}

	// The grants are visible through the SAME mechanism `guard approve`
	// uses — one shared table, no separate per-detector store.
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	if !st.ApprovalActiveFor(context.Background(), "R-190", "s1", "", time.Now().UTC()) {
		t.Error("credit_card grant not visible to ApprovalActiveFor under R-190/session s1")
	}
	if !st.ApprovalActiveFor(context.Background(), "R-172", "any-session", "", time.Now().UTC()) {
		t.Error("github_pat grant not visible to ApprovalActiveFor under R-172/global")
	}
}

func TestGuardPromptClearCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	now := time.Now().UTC()
	if err := st.RecordPromptWarned(context.Background(), store.PromptReconsiderRow{
		Fingerprint: "fp-1", SessionID: "s1", Tool: "claude-code",
		Detectors: "credit_card", WarnedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("seed RecordPromptWarned: %v", err)
	}

	// Neither a fingerprint nor --all: rejected.
	if _, err := runGuardCmd(t, "prompt", "clear", "--config", cfgPath); err == nil {
		t.Error("clear with no fingerprint and no --all accepted")
	}
	// Both a fingerprint AND --all: rejected.
	if _, err := runGuardCmd(t, "prompt", "clear", "fp-1", "--all", "--config", cfgPath); err == nil {
		t.Error("clear with both a fingerprint and --all accepted")
	}
	// Unknown fingerprint: honest error.
	if _, err := runGuardCmd(t, "prompt", "clear", "does-not-exist", "--config", cfgPath); err == nil {
		t.Error("clear accepted an unknown fingerprint")
	}

	out, err := runGuardCmd(t, "prompt", "clear", "fp-1", "--config", cfgPath)
	if err != nil {
		t.Fatalf("clear fp-1: %v (%s)", err, out)
	}
	if !strings.Contains(out, "cleared fingerprint fp-1") {
		t.Errorf("clear output: %s", out)
	}
	if _, ok, err := st.LookupPromptReconsider(context.Background(), "fp-1", now); err != nil || ok {
		t.Errorf("fp-1 still present after clear: ok=%v err=%v", ok, err)
	}

	// --all clears everything.
	if err := st.RecordPromptWarned(context.Background(), store.PromptReconsiderRow{
		Fingerprint: "fp-2", SessionID: "s1", Tool: "claude-code",
		Detectors: "credit_card", WarnedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}); err != nil {
		t.Fatalf("seed RecordPromptWarned fp-2: %v", err)
	}
	out, err = runGuardCmd(t, "prompt", "clear", "--all", "--config", cfgPath)
	if err != nil {
		t.Fatalf("clear --all: %v (%s)", err, out)
	}
	if !strings.Contains(out, "cleared 1 reconsider-once grant") {
		t.Errorf("clear --all output: %s", out)
	}
}

func TestGuardPromptEventsCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	// No events yet.
	out, err := runGuardCmd(t, "prompt", "events", "--config", cfgPath)
	if err != nil {
		t.Fatalf("events (empty): %v (%s)", err, out)
	}
	if !strings.Contains(out, "no prompt-submit events in range") {
		t.Errorf("events (empty) output: %s", out)
	}

	// Seed one prompt-submit guard_events row and one NON-prompt row —
	// only the prompt-submit one must print.
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	secretValue := "sk-ant-api03-SUPERSECRETVALUENEVERSTORED"
	// TargetExcerpt is the opaque reconsider-once fingerprint hex for a
	// prompt-submit row (guard.ActionVerdictFromPrompt's doc comment) —
	// F5 (phase-3a review) makes `events` print it as a FINGERPRINT
	// column so it's copy-pasteable into `clear <fingerprint>`.
	fakeFingerprint := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	if _, err := st.InsertGuardEvents(context.Background(), []store.GuardEventRow{
		{
			TS: time.Now().UTC(), SessionID: "s1", Tool: "claude-code",
			EventKind: "user_prompt", RuleID: "R-172", Decision: "deny",
			Severity: "critical", Category: "exfil",
			Reason:        "detected api_key_prefixed×1 in the prompt text",
			TargetExcerpt: fakeFingerprint,
		},
		{
			TS: time.Now().UTC(), SessionID: "s1", Tool: "claude-code",
			EventKind: "shell_exec", RuleID: "R-101", Decision: "flag",
			Severity: "critical", Category: "destructive",
			Reason: "destructive command detected",
		},
	}); err != nil {
		t.Fatalf("seed InsertGuardEvents: %v", err)
	}

	out, err = runGuardCmd(t, "prompt", "events", "--config", cfgPath)
	if err != nil {
		t.Fatalf("events: %v (%s)", err, out)
	}
	if !strings.Contains(out, "R-172") {
		t.Errorf("events output missing the prompt-submit row: %s", out)
	}
	if !strings.Contains(out, "FINGERPRINT") {
		t.Errorf("events output missing the FINGERPRINT column header: %s", out)
	}
	if !strings.Contains(out, fakeFingerprint) {
		t.Errorf("events output missing the row's fingerprint value: %s", out)
	}
	if strings.Contains(out, "R-101") {
		t.Errorf("events output leaked a non-prompt-submit row: %s", out)
	}
	if strings.Contains(out, secretValue) {
		t.Errorf("events output leaked the raw secret value: %s", out)
	}
}
