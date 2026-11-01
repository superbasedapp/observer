package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// bootstrapEnv is a throwaway config (DB in the temp dir) and a recorder
// of exit calls with their time since the invocation started.
type bootstrapEnv struct {
	cp    string
	mu    sync.Mutex
	exits []int
	at    []time.Duration
	start time.Time
}

func newBootstrapEnv(t *testing.T) *bootstrapEnv {
	t.Helper()
	// The default [guard.prompt] (ask-once, enforce_independent) enforces
	// the prompt family under observe, so the prompt gate these tests drive
	// is an enforced gate and its interim plan (T-381) stays closed.
	return newBootstrapEnvMode(t, "observe", "")
}

// newBootstrapEnvMode is newBootstrapEnv with the guard mode and extra TOML
// appended, under a private HOME (the default policy paths are
// ~-anchored).
func newBootstrapEnvMode(t *testing.T, mode, rules string) *bootstrapEnv {
	t.Helper()
	dir := t.TempDir()
	setTestHome(t, filepath.Join(dir, "home"))
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = %q\n%s", filepath.Join(dir, "o.db"), mode, rules))
	return &bootstrapEnv{cp: cp}
}

func (e *bootstrapEnv) exit(code int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exits = append(e.exits, code)
	e.at = append(e.at, time.Since(e.start))
}

func (e *bootstrapEnv) recorded() ([]int, []time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]int(nil), e.exits...), append([]time.Duration(nil), e.at...)
}

// runBootstrap runs one real invocation of `observer hook claude-code
// user-prompt-submit` (an exit-code prompt gate: a block is exit 2, nothing
// on stdout) with the posture resolver replaced by resolve.
func runBootstrap(t *testing.T, e *bootstrapEnv, maxRuntime time.Duration, resolve func(string, string, integration.HookCap) bool) *failureHarness {
	t.Helper()
	h := newFailureHarness(t, hookFailurePlan{})
	prev := hookPostureFailsClosedFn
	hookPostureFailsClosedFn = func(resolved, configPath string, c integration.HookCap) hookPostureAnswer {
		return hookPostureAnswer{FailsClosed: resolve(resolved, configPath, c)}
	}
	t.Cleanup(func() { hookPostureFailsClosedFn = prev })
	t.Setenv("OBSERVER_HOOK_MAX_RUNTIME", "")
	withStdinT(t, `{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"hello"}`, func() {
		e.start = time.Now()
		runHookInvocation(context.Background(), []string{"claude-code", "user-prompt-submit"}, e.cp, maxRuntime, e.exit)
	})
	return h
}

// TestHookBootstrapTimeoutFailsClosed pins Sol A2-03 part 1: the watchdog is
// armed before the posture is resolved, and the plan it sees for a wired
// gate is already fail-closed, so a posture/config read that hangs past
// the budget is answered with the block, never with an uninitialized
// fail-open plan.
func TestHookBootstrapTimeoutFailsClosed(t *testing.T) {
	e := newBootstrapEnv(t)
	h := runBootstrap(t, e, 300*time.Millisecond, func(string, string, integration.HookCap) bool {
		time.Sleep(1500 * time.Millisecond)
		return true
	})
	exits, _ := e.recorded()
	if len(exits) == 0 || exits[0] != 2 {
		t.Fatalf("exits = %v, want a first exit 2 (the prompt gate block) while the posture was still resolving", exits)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("the exit-code dialect's block wrote stdout %q", h.stdout.String())
	}
	b, err := guardposture.Drain(guardposture.SpoolPath(e.cp), 0)
	if err != nil || b == nil || len(b.Records) != 1 || b.Records[0].Kind != guardposture.KindTimeout {
		t.Fatalf("spool = %+v (%v), want one timeout record", b, err)
	}
}

// TestHookBootstrapDeadlineIsAbsolute pins Sol A2-03 part 2: the budget is
// measured from the start of the invocation, so time spent resolving the
// plan is not added on top of it.
func TestHookBootstrapDeadlineIsAbsolute(t *testing.T) {
	const budget = time.Second
	hold := 600 * time.Millisecond
	if got := hookRemaining(time.Now().Add(-hold), budget); got > budget-hold+50*time.Millisecond || got <= 0 {
		t.Errorf("hookRemaining after %v of a %v budget = %v, want about %v", hold, budget, got, budget-hold)
	}
	if got := hookRemaining(time.Now().Add(-2*budget), budget); got != time.Nanosecond {
		t.Errorf("an exhausted budget = %v, want an immediate fire", got)
	}
	if got := hookRemaining(time.Now(), 0); got != 0 {
		t.Errorf("a disabled watchdog = %v, want 0 (still disabled)", got)
	}

	// End to end: a resolver that holds past the budget is answered at the
	// budget measured from start, not budget + hold.
	e2 := newBootstrapEnv(t)
	runBootstrap(t, e2, budget, func(string, string, integration.HookCap) bool {
		time.Sleep(budget + hold)
		return true
	})
	exits, at := e2.recorded()
	if len(exits) == 0 || exits[0] != 2 {
		t.Fatalf("exits = %v, want the block", exits)
	}
	if at[0] > budget+400*time.Millisecond {
		t.Errorf("the watchdog fired %v after start; the deadline is %v from start", at[0], budget)
	}
}

// TestHookBootstrapPanicFailsClosed: a panic while the plan is being
// resolved is caught by the panic guard (installed first) and answered
// with the provisional fail-closed plan.
func TestHookBootstrapPanicFailsClosed(t *testing.T) {
	e := newBootstrapEnv(t)
	h := runBootstrap(t, e, 5*time.Second, func(string, string, integration.HookCap) bool {
		panic("simulated posture read panic")
	})
	exits, _ := e.recorded()
	if len(exits) != 1 || exits[0] != 2 {
		t.Fatalf("exits = %v, want exactly [2]", exits)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	b, _ := guardposture.Drain(guardposture.SpoolPath(e.cp), 0)
	if b == nil || len(b.Records) != 1 || b.Records[0].Kind != guardposture.KindCrash {
		t.Fatalf("spool = %+v, want one crash record", b)
	}
}

// TestHookBootstrapOpensWhenNotEnforced: the provisional plan only stays
// closed while the posture is unknown; a not-enforced posture opens it and
// the invocation is the ordinary allow.
func TestHookBootstrapOpensWhenNotEnforced(t *testing.T) {
	e := newBootstrapEnvMode(t, "observe", "")
	runBootstrap(t, e, 2*time.Minute, func(string, string, integration.HookCap) bool { return false })
	if currentHookPlan().FailClosed {
		t.Error("a not-enforced posture left the plan closed")
	}
	if exits, _ := e.recorded(); len(exits) != 0 {
		t.Errorf("exits = %v, want none (a clean allow)", exits)
	}
}

// TestHookBootstrapNonEnforcingNodeFailsOpen pins T-381 (D-188's first-plan
// assumption against D-041 / D-150): on a node whose config does not
// enforce and that holds no policy file that could, a full derivation that
// hangs past the budget is answered with the fail-open exit and a fail_open
// record, never a block, even though the resolver would have said "closed"
// had it finished.
func TestHookBootstrapNonEnforcingNodeFailsOpen(t *testing.T) {
	e := newBootstrapEnvMode(t, "observe", bootstrapPromptNotEnforced)
	// The recorded exit does not end the test process, so the receiver may
	// still write its own allow after it; only the first exit matters.
	runBootstrap(t, e, 300*time.Millisecond, func(string, string, integration.HookCap) bool {
		time.Sleep(1500 * time.Millisecond)
		return true
	})
	exits, _ := e.recorded()
	if len(exits) == 0 || exits[0] != 0 {
		t.Fatalf("exits = %v, want a first exit 0 (fail open: this node does not enforce)", exits)
	}
	b, err := guardposture.Drain(guardposture.SpoolPath(e.cp), 0)
	if err != nil || b == nil || len(b.Records) != 1 || b.Records[0].Kind != guardposture.KindTimeout || !b.Records[0].FailedOpen() {
		t.Fatalf("spool = %+v (%v), want one fail_open timeout record", b, err)
	}
}

// bootstrapPromptNotEnforced makes the prompt family not enforcing under an
// observe mode: the prompt lane stays on, but its enforcement follows the
// global mode.
const bootstrapPromptNotEnforced = "[guard.prompt]\nenforce_independent = false\n"

// TestHookBootstrapPolicyFileKeepsInterimClosed: a policy file that could
// raise enforcement (here a cached org bundle, which can enforce the prompt
// family) keeps the interim plan closed under a non-enforcing config until
// the full derivation, which reads it, has answered.
func TestHookBootstrapPolicyFileKeepsInterimClosed(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "org-policy-bundle.json")
	writeFileT(t, bundle, "{}\n")
	e := newBootstrapEnvMode(t, "observe", bootstrapPromptNotEnforced+fmt.Sprintf("[guard.rules]\norg_bundle = %q\n", bundle))
	runBootstrap(t, e, 300*time.Millisecond, func(string, string, integration.HookCap) bool {
		time.Sleep(1500 * time.Millisecond)
		return true
	})
	exits, _ := e.recorded()
	if len(exits) == 0 || exits[0] != 2 {
		t.Fatalf("exits = %v, want the block while the policy file is unread", exits)
	}
}
