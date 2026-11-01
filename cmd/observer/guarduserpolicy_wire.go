package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// User guard-policy load failures made loud (T-323).
//
// A malformed ~/.observer/guard-policy.toml is DROPPED by the guard:
// hooks and the daemon run the built-in rules plus the signed org
// bundle, and the developer's own rules are off. The orchestrator
// ruling keeps that degradation (no fail-closed: built-ins and the org
// bundle stay in force) but forbids the silence. This file wires the
// three loud surfaces off ONE derivation, guard.CheckUserPolicy:
//
//   - `observer doctor` gets a failing guard.user_policy check naming
//     the file, line and error (guardUserPolicyDoctorCheck);
//   - the daemon raises a guard_error guard event, degraded_from
//     "user_policy_invalid", that reaches the org on the normal
//     guard_events push, once per distinct file content
//     (recordUserPolicyInvalid / guardUserPolicyLoop);
//   - the dashboard's /api/guard/summary carries the same status for
//     the Security page banner (internal/intelligence/dashboard).

// guardUserPolicyInterval is how often the daemon re-checks the user
// policy file. The check is one small file read and parse; the DB is
// only consulted when the file's content changed since the last tick.
const guardUserPolicyInterval = 30 * time.Second

// userHomeOrEmpty is os.UserHomeDir with the error folded to "" (the
// guard's own path resolution treats an empty home as "no ~ expansion").
func userHomeOrEmpty() string {
	home, _ := os.UserHomeDir()
	return home
}

// guardEvaluates reports whether the guard evaluates at all: a disabled
// guard (or mode "off") loads no user policy, so a broken one is not
// in effect either way.
func guardEvaluates(g config.GuardConfig) bool {
	return g.Enabled && g.Mode != "off"
}

// userPolicyLocation renders "path line N" (or just the path when the
// line is unknown).
func userPolicyLocation(st guard.UserPolicyStatus) string {
	if st.Line > 0 {
		return fmt.Sprintf("%s line %d", st.Path, st.Line)
	}
	return st.Path
}

// userPolicyInvalidTarget is the event target: the file path plus its
// content hash, so target_hash (always pushable) changes exactly when
// the file content does. The de-duplication key.
func userPolicyInvalidTarget(st guard.UserPolicyStatus) string {
	h := st.ContentHash
	if h == "" {
		h = "unreadable"
	}
	return st.Path + "@sha256:" + h
}

// userPolicyInvalidVerdict is the guard event for a user policy file
// the guard dropped: a guard_error FLAG (nothing was blocked; built-ins
// and the org bundle stay in force) with degraded_from
// "user_policy_invalid".
func userPolicyInvalidVerdict(st guard.UserPolicyStatus, at time.Time) guard.ActionVerdict {
	return guard.ActionVerdict{
		Input:    guard.ActionInput{Tool: "observer", Target: userPolicyInvalidTarget(st), Timestamp: at.UTC()},
		Kind:     policy.KindConfigChange,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag,
			RuleID:   guard.GuardErrorRuleID,
			Severity: policy.SeverityHigh,
			Reason: guardEventReason("user guard policy " + userPolicyLocation(st) + " does not load: " + st.Error +
				"; its rules are OFF (built-in rules and the org policy stay in force)"),
			Advice: "Fix the file (Security > Rules > Advanced: policy layers in the dashboard, or `observer guard lint`); the next daemon check clears this.",
			Source: policy.SourceBuiltin,
		},
		GuardError:   true,
		DegradedFrom: guard.UserPolicyInvalidDegradedFrom,
	}
}

// recordUserPolicyInvalid persists the user-policy-invalid event when
// the guard runs, the file is invalid, and no event already records
// this exact content. Returns true when it wrote one.
func recordUserPolicyInvalid(ctx context.Context, g config.GuardConfig, st guard.UserPolicyStatus, s *store.Store, now time.Time) (bool, error) {
	if !guardEvaluates(g) || !st.Invalid() || s == nil {
		return false, nil
	}
	exists, err := s.GuardEventExistsForTarget(ctx, guard.UserPolicyInvalidDegradedFrom, userPolicyInvalidTarget(st))
	if err != nil || exists {
		return false, err
	}
	if _, err := s.PersistGuardVerdicts(ctx, []guard.ActionVerdict{userPolicyInvalidVerdict(st, now)}); err != nil {
		return false, fmt.Errorf("persist user policy event: %w", err)
	}
	return true, nil
}

// guardUserPolicyLoop is the daemon's user-policy watcher: check at
// start, then every guardUserPolicyInterval, consulting the DB only
// when the file content (or its validity) changed. P1 like every
// sibling loop: never propagates an error.
func guardUserPolicyLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)
	st := store.New(database)
	home := userHomeOrEmpty()
	last := ""
	tick := func() {
		status := guard.CheckUserPolicy(cfg.Guard, home, os.ReadFile)
		key := fmt.Sprintf("%v|%s|%s", status.Invalid(), status.ContentHash, status.Error)
		if key == last {
			return
		}
		last = key
		wrote, err := recordUserPolicyInvalid(ctx, cfg.Guard, status, st, time.Now())
		if err != nil {
			logger.Warn("guard user policy: record event", "err", err)
			last = "" // retry next tick
			return
		}
		if wrote {
			logger.Warn("guard user policy does not load; its rules are off",
				"path", status.Path, "line", status.Line, "err", status.Error)
		}
	}
	tick()
	t := time.NewTicker(guardUserPolicyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// userPolicyFailClosedOnNode reports the organization's T-327 choice as the
// hooks on this node act on it (D-221): the daemon's verified posture, else
// the hook's own fallback derivation, for either gate family. It is the hook
// path's answer read back, never a second derivation.
func userPolicyFailClosedOnNode(configPath string) bool {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false
	}
	for _, c := range []integration.HookCap{integration.HookCapToolGate, integration.HookCapPromptGate} {
		if hookPostureFailsClosedFn(resolved, configPath, c).UserPolicyFailClosed {
			return true
		}
	}
	return false
}

// guardUserPolicyDoctorCheck is the `observer doctor` row. A broken
// file fails the check (doctor exits non-zero) while the guard runs,
// and warns when the guard is off (the file is not in effect today but
// will be dropped the moment the guard is turned on). failClosed is the
// organization's fail_closed choice on this node (userPolicyFailClosedOnNode):
// then the enforced gated hooks are BLOCKED, not merely missing rules.
func guardUserPolicyDoctorCheck(cfg config.Config, home string, readFile func(string) ([]byte, error), failClosed bool) diag.Check {
	const name = "guard.user_policy"
	st := guard.CheckUserPolicy(cfg.Guard, home, readFile)
	switch {
	case st.Path == "":
		return diag.Check{Name: name, Status: diag.StatusOK, Message: "no user policy configured ([guard.rules].user_policy is empty)"}
	case !st.Present:
		return diag.Check{Name: name, Status: diag.StatusOK, Message: "no user policy file at " + st.Path + " (built-in rules only)"}
	case st.Valid:
		return diag.Check{Name: name, Status: diag.StatusOK, Message: st.Path + " loads"}
	}
	status := diag.StatusFail
	tail := "its rules are OFF; built-in rules and the org policy stay in force"
	if failClosed {
		tail = "your organization requires fail-closed: every enforced gated hook (tool calls, prompts) is BLOCKED until this file loads"
	}
	if !guardEvaluates(cfg.Guard) {
		status = diag.StatusWarn
		tail = "the guard is off today; when it is on, this file's rules will be dropped"
	}
	return diag.Check{
		Name:    name,
		Status:  status,
		Message: userPolicyLocation(st) + ": " + st.Error + " (" + tail + ")",
		Details: []string{
			"edit it in the dashboard: Security > Rules > Advanced: policy layers (saves are lint-gated)",
			"or check it with: observer guard lint " + st.Path,
		},
	}
}
