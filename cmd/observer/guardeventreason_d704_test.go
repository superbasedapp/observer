package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// TestGuardEventReasonsRenderHomeAsTilde pins D-704 gap 5: no daemon-built
// guard_error reason names the developer's home. One row per builder.
func TestGuardEventReasonsRenderHomeAsTilde(t *testing.T) {
	const home = "/home/dev"
	prev := guardEventHome
	guardEventHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { guardEventHome = prev })
	at := time.Date(2026, 10, 17, 0, 1, 34, 0, time.UTC)
	bundle := home + "/.observer/org-policy-bundle.json"
	for _, tc := range []struct {
		name string
		v    guard.ActionVerdict
		want string
	}{
		{
			"org bundle tamper", tamperVerdict(guardTamper{tamperOrgBundle, "org bundle " + bundle + ": read " + bundle + ": is a directory"}, at),
			"org bundle ~/.observer/org-policy-bundle.json: read ~/.observer/org-policy-bundle.json: is a directory",
		},
		{
			"governance tamper", tamperVerdict(guardTamper{tamperGovernance, sidecarChangeDetail(home+"/.observer/governance-effective.json", nil)}, at),
			"(~/.observer/governance-effective.json)",
		},
		{
			"org lock tamper", tamperVerdict(guardTamper{tamperOrgLock, "guard-org-lock.json was changed or removed outside the daemon"}, at),
			"guard-org-lock.json was changed",
		},
		{
			"posture tamper found at start", postureTamperVerdict("found at daemon start: "+home+"/.observer/guard-posture.json does not verify", at),
			"~/.observer/guard-posture.json does not verify",
		},
		{
			"hooks switched off", hooksDisabledVerdict(hookdisable.Finding{Key: "disableAllHooks", Path: home + "/.claude/settings.json", Scope: "user", Effect: "every hook is off"}, at),
			"in ~/.claude/settings.json",
		},
		{
			"user policy does not load", userPolicyInvalidVerdict(guard.UserPolicyStatus{Path: home + "/.observer/guard-policy.toml", Error: "open " + home + "/.observer/guard-policy.toml: permission denied"}, at),
			"user guard policy ~/.observer/guard-policy.toml does not load: open ~/.observer/guard-policy.toml",
		},
		{
			"hook failure", hookFailureVerdict(guardposture.Record{Kind: "timeout", Tool: "claude-code", Event: "PreToolUse", At: at}),
			"hook failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.v.Verdict.Reason
			if strings.Contains(r, home) {
				t.Fatalf("reason names the home path: %q", r)
			}
			if !strings.Contains(r, tc.want) {
				t.Fatalf("reason = %q, want it to contain %q", r, tc.want)
			}
		})
	}
}
