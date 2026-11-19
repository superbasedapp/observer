//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_guardhooks.go is the daemon side of guard's hooks
// in a hosted box (lane HOOKS, decision SBXD-6, ledger SBX-HOOK-1):
// [terminal.sandbox.hosted].guard_hooks resolved for one launch (the rule
// table is sandboxremote.ResolveGuardHooks; whether a tool's hooks can be
// set up in a box is hook.BoxHooksCover, read from the tool's registry row,
// never its name), carried to the host helper on the plan file, served per
// tool in the probe (the New Terminal dialog's line, and the no_hook_gating
// disclosure only where gating does not apply), and stated as a rule on the
// consent screen. The box seed itself is the host helper's
// (terminal_sandbox_hosted_guardhooks_linux.go).

// hostedGuardEnforcing reports whether guard enforcement is in force on this
// machine for either gate family: the answer a failing gate hook reads (the
// daemon's trusted posture, else the config with every policy file that
// could enforce counted, hookPreliminaryFailsClosed). A variable so a test
// can pin it.
var hostedGuardEnforcing = func() bool {
	cp := daemonConfigPath()
	resolved, err := config.ResolveGlobalPath(cp)
	if err != nil {
		return false
	}
	return hookPreliminaryFailsClosed(resolved, cp, integration.HookCapToolGate) ||
		hookPreliminaryFailsClosed(resolved, cp, integration.HookCapPromptGate)
}

// hostedGuardHooksCovered reports whether tool's hooks can be set up in a
// box (a variable so a test can stand a row in).
var hostedGuardHooksCovered = func(tool string) bool {
	c, ok := integration.For(tool)
	return ok && hook.BoxHooksCover(c)
}

// hostedGuardHooksFor resolves guard_hooks for a launch of tool. enforcing
// is read only when the rule needs it (auto, a covered tool).
func hostedGuardHooksFor(tool string, cfg config.TerminalSandboxHostedConfig, enforcing func() bool) sandboxremote.GuardHooksResult {
	in := sandboxremote.GuardHooksInput{
		Mode: sandboxremote.NormalizeGuardHooks(cfg.GuardHooks), Covered: hostedGuardHooksCovered(tool), Tool: integration.DisplayName(tool),
	}
	if in.Mode == sandboxremote.GuardHooksAuto && in.Covered {
		in.Enforcing = enforcing()
	}
	return sandboxremote.ResolveGuardHooks(in)
}

// hostedFillHookNotices adds a hosted row's per-tool hook line to its probe
// entry (every sandbox-launchable tool) and drops the per-launch
// disclosures from the row's own list: no_hook_gating is said per tool,
// only where gating does not apply.
func hostedFillHookNotices(e *dashapi.SandboxBackendAvail, cfg config.TerminalSandboxConfig) {
	e.Disclosures = slices.DeleteFunc(e.Disclosures, func(d dashapi.SandboxDisclosure) bool {
		return sandboxbackend.Disclosure(d.ID).PerLaunch()
	})
	enforcing := onceBool(hostedGuardEnforcing)
	for _, c := range integration.Capabilities() {
		if !integration.TerminalLaunchable(c) || len(c.Sandbox.StateRW) == 0 {
			continue
		}
		r := hostedGuardHooksFor(c.Tool, cfg.Hosted, enforcing)
		if e.HookNotices == nil {
			e.HookNotices = map[string]dashapi.SandboxHookNotice{}
		}
		e.HookNotices[c.Tool] = dashapi.SandboxHookNotice{Gated: r.Seed, Code: r.Reason, Message: r.Message, Technical: r.Technical}
	}
}

// onceBool runs f at most once.
func onceBool(f func() bool) func() bool {
	done, v := false, false
	return func() bool {
		if !done {
			done, v = true, f()
		}
		return v
	}
}

// hostedGuardHooksCoveredNames are the display names of the launchable
// tools whose hooks can be set up in a box (the consent line names them).
func hostedGuardHooksCoveredNames() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if integration.TerminalLaunchable(c) && len(c.Sandbox.StateRW) > 0 && hostedGuardHooksCovered(c.Tool) {
			out = append(out, integration.DisplayName(c.Tool))
		}
	}
	slices.Sort(out)
	return out
}

// hostedApplyHookConsent puts the guard_hooks rule on the consent screen's
// "Hooks and guard" line. The rule is stated once per provider, so a
// resolution that changes per tool or with the machine's guard mode needs
// no new consent (SBXD-0): seeding sends nothing new anywhere (the hook
// calls travel the run's existing relay to this machine).
func hostedApplyHookConsent(scr *sandboxremote.ConsentScreen, cfg config.TerminalSandboxHostedConfig) {
	scr.SetHookLine(sandboxremote.GuardHooksConsentLine(cfg.GuardHooks, hostedGuardHooksCoveredNames()))
}
