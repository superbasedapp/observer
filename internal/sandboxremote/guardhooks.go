package sandboxremote

import "strings"

// guardhooks.go decides whether a hosted run's box gets guard's hook
// registration (lane HOOKS, decision SBXD-6, ledger SBX-HOOK-1), and owns
// every sentence that says so: the New Terminal dialog's per-tool line, the
// consent screen's "Hooks and guard" line and the Isolation picker's
// no_hook_gating disclosure (HostedHookNote, shown only when the line says
// gating does not apply).
//
// [terminal.sandbox.hosted].guard_hooks is auto (the default; "" reads as
// auto), on or off. auto seeds the hooks whenever guard enforcement is in
// force on this machine (either gate family, the same answer a failing gate
// hook reads, docs/guard.md "Hook failure semantics"). Seeding is possible
// only for a tool whose hook mechanism a box can be seeded for (the caller
// passes internal/hook.BoxHooksCover). The rule table is walked top-down.

// The guard_hooks values.
const (
	GuardHooksAuto = "auto"
	GuardHooksOn   = "on"
	GuardHooksOff  = "off"
)

// GuardHooksModes are the accepted values, in the order a picker offers
// them ("" is accepted too and means auto).
var GuardHooksModes = []string{GuardHooksAuto, GuardHooksOn, GuardHooksOff}

// The resolution reasons (closed; shown only under "Technical details").
const (
	GuardHooksReasonOff          = "off_by_setting"
	GuardHooksReasonNotCovered   = "tool_not_covered"
	GuardHooksReasonOn           = "on_by_setting"
	GuardHooksReasonEnforcing    = "auto_guard_enforcing"
	GuardHooksReasonNotEnforcing = "auto_guard_not_enforcing"
)

// GuardHooksInput is what the rule reads for one launch.
type GuardHooksInput struct {
	// Mode is the guard_hooks value ("" = auto).
	Mode string
	// Enforcing is whether guard enforcement is in force on this machine.
	Enforcing bool
	// Covered is whether the agent tool's hook mechanism can be seeded
	// into a box (hook.BoxHooksCover).
	Covered bool
	// Tool is the tool's display name, for the sentence.
	Tool string
}

// GuardHooksResult is the rule's answer.
type GuardHooksResult struct {
	// Seed is whether the box gets the tool's hook registration, so guard
	// checks the agent's tool calls there.
	Seed bool
	// Reason is the closed reason code.
	Reason string
	// Message is the plain sentence for the person, before Start.
	Message string
	// Technical is the internal detail ("Technical details").
	Technical string
}

// guardHooksRule is one row of the table.
type guardHooksRule struct {
	match  func(GuardHooksInput) bool
	seed   bool
	reason string
	say    func(GuardHooksInput) string
}

// guardHooksRules is the ordered rule table (one test row each,
// TestResolveGuardHooksRules).
var guardHooksRules = []guardHooksRule{
	{
		match: func(in GuardHooksInput) bool { return in.Mode == GuardHooksOff }, reason: GuardHooksReasonOff,
		say: func(GuardHooksInput) string {
			return "\"Guard in the box\" is set to Never in Terminals > Settings > Hosted sandboxes. " + HostedHookNote
		},
	},
	{
		match: func(in GuardHooksInput) bool { return !in.Covered }, reason: GuardHooksReasonNotCovered,
		say: func(in GuardHooksInput) string {
			return "Observer cannot set up its hooks for " + toolWords(in.Tool) + " in a box yet. " + HostedHookNote
		},
	},
	{
		match: func(in GuardHooksInput) bool { return in.Mode == GuardHooksOn }, seed: true, reason: GuardHooksReasonOn,
		say: guardHooksSeededSentence,
	},
	{
		match: func(in GuardHooksInput) bool { return in.Enforcing }, seed: true, reason: GuardHooksReasonEnforcing,
		say: guardHooksSeededSentence,
	},
	{
		match: func(GuardHooksInput) bool { return true }, reason: GuardHooksReasonNotEnforcing,
		say: func(GuardHooksInput) string {
			return "Guard enforcement is off on this machine, so Observer does not set up its hooks in the box. " + HostedHookNote
		},
	},
}

// guardHooksSeededSentence says what a seeded box does, including the cost
// of a dropped link.
func guardHooksSeededSentence(in GuardHooksInput) string {
	return "Observer sets up its hooks for " + toolWords(in.Tool) + " in the box, so this machine's guard checks the agent's commands and file edits there. If the box's link to this machine drops, checked actions are blocked until it is back."
}

// toolWords is the tool's name in a sentence ("the agent" when unknown).
func toolWords(tool string) string {
	if strings.TrimSpace(tool) == "" {
		return "the agent"
	}
	return tool
}

// NormalizeGuardHooks is the mode a value means: "" (and any spacing) is
// auto; any other value is returned as given.
func NormalizeGuardHooks(mode string) string {
	if m := strings.TrimSpace(mode); m != "" {
		return m
	}
	return GuardHooksAuto
}

// ResolveGuardHooks walks the rule table for one launch.
func ResolveGuardHooks(in GuardHooksInput) GuardHooksResult {
	in.Mode = NormalizeGuardHooks(in.Mode)
	for _, r := range guardHooksRules {
		if r.match(in) {
			return GuardHooksResult{Seed: r.seed, Reason: r.reason, Message: r.say(in), Technical: "guard_hooks = " + in.Mode + ": " + r.reason}
		}
	}
	return GuardHooksResult{}
}

// GuardHooksConsentLine is the consent screen's "Hooks and guard" line: the
// rule once, per provider, so a resolution that changes per tool or with
// the machine's guard mode needs no second consent (SBXD-0). covered names
// the tools a box can be seeded for. Seeding sends nothing new anywhere:
// the hook calls travel the run's existing relay to this machine.
func GuardHooksConsentLine(mode string, covered []string) string {
	tools := "the tools it can"
	if len(covered) > 0 {
		tools = strings.Join(covered, ", ")
	}
	switch NormalizeGuardHooks(mode) {
	case GuardHooksOff:
		return "Switched off for hosted boxes: Observer sets up no hooks in the box. " + HostedHookNote
	case GuardHooksOn:
		return "Observer sets up its hooks in the box for " + tools + ", so this machine's guard checks the agent's commands and file edits there; if the box's link to this machine drops, checked actions are blocked until it is back. For any other tool, no hook runs in the box unless the project itself commits one."
	}
	return "Whenever guard enforcement is on for this machine, Observer sets up its hooks in the box for " + tools + ", so this machine's guard checks the agent's commands and file edits there; if the box's link to this machine drops, checked actions are blocked until it is back. With enforcement off, or for any other tool, no hook runs in the box unless the project itself commits one."
}

// SetHookLine replaces the consent screen's "Hooks and guard" line with
// value (by label, as setConsentLine does).
func (s *ConsentScreen) SetHookLine(value string) {
	setConsentLine(s.Lines, HooksConsentLabel, value)
}

// HooksConsentLabel labels the consent screen's hooks line.
const HooksConsentLabel = "Hooks and guard"
