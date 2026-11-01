package pspolicy

import (
	"errors"
	"strings"
)

// Scope is one execution-policy scope, as `Get-ExecutionPolicy -List`
// names it.
type Scope string

// The five scopes, named as PowerShell names them.
const (
	MachinePolicy Scope = "MachinePolicy"
	UserPolicy    Scope = "UserPolicy"
	Process       Scope = "Process"
	CurrentUser   Scope = "CurrentUser"
	LocalMachine  Scope = "LocalMachine"
)

// Precedence is the documented scope order, highest first
// (about_Execution_Policies, "Execution policy precedence"). The first scope
// that is not Undefined decides.
var Precedence = []Scope{MachinePolicy, UserPolicy, Process, CurrentUser, LocalMachine}

// groupPolicyScopes are the scopes Group Policy sets. They outrank Process,
// so a host's `-ExecutionPolicy Bypass` cannot lift them, and the developer
// cannot change them with Set-ExecutionPolicy.
var groupPolicyScopes = map[Scope]bool{MachinePolicy: true, UserPolicy: true}

// Policy is an execution-policy value.
type Policy string

// The documented values. Undefined means the scope sets nothing.
const (
	Restricted   Policy = "Restricted"
	AllSigned    Policy = "AllSigned"
	RemoteSigned Policy = "RemoteSigned"
	Unrestricted Policy = "Unrestricted"
	Bypass       Policy = "Bypass"
	Default      Policy = "Default"
	Undefined    Policy = "Undefined"
)

// List is a parsed `Get-ExecutionPolicy -List` answer: scope to value. A
// scope the answer did not name is treated as Undefined.
type List map[Scope]Policy

// Outcome is whether PowerShell runs Observer's hook script.
type Outcome string

// The three outcomes.
const (
	// Runs: the effective policy runs an unsigned, locally written script.
	Runs Outcome = "runs"
	// Blocks: the effective policy refuses it.
	Blocks Outcome = "blocks"
	// Unclassified: the effective value is not one this table knows, so
	// nothing is claimed either way.
	Unclassified Outcome = "unclassified"
)

// policyRule is one row of the policy table: what a value does to an
// unsigned script file Observer wrote on this machine.
type policyRule struct {
	policy  Policy
	outcome Outcome
	// certain is false when the value means different things on different
	// Windows editions (Default).
	certain bool
	reason  string
}

// policyRules is the decision table, one row per documented value. Observer
// writes its hook scripts locally and does not sign them, so a script never
// carries a Mark of the Web (RemoteSigned runs it) and never carries a
// signature (AllSigned refuses it).
var policyRules = []policyRule{
	{Restricted, Blocks, true, "Restricted runs no script file"},
	{AllSigned, Blocks, true, "AllSigned runs only scripts signed by a trusted publisher, and Observer's hook scripts are not signed"},
	{RemoteSigned, Runs, true, "RemoteSigned runs a script written on this machine without a signature"},
	{Unrestricted, Runs, true, "Unrestricted runs a local script without a prompt"},
	{Bypass, Runs, true, "Bypass runs every script"},
	{Default, Blocks, false, "Default is Restricted on Windows client editions (RemoteSigned on Windows Server)"},
}

// Launch is how the host starts PowerShell for the hook.
type Launch struct {
	// BypassArg is true when the host passes `-ExecutionPolicy Bypass`,
	// which sets the Process scope for that one process.
	BypassArg bool
}

// Verdict is Evaluate's answer.
type Verdict struct {
	Outcome Outcome
	// Policy is the effective value.
	Policy Policy
	// Scope is the scope that set it; empty when no scope sets a policy and
	// the edition default applies.
	Scope Scope
	// GroupPolicy is true when Scope is MachinePolicy or UserPolicy: an
	// administrator set it, and only an administrator can change it.
	GroupPolicy bool
	// OverridesBypass is true when the host passes -ExecutionPolicy Bypass
	// and a Group Policy scope outranks it.
	OverridesBypass bool
	// Certain is false when the answer depends on the Windows edition (the
	// Default value, or no scope set at all).
	Certain bool
	// Reason is one sentence on why the value runs or refuses the script.
	Reason string
}

// Evaluate returns the effective policy for a PowerShell process the host
// starts as launch describes, and whether it runs Observer's hook script.
//
// The list's own Process entry is ignored: it is the Process scope of
// whichever PowerShell answered the query (set by its own command line or a
// PSExecutionPolicyPreference in the reader's environment), never the
// host's. The host's Process scope comes from launch.
func Evaluate(l List, launch Launch) Verdict {
	for _, scope := range Precedence {
		p := l[scope]
		if scope == Process {
			p = Undefined
			if launch.BypassArg {
				p = Bypass
			}
		}
		if p == "" || p == Undefined {
			continue
		}
		v := classify(p)
		v.Scope = scope
		v.GroupPolicy = groupPolicyScopes[scope]
		v.OverridesBypass = v.GroupPolicy && launch.BypassArg
		return v
	}
	v := classify(Default)
	v.Reason = "no scope sets a policy; " + v.Reason
	return v
}

// classify looks p up in policyRules.
func classify(p Policy) Verdict {
	for _, r := range policyRules {
		if r.policy == p {
			return Verdict{Outcome: r.outcome, Policy: p, Certain: r.certain, Reason: r.reason}
		}
	}
	return Verdict{Outcome: Unclassified, Policy: p, Reason: "the value " + string(p) + " is not one Observer classifies"}
}

// ListScript is the PowerShell command a reader runs to produce ParseList's
// input: one `Scope=Policy` line per scope. It only reads.
const ListScript = `Get-ExecutionPolicy -List | ForEach-Object { '{0}={1}' -f $_.Scope, $_.ExecutionPolicy }`

// ErrNoScopes is ParseList's error when the text names no known scope.
var ErrNoScopes = errors.New("pspolicy: no execution-policy scope in the answer")

// ParseList parses ListScript's output. Scope names and values are matched
// case-insensitively and returned in their canonical spelling; an unknown
// value is kept verbatim (Evaluate reports it Unclassified); a line naming
// no known scope is ignored. It fails only when no known scope is present.
func ParseList(out string) (List, error) {
	l := List{}
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		scope, known := canonicalScope(strings.TrimSpace(name))
		if !known {
			continue
		}
		l[scope] = canonicalPolicy(strings.TrimSpace(value))
	}
	if len(l) == 0 {
		return nil, ErrNoScopes
	}
	return l, nil
}

func canonicalScope(s string) (Scope, bool) {
	for _, sc := range Precedence {
		if strings.EqualFold(s, string(sc)) {
			return sc, true
		}
	}
	return "", false
}

func canonicalPolicy(s string) Policy {
	if s == "" || strings.EqualFold(s, string(Undefined)) {
		return Undefined
	}
	for _, r := range policyRules {
		if strings.EqualFold(s, string(r.policy)) {
			return r.policy
		}
	}
	return Policy(s)
}
