package secassess

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The live network tier the confined kinds need.
const confinedTier = "proxy_only"

// loopbackBackends is the grounded table of sandbox backends that give a box
// a network namespace of its own with a private loopback, so a development
// server started inside the box is reachable only from inside it. A backend is
// listed only with the document that grounds it; every other row is refused
// for a kind whose confinement is the sandbox (plan section 4, rule E9). The
// registry has no "private loopback" column and adding one is a change to
// every backend row, so this is data here until a backend is live checked.
var loopbackBackends = []struct {
	ID     string
	Ground string
}{
	{ID: "bwrap", Ground: "docs/sandboxed-terminals.md, \"It is, by default, loopback isolation\" (security ledger SR27-SBX-1): a private network namespace, loopback only"},
}

// LoopbackBackendIDs returns the ids of the grounded backends, in table order.
func LoopbackBackendIDs() []string {
	out := make([]string, 0, len(loopbackBackends))
	for _, b := range loopbackBackends {
		out = append(out, b.ID)
	}
	return out
}

// backendEligible says whether a backend is one an assessment that runs only in
// a sandbox can use on the live network tier (the confined tier, or the internet
// tier when it is relaxed): grounded for an in-box loopback, available, local,
// not beta, capturing fully, and supporting that tier. Rule E9 and AutoBackend
// both read it, so what the plan names and what the launch picks never differ.
func backendEligible(b BackendFact, tierRelaxed bool) bool {
	grounded := false
	for _, g := range loopbackBackends {
		if g.ID == b.ID {
			grounded = true
		}
	}
	live := confinedTier
	if tierRelaxed {
		live = "internet"
	}
	return grounded && b.Available && b.Local && !b.Beta && b.FullCapture && slices.Contains(b.Tiers, live)
}

// AutoBackend is the backend the launch route picks for a kind that runs only
// in a sandbox when the caller names none (Automatic): the first eligible one in
// the probe's order, "" when there is none. A plan that is refused before rule E9
// has chosen reads it to say what the sandbox would be, so a refusal for another
// reason (a target that is not on loopback, say) never reads as "no sandbox is
// chosen".
func AutoBackend(f Facts, tierRelaxed bool) string {
	for _, b := range f.Backends {
		if backendEligible(b, tierRelaxed) {
			return b.ID
		}
	}
	return ""
}

// BackendFact is one sandbox backend as the probe reported it, reduced to the
// facts the rules read.
type BackendFact struct {
	ID    string
	Label string
	// Available: the probe says a launch on this row would be built now.
	Available bool
	// Beta: verification is not live.
	Beta bool
	// Local: the row runs on this machine (not a hosted provider).
	Local bool
	// Tiers are the network tiers the row supports.
	Tiers []string
	// FullCapture: the computed capture level on the live tier starts with
	// "full" (the hook path reaches the home daemon and the tier is enforced).
	FullCapture bool
	// MasksSecrets: the row can hide the workspace's secret files inside the box
	// on request (the probe's capability flag; decision D32). Read only by
	// MaskCapabilityOf, never by the eligibility rules.
	MasksSecrets bool
}

// Facts is what the dashboard knows when it asks "may this run": plain data
// read from the sandbox probe, the integration registry and the project.
type Facts struct {
	// ProjectOnDisk: the project's folder is a directory on this machine.
	ProjectOnDisk bool
	// SandboxProbed: the daemon has a sandbox probe at all.
	SandboxProbed bool
	// Tier is the live network tier ([terminal.sandbox].egress).
	Tier     string
	Backends []BackendFact
	// ToolSandboxable and ToolSandboxReason are the probe's per-tool answer.
	ToolSandboxable   bool
	ToolSandboxReason string
	// ToolProxyRouted: the tool has a live-verified proxy route.
	ToolProxyRouted bool
	// SourceLiveAvailable: the "live" workspace source is available.
	SourceLiveAvailable bool
	// ProxyPort is Observer's own proxy port (an in-box launcher listens on
	// it), 0 when unknown.
	ProxyPort int
	// GatewayPort is the in-box egress gateway's port when the live tier has
	// a gateway (sandbox.GatewayPort), 0 when it has none or it is unknown.
	GatewayPort int
	// TierRelaxOK says the consent route of the tier relaxation is self (the
	// caller ran ConsentRoute); TierRelax is what the rule re-checks it against
	// (plan section 13.9): the live tier must be internet with a narrowed host
	// list, whatever the caller decided.
	TierRelaxOK bool
	TierRelax   TierFacts
}

// Request is what the caller asks for.
type Request struct {
	Kind ID
	// Target is the typed target URL, ConfirmTarget the string the dialog
	// echoes back as the one the developer saw.
	Target        string
	ConfirmTarget string
	// Sandbox is whether the caller asked for a sandboxed launch.
	Sandbox bool
	// Backend is the caller's backend choice ("" or "auto" is none).
	Backend string
	// WorkspaceSource is the caller's source ("" is live).
	WorkspaceSource string
	// Plan: the request is a read of the plan, not a launch; the confirmation
	// echo is not required yet.
	Plan bool
	// TierRelax is the developer's tick of the tier relaxation: the run may
	// start under the live internet tier (plan section 13.9).
	TierRelax bool
}

// Verdict is the answer of Eligible.
type Verdict struct {
	OK bool
	// Rule is the refusing rule's id ("E3"), Code its closed refusal code and
	// Reason the sentence the developer reads (what is wrong, what to do).
	Rule   string
	Code   string
	Reason string
	// Target is the normalized target for a kind that has one.
	Target Target
	// What the server forces onto the launch.
	ForceSandbox bool
	ForceSource  string
	Backend      string
	// TierRelaxed says E8 accepted the live tier through the tier relaxation.
	TierRelaxed bool
}

// The refusal codes.
const (
	CodeNotLaunchable      = "not_agent_shaped"
	CodeProjectMissing     = "project_missing"
	CodeTargetRequired     = "target_required"
	CodeTargetUnconfirmed  = "target_unconfirmed"
	CodeTargetReservedPort = "target_reserved_port"
	CodeSandboxRequired    = "sandbox_required"
	CodeSandboxUnavailable = "sandbox_unavailable"
	CodeTierNotConfined    = "tier_not_confined"
	CodeToolNotProxyRouted = "tool_not_proxy_routed"
	CodeBackendNotGrounded = "backend_not_grounded"
	CodeSourceNotLive      = "source_not_live"
)

// rule is one row of the eligibility table. check returns the refusal reason,
// or "" when the row passes; it may fill v for later rows and the caller.
type rule struct {
	ID      string
	Code    string
	Applies func(Kind) bool
	check   func(k Kind, f Facts, r Request, v *Verdict) string
}

func always(Kind) bool           { return true }
func hasTarget(k Kind) bool      { return k.Target == TargetRequired }
func needsSandbox(k Kind) bool   { return k.Sandbox == SandboxRequired }
func launchableKind(k Kind) bool { return k.Launchable }

// rules is THE eligibility table, walked top to bottom; the first refusal
// wins. One test row per rule.
var rules = []rule{
	{ID: "E1", Code: CodeNotLaunchable, Applies: always, check: func(k Kind, _ Facts, _ Request, _ *Verdict) string {
		if k.Launchable {
			return ""
		}
		return k.Reason
	}},
	{ID: "E2", Code: CodeProjectMissing, Applies: launchableKind, check: func(_ Kind, f Facts, _ Request, _ *Verdict) string {
		if f.ProjectOnDisk {
			return ""
		}
		return "This project's folder is not on this machine, so an agent cannot work in it. Pick a project whose folder is here."
	}},
	{ID: "E3", Code: CodeTargetRequired, Applies: hasTarget, check: func(_ Kind, _ Facts, r Request, v *Verdict) string {
		if strings.TrimSpace(r.Target) == "" {
			return "Name the development server to test, for example http://localhost:3000/. It must be on this machine (localhost, 127.0.0.1 or [::1]) and have a port."
		}
		t, err := ParseTarget(r.Target)
		if err != nil {
			if errors.Is(err, ErrNotLoopback) {
				return "The target must be localhost, 127.0.0.1 or [::1] with a port. Only your own app, on this machine, can be tested."
			}
			return "The target is not usable: " + strings.TrimPrefix(err.Error(), "secassess: ") + "."
		}
		if len(t.String()) > MaxLaunchTargetBytes {
			return fmt.Sprintf("The target address is over %d characters. Type the development server's address with a short path, for example http://localhost:3000/.", MaxLaunchTargetBytes)
		}
		v.Target = t
		return ""
	}},
	{ID: "E4", Code: CodeTargetUnconfirmed, Applies: hasTarget, check: func(_ Kind, _ Facts, r Request, v *Verdict) string {
		if r.Plan || strings.TrimSpace(r.ConfirmTarget) == v.Target.String() {
			return ""
		}
		return "The confirmation does not match the target (" + v.Target.String() + "). Confirm the exact target shown."
	}},
	{ID: "E5", Code: CodeTargetReservedPort, Applies: hasTarget, check: func(_ Kind, f Facts, _ Request, v *Verdict) string {
		if f.ProxyPort != 0 && v.Target.PortNumber() == f.ProxyPort {
			return "Port " + v.Target.Port + " is Observer's own proxy port, which the sandbox listens on. Pick the port your development server uses."
		}
		if f.GatewayPort != 0 && v.Target.PortNumber() == f.GatewayPort {
			return "Port " + v.Target.Port + " is the port the sandbox's egress gateway listens on, inside the box. Pick the port your development server uses."
		}
		return ""
	}},
	{ID: "E6", Code: CodeSandboxRequired, Applies: needsSandbox, check: func(_ Kind, _ Facts, r Request, _ *Verdict) string {
		if r.Sandbox {
			return ""
		}
		return "This assessment runs only in a sandbox. Turn on Run in sandbox; it is never run on the bare machine."
	}},
	{ID: "E7", Code: CodeSandboxUnavailable, Applies: needsSandbox, check: func(_ Kind, f Facts, _ Request, _ *Verdict) string {
		if !f.SandboxProbed {
			return "This daemon has no sandbox support, and this assessment runs only in a sandbox."
		}
		available := false
		for _, b := range f.Backends {
			if b.Available {
				available = true
			}
		}
		if !available {
			return "No sandbox backend is available on this machine (Terminals > Settings > Sandbox isolation shows why), and this assessment runs only in a sandbox."
		}
		if !f.ToolSandboxable {
			reason := f.ToolSandboxReason
			if reason == "" {
				reason = "no grounded sandbox row for this tool"
			}
			return "This agent cannot be sandboxed: " + reason + ". Pick another agent."
		}
		return ""
	}},
	{ID: "E8", Code: CodeTierNotConfined, Applies: needsSandbox, check: func(_ Kind, f Facts, r Request, v *Verdict) string {
		if f.Tier == confinedTier {
			return ""
		}
		tier := f.Tier
		if tier == "" {
			tier = "internet"
		}
		// The tier relaxation (plan section 13.9): the developer's tick, the
		// caller's own consent decision AND the live facts must all hold, so a
		// mistaken caller can never widen anything but the internet tier with a
		// host list.
		if r.TierRelax && f.TierRelaxOK && tier == "internet" && f.TierRelax.Narrowed() {
			v.TierRelaxed = true
			return ""
		}
		switch tier {
		case "none":
			return "The sandbox network is set to none, which leaves the agent no route to its model. Set " + LabelSandboxNetwork + " to proxy only in " + WhereSandbox + "."
		default:
			return "The sandbox network is set to " + TierName(tier) + ", which is not confined enough for this assessment. Set " + LabelSandboxNetwork + " to proxy only in " + WhereSandbox + " so the model connection is the only route out."
		}
	}},
	{ID: "E8b", Code: CodeToolNotProxyRouted, Applies: needsSandbox, check: func(_ Kind, f Facts, _ Request, v *Verdict) string {
		// Under the relaxed internet tier an agent that is not proxy routed
		// reaches its model through the egress gateway.
		if f.ToolProxyRouted || v.TierRelaxed {
			return ""
		}
		return "This agent is not routed through Observer's proxy, so with the sandbox network limited to the model proxy it would start with no route to its model. Pick an agent Observer routes (the Adapters page lists them)."
	}},
	{ID: "E9", Code: CodeBackendNotGrounded, Applies: needsSandbox, check: func(_ Kind, f Facts, r Request, v *Verdict) string {
		choice := strings.TrimSpace(r.Backend)
		if choice == "auto" {
			choice = ""
		}
		for _, b := range f.Backends {
			if choice != "" && b.ID != choice {
				continue
			}
			if backendEligible(b, v.TierRelaxed) {
				v.Backend = b.ID
				return ""
			}
		}
		if choice != "" {
			return "The sandbox backend " + choice + " is not one this assessment can use: it must be available, local, not beta, give the box its own loopback and capture fully on the live network tier. Pick Automatic or " + strings.Join(LoopbackBackendIDs(), ", ") + "."
		}
		return "No sandbox backend on this machine is grounded for an in-box loopback target (today: " + strings.Join(LoopbackBackendIDs(), ", ") + ", on Linux or WSL2, available and not beta). Set one up under Terminals > Settings > Sandbox isolation."
	}},
	{ID: "E10", Code: CodeSourceNotLive, Applies: needsSandbox, check: func(_ Kind, f Facts, r Request, _ *Verdict) string {
		src := strings.TrimSpace(r.WorkspaceSource)
		if src != "" && src != "live" {
			return "A sandboxed assessment uses the live workspace: a clone gives Observer no way to read the result files the agent writes. Choose the live workspace."
		}
		if !f.SourceLiveAvailable {
			return "The live workspace source is not available on this machine, and the result files are read from it."
		}
		return ""
	}},
}

// Eligible walks the rule table for the kind and returns the first refusal,
// or the verdict a launch is built from. An unknown kind is refused as not
// agent-shaped.
func Eligible(id ID, f Facts, r Request) Verdict {
	k, ok := KindByID(string(id))
	if !ok {
		return Verdict{Rule: "E1", Code: CodeNotLaunchable, Reason: "Unknown assessment kind."}
	}
	var v Verdict
	for _, rl := range rules {
		if !rl.Applies(k) {
			continue
		}
		if why := rl.check(k, f, r, &v); why != "" {
			v.OK, v.Rule, v.Code, v.Reason = false, rl.ID, rl.Code, why
			return v
		}
	}
	v.OK = true
	if k.Sandbox == SandboxRequired {
		v.ForceSandbox, v.ForceSource = true, "live"
	}
	return v
}

// RuleIDs returns the rule ids in table order (for the plan and the tests).
func RuleIDs() []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}
