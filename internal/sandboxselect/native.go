package sandboxselect

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// native.go is the agent-native sandbox half of the nesting table (sandbox
// plan v2 section 4.4, rows N11 to N14): what happens to an agent's OWN
// sandbox (Claude Code's, Codex's, Copilot CLI's) inside the layer Observer
// builds. The per-tool facts live in internal/integration's nativeSandboxes
// side table; the cmd layer reduces a row to NativeSandbox at the boundary,
// so this package never names a tool.

// NativeSandbox is what the nesting rows need about the agent's own sandbox.
type NativeSandbox struct {
	// Present: the agent has a native sandbox at all.
	Present bool
	// NeedsFreshProc: it mounts a fresh /proc (N11).
	NeedsFreshProc bool
	// NeedsDevNetTUN: it needs /dev/net/tun and slirp4netns (N12).
	NeedsDevNetTUN bool
	// AppContainer: it is AppContainer-based or creates users and firewall
	// rules (N14).
	AppContainer bool
	// PerRunDisable: a grounded switch turns it off for this run alone (a
	// flag, an env var or a per-run settings file; never a write to the
	// user's global settings, review R2-25).
	PerRunDisable bool
	// PerRunWeak: a grounded per-run switch runs it in a weaker nested
	// mode; UserOn: Observer read that the user turned it on. Weak mode is
	// applied only when both hold (lane SBX-P3D).
	PerRunWeak bool
	UserOn     bool
	// VendorForced: a vendor managed policy forces it on (read from the
	// vendor's documented managed-policy file); ForcedPolicy is the node's
	// [terminal.sandbox].vendor_forced_native (nest_or_refuse or refuse).
	VendorForced bool
	ForcedPolicy string
	// HostOS is the daemon's operating system (a GOOS value): the forced
	// conflict's text offers a layer only where it runs ("" offers it).
	HostOS string
}

// NativeOutcome is what the launch does with the agent's own sandbox.
type NativeOutcome string

// The closed NativeOutcome vocabulary.
const (
	// NativeKept: the agent's sandbox runs inside Observer's layer.
	NativeKept NativeOutcome = "kept"
	// NativeDisable: the launcher applies the per-run disable switch.
	NativeDisable NativeOutcome = "disable"
	// NativeWeakMode: the launcher applies the per-run weak-mode switch.
	NativeWeakMode NativeOutcome = "weak"
	// NativeRefuse: the stack is refused (tool_conflict).
	NativeRefuse NativeOutcome = "refuse"
	// NativeNone: the agent has no native sandbox.
	NativeNone NativeOutcome = "not_applicable"
)

// NativeVerdict is the nesting table's answer for one layer.
type NativeVerdict struct {
	Outcome NativeOutcome
	Rule    string
	Reason  string
	// Forced: a vendor managed policy forces the agent's sandbox on and it
	// runs (recorded org_forced).
	Forced bool
}

// nativeRule is one row: when it matches, the agent's sandbox cannot stay on
// (conflict) or is known to nest (keep).
type nativeRule struct {
	id       string
	match    func(l sandboxbackend.Capability, tier vocab.Tier, n NativeSandbox) bool
	conflict bool
	reason   string
}

// nativeRules is walked top-down; the first matching row decides. A layer no
// row matches keeps the agent's sandbox (the table lists the conflicts the
// analysis found; the probe matrix grounds each Linux cell).
var nativeRules = []nativeRule{
	{"N13", func(l sandboxbackend.Capability, _ vocab.Tier, _ NativeSandbox) bool {
		return l.Iso.Class == vocab.ClassHWVM && l.GuestUnprivUserns
	}, false, "the guest kernel is ours, so the agent's sandbox nests"},
	{"N11", func(l sandboxbackend.Capability, _ vocab.Tier, n NativeSandbox) bool {
		return l.Iso.Class == vocab.ClassProcess && l.ProcView == sandboxbackend.ProcFreshCovered && n.NeedsFreshProc
	}, true, "the agent's sandbox mounts a fresh /proc, which the kernel refuses inside this layer's covered /proc"},
	{"N12", func(l sandboxbackend.Capability, tier vocab.Tier, n NativeSandbox) bool {
		return l.Iso.Class == vocab.ClassProcess && tier != vocab.TierHost && !l.DevNetTUN && n.NeedsDevNetTUN
	}, true, "the agent's sandbox needs /dev/net/tun, which this layer's private network does not provide"},
	{"N14", func(l sandboxbackend.Capability, _ vocab.Tier, n NativeSandbox) bool {
		return l.AppContainer && n.AppContainer
	}, true, "nesting an AppContainer-based sandbox is unproven, so it is refused until a probe shows it works"},
}

// VendorForcedNestOrRefuse and VendorForcedRefuse are the values of
// [terminal.sandbox].vendor_forced_native (sandbox plan 4.4, D-746 Q17).
const (
	VendorForcedNestOrRefuse = "nest_or_refuse"
	VendorForcedRefuse       = "refuse"
)

// conflictOutcome is one row of what a conflict does, walked top-down.
type conflictOutcome struct {
	id      string
	match   func(n NativeSandbox) bool
	outcome NativeOutcome
	reason  func(n NativeSandbox) string
}

// conflictOutcomes is THE table for a matched conflict row: a sandbox a
// vendor policy forces on is refused in a layer no keep row matched (the
// one stack where both run is an hw_vm layer whose guest allows
// unprivileged user namespaces, N13: the cloud-hypervisor row with an image
// set declaring them, lane SBX-P4; nothing switches a launch to it
// automatically); a sandbox the user turned on keeps a weaker nested mode when one
// is grounded per run; otherwise a grounded per-run switch turns it off;
// otherwise the launch is refused.
var conflictOutcomes = []conflictOutcome{
	{"forced", func(n NativeSandbox) bool { return n.VendorForced }, NativeRefuse, func(n NativeSandbox) string {
		if n.ForcedPolicy == VendorForcedRefuse {
			return "a vendor managed policy forces the agent's sandbox on and [terminal.sandbox].vendor_forced_native = refuse (" + VerdictToolConflict + ")"
		}
		if !nestRowRunsOn(n.HostOS) {
			return "a vendor managed policy forces the agent's sandbox on; [terminal.sandbox].vendor_forced_native = nest_or_refuse keeps it only in a layer where both sandboxes run, and no such layer runs on this host (" + VerdictToolConflict + ")"
		}
		return "a vendor managed policy forces the agent's sandbox on; [terminal.sandbox].vendor_forced_native = nest_or_refuse keeps it only in a layer where both sandboxes run: the " + sandboxbackend.BackendCloudHypervisor + " microVM row (beta, with an image set that declares user namespaces, N13); choose it by name, this layer is not one (" + VerdictToolConflict + ")"
	}},
	{"weak", func(n NativeSandbox) bool { return n.UserOn && n.PerRunWeak }, NativeWeakMode, func(NativeSandbox) string {
		return "you turned the agent's sandbox on, so it runs in its weaker nested mode for this run"
	}},
	{"disable", func(n NativeSandbox) bool { return n.PerRunDisable }, NativeDisable, func(NativeSandbox) string { return "" }},
	{"refuse", func(NativeSandbox) bool { return true }, NativeRefuse, func(NativeSandbox) string {
		return "it has no per-run off switch (" + VerdictToolConflict + ")"
	}},
}

// nestHostOS maps a registry host onto the GOOS value it runs under.
var nestHostOS = map[sandboxbackend.HostKind]string{
	sandboxbackend.HostLinux:   "linux",
	sandboxbackend.HostWSL2:    "linux",
	sandboxbackend.HostMacOS:   "darwin",
	sandboxbackend.HostWindows: "windows",
}

// nestRowRunsOn reports whether the layer that keeps a forced agent
// sandbox (the cloud-hypervisor row) is grounded on goos, read from its
// registry row's hosts ("" is not judged and offers it).
func nestRowRunsOn(goos string) bool {
	if goos == "" {
		return true
	}
	row, ok := sandboxbackend.Get(sandboxbackend.BackendCloudHypervisor)
	if !ok {
		return false
	}
	for _, v := range row.Verification {
		if nestHostOS[v.Host] == goos {
			return true
		}
	}
	return false
}

// NativeNesting decides the agent's own sandbox inside one layer on tier: a
// conflict row is resolved by conflictOutcomes; a keep row or no row keeps
// it (recorded org_forced when a vendor policy forces it on).
func NativeNesting(layer sandboxbackend.Capability, tier vocab.Tier, n NativeSandbox) NativeVerdict {
	if !n.Present {
		return NativeVerdict{Outcome: NativeNone}
	}
	for _, r := range nativeRules {
		if !r.match(layer, tier, n) {
			continue
		}
		if !r.conflict {
			return NativeVerdict{Outcome: NativeKept, Rule: r.id, Reason: r.reason, Forced: n.VendorForced}
		}
		for _, o := range conflictOutcomes {
			if !o.match(n) {
				continue
			}
			reason := r.reason
			if extra := o.reason(n); extra != "" {
				reason += "; " + extra
			}
			return NativeVerdict{Outcome: o.outcome, Rule: r.id, Reason: reason}
		}
	}
	return NativeVerdict{Outcome: NativeKept, Rule: "N-native-default", Reason: "no known conflict with this layer", Forced: n.VendorForced}
}

// NativeStateFor is the G19 native_sandbox_state a verdict records. A kept
// sandbox the agent may or may not have turned on records nothing, so the
// evidence never claims a state Observer did not establish.
func NativeStateFor(v NativeVerdict) vocab.NativeSandboxState {
	switch v.Outcome {
	case NativeNone:
		return vocab.NativeNotApplicable
	case NativeDisable:
		return vocab.NativeDisabledByObserver
	case NativeWeakMode:
		return vocab.NativeWeak
	case NativeKept:
		if v.Forced {
			return vocab.NativeOrgForced
		}
		return ""
	default:
		return ""
	}
}
