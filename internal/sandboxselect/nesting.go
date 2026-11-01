package sandboxselect

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// Layer is one layer of a stack, outermost first.
type Layer struct {
	Row sandboxbackend.Capability
	// OwnsNetwork: this layer owns the network boundary of the run (N8:
	// exactly one layer does).
	OwnsNetwork bool
}

// NestingVerdict is what the nesting table says about a stack.
type NestingVerdict struct {
	OK     bool
	Rule   string
	Reason string
}

// stackRule is a rule over the whole stack.
type stackRule struct {
	id    string
	check func(stack []Layer) (refused bool, reason string)
}

// pairRule is a rule over one (outer, inner) pair; the first matching row
// decides the pair.
type pairRule struct {
	id      string
	match   func(outer, inner sandboxbackend.Capability) bool
	allowed func(outer, inner sandboxbackend.Capability) bool
	reason  string
}

// stackRules come first (section 4.4 N1, N8, N10).
var stackRules = []stackRule{
	{"N1", func(s []Layer) (bool, string) {
		for i, l := range s {
			if i > 0 && l.Row.Iso.Location == vocab.LocationRemote {
				return true, "a remote box must be the outermost layer"
			}
		}
		return false, ""
	}},
	{"N10", func(s []Layer) (bool, string) {
		for _, l := range s {
			if l.Row.Iso.Tenancy == sandboxbackend.TenancyShared {
				return true, "a shared VM is a host substrate, not a per-run layer"
			}
		}
		return false, ""
	}},
	{"N8", func(s []Layer) (bool, string) {
		n := 0
		for _, l := range s {
			if l.OwnsNetwork {
				n++
			}
		}
		if n != 1 {
			return true, "exactly one layer must own the network boundary"
		}
		return false, ""
	}},
}

func isClass(c sandboxbackend.Capability, cl vocab.IsoClass) bool { return c.Iso.Class == cl }

// pairRules is the pairwise half of the nesting table, first match wins; a
// pair no row matches is refused.
var pairRules = []pairRule{
	{
		// N9 comes first: a Landlock ruleset stacks innermost under any
		// layer (rulesets always stack, up to 16), including under a process
		// layer, which N7 otherwise keeps innermost.
		"N9", func(_, i sandboxbackend.Capability) bool { return i.Landlock },
		func(_, _ sandboxbackend.Capability) bool { return true }, "",
	},
	{
		"N6", func(o, i sandboxbackend.Capability) bool { return o.Seatbelt && i.Seatbelt },
		func(_, _ sandboxbackend.Capability) bool { return false }, "Seatbelt cannot nest",
	},
	{
		"N7", func(o, _ sandboxbackend.Capability) bool { return isClass(o, vocab.ClassProcess) },
		func(_, _ sandboxbackend.Capability) bool { return false }, "a process sandbox is always the innermost layer",
	},
	{
		"N2", func(o, i sandboxbackend.Capability) bool {
			return isClass(o, vocab.ClassHWVM) && isClass(i, vocab.ClassProcess)
		},
		func(_, _ sandboxbackend.Capability) bool { return true }, "",
	},
	{
		"N3", func(o, i sandboxbackend.Capability) bool {
			return isClass(o, vocab.ClassHWVM) && isClass(i, vocab.ClassContainer)
		},
		func(_, _ sandboxbackend.Capability) bool { return true }, "",
	},
	{
		"N4", func(o, i sandboxbackend.Capability) bool {
			return isClass(o, vocab.ClassContainer) && isClass(i, vocab.ClassProcess)
		},
		func(o, _ sandboxbackend.Capability) bool { return o.AllowsNestedUserns }, "the outer container does not allow nested user namespaces",
	},
	{
		"N5", func(o, i sandboxbackend.Capability) bool {
			return isClass(o, vocab.ClassContainer) && isClass(i, vocab.ClassHWVM)
		},
		func(o, _ sandboxbackend.Capability) bool { return o.PassesKVM }, "the outer container does not pass /dev/kvm",
	},
}

// ValidateStack walks the nesting table over a stack, outermost first. An
// empty stack is refused.
func ValidateStack(stack []Layer) NestingVerdict {
	if len(stack) == 0 {
		return NestingVerdict{Rule: "N0", Reason: "an empty stack"}
	}
	for _, r := range stackRules {
		if bad, why := r.check(stack); bad {
			return NestingVerdict{Rule: r.id, Reason: why}
		}
	}
	for i := 0; i+1 < len(stack); i++ {
		outer, inner := stack[i].Row, stack[i+1].Row
		matched := false
		for _, r := range pairRules {
			if !r.match(outer, inner) {
				continue
			}
			matched = true
			if !r.allowed(outer, inner) {
				return NestingVerdict{Rule: r.id, Reason: r.reason}
			}
			break
		}
		if !matched {
			return NestingVerdict{Rule: "N-unlisted", Reason: "no nesting row allows " + string(outer.Iso.Class) + " around " + string(inner.Iso.Class)}
		}
	}
	return NestingVerdict{OK: true}
}

// EffectiveClass is the highest class among the stack's layers (each layer
// already judged as built, so a degraded layer was lowered before this).
func EffectiveClass(stack []Layer) vocab.IsoClass {
	best := vocab.ClassNone
	for _, l := range stack {
		if l.Row.Iso.Class.Rank() > best.Rank() {
			best = l.Row.Iso.Class
		}
	}
	return best
}

// StackCapture is the minimum of the layers' computed levels (any layer
// can cut capture).
func StackCapture(levels []vocab.CaptureLevel) vocab.CaptureLevel {
	if len(levels) == 0 {
		return vocab.CaptureNone
	}
	out := levels[0]
	for _, l := range levels[1:] {
		out = vocab.MinCapture(out, l)
	}
	return out
}
