package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func layerOf(class vocab.IsoClass, mut ...func(*sandboxbackend.Capability)) sandboxbackend.Capability {
	c := sandboxbackend.Capability{Iso: sandboxbackend.Isolation{Class: class, Location: vocab.LocationLocal, Tenancy: sandboxbackend.TenancyPerRun}}
	for _, m := range mut {
		m(&c)
	}
	return c
}

// TestNestingRules: one case per row of the nesting table built in P1a
// (N1 to N8 and N10; N9 and N11 to N14 need the nativeSandboxes side table
// and land with it).
func TestNestingRules(t *testing.T) {
	vm := layerOf(vocab.ClassHWVM)
	proc := layerOf(vocab.ClassProcess)
	ctr := layerOf(vocab.ClassContainer)
	remote := layerOf(vocab.ClassHWVM, func(c *sandboxbackend.Capability) { c.Iso.Location = vocab.LocationRemote })
	shared := layerOf(vocab.ClassContainer, func(c *sandboxbackend.Capability) { c.Iso.Tenancy = sandboxbackend.TenancyShared })
	seat := layerOf(vocab.ClassProcess, func(c *sandboxbackend.Capability) { c.Seatbelt = true })
	userns := layerOf(vocab.ClassContainer, func(c *sandboxbackend.Capability) { c.AllowsNestedUserns = true })
	kvm := layerOf(vocab.ClassContainer, func(c *sandboxbackend.Capability) { c.PassesKVM = true })
	for _, tc := range []struct {
		name  string
		stack []Layer
		ok    bool
		rule  string
	}{
		{"depth one", []Layer{{proc, true}}, true, ""},
		{"N1 remote inside a local layer", []Layer{{vm, true}, {remote, false}}, false, "N1"},
		{"N1 remote outermost", []Layer{{remote, true}, {proc, false}}, true, ""},
		{"N2 process inside a VM", []Layer{{vm, true}, {proc, false}}, true, ""},
		{"N3 container inside a VM", []Layer{{vm, true}, {ctr, false}}, true, ""},
		{"N4 process inside a container without nested userns", []Layer{{ctr, true}, {proc, false}}, false, "N4"},
		{"N4 process inside a container with nested userns", []Layer{{userns, true}, {proc, false}}, true, ""},
		{"N5 VM inside a container without /dev/kvm", []Layer{{ctr, true}, {vm, false}}, false, "N5"},
		{"N5 VM inside a container passing /dev/kvm", []Layer{{kvm, true}, {vm, false}}, true, ""},
		{"N6 Seatbelt inside Seatbelt", []Layer{{seat, true}, {seat, false}}, false, "N6"},
		{"N7 a process sandbox as an outer layer", []Layer{{proc, true}, {ctr, false}}, false, "N7"},
		{"N8 two network owners", []Layer{{vm, true}, {proc, true}}, false, "N8"},
		{"N8 no network owner", []Layer{{proc, false}}, false, "N8"},
		{"N10 a shared VM as a layer", []Layer{{shared, true}}, false, "N10"},
		{"unlisted pair", []Layer{{vm, true}, {vm, false}}, false, "N-unlisted"},
		{"empty", nil, false, "N0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ValidateStack(tc.stack)
			if v.OK != tc.ok || (!tc.ok && v.Rule != tc.rule) {
				t.Fatalf("verdict %+v, want ok %v rule %s", v, tc.ok, tc.rule)
			}
		})
	}
}

func TestStackDerivations(t *testing.T) {
	stack := []Layer{{layerOf(vocab.ClassHWVM), true}, {layerOf(vocab.ClassProcess), false}}
	if got := EffectiveClass(stack); got != vocab.ClassHWVM {
		t.Errorf("effective class %s", got)
	}
	if got := StackCapture([]vocab.CaptureLevel{vocab.CaptureFull, vocab.CaptureTranscriptsOnly}); got != vocab.CaptureTranscriptsOnly {
		t.Errorf("stack capture %s", got)
	}
	if got := StackCapture(nil); got != vocab.CaptureNone {
		t.Errorf("empty stack capture %s", got)
	}
}
