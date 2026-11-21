package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func seccompLayer(s vocab.Seccomp) sandboxbackend.Capability {
	return sandboxbackend.Capability{Iso: sandboxbackend.Isolation{Seccomp: s}}
}

// TestSeccompRunStateRows: one case per row of seccompRunRows, plus the
// shapes that fall through to a later row.
func TestSeccompRunStateRows(t *testing.T) {
	t.Parallel()
	obs := seccompLayer(vocab.SeccompObserverProfile)
	eng := seccompLayer(vocab.SeccompEngineDefault)
	none := seccompLayer(vocab.SeccompNone)
	ungrounded := seccompLayer("")
	for _, c := range []struct {
		name   string
		keyOn  bool
		layers []sandboxbackend.Capability
		want   vocab.SeccompRun
	}{
		{"row 1: key on, Observer's profile", true, []sandboxbackend.Capability{obs}, vocab.SeccompRunObserverDefault},
		{"row 2: engine default, key off", false, []sandboxbackend.Capability{eng}, vocab.SeccompRunEngineDefault},
		{"row 2: engine default, key on", true, []sandboxbackend.Capability{eng}, vocab.SeccompRunEngineDefault},
		{"row 3: Observer's profile, key off", false, []sandboxbackend.Capability{obs}, vocab.SeccompRunOff},
		{"row 4: key on, no filtering layer", true, []sandboxbackend.Capability{none}, vocab.SeccompRunNotApplicable},
		{"row 4: key on, ungrounded layer", true, []sandboxbackend.Capability{ungrounded}, vocab.SeccompRunNotApplicable},
		{"row 5: key off, no filtering layer", false, []sandboxbackend.Capability{none}, vocab.SeccompRunNone},
		{"row 5: key off, no layer", false, nil, vocab.SeccompRunNone},
		{"key on, a stack with Observer's profile inside", true, []sandboxbackend.Capability{none, obs}, vocab.SeccompRunObserverDefault},
	} {
		if got := SeccompRunState(c.keyOn, c.layers); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSeccompRunStateRegistry: every registry row resolves to a valid
// state both ways, and a row that loads no filter never claims one.
func TestSeccompRunStateRegistry(t *testing.T) {
	t.Parallel()
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		for _, on := range []bool{false, true} {
			got := SeccompRunState(on, []sandboxbackend.Capability{row})
			if !got.Valid() {
				t.Errorf("%s key=%v: %q is not in the vocabulary", row.ID, on, got)
			}
			if got.Applied() && row.Iso.Seccomp != vocab.SeccompEngineDefault && !(on && row.FiltersWithObserverProfile()) {
				t.Errorf("%s key=%v: claims %q", row.ID, on, got)
			}
		}
	}
}

// TestSeccompLabels: the key-on states have words; every label is for a
// valid state.
func TestSeccompLabels(t *testing.T) {
	t.Parallel()
	for s := range seccompLabels {
		if !s.Valid() {
			t.Errorf("label for %q", s)
		}
	}
	for _, s := range []vocab.SeccompRun{vocab.SeccompRunObserverDefault, vocab.SeccompRunNotApplicable} {
		if SeccompLabel(s) == "" {
			t.Errorf("%s has no label", s)
		}
	}
	if SeccompLabel(vocab.SeccompRunOff) != "" || SeccompLabel("") != "" {
		t.Error("a key-off state prints a label")
	}
}
