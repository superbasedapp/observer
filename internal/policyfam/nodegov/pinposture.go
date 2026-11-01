package nodegov

import (
	"fmt"
	"sort"
	"sync"
)

// pinposture.go is the module posture-provider seam for settings.pin
// (roadmap section 11 item 7, N3; the governance kit left it undone). The
// per-key directions compilePinned checks are necessary but not sufficient:
// pins that are each safe can together weaken a node (sandbox plan v2
// section 8.5). A module that owns pinnable keys registers one evaluator
// for them here; the node's accept path (cmd/observer's CheckPosture for
// node.governance) runs every evaluator whose keys a body pins, and a
// refusal rejects the body with posture_loosened naming the axis.
//
// The registry holds no module types: an evaluator is a plain function over
// the pinned map, so this package stays pure and a module compiled out of a
// build simply registers nothing (its keys then carry their per-key
// directions only).

// PinPostureCheck evaluates a pin set for the keys its module owns. pins
// holds only those keys (normalized values, as PolicySpec.Pinned carries
// them). It returns the first axis the pins would loosen on this node with
// an error, or "" and nil when the node stays at least as strict.
type PinPostureCheck func(pins map[string]any) (axis string, err error)

type pinPostureProvider struct {
	owner string
	keys  []string
	check PinPostureCheck
}

var (
	pinPostureMu        sync.RWMutex
	pinPostureProviders = map[string]pinPostureProvider{}
)

// RegisterPinPosture registers owner's evaluator for keys. Every key must be
// a PinnableKeys row, and no key may belong to two owners: a second owner of
// a key, an unknown key, an empty owner or a nil check is refused with an
// error and nothing is registered (the module's init logs it; the keys then
// keep their per-key directions only, never a silent second evaluator).
func RegisterPinPosture(owner string, keys []string, check PinPostureCheck) error {
	if owner == "" || check == nil || len(keys) == 0 {
		return fmt.Errorf("nodegov.RegisterPinPosture: owner, keys and check are required")
	}
	for _, k := range keys {
		if !IsPinnableKey(k) {
			return fmt.Errorf("nodegov.RegisterPinPosture: %s names %q, which is not a pinnable key", owner, k)
		}
	}
	pinPostureMu.Lock()
	defer pinPostureMu.Unlock()
	if _, dup := pinPostureProviders[owner]; dup {
		return fmt.Errorf("nodegov.RegisterPinPosture: %s is already registered", owner)
	}
	for other, p := range pinPostureProviders {
		for _, k := range keys {
			for _, ok := range p.keys {
				if k == ok {
					return fmt.Errorf("nodegov.RegisterPinPosture: %q already belongs to %s", k, other)
				}
			}
		}
	}
	pinPostureProviders[owner] = pinPostureProvider{owner: owner, keys: append([]string(nil), keys...), check: check}
	return nil
}

// SwapPinPostureForTest replaces owner's registration for the length of a
// test (nil removes it) and returns the function that puts the registry
// back. Tests only.
func SwapPinPostureForTest(owner string, keys []string, check PinPostureCheck) (restore func()) {
	pinPostureMu.Lock()
	prev, had := pinPostureProviders[owner]
	if check == nil {
		delete(pinPostureProviders, owner)
	} else {
		pinPostureProviders[owner] = pinPostureProvider{owner: owner, keys: append([]string(nil), keys...), check: check}
	}
	pinPostureMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			pinPostureMu.Lock()
			defer pinPostureMu.Unlock()
			if had {
				pinPostureProviders[owner] = prev
			} else {
				delete(pinPostureProviders, owner)
			}
		})
	}
}

// PinPostureOwners lists the registered owners, sorted.
func PinPostureOwners() []string {
	pinPostureMu.RLock()
	defer pinPostureMu.RUnlock()
	out := make([]string, 0, len(pinPostureProviders))
	for o := range pinPostureProviders {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// CheckPinPosture runs, in owner order, every registered evaluator whose
// keys pins names, each with only its own keys. The first refusal wins. A
// pin set naming none of a module's keys never runs that module's
// evaluator, so a body that pins nothing a module owns costs it nothing.
func CheckPinPosture(pins map[string]any) (axis string, err error) {
	if len(pins) == 0 {
		return "", nil
	}
	pinPostureMu.RLock()
	providers := make([]pinPostureProvider, 0, len(pinPostureProviders))
	for _, p := range pinPostureProviders {
		providers = append(providers, p)
	}
	pinPostureMu.RUnlock()
	sort.Slice(providers, func(i, j int) bool { return providers[i].owner < providers[j].owner })
	for _, p := range providers {
		own := map[string]any{}
		for _, k := range p.keys {
			if v, ok := pins[k]; ok {
				own[k] = v
			}
		}
		if len(own) == 0 {
			continue
		}
		if axis, err := p.check(own); err != nil {
			return axis, err
		}
	}
	return "", nil
}

// SpecPins is the pin set a compiled body applies: its `pinned` block and
// its feature locks' expansion together (one key, one value: Compile already
// refused a disagreement).
func SpecPins(s PolicySpec) map[string]any {
	if len(s.Pinned) == 0 && len(s.FeaturePinned) == 0 {
		return nil
	}
	out := make(map[string]any, len(s.Pinned)+len(s.FeaturePinned))
	for k, v := range s.FeaturePinned {
		out[k] = v
	}
	for k, v := range s.Pinned {
		out[k] = v
	}
	return out
}

// pinLintNotes are the publish-lint notes per list direction (sandbox plan
// v2 section 8.5): the server cannot compute a node's posture, so for the
// operators whose result depends on each node's own list it says, before
// publication, what a node does when the result would loosen it.
var pinLintNotes = map[Direction]string{
	DirOrderedFilter:   "removes entries from each node's own order; a node whose first choice it removes for a weaker one refuses the body with posture_loosened, and on a node whose every entry it removes nothing is enabled (with the sandbox on, that node refuses the body the same way)",
	DirSetIntersection: "keeps only entries each node also allows; on a node whose own list shares no entry with it nothing is allowed (for remote_allowed_hosts, remote clones turn off); an empty intersection never means any",
}

// PinPostureWarnings is the publish lint for a pin set: one note per pinned
// key whose direction makes the result depend on each node's own value. It
// never refuses: the per-key directions (compilePinned) are the refusal at
// publish, and the result check runs on each node at accept.
func PinPostureWarnings(pins map[string]any) []string {
	var out []string
	for _, k := range sortedKeys(pins) {
		row, ok := LookupPinnableKey(k)
		if !ok {
			continue
		}
		if note, ok := pinLintNotes[row.Direction]; ok {
			out = append(out, fmt.Sprintf("pinned.%s %s", k, note))
		}
	}
	return out
}
