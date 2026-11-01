package policyfam

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// linked.go is the seam for a policy family whose compiler belongs to an
// optional component (modular packaging, lane MP-L1G; the module family
// template of roadmap F0-9, lane SHR-KIT). Such a family keeps its name in
// SupportedFamilies (the closed enum and its stable order never depend on the
// build: familyTable's LinkedOnly column marks it), but its compiler is
// linked by a registration pair file that the component's omit tag leaves
// out. When the pair is absent, CompileFamilyBody answers ErrFamilyNotLinked
// for that family, so a publish is refused and an accepting node refuses the
// body with a named reason, never a silent no-op. Families using it:
// tools.mcp_access (family_mcpaccess.go, omitted by
// sbo_omit_org_agentaccess), and the module families security.scanning and
// terminals.isolation, whose pair files the security and sandbox lanes add.
//
// A family registered twice is refused, never replaced (JSP-1 R5: the old
// seam silently let a second registration win). Both registrations are
// dropped, every body of the family NACKs with ErrFamilyConflict, and
// LinkedConflicts lists it so the daemon logs it at start. No panic: this is
// library code reached from init.

// ErrFamilyNotLinked is a supported family whose compiler is not in this
// build. Callers can match it with errors.Is.
var ErrFamilyNotLinked = errors.New("policyfam: family compiler is not in this build")

// ErrFamilyConflict is a linked family registered by more than one pair file.
// The family stays unlinked (fail closed: every body NACKs). It wraps
// ErrFamilyNotLinked, so a caller that only knows the older sentinel still
// reads "not linked".
var ErrFamilyConflict = fmt.Errorf("policyfam: family registered more than once: %w", ErrFamilyNotLinked)

// LinkedFamily is the compiler of a family registered through
// RegisterLinkedFamily. Compile and Enforces are required; the other legs
// are optional.
type LinkedFamily struct {
	// Compile is the family's CompileFamilyBody leg: the compiled spec and
	// the canonical body bytes.
	Compile func(raw []byte, maxBytes int64) (spec any, canonicalBody []byte, err error)
	// Enforces is the family's SpecRequestsEnforceMode leg, called with a
	// spec Compile returned.
	Enforces func(spec any) bool
	// RequiredCapabilities derives the capability tokens a compiled body
	// needs on the node (for security.scanning: one token per section). The
	// org server's publish step unions them into the envelope's
	// RequiredCapabilities, so the server and the node agree. Nil: none.
	RequiredCapabilities func(spec any) []string
	// LiveCapabilities is what this build adds to the node's advertised
	// capability tokens for the family (the node side of the same tokens).
	// Nil: none.
	LiveCapabilities func() []string
	// CheckPosture is the family's evaluator for the result-based posture
	// check (roadmap F0-8): it compares this node's effective posture before
	// and after the compiled body, typically through postureop.Compare over
	// the module's axes, and returns the first loosened axis with an error.
	// Nil: the family carries nothing a posture check could refuse.
	CheckPosture func(spec any) (axis string, err error)
	// LintWarnings is the family's publish lint beyond the compile: notes
	// that never stop publication (for terminals.isolation, a floor that
	// only remote rows can meet on some host OS). Nil: none. Added by lane
	// SBX-P1B; additive, every other family leaves it nil.
	LintWarnings func(spec any) []string
	// Owner is the node catalog id of the optional module that owns the
	// family (terminals.isolation: terminals.sandbox), "" for none. A node
	// whose [components] leaves that module inactive advertises none of the
	// family's live tokens (LinkedLiveCapabilitiesActive), so a floor that
	// needs them NACKs there instead of being accepted by a module that does
	// not run. Additive (SBX-P1B merge audit low item); every other family
	// leaves it empty.
	Owner string
	// RequiredComponents names the node catalog components a compiled body
	// requires (for security.scanning: require.components, the known
	// children only). The org server projects them as node.components
	// require for a managed member at serve time (D-753, security plan 7.3
	// and 4.9, lane SEC-E3), and the fleet evaluator checks a managed node
	// runs them. Nil: none. Additive; every other family leaves it nil.
	RequiredComponents func(spec any) []string
}

var (
	linkedMu        sync.RWMutex
	linkedFamilies  = map[string]LinkedFamily{}
	linkedConflicts = map[string]int{}
)

// RegisterLinkedFamily links family's compiler into this build. It is called
// from a registration pair file's init. A second registration of the same
// family is refused: both are dropped, the family answers ErrFamilyConflict
// from then on, and LinkedConflicts names it.
func RegisterLinkedFamily(family string, f LinkedFamily) {
	linkedMu.Lock()
	defer linkedMu.Unlock()
	if _, dup := linkedFamilies[family]; dup || linkedConflicts[family] > 0 {
		linkedConflicts[family]++
		delete(linkedFamilies, family)
		return
	}
	linkedFamilies[family] = f
}

// SwapLinkedFamilyForTest replaces family's registration for the length of a
// test: a non-nil f links that compiler, nil leaves the family unlinked (what
// a build without the family's pair file answers). A duplicate-registration
// conflict on the family is cleared while it is swapped. The returned func
// puts the registry back exactly as it was and is safe to call more than once,
// so no registration outlives the test that made it (audit SHR-KIT finding
// 5). Tests only: a build links a family through RegisterLinkedFamily.
func SwapLinkedFamilyForTest(family string, f *LinkedFamily) (restore func()) {
	linkedMu.Lock()
	prev, hadPrev := linkedFamilies[family]
	prevConflicts, hadConflicts := linkedConflicts[family]
	delete(linkedConflicts, family)
	if f == nil {
		delete(linkedFamilies, family)
	} else {
		linkedFamilies[family] = *f
	}
	linkedMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			linkedMu.Lock()
			defer linkedMu.Unlock()
			if hadPrev {
				linkedFamilies[family] = prev
			} else {
				delete(linkedFamilies, family)
			}
			if hadConflicts {
				linkedConflicts[family] = prevConflicts
			} else {
				delete(linkedConflicts, family)
			}
		})
	}
}

// LinkedConflicts lists the families registered more than once, sorted. The
// daemon logs it at start; a test asserts it is empty in every build.
func LinkedConflicts() []string {
	linkedMu.RLock()
	defer linkedMu.RUnlock()
	out := make([]string, 0, len(linkedConflicts))
	for f := range linkedConflicts {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// IsFamilyLinked reports whether family is supported and its compiler is in
// this build.
func IsFamilyLinked(family string) bool {
	if !IsSupportedFamily(family) {
		return false
	}
	if !IsLinkedOnlyFamily(family) {
		return true
	}
	_, ok := lookupLinkedFamily(family)
	return ok
}

func lookupLinkedFamily(family string) (LinkedFamily, bool) {
	linkedMu.RLock()
	defer linkedMu.RUnlock()
	if linkedConflicts[family] > 0 {
		return LinkedFamily{}, false
	}
	f, ok := linkedFamilies[family]
	return f, ok && f.Compile != nil && f.Enforces != nil
}

func linkedConflict(family string) bool {
	linkedMu.RLock()
	defer linkedMu.RUnlock()
	return linkedConflicts[family] > 0
}

// compileLinked compiles a linked family's body, or answers
// ErrFamilyNotLinked (or ErrFamilyConflict) naming the family.
func compileLinked(family string, raw []byte, maxBytes int64) (any, []byte, error) {
	if linkedConflict(family) {
		return nil, nil, fmt.Errorf("policyfam.CompileFamilyBody: %q: %w", family, ErrFamilyConflict)
	}
	f, ok := lookupLinkedFamily(family)
	if !ok {
		return nil, nil, fmt.Errorf("policyfam.CompileFamilyBody: %q: %w", family, ErrFamilyNotLinked)
	}
	return f.Compile(raw, maxBytes)
}

// linkedEnforces is SpecRequestsEnforceMode for a linked family. spec came
// from compileLinked, so the family is registered; were it not, the answer is
// the conservative one (true: the body needs the node's enforce consent).
func linkedEnforces(family string, spec any) bool {
	f, ok := lookupLinkedFamily(family)
	if !ok {
		return true
	}
	return f.Enforces(spec)
}

// LinkedRequiredCapabilities returns the capability tokens a compiled body of
// a linked family needs, sorted and deduplicated. Empty for a family that is
// not linked or declares no leg.
func LinkedRequiredCapabilities(family string, spec any) []string {
	f, ok := lookupLinkedFamily(family)
	if !ok || f.RequiredCapabilities == nil {
		return nil
	}
	return sortedUnique(f.RequiredCapabilities(spec))
}

// LinkedRequiredComponents is the node catalog components a compiled body
// of family requires (LinkedFamily.RequiredComponents), sorted and unique;
// nil for a family that is not linked or declares none.
func LinkedRequiredComponents(family string, spec any) []string {
	f, ok := lookupLinkedFamily(family)
	if !ok || f.RequiredComponents == nil {
		return nil
	}
	return sortedUnique(f.RequiredComponents(spec))
}

// LinkedLiveCapabilities is the union of every linked family's live
// capability tokens in this build, sorted.
func LinkedLiveCapabilities() []string {
	return LinkedLiveCapabilitiesActive(nil)
}

// LinkedLiveCapabilitiesActive is LinkedLiveCapabilities without the
// families whose owning module active reports inactive (LinkedFamily.Owner).
// A nil active, or a family with no owner, keeps every token.
func LinkedLiveCapabilitiesActive(active func(owner string) bool) []string {
	linkedMu.RLock()
	var all []string
	for name, f := range linkedFamilies {
		if linkedConflicts[name] > 0 || f.LiveCapabilities == nil {
			continue
		}
		if f.Owner != "" && active != nil && !active(f.Owner) {
			continue
		}
		all = append(all, f.LiveCapabilities()...)
	}
	linkedMu.RUnlock()
	return sortedUnique(all)
}

// CheckLinkedPosture runs a linked family's posture evaluator on a compiled
// spec. A family with no evaluator (or not linked) passes: the accept gate
// it feeds (orgclient.PolicyResourceOptions.CheckPosture) then changes
// nothing for it.
func CheckLinkedPosture(family string, spec any) (axis string, err error) {
	f, ok := lookupLinkedFamily(family)
	if !ok || f.CheckPosture == nil {
		return "", nil
	}
	return f.CheckPosture(spec)
}

// LinkedLintWarnings runs a linked family's publish lint on a compiled spec.
// A family with no lint leg (or not linked) has nothing to say.
func LinkedLintWarnings(family string, spec any) []string {
	f, ok := lookupLinkedFamily(family)
	if !ok || f.LintWarnings == nil {
		return nil
	}
	return f.LintWarnings(spec)
}

func sortedUnique(v []string) []string {
	if len(v) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(v))
	out := make([]string, 0, len(v))
	for _, s := range v {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
