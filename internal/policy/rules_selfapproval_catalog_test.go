package policy

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestSecurityTreeRequiresMatchesCatalog pins securityTreeRequires to the
// real catalog (lane sec-gate3 audit finding 1): it must list exactly the
// ids outside the security tree that the security module or one of its
// children requires, directly or through another component, so a new
// requirement cannot open a removal R-165 does not see.
func TestSecurityTreeRequiresMatchesCatalog(t *testing.T) {
	byID := map[string]components.Component{}
	for _, c := range components.All() {
		byID[c.ID] = c
	}
	if _, ok := byID[securityComponentRoot]; !ok {
		t.Fatalf("the catalog has no %q component", securityComponentRoot)
	}
	outside := map[string]bool{}
	seen := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		c, ok := byID[id]
		if !ok {
			t.Fatalf("the catalog has no component %q", id)
		}
		for _, r := range c.Requires {
			if !isSecurityComponent(r) {
				outside[r] = true
			}
			walk(r)
		}
	}
	for id := range byID {
		if isSecurityComponent(id) {
			walk(id)
		}
	}
	var want []string
	for id := range outside {
		want = append(want, id)
	}
	slices.Sort(want)
	got := slices.Clone(securityTreeRequires)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("securityTreeRequires = %v, the catalog says %v", got, want)
	}
	for _, id := range want {
		if !lowersSecurityOnRemove(id) || !componentRemoveList.MatchString(`{"change":{"remove":["`+id+`"]}}`) {
			t.Errorf("removing %q is not matched", id)
		}
	}
}

// TestSecurityKeepingBasesMatchCatalog pins securityKeepingBases to the
// catalog (lane sec-gate4 milestone 2b): a distro keeps the security
// module on exactly when every component of the security tree and every
// component the tree requires that the full distro has on is on in it
// too; "" and "all" (everything compiled in) always keep it. A distro
// that changes its cells cannot open a base selection R-165 does not see.
func TestSecurityKeepingBasesMatchCatalog(t *testing.T) {
	var watched []components.Component
	for _, c := range components.All() {
		if isSecurityComponent(c.ID) || slices.Contains(securityTreeRequires, c.ID) {
			watched = append(watched, c)
		}
	}
	want := []string{"", "all"}
	for _, d := range components.Distros() {
		keeps := true
		for _, c := range watched {
			if c.Distros[components.DistroFull] == components.DefaultOn && c.Distros[d] != components.DefaultOn {
				keeps = false
			}
		}
		if keeps {
			want = append(want, string(d))
		}
	}
	got := slices.Clone(securityKeepingBases)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("securityKeepingBases = %v, the catalog says %v", got, want)
	}
	for _, d := range components.Distros() {
		body := `{"change":{"set_base":"` + string(d) + `"}}`
		if matched := componentSetBase.MatchString(body) && !keepsSecurityBase(string(d)); matched == slices.Contains(want, string(d)) {
			t.Errorf("selecting %q: matched %v", d, matched)
		}
	}
}
