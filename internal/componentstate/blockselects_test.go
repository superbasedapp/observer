package componentstate

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestBlockSelectsOnlyWhatTheBlockNames pins D-MU3: a block that adds one
// component selects only that component for the opt-in rules; a named
// distro selects its base set; no block selects nothing.
func TestBlockSelectsOnlyWhatTheBlockNames(t *testing.T) {
	var full []string
	for _, d := range components.Distros() {
		if d == "developer" {
			full = BaseSet(d)
		}
	}
	if len(full) == 0 {
		t.Fatal("no developer distro base set")
	}
	inBase := full[len(full)-1]
	cases := []struct {
		name string
		sec  config.ComponentsConfig
		id   string
		want bool
	}{
		{"no block", config.ComponentsConfig{}, "terminals.sandbox.seatbelt", false},
		{"add-only block, other id", config.ComponentsConfig{Add: []string{"integration.service"}}, "terminals.sandbox.seatbelt", false},
		{"add-only block, the added id", config.ComponentsConfig{Add: []string{"terminals.sandbox.seatbelt"}}, "terminals.sandbox.seatbelt", true},
		{"remove-only block", config.ComponentsConfig{Remove: []string{"integration.service"}}, "isolation.seal", false},
		{"named distro, id in its base", config.ComponentsConfig{Distro: "developer"}, inBase, true},
		{"unknown distro selects nothing", config.ComponentsConfig{Distro: "nope"}, inBase, false},
	}
	for _, tc := range cases {
		s := Resolve(tc.sec, nil)
		if got := s.BlockSelects(tc.id); got != tc.want {
			t.Errorf("%s: BlockSelects(%q) = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
	managed := ResolveGoverned(config.ComponentsConfig{Add: []string{"integration.service"}}, nil, Governed{OrgManaged: true})
	if !managed.BlockSelects("terminals.sandbox.seatbelt") {
		t.Error("an org-managed node keeps the block-exists rule")
	}
}
